"""Read-only service adapter for the gateway's durable account journal.

The component resolves wire scopes through server-owned account and principal
maps, then delegates reads and consumer positions to ``GatewayEventJournal``.
It does not query a provider or create a separate ledger. A returned snapshot
is the journal's persisted baseline, followed by events after that baseline;
it is never a fresh provider snapshot.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Optional

from bt_api_base.account_protocol import AccountObservation
from bt_api_base.service_protocol import MAX_REFERENCE_BYTES, WireIdentity, WireScope

from .account_session_worker import GatewayAccountSessionWorker
from .account_view_projection import validate_policy_set
from .event_journal import (
    GatewayAccountEvent,
    GatewayAccountSnapshot,
    GatewayConsumerProgress,
    GatewayEventJournal,
    GatewayEventJournalError,
    GatewayReadBatch,
)
from .router import GatewayPrincipal

_SERVICE_REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MARKET_HUB_PORTS = frozenset({"service.market_source"})
_ACCOUNT_SESSION_WORKER_PORTS = frozenset(
    {"service.account_read", "service.provider_session", "service.owner_control"}
)
_DEFAULT_READ_LIMIT = 100
_UNSAMPLED_SOURCE_CURSOR = object()

SUPPORTED_OPERATIONS = frozenset(
    {
        "account.ack",
        "account.head",
        "account.progress",
        "account.read_after",
        "account.snapshot",
    }
)


class GatewayServiceError(RuntimeError):
    """A finite, value-free error from gateway service validation or routing."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def validate_service_options(
    options: Mapping[str, object], bind_ports: tuple[str, ...]
) -> Mapping[str, object]:
    """Validate the declared gateway service roles without performing I/O.

    ``market_hub`` accepts only ``service.market_source`` and the ``role``
    option. ``account_session_worker`` accepts a nonempty subset of its SDK
    service ports and requires an SDK-shaped ``account_session_ref``.
    """

    if not isinstance(options, Mapping):
        raise GatewayServiceError("INVALID_OPTIONS")
    if type(bind_ports) is not tuple or not bind_ports:
        raise GatewayServiceError("INVALID_BIND_PORTS")
    if any(type(port) is not str for port in bind_ports):
        raise GatewayServiceError("INVALID_BIND_PORTS")
    if len(set(bind_ports)) != len(bind_ports):
        raise GatewayServiceError("INVALID_BIND_PORTS")
    if any(type(key) is not str for key in options):
        raise GatewayServiceError("INVALID_OPTIONS")

    role = options.get("role")
    if type(role) is not str:
        raise GatewayServiceError("MISSING_OR_INVALID_ROLE")
    copied: dict[str, object]
    if role == "market_hub":
        allowed_ports = _MARKET_HUB_PORTS
        allowed_options = frozenset({"role"})
        copied = {"role": role}
    elif role == "account_session_worker":
        allowed_ports = _ACCOUNT_SESSION_WORKER_PORTS
        allowed_options = frozenset({"role", "account_session_ref"})
        session_ref = options.get("account_session_ref")
        if session_ref is None:
            raise GatewayServiceError("MISSING_ACCOUNT_SESSION_REF")
        if not _is_service_reference(session_ref):
            raise GatewayServiceError("INVALID_ACCOUNT_SESSION_REF")
        copied = {"role": role, "account_session_ref": session_ref}
    else:
        raise GatewayServiceError("UNKNOWN_SERVICE_ROLE")

    if any(key not in allowed_options for key in options):
        raise GatewayServiceError("UNKNOWN_OPTION")
    if any(port not in allowed_ports for port in bind_ports):
        raise GatewayServiceError("ROLE_PORT_MISMATCH")
    return MappingProxyType(copied)


@dataclass(frozen=True)
class GatewayServiceAccountScope:
    """Trusted mapping from one wire account to its exact journal streams.

    Strategy keys are trusted ``WireScope.strategy_ref`` values and values
    are the corresponding journal strategy scopes. Account-wide requests
    (where ``strategy_ref`` is ``None``) use only the explicitly configured
    ``account_read_strategy_scope``; no synthetic or aggregate strategy is
    inferred. A strategy request may also carry its registered ``run_id``;
    reads still use the mapped durable strategy stream rather than a per-run
    journal stream.
    """

    account_ref: str
    execution_domain_ref: str
    journal_account_scope: str
    strategy_scope_map: Mapping[str, str] = field(default_factory=dict)
    account_read_strategy_scope: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.
    shared_account_facts_scope: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.
    shared_fact_strategy_refs: Iterable[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        _require_wire_text(self.account_ref, "INVALID_ACCOUNT_SCOPE")
        _require_wire_text(self.execution_domain_ref, "INVALID_ACCOUNT_SCOPE")
        _require_wire_text(self.journal_account_scope, "INVALID_ACCOUNT_SCOPE")
        if not isinstance(self.strategy_scope_map, Mapping):
            raise GatewayServiceError("INVALID_STRATEGY_SCOPE_MAP")
        copied: dict[str, str] = {}
        for strategy_ref, journal_strategy_scope in self.strategy_scope_map.items():
            _require_wire_text(strategy_ref, "INVALID_STRATEGY_SCOPE_MAP")
            _require_wire_text(journal_strategy_scope, "INVALID_STRATEGY_SCOPE_MAP")
            copied[strategy_ref] = journal_strategy_scope
        if len(set(copied.values())) != len(copied):
            raise GatewayServiceError("AMBIGUOUS_STRATEGY_SCOPE_MAP")

        shared_scope = self.shared_account_facts_scope
        if shared_scope is not None:
            _require_wire_text(shared_scope, "INVALID_SHARED_ACCOUNT_FACTS_SCOPE")
            if shared_scope in copied.values():
                raise GatewayServiceError("AMBIGUOUS_SHARED_ACCOUNT_FACTS_SCOPE")
        try:
            shared_refs = frozenset(self.shared_fact_strategy_refs)
        except (TypeError, ValueError) as exc:
            raise GatewayServiceError("INVALID_SHARED_FACT_STRATEGY_REFS") from exc
        if isinstance(self.shared_fact_strategy_refs, (str, bytes)):
            raise GatewayServiceError("INVALID_SHARED_FACT_STRATEGY_REFS")
        if shared_refs and shared_scope is None:
            raise GatewayServiceError("SHARED_FACT_SCOPE_REQUIRED")
        for strategy_ref in shared_refs:
            _require_wire_text(strategy_ref, "INVALID_SHARED_FACT_STRATEGY_REFS")
            if strategy_ref in copied:
                raise GatewayServiceError("AMBIGUOUS_SHARED_FACT_STRATEGY")

        account_strategy_scope = self.account_read_strategy_scope
        if account_strategy_scope is not None:
            _require_wire_text(account_strategy_scope, "INVALID_ACCOUNT_READ_SCOPE")
            if account_strategy_scope in copied.values():
                raise GatewayServiceError("AMBIGUOUS_ACCOUNT_READ_SCOPE")

        object.__setattr__(self, "strategy_scope_map", MappingProxyType(copied))
        object.__setattr__(self, "shared_fact_strategy_refs", shared_refs)


class GatewayReadService:
    """Read account journal streams for authenticated, trusted principals.

    The journal is borrowed and remains owned by the caller. Account and
    principal mappings are copied at construction so later caller mutation
    cannot widen this service's routing table. Consumer operations also need
    a ``WireIdentity`` supplied by the trusted service caller; this class
    checks its shape and principal binding but does not authenticate claims.
    """

    def __init__(
        self,
        journal: GatewayEventJournal,
        *,
        accounts: Mapping[str, GatewayServiceAccountScope],
        principals: Mapping[str, GatewayPrincipal],
        state_worker: Optional[GatewayAccountSessionWorker] = None,  # noqa: UP045
    ) -> None:
        if not isinstance(journal, GatewayEventJournal):
            raise GatewayServiceError("INVALID_JOURNAL")
        self._journal = journal
        self._accounts = MappingProxyType(_copy_accounts(accounts))
        self._principals = MappingProxyType(_copy_principals(principals))
        if state_worker is not None:
            if type(state_worker) is not GatewayAccountSessionWorker:
                raise GatewayServiceError("INVALID_STATE_WORKER")
            if state_worker.journal is not journal:
                raise GatewayServiceError("STATE_WORKER_JOURNAL_MISMATCH")
            if len(self._accounts) != 1:
                raise GatewayServiceError("STATE_WORKER_ACCOUNT_MAPPING_INVALID")
            account = next(iter(self._accounts.values()))
            if account.journal_account_scope != state_worker.journal_account_scope:
                raise GatewayServiceError("STATE_WORKER_JOURNAL_SCOPE_MISMATCH")
            try:
                view_policies = validate_policy_set(state_worker.view_policies)
            except Exception:
                raise GatewayServiceError("STATE_VIEW_POLICIES_INVALID") from None
            self._view_policies = MappingProxyType(
                {policy.view_scope: policy for policy in view_policies}
            )
            view_scopes = frozenset(self._view_policies)
            if view_policies:
                if not set(account.strategy_scope_map.values()) <= view_scopes:
                    raise GatewayServiceError("STATE_VIEW_SCOPE_MAPPING_INVALID")
                if account.account_read_strategy_scope in view_scopes:
                    raise GatewayServiceError("STATE_VIEW_CANONICAL_SCOPE_CONFLICT")
            shared_scope = account.shared_account_facts_scope
            account_read_scope = account.account_read_strategy_scope
            if (shared_scope is not None and shared_scope != state_worker.state_scope) or (
                account_read_scope is not None and account_read_scope != state_worker.state_scope
            ):
                raise GatewayServiceError("STATE_WORKER_STATE_SCOPE_MISMATCH")
            canonical_scope_unbound = (shared_scope is None and account_read_scope is None) or (
                not account.shared_fact_strategy_refs and account_read_scope is None
            )
            if canonical_scope_unbound and not (view_policies and account.strategy_scope_map):
                raise GatewayServiceError("STATE_WORKER_STATE_SCOPE_UNBOUND")
        else:
            self._view_policies = MappingProxyType({})
        self._state_worker = state_worker

    def handle(
        self,
        operation: str,
        *,
        principal_ref: str,
        scope: WireScope,
        arguments: Mapping[str, object],
        identity: Optional[WireIdentity] = None,  # noqa: UP045 -- Python 3.9 support.
        result_fits: Optional[Callable[[Mapping[str, object]], bool]] = None,  # noqa: UP045
    ) -> Mapping[str, object]:
        """Dispatch a bounded journal read or consumer-progress operation.

        ``result_fits`` is trusted in-process context supplied by the service
        runtime. For tracked reads it must be a pure, monotone result-size
        predicate over the complete mapping returned to the client. It is never
        accepted through wire ``arguments``.
        """

        if type(operation) is not str or operation not in SUPPORTED_OPERATIONS:
            raise GatewayServiceError("UNSUPPORTED_OPERATION")
        if type(principal_ref) is not str:
            raise GatewayServiceError("INVALID_PRINCIPAL_REF")
        principal = self._principals.get(principal_ref)
        if principal is None:
            raise GatewayServiceError("UNKNOWN_PRINCIPAL")
        if type(scope) is not WireScope:
            raise GatewayServiceError("INVALID_SCOPE")
        account, journal_strategy_scope = self._resolve_scope(scope)
        if not isinstance(arguments, Mapping):
            raise GatewayServiceError("INVALID_ARGUMENTS")
        if any(type(key) is not str for key in arguments):
            raise GatewayServiceError("INVALID_ARGUMENTS")

        if operation == "account.read_after":
            _reject_unknown_arguments(
                arguments, frozenset({"cursor", "limit", "track_delivery", "stream_epoch"})
            )
            cursor = arguments.get("cursor")
            limit = arguments.get("limit", _DEFAULT_READ_LIMIT)
            _validate_read_arguments(cursor, limit, cursor_allowed=True)
            track_delivery = arguments.get("track_delivery", False)
            if type(track_delivery) is not bool:
                raise GatewayServiceError("INVALID_ARGUMENTS")
            if track_delivery:
                if result_fits is not None and not callable(result_fits):
                    raise GatewayServiceError("INVALID_RESULT_FITNESS_CHECK")
                consumer_ref = self._consumer_ref(
                    identity,
                    principal_ref=principal_ref,
                    principal=principal,
                    scope=scope,
                    account=account,
                    journal_strategy_scope=journal_strategy_scope,
                )

                if result_fits is None:
                    batch, progress = self._journal.read_for_consumer(
                        principal,
                        account.journal_account_scope,
                        journal_strategy_scope,
                        consumer_ref,
                        cursor=cursor,  # type: ignore[arg-type] -- validated above.
                        limit=limit,  # type: ignore[arg-type] -- validated above.
                        stream_epoch=arguments.get("stream_epoch"),
                    )
                    return self._consumer_read_result(
                        batch,
                        progress,
                        operation=operation,
                        strategy_scope=journal_strategy_scope,
                    )

                selected_batch: Optional[GatewayReadBatch] = None  # noqa: UP045
                selected_progress: Optional[GatewayConsumerProgress] = None  # noqa: UP045
                selected_result: Optional[Mapping[str, object]] = None  # noqa: UP045
                selected_fits = False
                state_status_snapshot: Optional[Mapping[str, object]] = None  # noqa: UP045
                source_cursor_snapshot: object = _UNSAMPLED_SOURCE_CURSOR
                state_status_captured = False

                def page_fits(
                    candidate_batch: GatewayReadBatch,
                    candidate_progress: GatewayConsumerProgress,
                ) -> bool:
                    nonlocal selected_batch, selected_progress, selected_result
                    nonlocal selected_fits, state_status_snapshot, state_status_captured
                    nonlocal source_cursor_snapshot
                    if self._state_worker is not None and not state_status_captured:
                        candidate_status = self._state_worker.read_status()
                        if not isinstance(candidate_status, Mapping):
                            raise GatewayServiceError("STATE_STATUS_INVALID")
                        state_status_snapshot = candidate_status
                        source_snapshot = self._state_worker.latest_snapshot
                        source_cursor_snapshot = (
                            source_snapshot.cursor
                            if type(source_snapshot) is GatewayAccountSnapshot
                            else None
                        )
                        state_status_captured = True
                    candidate_result = self._consumer_read_result(
                        candidate_batch,
                        candidate_progress,
                        operation=operation,
                        strategy_scope=journal_strategy_scope,
                        state_status=state_status_snapshot,
                        source_cursor=source_cursor_snapshot,
                    )
                    fits = result_fits(candidate_result)
                    if type(fits) is not bool:
                        raise GatewayServiceError("INVALID_RESULT_FITNESS_RESULT")
                    selected_batch = candidate_batch
                    selected_progress = candidate_progress
                    selected_result = candidate_result
                    selected_fits = fits
                    return fits

                batch, progress = self._journal.read_for_consumer(
                    principal,
                    account.journal_account_scope,
                    journal_strategy_scope,
                    consumer_ref,
                    cursor=cursor,  # type: ignore[arg-type] -- validated above.
                    limit=limit,  # type: ignore[arg-type] -- validated above.
                    stream_epoch=arguments.get("stream_epoch"),
                    page_fits=page_fits,
                )
                if (
                    selected_batch != batch
                    or selected_progress != progress
                    or selected_result is None
                    or not selected_fits
                ):
                    raise GatewayServiceError("CONSUMER_PAGE_RESULT_MISMATCH")
                return selected_result
            if "stream_epoch" in arguments:
                raise GatewayServiceError("UNKNOWN_ARGUMENT")
            batch = self._journal.read_after(
                principal,
                account.journal_account_scope,
                journal_strategy_scope,
                cursor=cursor,  # type: ignore[arg-type] -- validated above.
                limit=limit,  # type: ignore[arg-type] -- validated above.
            )
            return self._with_state_status(
                _batch_result(batch, include_snapshot_source=False),
                operation=operation,
                strategy_scope=journal_strategy_scope,
            )

        if operation == "account.progress":
            _reject_unknown_arguments(arguments, frozenset())
            consumer_ref = self._consumer_ref(
                identity,
                principal_ref=principal_ref,
                principal=principal,
                scope=scope,
                account=account,
                journal_strategy_scope=journal_strategy_scope,
            )
            progress = self._journal.consumer_progress(
                principal,
                account.journal_account_scope,
                journal_strategy_scope,
                consumer_ref,
            )
            return MappingProxyType({"consumer_progress": _consumer_progress_result(progress)})

        if operation == "account.ack":
            _reject_unknown_arguments(arguments, frozenset({"stream_epoch", "cursor"}))
            if set(arguments) != {"stream_epoch", "cursor"}:
                raise GatewayServiceError("INVALID_ARGUMENTS")
            consumer_ref = self._consumer_ref(
                identity,
                principal_ref=principal_ref,
                principal=principal,
                scope=scope,
                account=account,
                journal_strategy_scope=journal_strategy_scope,
            )
            progress = self._journal.acknowledge(
                principal,
                account.journal_account_scope,
                journal_strategy_scope,
                consumer_ref,
                stream_epoch=arguments["stream_epoch"],
                cursor=arguments["cursor"],
            )
            return MappingProxyType({"consumer_progress": _consumer_progress_result(progress)})

        if operation == "account.snapshot":
            _reject_unknown_arguments(arguments, frozenset({"limit"}))
            limit = arguments.get("limit", _DEFAULT_READ_LIMIT)
            _validate_read_arguments(None, limit, cursor_allowed=False)
            batch = self._journal.read_after(
                principal,
                account.journal_account_scope,
                journal_strategy_scope,
                cursor=None,
                limit=limit,  # type: ignore[arg-type] -- validated above.
            )
            return self._with_state_status(
                _batch_result(batch, include_snapshot_source=True),
                operation=operation,
                strategy_scope=journal_strategy_scope,
            )

        _reject_unknown_arguments(arguments, frozenset())
        batch = self._journal.read_after(
            principal,
            account.journal_account_scope,
            journal_strategy_scope,
            cursor=None,
            limit=1,
        )
        result: dict[str, object] = {"latest_cursor": batch.latest_cursor}
        if self._state_worker is not None:
            return self._with_state_status(
                MappingProxyType(result),
                operation=operation,
                strategy_scope=journal_strategy_scope,
            )
        return MappingProxyType(result)

    def _consumer_ref(
        self,
        identity: Optional[WireIdentity],  # noqa: UP045 -- Python 3.9 support.
        *,
        principal_ref: str,
        principal: GatewayPrincipal,
        scope: WireScope,
        account: GatewayServiceAccountScope,
        journal_strategy_scope: str,
    ) -> str:
        if type(identity) is not WireIdentity or identity.principal_ref != principal_ref:
            # A missing or mismatched claim must not bypass normal journal ACL
            # checks. This read is side-effect free and never creates progress.
            self._journal.read_after(
                principal,
                account.journal_account_scope,
                journal_strategy_scope,
                cursor=None,
                limit=1,
            )
            if identity is None:
                raise GatewayServiceError("CONSUMER_IDENTITY_REQUIRED")
            if type(identity) is not WireIdentity:
                raise GatewayServiceError("CONSUMER_IDENTITY_INVALID")
            raise GatewayServiceError("CONSUMER_PRINCIPAL_MISMATCH")
        identity_scope = {
            "execution_domain_ref": scope.execution_domain_ref,
            "account_ref": scope.account_ref,
            "strategy_ref": scope.strategy_ref,
        }
        identity_claim = {
            "role": identity.role.value,
            "principal_ref": identity.principal_ref,
            "actor_ref": identity.actor_ref,
            "delegate_ref": identity.delegate_ref,
        }
        canonical = json.dumps(
            {"identity": identity_claim, "scope": identity_scope},
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
        return hashlib.sha256(canonical).hexdigest()

    def _with_state_status(
        self,
        result: Mapping[str, object],
        *,
        operation: str,
        strategy_scope: str,
        state_status: Optional[Mapping[str, object]] = None,  # noqa: UP045
        source_cursor: object = _UNSAMPLED_SOURCE_CURSOR,
    ) -> Mapping[str, object]:
        if self._state_worker is None:
            return result
        copied = dict(result)
        status_sample = self._state_worker.read_status() if state_status is None else state_status
        if not isinstance(status_sample, Mapping):
            raise GatewayServiceError("STATE_STATUS_INVALID")
        status = dict(status_sample)
        if source_cursor is _UNSAMPLED_SOURCE_CURSOR:
            latest_snapshot = self._state_worker.latest_snapshot
            source_cursor = (
                latest_snapshot.cursor if type(latest_snapshot) is GatewayAccountSnapshot else None
            )
        policy = self._view_policies.get(strategy_scope)
        if policy is not None:
            view_cursor = result.get("latest_cursor")
            page_complete = operation == "account.head"
            if operation in {"account.read_after", "account.snapshot"}:
                next_cursor = result.get("next_cursor")
                page_complete = (
                    type(next_cursor) is int
                    and type(view_cursor) is int
                    and next_cursor == view_cursor
                )
            view_current = False
            if (
                status.get("ready") is True
                and page_complete
                and type(source_cursor) is int
                and source_cursor >= 0
                and type(view_cursor) is int
                and view_cursor >= 0
            ):
                current = self._journal.account_view_is_current(
                    self._state_worker.journal_account_scope,
                    self._state_worker.state_scope,
                    policy.view_scope,
                    policy.digest,
                    source_cursor,
                    view_cursor,
                )
                view_current = type(current) is bool and current
            if not view_current:
                status["ready"] = False
                status["fresh_for_seconds"] = 0.0
        elif status.get("ready") is True and not _state_result_matches_worker(
            result,
            operation=operation,
            strategy_scope=strategy_scope,
            worker=self._state_worker,
            generation=status.get("session_generation"),
        ):
            status["ready"] = False
            status["fresh_for_seconds"] = 0.0
        copied["state_status"] = MappingProxyType(status)
        return MappingProxyType(copied)

    def _consumer_read_result(
        self,
        batch: GatewayReadBatch,
        progress: GatewayConsumerProgress,
        *,
        operation: str,
        strategy_scope: str,
        state_status: Optional[Mapping[str, object]] = None,  # noqa: UP045
        source_cursor: object = _UNSAMPLED_SOURCE_CURSOR,
    ) -> Mapping[str, object]:
        result = dict(_batch_result(batch, include_snapshot_source=False))
        result["consumer_progress"] = _consumer_progress_result(progress)
        return self._with_state_status(
            MappingProxyType(result),
            operation=operation,
            strategy_scope=strategy_scope,
            state_status=state_status,
            source_cursor=source_cursor,
        )

    def _resolve_scope(self, scope: WireScope) -> tuple[GatewayServiceAccountScope, str]:
        if (
            scope.account_ref is None
            or scope.account_refs
            or (scope.strategy_ref is None and scope.run_id is not None)
            or scope.manual_book_ref is not None
            or scope.portfolio_ref is not None
            or scope.group_id is not None
            or scope.leg_id is not None
        ):
            raise GatewayServiceError("ACCOUNT_SCOPE_REQUIRED")
        account = self._accounts.get(scope.account_ref)
        if account is None:
            raise GatewayServiceError("UNKNOWN_ACCOUNT")
        if scope.execution_domain_ref != account.execution_domain_ref:
            raise GatewayServiceError("EXECUTION_DOMAIN_DENIED")
        if scope.strategy_ref is None:
            journal_strategy_scope = account.account_read_strategy_scope
            if journal_strategy_scope is None:
                raise GatewayServiceError("ACCOUNT_WIDE_READ_NOT_CONFIGURED")
        else:
            if scope.strategy_ref in account.shared_fact_strategy_refs:
                journal_strategy_scope = account.shared_account_facts_scope
            else:
                journal_strategy_scope = account.strategy_scope_map.get(scope.strategy_ref)
            if journal_strategy_scope is None:
                raise GatewayServiceError("STRATEGY_SCOPE_DENIED")
        return account, journal_strategy_scope


def _copy_accounts(
    accounts: Mapping[str, GatewayServiceAccountScope],
) -> dict[str, GatewayServiceAccountScope]:
    if not isinstance(accounts, Mapping) or not accounts:
        raise GatewayServiceError("INVALID_ACCOUNT_RESOURCES")
    copied: dict[str, GatewayServiceAccountScope] = {}
    for account_ref, account in accounts.items():
        _require_wire_text(account_ref, "INVALID_ACCOUNT_RESOURCES")
        if type(account) is not GatewayServiceAccountScope or account.account_ref != account_ref:
            raise GatewayServiceError("INVALID_ACCOUNT_RESOURCES")
        copied[account_ref] = account
    return copied


def _copy_principals(principals: Mapping[str, GatewayPrincipal]) -> dict[str, GatewayPrincipal]:
    if not isinstance(principals, Mapping) or not principals:
        raise GatewayServiceError("INVALID_PRINCIPAL_RESOURCES")
    copied: dict[str, GatewayPrincipal] = {}
    for principal_ref, principal in principals.items():
        _require_wire_text(principal_ref, "INVALID_PRINCIPAL_RESOURCES")
        if type(principal) is not GatewayPrincipal or principal.principal_id != principal_ref:
            raise GatewayServiceError("INVALID_PRINCIPAL_RESOURCES")
        copied[principal_ref] = principal
    return copied


def _require_wire_text(value: object, code: str) -> None:
    if type(value) is not str:
        raise GatewayServiceError(code)
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise GatewayServiceError(code) from exc
    if (
        not encoded
        or len(encoded) > MAX_REFERENCE_BYTES
        or value != value.strip()
        or any(ord(char) < 32 or 0x7F <= ord(char) <= 0x9F for char in value)
    ):
        raise GatewayServiceError(code)


def _is_service_reference(value: object) -> bool:
    return type(value) is str and _SERVICE_REFERENCE_PATTERN.fullmatch(value) is not None


def _reject_unknown_arguments(arguments: Mapping[str, object], allowed: frozenset[str]) -> None:
    if any(key not in allowed for key in arguments):
        raise GatewayServiceError("UNKNOWN_ARGUMENT")


def _validate_read_arguments(cursor: object, limit: object, *, cursor_allowed: bool) -> None:
    if not cursor_allowed and cursor is not None:
        raise GatewayServiceError("UNKNOWN_ARGUMENT")
    if cursor is not None and (type(cursor) is not int or cursor < 0):
        raise GatewayEventJournalError("CURSOR_INVALID", "cursor is invalid")
    if type(limit) is not int or not 1 <= limit <= GatewayEventJournal.MAX_BATCH_SIZE:
        raise GatewayEventJournalError("BATCH_SIZE_INVALID", "limit is invalid")


def _batch_result(
    batch: GatewayReadBatch, *, include_snapshot_source: bool
) -> Mapping[str, object]:
    snapshot = _snapshot_result(batch.snapshot)
    events = tuple(_event_result(event) for event in batch.events)
    result: dict[str, object] = {
        "requested_cursor": batch.requested_cursor,
        "snapshot": snapshot,
        "events": events,
        "next_cursor": batch.next_cursor,
        "latest_cursor": batch.latest_cursor,
        "recovered_from_snapshot": (
            batch.requested_cursor is not None
            and batch.snapshot is not None
            and batch.requested_cursor < batch.snapshot.cursor
        ),
    }
    if include_snapshot_source:
        result["snapshot_source"] = (
            "persisted_journal_baseline" if batch.snapshot is not None else None
        )
    return MappingProxyType(result)


def _consumer_progress_result(
    progress: GatewayConsumerProgress,
) -> Mapping[str, object]:
    if type(progress) is not GatewayConsumerProgress:
        raise GatewayServiceError("CONSUMER_PROGRESS_INVALID")
    if (
        type(progress.stream_epoch) is not str
        or not progress.stream_epoch
        or type(progress.offered_cursor) is not int
        or progress.offered_cursor < 0
        or type(progress.acknowledged_cursor) is not int
        or progress.acknowledged_cursor < 0
        or progress.acknowledged_cursor > progress.offered_cursor
    ):
        raise GatewayServiceError("CONSUMER_PROGRESS_INVALID")
    return MappingProxyType(
        {
            "stream_epoch": progress.stream_epoch,
            "offered_cursor": progress.offered_cursor,
            "acknowledged_cursor": progress.acknowledged_cursor,
        }
    )


def _snapshot_result(
    snapshot: Optional[GatewayAccountSnapshot],  # noqa: UP045 -- Python 3.9 support.
) -> Optional[Mapping[str, object]]:  # noqa: UP045 -- Python 3.9 support.
    if snapshot is None:
        return None
    return MappingProxyType(
        {
            "account_scope": snapshot.account_scope,
            "strategy_scope": snapshot.strategy_scope,
            "snapshot_id": snapshot.snapshot_id,
            "cursor": snapshot.cursor,
            "payload": snapshot.payload,
            "captured_at": snapshot.captured_at,
        }
    )


def _state_result_matches_worker(
    result: Mapping[str, object],
    *,
    operation: str,
    strategy_scope: str,
    worker: GatewayAccountSessionWorker,
    generation: object,
) -> bool:
    latest = worker.latest_snapshot
    if latest is None:
        return False
    observation_value = latest.payload.get("observation")
    if not isinstance(observation_value, Mapping):
        return False
    try:
        observation = AccountObservation.from_dict(observation_value)
    except (KeyError, TypeError, ValueError):
        return False
    expected_schema_version = 2 if observation.open_orders is not None else 1
    schema_version = latest.payload.get("schema_version")
    if (
        strategy_scope != worker.state_scope
        or latest.account_scope != worker.journal_account_scope
        or latest.strategy_scope != worker.state_scope
        or latest.cursor != result.get("latest_cursor")
        or latest.payload.get("schema_id") != "sdk.account.state"
        or type(schema_version) is not int
        or schema_version != expected_schema_version
        or latest.payload.get("session_generation") != generation
    ):
        return False
    if operation == "account.head":
        return True
    if operation == "account.read_after":
        events = result.get("events")
        returned_snapshot = result.get("snapshot")
        return not events and (
            returned_snapshot is None
            or _snapshot_result_matches(returned_snapshot, latest, generation)
        )
    return _snapshot_result_matches(result.get("snapshot"), latest, generation)


def _snapshot_result_matches(
    value: object, latest: GatewayAccountSnapshot, generation: object
) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("account_scope") == latest.account_scope
        and value.get("strategy_scope") == latest.strategy_scope
        and value.get("snapshot_id") == latest.snapshot_id
        and value.get("cursor") == latest.cursor
        and isinstance(value.get("payload"), Mapping)
        and value.get("payload") == latest.payload
        and value["payload"].get("session_generation") == generation  # type: ignore[index]
    )


def _event_result(event: GatewayAccountEvent) -> Mapping[str, object]:
    return MappingProxyType(
        {
            "account_scope": event.account_scope,
            "strategy_scope": event.strategy_scope,
            "sequence": event.sequence,
            "event_id": event.event_id,
            "kind": event.kind,
            "payload": event.payload,
            "observed_at": event.observed_at,
        }
    )
