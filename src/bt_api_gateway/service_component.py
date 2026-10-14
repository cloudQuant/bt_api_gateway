"""Read-only service adapter for the gateway's durable account journal.

The component resolves wire scopes through server-owned account and principal
maps, then delegates every data read to :meth:`GatewayEventJournal.read_after`.
It does not query a provider or create a separate ledger.  A returned snapshot
is the journal's persisted baseline, followed by events after that baseline;
it is never a fresh provider snapshot.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Optional

from bt_api_base.service_protocol import MAX_REFERENCE_BYTES, WireScope

from .event_journal import (
    GatewayAccountEvent,
    GatewayAccountSnapshot,
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

SUPPORTED_OPERATIONS = frozenset({"account.read_after", "account.snapshot", "account.head"})


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

        account_strategy_scope = self.account_read_strategy_scope
        if account_strategy_scope is not None:
            _require_wire_text(account_strategy_scope, "INVALID_ACCOUNT_READ_SCOPE")
            if account_strategy_scope in copied.values():
                raise GatewayServiceError("AMBIGUOUS_ACCOUNT_READ_SCOPE")

        object.__setattr__(self, "strategy_scope_map", MappingProxyType(copied))


class GatewayReadService:
    """Read account journal streams for authenticated, trusted principals.

    The journal is borrowed and remains owned by the caller. Account and
    principal mappings are copied at construction so later caller mutation
    cannot widen this service's routing table.
    """

    def __init__(
        self,
        journal: GatewayEventJournal,
        *,
        accounts: Mapping[str, GatewayServiceAccountScope],
        principals: Mapping[str, GatewayPrincipal],
    ) -> None:
        if not isinstance(journal, GatewayEventJournal):
            raise GatewayServiceError("INVALID_JOURNAL")
        self._journal = journal
        self._accounts = MappingProxyType(_copy_accounts(accounts))
        self._principals = MappingProxyType(_copy_principals(principals))

    def handle(
        self,
        operation: str,
        *,
        principal_ref: str,
        scope: WireScope,
        arguments: Mapping[str, object],
    ) -> Mapping[str, object]:
        """Read one bounded journal page using server-resolved ACL and scope."""

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
            _reject_unknown_arguments(arguments, frozenset({"cursor", "limit"}))
            cursor = arguments.get("cursor")
            limit = arguments.get("limit", _DEFAULT_READ_LIMIT)
            _validate_read_arguments(cursor, limit, cursor_allowed=True)
            batch = self._journal.read_after(
                principal,
                account.journal_account_scope,
                journal_strategy_scope,
                cursor=cursor,  # type: ignore[arg-type] -- validated above.
                limit=limit,  # type: ignore[arg-type] -- validated above.
            )
            return _batch_result(batch, include_snapshot_source=False)

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
            return _batch_result(batch, include_snapshot_source=True)

        _reject_unknown_arguments(arguments, frozenset())
        batch = self._journal.read_after(
            principal,
            account.journal_account_scope,
            journal_strategy_scope,
            cursor=None,
            limit=1,
        )
        return MappingProxyType({"latest_cursor": batch.latest_cursor})

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
