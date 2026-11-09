"""Trusted local dispatch bridge; not authentication or an account owner.

The guard is held by the caller and is never released here. The injected native
port must honor the SDK durable pre-dispatch marker and may call the venue only
after commit returns that marker. This module does not prove provider facts.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, ExitStack, contextmanager, nullcontext
from dataclasses import dataclass
from typing import Any

from bt_api_base.direct_write_protocol import NativeOrderIdentity, PreDispatchRecord, WriteOperation
from bt_api_base.gateway_direct_protocol import (
    GatewayDirectProtocolError,
    validate_gateway_native_identity,
)

from .direct_command_journal import DirectCommandRecord, GatewayDirectCommandJournal, _json
from .session_guard import LocalAccountSessionGuard


class DirectDispatchError(RuntimeError):
    """Finite local dispatch failure with no implied provider outcome."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


ScopeRecheck = Callable[[], None]
RequestFence = Callable[[DirectCommandRecord], AbstractContextManager[ScopeRecheck | None]]


@contextmanager
def _request_scope(
    fence: RequestFence | None, row: DirectCommandRecord
) -> Iterator[ScopeRecheck | None]:
    """Never allow an injected context manager to suppress a denied operation."""
    scope = nullcontext() if fence is None else fence(row)
    recheck = scope.__enter__()
    try:
        if recheck is not None and not callable(recheck):
            raise DirectDispatchError("INVALID_REQUEST_FENCE")
        yield recheck
    except BaseException as exc:
        scope.__exit__(type(exc), exc, exc.__traceback__)
        raise
    else:
        scope.__exit__(None, None, None)


@dataclass(frozen=True)
class NativeDispatchOutcome:
    """Explicit adapter result; no SDK/provider type is implicitly trusted."""

    sent: bool | None
    identity: NativeOrderIdentity | None
    marker_id: str | None
    error_code: str | None = None

    def __post_init__(self) -> None:
        if self.sent is not None and type(self.sent) is not bool:
            raise ValueError("invalid sent outcome")
        if self.identity is not None and type(self.identity) is not NativeOrderIdentity:
            raise ValueError("invalid identity")
        for item in (self.marker_id, self.error_code):
            if item is not None and (
                type(item) is not str or not item or item != item.strip() or len(item) > 256
            ):
                raise ValueError("invalid outcome field")


def _identity(identity: NativeOrderIdentity, route: str) -> dict[str, object]:
    if type(identity) is not NativeOrderIdentity or identity.exchange_name != route:
        raise DirectDispatchError("IDENTITY_INVALID")
    try:
        validate_gateway_native_identity(identity)
    except GatewayDirectProtocolError:
        raise DirectDispatchError("IDENTITY_INVALID") from None
    try:
        fields_json = _json(dict(identity.fields))
    except Exception:
        raise DirectDispatchError("IDENTITY_INVALID") from None
    return {
        "exchange_name": identity.exchange_name,
        "client_order_id": identity.client_order_id,
        "session_generation": identity.session_generation,
        "fields_json": fields_json,
    }


def _request(payload_json: str) -> dict[str, object]:
    try:
        value = json.loads(payload_json)
    except (TypeError, ValueError):
        raise DirectDispatchError("PAYLOAD_INVALID") from None
    if (
        type(value) is not dict
        or not value
        or any(item is not None and type(item) not in (str, int, bool) for item in value.values())
    ):
        raise DirectDispatchError("PAYLOAD_UNSUPPORTED")
    symbol = value.get("symbol")
    if type(symbol) is not str or not symbol or symbol != symbol.strip():
        raise DirectDispatchError("PAYLOAD_UNSUPPORTED")
    return value


class GatewayDirectDispatcher:
    """One guard-bound thread's trusted local bridge to SDK dispatch.

    Principal is only a journal label. External owner supplies authenticated
    scope, provider-specific identity keys, admission, and actual native port.
    """

    def __init__(
        self,
        journal: GatewayDirectCommandJournal,
        exchange_name: str,
        guard: LocalAccountSessionGuard,
        native_place: Callable[[dict[str, object], Any, str], NativeDispatchOutcome],
        identity_keys: Callable[[NativeOrderIdentity], tuple[str, ...]],
        assert_admitted: Callable[[DirectCommandRecord], object],
    ) -> None:
        if (
            type(journal) is not GatewayDirectCommandJournal
            or type(guard) is not LocalAccountSessionGuard
        ):
            raise DirectDispatchError("INVALID_COMPOSITION")
        if (
            type(exchange_name) is not str
            or not exchange_name
            or exchange_name != exchange_name.strip()
            or len(exchange_name) > 256
        ):
            raise DirectDispatchError("INVALID_COMPOSITION")
        if not all(callable(x) for x in (native_place, identity_keys, assert_admitted)):
            raise DirectDispatchError("INVALID_COMPOSITION")
        if (
            hashlib.sha256(journal.account_scope.encode("utf-8")).hexdigest()
            != guard.account_key_digest
        ):
            raise DirectDispatchError("ACCOUNT_SCOPE_MISMATCH")
        guard.assert_owned()
        self._guard_generation = guard.acquire()
        if self._guard_generation != journal.generation:
            raise DirectDispatchError("GENERATION_MISMATCH")
        self._journal = journal
        self._exchange = exchange_name
        self._guard = guard
        self._native_place = native_place
        self._identity_keys = identity_keys
        self._admission = assert_admitted
        self._active = False
        guard.bind_consumer(self)

    @property
    def journal(self) -> GatewayDirectCommandJournal:
        """Return the exact journal object bound to this dispatcher."""
        return self._journal

    def is_bound_to(self, journal: object, guard: object, exchange_name: object) -> bool:
        """Check exact owner-thread composition without exposing mutable resources."""
        self._owned()
        return self._journal is journal and self._guard is guard and self._exchange == exchange_name

    def assert_owned(self) -> None:
        """Verify the creating process and thread still hold the same guard generation."""
        self._owned()

    def _owned(self) -> None:
        self._guard.assert_owned()
        if self._guard.acquire() != self._guard_generation:
            raise DirectDispatchError("GUARD_GENERATION_CHANGED")

    def _admitted(self, row: DirectCommandRecord) -> None:
        try:
            admitted = self._admission(row)
        except Exception:
            raise DirectDispatchError("ADMISSION_DENIED") from None
        if admitted is not True:
            raise DirectDispatchError("ADMISSION_DENIED")

    def dispatch(
        self,
        strategy: str,
        request_key: str,
        principal: str,
        reservation_id: str,
        digest: str,
        expected_version: int,
        *,
        request_fence: RequestFence | None = None,
        delegation_permit: object | None = None,
        market_gate: object | None = None,
        market_permit: object | None = None,
    ) -> DirectCommandRecord:
        if request_fence is not None and not callable(request_fence):
            raise DirectDispatchError("INVALID_REQUEST_FENCE")
        if ((market_gate is None) != (market_permit is None)
                or (market_gate is not None and (request_fence is None
                    or not all(callable(getattr(market_gate, name, None)) for name in
                               ('dispatch_fence', 'native_fence', 'recheck', 'native_recheck', 'matches_delegation'))
                    or market_gate.matches_delegation(market_permit, delegation_permit) is not True))):
            raise DirectDispatchError('INVALID_MARKET_GATE')
        if delegation_permit is not None:
            from .direct_delegation import GatewayDelegationPermit
            if (type(delegation_permit) is not GatewayDelegationPermit
                    or delegation_permit.operation != "direct.dispatch" or request_fence is None):
                raise DirectDispatchError("INVALID_DELEGATION")
            cmd = delegation_permit.command
            if (cmd.account_scope != self._journal.account_scope or cmd.strategy_scope != strategy
                    or cmd.request_key != request_key or cmd.actor_principal != principal
                    or cmd.payload_digest != digest):
                raise DirectDispatchError("INVALID_DELEGATION")
            # A parent recheck requires the journal.  The native provider can
            # invoke its last recheck while holding its trading-session lock;
            # acquiring the journal there would invert the journal -> session
            # lock order used by admission.  Until there is a bounded owner
            # fence spanning that boundary, do not write a dispatch marker.
            if market_gate is not None and cmd.parent_ref is not None:
                raise DirectDispatchError("PARENT_NATIVE_FENCE_UNAVAILABLE")
        self._owned()
        if self._active:
            raise DirectDispatchError("DISPATCH_REENTRANT")
        row = self._journal.get(strategy, request_key, principal)
        if row.reservation_id != reservation_id or row.digest != digest:
            raise DirectDispatchError("REQUEST_CONFLICT")
        if delegation_permit is not None:
            # Re-observation of an already dispatched/expired command still
            # requires current authority and the original persisted envelope.
            with _request_scope(request_fence, row) as recheck:
                with self._journal._transaction() as db:
                    saved = db.execute(
                        "SELECT envelope_json,envelope_digest FROM direct_delegated_commands "
                        "WHERE account=? AND strategy=? AND request_key=?",
                        (self._journal.account_scope, strategy, request_key),
                    ).fetchone()
                    cmd = delegation_permit.command
                    if (saved is None or saved["envelope_json"] != cmd.canonical_json
                            or saved["envelope_digest"] != cmd.digest):
                        raise DirectDispatchError("INVALID_DELEGATION")
                    delegation_permit.recheck(db)
                    if recheck is not None:
                        recheck()
                    delegation_permit.recheck(db)
        if row.status != "RESERVED":
            return row
        row = self._journal.expire(strategy, request_key, principal)
        if row.status != "RESERVED":
            return row
        if type(expected_version) is not int or row.version != expected_version:
            raise DirectDispatchError("VERSION_CONFLICT")
        # A durable reservation is not yet a dispatch authorization.  Until
        # every authority that can affect an order participates in the same
        # single-use, nonblocking native claim, do not write a dispatch marker
        # or enter any injected native provider.  In particular, forwarding the
        # old native_fence would hold Registry and market locks over native I/O.
        raise DirectDispatchError("DISPATCH_CLAIM_UNAVAILABLE")
        payload = _request(row.payload_json)
        self._active = True
        try:
            with _request_scope(request_fence, row):
                self._owned()
                self._admitted(row)
                self._owned()
            port = _CommitPort(self, row, request_fence, delegation_permit, market_gate, market_permit)
            try:
                outcome = self._native_place(payload, port, self._journal.account_scope)
            except Exception:
                outcome = None
            finally:
                port.close()
            self._owned()
            current = port.current_after_attempt()
            if current is None:
                raise DirectDispatchError("PRE_DISPATCH_FAILED")
            # A commit followed by a missing, malformed or mismatched reply is
            # UNKNOWN, including a lost commit reply before SDK can send.
            result = "UNKNOWN"
            if type(outcome) is NativeDispatchOutcome and outcome.marker_id == reservation_id:
                try:
                    matching = (
                        outcome.identity is not None
                        and _identity(outcome.identity, self._exchange) == port.identity
                    )
                except Exception:
                    matching = False
                if matching and outcome.sent is True:
                    result = "SENT"
                elif matching and outcome.sent is False:
                    result = "NOT_SENT"
            self._owned()
            try:
                return self._journal.finish(
                    strategy,
                    request_key,
                    reservation_id,
                    digest,
                    principal,
                    current.version,
                    port.identity,
                    port.keys,
                    result,
                )
            except Exception:
                raise DirectDispatchError("FINISH_FAILED") from None
        finally:
            self._active = False


class _CommitPort:
    """One-use commit port; only a newly committed row yields a marker."""

    def __init__(
        self,
        owner: GatewayDirectDispatcher,
        record: DirectCommandRecord,
        request_fence: RequestFence | None,
        delegation_permit: object | None,
        market_gate: object | None,
        market_permit: object | None,
    ) -> None:
        self._owner = owner
        self._record = record
        self._request_fence = request_fence
        self._delegation_permit = delegation_permit
        self._market_gate, self._market_permit = market_gate, market_permit
        self.identity: dict[str, object] | None = None
        self.keys: tuple[str, ...] = ()
        self.prepared_digest: str | None = None
        self._attempted = False
        self._known_not_new = False
        self._closed = False

    def close(self) -> None:
        self._closed = True

    @contextmanager
    def native_fence(self):
        """Hold current trusted market evidence around the final native call."""
        if self._closed or not self._owner._active:
            raise DirectDispatchError('COMMIT_CLOSED')
        if self._market_gate is None:
            yield None
            return
        with _request_scope(self._request_fence, self._record) as recheck:
            if recheck is None:
                raise DirectDispatchError('INVALID_REQUEST_FENCE')
            with self._market_gate.native_fence(self._market_permit, self._record):
                def final_recheck():
                    self._owner._owned()
                    self._owner._admitted(self._record)
                    recheck()
                    if self._delegation_permit is not None:
                        if self._market_gate.matches_delegation(self._market_permit, self._delegation_permit) is not True:
                            raise DirectDispatchError('INVALID_DELEGATION')
                        if self._delegation_permit.command.parent_ref is not None:
                            raise DirectDispatchError('PARENT_NATIVE_FENCE_UNAVAILABLE')
                        # Non-parent grants do not require a journal-backed
                        # authority check. Registry is held by the outer scope.
                        self._delegation_permit.recheck(None)
                    recheck()
                    self._market_gate.native_recheck(self._market_permit, self._record)
                final_recheck()
                yield final_recheck

    def commit(self, record: PreDispatchRecord) -> str | None:
        self._owner._owned()
        if self._closed or not self._owner._active:
            raise DirectDispatchError("COMMIT_CLOSED")
        if self._attempted:
            raise DirectDispatchError("COMMIT_REUSED")
        self._attempted = True
        if type(record) is not PreDispatchRecord or record.identity is None:
            raise DirectDispatchError("COMMIT_RECORD_INVALID")
        try:
            record.to_dict()  # Revalidate any sealed prepared value before persistence.
        except Exception:
            raise DirectDispatchError("COMMIT_RECORD_INVALID") from None
        # This injected projection must be pure; do it before the short fence.
        try:
            keys = self._owner._identity_keys(record.identity)
        except Exception:
            raise DirectDispatchError("IDENTITY_INVALID") from None
        with ExitStack() as stack:
            recheck = stack.enter_context(_request_scope(self._request_fence, self._record))
            if self._market_gate is not None:
                stack.enter_context(self._market_gate.dispatch_fence(self._market_permit, self._record))
            self._owner._owned()
            if (
                record.operation is not WriteOperation.PLACE
                or record.exchange_name != self._owner._exchange
                or record.host_scope != self._owner._journal.account_scope
                or record.target_identity is not None
                or record.session_generation != record.identity.session_generation
                or record.symbol != _request(self._record.payload_json)["symbol"]
            ):
                raise DirectDispatchError("COMMIT_RECORD_INVALID")
            try:
                summary = _json(dict(record.request_summary))
            except Exception:
                raise DirectDispatchError("COMMIT_RECORD_INVALID") from None
            if summary != self._record.payload_json:
                raise DirectDispatchError("REQUEST_CONFLICT")
            identity = _identity(record.identity, self._owner._exchange)
            current = self._owner._journal.get(
                self._record.strategy_scope, self._record.request_key, self._record.principal
            )
            if current != self._record:
                raise DirectDispatchError("REQUEST_CONFLICT")
            self._owner._admitted(current)
            self._owner._owned()
            self.identity, self.keys = identity, keys
            self.prepared_digest = (
                None if record.prepared_place is None else record.prepared_place.digest()
            )

            def before_dispatch() -> None:
                # Lock order: request fence (registry) -> journal SQLite.
                # This recheck performs no provider I/O and does not reenter the fence.
                self._owner._owned()
                self._owner._admitted(current)
                self._owner._owned()
                if recheck is not None:
                    recheck()
                if self._market_gate is not None:
                    self._market_gate.recheck(self._market_permit, current)

            def before_commit() -> None:
                before_dispatch()

            result = self._owner._journal.begin_dispatch(
                current.strategy_scope,
                current.request_key,
                current.reservation_id,
                current.digest,
                current.principal,
                current.version,
                identity,
                keys,
                before_dispatch=before_dispatch,
                before_commit=before_commit,
                prepared_place=record.prepared_place,
                delegation_permit=self._delegation_permit,
                # The enclosing request scope already holds the Registry
                # fence through the journal commit; it cannot be re-entered.
                delegation_fence=nullcontext if self._delegation_permit is not None else None,
            )
            if not result.newly_started:
                self._known_not_new = True
        if self._known_not_new:
            return None
        return current.reservation_id

    def current_after_attempt(self) -> DirectCommandRecord | None:
        if self.identity is None or self._known_not_new:
            return None
        row = self._owner._journal.get(
            self._record.strategy_scope, self._record.request_key, self._record.principal
        )
        if self.prepared_digest is not None:
            prepared = self._owner._journal.get_prepared_place(self._record.reservation_id)
            if prepared is None or prepared.digest() != self.prepared_digest:
                return None
        if (
            row.status != "DISPATCHING"
            or row.reservation_id != self._record.reservation_id
            or row.version != self._record.version + 1
            or row.native_identity_json != _json(self.identity)
            or row.strong_identity_keys != self.keys
        ):
            return None
        return row
