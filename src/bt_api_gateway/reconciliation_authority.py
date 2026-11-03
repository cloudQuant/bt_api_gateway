"""Owner-local reconciliation inspection; not a wire or ledger authority.

The injected continuity and grant ports are trusted server assembly, never
wire arguments. No current built-in provider supplies the continuity port.
Provider and journal state have no shared transaction: repeated checks can
detect changes, but cannot fence an in-flight provider event or remote action.
The returned opaque handle therefore cannot be used as an authorization
token or a substitute for a dispatch fence.

``position_report(candidate)`` (iteration 60, acceptance G2) rechecks a
handle and returns the inspected full-account rows as *reconciliation
evidence* for the strategy ledger: the rows of the verified full-position
receipt at the journal cut, the provider observation time and a validity
that never outlives the shortest of the receipt, stream binding, grant and
account-binding leases. It is evidence for comparing books, bounded in time;
it does not fence in-flight provider events (the ledger's in-flight window
and freshness rules still apply) and grants no write authority.
"""

from __future__ import annotations

import json
import threading
import time
import weakref
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from bt_api_base.account_protocol import AccountKey, AccountPosition, AccountResourceKey
from bt_api_base.position_bootstrap_protocol import PositionStreamBinding

from .account_position_snapshot import GatewayFullPositionSnapshotReceipt
from .account_session_worker import GatewayAccountSessionWorker
from .router import GatewayCommandKind, GatewayPrincipal


class GatewayReconciliationInspectionError(RuntimeError):
    """Finite, payload-free reason that an inspection is unavailable."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PositionContinuityPort(Protocol):
    """Trusted host adapter, not a client-supplied verifier or proof DTO.

    ``projection`` checks its source subscription and lease on every call.
    ``assert_receipt_binding`` independently verifies the exact owner receipt
    and the original source snapshot/cut using provider-owned evidence.
    Matching strings or a self-reported object do not establish that binding.
    """

    def projection(self) -> Any: ...

    def assert_receipt_binding(
        self, receipt: GatewayFullPositionSnapshotReceipt, projection: Any
    ) -> bool: ...


class ReconciliationGrantPort(Protocol):
    """Live server-owned grant check for one authenticated account principal.

    The server must never reuse a revision after revoking or changing the
    grant. A revision string supplied by a wire client is not a grant.
    """

    def current_grant(
        self, principal: GatewayPrincipal, account_ref: str, now_ns: int
    ) -> tuple[str, int]: ...


class ReconciliationAccountBindingPort(Protocol):
    """Trusted registry validates the exact account identity and journal route.

    This must consult an independently owned registration, not echo the supplied
    arguments. Revisions cannot be reused after changing or revoking a binding.
    """

    def current_binding(
        self,
        account_ref: str,
        account_key: AccountKey,
        journal_account_scope: str,
        state_scope: str,
        now_ns: int,
    ) -> tuple[str, int]: ...


class GatewayReconciliationCandidate:
    """Opaque, server-local handle with no wire or account-report conversion."""

    __slots__ = ("_issuer", "__weakref__")

    def __init__(self, issuer: GatewayReconciliationInspector) -> None:
        self._issuer = issuer

    def assert_current(self) -> None:
        """Recheck this handle; this does not fence a subsequent action."""
        self._issuer._assert_current(self)


class GatewayReconciliationInspector:
    """Check an owner receipt, verified stream, live grant and journal cut.

    ``principals`` is a server-owned reconciliation allowlist mapping a
    principal id to its exact registered principal object and a server-derived
    journal consumer ref. ``required_resources`` is the server-configured
    account universe; the continuity adapter must verify full provider scope
    independently, including the resources with no position rows.
    """

    def __init__(
        self,
        worker: GatewayAccountSessionWorker,
        continuity: PositionContinuityPort,
        grants: ReconciliationGrantPort,
        *,
        account_ref: str,
        required_resources: tuple[AccountResourceKey, ...],
        principals: Mapping[str, tuple[GatewayPrincipal, str]],
        account_bindings: ReconciliationAccountBindingPort | None = None,
        clock_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        if type(worker) is not GatewayAccountSessionWorker:
            raise GatewayReconciliationInspectionError("WORKER_INVALID")
        worker._check_owner()
        if not callable(getattr(continuity, "projection", None)) or not callable(
            getattr(continuity, "assert_receipt_binding", None)
        ):
            raise GatewayReconciliationInspectionError("CONTINUITY_PORT_INVALID")
        if not callable(getattr(grants, "current_grant", None)) or not callable(clock_ns):
            raise GatewayReconciliationInspectionError("GRANT_PORT_INVALID")
        if not callable(getattr(account_bindings, "current_binding", None)):
            raise GatewayReconciliationInspectionError("ACCOUNT_BINDING_PORT_INVALID")
        if type(account_ref) is not str or not account_ref or account_ref != account_ref.strip():
            raise GatewayReconciliationInspectionError("ACCOUNT_REF_INVALID")
        if (
            type(required_resources) is not tuple
            or not required_resources
            or any(type(resource) is not AccountResourceKey for resource in required_resources)
            or len(set(required_resources)) != len(required_resources)
            or frozenset(required_resources) != frozenset(worker.required_coverage)
        ):
            raise GatewayReconciliationInspectionError("RESOURCE_UNIVERSE_INVALID")
        if not isinstance(principals, Mapping) or not principals:
            raise GatewayReconciliationInspectionError("PRINCIPALS_INVALID")
        copied = {}
        for principal_id, entry in principals.items():
            if (
                type(principal_id) is not str
                or type(entry) is not tuple
                or len(entry) != 2
                or type(entry[0]) is not GatewayPrincipal
                or entry[0].principal_id != principal_id
                or type(entry[1]) is not str
                or not entry[1]
                or entry[1] != entry[1].strip()
                or worker.journal_account_scope not in entry[0].account_scopes
                or worker.state_scope not in entry[0].strategy_scopes
                or GatewayCommandKind.READ not in entry[0].allowed_kinds
            ):
                raise GatewayReconciliationInspectionError("PRINCIPALS_INVALID")
            copied[principal_id] = entry
        self._worker = worker
        self._owner_thread = threading.get_ident()
        self._continuity = continuity
        self._grants = grants
        self._account_bindings = account_bindings
        self._account_ref = account_ref
        self._resources = frozenset(required_resources)
        self._principals = copied
        self._clock = clock_ns
        self._last_ns = 0
        self._last_evidence: dict[str, Any] | None = None
        self._issued: weakref.WeakKeyDictionary[GatewayReconciliationCandidate, tuple] = (
            weakref.WeakKeyDictionary()
        )

    def inspect(self, principal: GatewayPrincipal) -> GatewayReconciliationCandidate:
        """Inspect only for the exact server-registered principal object."""
        self._check_owner()
        if type(principal) is not GatewayPrincipal:
            raise GatewayReconciliationInspectionError("PRINCIPAL_DENIED")
        entry = self._principals.get(principal.principal_id)
        if entry is None or entry[0] is not principal:
            raise GatewayReconciliationInspectionError("PRINCIPAL_DENIED")
        first = self._sample(principal, entry[1])
        if self._sample(principal, entry[1]) != first:
            raise GatewayReconciliationInspectionError("INSPECTION_CHANGED")
        candidate = GatewayReconciliationCandidate(self)
        self._issued[candidate] = (principal, entry[1], first, self._last_evidence)
        return candidate

    def position_report(self, candidate: GatewayReconciliationCandidate) -> dict[str, Any]:
        """Recheck ``candidate`` and return its bounded reconciliation evidence."""
        self._assert_current(candidate)
        evidence = self._issued[candidate][3]
        if evidence is None:
            raise GatewayReconciliationInspectionError("INSPECTION_UNKNOWN")
        now = self._now()
        if evidence["valid_until_ns"] <= now:
            raise GatewayReconciliationInspectionError("INSPECTION_EXPIRED")
        return dict(evidence, positions=list(evidence["positions"]))

    def _assert_current(self, candidate: GatewayReconciliationCandidate) -> None:
        self._check_owner()
        entry = self._issued.get(candidate)
        if entry is None:
            raise GatewayReconciliationInspectionError("INSPECTION_UNKNOWN")
        principal, consumer_ref, original, _evidence = entry
        current = self._principals.get(principal.principal_id)
        if current is None or current[0] is not principal or current[1] != consumer_ref:
            raise GatewayReconciliationInspectionError("PRINCIPAL_DENIED")
        try:
            if self._sample(principal, consumer_ref) != original:
                raise GatewayReconciliationInspectionError("INSPECTION_CHANGED")
        except Exception:
            # An invalidated handle never becomes current again after a
            # reconnect, authorization restoration or data reversal.
            self._issued.pop(candidate, None)
            raise

    def _check_owner(self) -> None:
        if threading.get_ident() != self._owner_thread:
            raise GatewayReconciliationInspectionError("WRONG_OWNER_THREAD")

    def _now(self) -> int:
        try:
            value = self._clock()
        except Exception:
            raise GatewayReconciliationInspectionError("CLOCK_INVALID") from None
        if type(value) is not int or value <= 0 or value < self._last_ns:
            raise GatewayReconciliationInspectionError("CLOCK_INVALID")
        self._last_ns = value
        return value

    def _grant(self, principal: GatewayPrincipal, now: int) -> tuple[str, int]:
        try:
            grant = self._grants.current_grant(principal, self._account_ref, now)
        except Exception:
            raise GatewayReconciliationInspectionError("GRANT_UNAVAILABLE") from None
        if (
            type(grant) is not tuple
            or len(grant) != 2
            or type(grant[0]) is not str
            or not grant[0]
            or grant[0] != grant[0].strip()
            or type(grant[1]) is not int
            or grant[1] <= now
        ):
            raise GatewayReconciliationInspectionError("GRANT_UNAVAILABLE")
        return grant

    def _sample(self, principal: GatewayPrincipal, consumer_ref: str) -> tuple:
        now = self._now()
        grant = self._grant(principal, now)
        account_binding = self._account_binding(now)
        try:
            receipt = self._worker.read_full_position_snapshot_receipt()
            if type(receipt) is not GatewayFullPositionSnapshotReceipt:
                raise ValueError
            receipt.assert_current()
            projection = self._continuity.projection()
            if self._continuity.assert_receipt_binding(receipt, projection) is not True:
                raise ValueError
        except Exception:
            raise GatewayReconciliationInspectionError("SOURCE_UNAVAILABLE") from None
        try:
            binding = projection.binding
            positions = projection.positions
            if (
                type(binding) is not PositionStreamBinding
                or binding.account_key != receipt.account_key
                or receipt.account_key != self._worker.account_key
                or binding.account_ref != self._account_ref
                or binding.session_ref != receipt.session_generation
                or binding.valid_until_ns <= now
                or receipt.valid_until_ns <= now
                or frozenset(receipt.observation.coverage) != self._resources
                or projection.snapshot_receipt_ref != receipt.coverage.snapshot_version
                or type(projection.snapshot_cut_sequence) is not int
                or projection.snapshot_cut_sequence < 0
                or type(projection.sequence) is not int
                or projection.sequence != projection.snapshot_cut_sequence
                or projection.observed_ns != receipt.coverage.observed_at_ns
                or projection.observed_ns > now
                or type(positions) is not tuple
                or any(type(row) is not AccountPosition for row in positions)
                or _rows(positions) != _rows(receipt.observation.positions)
            ):
                raise ValueError
        except Exception:
            raise GatewayReconciliationInspectionError("SOURCE_BINDING_MISMATCH") from None

        try:
            batch, progress = self._worker.journal.inspect_reconciliation_cut(
                principal,
                self._worker.journal_account_scope,
                self._worker.state_scope,
                consumer_ref,
            )
            if (
                batch.snapshot is None
                or batch.snapshot != self._worker.latest_snapshot
                or batch.events
                or batch.next_cursor != receipt.snapshot_cursor
                or batch.latest_cursor != receipt.snapshot_cursor
                or progress.offered_cursor != receipt.snapshot_cursor
                or progress.acknowledged_cursor != receipt.snapshot_cursor
            ):
                raise ValueError
            receipt.assert_current()
            latest = self._continuity.projection()
            if (
                _projection_key(latest) != _projection_key(projection)
                or self._continuity.assert_receipt_binding(receipt, latest) is not True
            ):
                raise ValueError
            finished = self._now()
            if (
                finished >= binding.valid_until_ns
                or finished >= receipt.valid_until_ns
                or self._grant(principal, finished) != grant
                or self._account_binding(finished) != account_binding
            ):
                raise ValueError
        except Exception:
            raise GatewayReconciliationInspectionError("JOURNAL_OR_GRANT_UNAVAILABLE") from None
        self._last_evidence = {
            "account_ref": self._account_ref,
            "positions": tuple(row.to_dict() for row in positions),
            "observed_ns": projection.observed_ns,
            "valid_until_ns": min(
                binding.valid_until_ns, receipt.valid_until_ns, grant[1], account_binding[1]
            ),
            "snapshot_cursor": receipt.snapshot_cursor,
            "stream_epoch": progress.stream_epoch,
            "receipt_fingerprint": receipt.fingerprint,
            "grant_revision": grant[0],
        }
        return (
            receipt.fingerprint,
            _projection_key(projection),
            progress.stream_epoch,
            receipt.snapshot_cursor,
            grant,
            account_binding,
        )

    def _account_binding(self, now: int) -> tuple[str, int]:
        try:
            binding = self._account_bindings.current_binding(
                self._account_ref,
                self._worker.account_key,
                self._worker.journal_account_scope,
                self._worker.state_scope,
                now,
            )
        except Exception:
            raise GatewayReconciliationInspectionError("ACCOUNT_BINDING_UNAVAILABLE") from None
        if (
            type(binding) is not tuple
            or len(binding) != 2
            or type(binding[0]) is not str
            or not binding[0]
            or binding[0] != binding[0].strip()
            or type(binding[1]) is not int
            or binding[1] <= now
        ):
            raise GatewayReconciliationInspectionError("ACCOUNT_BINDING_UNAVAILABLE")
        return binding


def _projection_key(projection: Any) -> tuple:
    binding = projection.binding
    binding_key = json.dumps(
        {
            "account_key": binding.account_key.to_dict(),
            "account_ref": binding.account_ref,
            "route_ref": binding.route_ref,
            "session_ref": binding.session_ref,
            "connection_epoch": binding.connection_epoch,
            "subscription_epoch": binding.subscription_epoch,
            "subscription_ready_ref": binding.subscription_ready_ref,
            "valid_until_ns": binding.valid_until_ns,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return (
        binding_key,
        projection.snapshot_receipt_ref,
        projection.snapshot_cut_sequence,
        projection.sequence,
        projection.observed_ns,
        _rows(projection.positions),
    )


def _rows(rows: tuple[AccountPosition, ...]) -> tuple[str, ...]:
    return tuple(
        sorted(json.dumps(row.to_dict(), sort_keys=True, separators=(",", ":")) for row in rows)
    )


__all__ = [
    "GatewayReconciliationCandidate",
    "GatewayReconciliationInspectionError",
    "GatewayReconciliationInspector",
    "PositionContinuityPort",
    "ReconciliationAccountBindingPort",
    "ReconciliationGrantPort",
]
