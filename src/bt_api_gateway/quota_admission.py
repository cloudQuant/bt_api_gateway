"""Cross-process provider quota admission for one trusted Gateway owner.

The SQLite file is a local coordination journal, not account state. All
processes that share a provider quota domain on one host must use the same
file and the same ``quota_domain_ref``. The file must live on local storage;
network filesystems and independent per-node copies do not provide a shared
quota owner. Only opaque identifiers and quota events are persisted; provider
credentials never enter this module.

Each grant consumes one slot even if the provider call later fails. Ordinary
work is limited to ``capacity_per_window - reserved_capacity``. Risk CLOSE,
cancellation, reconciliation, and accepted-group actions may use the reserved
slots. Risk/Execution callers share one provider-neutral callback and one quota
owner rather than creating independent limiters.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import math
import os
import re
import sqlite3
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Optional, Union

from bt_api_base.exceptions import RateLimitError

from .database_identity import GatewayDatabaseIdentityError, SQLiteFileIdentity

_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CRITICAL_OPERATIONS = frozenset(
    {"close", "cancel", "reconcile", "accepted_group_action"}
)
_OPTIONAL_PROVIDER_READS = frozenset(
    {
        "read_account_configuration",
        "read_exchange_server_time",
        "read_instrument_metadata",
    }
)
_NANOSECONDS = 1_000_000_000
_MAX_QUEUE = 65_536
_MAX_CAPACITY = 1_000_000
_MAX_PROVIDER_CALL_TIMEOUT_SECONDS = 86_400.0


def _is_sqlite_busy(exc: sqlite3.OperationalError) -> bool:
    """Identify SQLite lock-acquisition conflicts across supported runtimes."""

    error_code = getattr(exc, "sqlite_errorcode", None)
    busy_codes = {
        getattr(sqlite3, "SQLITE_BUSY", 5),
        getattr(sqlite3, "SQLITE_LOCKED", 6),
    }
    if isinstance(error_code, int):
        return (error_code & 0xFF) in busy_codes
    # Python 3.9 exposes no sqlite_errorcode attribute. Keep only SQLite's
    # canonical lock messages as a compatibility fallback, never a substring
    # match against arbitrary operational errors.
    return str(exc).lower() in {
        "database is locked",
        "database table is locked",
        "database schema is locked",
    }


class GatewayQuotaOperation(str, Enum):
    """Finite provider operation classes understood by the quota owner."""

    LOGIN = "login"
    RECONNECT = "reconnect"
    SUBSCRIBE = "subscribe"
    QUERY = "query"
    CTP_QUERY = "ctp_query"
    OPEN = "open"
    CLOSE = "close"
    CANCEL = "cancel"
    RECONCILE = "reconcile"
    ACCEPTED_GROUP_ACTION = "accepted_group_action"


class GatewayQuotaAdmissionError(RuntimeError):
    """Value-free admission failure safe to pass through service boundaries."""

    _CODES = frozenset(
        {
            "INVALID_CONFIGURATION",
            "DOMAIN_CONFIGURATION_MISMATCH",
            "INVALID_SUBJECT",
            "INVALID_OPERATION",
            "INVALID_DEADLINE",
            "DEADLINE_EXCEEDED",
            "QUEUE_FULL",
            "OWNER_UNAVAILABLE",
            "CLOCK_EPOCH_RESET",
            "INVALID_RATE_LIMIT_BACKOFF",
            "DOMAIN_IDENTITY_CHANGED",
            "SESSION_OWNERSHIP_UNAVAILABLE",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "OWNER_UNAVAILABLE"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class GatewayQuotaSubject:
    """Non-secret request identity; run metadata does not split fairness buckets."""

    account_ref: str
    strategy_ref: Optional[str] = None  # noqa: UP045 -- Gateway package supports Python 3.9.
    instrument_ref: Optional[str] = None  # noqa: UP045 -- Gateway package supports Python 3.9.
    run_ref: Optional[str] = None  # noqa: UP045 -- Gateway package supports Python 3.9.

    def __post_init__(self) -> None:
        if not _valid_ref(self.account_ref):
            raise GatewayQuotaAdmissionError("INVALID_SUBJECT")
        if self.strategy_ref is not None and not _valid_ref(self.strategy_ref):
            raise GatewayQuotaAdmissionError("INVALID_SUBJECT")
        if self.instrument_ref is not None and not _valid_ref(self.instrument_ref):
            raise GatewayQuotaAdmissionError("INVALID_SUBJECT")
        if self.run_ref is not None and not _valid_ref(self.run_ref):
            raise GatewayQuotaAdmissionError("INVALID_SUBJECT")


@dataclass(frozen=True, slots=True)
class GatewayQuotaGrant:
    """Finite receipt for a consumed provider quota slot."""

    grant_id: str
    operation: GatewayQuotaOperation
    sequence: int
    granted_monotonic_ns: int
    subject_digest: str
    run_digest: Optional[str]


@dataclass(frozen=True, slots=True)
class _WaitWakeSnapshot:
    """Immutable committed facts for calculating an advisory wake hint."""

    waiters: tuple[tuple[object, ...], ...]
    request_id: str
    now_ns: int
    base_wake_ns: int
    grant_count: int
    grant_sequence: int
    capacity: int
    reserved_capacity: int
    projected_now_ns: int
    deadline_monotonic_ns: int
    poll_interval_ns: int
    next_quota_event_ns: Optional[int]  # noqa: UP045 -- Gateway package supports Python 3.9.


def _subject_queue_candidate(
    queue: list[tuple[str, str, int, int]],
    *,
    grant_count: int,
    capacity: int,
    reserved_capacity: int,
) -> Optional[tuple[str, str, int, int]]:  # noqa: UP045 -- Python 3.9.
    """Select this subject's ticket head, with only the reserved critical bypass."""

    if not queue:
        return None

    regular_limit = capacity - reserved_capacity
    head = queue[0]
    head_is_critical = head[1] in _CRITICAL_OPERATIONS
    head_limit = capacity if head_is_critical else regular_limit
    if grant_count < head_limit:
        return head

    # A regular head keeps its place whenever regular capacity is available.
    # Only a blocked regular head may yield a subject turn to its earliest
    # critical waiter, and only while the reserved part of total capacity is
    # still available.
    if head_is_critical or grant_count >= capacity:
        return None
    return next(
        (row for row in queue[1:] if row[1] in _CRITICAL_OPERATIONS),
        None,
    )


def _virtual_waiter_rank(
    waiters: list[tuple[object, ...]],
    request_id: str,
    *,
    grant_count: int,
    grant_sequence: int,
    capacity: int,
    reserved_capacity: int,
    projected_now_ns: int,
    include_overflow: bool = False,
) -> tuple[Optional[int], Optional[int]]:  # noqa: UP045 -- Python 3.9.
    """Return an advisory rank using the same subject-head selector as admission.

    The durable snapshot is held fixed while virtual service turns advance the
    global sequence. By default it simulates only the target operation's
    currently open burst and stops at its quota threshold. With
    ``include_overflow``, it continues with a bounded advisory queue-turn rank
    at the projected eligibility snapshot; those turns only stagger rechecks
    and never represent or authorize future grants. Expiry times are projected
    by the caller from persisted grants; every wake still rechecks SQLite
    under the writer transaction.
    """

    target_row = next(
        (row for row in waiters if str(row[0]) == request_id),
        None,
    )
    if target_row is None or int(target_row[5]) <= projected_now_ns:
        return None, None

    target_operation = str(target_row[2])
    target_limit = (
        capacity
        if target_operation in _CRITICAL_OPERATIONS
        else capacity - reserved_capacity
    )
    if grant_count >= target_limit:
        return None, None

    queues: dict[str, list[tuple[str, str, int, int]]] = {}
    last_served: dict[str, int] = {}
    for row in waiters:
        if int(row[5]) <= projected_now_ns:
            continue
        request = str(row[0])
        subject = str(row[1])
        operation = str(row[2])
        ticket = int(row[3])
        last_served.setdefault(subject, int(row[4]))
        deadline = int(row[5])
        queues.setdefault(subject, []).append((request, operation, ticket, deadline))

    for queue in queues.values():
        queue.sort(key=lambda row: row[2])

    regular_limit = capacity - reserved_capacity

    def eligible_heads(count: int) -> list[tuple[int, int, str]]:
        result: list[tuple[int, int, str]] = []
        for subject, queue in queues.items():
            selected = _subject_queue_candidate(
                queue,
                grant_count=count,
                capacity=capacity,
                reserved_capacity=reserved_capacity,
            )
            if selected is not None:
                heapq.heappush(result, (last_served[subject], selected[2], subject))
        return result

    heads = eligible_heads(grant_count)

    virtual_sequence = grant_sequence
    rank = 0
    projected_grants = grant_count
    predecessor_deadline: Optional[int] = None  # noqa: UP045 -- Python 3.9.
    overflow_mode = False
    overflow_eligibility_count = max(0, target_limit - 1)
    # Only simulate the currently open burst for this request. In particular,
    # a regular request must not be ranked behind critical turns that would
    # consume reserved-only capacity after the regular threshold closes.
    while True:
        if projected_grants >= target_limit and not overflow_mode:
            if not include_overflow:
                break
            overflow_mode = True
            # Preserve each subject's position after the actual open burst,
            # then rank the queue at the target operation's next-slot
            # boundary. This keeps a critical request from being placed
            # behind regular-only heads while only reserved capacity can
            # reopen, and keeps regular requests within their own threshold.
            # The rank is only a wake hint; no grant or capacity change is
            # assumed.
            heads = eligible_heads(overflow_eligibility_count)
        if not heads:
            break

        _, selected_ticket, subject = heapq.heappop(heads)
        eligibility_count = (
            overflow_eligibility_count if overflow_mode else projected_grants
        )
        current = _subject_queue_candidate(
            queues[subject],
            grant_count=eligibility_count,
            capacity=capacity,
            reserved_capacity=reserved_capacity,
        )
        if current is None:
            continue
        if current[2] != selected_ticket:
            # A quota threshold changed since this subject was inserted in
            # the heap. Re-key its newly eligible ticket without consuming a
            # virtual service turn.
            heapq.heappush(
                heads, (last_served[subject], current[2], subject)
            )
            continue
        if current[0] == request_id:
            return rank, predecessor_deadline

        if predecessor_deadline is None or current[3] < predecessor_deadline:
            predecessor_deadline = current[3]
        rank += 1
        virtual_sequence += 1
        if not overflow_mode:
            projected_grants += 1
        last_served[subject] = virtual_sequence
        queues[subject].remove(current)
        if not overflow_mode and projected_grants == regular_limit:
            # The regular threshold changes every subject's selected ticket:
            # rebuild once so blocked regular heads can yield only to their
            # own earliest critical waiter.
            heads = eligible_heads(projected_grants)
        else:
            next_waiter = _subject_queue_candidate(
                queues[subject],
                grant_count=(
                    overflow_eligibility_count if overflow_mode else projected_grants
                ),
                capacity=capacity,
                reserved_capacity=reserved_capacity,
            )
            if next_waiter is not None:
                heapq.heappush(
                    heads, (last_served[subject], next_waiter[2], subject)
                )

    return None, predecessor_deadline


def _virtual_waiter_wake_rank(
    waiters: list[tuple[object, ...]],
    request_id: str,
    *,
    grant_count: int,
    grant_sequence: int,
    capacity: int,
    reserved_capacity: int,
    projected_now_ns: int,
) -> tuple[Optional[int], Optional[int]]:  # noqa: UP045 -- Python 3.9.
    """Use exact open-burst rank, then advisory queue-turn rank for overflow."""

    return _virtual_waiter_rank(
        waiters,
        request_id,
        grant_count=grant_count,
        grant_sequence=grant_sequence,
        capacity=capacity,
        reserved_capacity=reserved_capacity,
        projected_now_ns=projected_now_ns,
        include_overflow=True,
    )


def _ranked_wake_ns(
    now_ns: int,
    base_wake_ns: int,
    rank: Optional[int],  # noqa: UP045 -- Python 3.9.
    predecessor_deadline_ns: Optional[int],  # noqa: UP045 -- Python 3.9.
    deadline_monotonic_ns: int,
    poll_interval_ns: int,
    next_quota_event_ns: Optional[int],  # noqa: UP045 -- Python 3.9.
) -> int:
    """Spread advisory polls without letting capacity expiry erase the rank."""

    wake_ns = base_wake_ns + (
        poll_interval_ns if rank is None else rank * poll_interval_ns
    )
    wake_ns = min(wake_ns, deadline_monotonic_ns)
    if predecessor_deadline_ns is not None:
        wake_ns = min(wake_ns, predecessor_deadline_ns)
    # A known positive expiry only increases capacity; it does not invalidate
    # the queue-turn hint. Keep the stagger so every queued caller does not
    # wake on each closely spaced expiry. The writer transaction reselects
    # and rechecks all durable state after the scheduled wake.
    if (
        rank is None
        and next_quota_event_ns is not None
        and next_quota_event_ns > base_wake_ns
    ):
        wake_ns = min(wake_ns, next_quota_event_ns)
    return max(now_ns, wake_ns)


def _wake_ns_from_snapshot(snapshot: _WaitWakeSnapshot) -> int:
    """Calculate an absolute wake hint after the writer transaction closes."""

    try:
        rank, predecessor_deadline_ns = _virtual_waiter_wake_rank(
            snapshot.waiters,
            snapshot.request_id,
            grant_count=snapshot.grant_count,
            grant_sequence=snapshot.grant_sequence,
            capacity=snapshot.capacity,
            reserved_capacity=snapshot.reserved_capacity,
            projected_now_ns=snapshot.projected_now_ns,
        )
        wake_at_ns = _ranked_wake_ns(
            snapshot.now_ns,
            snapshot.base_wake_ns,
            rank,
            predecessor_deadline_ns,
            snapshot.deadline_monotonic_ns,
            snapshot.poll_interval_ns,
            snapshot.next_quota_event_ns,
        )
        return wake_at_ns
    except GatewayQuotaAdmissionError:
        raise
    except Exception:
        # Before this computation moved past transaction scope, _transaction
        # normalized unexpected helper failures to the same finite error.
        raise GatewayQuotaAdmissionError("OWNER_UNAVAILABLE") from None


class GatewayQuotaAdmission:
    """Bounded fair sliding-window admission shared by local processes.

    ``quota_domain_ref`` is a trusted, non-secret deployment label for the
    provider's shared account/API-key/IP/session budget. A distinct provider
    quota domain must use a distinct reference. Processes coordinate through
    the same local SQLite file; an unavailable file fails closed.
    """

    __slots__ = (
        "_database_path",
        "_domain_digest",
        "_capacity",
        "_window_ns",
        "_reserved_capacity",
        "_max_queue",
        "_max_queue_per_subject",
        "_max_backoff_ns",
        "_max_queue_wait_ns",
        "_poll_interval_seconds",
        "_database_identity",
    )

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        quota_domain_ref: str,
        *,
        capacity_per_window: int,
        window_seconds: float,
        reserved_capacity: int = 0,
        max_queue: int = 1024,
        max_queue_per_subject: int = 32,
        max_backoff_seconds: float = 300.0,
        max_queue_wait_seconds: float = 60.0,
        poll_interval_seconds: float = 0.025,
    ) -> None:
        try:
            if (
                type(quota_domain_ref) is not str
                or not _valid_ref(quota_domain_ref)
                or type(capacity_per_window) is not int
                or not 1 <= capacity_per_window <= _MAX_CAPACITY
                or type(reserved_capacity) is not int
                or not 0 <= reserved_capacity < capacity_per_window
                or type(max_queue) is not int
                or not 1 <= max_queue <= _MAX_QUEUE
                or type(max_queue_per_subject) is not int
                or not 1 <= max_queue_per_subject <= max_queue
            ):
                raise ValueError
            window_ns = _seconds_to_ns(window_seconds, minimum=0.01, maximum=86_400.0)
            max_backoff_ns = _seconds_to_ns(
                max_backoff_seconds, minimum=0.01, maximum=86_400.0
            )
            max_queue_wait_ns = _seconds_to_ns(
                max_queue_wait_seconds, minimum=0.01, maximum=300.0
            )
            if (
                isinstance(poll_interval_seconds, bool)
                or not isinstance(poll_interval_seconds, (int, float))
                or not math.isfinite(float(poll_interval_seconds))
                or not 0.001 <= float(poll_interval_seconds) <= 0.25
            ):
                raise ValueError
            if not isinstance(database_path, (str, os.PathLike)):
                raise ValueError
            raw_path = os.fspath(database_path)
            if type(raw_path) is not str or not raw_path or raw_path == ":memory:":
                raise ValueError
            if raw_path.startswith(("\\\\", "//")):
                raise ValueError
            path = Path(os.path.abspath(raw_path))
            if not path.parent.is_dir():
                raise ValueError
            if path.exists() and not path.is_file():
                raise ValueError
        except GatewayQuotaAdmissionError:
            raise
        except Exception:
            raise GatewayQuotaAdmissionError("INVALID_CONFIGURATION") from None

        self._database_path = str(path)
        self._database_identity = SQLiteFileIdentity(path)
        self._domain_digest = hashlib.sha256(quota_domain_ref.encode("ascii")).hexdigest()
        self._capacity = capacity_per_window
        self._window_ns = window_ns
        self._reserved_capacity = reserved_capacity
        self._max_queue = max_queue
        self._max_queue_per_subject = max_queue_per_subject
        self._max_backoff_ns = max_backoff_ns
        self._max_queue_wait_ns = max_queue_wait_ns
        self._poll_interval_seconds = float(poll_interval_seconds)
        self._initialize()

    @property
    def configuration_version(self) -> str:
        """Opaque digest of the persisted domain settings bound by this owner."""

        payload = {
            "domain_digest": self._domain_digest,
            "capacity": self._capacity,
            "window_ns": self._window_ns,
            "reserved_capacity": self._reserved_capacity,
            "max_queue": self._max_queue,
            "max_queue_per_subject": self._max_queue_per_subject,
            "max_backoff_ns": self._max_backoff_ns,
            "max_queue_wait_ns": self._max_queue_wait_ns,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()

    def assert_configuration(
        self, deadline_monotonic_ns: Optional[int] = None  # noqa: UP045 -- Python 3.9.
    ) -> str:
        """Recheck persisted domain settings before dispatch, within its deadline."""

        timeout_seconds = 1.0
        if deadline_monotonic_ns is not None:
            if type(deadline_monotonic_ns) is not int:
                raise GatewayQuotaAdmissionError("INVALID_DEADLINE")
            remaining_ns = deadline_monotonic_ns - time.monotonic_ns()
            if remaining_ns <= 0:
                raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
            timeout_seconds = min(1.0, remaining_ns / _NANOSECONDS)
        try:
            with self._connection(timeout_seconds=timeout_seconds) as connection:
                row = connection.execute(
                    "SELECT capacity, window_ns, reserved_capacity, max_queue, "
                    "max_queue_per_subject, max_backoff_ns, max_queue_wait_ns "
                    "FROM quota_domains WHERE domain_digest = ?",
                    (self._domain_digest,),
                ).fetchone()
        except GatewayQuotaAdmissionError:
            raise
        except Exception:
            raise GatewayQuotaAdmissionError("OWNER_UNAVAILABLE") from None
        expected = (
            self._capacity,
            self._window_ns,
            self._reserved_capacity,
            self._max_queue,
            self._max_queue_per_subject,
            self._max_backoff_ns,
            self._max_queue_wait_ns,
        )
        if row is None or tuple(row) != expected:
            raise GatewayQuotaAdmissionError("DOMAIN_CONFIGURATION_MISMATCH")
        return self.configuration_version

    def admit(
        self,
        subject: GatewayQuotaSubject,
        operation: GatewayQuotaOperation,
        deadline_monotonic_ns: int,
    ) -> GatewayQuotaGrant:
        """Wait fairly for one slot, returning before the business deadline."""

        if type(subject) is not GatewayQuotaSubject:
            raise GatewayQuotaAdmissionError("INVALID_SUBJECT")
        if type(operation) is not GatewayQuotaOperation:
            raise GatewayQuotaAdmissionError("INVALID_OPERATION")
        if type(deadline_monotonic_ns) is not int:
            raise GatewayQuotaAdmissionError("INVALID_DEADLINE")
        subject_digest = _subject_digest(subject)
        run_digest = _run_digest(subject)
        request_id = uuid.uuid4().hex
        granted = False
        try:
            with self._transaction(deadline_monotonic_ns) as connection:
                now = self._clock_locked(connection, time.monotonic_ns())
                if deadline_monotonic_ns <= now:
                    raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
                if deadline_monotonic_ns - now > self._max_queue_wait_ns:
                    raise GatewayQuotaAdmissionError("INVALID_DEADLINE")
                self._prune_locked(connection, now)
                now = self._clock_locked(connection, time.monotonic_ns())
                if now >= deadline_monotonic_ns:
                    raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
                total = self._scalar(
                    connection,
                    "SELECT COUNT(*) FROM waiters WHERE domain_digest = ?",
                    (self._domain_digest,),
                )
                per_subject = self._scalar(
                    connection,
                    "SELECT COUNT(*) FROM waiters WHERE domain_digest = ? AND subject_digest = ?",
                    (self._domain_digest, subject_digest),
                )
                if total >= self._max_queue or per_subject >= self._max_queue_per_subject:
                    raise GatewayQuotaAdmissionError("QUEUE_FULL")
                now = self._clock_locked(connection, time.monotonic_ns())
                if now >= deadline_monotonic_ns:
                    raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
                row = connection.execute(
                    "SELECT next_ticket FROM quota_domains WHERE domain_digest = ?",
                    (self._domain_digest,),
                ).fetchone()
                ticket = int(row[0])
                connection.execute(
                    "INSERT INTO waiters "
                    "(domain_digest, request_id, subject_digest, run_digest, operation, "
                    "deadline_ns, ticket) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        self._domain_digest,
                        request_id,
                        subject_digest,
                        run_digest,
                        operation.value,
                        deadline_monotonic_ns,
                        ticket,
                    ),
                )
                connection.execute(
                    "UPDATE quota_domains SET next_ticket = next_ticket + 1 "
                    "WHERE domain_digest = ?",
                    (self._domain_digest,),
                )

            while True:
                wait_seconds = self._poll_interval_seconds
                wake_at_ns: Optional[int] = None  # noqa: UP045 -- Python 3.9.
                wake_snapshot: Optional[_WaitWakeSnapshot] = None  # noqa: UP045 -- Python 3.9.
                pending_grant: Optional[GatewayQuotaGrant] = None  # noqa: UP045 -- Python 3.9.
                clock_epoch_reset = False

                def mark_clock_epoch_reset() -> None:
                    nonlocal clock_epoch_reset
                    clock_epoch_reset = True

                with self._transaction(deadline_monotonic_ns) as connection:
                    now = self._clock_locked(
                        connection,
                        time.monotonic_ns(),
                        on_epoch_reset=mark_clock_epoch_reset,
                    )
                    if clock_epoch_reset:
                        continue
                    self._prune_locked(connection, now)
                    now = self._clock_locked(
                        connection,
                        time.monotonic_ns(),
                        on_epoch_reset=mark_clock_epoch_reset,
                    )
                    if clock_epoch_reset:
                        continue
                    if now >= deadline_monotonic_ns:
                        raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
                    own = connection.execute(
                        "SELECT subject_digest FROM waiters "
                        "WHERE domain_digest = ? AND request_id = ?",
                        (self._domain_digest, request_id),
                    ).fetchone()
                    if own is None:
                        raise GatewayQuotaAdmissionError("CLOCK_EPOCH_RESET")

                    domain = connection.execute(
                        "SELECT backoff_until_ns, grant_sequence FROM quota_domains "
                        "WHERE domain_digest = ?",
                        (self._domain_digest,),
                    ).fetchone()
                    backoff_until_ns = int(domain[0])
                    grant_count = self._scalar(
                        connection,
                        "SELECT COUNT(*) FROM grants WHERE domain_digest = ?",
                        (self._domain_digest,),
                    )
                    rows = connection.execute(
                        "SELECT w.request_id, w.subject_digest, w.operation, w.ticket, "
                        "COALESCE(s.last_served_sequence, 0), w.deadline_ns "
                        "FROM waiters AS w LEFT JOIN quota_subjects AS s "
                        "ON s.domain_digest = w.domain_digest "
                        "AND s.subject_digest = w.subject_digest "
                        "WHERE w.domain_digest = ? ORDER BY w.ticket",
                        (self._domain_digest,),
                    ).fetchall()
                    threshold = (
                        self._capacity
                        if operation.value in _CRITICAL_OPERATIONS
                        else self._capacity - self._reserved_capacity
                    )
                    if threshold <= 0:
                        wait_seconds = max(
                            0.0,
                            (deadline_monotonic_ns - now) / _NANOSECONDS,
                        )
                    elif grant_count >= threshold:
                        needed_to_expire = grant_count - threshold + 1
                        quota_slot_row = connection.execute(
                            "SELECT granted_ns FROM grants WHERE domain_digest = ? "
                            "ORDER BY granted_ns LIMIT 1 OFFSET ?",
                            (self._domain_digest, needed_to_expire - 1),
                        ).fetchone()
                        if quota_slot_row is not None:
                            quota_available_ns = (
                                int(quota_slot_row[0]) + self._window_ns
                            )
                            base_wake_ns = max(quota_available_ns, backoff_until_ns)
                            projected_grant_count = self._scalar(
                                connection,
                                "SELECT COUNT(*) FROM grants WHERE domain_digest = ? "
                                "AND granted_ns > ?",
                                (
                                    self._domain_digest,
                                    base_wake_ns - self._window_ns,
                                ),
                            )
                            next_grant_after_wake = connection.execute(
                                "SELECT MIN(granted_ns) FROM grants WHERE domain_digest = ? "
                                "AND granted_ns > ?",
                                (
                                    self._domain_digest,
                                    base_wake_ns - self._window_ns,
                                ),
                            ).fetchone()[0]
                            next_quota_event_ns = (
                                int(next_grant_after_wake) + self._window_ns
                                if next_grant_after_wake is not None
                                else None
                            )
                            wake_snapshot = _WaitWakeSnapshot(
                                waiters=tuple(rows),
                                request_id=request_id,
                                now_ns=now,
                                base_wake_ns=base_wake_ns,
                                grant_count=projected_grant_count,
                                grant_sequence=int(domain[1]),
                                capacity=self._capacity,
                                reserved_capacity=self._reserved_capacity,
                                projected_now_ns=base_wake_ns,
                                deadline_monotonic_ns=deadline_monotonic_ns,
                                poll_interval_ns=int(
                                    self._poll_interval_seconds * _NANOSECONDS
                                ),
                                next_quota_event_ns=next_quota_event_ns,
                            )
                        else:
                            # Conservatively keep the normal cadence if the
                            # active-grant projection is unexpectedly short.
                            wait_seconds = self._poll_interval_seconds
                    elif backoff_until_ns > now:
                        projected_grant_count = self._scalar(
                            connection,
                            "SELECT COUNT(*) FROM grants WHERE domain_digest = ? "
                            "AND granted_ns > ?",
                            (
                                self._domain_digest,
                                backoff_until_ns - self._window_ns,
                            ),
                        )
                        next_grant_after_backoff = connection.execute(
                            "SELECT MIN(granted_ns) FROM grants WHERE domain_digest = ? "
                            "AND granted_ns > ?",
                            (
                                self._domain_digest,
                                backoff_until_ns - self._window_ns,
                            ),
                        ).fetchone()[0]
                        next_quota_event_ns = (
                            int(next_grant_after_backoff) + self._window_ns
                            if next_grant_after_backoff is not None
                            else None
                        )
                        wake_snapshot = _WaitWakeSnapshot(
                            waiters=tuple(rows),
                            request_id=request_id,
                            now_ns=now,
                            base_wake_ns=backoff_until_ns,
                            grant_count=projected_grant_count,
                            grant_sequence=int(domain[1]),
                            capacity=self._capacity,
                            reserved_capacity=self._reserved_capacity,
                            projected_now_ns=backoff_until_ns,
                            deadline_monotonic_ns=deadline_monotonic_ns,
                            poll_interval_ns=int(
                                self._poll_interval_seconds * _NANOSECONDS
                            ),
                            next_quota_event_ns=next_quota_event_ns,
                        )
                    else:
                        subject_waiters: dict[
                            str, list[tuple[str, str, int, int]]
                        ] = {}
                        rows_by_request: dict[str, tuple[object, ...]] = {}
                        for row in rows:
                            request_key = str(row[0])
                            subject_key = str(row[1])
                            rows_by_request[request_key] = tuple(row)
                            subject_waiters.setdefault(subject_key, []).append(
                                (
                                    request_key,
                                    str(row[2]),
                                    int(row[3]),
                                    int(row[5]),
                                )
                            )

                        eligible: list[tuple[object, ...]] = []
                        for queue in subject_waiters.values():
                            selected = _subject_queue_candidate(
                                queue,
                                grant_count=grant_count,
                                capacity=self._capacity,
                                reserved_capacity=self._reserved_capacity,
                            )
                            if selected is not None:
                                eligible.append(rows_by_request[selected[0]])
                        candidate = min(
                            eligible,
                            key=lambda row: (int(row[4]), int(row[3])),
                            default=None,
                        )
                        if candidate is not None and str(candidate[0]) == request_id:
                            now = self._clock_locked(
                                connection,
                                time.monotonic_ns(),
                                on_epoch_reset=mark_clock_epoch_reset,
                            )
                            if clock_epoch_reset:
                                continue
                            if now >= deadline_monotonic_ns:
                                raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
                            sequence = int(domain[1]) + 1
                            grant_id = uuid.uuid4().hex
                            connection.execute(
                                "INSERT INTO grants "
                                "(grant_id, domain_digest, subject_digest, run_digest, "
                                "operation, granted_ns, sequence) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                                (
                                    grant_id,
                                    self._domain_digest,
                                    subject_digest,
                                    run_digest,
                                    operation.value,
                                    now,
                                    sequence,
                                ),
                            )
                            connection.execute(
                                "INSERT INTO quota_subjects "
                                "(domain_digest, subject_digest, last_served_sequence) "
                                "VALUES (?, ?, ?) ON CONFLICT(domain_digest, subject_digest) "
                                "DO UPDATE SET last_served_sequence = excluded.last_served_sequence",
                                (self._domain_digest, subject_digest, sequence),
                            )
                            connection.execute(
                                "DELETE FROM waiters WHERE domain_digest = ? AND request_id = ?",
                                (self._domain_digest, request_id),
                            )
                            connection.execute(
                                "UPDATE quota_domains SET grant_sequence = ? "
                                "WHERE domain_digest = ?",
                                (sequence, self._domain_digest),
                            )
                            connection.execute(
                                "DELETE FROM quota_subjects WHERE domain_digest = ? "
                                "AND last_served_sequence < ? AND subject_digest NOT IN "
                                "(SELECT subject_digest FROM waiters WHERE domain_digest = ?)",
                                (
                                    self._domain_digest,
                                    max(0, sequence - self._max_queue * 16),
                                    self._domain_digest,
                                ),
                            )
                            pending_grant = GatewayQuotaGrant(
                                grant_id=grant_id,
                                operation=operation,
                                sequence=sequence,
                                granted_monotonic_ns=now,
                                subject_digest=subject_digest,
                                run_digest=run_digest,
                            )
                        else:
                            next_grant = connection.execute(
                                "SELECT MIN(granted_ns) FROM grants WHERE domain_digest = ?",
                                (self._domain_digest,),
                            ).fetchone()[0]
                            next_quota_event_ns = (
                                int(next_grant) + self._window_ns
                                if next_grant is not None
                                else None
                            )
                            wake_snapshot = _WaitWakeSnapshot(
                                waiters=tuple(rows),
                                request_id=request_id,
                                now_ns=now,
                                base_wake_ns=now,
                                grant_count=grant_count,
                                grant_sequence=int(domain[1]),
                                capacity=self._capacity,
                                reserved_capacity=self._reserved_capacity,
                                projected_now_ns=now,
                                deadline_monotonic_ns=deadline_monotonic_ns,
                                poll_interval_ns=int(
                                    self._poll_interval_seconds * _NANOSECONDS
                                ),
                                next_quota_event_ns=next_quota_event_ns,
                            )
                if pending_grant is not None:
                    # Only treat the waiter as granted once COMMIT has
                    # returned successfully. A late successful commit keeps
                    # its quota record but is not returned as usable capacity.
                    granted = True
                    if time.monotonic_ns() >= deadline_monotonic_ns:
                        raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
                    return pending_grant
                if wake_snapshot is not None:
                    # The hint is derived only from the immutable committed
                    # snapshot. The next loop iteration performs a fresh
                    # writer-transaction recheck before any grant.
                    wake_at_ns = _wake_ns_from_snapshot(wake_snapshot)
                fresh_now_ns = time.monotonic_ns()
                remaining_ns = deadline_monotonic_ns - fresh_now_ns
                if remaining_ns <= 0:
                    raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
                if wake_at_ns is None:
                    sleep_ns = min(
                        int(wait_seconds * _NANOSECONDS), remaining_ns
                    )
                else:
                    sleep_ns = min(max(0, wake_at_ns - fresh_now_ns), remaining_ns)
                time.sleep(sleep_ns / _NANOSECONDS)
        finally:
            if not granted:
                self._remove_waiter(request_id, deadline_monotonic_ns)

    def defer_after_rate_limit(
        self, retry_after_seconds: Optional[float] = None  # noqa: UP045 -- Python 3.9.
    ) -> None:
        """Apply provider-confirmed 429 backoff to every process in this domain."""

        if retry_after_seconds is None:
            retry_ns = self._max_backoff_ns
        else:
            try:
                if isinstance(retry_after_seconds, bool) or not isinstance(
                    retry_after_seconds, (int, float)
                ):
                    raise ValueError
                requested_seconds = float(retry_after_seconds)
                if not math.isfinite(requested_seconds) or requested_seconds < 0.001:
                    raise ValueError
                retry_seconds = min(
                    requested_seconds, self._max_backoff_ns / _NANOSECONDS
                )
                retry_ns = int(retry_seconds * _NANOSECONDS)
            except (OverflowError, TypeError, ValueError):
                raise GatewayQuotaAdmissionError("INVALID_RATE_LIMIT_BACKOFF") from None
        with self._transaction() as connection:
            now = self._clock_locked(connection, time.monotonic_ns())
            connection.execute(
                "UPDATE quota_domains SET backoff_until_ns = MAX(backoff_until_ns, ?) "
                "WHERE domain_digest = ?",
                (now + retry_ns, self._domain_digest),
            )

    def status(self) -> Mapping[str, int | float]:
        """Return bounded owner metrics without account/domain identifiers."""

        with self._transaction() as connection:
            now = self._clock_locked(connection, time.monotonic_ns())
            self._prune_locked(connection, now)
            grants = self._scalar(
                connection,
                "SELECT COUNT(*) FROM grants WHERE domain_digest = ?",
                (self._domain_digest,),
            )
            waiters = self._scalar(
                connection,
                "SELECT COUNT(*) FROM waiters WHERE domain_digest = ?",
                (self._domain_digest,),
            )
            row = connection.execute(
                "SELECT backoff_until_ns FROM quota_domains WHERE domain_digest = ?",
                (self._domain_digest,),
            ).fetchone()
            return MappingProxyType(
                {
                    "capacity_per_window": self._capacity,
                    "reserved_capacity": self._reserved_capacity,
                    "grants_in_window": grants,
                    "pending_waiters": waiters,
                    "backoff_remaining_seconds": max(0.0, (int(row[0]) - now) / _NANOSECONDS),
                }
            )

    @property
    def pending_waiter_count(self) -> int:
        return int(self.status()["pending_waiters"])

    def _initialize(self) -> None:
        try:
            with self._connection() as connection:
                connection.executescript(
                    "CREATE TABLE IF NOT EXISTS quota_domains ("
                    "domain_digest TEXT PRIMARY KEY, capacity INTEGER NOT NULL, "
                    "window_ns INTEGER NOT NULL, reserved_capacity INTEGER NOT NULL, "
                    "max_queue INTEGER NOT NULL, max_queue_per_subject INTEGER NOT NULL, "
                    "max_backoff_ns INTEGER NOT NULL, max_queue_wait_ns INTEGER NOT NULL, "
                    "last_mono_ns INTEGER NOT NULL, backoff_until_ns INTEGER NOT NULL, "
                    "next_ticket INTEGER NOT NULL, grant_sequence INTEGER NOT NULL);"
                    "CREATE TABLE IF NOT EXISTS waiters ("
                    "domain_digest TEXT NOT NULL, request_id TEXT NOT NULL, "
                    "subject_digest TEXT NOT NULL, run_digest TEXT, operation TEXT NOT NULL, "
                    "deadline_ns INTEGER NOT NULL, ticket INTEGER NOT NULL, "
                    "PRIMARY KEY(domain_digest, request_id), "
                    "UNIQUE(domain_digest, ticket));"
                    "CREATE INDEX IF NOT EXISTS quota_waiters_order "
                    "ON waiters(domain_digest, ticket);"
                    "CREATE INDEX IF NOT EXISTS quota_waiters_subject "
                    "ON waiters(domain_digest, subject_digest, ticket);"
                    "CREATE TABLE IF NOT EXISTS quota_subjects ("
                    "domain_digest TEXT NOT NULL, subject_digest TEXT NOT NULL, "
                    "last_served_sequence INTEGER NOT NULL, "
                    "PRIMARY KEY(domain_digest, subject_digest));"
                    "CREATE TABLE IF NOT EXISTS grants ("
                    "grant_id TEXT PRIMARY KEY, domain_digest TEXT NOT NULL, "
                    "subject_digest TEXT NOT NULL, run_digest TEXT, operation TEXT NOT NULL, "
                    "granted_ns INTEGER NOT NULL, sequence INTEGER NOT NULL, "
                    "UNIQUE(domain_digest, sequence));"
                    "CREATE INDEX IF NOT EXISTS quota_grants_window "
                    "ON grants(domain_digest, granted_ns);"
                )
                connection.execute("BEGIN IMMEDIATE")
                for table in ("waiters", "grants"):
                    columns = {
                        str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")
                    }
                    if "run_digest" not in columns:
                        connection.execute(f"ALTER TABLE {table} ADD COLUMN run_digest TEXT")
                connection.commit()
                now = time.monotonic_ns()
                connection.execute(
                    "INSERT OR IGNORE INTO quota_domains "
                    "(domain_digest, capacity, window_ns, reserved_capacity, max_queue, "
                    "max_queue_per_subject, max_backoff_ns, max_queue_wait_ns, last_mono_ns, "
                    "backoff_until_ns, next_ticket, grant_sequence) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, 0)",
                    (
                        self._domain_digest,
                        self._capacity,
                        self._window_ns,
                        self._reserved_capacity,
                        self._max_queue,
                        self._max_queue_per_subject,
                        self._max_backoff_ns,
                        self._max_queue_wait_ns,
                        now,
                    ),
                )
                row = connection.execute(
                    "SELECT capacity, window_ns, reserved_capacity, max_queue, "
                    "max_queue_per_subject, max_backoff_ns, max_queue_wait_ns "
                    "FROM quota_domains WHERE domain_digest = ?",
                    (self._domain_digest,),
                ).fetchone()
                expected = (
                    self._capacity,
                    self._window_ns,
                    self._reserved_capacity,
                    self._max_queue,
                    self._max_queue_per_subject,
                    self._max_backoff_ns,
                    self._max_queue_wait_ns,
                )
                if tuple(row) != expected:
                    raise GatewayQuotaAdmissionError("DOMAIN_CONFIGURATION_MISMATCH")
        except GatewayQuotaAdmissionError:
            raise
        except Exception:
            raise GatewayQuotaAdmissionError("OWNER_UNAVAILABLE") from None

    @contextmanager
    def _transaction(
        self, deadline_monotonic_ns: Optional[int] = None  # noqa: UP045 -- Python 3.9.
    ) -> Iterator[sqlite3.Connection]:
        while True:
            if deadline_monotonic_ns is None:
                timeout_seconds = 1.0
            else:
                remaining_ns = deadline_monotonic_ns - time.monotonic_ns()
                if remaining_ns <= 0:
                    raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
                # A request must not sit inside SQLite's busy handler for its
                # whole business deadline. A failed BEGIN is retried outside
                # SQLite at the existing owner polling cadence.
                timeout_seconds = min(
                    self._poll_interval_seconds, remaining_ns / _NANOSECONDS
                )

            retry_begin = False
            transaction_started = False
            try:
                with self._connection(timeout_seconds=timeout_seconds) as connection:
                    try:
                        connection.execute("BEGIN IMMEDIATE")
                        transaction_started = True
                    except sqlite3.OperationalError as exc:
                        if deadline_monotonic_ns is None or not _is_sqlite_busy(exc):
                            raise
                        retry_begin = True
                    if not retry_begin:
                        committed = False
                        try:
                            if (
                                deadline_monotonic_ns is not None
                                and time.monotonic_ns() >= deadline_monotonic_ns
                            ):
                                raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
                            yield connection
                            if deadline_monotonic_ns is not None:
                                remaining_ns = (
                                    deadline_monotonic_ns - time.monotonic_ns()
                                )
                                if remaining_ns <= 0:
                                    raise GatewayQuotaAdmissionError(
                                        "DEADLINE_EXCEEDED"
                                    )
                                busy_timeout_ms = int(
                                    min(
                                        timeout_seconds,
                                        remaining_ns / _NANOSECONDS,
                                    )
                                    * 1000
                                )
                                connection.execute(
                                    f"PRAGMA busy_timeout = {busy_timeout_ms}"
                                )
                                if time.monotonic_ns() >= deadline_monotonic_ns:
                                    raise GatewayQuotaAdmissionError(
                                        "DEADLINE_EXCEEDED"
                                    )
                            connection.commit()
                            committed = True
                        except BaseException:
                            if not committed:
                                connection.rollback()
                            raise
                        if (
                            deadline_monotonic_ns is not None
                            and time.monotonic_ns() >= deadline_monotonic_ns
                        ):
                            # COMMIT succeeded. Keep its durable quota row and
                            # report only that the business deadline elapsed.
                            raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
            except GatewayQuotaAdmissionError:
                raise
            except sqlite3.OperationalError as exc:
                if (
                    deadline_monotonic_ns is not None
                    and not transaction_started
                    and time.monotonic_ns() >= deadline_monotonic_ns
                ):
                    raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED") from None
                # Only BUSY/LOCKED from BEGIN is retryable. Errors from the
                # transaction body or commit remain terminal and are never
                # replayed.
                if _is_sqlite_busy(exc):
                    raise GatewayQuotaAdmissionError("OWNER_UNAVAILABLE") from None
                raise GatewayQuotaAdmissionError("OWNER_UNAVAILABLE") from None
            except Exception:
                raise GatewayQuotaAdmissionError("OWNER_UNAVAILABLE") from None

            if not retry_begin:
                return
            assert deadline_monotonic_ns is not None
            remaining_ns = deadline_monotonic_ns - time.monotonic_ns()
            if remaining_ns <= 0:
                raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
            time.sleep(
                min(self._poll_interval_seconds, remaining_ns / _NANOSECONDS)
            )

    @contextmanager
    def _connection(self, *, timeout_seconds: float = 1.0) -> Iterator[sqlite3.Connection]:
        connection: Optional[sqlite3.Connection] = None  # noqa: UP045 -- Python 3.9.
        try:
            self._database_identity.verify()
            connection = sqlite3.connect(
                self._database_path, timeout=timeout_seconds, isolation_level=None
            )
            self._database_identity.verify()
            busy_timeout_ms = max(0, int(timeout_seconds * 1000.0))
            connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
            yield connection
        except GatewayQuotaAdmissionError:
            raise
        except GatewayDatabaseIdentityError:
            raise GatewayQuotaAdmissionError("DOMAIN_IDENTITY_CHANGED") from None
        except sqlite3.OperationalError:
            raise
        except Exception:
            raise GatewayQuotaAdmissionError("OWNER_UNAVAILABLE") from None
        finally:
            if connection is not None:
                connection.close()

    def _clock_locked(
        self,
        connection: sqlite3.Connection,
        observed_now: int,
        *,
        on_epoch_reset: Optional[Callable[[], None]] = None,  # noqa: UP045 -- Python 3.9.
    ) -> int:
        row = connection.execute(
            "SELECT last_mono_ns, backoff_until_ns FROM quota_domains "
            "WHERE domain_digest = ?",
            (self._domain_digest,),
        ).fetchone()
        if row is None:
            raise GatewayQuotaAdmissionError("OWNER_UNAVAILABLE")
        previous_now, backoff_until = int(row[0]), int(row[1])
        if observed_now < previous_now:
            if on_epoch_reset is not None:
                on_epoch_reset()
            # A monotonic-clock epoch change is fail-closed: prior grants are
            # held for a complete fresh window and stale waiters are discarded.
            connection.execute(
                "UPDATE grants SET granted_ns = ? WHERE domain_digest = ?",
                (observed_now, self._domain_digest),
            )
            connection.execute(
                "DELETE FROM waiters WHERE domain_digest = ?", (self._domain_digest,)
            )
            backoff = (
                observed_now + self._max_backoff_ns
                if backoff_until > previous_now
                else observed_now
            )
            connection.execute(
                "UPDATE quota_domains SET last_mono_ns = ?, backoff_until_ns = ? "
                "WHERE domain_digest = ?",
                (observed_now, backoff, self._domain_digest),
            )
            return observed_now
        connection.execute(
            "UPDATE quota_domains SET last_mono_ns = ? WHERE domain_digest = ?",
            (observed_now, self._domain_digest),
        )
        return observed_now

    def _prune_locked(self, connection: sqlite3.Connection, now: int) -> None:
        connection.execute(
            "DELETE FROM grants WHERE domain_digest = ? AND granted_ns <= ?",
            (self._domain_digest, now - self._window_ns),
        )
        connection.execute(
            "DELETE FROM waiters WHERE domain_digest = ? AND deadline_ns <= ?",
            (self._domain_digest, now),
        )

    def _remove_waiter(self, request_id: str, deadline_monotonic_ns: int) -> None:
        if time.monotonic_ns() >= deadline_monotonic_ns:
            # The persisted deadline lets a later owner prune this row without
            # extending the caller's already-expired business operation.
            return
        try:
            with self._transaction(deadline_monotonic_ns) as connection:
                connection.execute(
                    "DELETE FROM waiters WHERE domain_digest = ? AND request_id = ?",
                    (self._domain_digest, request_id),
                )
        except GatewayQuotaAdmissionError:
            # The waiter has a persisted deadline and is pruned by a later call.
            pass

    @staticmethod
    def _scalar(
        connection: sqlite3.Connection, query: str, parameters: tuple[object, ...]
    ) -> int:
        row = connection.execute(query, parameters).fetchone()
        return int(row[0])


@dataclass(frozen=True, slots=True)
class GatewayQuotaDomainConfig:
    """Explicit single-host shared SQLite settings for one provider quota domain.

    Every account binding for the same API-key/IP/session budget must receive
    this same trusted database path and domain reference. There is no implicit
    per-host/per-account database default and no multi-host mode.
    """

    database_path: Union[str, os.PathLike] = field(repr=False)  # noqa: UP007 -- Python 3.9.
    quota_domain_ref: str
    capacity_per_window: int
    window_seconds: float
    reserved_capacity: int = 0
    max_queue: int = 1024
    max_queue_per_subject: int = 32
    max_backoff_seconds: float = 300.0
    max_queue_wait_seconds: float = 60.0
    poll_interval_seconds: float = 0.025
    deployment_mode: str = "single_host_shared_sqlite"

    def __post_init__(self) -> None:
        if (
            type(self.deployment_mode) is not str
            or self.deployment_mode != "single_host_shared_sqlite"
        ):
            raise GatewayQuotaAdmissionError("INVALID_CONFIGURATION")
        try:
            if not isinstance(self.database_path, (str, os.PathLike)):
                raise ValueError
            raw = os.fspath(self.database_path)
            if type(raw) is not str or not raw or not os.path.isabs(raw):
                raise ValueError
            if raw.startswith(("\\\\", "//")):
                raise ValueError
            canonical = Path(os.path.abspath(raw))
            if not canonical.parent.is_dir() or (canonical.exists() and not canonical.is_file()):
                raise ValueError
            object.__setattr__(self, "database_path", canonical)
        except Exception:
            raise GatewayQuotaAdmissionError("INVALID_CONFIGURATION") from None


@dataclass(frozen=True, slots=True)
class GatewayQuotaDomainBinding:
    """Trusted, explicit owner binding shared by account and dispatch paths."""

    config: GatewayQuotaDomainConfig
    _admission: GatewayQuotaAdmission = field(init=False, repr=False, compare=False)
    _configuration_version: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.config) is not GatewayQuotaDomainConfig:
            raise GatewayQuotaAdmissionError("INVALID_CONFIGURATION")
        admission = GatewayQuotaAdmission(
            self.config.database_path,
            self.config.quota_domain_ref,
            capacity_per_window=self.config.capacity_per_window,
            window_seconds=self.config.window_seconds,
            reserved_capacity=self.config.reserved_capacity,
            max_queue=self.config.max_queue,
            max_queue_per_subject=self.config.max_queue_per_subject,
            max_backoff_seconds=self.config.max_backoff_seconds,
            max_queue_wait_seconds=self.config.max_queue_wait_seconds,
            poll_interval_seconds=self.config.poll_interval_seconds,
        )
        object.__setattr__(self, "_admission", admission)
        object.__setattr__(self, "_configuration_version", admission.configuration_version)

    @property
    def admission(self) -> GatewayQuotaAdmission:
        return self._admission

    @property
    def configuration_version(self) -> str:
        return self._configuration_version

    def assert_current(
        self, deadline_monotonic_ns: Optional[int] = None  # noqa: UP045 -- Python 3.9.
    ) -> None:
        if self._admission.assert_configuration(deadline_monotonic_ns) != self._configuration_version:
            raise GatewayQuotaAdmissionError("DOMAIN_CONFIGURATION_MISMATCH")


class GatewayQuotaProviderSession:
    """Apply shared admission to the fixed read-only provider session surface."""

    __slots__ = (
        "_provider",
        "_admission",
        "_subject",
        "_connect_count",
        "_assert_session_owned",
        "_assert_domain_current",
    )

    def __init__(
        self,
        provider: object,
        admission: GatewayQuotaAdmission,
        subject: GatewayQuotaSubject,
        *,
        assert_session_owned: Optional[Callable[[], None]] = None,  # noqa: UP045 -- Python 3.9.
        assert_domain_current: Optional[Callable[[Optional[int]], None]] = None,  # noqa: UP045
    ) -> None:
        if (
            not callable(getattr(provider, "connect", None))
            or not callable(getattr(provider, "read_account", None))
            or not callable(getattr(provider, "close", None))
            or type(admission) is not GatewayQuotaAdmission
            or type(subject) is not GatewayQuotaSubject
            or (assert_session_owned is not None and not callable(assert_session_owned))
            or (assert_domain_current is not None and not callable(assert_domain_current))
        ):
            raise GatewayQuotaAdmissionError("INVALID_CONFIGURATION")
        self._provider = provider
        self._admission = admission
        self._subject = subject
        self._connect_count = 0
        self._assert_session_owned = assert_session_owned
        self._assert_domain_current = assert_domain_current

    def connect(self, *, account_key: object, generation: str, timeout: float) -> object:
        operation = (
            GatewayQuotaOperation.LOGIN
            if self._connect_count == 0
            else GatewayQuotaOperation.RECONNECT
        )
        return self._call(
            "connect",
            operation,
            on_dispatch=self._record_connect_dispatch,
            account_key=account_key,
            generation=generation,
            timeout=timeout,
        )

    def _record_connect_dispatch(self) -> None:
        self._connect_count += 1

    def read_account(self, *, generation: str, timeout: float) -> object:
        return self._call(
            "read_account",
            GatewayQuotaOperation.QUERY,
            generation=generation,
            timeout=timeout,
        )

    def close(self) -> Optional[bool]:  # noqa: UP045 -- Gateway package supports Python 3.9.
        return self._provider.close()  # type: ignore[attr-defined]

    def defer_after_rate_limit(
        self, retry_after_seconds: Optional[float] = None  # noqa: UP045 -- Python 3.9.
    ) -> None:
        """Expose the trusted provider adapter's explicit 429 feedback hook."""

        self._admission.defer_after_rate_limit(retry_after_seconds)

    def __getattr__(self, name: str) -> object:
        if name not in _OPTIONAL_PROVIDER_READS:
            raise AttributeError(name)
        method = getattr(self._provider, name, None)
        if not callable(method):
            raise AttributeError(name)

        if name == "read_instrument_metadata":

            def read_instrument_metadata(
                *,
                instrument_id: str,
                exchange_id: str,
                generation: str,
                timeout: float,
            ) -> object:
                return self._call(
                    name,
                    GatewayQuotaOperation.CTP_QUERY,
                    instrument_id=instrument_id,
                    exchange_id=exchange_id,
                    generation=generation,
                    timeout=timeout,
                )

            return read_instrument_metadata

        def read_fact(*, generation: str, timeout: float) -> object:
            return self._call(
                name,
                GatewayQuotaOperation.QUERY,
                generation=generation,
                timeout=timeout,
            )

        return read_fact

    def _call(
        self,
        method_name: str,
        operation: GatewayQuotaOperation,
        *,
        on_dispatch: Optional[Callable[[], None]] = None,  # noqa: UP045 -- Python 3.9.
        **arguments: object,
    ) -> object:
        timeout = arguments.get("timeout")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
        ):
            raise GatewayQuotaAdmissionError("INVALID_DEADLINE")
        try:
            timeout_seconds = float(timeout)
        except (OverflowError, TypeError, ValueError):
            raise GatewayQuotaAdmissionError("INVALID_DEADLINE") from None
        if (
            not math.isfinite(timeout_seconds)
            or not 0.0 < timeout_seconds <= _MAX_PROVIDER_CALL_TIMEOUT_SECONDS
        ):
            raise GatewayQuotaAdmissionError("INVALID_DEADLINE")
        deadline = time.monotonic_ns() + int(timeout_seconds * _NANOSECONDS)
        self._assert_dispatch_ownership(deadline)
        self._admission.admit(self._subject, operation, deadline)
        remaining = (deadline - time.monotonic_ns()) / _NANOSECONDS
        if remaining <= 0:
            raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
        method = getattr(self._provider, method_name)
        call_arguments = dict(arguments)
        # Admission can wait. Revalidate the account lease and persisted domain
        # version immediately before the irreversible provider boundary.
        self._assert_dispatch_ownership(deadline)
        remaining = (deadline - time.monotonic_ns()) / _NANOSECONDS
        if remaining <= 0:
            raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
        call_arguments["timeout"] = remaining
        if on_dispatch is not None:
            on_dispatch()
        try:
            return method(**call_arguments)
        except RateLimitError as exc:
            self._admission.defer_after_rate_limit(exc.retry_after)
            raise

    def _assert_dispatch_ownership(self, deadline_monotonic_ns: int) -> None:
        if self._assert_session_owned is not None:
            try:
                self._assert_session_owned()
            except Exception:
                raise GatewayQuotaAdmissionError("SESSION_OWNERSHIP_UNAVAILABLE") from None
        if self._assert_domain_current is None:
            self._admission.assert_configuration(deadline_monotonic_ns)
            return
        self._assert_domain_current(deadline_monotonic_ns)

    def __repr__(self) -> str:
        return "<GatewayQuotaProviderSession>"


class GatewayQuotaDispatchAdmission:
    """Adapt trusted Risk/CANCEL dispatch facts to the shared quota owner.

    Callers pass server-resolved identity and a finite operation label. A
    strategy run supplies both strategy and run references; a trusted
    account-scoped manual intent supplies neither, sharing an account quota
    bucket. The adapter consumes the grant internally so account-owner APIs
    receive only ``None`` on success and a value-free quota error on denial.
    """

    __slots__ = ("_admission", "_assert_domain_current")

    _OPERATIONS = MappingProxyType(
        {
            "OPEN": GatewayQuotaOperation.OPEN,
            "CLOSE": GatewayQuotaOperation.CLOSE,
            "CANCEL": GatewayQuotaOperation.CANCEL,
            "RECONCILE": GatewayQuotaOperation.RECONCILE,
            "ACCEPTED_GROUP_ACTION": GatewayQuotaOperation.ACCEPTED_GROUP_ACTION,
        }
    )

    def __init__(
        self,
        admission: GatewayQuotaAdmission,
        *,
        assert_domain_current: Optional[Callable[[Optional[int]], None]] = None,  # noqa: UP045
    ) -> None:
        if (
            type(admission) is not GatewayQuotaAdmission
            or (assert_domain_current is not None and not callable(assert_domain_current))
        ):
            raise GatewayQuotaAdmissionError("INVALID_CONFIGURATION")
        self._admission = admission
        self._assert_domain_current = assert_domain_current

    def __call__(
        self,
        account_ref: str,
        strategy_ref: Optional[str],  # noqa: UP045 -- Gateway package supports Python 3.9.
        run_ref: Optional[str],  # noqa: UP045 -- Gateway package supports Python 3.9.
        instrument_ref: Optional[str],  # noqa: UP045 -- Gateway package supports Python 3.9.
        operation: str,
        deadline_monotonic_ns: int,
    ) -> None:
        if (
            not _valid_ref(account_ref)
            or (strategy_ref is None) != (run_ref is None)
            or (strategy_ref is not None and not _valid_ref(strategy_ref))
            or (run_ref is not None and not _valid_ref(run_ref))
        ):
            raise GatewayQuotaAdmissionError("INVALID_SUBJECT")
        if instrument_ref is not None and not _valid_ref(instrument_ref):
            raise GatewayQuotaAdmissionError("INVALID_SUBJECT")
        if type(operation) is not str:
            raise GatewayQuotaAdmissionError("INVALID_OPERATION")
        quota_operation = self._OPERATIONS.get(operation)
        if quota_operation is None:
            raise GatewayQuotaAdmissionError("INVALID_OPERATION")
        if type(deadline_monotonic_ns) is not int:
            raise GatewayQuotaAdmissionError("INVALID_DEADLINE")
        subject = GatewayQuotaSubject(
            account_ref=account_ref,
            strategy_ref=strategy_ref,
            instrument_ref=instrument_ref,
            run_ref=run_ref,
        )
        self._assert_current(deadline_monotonic_ns)
        self._admission.admit(subject, quota_operation, deadline_monotonic_ns)
        self._assert_current(deadline_monotonic_ns)
        if time.monotonic_ns() >= deadline_monotonic_ns:
            raise GatewayQuotaAdmissionError("DEADLINE_EXCEEDED")
        return None

    def _assert_current(self, deadline_monotonic_ns: int) -> None:
        if self._assert_domain_current is None:
            self._admission.assert_configuration(deadline_monotonic_ns)
            return
        self._assert_domain_current(deadline_monotonic_ns)

    def __repr__(self) -> str:
        return "<GatewayQuotaDispatchAdmission>"


def _subject_digest(subject: GatewayQuotaSubject) -> str:
    identity = [subject.account_ref, subject.strategy_ref, subject.instrument_ref]
    payload = json.dumps(
        identity,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _run_digest(subject: GatewayQuotaSubject) -> Optional[str]:
    if subject.run_ref is None:
        return None
    return hashlib.sha256(subject.run_ref.encode("ascii")).hexdigest()


def _valid_ref(value: object) -> bool:
    return type(value) is str and _SAFE_REF.fullmatch(value) is not None


def _seconds_to_ns(value: object, *, minimum: float, maximum: float) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        raise GatewayQuotaAdmissionError("INVALID_CONFIGURATION")
    return int(float(value) * _NANOSECONDS)


__all__ = [
    "GatewayQuotaAdmission",
    "GatewayQuotaAdmissionError",
    "GatewayQuotaDispatchAdmission",
    "GatewayQuotaGrant",
    "GatewayQuotaOperation",
    "GatewayQuotaProviderSession",
    "GatewayQuotaSubject",
]
