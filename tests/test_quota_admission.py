"""Tests for the provider-neutral dispatch quota adapter."""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

import bt_api_gateway.quota_admission as quota_module
from bt_api_gateway.quota_admission import (
    GatewayQuotaAdmission,
    GatewayQuotaAdmissionError,
    GatewayQuotaDispatchAdmission,
    GatewayQuotaGrant,
    GatewayQuotaOperation,
    GatewayQuotaSubject,
)


def _is_test_sqlite_busy(exc: sqlite3.OperationalError) -> bool:
    error_code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(error_code, int):
        return (error_code & 0xFF) in {
            getattr(sqlite3, "SQLITE_BUSY", 5),
            getattr(sqlite3, "SQLITE_LOCKED", 6),
        }
    return str(exc).lower() in {
        "database is locked",
        "database table is locked",
        "database schema is locked",
    }


def _owner(path: Path, *, capacity: int = 16, reserved: int = 8) -> GatewayQuotaAdmission:
    return GatewayQuotaAdmission(
        path,
        "synthetic:dispatch-quota-v1",
        capacity_per_window=capacity,
        window_seconds=60.0,
        reserved_capacity=reserved,
        max_queue=32,
        max_queue_per_subject=8,
        max_backoff_seconds=1.0,
        max_queue_wait_seconds=5.0,
        poll_interval_seconds=0.002,
    )


class _LogicalQuotaClock:
    """Clock namespace for deadline tests without wall-time SQLite jitter."""

    def __init__(self, now_ns: int) -> None:
        self.now_ns = now_ns

    def monotonic_ns(self) -> int:
        return self.now_ns

    def sleep(self, seconds: float) -> None:
        self.now_ns += int(seconds * 1_000_000_000)


def test_dispatch_adapter_maps_trusted_operations_and_keeps_run_metadata(
    tmp_path: Path,
) -> None:
    path = tmp_path / "dispatch-quota.sqlite3"
    owner = _owner(path)
    callback = GatewayQuotaDispatchAdmission(owner)
    deadline = time.monotonic_ns() + 2_000_000_000

    assert callback("acct:1", "strategy:1", "run:1", "BTC-PERP", "OPEN", deadline) is None
    assert callback("acct:1", "strategy:1", "run:2", "BTC-PERP", "OPEN", deadline) is None
    assert callback("acct:1", "strategy:1", "run:1", "BTC-PERP", "CLOSE", deadline) is None
    assert callback("acct:1", "strategy:1", "run:1", "BTC-PERP", "CANCEL", deadline) is None
    assert callback("acct:1", "strategy:1", "run:1", "BTC-PERP", "RECONCILE", deadline) is None
    assert (
        callback(
            "acct:1",
            "strategy:1",
            "run:1",
            "BTC-PERP",
            "ACCEPTED_GROUP_ACTION",
            deadline,
        )
        is None
    )

    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT operation, subject_digest, run_digest FROM grants ORDER BY sequence"
        ).fetchall()

    assert [row[0] for row in rows] == [
        "open",
        "open",
        "close",
        "cancel",
        "reconcile",
        "accepted_group_action",
    ]
    assert rows[0][1] == rows[1][1]
    assert rows[0][2] != rows[1][2]
    assert all(len(row[1]) == len(row[2]) == 64 for row in rows)

    with pytest.raises(GatewayQuotaAdmissionError) as unsupported:
        callback("acct:1", "strategy:1", "run:1", "BTC-PERP", "ADMIN", deadline)
    assert unsupported.value.code == "INVALID_OPERATION"
    with pytest.raises(GatewayQuotaAdmissionError) as missing_run:
        callback("acct:1", "strategy:1", "", "BTC-PERP", "OPEN", deadline)
    assert missing_run.value.code == "INVALID_SUBJECT"


@pytest.mark.parametrize(
    ("critical_operation", "stored_operation"),
    (
        ("CLOSE", "close"),
        ("CANCEL", "cancel"),
        ("RECONCILE", "reconcile"),
        ("ACCEPTED_GROUP_ACTION", "accepted_group_action"),
    ),
)
def test_critical_operations_can_use_reserved_capacity_but_open_cannot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    critical_operation: str,
    stored_operation: str,
) -> None:
    path = tmp_path / "reserved-quota.sqlite3"
    owner = _owner(path, capacity=2, reserved=1)
    callback = GatewayQuotaDispatchAdmission(owner)
    clock = _LogicalQuotaClock(time.monotonic_ns())
    monkeypatch.setattr(quota_module, "time", clock)

    assert callback(
        "acct:2", "strategy:2", "run:2", "ETH-PERP", "OPEN", clock.monotonic_ns() + 100_000_000
    ) is None
    with pytest.raises(GatewayQuotaAdmissionError) as denied:
        callback(
            "acct:2", "strategy:2", "run:2", "ETH-PERP", "OPEN", clock.monotonic_ns() + 10_000_000
        )
    assert denied.value.code == "DEADLINE_EXCEEDED"
    assert callback(
        "acct:2",
        "strategy:2",
        "run:2",
        "ETH-PERP",
        critical_operation,
        clock.monotonic_ns() + 100_000_000,
    ) is None

    with sqlite3.connect(path) as connection:
        operations = connection.execute(
            "SELECT operation FROM grants ORDER BY sequence"
        ).fetchall()
    assert operations == [("open",), (stored_operation,)]


@pytest.mark.parametrize(
    ("operation", "stored_operation"),
    (
        (GatewayQuotaOperation.CANCEL, "cancel"),
        (GatewayQuotaOperation.RECONCILE, "reconcile"),
        (GatewayQuotaOperation.ACCEPTED_GROUP_ACTION, "accepted_group_action"),
    ),
)
def test_critical_waiter_bypasses_same_subject_open_only_at_reserved_boundary(
    tmp_path: Path,
    operation: GatewayQuotaOperation,
    stored_operation: str,
) -> None:
    path = tmp_path / f"reserved-bypass-{stored_operation}.sqlite3"
    owner = _adaptive_wait_owner(path, capacity=2, reserved=1)
    now = time.monotonic_ns()
    owner.admit(
        GatewayQuotaSubject("acct:seed", "strategy:seed", "BTC-PERP", "run:seed"),
        GatewayQuotaOperation.OPEN,
        now + 1_000_000_000,
    )
    blocked_open = GatewayQuotaSubject(
        "acct:shared", "strategy:shared", "BTC-PERP", "run:open"
    )
    critical = GatewayQuotaSubject(
        "acct:shared", "strategy:shared", "BTC-PERP", "run:critical"
    )
    assert quota_module._subject_digest(blocked_open) == quota_module._subject_digest(
        critical
    )
    blocked_deadline = now + 5_000_000_000
    open_id = "a" * 32
    _persist_waiter(
        path,
        owner,
        blocked_open,
        GatewayQuotaOperation.OPEN,
        deadline_ns=blocked_deadline,
        request_id=open_id,
    )

    grant = owner.admit(
        critical,
        operation,
        time.monotonic_ns() + 40_000_000,
    )

    assert grant.operation is operation
    with sqlite3.connect(path) as connection:
        operations = connection.execute(
            "SELECT operation FROM grants WHERE domain_digest = ? ORDER BY sequence",
            (owner._domain_digest,),
        ).fetchall()
        pending = connection.execute(
            "SELECT request_id, operation FROM waiters WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchall()
    assert operations == [("open",), (stored_operation,)]
    assert pending == [(open_id, "open")]
    assert len(operations) <= owner._capacity


def test_same_subject_critical_does_not_overtake_open_while_regular_capacity_is_available(
    tmp_path: Path,
) -> None:
    path = tmp_path / "regular-capacity-keeps-subject-fifo.sqlite3"
    owner = _adaptive_wait_owner(path, capacity=3, reserved=1)
    now = time.monotonic_ns()
    owner.admit(
        GatewayQuotaSubject("acct:seed", "strategy:seed", "BTC-PERP", "run:seed"),
        GatewayQuotaOperation.OPEN,
        now + 1_000_000_000,
    )
    blocked_open = GatewayQuotaSubject(
        "acct:shared", "strategy:shared", "BTC-PERP", "run:open"
    )
    current_cancel = GatewayQuotaSubject(
        "acct:shared", "strategy:shared", "BTC-PERP", "run:cancel"
    )
    open_id = "f" * 32
    _persist_waiter(
        path,
        owner,
        blocked_open,
        GatewayQuotaOperation.OPEN,
        deadline_ns=now + 5_000_000_000,
        request_id=open_id,
    )

    with pytest.raises(GatewayQuotaAdmissionError) as expired:
        owner.admit(
            current_cancel,
            GatewayQuotaOperation.CANCEL,
            time.monotonic_ns() + 25_000_000,
        )

    assert expired.value.code == "DEADLINE_EXCEEDED"
    with sqlite3.connect(path) as connection:
        grants = connection.execute(
            "SELECT operation FROM grants WHERE domain_digest = ? ORDER BY sequence",
            (owner._domain_digest,),
        ).fetchall()
        earlier_open = connection.execute(
            "SELECT operation FROM waiters WHERE domain_digest = ? AND request_id = ?",
            (owner._domain_digest, open_id),
        ).fetchone()
    assert grants == [("open",)]
    assert earlier_open == ("open",)


@pytest.mark.parametrize(
    ("earlier_operation", "current_operation"),
    (
        (GatewayQuotaOperation.CANCEL, GatewayQuotaOperation.CANCEL),
        (GatewayQuotaOperation.CANCEL, GatewayQuotaOperation.RECONCILE),
        (
            GatewayQuotaOperation.RECONCILE,
            GatewayQuotaOperation.ACCEPTED_GROUP_ACTION,
        ),
    ),
)
def test_blocked_subject_does_not_skip_earlier_critical_ticket(
    tmp_path: Path,
    earlier_operation: GatewayQuotaOperation,
    current_operation: GatewayQuotaOperation,
) -> None:
    path = tmp_path / f"critical-fifo-{earlier_operation.value}-{current_operation.value}.sqlite3"
    owner = _adaptive_wait_owner(path, capacity=2, reserved=1)
    now = time.monotonic_ns()
    owner.admit(
        GatewayQuotaSubject("acct:seed", "strategy:seed", "BTC-PERP", "run:seed"),
        GatewayQuotaOperation.OPEN,
        now + 1_000_000_000,
    )
    subject = GatewayQuotaSubject(
        "acct:fifo", "strategy:fifo", "BTC-PERP", "run:old"
    )
    deadline = now + 5_000_000_000
    open_id = "b" * 32
    critical_id = "c" * 32
    _persist_waiter(
        path,
        owner,
        subject,
        GatewayQuotaOperation.OPEN,
        deadline_ns=deadline,
        request_id=open_id,
    )
    earlier_ticket = _persist_waiter(
        path,
        owner,
        subject,
        earlier_operation,
        deadline_ns=deadline,
        request_id=critical_id,
    )

    with pytest.raises(GatewayQuotaAdmissionError) as expired:
        owner.admit(
            GatewayQuotaSubject(
                "acct:fifo", "strategy:fifo", "BTC-PERP", "run:current"
            ),
            current_operation,
            time.monotonic_ns() + 25_000_000,
        )

    assert expired.value.code == "DEADLINE_EXCEEDED"
    with sqlite3.connect(path) as connection:
        grants = connection.execute(
            "SELECT operation FROM grants WHERE domain_digest = ? ORDER BY sequence",
            (owner._domain_digest,),
        ).fetchall()
        earlier = connection.execute(
            "SELECT ticket, operation FROM waiters "
            "WHERE domain_digest = ? AND request_id = ?",
            (owner._domain_digest, critical_id),
        ).fetchone()
    assert grants == [("open",)]
    assert earlier == (earlier_ticket, earlier_operation.value)


def test_cross_subject_turn_fairness_survives_reserved_bypass(
    tmp_path: Path,
) -> None:
    rows = [
        ("a-open", "subject-a", "open", 1, 100, 900),
        ("a-cancel", "subject-a", "cancel", 2, 100, 900),
        ("b-cancel", "subject-b", "cancel", 3, 0, 900),
    ]

    assert quota_module._virtual_waiter_rank(
        rows,
        "b-cancel",
        grant_count=2,
        grant_sequence=100,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    ) == (0, None)
    assert quota_module._virtual_waiter_rank(
        rows,
        "a-cancel",
        grant_count=2,
        grant_sequence=100,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    ) == (None, 900)

    path = tmp_path / "reserved-bypass-subject-fairness.sqlite3"
    owner = _adaptive_wait_owner(path, capacity=3, reserved=1)
    now = time.monotonic_ns()
    for index in range(2):
        owner.admit(
            GatewayQuotaSubject(
                f"acct:seed:{index}",
                f"strategy:seed:{index}",
                "BTC-PERP",
                f"run:seed:{index}",
            ),
            GatewayQuotaOperation.OPEN,
            time.monotonic_ns() + 1_000_000_000,
        )
    older_subject = GatewayQuotaSubject(
        "acct:older", "strategy:older", "BTC-PERP", "run:older"
    )
    current_subject = GatewayQuotaSubject(
        "acct:current", "strategy:current", "BTC-PERP", "run:current"
    )
    _persist_waiter(
        path,
        owner,
        older_subject,
        GatewayQuotaOperation.OPEN,
        deadline_ns=now + 5_000_000_000,
        request_id="d" * 32,
    )
    _persist_waiter(
        path,
        owner,
        older_subject,
        GatewayQuotaOperation.CANCEL,
        deadline_ns=now + 5_000_000_000,
        request_id="e" * 32,
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO quota_subjects "
            "(domain_digest, subject_digest, last_served_sequence) VALUES (?, ?, ?)",
            (owner._domain_digest, quota_module._subject_digest(older_subject), 100),
        )
        connection.execute(
            "UPDATE quota_domains SET grant_sequence = 100 WHERE domain_digest = ?",
            (owner._domain_digest,),
        )

    grant = owner.admit(
        current_subject,
        GatewayQuotaOperation.CANCEL,
        time.monotonic_ns() + 250_000_000,
    )

    assert grant.operation is GatewayQuotaOperation.CANCEL
    assert grant.subject_digest == quota_module._subject_digest(current_subject)
    with sqlite3.connect(path) as connection:
        grants = connection.execute(
            "SELECT operation, subject_digest FROM grants WHERE domain_digest = ? "
            "ORDER BY sequence",
            (owner._domain_digest,),
        ).fetchall()
        older_pending = connection.execute(
            "SELECT request_id, operation FROM waiters WHERE domain_digest = ? "
            "AND subject_digest = ? ORDER BY ticket",
            (owner._domain_digest, quota_module._subject_digest(older_subject)),
        ).fetchall()
    assert grants[-1] == ("cancel", quota_module._subject_digest(current_subject))
    assert older_pending == [("d" * 32, "open"), ("e" * 32, "cancel")]
    assert len(grants) == owner._capacity


def test_virtual_rank_keeps_blocked_open_and_consumes_bypassed_critical_once() -> None:
    rows = [
        ("open", "subject-a", "open", 1, 10, 900),
        ("cancel", "subject-a", "cancel", 2, 10, 900),
        ("reconcile", "subject-a", "reconcile", 3, 10, 900),
    ]

    assert quota_module._virtual_waiter_rank(
        rows,
        "reconcile",
        grant_count=2,
        grant_sequence=10,
        capacity=4,
        reserved_capacity=2,
        projected_now_ns=0,
    ) == (1, 900)
    assert quota_module._virtual_waiter_wake_rank(
        rows,
        "reconcile",
        grant_count=2,
        grant_sequence=10,
        capacity=4,
        reserved_capacity=2,
        projected_now_ns=0,
    ) == (1, 900)
    assert quota_module._virtual_waiter_rank(
        rows,
        "open",
        grant_count=2,
        grant_sequence=10,
        capacity=4,
        reserved_capacity=2,
        projected_now_ns=0,
    ) == (None, None)


def test_reserved_bypass_refuses_when_all_quota_capacity_is_used(
    tmp_path: Path,
) -> None:
    path = tmp_path / "reserved-full-capacity.sqlite3"
    owner = _adaptive_wait_owner(path, capacity=2, reserved=1)
    subject = GatewayQuotaSubject("acct:full", "strategy:full", "BTC-PERP", "run:one")
    now = time.monotonic_ns()
    owner.admit(subject, GatewayQuotaOperation.OPEN, now + 1_000_000_000)
    owner.admit(
        GatewayQuotaSubject("acct:seed", "strategy:seed", "ETH-PERP", "run:seed"),
        GatewayQuotaOperation.CANCEL,
        time.monotonic_ns() + 1_000_000_000,
    )

    with pytest.raises(GatewayQuotaAdmissionError) as expired:
        owner.admit(
            GatewayQuotaSubject(
                "acct:full", "strategy:full", "BTC-PERP", "run:cancel"
            ),
            GatewayQuotaOperation.CANCEL,
            time.monotonic_ns() + 25_000_000,
        )

    assert expired.value.code == "DEADLINE_EXCEEDED"
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM grants WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchone()[0] == owner._capacity


def test_manual_account_bucket_requires_both_strategy_refs_absent(tmp_path: Path) -> None:
    path = tmp_path / "manual-account-quota.sqlite3"
    callback = GatewayQuotaDispatchAdmission(_owner(path))
    deadline = time.monotonic_ns() + 2_000_000_000

    assert callback("acct:manual", None, None, "BTC-PERP", "OPEN", deadline) is None
    assert callback("acct:manual", None, None, "BTC-PERP", "CLOSE", deadline) is None

    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT operation, subject_digest FROM grants ORDER BY sequence"
        ).fetchall()

    assert [row[0] for row in rows] == ["open", "close"]
    assert rows[0][1] == rows[1][1]
    assert len(rows[0][1]) == 64

    with pytest.raises(GatewayQuotaAdmissionError) as missing_run:
        callback("acct:manual", "strategy:1", None, "BTC-PERP", "OPEN", deadline)
    assert missing_run.value.code == "INVALID_SUBJECT"

    with pytest.raises(GatewayQuotaAdmissionError) as missing_strategy:
        callback("acct:manual", None, "run:1", "BTC-PERP", "OPEN", deadline)
    assert missing_strategy.value.code == "INVALID_SUBJECT"


def test_existing_quota_schema_adds_run_metadata_columns(tmp_path: Path) -> None:
    path = tmp_path / "legacy-quota.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            "CREATE TABLE quota_domains ("
            "domain_digest TEXT PRIMARY KEY, capacity INTEGER NOT NULL, "
            "window_ns INTEGER NOT NULL, reserved_capacity INTEGER NOT NULL, "
            "max_queue INTEGER NOT NULL, max_queue_per_subject INTEGER NOT NULL, "
            "max_backoff_ns INTEGER NOT NULL, max_queue_wait_ns INTEGER NOT NULL, "
            "last_mono_ns INTEGER NOT NULL, backoff_until_ns INTEGER NOT NULL, "
            "next_ticket INTEGER NOT NULL, grant_sequence INTEGER NOT NULL);"
            "CREATE TABLE waiters (domain_digest TEXT NOT NULL, request_id TEXT NOT NULL, "
            "subject_digest TEXT NOT NULL, operation TEXT NOT NULL, deadline_ns INTEGER NOT NULL, "
            "ticket INTEGER NOT NULL, PRIMARY KEY(domain_digest, request_id), "
            "UNIQUE(domain_digest, ticket));"
            "CREATE TABLE quota_subjects (domain_digest TEXT NOT NULL, "
            "subject_digest TEXT NOT NULL, last_served_sequence INTEGER NOT NULL, "
            "PRIMARY KEY(domain_digest, subject_digest));"
            "CREATE TABLE grants (grant_id TEXT PRIMARY KEY, domain_digest TEXT NOT NULL, "
            "subject_digest TEXT NOT NULL, operation TEXT NOT NULL, granted_ns INTEGER NOT NULL, "
            "sequence INTEGER NOT NULL, UNIQUE(domain_digest, sequence));"
        )

    callback = GatewayQuotaDispatchAdmission(_owner(path))
    assert callback(
        "acct:migrated",
        "strategy:migrated",
        "run:migrated",
        "BTC-PERP",
        "OPEN",
        time.monotonic_ns() + 2_000_000_000,
    ) is None

    with sqlite3.connect(path) as connection:
        assert "run_digest" in {
            row[1] for row in connection.execute("PRAGMA table_info(waiters)")
        }
        grant_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(grants)")
        }
        assert "run_digest" in grant_columns
        assert connection.execute("SELECT run_digest FROM grants").fetchone()[0]


class _StopBeforeQuotaWait(Exception):  # noqa: N818
    pass


def _adaptive_wait_owner(
    path: Path,
    *,
    capacity: int,
    reserved: int,
    max_backoff_seconds: float = 10.0,
    max_queue_wait_seconds: float = 120.0,
) -> GatewayQuotaAdmission:
    return GatewayQuotaAdmission(
        path,
        "synthetic:adaptive-wait-v1",
        capacity_per_window=capacity,
        window_seconds=60.0,
        reserved_capacity=reserved,
        max_queue=32,
        max_queue_per_subject=8,
        max_backoff_seconds=max_backoff_seconds,
        max_queue_wait_seconds=max_queue_wait_seconds,
        poll_interval_seconds=0.002,
    )


def _persist_waiter(
    path: Path,
    owner: GatewayQuotaAdmission,
    subject: GatewayQuotaSubject,
    operation: GatewayQuotaOperation,
    *,
    deadline_ns: int,
    request_id: str,
) -> int:
    """Create a durable queue predecessor for an admission-boundary test."""

    with sqlite3.connect(path) as connection:
        ticket = int(
            connection.execute(
                "SELECT next_ticket FROM quota_domains WHERE domain_digest = ?",
                (owner._domain_digest,),
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO waiters "
            "(domain_digest, request_id, subject_digest, run_digest, operation, "
            "deadline_ns, ticket) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                owner._domain_digest,
                request_id,
                quota_module._subject_digest(subject),
                quota_module._run_digest(subject),
                operation.value,
                deadline_ns,
                ticket,
            ),
        )
        connection.execute(
            "UPDATE quota_domains SET next_ticket = next_ticket + 1 "
            "WHERE domain_digest = ?",
            (owner._domain_digest,),
        )
    return ticket


def _capture_one_quota_wait(
    path: Path, monkeypatch: pytest.MonkeyPatch
) -> list[tuple[float, int, int, list[int]]]:
    waits: list[tuple[float, int, int, list[int]]] = []

    def stop_before_sleep(seconds: float) -> None:
        with sqlite3.connect(path) as connection:
            now = int(
                connection.execute(
                    "SELECT last_mono_ns FROM quota_domains"
                ).fetchone()[0]
            )
            backoff_until = int(
                connection.execute(
                    "SELECT backoff_until_ns FROM quota_domains"
                ).fetchone()[0]
            )
            grants = [
                int(row[0])
                for row in connection.execute(
                    "SELECT granted_ns FROM grants ORDER BY granted_ns"
                ).fetchall()
            ]
        waits.append((seconds, now, backoff_until, grants))
        raise _StopBeforeQuotaWait

    monkeypatch.setattr(quota_module.time, "sleep", stop_before_sleep)
    return waits


@pytest.mark.parametrize(
    ("operation", "expected_expiry_index"),
    [
        (GatewayQuotaOperation.OPEN, 1),
        (GatewayQuotaOperation.CANCEL, 0),
    ],
)
def test_adaptive_wait_uses_operation_threshold_and_kth_grant_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: GatewayQuotaOperation,
    expected_expiry_index: int,
) -> None:
    path = tmp_path / f"adaptive-expiry-{operation.value}.sqlite3"
    owner = _adaptive_wait_owner(path, capacity=3, reserved=1)
    for index in range(3):
        owner.admit(
            GatewayQuotaSubject(
                f"acct:reserved-{index}", f"strategy:{index}", "BTC-PERP", f"run:{index}"
            ),
            GatewayQuotaOperation.CANCEL,
            time.monotonic_ns() + 1_000_000_000,
        )

    base = time.monotonic_ns()
    grant_times = [base - 30_000_000, base - 20_000_000, base - 10_000_000]
    with sqlite3.connect(path) as connection:
        for sequence, granted_ns in enumerate(grant_times, start=1):
            connection.execute(
                "UPDATE grants SET granted_ns = ? WHERE domain_digest = ? AND sequence = ?",
                (granted_ns, owner._domain_digest, sequence),
            )
        connection.execute(
            "UPDATE quota_domains SET last_mono_ns = ?, backoff_until_ns = 0 "
            "WHERE domain_digest = ?",
            (base, owner._domain_digest),
        )

    waits = _capture_one_quota_wait(path, monkeypatch)
    with pytest.raises(_StopBeforeQuotaWait):
        owner.admit(
            GatewayQuotaSubject("acct:waiter", "strategy:waiter", "BTC-PERP", "run:waiter"),
            operation,
            base + 70_000_000_000,
        )

    assert len(waits) == 1
    requested_seconds, poll_now_ns, backoff_until_ns, active_grants = waits[0]
    threshold = 3 if operation is GatewayQuotaOperation.CANCEL else 2
    needed_to_expire = len(active_grants) - threshold + 1
    expected_wake_ns = max(
        active_grants[expected_expiry_index] + 60_000_000_000,
        backoff_until_ns,
    )
    assert expected_expiry_index == needed_to_expire - 1
    assert requested_seconds == pytest.approx(
        max(0.0, (expected_wake_ns - poll_now_ns) / 1_000_000_000), abs=1e-6
    )


def test_adaptive_wait_uses_later_rate_limit_backoff_or_grant_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "adaptive-backoff.sqlite3"
    owner = _adaptive_wait_owner(
        path,
        capacity=1,
        reserved=0,
        max_backoff_seconds=5.0,
        max_queue_wait_seconds=5.0,
    )
    owner.admit(
        GatewayQuotaSubject("acct:seed", "strategy:seed", "BTC-PERP", "run:seed"),
        GatewayQuotaOperation.OPEN,
        time.monotonic_ns() + 1_000_000_000,
    )
    owner.defer_after_rate_limit(2.0)
    base = time.monotonic_ns()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE grants SET granted_ns = ? WHERE domain_digest = ?",
            (base - 59_500_000_000, owner._domain_digest),
        )
        connection.execute(
            "UPDATE quota_domains SET last_mono_ns = ? WHERE domain_digest = ?",
            (base, owner._domain_digest),
        )

    clock = _LogicalQuotaClock(base)
    monkeypatch.setattr(quota_module, "time", clock)
    waits = _capture_one_quota_wait(path, monkeypatch)
    with pytest.raises(_StopBeforeQuotaWait):
        owner.admit(
            GatewayQuotaSubject("acct:waiter", "strategy:waiter", "BTC-PERP", "run:waiter"),
            GatewayQuotaOperation.OPEN,
            base + 4_000_000_000,
        )

    assert len(waits) == 1
    requested_seconds, poll_now_ns, backoff_until_ns, active_grants = waits[0]
    grant_expiry_ns = active_grants[0] + 60_000_000_000
    assert backoff_until_ns > grant_expiry_ns
    assert requested_seconds == pytest.approx(
        (backoff_until_ns - poll_now_ns) / 1_000_000_000, abs=1e-6
    )


def test_adaptive_wait_spreads_fairness_losers_by_virtual_turn_rank(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "adaptive-fairness.sqlite3"
    owner = _adaptive_wait_owner(path, capacity=2, reserved=0)
    owner.admit(
        GatewayQuotaSubject("acct:seed", "strategy:seed", "BTC-PERP", "run:seed"),
        GatewayQuotaOperation.OPEN,
        time.monotonic_ns() + 1_000_000_000,
    )
    base = time.monotonic_ns()
    deadline = base + 4_000_000_000
    head_subject = GatewayQuotaSubject(
        "acct:fair", "strategy:older", "BTC-PERP", "run:older"
    )
    with sqlite3.connect(path) as connection:
        next_ticket = int(
            connection.execute(
                "SELECT next_ticket FROM quota_domains WHERE domain_digest = ?",
                (owner._domain_digest,),
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO waiters "
            "(domain_digest, request_id, subject_digest, run_digest, operation, deadline_ns, ticket) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                owner._domain_digest,
                "0" * 32,
                quota_module._subject_digest(head_subject),
                quota_module._run_digest(head_subject),
                GatewayQuotaOperation.OPEN.value,
                deadline,
                next_ticket,
            ),
        )
        connection.execute(
            "UPDATE quota_domains SET next_ticket = next_ticket + 1 "
            "WHERE domain_digest = ?",
            (owner._domain_digest,),
        )

    clock = _LogicalQuotaClock(base)
    monkeypatch.setattr(quota_module, "time", clock)
    waits = _capture_one_quota_wait(path, monkeypatch)
    with pytest.raises(_StopBeforeQuotaWait):
        owner.admit(
            GatewayQuotaSubject("acct:fair", "strategy:later", "BTC-PERP", "run:later"),
            GatewayQuotaOperation.OPEN,
            deadline,
        )

    assert len(waits) == 1
    assert waits[0][0] == pytest.approx(owner._poll_interval_seconds, abs=1e-6)
    assert len(waits[0][3]) == 1


def test_virtual_waiter_rank_matches_global_sequence_round_robin_and_deadlines() -> None:
    deadline_by_request = {
        "a1": 900,
        "b1": 800,
        "b2": 700,
        "a2": 600,
    }
    rows = [
        ("a1", "subject-a", "open", 1, 100, deadline_by_request["a1"]),
        ("b1", "subject-b", "open", 2, 0, deadline_by_request["b1"]),
        ("b2", "subject-b", "open", 3, 0, deadline_by_request["b2"]),
        ("a2", "subject-a", "open", 4, 100, deadline_by_request["a2"]),
    ]

    ranks = {
        request_id: quota_module._virtual_waiter_rank(
            rows,
            request_id,
            grant_count=0,
            grant_sequence=100,
            capacity=10,
            reserved_capacity=2,
            projected_now_ns=0,
        )
        for request_id in ("b1", "a1", "b2", "a2")
    }

    assert [ranks[name][0] for name in ("b1", "a1", "b2", "a2")] == [0, 1, 2, 3]
    assert ranks["a2"] == (3, 700)


def test_admit_keeps_last_served_selector_when_deadline_column_is_appended(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "adaptive-selector-column-order.sqlite3"
    owner = _adaptive_wait_owner(path, capacity=2, reserved=0)
    older_ticket = GatewayQuotaSubject(
        "acct:selector", "strategy:older", "BTC-PERP", "run:older"
    )
    selected = GatewayQuotaSubject(
        "acct:selector", "strategy:selected", "BTC-PERP", "run:selected"
    )
    now = time.monotonic_ns()
    older_deadline = now + 1_000_000_000
    selected_deadline = now + 5_000_000_000
    older_digest = quota_module._subject_digest(older_ticket)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO waiters "
            "(domain_digest, request_id, subject_digest, run_digest, operation, deadline_ns, ticket) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                owner._domain_digest,
                "older-waiter",
                older_digest,
                quota_module._run_digest(older_ticket),
                GatewayQuotaOperation.OPEN.value,
                older_deadline,
                1,
            ),
        )
        connection.execute(
            "INSERT INTO quota_subjects "
            "(domain_digest, subject_digest, last_served_sequence) VALUES (?, ?, ?)",
            (owner._domain_digest, older_digest, 100),
        )
        connection.execute(
            "UPDATE quota_domains SET next_ticket = 2, grant_sequence = 100, "
            "last_mono_ns = ? WHERE domain_digest = ?",
            (now, owner._domain_digest),
        )

    def fail_if_target_loses(seconds: float) -> None:
        raise _StopBeforeQuotaWait

    monkeypatch.setattr(quota_module.time, "sleep", fail_if_target_loses)
    grant = owner.admit(selected, GatewayQuotaOperation.OPEN, selected_deadline)

    assert grant.sequence == 101
    assert grant.subject_digest == quota_module._subject_digest(selected)
    with sqlite3.connect(path) as connection:
        selected_rows = connection.execute(
            "SELECT subject_digest FROM grants WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchall()
        assert selected_rows == [(quota_module._subject_digest(selected),)]


def test_virtual_waiter_rank_preserves_reserved_operation_eligibility() -> None:
    rows = [
        ("open", "subject-open", "open", 1, 0, 900),
        ("cancel", "subject-cancel", "cancel", 2, 0, 900),
    ]

    open_at_regular_limit = quota_module._virtual_waiter_rank(
        rows,
        "open",
        grant_count=2,
        grant_sequence=2,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    )
    cancel_at_regular_limit = quota_module._virtual_waiter_rank(
        rows,
        "cancel",
        grant_count=2,
        grant_sequence=2,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    )
    open_with_regular_slot = quota_module._virtual_waiter_rank(
        rows,
        "open",
        grant_count=1,
        grant_sequence=2,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    )
    open_reserved_wake_rank = quota_module._virtual_waiter_wake_rank(
        rows,
        "open",
        grant_count=2,
        grant_sequence=2,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    )
    cancel_reserved_wake_rank = quota_module._virtual_waiter_wake_rank(
        rows,
        "cancel",
        grant_count=2,
        grant_sequence=2,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    )

    assert open_at_regular_limit == (None, None)
    assert cancel_at_regular_limit == (0, None)
    assert open_with_regular_slot == (0, None)
    assert open_reserved_wake_rank == (None, None)
    assert cancel_reserved_wake_rank == (0, None)


def test_virtual_waiter_rank_stops_at_regular_burst_but_keeps_reserved_turns() -> None:
    rows = [
        ("a-open", "subject-a", "open", 1, 100, 900),
        ("a-cancel", "subject-a", "cancel", 2, 100, 900),
        ("b-cancel", "subject-b", "cancel", 3, 0, 900),
        ("b-open", "subject-b", "open", 4, 0, 900),
        ("c-open", "subject-c", "open", 5, 50, 900),
        ("c-cancel", "subject-c", "cancel", 6, 50, 900),
    ]

    rank_b_cancel = quota_module._virtual_waiter_rank(
        rows,
        "b-cancel",
        grant_count=0,
        grant_sequence=100,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    )
    rank_c_open = quota_module._virtual_waiter_rank(
        rows,
        "c-open",
        grant_count=0,
        grant_sequence=100,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    )
    rank_a_open = quota_module._virtual_waiter_rank(
        rows,
        "a-open",
        grant_count=0,
        grant_sequence=100,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    )
    rank_c_cancel = quota_module._virtual_waiter_rank(
        rows,
        "c-cancel",
        grant_count=0,
        grant_sequence=100,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    )
    rank_a_cancel = quota_module._virtual_waiter_rank(
        rows,
        "a-cancel",
        grant_count=0,
        grant_sequence=100,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    )
    open_after_critical_consumes_regular_slot = quota_module._virtual_waiter_rank(
        rows,
        "a-open",
        grant_count=1,
        grant_sequence=100,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    )
    reserved_critical_rows = [
        ("cancel-a", "critical-a", "cancel", 1, 0, 900),
        ("cancel-b", "critical-b", "cancel", 2, 1, 900),
        ("open", "regular", "open", 3, 2, 900),
    ]
    critical_after_regular_limit = quota_module._virtual_waiter_rank(
        reserved_critical_rows,
        "cancel-b",
        grant_count=1,
        grant_sequence=100,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    )

    # The first virtual burst is B-cancel then C-open; regular admission closes
    # at two grants. A-cancel then wins the reserved turn by its older last-served
    # sequence, leaving no slot for C-cancel in this burst.
    assert rank_b_cancel == (0, None)
    assert rank_c_open == (1, 900)
    assert rank_a_open == (None, 900)
    assert rank_a_cancel == (2, 900)
    assert rank_c_cancel == (None, 900)
    assert open_after_critical_consumes_regular_slot == (None, 900)
    assert critical_after_regular_limit == (1, 900)


def test_virtual_waiter_overflow_gets_fair_bounded_queue_turn_rank() -> None:
    rows = [
        (f"request-{index}", f"subject-{index}", "open", index + 1, 0, 10_000)
        for index in range(200)
    ]

    first_burst_rank = quota_module._virtual_waiter_rank(
        rows,
        "request-0",
        grant_count=99,
        grant_sequence=100,
        capacity=100,
        reserved_capacity=0,
        projected_now_ns=0,
    )
    overflow_rank = quota_module._virtual_waiter_wake_rank(
        rows,
        "request-100",
        grant_count=99,
        grant_sequence=100,
        capacity=100,
        reserved_capacity=0,
        projected_now_ns=0,
    )
    last_overflow_rank = quota_module._virtual_waiter_wake_rank(
        rows,
        "request-199",
        grant_count=99,
        grant_sequence=100,
        capacity=100,
        reserved_capacity=0,
        projected_now_ns=0,
    )

    assert first_burst_rank == (0, None)
    assert overflow_rank == (100, 10_000)
    assert last_overflow_rank == (199, 10_000)

    # A nearby positive expiry must not collapse distinct queue-turn hints
    # into a shared wake. The wake only schedules a later full recheck.
    overflow_wake = quota_module._ranked_wake_ns(
        now_ns=0,
        base_wake_ns=100,
        rank=overflow_rank[0],
        predecessor_deadline_ns=overflow_rank[1],
        deadline_monotonic_ns=10_000,
        poll_interval_ns=5,
        next_quota_event_ns=101,
    )
    assert overflow_wake == 600

    unequal_history_rows = [
        ("a1", "subject-a", "open", 1, 100, 900),
        ("b1", "subject-b", "open", 2, 0, 900),
        ("b2", "subject-b", "open", 3, 0, 900),
        ("a2", "subject-a", "open", 4, 100, 900),
    ]
    overflow_turns = {
        request_id: quota_module._virtual_waiter_wake_rank(
            unequal_history_rows,
            request_id,
            grant_count=0,
            grant_sequence=100,
            capacity=1,
            reserved_capacity=0,
            projected_now_ns=0,
        )[0]
        for request_id in ("b1", "a1", "b2", "a2")
    }
    assert [overflow_turns[key] for key in ("b1", "a1", "b2", "a2")] == [
        0,
        1,
        2,
        3,
    ]


def test_critical_overflow_rank_skips_regular_heads_at_reserved_boundary() -> None:
    rows = [
        ("a-open", "subject-a", "open", 1, 0, 900),
        ("b-cancel", "subject-b", "cancel", 2, 1, 900),
        ("c-open", "subject-c", "open", 3, 2, 900),
        ("d-cancel", "subject-d", "cancel", 4, 3, 900),
    ]

    critical_overflow = quota_module._virtual_waiter_wake_rank(
        rows,
        "d-cancel",
        grant_count=1,
        grant_sequence=3,
        capacity=3,
        reserved_capacity=1,
        projected_now_ns=0,
    )

    # OPEN A and CANCEL B occupy the two regular slots. At the next-slot
    # boundary only critical operations may use the reserved slot, so OPEN C
    # must not push CANCEL D one queue turn later.
    assert critical_overflow == (2, 900)


def test_ranked_wake_respects_predecessor_deadline_and_unranked_quota_event() -> None:
    wake_before_quota_event = quota_module._ranked_wake_ns(
        now_ns=100,
        base_wake_ns=100,
        rank=10,
        predecessor_deadline_ns=135,
        deadline_monotonic_ns=1_000,
        poll_interval_ns=5,
        next_quota_event_ns=150,
    )
    wake_at_quota_event = quota_module._ranked_wake_ns(
        now_ns=100,
        base_wake_ns=100,
        rank=None,
        predecessor_deadline_ns=None,
        deadline_monotonic_ns=1_000,
        poll_interval_ns=5,
        next_quota_event_ns=102,
    )

    assert wake_before_quota_event == 135
    assert wake_at_quota_event == 102


def test_admit_reselects_after_ranked_predecessor_is_withdrawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "adaptive-withdrawn-predecessor.sqlite3"
    owner = _adaptive_wait_owner(path, capacity=2, reserved=0)
    owner.admit(
        GatewayQuotaSubject("acct:seed", "strategy:seed", "BTC-PERP", "run:seed"),
        GatewayQuotaOperation.OPEN,
        time.monotonic_ns() + 1_000_000_000,
    )
    base = time.monotonic_ns()
    deadline = base + 4_000_000_000
    head_subject = GatewayQuotaSubject(
        "acct:withdrawn", "strategy:head", "BTC-PERP", "run:head"
    )
    with sqlite3.connect(path) as connection:
        next_ticket = int(
            connection.execute(
                "SELECT next_ticket FROM quota_domains WHERE domain_digest = ?",
                (owner._domain_digest,),
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO waiters "
            "(domain_digest, request_id, subject_digest, run_digest, operation, deadline_ns, ticket) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                owner._domain_digest,
                "1" * 32,
                quota_module._subject_digest(head_subject),
                quota_module._run_digest(head_subject),
                GatewayQuotaOperation.OPEN.value,
                deadline,
                next_ticket,
            ),
        )
        connection.execute(
            "UPDATE quota_domains SET next_ticket = next_ticket + 1 "
            "WHERE domain_digest = ?",
            (owner._domain_digest,),
        )

    waits: list[float] = []

    def withdraw_predecessor(seconds: float) -> None:
        waits.append(seconds)
        with sqlite3.connect(path) as connection:
            connection.execute(
                "DELETE FROM waiters WHERE domain_digest = ? AND request_id = ?",
                (owner._domain_digest, "1" * 32),
            )

    monkeypatch.setattr(quota_module.time, "sleep", withdraw_predecessor)
    grant = owner.admit(
        GatewayQuotaSubject(
            "acct:withdrawn", "strategy:later", "BTC-PERP", "run:later"
        ),
        GatewayQuotaOperation.OPEN,
        deadline,
    )

    assert grant.sequence == 2
    assert waits == [pytest.approx(owner._poll_interval_seconds, abs=1e-6)]
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM waiters WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM grants WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchone()[0] == 2


def test_adaptive_wake_revalidates_after_concurrent_grant_stales_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "adaptive-stale-hint.sqlite3"
    owner = _adaptive_wait_owner(path, capacity=2, reserved=0)
    owner.admit(
        GatewayQuotaSubject("acct:seed", "strategy:seed", "BTC-PERP", "run:seed"),
        GatewayQuotaOperation.OPEN,
        time.monotonic_ns() + 1_000_000_000,
    )
    base = time.monotonic_ns()
    deadline = base + 4_000_000_000
    predecessor = GatewayQuotaSubject(
        "acct:stale", "strategy:predecessor", "BTC-PERP", "run:predecessor"
    )
    with sqlite3.connect(path) as connection:
        next_ticket = int(
            connection.execute(
                "SELECT next_ticket FROM quota_domains WHERE domain_digest = ?",
                (owner._domain_digest,),
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO waiters "
            "(domain_digest, request_id, subject_digest, run_digest, operation, deadline_ns, ticket) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                owner._domain_digest,
                "2" * 32,
                quota_module._subject_digest(predecessor),
                quota_module._run_digest(predecessor),
                GatewayQuotaOperation.OPEN.value,
                deadline,
                next_ticket,
            ),
        )
        connection.execute(
            "UPDATE quota_domains SET next_ticket = next_ticket + 1 "
            "WHERE domain_digest = ?",
            (owner._domain_digest,),
        )

    target = GatewayQuotaSubject(
        "acct:stale", "strategy:target", "BTC-PERP", "run:target"
    )
    sleep_facts: list[tuple[float, int, int]] = []

    def add_competing_grant_then_stop(seconds: float) -> None:
        competitor = GatewayQuotaSubject(
            "acct:competing", "strategy:competing", "BTC-PERP", "run:competing"
        )
        if not sleep_facts:
            now = time.monotonic_ns()
            subject_digest = quota_module._subject_digest(competitor)
            run_digest = quota_module._run_digest(competitor)
            with sqlite3.connect(path) as connection:
                sequence = int(
                    connection.execute(
                        "SELECT grant_sequence FROM quota_domains WHERE domain_digest = ?",
                        (owner._domain_digest,),
                    ).fetchone()[0]
                ) + 1
                connection.execute(
                    "INSERT INTO grants "
                    "(grant_id, domain_digest, subject_digest, run_digest, operation, granted_ns, sequence) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        "stale-hint-competing-grant",
                        owner._domain_digest,
                        subject_digest,
                        run_digest,
                        GatewayQuotaOperation.OPEN.value,
                        now,
                        sequence,
                    ),
                )
                connection.execute(
                    "INSERT INTO quota_subjects "
                    "(domain_digest, subject_digest, last_served_sequence) "
                    "VALUES (?, ?, ?) ON CONFLICT(domain_digest, subject_digest) "
                    "DO UPDATE SET last_served_sequence = excluded.last_served_sequence",
                    (owner._domain_digest, subject_digest, sequence),
                )
                connection.execute(
                    "UPDATE quota_domains SET grant_sequence = ?, last_mono_ns = ? "
                    "WHERE domain_digest = ?",
                    (sequence, now, owner._domain_digest),
                )
            sleep_facts.append((seconds, -1, -1))
            return

        with sqlite3.connect(path) as connection:
            grant_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM grants WHERE domain_digest = ?",
                    (owner._domain_digest,),
                ).fetchone()[0]
            )
            target_pending = int(
                connection.execute(
                    "SELECT COUNT(*) FROM waiters WHERE domain_digest = ? "
                    "AND subject_digest = ?",
                    (owner._domain_digest, quota_module._subject_digest(target)),
                ).fetchone()[0]
            )
        sleep_facts.append((seconds, grant_count, target_pending))
        raise _StopBeforeQuotaWait

    monkeypatch.setattr(quota_module.time, "sleep", add_competing_grant_then_stop)
    with pytest.raises(_StopBeforeQuotaWait):
        owner.admit(target, GatewayQuotaOperation.OPEN, deadline)

    assert len(sleep_facts) == 2
    assert sleep_facts[1][0] > 0.0
    assert sleep_facts[1][1:] == (2, 1)
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM grants WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchone()[0] == 2


def test_adaptive_wait_never_sleeps_past_business_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "adaptive-deadline.sqlite3"
    owner = _adaptive_wait_owner(
        path,
        capacity=1,
        reserved=0,
        max_queue_wait_seconds=5.0,
    )
    owner.admit(
        GatewayQuotaSubject("acct:seed", "strategy:seed", "BTC-PERP", "run:seed"),
        GatewayQuotaOperation.OPEN,
        time.monotonic_ns() + 1_000_000_000,
    )
    base = time.monotonic_ns()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE grants SET granted_ns = ? WHERE domain_digest = ?",
            (base, owner._domain_digest),
        )
        connection.execute(
            "UPDATE quota_domains SET last_mono_ns = ? WHERE domain_digest = ?",
            (base, owner._domain_digest),
        )
    deadline = base + 300_000_000

    waits = _capture_one_quota_wait(path, monkeypatch)
    with pytest.raises(_StopBeforeQuotaWait):
        owner.admit(
            GatewayQuotaSubject("acct:deadline", "strategy:deadline", "BTC-PERP", "run:deadline"),
            GatewayQuotaOperation.OPEN,
            deadline,
        )

    assert len(waits) == 1
    requested_seconds, poll_now_ns, _, active_grants = waits[0]
    quota_expiry_ns = active_grants[0] + 60_000_000_000
    deadline_wait = max(0.0, (deadline - poll_now_ns) / 1_000_000_000)
    quota_wait = max(0.0, (quota_expiry_ns - poll_now_ns) / 1_000_000_000)
    assert deadline_wait < quota_wait
    assert requested_seconds <= deadline_wait
    assert deadline_wait - requested_seconds < 0.01


def test_admit_commits_clock_epoch_reset_before_returning_reset_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "clock-reset-commit.sqlite3"
    owner = _adaptive_wait_owner(path, capacity=1, reserved=0)
    owner.admit(
        GatewayQuotaSubject("acct:seed", "strategy:seed", "BTC-PERP", "run:seed"),
        GatewayQuotaOperation.OPEN,
        time.monotonic_ns() + 1_000_000_000,
    )
    original_clock_locked = GatewayQuotaAdmission._clock_locked
    call_count = 0
    reset_samples: list[int] = []
    rank_calls: list[None] = []

    def inject_reset_during_waiter_poll(
        quota_owner: GatewayQuotaAdmission,
        connection: sqlite3.Connection,
        observed_now: int,
        *,
        on_epoch_reset=None,
    ) -> int:
        nonlocal call_count
        call_count += 1
        if quota_owner is owner and call_count == 4:
            reset_samples.append(observed_now)
            connection.execute(
                "UPDATE quota_domains SET last_mono_ns = ? WHERE domain_digest = ?",
                (observed_now + 1, owner._domain_digest),
            )
        return original_clock_locked(
            quota_owner,
            connection,
            observed_now,
            on_epoch_reset=on_epoch_reset,
        )

    monkeypatch.setattr(
        GatewayQuotaAdmission, "_clock_locked", inject_reset_during_waiter_poll
    )

    def unexpected_wake_calculation(*args, **kwargs):
        rank_calls.append(None)
        return 0, None

    monkeypatch.setattr(
        quota_module, "_virtual_waiter_wake_rank", unexpected_wake_calculation
    )
    with pytest.raises(GatewayQuotaAdmissionError) as reset:
        owner.admit(
            GatewayQuotaSubject("acct:waiter", "strategy:waiter", "BTC-PERP", "run:waiter"),
            GatewayQuotaOperation.OPEN,
            time.monotonic_ns() + 2_000_000_000,
        )

    assert reset.value.code == "CLOCK_EPOCH_RESET"
    assert call_count >= 5
    assert len(reset_samples) == 1
    assert rank_calls == []
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM waiters").fetchone()[0] == 0
        granted_ns = int(connection.execute("SELECT granted_ns FROM grants").fetchone()[0])
        last_mono_ns = int(
            connection.execute(
                "SELECT last_mono_ns FROM quota_domains WHERE domain_digest = ?",
                (owner._domain_digest,),
            ).fetchone()[0]
        )
    assert granted_ns == reset_samples[0]
    assert last_mono_ns >= reset_samples[0]


def test_advisory_rank_runs_after_commit_and_keeps_reserved_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "advisory-rank-after-commit.sqlite3"
    owner = _adaptive_wait_owner(path, capacity=3, reserved=1)
    for index in range(2):
        owner.admit(
            GatewayQuotaSubject(
                f"acct:open-seed-{index}",
                f"strategy:open-seed-{index}",
                "BTC-PERP",
                f"run:open-seed-{index}",
            ),
            GatewayQuotaOperation.OPEN,
            time.monotonic_ns() + 1_000_000_000,
        )

    base = time.monotonic_ns()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE grants SET granted_ns = ? WHERE domain_digest = ? AND sequence = 1",
            (base - 55_000_000_000, owner._domain_digest),
        )
        connection.execute(
            "UPDATE grants SET granted_ns = ? WHERE domain_digest = ? AND sequence = 2",
            (base - 54_000_000_000, owner._domain_digest),
        )
        connection.execute(
            "UPDATE quota_domains SET last_mono_ns = ? WHERE domain_digest = ?",
            (base, owner._domain_digest),
        )

    original_rank = quota_module._virtual_waiter_wake_rank
    rank_snapshot_counts: list[int] = []

    def rank_only_after_writer_commit(*args, **kwargs):
        # This transaction can begin only after admit() committed and closed
        # its immutable poll snapshot.
        probe = sqlite3.connect(path, timeout=0.0, isolation_level=None)
        try:
            probe.execute("BEGIN IMMEDIATE")
            probe.execute("ROLLBACK")
        finally:
            probe.close()
        rank_snapshot_counts.append(kwargs["grant_count"])
        return original_rank(*args, **kwargs)

    monkeypatch.setattr(
        quota_module, "_virtual_waiter_wake_rank", rank_only_after_writer_commit
    )
    waits = _capture_one_quota_wait(path, monkeypatch)
    open_deadline = base + 10_000_000_000
    with pytest.raises(_StopBeforeQuotaWait):
        owner.admit(
            GatewayQuotaSubject(
                "acct:reserved-open", "strategy:reserved-open", "BTC-PERP", "run:open"
            ),
            GatewayQuotaOperation.OPEN,
            open_deadline,
        )

    assert rank_snapshot_counts == [1]
    assert len(waits) == 1
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM grants WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchone()[0] == 2

    # OPEN remains blocked at capacity-reserved, while a critical operation
    # can still consume that reserved slot through the normal writer path.
    cancel = owner.admit(
        GatewayQuotaSubject(
            "acct:reserved-cancel", "strategy:reserved-cancel", "BTC-PERP", "run:cancel"
        ),
        GatewayQuotaOperation.CANCEL,
        time.monotonic_ns() + 1_000_000_000,
    )
    assert cancel.sequence == 3
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT operation FROM grants WHERE domain_digest = ? ORDER BY sequence",
            (owner._domain_digest,),
        ).fetchall() == [("open",), ("open",), ("cancel",)]


def test_ranked_sleep_subtracts_post_snapshot_monotonic_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "ranked-sleep-fresh-clock.sqlite3"
    owner = GatewayQuotaAdmission(
        path,
        "synthetic:ranked-sleep-fresh-clock",
        capacity_per_window=1,
        window_seconds=60.0,
        reserved_capacity=0,
        max_queue=8,
        max_queue_per_subject=4,
        max_backoff_seconds=1.0,
        max_queue_wait_seconds=5.0,
        poll_interval_seconds=0.002,
    )
    owner.admit(
        GatewayQuotaSubject("acct:seed", "strategy:seed", "BTC-PERP", "run:seed"),
        GatewayQuotaOperation.OPEN,
        time.monotonic_ns() + 1_000_000_000,
    )
    base = time.monotonic_ns()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE grants SET granted_ns = ? WHERE domain_digest = ?",
            (base - 59_500_000_000, owner._domain_digest),
        )
        connection.execute(
            "UPDATE quota_domains SET last_mono_ns = ? WHERE domain_digest = ?",
            (base, owner._domain_digest),
        )

    original_wake = quota_module._wake_ns_from_snapshot
    wake_values: list[int] = []
    post_rank_samples: list[int] = []
    sleeps: list[float] = []
    simulated_rank_cost_ns = 200_000_000
    clock = _LogicalQuotaClock(base)
    rank_finished = False

    def delayed_wake(snapshot):
        nonlocal rank_finished
        wake_at_ns = original_wake(snapshot)
        wake_values.append(wake_at_ns)
        clock.now_ns += simulated_rank_cost_ns
        rank_finished = True
        return wake_at_ns

    def delayed_monotonic_ns() -> int:
        if rank_finished:
            post_rank_samples.append(clock.now_ns)
        return clock.now_ns

    def stop_before_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        raise _StopBeforeQuotaWait

    monkeypatch.setattr(quota_module, "time", clock)
    monkeypatch.setattr(clock, "monotonic_ns", delayed_monotonic_ns)
    monkeypatch.setattr(quota_module, "_wake_ns_from_snapshot", delayed_wake)
    monkeypatch.setattr(clock, "sleep", stop_before_sleep)

    deadline = base + 3_000_000_000
    with pytest.raises(_StopBeforeQuotaWait):
        owner.admit(
            GatewayQuotaSubject("acct:waiter", "strategy:waiter", "BTC-PERP", "run:waiter"),
            GatewayQuotaOperation.OPEN,
            deadline,
        )

    assert len(wake_values) == len(sleeps) == 1
    assert post_rank_samples
    remaining_ns = min(
        max(0, wake_values[0] - post_rank_samples[0]),
        deadline - post_rank_samples[0],
    )
    assert remaining_ns > 0
    assert sleeps[0] == remaining_ns / 1_000_000_000
    assert sleeps[0] < (wake_values[0] - (base + 50_000_000)) / 1_000_000_000


def test_transaction_retries_only_busy_begin_before_yield(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = _adaptive_wait_owner(tmp_path / "begin-busy-retry.sqlite3", capacity=2, reserved=0)
    begin_attempts = 0
    commits = 0
    rollbacks = 0
    body_calls = 0
    requested_timeouts: list[float] = []
    busy_timeout_values: list[int] = []
    sleeps: list[float] = []

    class ScriptedConnection:
        def execute(self, statement: str):
            nonlocal begin_attempts
            if statement.startswith("PRAGMA busy_timeout = "):
                busy_timeout_values.append(int(statement.rsplit("=", 1)[1]))
                return None
            assert statement == "BEGIN IMMEDIATE"
            begin_attempts += 1
            if begin_attempts == 1:
                error = sqlite3.OperationalError("database is locked")
                error.sqlite_errorcode = sqlite3.SQLITE_BUSY
                raise error

        def commit(self) -> None:
            nonlocal commits
            commits += 1

        def rollback(self) -> None:
            nonlocal rollbacks
            rollbacks += 1

    scripted = ScriptedConnection()

    @contextmanager
    def scripted_connection(_owner, *, timeout_seconds: float = 1.0):
        requested_timeouts.append(timeout_seconds)
        yield scripted

    monkeypatch.setattr(GatewayQuotaAdmission, "_connection", scripted_connection)
    monkeypatch.setattr(quota_module.time, "sleep", sleeps.append)
    with owner._transaction(time.monotonic_ns() + 1_000_000_000) as connection:
        assert connection is scripted
        body_calls += 1

    assert begin_attempts == 2
    assert body_calls == commits == 1
    assert rollbacks == 0
    assert len(requested_timeouts) == 2
    assert all(0 < timeout <= owner._poll_interval_seconds for timeout in requested_timeouts)
    assert len(busy_timeout_values) == 1
    assert busy_timeout_values[0] <= int(requested_timeouts[-1] * 1000)
    assert sleeps == [owner._poll_interval_seconds]


@pytest.mark.parametrize("failure_point", ["body", "commit"])
def test_transaction_busy_after_begin_is_not_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    owner = _adaptive_wait_owner(
        tmp_path / f"{failure_point}-busy-no-retry.sqlite3", capacity=2, reserved=0
    )
    begin_attempts = 0
    rollbacks = 0
    now_ns = [1_000]
    deadline = 1_100

    class ScriptedConnection:
        def execute(self, statement: str):
            nonlocal begin_attempts
            assert statement == "BEGIN IMMEDIATE"
            begin_attempts += 1

        def commit(self) -> None:
            if failure_point == "commit":
                now_ns[0] = deadline + 1
                error = sqlite3.OperationalError("database is locked")
                error.sqlite_errorcode = sqlite3.SQLITE_BUSY
                raise error

        def rollback(self) -> None:
            nonlocal rollbacks
            rollbacks += 1

    scripted = ScriptedConnection()

    @contextmanager
    def scripted_connection(_owner, *, timeout_seconds: float = 1.0):
        yield scripted

    monkeypatch.setattr(GatewayQuotaAdmission, "_connection", scripted_connection)
    monkeypatch.setattr(quota_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(quota_module.time, "monotonic_ns", lambda: now_ns[0])
    with pytest.raises(GatewayQuotaAdmissionError) as unavailable:
        with owner._transaction(deadline):
            if failure_point == "body":
                now_ns[0] = deadline + 1
                error = sqlite3.OperationalError("database is locked")
                error.sqlite_errorcode = sqlite3.SQLITE_BUSY
                raise error

    assert unavailable.value.code == "OWNER_UNAVAILABLE"
    assert begin_attempts == rollbacks == 1


def test_transaction_that_acquires_writer_after_deadline_rolls_back_before_yield(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = _adaptive_wait_owner(
        tmp_path / "begin-acquired-after-deadline.sqlite3", capacity=2, reserved=0
    )
    now_ns = [1_000]
    deadline = 1_100
    begin_attempts = 0
    body_calls = 0
    commits = 0
    rollbacks = 0

    class ScriptedConnection:
        def execute(self, statement: str):
            nonlocal begin_attempts
            assert statement == "BEGIN IMMEDIATE"
            begin_attempts += 1

        def commit(self) -> None:
            nonlocal commits
            commits += 1

        def rollback(self) -> None:
            nonlocal rollbacks
            rollbacks += 1

    scripted = ScriptedConnection()

    @contextmanager
    def scripted_connection(_owner, *, timeout_seconds: float = 1.0):
        yield scripted

    def monotonic_sample() -> int:
        if begin_attempts:
            return deadline
        return now_ns[0]

    monkeypatch.setattr(GatewayQuotaAdmission, "_connection", scripted_connection)
    monkeypatch.setattr(quota_module.time, "monotonic_ns", monotonic_sample)
    with pytest.raises(GatewayQuotaAdmissionError) as expired:
        with owner._transaction(deadline):
            body_calls += 1

    assert expired.value.code == "DEADLINE_EXCEEDED"
    assert begin_attempts == 1
    assert body_calls == commits == 0
    assert rollbacks == 1


def test_admit_rejects_late_successful_commit_and_keeps_its_quota_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "late-quota-commit.sqlite3"
    owner = _adaptive_wait_owner(path, capacity=2, reserved=0)
    now_ns = [time.monotonic_ns()]
    deadline = now_ns[0] + 100_000_000
    commit_calls = 0
    grant_commit_calls = 0
    rollback_calls = 0
    original_connection = GatewayQuotaAdmission._connection

    class LateCommitConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection
            self._has_grant_write = False

        def execute(self, statement: str, parameters=()):
            if statement.lstrip().startswith("INSERT INTO grants"):
                self._has_grant_write = True
            return self._connection.execute(statement, parameters)

        def commit(self) -> None:
            nonlocal commit_calls, grant_commit_calls
            self._connection.commit()
            commit_calls += 1
            if self._has_grant_write:
                grant_commit_calls += 1
                now_ns[0] = deadline + 1

        def rollback(self) -> None:
            nonlocal rollback_calls
            rollback_calls += 1
            self._connection.rollback()

        def __getattr__(self, name: str):
            return getattr(self._connection, name)

    @contextmanager
    def late_commit_connection(
        quota_owner: GatewayQuotaAdmission, *, timeout_seconds: float = 1.0
    ):
        with original_connection(
            quota_owner, timeout_seconds=timeout_seconds
        ) as connection:
            yield LateCommitConnection(connection)

    monkeypatch.setattr(GatewayQuotaAdmission, "_connection", late_commit_connection)
    monkeypatch.setattr(quota_module.time, "monotonic_ns", lambda: now_ns[0])

    with pytest.raises(GatewayQuotaAdmissionError) as expired:
        owner.admit(
            GatewayQuotaSubject(
                "acct:late", "strategy:late", "BTC-PERP", "run:late"
            ),
            GatewayQuotaOperation.OPEN,
            deadline,
        )

    assert expired.value.code == "DEADLINE_EXCEEDED"
    assert commit_calls == 2
    assert grant_commit_calls == 1
    assert rollback_calls == 0
    with sqlite3.connect(path) as connection:
        grants = connection.execute(
            "SELECT operation, sequence FROM grants WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchall()
        waiters = connection.execute(
            "SELECT COUNT(*) FROM waiters WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchone()[0]
    assert grants == [("open", 1)]
    assert waiters == 0


def test_admit_commit_failure_does_not_return_grant_or_skip_waiter_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "quota-grant-commit-failure.sqlite3"
    owner = _adaptive_wait_owner(path, capacity=2, reserved=0)
    original_connection = GatewayQuotaAdmission._connection
    grant_insert_calls = 0
    grant_commit_attempts = 0
    commit_attempts = 0
    successful_commits = 0
    rollback_calls = 0

    class FailGrantCommitConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection
            self._has_grant_write = False

        def execute(self, statement: str, parameters=()):
            nonlocal grant_insert_calls
            if statement.lstrip().startswith("INSERT INTO grants"):
                grant_insert_calls += 1
                self._has_grant_write = True
            return self._connection.execute(statement, parameters)

        def commit(self) -> None:
            nonlocal grant_commit_attempts, commit_attempts, successful_commits
            commit_attempts += 1
            if self._has_grant_write:
                grant_commit_attempts += 1
                error = sqlite3.OperationalError("database is locked")
                error.sqlite_errorcode = sqlite3.SQLITE_BUSY
                raise error
            self._connection.commit()
            successful_commits += 1

        def rollback(self) -> None:
            nonlocal rollback_calls
            rollback_calls += 1
            self._connection.rollback()

        def __getattr__(self, name: str):
            return getattr(self._connection, name)

    @contextmanager
    def failing_grant_connection(
        quota_owner: GatewayQuotaAdmission, *, timeout_seconds: float = 1.0
    ):
        with original_connection(
            quota_owner, timeout_seconds=timeout_seconds
        ) as connection:
            yield FailGrantCommitConnection(connection)

    monkeypatch.setattr(
        GatewayQuotaAdmission, "_connection", failing_grant_connection
    )

    with pytest.raises(GatewayQuotaAdmissionError) as unavailable:
        owner.admit(
            GatewayQuotaSubject(
                "acct:commit-fail", "strategy:commit-fail", "BTC-PERP", "run:commit-fail"
            ),
            GatewayQuotaOperation.OPEN,
            time.monotonic_ns() + 500_000_000,
        )

    assert unavailable.value.code == "OWNER_UNAVAILABLE"
    assert grant_insert_calls == grant_commit_attempts == 1
    assert commit_attempts == 3
    assert successful_commits == 2
    assert rollback_calls == 1
    with sqlite3.connect(path) as connection:
        grants = connection.execute(
            "SELECT operation FROM grants WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchall()
        waiters = connection.execute(
            "SELECT COUNT(*) FROM waiters WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchone()[0]
    assert grants == []
    assert waiters == 0


def test_deadline_spent_before_commit_rolls_back_without_replaying_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = _adaptive_wait_owner(
        tmp_path / "quota-precommit-deadline.sqlite3", capacity=2, reserved=0
    )
    now_ns = [1_000]
    deadline = 10_000
    begin_calls = 0
    body_calls = 0
    commit_calls = 0
    rollback_calls = 0
    busy_timeout_updates: list[str] = []

    class DeadlineConnection:
        def execute(self, statement: str, parameters=()):
            nonlocal begin_calls
            if statement == "BEGIN IMMEDIATE":
                begin_calls += 1
                return None
            if statement.startswith("PRAGMA busy_timeout = "):
                busy_timeout_updates.append(statement)
                now_ns[0] = deadline
                return None
            raise AssertionError(f"unexpected transaction statement: {statement}")

        def commit(self) -> None:
            nonlocal commit_calls
            commit_calls += 1

        def rollback(self) -> None:
            nonlocal rollback_calls
            rollback_calls += 1

    scripted = DeadlineConnection()

    @contextmanager
    def scripted_connection(
        _owner: GatewayQuotaAdmission, *, timeout_seconds: float = 1.0
    ):
        yield scripted

    monkeypatch.setattr(GatewayQuotaAdmission, "_connection", scripted_connection)
    monkeypatch.setattr(quota_module.time, "monotonic_ns", lambda: now_ns[0])

    with pytest.raises(GatewayQuotaAdmissionError) as expired:
        with owner._transaction(deadline):
            body_calls += 1
            now_ns[0] = deadline - 500

    assert expired.value.code == "DEADLINE_EXCEEDED"
    assert begin_calls == body_calls == rollback_calls == 1
    assert commit_calls == 0
    assert busy_timeout_updates == ["PRAGMA busy_timeout = 0"]


def test_initial_enqueue_retries_busy_begin_until_lock_releases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "initial-enqueue-busy-release.sqlite3"
    owner = _adaptive_wait_owner(
        path,
        capacity=2,
        reserved=0,
        max_queue_wait_seconds=1.0,
    )
    blocker = sqlite3.connect(path, timeout=0.0, isolation_level=None, check_same_thread=False)
    blocker.execute("BEGIN IMMEDIATE")
    release_error: list[BaseException] = []

    def release_writer() -> None:
        try:
            time.sleep(0.04)
            blocker.execute("ROLLBACK")
        except BaseException as exc:  # pragma: no cover - diagnostic on failure.
            release_error.append(exc)
        finally:
            blocker.close()

    owner_connections: list[sqlite3.Connection] = []
    original_connection = GatewayQuotaAdmission._connection

    @contextmanager
    def track_owner_connection(
        quota_owner: GatewayQuotaAdmission, *, timeout_seconds: float = 1.0
    ):
        with original_connection(
            quota_owner, timeout_seconds=timeout_seconds
        ) as connection:
            owner_connections.append(connection)
            yield connection

    monkeypatch.setattr(GatewayQuotaAdmission, "_connection", track_owner_connection)
    release_thread = threading.Thread(target=release_writer, name="quota-lock-release")
    release_thread.start()
    try:
        grant = owner.admit(
            GatewayQuotaSubject("acct:initial", "strategy:initial", "BTC-PERP", "run:initial"),
            GatewayQuotaOperation.OPEN,
            time.monotonic_ns() + 900_000_000,
        )
    finally:
        release_thread.join(timeout=1.0)
        if release_thread.is_alive():
            try:
                blocker.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            release_thread.join(timeout=0.25)

    assert not release_thread.is_alive()
    assert release_error == []
    assert len(owner_connections) >= 2
    for connection in owner_connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
            connection.execute("SELECT 1")

    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT granted_ns FROM grants WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchone()
        last_mono_ns = int(
            connection.execute(
                "SELECT last_mono_ns FROM quota_domains WHERE domain_digest = ?",
                (owner._domain_digest,),
            ).fetchone()[0]
        )
        pending = int(
            connection.execute(
                "SELECT COUNT(*) FROM waiters WHERE domain_digest = ?",
                (owner._domain_digest,),
            ).fetchone()[0]
        )
    assert row is not None
    assert grant.granted_monotonic_ns == int(row[0])
    assert last_mono_ns >= grant.granted_monotonic_ns
    assert pending == 0


def test_initial_enqueue_lock_held_through_deadline_leaves_no_waiter(
    tmp_path: Path,
) -> None:
    path = tmp_path / "initial-enqueue-busy-deadline.sqlite3"
    owner = _adaptive_wait_owner(
        path,
        capacity=2,
        reserved=0,
        max_queue_wait_seconds=1.0,
    )
    blocker = sqlite3.connect(path, timeout=0.0, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    deadline = time.monotonic_ns() + 80_000_000
    started = time.monotonic_ns()
    try:
        with pytest.raises(GatewayQuotaAdmissionError) as expired:
            owner.admit(
                GatewayQuotaSubject("acct:never", "strategy:never", "BTC-PERP", "run:never"),
                GatewayQuotaOperation.OPEN,
                deadline,
            )
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()

    assert expired.value.code == "DEADLINE_EXCEEDED"
    assert time.monotonic_ns() >= deadline
    assert time.monotonic_ns() - started < 1_000_000_000
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM waiters WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchone()[0] == 0


def test_persisted_waiter_survives_busy_begin_until_expired_grant_releases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "persisted-waiter-busy-release.sqlite3"
    owner = _adaptive_wait_owner(
        path,
        capacity=1,
        reserved=0,
        max_queue_wait_seconds=2.0,
    )
    seed = GatewayQuotaSubject("acct:seed", "strategy:seed", "BTC-PERP", "run:seed")
    owner.admit(seed, GatewayQuotaOperation.OPEN, time.monotonic_ns() + 1_000_000_000)
    now_ns = time.monotonic_ns()
    seed_expiry_ns = now_ns + 400_000_000
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE grants SET granted_ns = ? WHERE domain_digest = ?",
            (seed_expiry_ns - owner._window_ns, owner._domain_digest),
        )
        connection.execute(
            "UPDATE quota_domains SET last_mono_ns = ? WHERE domain_digest = ?",
            (now_ns, owner._domain_digest),
        )

    outcomes: list[GatewayQuotaGrant] = []
    errors: list[BaseException] = []
    waiter = GatewayQuotaSubject("acct:waiter", "strategy:waiter", "BTC-PERP", "run:waiter")
    deadline = time.monotonic_ns() + 1_500_000_000
    busy_begin_attempts: list[int] = []
    busy_begin_observed = threading.Event()

    class BeginTrackingConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection

        def execute(self, statement: str, parameters=()):
            try:
                return self._connection.execute(statement, parameters)
            except sqlite3.OperationalError as exc:
                if statement == "BEGIN IMMEDIATE" and _is_test_sqlite_busy(exc):
                    busy_begin_attempts.append(time.monotonic_ns())
                    busy_begin_observed.set()
                raise

        def __getattr__(self, name: str):
            return getattr(self._connection, name)

    original_connection = GatewayQuotaAdmission._connection

    @contextmanager
    def track_owner_connection(
        quota_owner: GatewayQuotaAdmission, *, timeout_seconds: float = 1.0
    ):
        with original_connection(
            quota_owner, timeout_seconds=timeout_seconds
        ) as connection:
            yield BeginTrackingConnection(connection)

    monkeypatch.setattr(GatewayQuotaAdmission, "_connection", track_owner_connection)

    def admit_waiter() -> None:
        try:
            outcomes.append(owner.admit(waiter, GatewayQuotaOperation.OPEN, deadline))
        except BaseException as exc:  # pragma: no cover - surfaced in the main test.
            errors.append(exc)

    worker = threading.Thread(target=admit_waiter, name="quota-persisted-waiter")
    worker.start()
    blocker = sqlite3.connect(path, timeout=0.0, isolation_level=None)
    acquired_lock = False
    try:
        pending = 0
        row_deadline = time.monotonic() + 1.0
        while time.monotonic() < row_deadline:
            with sqlite3.connect(path) as connection:
                pending = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM waiters WHERE domain_digest = ? AND subject_digest = ?",
                        (owner._domain_digest, quota_module._subject_digest(waiter)),
                    ).fetchone()[0]
                )
            if pending == 1:
                break
            time.sleep(0.002)
        assert pending == 1, "admit did not persist its waiter before polling"

        lock_deadline = time.monotonic() + 0.5
        while time.monotonic() < lock_deadline:
            try:
                blocker.execute("BEGIN IMMEDIATE")
                acquired_lock = True
                break
            except sqlite3.OperationalError as exc:
                if not _is_test_sqlite_busy(exc):
                    raise
                time.sleep(0.002)
        assert acquired_lock, "test failed to establish a SQLite writer lock"
        remaining_deadline_seconds = max(
            0.0, (deadline - time.monotonic_ns()) / 1_000_000_000
        )
        assert busy_begin_observed.wait(timeout=remaining_deadline_seconds), (
            "persisted waiter did not reach a BUSY BEGIN while the writer lock was held"
        )

        with sqlite3.connect(path) as connection:
            pending_while_locked = int(
                connection.execute(
                    "SELECT COUNT(*) FROM waiters WHERE domain_digest = ? AND subject_digest = ?",
                    (owner._domain_digest, quota_module._subject_digest(waiter)),
                ).fetchone()[0]
            )
        assert pending_while_locked == 1
        assert busy_begin_attempts
        blocker.execute("ROLLBACK")
        acquired_lock = False
    finally:
        if acquired_lock:
            blocker.execute("ROLLBACK")
        blocker.close()
        worker.join(timeout=2.5)

    assert not worker.is_alive()
    assert errors == []
    assert len(outcomes) == 1
    assert outcomes[0].sequence == 2
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM waiters WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT sequence, granted_ns FROM grants WHERE domain_digest = ?",
            (owner._domain_digest,),
        ).fetchall() == [(2, outcomes[0].granted_monotonic_ns)]


def test_begin_busy_retries_end_at_business_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = _adaptive_wait_owner(tmp_path / "begin-busy-deadline.sqlite3", capacity=2, reserved=0)
    now_ns = [10_000_000_000]
    deadline = now_ns[0] + 11_000_000
    begin_attempts = 0
    sleeps: list[float] = []

    class AlwaysBusyConnection:
        def execute(self, statement: str):
            nonlocal begin_attempts
            assert statement == "BEGIN IMMEDIATE"
            begin_attempts += 1
            error = sqlite3.OperationalError("database is locked")
            error.sqlite_errorcode = sqlite3.SQLITE_BUSY
            raise error

        def commit(self) -> None:
            raise AssertionError("begin never succeeded")

        def rollback(self) -> None:
            raise AssertionError("begin never succeeded")

    scripted = AlwaysBusyConnection()

    @contextmanager
    def scripted_connection(_owner, *, timeout_seconds: float = 1.0):
        assert 0 < timeout_seconds <= owner._poll_interval_seconds
        yield scripted

    def advance_clock(seconds: float) -> None:
        sleeps.append(seconds)
        now_ns[0] += int(seconds * 1_000_000_000)

    monkeypatch.setattr(GatewayQuotaAdmission, "_connection", scripted_connection)
    monkeypatch.setattr(quota_module.time, "monotonic_ns", lambda: now_ns[0])
    monkeypatch.setattr(quota_module.time, "sleep", advance_clock)
    with pytest.raises(GatewayQuotaAdmissionError) as expired:
        with owner._transaction(deadline):
            raise AssertionError("busy BEGIN must not yield")

    assert expired.value.code == "DEADLINE_EXCEEDED"
    assert 1 < begin_attempts < 10
    assert sum(sleeps) == pytest.approx(0.011)
