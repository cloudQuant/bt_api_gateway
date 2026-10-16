"""Tests for the provider-neutral dispatch quota adapter."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from bt_api_gateway.quota_admission import (
    GatewayQuotaAdmission,
    GatewayQuotaAdmissionError,
    GatewayQuotaDispatchAdmission,
)


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
    tmp_path: Path, critical_operation: str, stored_operation: str
) -> None:
    path = tmp_path / "reserved-quota.sqlite3"
    owner = _owner(path, capacity=2, reserved=1)
    callback = GatewayQuotaDispatchAdmission(owner)

    assert callback(
        "acct:2", "strategy:2", "run:2", "ETH-PERP", "OPEN", time.monotonic_ns() + 100_000_000
    ) is None
    with pytest.raises(GatewayQuotaAdmissionError) as denied:
        callback(
            "acct:2", "strategy:2", "run:2", "ETH-PERP", "OPEN", time.monotonic_ns() + 10_000_000
        )
    assert denied.value.code == "DEADLINE_EXCEEDED"
    assert callback(
        "acct:2",
        "strategy:2",
        "run:2",
        "ETH-PERP",
        critical_operation,
        time.monotonic_ns() + 100_000_000,
    ) is None

    with sqlite3.connect(path) as connection:
        operations = connection.execute(
            "SELECT operation FROM grants ORDER BY sequence"
        ).fetchall()
    assert operations == [("open",), (stored_operation,)]


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
