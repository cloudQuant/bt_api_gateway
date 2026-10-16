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


def test_dispatch_adapter_maps_trusted_operations_and_preserves_run_identity(
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
            "SELECT operation, subject_digest FROM grants ORDER BY sequence"
        ).fetchall()

    assert [row[0] for row in rows] == [
        "open",
        "open",
        "close",
        "cancel",
        "reconcile",
        "accepted_group_action",
    ]
    assert rows[0][1] != rows[1][1]
    assert all(len(row[1]) == 64 for row in rows)

    with pytest.raises(GatewayQuotaAdmissionError) as unsupported:
        callback("acct:1", "strategy:1", "run:1", "BTC-PERP", "ADMIN", deadline)
    assert unsupported.value.code == "INVALID_OPERATION"
    with pytest.raises(GatewayQuotaAdmissionError) as missing_run:
        callback("acct:1", "strategy:1", "", "BTC-PERP", "OPEN", deadline)
    assert missing_run.value.code == "INVALID_SUBJECT"


def test_close_can_use_reserved_capacity_but_open_cannot(tmp_path: Path) -> None:
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
        "acct:2", "strategy:2", "run:2", "ETH-PERP", "CLOSE", time.monotonic_ns() + 100_000_000
    ) is None

    with sqlite3.connect(path) as connection:
        operations = connection.execute(
            "SELECT operation FROM grants ORDER BY sequence"
        ).fetchall()
    assert operations == [("open",), ("close",)]


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
