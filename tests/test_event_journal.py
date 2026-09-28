"""Offline durability, scope-isolation, and snapshot-recovery contracts."""

from __future__ import annotations

import pytest

from bt_api_gateway import (
    GatewayCommandKind,
    GatewayEventJournal,
    GatewayEventJournalError,
    GatewayPrincipal,
)


def _reader(principal_id: str, strategy_scope: str) -> GatewayPrincipal:
    return GatewayPrincipal(
        principal_id=principal_id,
        account_scopes=frozenset({"account:fixture"}),
        strategy_scopes=frozenset({strategy_scope}),
        allowed_kinds=frozenset({GatewayCommandKind.READ}),
    )


def test_two_clients_share_account_without_cross_strategy_event_visibility(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=lambda: 1_700_000_000.0)
    alpha = _reader("client-alpha", "strategy:alpha")
    beta = _reader("client-beta", "strategy:beta")
    journal.append(
        "account:fixture",
        "strategy:alpha",
        "provider.event.alpha.1",
        "order_update",
        {"client_order_id": "alpha-1", "status": "working"},
    )
    journal.append(
        "account:fixture",
        "strategy:beta",
        "provider.event.beta.1",
        "order_update",
        {"client_order_id": "beta-1", "status": "filled"},
    )

    alpha_batch = journal.read_after(alpha, "account:fixture", "strategy:alpha", 0)
    beta_batch = journal.read_after(beta, "account:fixture", "strategy:beta", 0)

    assert [event.payload["client_order_id"] for event in alpha_batch.events] == ["alpha-1"]
    assert [event.payload["client_order_id"] for event in beta_batch.events] == ["beta-1"]
    with pytest.raises(GatewayEventJournalError) as denied:
        journal.read_after(alpha, "account:fixture", "strategy:beta", 0)
    assert denied.value.code == "STRATEGY_SCOPE_DENIED"


def test_duplicate_event_redelivery_keeps_cursor_and_replays_after_restart(tmp_path) -> None:
    database = tmp_path / "gateway.db"

    def clock() -> float:
        return 1_700_000_000.0

    journal = GatewayEventJournal(database, clock=clock)
    reader = _reader("client-alpha", "strategy:alpha")
    first = journal.append(
        "account:fixture",
        "strategy:alpha",
        "stable.provider.event.1",
        "order_update",
        {"client_order_id": "alpha-1", "status": "working"},
        observed_at=1_700_000_001.0,
    )

    redelivered = journal.append(
        "account:fixture",
        "strategy:alpha",
        "stable.provider.event.1",
        "order_update",
        {"status": "working", "client_order_id": "alpha-1"},
        observed_at=1_700_000_002.0,
    )
    second = journal.append(
        "account:fixture",
        "strategy:alpha",
        "stable.provider.event.2",
        "order_update",
        {"client_order_id": "alpha-1", "status": "filled"},
        observed_at=1_700_000_003.0,
    )
    restarted = GatewayEventJournal(database, clock=clock)

    resumed = restarted.read_after(reader, "account:fixture", "strategy:alpha", first.sequence)

    assert first.sequence == redelivered.sequence == 1
    assert redelivered.observed_at == first.observed_at
    assert second.sequence == 2
    assert [event.event_id for event in resumed.events] == ["stable.provider.event.2"]
    assert resumed.requested_cursor == 1
    assert resumed.next_cursor == resumed.latest_cursor == 2


def test_snapshot_compaction_recovers_stale_client_then_replays_new_events(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=lambda: 1_700_000_000.0)
    reader = _reader("client-alpha", "strategy:alpha")
    for sequence in (1, 2):
        journal.append(
            "account:fixture",
            "strategy:alpha",
            f"provider.event.{sequence}",
            "position_update",
            {"symbol": "BTC-USDT", "quantity": str(sequence)},
            observed_at=1_700_000_000.0 + sequence,
        )

    snapshot = journal.capture_snapshot(
        "account:fixture",
        "strategy:alpha",
        "snapshot:2",
        expected_cursor=2,
        payload={"positions": {"BTC-USDT": "2"}},
        captured_at=1_700_000_003.0,
    )
    redelivered_compacted = journal.append(
        "account:fixture",
        "strategy:alpha",
        "provider.event.1",
        "position_update",
        {"symbol": "BTC-USDT", "quantity": "1"},
        observed_at=1_700_000_003.5,
    )
    with pytest.raises(GatewayEventJournalError) as reused:
        journal.append(
            "account:fixture",
            "strategy:alpha",
            "provider.event.1",
            "position_update",
            {"symbol": "BTC-USDT", "quantity": "999"},
            observed_at=1_700_000_003.5,
        )
    latest = journal.append(
        "account:fixture",
        "strategy:alpha",
        "provider.event.3",
        "position_update",
        {"symbol": "BTC-USDT", "quantity": "3"},
        observed_at=1_700_000_004.0,
    )

    recovered = journal.read_after(reader, "account:fixture", "strategy:alpha", 0)
    resumed = journal.read_after(reader, "account:fixture", "strategy:alpha", snapshot.cursor)
    caught_up = journal.read_after(reader, "account:fixture", "strategy:alpha", latest.sequence)

    assert recovered.snapshot == snapshot
    assert redelivered_compacted.sequence == 1
    assert redelivered_compacted.observed_at == 1_700_000_001.0
    assert reused.value.code == "EVENT_ID_REUSED"
    assert recovered.snapshot.cursor == 2
    assert [event.sequence for event in recovered.events] == [3]
    assert recovered.next_cursor == recovered.latest_cursor == 3
    assert resumed.snapshot is None
    assert [event.sequence for event in resumed.events] == [3]
    assert caught_up.snapshot is None
    assert caught_up.events == ()
    assert caught_up.next_cursor == caught_up.latest_cursor == 3


def test_new_client_can_bootstrap_from_snapshot_at_empty_stream_cursor(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=lambda: 1_700_000_000.0)
    reader = _reader("client-alpha", "strategy:alpha")
    snapshot = journal.capture_snapshot(
        "account:fixture",
        "strategy:alpha",
        "initial-snapshot",
        expected_cursor=0,
        payload={"positions": {}},
        captured_at=1_700_000_001.0,
    )

    bootstrap = journal.read_after(reader, "account:fixture", "strategy:alpha")
    resumed = journal.read_after(reader, "account:fixture", "strategy:alpha", 0)

    assert bootstrap.requested_cursor is None
    assert bootstrap.snapshot == snapshot
    assert bootstrap.next_cursor == 0
    assert resumed.snapshot is None
    assert resumed.next_cursor == 0


def test_snapshot_requires_current_cursor_and_event_id_cannot_change_payload(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=lambda: 1_700_000_000.0)
    journal.append(
        "account:fixture",
        "strategy:alpha",
        "provider.event.1",
        "position_update",
        {"symbol": "BTC-USDT", "quantity": "1"},
    )

    with pytest.raises(GatewayEventJournalError) as stale:
        journal.capture_snapshot(
            "account:fixture",
            "strategy:alpha",
            "snapshot:stale",
            expected_cursor=0,
            payload={"positions": {}},
        )
    assert stale.value.code == "SNAPSHOT_CURSOR_STALE"

    with pytest.raises(GatewayEventJournalError) as reused:
        journal.append(
            "account:fixture",
            "strategy:alpha",
            "provider.event.1",
            "position_update",
            {"symbol": "BTC-USDT", "quantity": "999"},
        )
    assert reused.value.code == "EVENT_ID_REUSED"
    batch = journal.read_after(
        _reader("client-alpha", "strategy:alpha"), "account:fixture", "strategy:alpha", 0
    )
    assert batch.latest_cursor == 1
    assert batch.events[0].payload["quantity"] == "1"


def test_snapshot_content_cannot_change_without_cursor_progress(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=lambda: 1_700_000_000.0)
    journal.append(
        "account:fixture",
        "strategy:alpha",
        "provider.event.1",
        "position_update",
        {"symbol": "BTC-USDT", "quantity": "1"},
    )
    journal.capture_snapshot(
        "account:fixture",
        "strategy:alpha",
        "snapshot:one",
        expected_cursor=1,
        payload={"positions": {"BTC-USDT": "1"}},
        captured_at=1_700_000_001.0,
    )

    with pytest.raises(GatewayEventJournalError) as conflict:
        journal.capture_snapshot(
            "account:fixture",
            "strategy:alpha",
            "snapshot:two",
            expected_cursor=1,
            payload={"positions": {"BTC-USDT": "999"}},
            captured_at=1_700_000_002.0,
        )

    assert conflict.value.code == "SNAPSHOT_CURSOR_CONFLICT"


def test_event_stream_rejects_bad_cursor_and_redacted_payloads(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=lambda: 1_700_000_000.0)
    reader = _reader("client-alpha", "strategy:alpha")
    with pytest.raises(ValueError, match="redacted"):
        journal.append(
            "account:fixture",
            "strategy:alpha",
            "provider.event.secret",
            "account_update",
            {"api_token": "never-persist"},
        )
    with pytest.raises(GatewayEventJournalError) as ahead:
        journal.read_after(reader, "account:fixture", "strategy:alpha", 1)
    assert ahead.value.code == "CURSOR_AHEAD"
    assert journal.read_after(reader, "account:fixture", "strategy:alpha", 0).latest_cursor == 0
