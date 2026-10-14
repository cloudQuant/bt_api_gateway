"""Durable replacement-snapshot contracts for account state streams."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from bt_api_gateway import (
    GatewayCommandKind,
    GatewayEventJournal,
    GatewayEventJournalError,
    GatewayPrincipal,
)


def _reader() -> GatewayPrincipal:
    return GatewayPrincipal(
        principal_id="client-state",
        account_scopes=frozenset({"account:state"}),
        strategy_scopes=frozenset({"strategy:state"}),
        allowed_kinds=frozenset({GatewayCommandKind.READ}),
    )


def _replace(
    journal: GatewayEventJournal,
    snapshot_id: str,
    payload: dict[str, object],
    expected_cursor: int,
    captured_at: float,
):
    return journal.replace_state_snapshot(
        "account:state",
        "strategy:state",
        snapshot_id,
        payload,
        expected_cursor=expected_cursor,
        captured_at=captured_at,
    )


def test_state_snapshot_exact_retry_returns_stored_snapshot_and_rejects_reuse(tmp_path) -> None:
    database = tmp_path / "gateway.db"
    journal = GatewayEventJournal(database, clock=lambda: 1_700_000_000.0)
    first = _replace(
        journal,
        "state:one",
        {"cash": "100", "positions": {"BTC-USDT": "2"}},
        0,
        1_700_000_001.0,
    )

    replay = _replace(
        journal,
        "state:one",
        {"positions": {"BTC-USDT": "2"}, "cash": "100"},
        0,
        1_700_000_001.0,
    )
    with pytest.raises(GatewayEventJournalError) as payload_reuse:
        _replace(
            journal,
            "state:one",
            {"cash": "999", "positions": {"BTC-USDT": "2"}},
            0,
            1_700_000_001.0,
        )
    with pytest.raises(GatewayEventJournalError) as time_reuse:
        _replace(
            journal,
            "state:one",
            {"cash": "100", "positions": {"BTC-USDT": "2"}},
            0,
            1_700_000_002.0,
        )

    assert first == replay
    assert first.cursor == 1
    assert payload_reuse.value.code == "SNAPSHOT_ID_REUSED"
    assert time_reuse.value.code == "SNAPSHOT_ID_REUSED"


def test_two_writers_using_same_cursor_have_one_winner(tmp_path) -> None:
    database = tmp_path / "gateway.db"
    first_journal = GatewayEventJournal(database)
    second_journal = GatewayEventJournal(database)
    initial = _replace(first_journal, "state:one", {"balance": "1"}, 0, 1_700_000_001.0)
    start = Barrier(2)

    def update(journal: GatewayEventJournal, snapshot_id: str):
        start.wait(timeout=5)
        try:
            return _replace(
                journal, snapshot_id, {"balance": snapshot_id}, initial.cursor, 1_700_000_002.0
            )
        except GatewayEventJournalError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (
            executor.submit(update, first_journal, "state:left"),
            executor.submit(update, second_journal, "state:right"),
        )
        outcomes = [future.result(timeout=10) for future in futures]

    successes = [outcome for outcome in outcomes if not isinstance(outcome, str)]
    conflicts = [outcome for outcome in outcomes if isinstance(outcome, str)]
    assert len(successes) == 1
    assert successes[0].cursor == 2
    assert conflicts == ["SNAPSHOT_CURSOR_STALE"]


def test_state_snapshot_rolls_back_mode_and_cursor_when_snapshot_write_fails(tmp_path) -> None:
    database = tmp_path / "gateway.db"
    journal = GatewayEventJournal(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TRIGGER fail_state_snapshot
            BEFORE INSERT ON gateway_event_snapshots
            WHEN NEW.snapshot_id = 'state:fail'
            BEGIN
                SELECT RAISE(ABORT, 'injected snapshot write failure');
            END
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="injected snapshot write failure"):
        _replace(journal, "state:fail", {"balance": "1"}, 0, 1_700_000_001.0)

    with sqlite3.connect(database) as connection:
        counts = {
            "gateway_event_stream_modes": connection.execute(
                "SELECT COUNT(*) FROM gateway_event_stream_modes"
            ).fetchone()[0],
            "gateway_event_sequences": connection.execute(
                "SELECT COUNT(*) FROM gateway_event_sequences"
            ).fetchone()[0],
            "gateway_event_snapshots": connection.execute(
                "SELECT COUNT(*) FROM gateway_event_snapshots"
            ).fetchone()[0],
            "gateway_events": connection.execute("SELECT COUNT(*) FROM gateway_events").fetchone()[
                0
            ],
            "gateway_event_dedupe": connection.execute(
                "SELECT COUNT(*) FROM gateway_event_dedupe"
            ).fetchone()[0],
        }
    assert counts == {
        "gateway_event_stream_modes": 0,
        "gateway_event_sequences": 0,
        "gateway_event_snapshots": 0,
        "gateway_events": 0,
        "gateway_event_dedupe": 0,
    }


def test_state_snapshot_survives_restart_and_replaces_for_lagging_readers(tmp_path) -> None:
    database = tmp_path / "gateway.db"
    journal = GatewayEventJournal(database, clock=lambda: 1_700_000_000.0)
    first = _replace(journal, "state:one", {"balance": "1"}, 0, 1_700_000_001.0)
    latest = _replace(journal, "state:two", {"balance": "2"}, 1, 1_700_000_002.0)
    restarted = GatewayEventJournal(database, clock=lambda: 1_700_000_000.0)

    from_zero = restarted.read_after(_reader(), "account:state", "strategy:state", 0)
    from_old_cursor = restarted.read_after(
        _reader(), "account:state", "strategy:state", first.cursor
    )
    caught_up = restarted.read_after(_reader(), "account:state", "strategy:state", latest.cursor)

    assert from_zero.snapshot == latest
    assert from_zero.snapshot.payload["balance"] == "2"
    assert from_zero.events == ()
    assert from_zero.next_cursor == from_zero.latest_cursor == 2
    assert from_old_cursor.snapshot == latest
    assert from_old_cursor.events == ()
    assert caught_up.snapshot is None
    assert caught_up.next_cursor == caught_up.latest_cursor == 2


def test_one_hundred_state_updates_keep_event_and_dedupe_tables_empty(tmp_path) -> None:
    database = tmp_path / "gateway.db"
    journal = GatewayEventJournal(database)
    cursor = 0
    for balance in range(100):
        snapshot = _replace(
            journal,
            f"state:{balance}",
            {"balance": str(balance)},
            cursor,
            1_700_000_000.0 + balance,
        )
        cursor = snapshot.cursor

    restarted = GatewayEventJournal(database)
    batch = restarted.read_after(_reader(), "account:state", "strategy:state", 0)
    with sqlite3.connect(database) as connection:
        event_count = connection.execute("SELECT COUNT(*) FROM gateway_events").fetchone()[0]
        dedupe_count = connection.execute("SELECT COUNT(*) FROM gateway_event_dedupe").fetchone()[0]
        sequence_rows = connection.execute(
            """
            SELECT COUNT(*), MAX(latest_sequence) FROM gateway_event_sequences
            WHERE account_scope = 'account:state' AND strategy_scope = 'strategy:state'
            """
        ).fetchone()
        snapshot_rows = connection.execute(
            """
            SELECT COUNT(*) FROM gateway_event_snapshots
            WHERE account_scope = 'account:state' AND strategy_scope = 'strategy:state'
            """
        ).fetchone()[0]

    assert event_count == dedupe_count == 0
    assert sequence_rows == (1, 100)
    assert snapshot_rows == 1
    assert batch.latest_cursor == batch.next_cursor == 100
    assert batch.snapshot.cursor == 100
    assert batch.snapshot.payload["balance"] == "99"


def test_state_and_event_stream_modes_cannot_be_mixed(tmp_path) -> None:
    event_journal = GatewayEventJournal(tmp_path / "events.db")
    event_journal.append(
        "account:state",
        "strategy:state",
        "provider.event.1",
        "position_update",
        {"quantity": "1"},
    )
    with pytest.raises(GatewayEventJournalError) as state_after_event:
        _replace(event_journal, "state:one", {"quantity": "1"}, 1, 1_700_000_001.0)
    assert state_after_event.value.code == "STREAM_MODE_CONFLICT"

    snapshot_journal = GatewayEventJournal(tmp_path / "snapshot.db")
    snapshot_journal.capture_snapshot(
        "account:state",
        "strategy:state",
        "event-snapshot:zero",
        expected_cursor=0,
        payload={"positions": {}},
    )
    with pytest.raises(GatewayEventJournalError) as state_after_snapshot:
        _replace(snapshot_journal, "state:one", {"quantity": "1"}, 0, 1_700_000_001.0)
    assert state_after_snapshot.value.code == "STREAM_MODE_CONFLICT"

    state_journal = GatewayEventJournal(tmp_path / "state.db")
    _replace(state_journal, "state:one", {"quantity": "1"}, 0, 1_700_000_001.0)
    with pytest.raises(GatewayEventJournalError) as append_after_state:
        state_journal.append(
            "account:state",
            "strategy:state",
            "provider.event.1",
            "position_update",
            {"quantity": "2"},
        )
    with pytest.raises(GatewayEventJournalError) as snapshot_after_state:
        state_journal.capture_snapshot(
            "account:state",
            "strategy:state",
            "event-snapshot:one",
            expected_cursor=1,
            payload={"positions": {}},
        )
    assert append_after_state.value.code == "STREAM_MODE_CONFLICT"
    assert snapshot_after_state.value.code == "STREAM_MODE_CONFLICT"


def test_state_snapshot_payload_size_and_cursor_are_bounded(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    with pytest.raises(GatewayEventJournalError) as too_large:
        _replace(
            journal,
            "state:large",
            {"padding": "x" * GatewayEventJournal.MAX_STATE_SNAPSHOT_BYTES},
            0,
            1_700_000_001.0,
        )
    assert too_large.value.code == "STATE_SNAPSHOT_TOO_LARGE"

    with pytest.raises(ValueError, match="expected_cursor"):
        journal.replace_state_snapshot(
            "account:state",
            "strategy:state",
            "state:invalid-cursor",
            {"balance": "1"},
            expected_cursor=True,
            captured_at=1_700_000_001.0,
        )
    with pytest.raises(GatewayEventJournalError) as stale:
        _replace(journal, "state:stale", {"balance": "1"}, 1, 1_700_000_001.0)

    assert stale.value.code == "SNAPSHOT_CURSOR_STALE"
    with sqlite3.connect(tmp_path / "gateway.db") as connection:
        mode_count = connection.execute(
            "SELECT COUNT(*) FROM gateway_event_stream_modes"
        ).fetchone()[0]
    assert mode_count == 0
