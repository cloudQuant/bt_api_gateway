"""Durable consumer offer and acknowledgement contracts."""

from __future__ import annotations

import sqlite3

import pytest

from bt_api_gateway import (
    GatewayCommandKind,
    GatewayEventJournal,
    GatewayEventJournalError,
    GatewayPrincipal,
)


def _reader(
    principal_id: str = "principal:a",
    accounts: tuple[str, ...] = ("account:a",),
    strategies: tuple[str, ...] = ("strategy:a",),
) -> GatewayPrincipal:
    return GatewayPrincipal(
        principal_id=principal_id,
        account_scopes=frozenset(accounts),
        strategy_scopes=frozenset(strategies),
        allowed_kinds=frozenset({GatewayCommandKind.READ}),
    )


def _append(journal: GatewayEventJournal, count: int = 1) -> None:
    for index in range(count):
        journal.append(
            "account:a",
            "strategy:a",
            "event:" + str(index + 1),
            "order_update",
            {"sequence": index + 1},
            observed_at=1_700_000_000.0 + index,
        )


def _error_code(call, code: str) -> None:
    with pytest.raises(GatewayEventJournalError) as raised:
        call()
    assert raised.value.code == code


def test_epoch_and_progress_survive_reopen_and_are_independent_by_key(tmp_path) -> None:
    database = tmp_path / "gateway.db"
    journal = GatewayEventJournal(database)
    _append(journal, 2)
    principal = _reader(
        accounts=("account:a", "account:b"), strategies=("strategy:a", "strategy:b")
    )

    first_batch, first = journal.read_for_consumer(
        principal, "account:a", "strategy:a", "consumer:one", cursor=0, limit=1
    )
    _, second = journal.read_for_consumer(
        principal, "account:a", "strategy:a", "consumer:two", cursor=0, limit=2
    )
    _, other_strategy = journal.read_for_consumer(
        principal, "account:a", "strategy:b", "consumer:one", cursor=0
    )
    other_principal = _reader("principal:b")
    _, other_identity = journal.read_for_consumer(
        other_principal, "account:a", "strategy:a", "consumer:one", cursor=0
    )

    assert [event.sequence for event in first_batch.events] == [1]
    assert first.offered_cursor == 1
    assert second.offered_cursor == 2
    assert first.stream_epoch == second.stream_epoch == other_identity.stream_epoch
    assert other_strategy.stream_epoch != first.stream_epoch

    reopened = GatewayEventJournal(database)
    assert reopened.consumer_progress(principal, "account:a", "strategy:a", "consumer:one") == first
    assert (
        reopened.consumer_progress(principal, "account:a", "strategy:a", "consumer:two") == second
    )

    reopened.acknowledge(
        principal,
        "account:a",
        "strategy:a",
        "consumer:one",
        stream_epoch=first.stream_epoch,
        cursor=1,
    )
    assert (
        reopened.consumer_progress(
            principal, "account:a", "strategy:a", "consumer:two"
        ).acknowledged_cursor
        == 0
    )
    reopened.acknowledge(
        other_principal,
        "account:a",
        "strategy:a",
        "consumer:one",
        stream_epoch=other_identity.stream_epoch,
        cursor=2,
    )
    assert (
        reopened.consumer_progress(
            principal, "account:a", "strategy:a", "consumer:one"
        ).acknowledged_cursor
        == 1
    )

    other_database = GatewayEventJournal(tmp_path / "other.db")
    _, new_database_progress = other_database.read_for_consumer(
        principal, "account:a", "strategy:a", "consumer:one", cursor=0
    )
    assert new_database_progress.stream_epoch != first.stream_epoch


def test_initial_cursor_and_resume_must_stay_within_offered_range(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    _append(journal, 3)
    principal = _reader()

    _error_code(
        lambda: journal.read_for_consumer(
            principal, "account:a", "strategy:a", "consumer:x", cursor=1
        ),
        "STREAM_EPOCH_REQUIRED",
    )
    _error_code(
        lambda: journal.read_for_consumer(
            principal,
            "account:a",
            "strategy:a",
            "consumer:x",
            cursor=1,
            stream_epoch="untrusted-epoch",
        ),
        "STREAM_EPOCH_MISMATCH",
    )

    _, progress = journal.read_for_consumer(
        principal, "account:a", "strategy:a", "consumer:x", cursor=0, limit=1
    )
    assert progress.offered_cursor == 1
    _error_code(
        lambda: journal.read_for_consumer(
            principal,
            "account:a",
            "strategy:a",
            "consumer:x",
            cursor=2,
            stream_epoch=progress.stream_epoch,
        ),
        "CONSUMER_CURSOR_UNOFFERED",
    )

    resumed, unchanged = journal.read_for_consumer(
        principal,
        "account:a",
        "strategy:a",
        "consumer:x",
        cursor=1,
        stream_epoch=progress.stream_epoch,
        limit=1,
    )
    assert [event.sequence for event in resumed.events] == [2]
    assert unchanged.offered_cursor == 2


def test_acknowledgement_is_bounded_monotone_and_does_not_delete_events(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    _append(journal, 2)
    principal = _reader()
    _, progress = journal.read_for_consumer(
        principal, "account:a", "strategy:a", "consumer:x", cursor=0, limit=2
    )

    _error_code(
        lambda: journal.acknowledge(
            principal,
            "account:a",
            "strategy:a",
            "consumer:x",
            stream_epoch="wrong-epoch",
            cursor=1,
        ),
        "STREAM_EPOCH_MISMATCH",
    )
    _error_code(
        lambda: journal.acknowledge(
            principal,
            "account:a",
            "strategy:a",
            "consumer:x",
            stream_epoch=progress.stream_epoch,
            cursor=3,
        ),
        "ACK_CURSOR_AHEAD",
    )
    _error_code(
        lambda: journal.acknowledge(
            principal,
            "account:a",
            "strategy:a",
            "consumer:x",
            stream_epoch=progress.stream_epoch,
            cursor=True,
        ),
        "ACK_CURSOR_INVALID",
    )

    acknowledged = journal.acknowledge(
        principal,
        "account:a",
        "strategy:a",
        "consumer:x",
        stream_epoch=progress.stream_epoch,
        cursor=2,
    )
    assert acknowledged.acknowledged_cursor == 2
    assert (
        journal.acknowledge(
            principal,
            "account:a",
            "strategy:a",
            "consumer:x",
            stream_epoch=progress.stream_epoch,
            cursor=1,
        )
        == acknowledged
    )
    assert [
        event.sequence
        for event in journal.read_after(principal, "account:a", "strategy:a", 0).events
    ] == [1, 2]


def test_snapshot_baseline_advances_offer_after_compaction(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    _append(journal, 3)
    principal = _reader()
    _, offered = journal.read_for_consumer(
        principal, "account:a", "strategy:a", "consumer:x", cursor=0, limit=1
    )
    assert offered.offered_cursor == 1

    journal.capture_snapshot(
        "account:a",
        "strategy:a",
        "snapshot:three",
        expected_cursor=3,
        payload={"covered": 3},
        captured_at=1_700_000_010.0,
    )
    batch, recovered = journal.read_for_consumer(
        principal,
        "account:a",
        "strategy:a",
        "consumer:x",
        cursor=1,
        stream_epoch=offered.stream_epoch,
    )
    assert batch.snapshot is not None
    assert batch.snapshot.cursor == batch.next_cursor == 3
    assert recovered.offered_cursor == 3
    assert recovered.acknowledged_cursor == 0


def test_progress_lookup_and_ack_require_existing_consumer_and_acl(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    allowed = _reader()
    _error_code(
        lambda: journal.consumer_progress(allowed, "account:a", "strategy:a", "consumer:x"),
        "CONSUMER_NOT_FOUND",
    )

    denied_account = _reader("other", accounts=("account:other",))
    _error_code(
        lambda: journal.read_for_consumer(denied_account, "account:a", "strategy:a", "consumer:x"),
        "ACCOUNT_SCOPE_DENIED",
    )
    _error_code(
        lambda: journal.consumer_progress(denied_account, "account:a", "strategy:a", "consumer:x"),
        "ACCOUNT_SCOPE_DENIED",
    )
    _error_code(
        lambda: journal.acknowledge(
            denied_account,
            "account:a",
            "strategy:a",
            "consumer:x",
            stream_epoch="epoch",
            cursor=0,
        ),
        "ACCOUNT_SCOPE_DENIED",
    )

    with journal._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM gateway_consumer_streams").fetchone()[0] == 0
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM gateway_consumer_progress").fetchone()[0] == 0
        )


def test_invalid_consumer_and_cursor_values_have_finite_codes(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    principal = _reader()
    _error_code(
        lambda: journal.read_for_consumer(principal, "account:a", "strategy:a", "bad\nconsumer"),
        "CONSUMER_REF_INVALID",
    )
    _error_code(
        lambda: journal.read_for_consumer(principal, "account:a", "strategy:a", "x" * 129),
        "CONSUMER_REF_INVALID",
    )
    _error_code(
        lambda: journal.read_for_consumer(
            principal, "account:a", "strategy:a", "consumer:x", cursor=True
        ),
        "CURSOR_INVALID",
    )
    _error_code(
        lambda: journal.read_for_consumer(
            principal, "account:a", "strategy:a", "consumer:x", limit=0
        ),
        "BATCH_SIZE_INVALID",
    )
    _error_code(
        lambda: journal.consumer_progress(principal, "account:a", "strategy:a", "absent"),
        "CONSUMER_NOT_FOUND",
    )


def test_failed_offer_rolls_back_stream_epoch_and_progress_insert(tmp_path) -> None:
    database = tmp_path / "gateway.db"
    journal = GatewayEventJournal(database)
    _append(journal)
    principal = _reader()
    with journal._connection() as connection:
        connection.execute(
            """
            CREATE TRIGGER fail_consumer_insert BEFORE INSERT ON gateway_consumer_progress
            BEGIN SELECT RAISE(ABORT, 'synthetic insert failure'); END
            """
        )

    with pytest.raises(sqlite3.IntegrityError):
        journal.read_for_consumer(principal, "account:a", "strategy:a", "consumer:x", cursor=0)

    with journal._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM gateway_consumer_streams").fetchone()[0] == 0
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM gateway_consumer_progress").fetchone()[0] == 0
        )
        connection.execute("DROP TRIGGER fail_consumer_insert")

    _, progress = journal.read_for_consumer(
        principal, "account:a", "strategy:a", "consumer:x", cursor=0
    )
    assert progress.offered_cursor == 1


def test_capacity_rejects_only_new_streams_and_consumers(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    journal.MAX_CONSUMER_STREAMS = 1
    journal.MAX_CONSUMER_PROGRESS_RECORDS = 1
    principal = _reader(
        accounts=("account:a", "account:b"), strategies=("strategy:a", "strategy:b")
    )

    _, first = journal.read_for_consumer(
        principal, "account:a", "strategy:a", "consumer:one", cursor=0
    )
    _error_code(
        lambda: journal.read_for_consumer(
            principal, "account:a", "strategy:a", "consumer:two", cursor=0
        ),
        "CONSUMER_PROGRESS_CAPACITY",
    )
    _, still_usable = journal.read_for_consumer(
        principal,
        "account:a",
        "strategy:a",
        "consumer:one",
        cursor=0,
        stream_epoch=first.stream_epoch,
    )
    assert still_usable == first
    _error_code(
        lambda: journal.read_for_consumer(
            principal, "account:b", "strategy:b", "consumer:one", cursor=0
        ),
        "CONSUMER_STREAM_CAPACITY",
    )

    with journal._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM gateway_consumer_streams").fetchone()[0] == 1
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM gateway_consumer_progress").fetchone()[0] == 1
        )
