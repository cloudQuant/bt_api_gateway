"""Transactional response-size selection for tracked consumer pages."""

from __future__ import annotations

import json
from collections.abc import Mapping

import pytest

from bt_api_gateway import (
    GatewayCommandKind,
    GatewayEventJournal,
    GatewayEventJournalError,
    GatewayPrincipal,
)
from bt_api_gateway.event_journal import GatewayConsumerProgress, GatewayReadBatch


def _reader() -> GatewayPrincipal:
    return GatewayPrincipal(
        principal_id="principal:a",
        account_scopes=frozenset({"account:a"}),
        strategy_scopes=frozenset({"strategy:a"}),
        allowed_kinds=frozenset({GatewayCommandKind.READ}),
    )


def _append(
    journal: GatewayEventJournal,
    count: int,
    *,
    text: str = "fact",
) -> None:
    for sequence in range(1, count + 1):
        journal.append(
            "account:a",
            "strategy:a",
            f"event:{sequence}",
            "account.fact",
            {"sequence": sequence, "text": text},
            observed_at=1_800_000_000.0 + sequence,
        )


def _snapshot_json(batch: GatewayReadBatch):
    snapshot = batch.snapshot
    if snapshot is None:
        return None
    return {
        "account_scope": snapshot.account_scope,
        "strategy_scope": snapshot.strategy_scope,
        "snapshot_id": snapshot.snapshot_id,
        "cursor": snapshot.cursor,
        "payload": _plain_json(snapshot.payload),
        "captured_at": snapshot.captured_at,
    }


def _wire_reply_size(batch: GatewayReadBatch, progress: GatewayConsumerProgress) -> int:
    value = {
        "requested_cursor": batch.requested_cursor,
        "snapshot": _snapshot_json(batch),
        "events": [
            {
                "account_scope": event.account_scope,
                "strategy_scope": event.strategy_scope,
                "sequence": event.sequence,
                "event_id": event.event_id,
                "kind": event.kind,
                "payload": _plain_json(event.payload),
                "observed_at": event.observed_at,
            }
            for event in batch.events
        ],
        "next_cursor": batch.next_cursor,
        "latest_cursor": batch.latest_cursor,
        "recovered_from_snapshot": (
            batch.requested_cursor is not None
            and batch.snapshot is not None
            and batch.requested_cursor < batch.snapshot.cursor
        ),
        "consumer_progress": {
            "stream_epoch": progress.stream_epoch,
            "offered_cursor": progress.offered_cursor,
            "acknowledged_cursor": progress.acknowledged_cursor,
        },
    }
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return len(encoded)


def _plain_json(value):
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_json(item) for item in value]
    return value


def _error_code(call, expected: str) -> None:
    with pytest.raises(GatewayEventJournalError) as raised:
        call()
    assert raised.value.code == expected


def _counts(journal: GatewayEventJournal) -> tuple[int, int]:
    with journal._connection() as connection:
        streams = connection.execute("SELECT COUNT(*) FROM gateway_consumer_streams").fetchone()[0]
        progress = connection.execute("SELECT COUNT(*) FROM gateway_consumer_progress").fetchone()[
            0
        ]
    return streams, progress


def test_selects_largest_fitting_contiguous_prefix(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    _append(journal, 4)
    observed_prefixes: list[tuple[int, ...]] = []

    def page_fits(batch: GatewayReadBatch, progress: GatewayConsumerProgress) -> bool:
        prefix = tuple(event.sequence for event in batch.events)
        observed_prefixes.append(prefix)
        return len(prefix) <= 2 and progress.offered_cursor == batch.next_cursor

    batch, progress = journal.read_for_consumer(
        _reader(),
        "account:a",
        "strategy:a",
        "consumer:x",
        cursor=0,
        page_fits=page_fits,
    )

    assert observed_prefixes == [(1,), (1, 2, 3, 4), (1, 2), (1, 2, 3), (1, 2)]
    assert [event.sequence for event in batch.events] == [1, 2]
    assert batch.next_cursor == progress.offered_cursor == 2
    assert progress.acknowledged_cursor == 0
    assert _counts(journal) == (1, 1)


def test_page_fit_uses_exact_ascii_json_byte_size_for_unicode_payload(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    text = "价格💹"
    _append(journal, 1, text=text)
    base = journal.read_after(_reader(), "account:a", "strategy:a", cursor=0)
    expected_size = _wire_reply_size(base, GatewayConsumerProgress("0" * 32, 1, 0))
    escaped_size = len(
        json.dumps(
            {"text": text, "sequence": 1},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    )
    unescaped_size = len(
        json.dumps(
            {"text": text, "sequence": 1},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    )
    assert escaped_size > unescaped_size
    observed_sizes: list[int] = []

    def page_fits(batch: GatewayReadBatch, progress: GatewayConsumerProgress) -> bool:
        size = _wire_reply_size(batch, progress)
        observed_sizes.append(size)
        return size <= expected_size

    batch, progress = journal.read_for_consumer(
        _reader(),
        "account:a",
        "strategy:a",
        "consumer:unicode",
        cursor=0,
        page_fits=page_fits,
    )
    assert observed_sizes == [expected_size]
    assert batch.next_cursor == progress.offered_cursor == 1


def test_oversized_first_event_rolls_back_new_stream_and_consumer(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    _append(journal, 1, text="x" * 4096)

    _error_code(
        lambda: journal.read_for_consumer(
            _reader(),
            "account:a",
            "strategy:a",
            "consumer:large",
            cursor=0,
            page_fits=lambda _batch, _progress: False,
        ),
        "CONSUMER_PAGE_TOO_LARGE",
    )
    assert _counts(journal) == (0, 0)
    _error_code(
        lambda: journal.consumer_progress(_reader(), "account:a", "strategy:a", "consumer:large"),
        "CONSUMER_NOT_FOUND",
    )


def test_failed_later_page_preserves_existing_offer_and_ack(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    _append(journal, 1)
    principal = _reader()
    _, initial = journal.read_for_consumer(
        principal, "account:a", "strategy:a", "consumer:x", cursor=0
    )
    journal.acknowledge(
        principal,
        "account:a",
        "strategy:a",
        "consumer:x",
        stream_epoch=initial.stream_epoch,
        cursor=1,
    )
    before = journal.consumer_progress(principal, "account:a", "strategy:a", "consumer:x")
    journal.append(
        "account:a",
        "strategy:a",
        "event:2",
        "account.fact",
        {"sequence": 2, "text": "cannot-fit"},
        observed_at=1_800_000_002.0,
    )

    _error_code(
        lambda: journal.read_for_consumer(
            principal,
            "account:a",
            "strategy:a",
            "consumer:x",
            cursor=1,
            stream_epoch=initial.stream_epoch,
            page_fits=lambda _batch, _progress: False,
        ),
        "CONSUMER_PAGE_TOO_LARGE",
    )
    assert journal.consumer_progress(principal, "account:a", "strategy:a", "consumer:x") == before


def test_snapshot_only_baseline_can_fit_before_an_oversized_tail(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    _append(journal, 2)
    journal.capture_snapshot(
        "account:a",
        "strategy:a",
        "snapshot:two",
        expected_cursor=2,
        payload={"baseline": "ready"},
        captured_at=1_800_000_010.0,
    )
    journal.append(
        "account:a",
        "strategy:a",
        "event:3",
        "account.fact",
        {"sequence": 3, "text": "x" * 4096},
        observed_at=1_800_000_011.0,
    )
    principals = _reader()
    seen: list[int] = []

    def baseline_fits(batch: GatewayReadBatch, _progress: GatewayConsumerProgress) -> bool:
        seen.append(len(batch.events))
        return not batch.events

    baseline, progress = journal.read_for_consumer(
        principals,
        "account:a",
        "strategy:a",
        "consumer:snapshot",
        cursor=0,
        page_fits=baseline_fits,
    )
    assert seen == [0, 1, 0]
    assert baseline.snapshot is not None and baseline.snapshot.cursor == 2
    assert baseline.events == ()
    assert baseline.next_cursor == progress.offered_cursor == 2

    tail, tail_progress = journal.read_for_consumer(
        principals,
        "account:a",
        "strategy:a",
        "consumer:snapshot",
        cursor=2,
        stream_epoch=progress.stream_epoch,
        page_fits=lambda batch, _progress: bool(batch.events),
    )
    assert tail.snapshot is None
    assert [event.sequence for event in tail.events] == [3]
    assert tail.next_cursor == tail_progress.offered_cursor == 3


def test_unfitting_snapshot_and_tail_roll_back_new_consumer(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    _append(journal, 2)
    journal.capture_snapshot(
        "account:a",
        "strategy:a",
        "snapshot:two",
        expected_cursor=2,
        payload={"value": "x" * 4096},
        captured_at=1_800_000_010.0,
    )
    journal.append(
        "account:a",
        "strategy:a",
        "event:3",
        "account.fact",
        {"sequence": 3, "text": "tail"},
        observed_at=1_800_000_011.0,
    )
    _error_code(
        lambda: journal.read_for_consumer(
            _reader(),
            "account:a",
            "strategy:a",
            "consumer:oversized-snapshot",
            cursor=0,
            page_fits=lambda _batch, _progress: False,
        ),
        "CONSUMER_PAGE_TOO_LARGE",
    )
    assert _counts(journal) == (0, 0)
    with journal._connection() as connection:
        row = connection.execute(
            "SELECT snapshot_id, cursor FROM gateway_event_snapshots"
        ).fetchone()
    assert row["snapshot_id"] == "snapshot:two"
    assert row["cursor"] == 2


def test_invalid_fit_result_and_callback_exception_roll_back(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    _append(journal, 1)
    _error_code(
        lambda: journal.read_for_consumer(
            _reader(),
            "account:a",
            "strategy:a",
            "consumer:invalid",
            cursor=0,
            page_fits=lambda _batch, _progress: 1,
        ),
        "CONSUMER_PAGE_FIT_INVALID",
    )
    assert _counts(journal) == (0, 0)

    def fail(_batch: GatewayReadBatch, _progress: GatewayConsumerProgress) -> bool:
        raise RuntimeError("should not escape")

    _error_code(
        lambda: journal.read_for_consumer(
            _reader(),
            "account:a",
            "strategy:a",
            "consumer:exception",
            cursor=0,
            page_fits=fail,
        ),
        "CONSUMER_PAGE_CHECK_FAILED",
    )
    assert _counts(journal) == (0, 0)


def test_untracked_read_and_default_tracked_read_keep_full_page_behavior(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    _append(journal, 3)
    principal = _reader()
    legacy = journal.read_after(principal, "account:a", "strategy:a", cursor=0, limit=2)
    tracked, progress = journal.read_for_consumer(
        principal, "account:a", "strategy:a", "consumer:legacy", cursor=0, limit=2
    )
    assert tracked == legacy
    assert progress.offered_cursor == tracked.next_cursor == 2


def test_fit_callback_receives_cumulative_offer_without_mutating_ack(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    _append(journal, 3)
    principal = _reader()
    _, first = journal.read_for_consumer(
        principal, "account:a", "strategy:a", "consumer:x", cursor=0, limit=2
    )
    journal.acknowledge(
        principal,
        "account:a",
        "strategy:a",
        "consumer:x",
        stream_epoch=first.stream_epoch,
        cursor=1,
    )
    seen: list[tuple[int, int, int]] = []

    def one_event(batch: GatewayReadBatch, progress: GatewayConsumerProgress) -> bool:
        seen.append((len(batch.events), progress.offered_cursor, progress.acknowledged_cursor))
        return len(batch.events) <= 1

    selected, progress = journal.read_for_consumer(
        principal,
        "account:a",
        "strategy:a",
        "consumer:x",
        cursor=0,
        stream_epoch=first.stream_epoch,
        limit=3,
        page_fits=one_event,
    )
    assert seen == [(1, 2, 1), (3, 3, 1), (2, 2, 1), (1, 2, 1)]
    assert [event.sequence for event in selected.events] == [1]
    assert progress.offered_cursor == 2
    assert progress.acknowledged_cursor == 1


def test_large_page_uses_logarithmically_bounded_fit_checks(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    _append(journal, 1000)
    inspected_prefixes: list[int] = []

    def bounded_size(batch: GatewayReadBatch, _progress: GatewayConsumerProgress) -> bool:
        prefix = len(batch.events)
        inspected_prefixes.append(prefix)
        return prefix <= 321

    batch, progress = journal.read_for_consumer(
        _reader(),
        "account:a",
        "strategy:a",
        "consumer:large-page",
        cursor=0,
        limit=1000,
        page_fits=bounded_size,
    )

    assert len(batch.events) == 321
    assert batch.next_cursor == progress.offered_cursor == 321
    assert inspected_prefixes[0] == 1
    assert inspected_prefixes[-1] == 321
    assert len(inspected_prefixes) <= 13
