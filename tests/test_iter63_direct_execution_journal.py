"""Synthetic same-DB execution attribution; no provider or account calls."""

import json
import sqlite3
import threading
from dataclasses import FrozenInstanceError, replace

import pytest
from bt_api_base.direct_write_protocol import (
    DirectExecutionEventKind,
    DirectOrderStatus,
    NativeOrderIdentity,
)
from bt_api_base.gateway_execution_protocol import GatewayReturnFact
from bt_api_base.market_protocol import MarketInstrumentKey

from bt_api_gateway.direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
)
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from bt_api_gateway.session_guard import LocalAccountSessionGuard, LocalAccountSessionGuardError


INSTRUMENT = MarketInstrumentKey("ctp", "SHFE", "simnow", "future", "rb2601", "rb2601")


@pytest.fixture
def setup(tmp_path):
    directory = tmp_path / "guards"
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, "acct", "owner")
    generation = guard.acquire()
    journal = GatewayDirectCommandJournal.create(
        tmp_path / "db", "acct", generation=generation, max_records=20, execution_max_facts=20
    )
    ledger = GatewayDirectExecutionLedger(journal, guard)
    yield journal, ledger, guard, tmp_path / "db"
    guard.release()


def command(
    journal, *, strategy="s1", key="req1", anchor="session-a", side="buy", status=None, quantity="2"
):
    row = journal.reserve(
        strategy,
        key,
        "principal",
        {"symbol": "rb2601", "side": side, "offset": "open", "quantity": quantity},
    )
    native = {
        "exchange_name": "CTP",
        "client_order_id": key,
        "session_generation": 1,
        "fields_json": "{}",
    }
    journal.begin_dispatch(
        strategy, key, row.reservation_id, row.digest, "principal", 1, native, (anchor,)
    )
    if status is not None:
        journal.finish(
            strategy, key, row.reservation_id, row.digest, "principal", 2, native, (anchor,), status
        )
    return row, native


def fact(
    *,
    kind=DirectExecutionEventKind.TRADE,
    keys=("session-a", "venue-a"),
    binding=("session-a",),
    venue="venue-a",
    trade_key=("SHFE", "trade-1"),
    side="buy",
    offset="open",
    quantity="1",
    price="10",
    instrument=INSTRUMENT,
    day="20300101",
    route="CTP",
    ref="source-1",
    status=None,
):
    identity = NativeOrderIdentity(route, "ref-a", {"trading_day": day}, 1) if keys else None
    return GatewayReturnFact(
        "acct",
        route,
        instrument,
        day,
        kind,
        ref,
        identity=identity,
        identity_keys=tuple(sorted(keys)),
        binding_keys=tuple(sorted(binding)),
        venue_key=venue,
        trade_key=trade_key if kind is DirectExecutionEventKind.TRADE else None,
        status=status,
        side=side,
        offset=offset,
        trade_quantity=quantity if kind is DirectExecutionEventKind.TRADE else None,
        trade_price=price if kind is DirectExecutionEventKind.TRADE else None,
    )


def revision(journal):
    with journal._transaction() as db:
        return journal._assert_anchor(db)


def test_order_learns_alias_then_trade_updates_exactly_once_and_finish_unchanged(setup):
    journal, ledger, guard, path = setup
    row, native = command(journal)
    order = fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED)
    before = journal.get("s1", "req1", "principal")
    result = ledger.ingest(order)
    assert result.disposition == "ATTRIBUTED" and not result.applied
    assert journal.get("s1", "req1", "principal") == before
    result = ledger.ingest(fact(keys=("venue-a",), binding=()))
    assert result.disposition == "ATTRIBUTED" and result.applied and result.strategy_scope == "s1"
    assert ledger.position("s1", INSTRUMENT) == "1"
    assert len(ledger.read_events("s1")) == 2
    old_revision = revision(journal)
    assert not ledger.ingest(fact(keys=("venue-a",), binding=())).applied
    assert revision(journal) == old_revision
    assert (
        journal.finish(
            "s1",
            "req1",
            row.reservation_id,
            row.digest,
            "principal",
            2,
            native,
            ("session-a",),
            "SENT",
        ).status
        == "SENT"
    )
    reopened = GatewayDirectCommandJournal(
        path,
        "acct",
        generation=journal.generation,
        expected_journal_id=journal.journal_id,
        minimum_revision=old_revision,
        max_records=20,
        execution_max_facts=20,
    )
    assert GatewayDirectExecutionLedger(reopened, guard).position("s1", INSTRUMENT) == "1"


def test_unknown_trade_then_alias_and_reconcile_once(setup):
    journal, ledger, _, _ = setup
    command(journal)
    early = fact(keys=("venue-a",), binding=())
    assert ledger.ingest(early).disposition == "UNATTRIBUTED"
    assert ledger.position("s1", INSTRUMENT) is None
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    results = ledger.reconcile_pending()
    assert len(results) == 1 and results[0].applied
    assert ledger.position("s1", INSTRUMENT) == "1"
    assert ledger.reconcile_pending() == ()
    assert not ledger.ingest(early).applied


def test_content_conflict_persistently_blocks_replay(setup):
    journal, ledger, guard, path = setup
    command(journal)
    first = fact(keys=("session-a",), binding=("session-a",), venue="session-a")
    assert ledger.ingest(first).applied
    conflict = ledger.ingest(replace(first, trade_price="11"))
    assert conflict.disposition == "CONFLICT"
    assert ledger.ingest(first).disposition == "CONFLICT"
    assert ledger.position("s1", INSTRUMENT) == "1"
    assert len(ledger.read_events("s1")) == 1
    with journal._transaction() as db:
        assert db.execute("SELECT count(*) FROM direct_execution_conflicts").fetchone()[0] == 1
    reopened = GatewayDirectCommandJournal(
        path,
        "acct",
        generation=journal.generation,
        expected_journal_id=journal.journal_id,
        minimum_revision=0,
        max_records=20,
        execution_max_facts=20,
    )
    recovered = GatewayDirectExecutionLedger(reopened, guard)
    assert recovered.ingest(first).disposition == "CONFLICT"
    assert recovered.position("s1", INSTRUMENT) == "1"


def test_duplicate_trade_reopens_with_one_applied_position(setup):
    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    first = fact(keys=("session-a",), binding=("session-a",), venue="session-a")
    assert ledger.ingest(first).applied
    duplicate = replace(first, identity_keys=("session-a", "venue-a"))
    assert ledger.ingest(duplicate).reason == "TRADE_DUPLICATE"
    reopened = GatewayDirectCommandJournal(
        path,
        "acct",
        generation=journal.generation,
        expected_journal_id=journal.journal_id,
        minimum_revision=0,
        max_records=20,
        execution_max_facts=20,
    )
    recovered = GatewayDirectExecutionLedger(reopened, guard)
    assert recovered.position("s1", INSTRUMENT) == "1"
    assert recovered.ingest(duplicate).reason == "TRADE_DUPLICATE"


def test_conflicting_key_binding_and_not_sent_late_trade(setup):
    journal, ledger, _, _ = setup
    command(journal, status="NOT_SENT")
    command(journal, strategy="s2", key="req2", anchor="session-b")
    conflict = fact(keys=("session-a", "session-b"), binding=("session-a",), venue="session-a")
    assert ledger.ingest(conflict).disposition == "CONFLICT"
    late = fact(
        keys=("session-a",), binding=("session-a",), venue="session-a", trade_key=("SHFE", "late")
    )
    result = ledger.ingest(late)
    assert result.applied and result.reason == "NOT_SENT_CONTRADICTION"
    assert journal.get("s1", "req1", "principal").status == "NOT_SENT"


def test_sell_delta_overfill_and_strategy_isolation(setup):
    journal, ledger, _, _ = setup
    command(journal, quantity="0.5")
    command(journal, strategy="s2", key="req2", anchor="session-b", side="sell")
    buy = fact(keys=("session-a",), binding=("session-a",), venue="session-a")
    assert ledger.ingest(buy).reason == "OVERFILL"
    sell = fact(
        keys=("session-b",),
        binding=("session-b",),
        venue="session-b",
        trade_key=("SHFE", "trade-2"),
        side="sell",
        quantity="0.25",
    )
    assert ledger.ingest(sell).applied
    assert ledger.position("s1", INSTRUMENT) == "1"
    assert ledger.position("s2", INSTRUMENT) == "-0.25"
    assert len(ledger.read_events("s1")) == len(ledger.read_events("s2")) == 1
    with pytest.raises(FrozenInstanceError):
        ledger.ingest(buy).reason = "changed"


def test_guard_thread_and_capacity_duplicate(setup):
    journal, ledger, _, _ = setup
    command(journal)
    f = fact(keys=("session-a",), binding=("session-a",), venue="session-a")
    assert ledger.ingest(f).applied
    errors, reads = [], []

    def other_thread():
        reads.append(ledger.position("s1", INSTRUMENT))
        try:
            ledger.ingest(f)
        except Exception as exc:
            errors.append(getattr(exc, "code", None))

    thread = threading.Thread(target=other_thread)
    thread.start()
    thread.join(timeout=2)
    assert reads == ["1"] and errors == ["WRONG_OWNER"]


def test_account_scope_requires_owner_and_is_read_only(setup):
    _, ledger, guard, _ = setup
    assert ledger.account_scope == "acct"
    with pytest.raises(AttributeError):
        ledger.account_scope = "different"
    errors = []

    def other_thread():
        try:
            ledger.account_scope
        except DirectCommandJournalError as exc:
            errors.append(exc.code)

    thread = threading.Thread(target=other_thread)
    thread.start()
    thread.join(timeout=2)
    assert not thread.is_alive() and errors == ["WRONG_OWNER"]
    guard.release()
    with pytest.raises(LocalAccountSessionGuardError) as error:
        _ = ledger.account_scope
    assert error.value.code == "SESSION_NOT_OWNED"


def test_trade_unknown_venue_cannot_be_claimed_by_another_strategy(setup):
    journal, ledger, guard, path = setup
    command(journal)
    command(journal, strategy="s2", key="req2", anchor="session-b")
    early = fact(keys=("session-a", "venue-x"), binding=("session-a",), venue="venue-x")
    assert ledger.ingest(early).reason == "IDENTITY_KEYS_UNBOUND"
    assert ledger.position("s1", INSTRUMENT) is None
    other_order = fact(
        kind=DirectExecutionEventKind.ORDER,
        keys=("session-b", "venue-x"),
        binding=("session-b",),
        venue="venue-x",
        status=DirectOrderStatus.ACCEPTED,
    )
    assert ledger.ingest(other_order).disposition == "ATTRIBUTED"
    (result,) = ledger.reconcile_pending()
    assert result.disposition == "CONFLICT" and not result.applied
    assert ledger.position("s1", INSTRUMENT) is None
    reopened = GatewayDirectCommandJournal(
        path,
        "acct",
        generation=journal.generation,
        expected_journal_id=journal.journal_id,
        minimum_revision=0,
        max_records=20,
        execution_max_facts=20,
    )
    assert GatewayDirectExecutionLedger(reopened, guard).position("s1", INSTRUMENT) is None


def test_unknown_extra_key_blocks_even_when_anchor_matches(setup):
    journal, ledger, _, _ = setup
    command(journal)
    incoming = fact(keys=("unknown-extra", "session-a"), binding=("session-a",), venue="session-a")
    assert ledger.ingest(incoming).reason == "IDENTITY_KEYS_UNBOUND"
    assert ledger.position("s1", INSTRUMENT) is None


def test_conflicting_binding_same_trade_key_preserves_prior_quantity(setup):
    journal, ledger, _, _ = setup
    command(journal)
    command(journal, strategy="s2", key="req2", anchor="session-b")
    first = fact(keys=("session-a",), binding=("session-a",), venue="session-a")
    assert ledger.ingest(first).applied
    wrong = replace(first, identity_keys=("session-a", "session-b"), binding_keys=("session-b",))
    assert ledger.ingest(wrong).disposition == "CONFLICT"
    assert ledger.ingest(first).disposition == "CONFLICT"
    assert ledger.position("s1", INSTRUMENT) == "1" and ledger.position("s2", INSTRUMENT) is None


def test_offset_missing_is_pending_and_scope_and_limit_validation(setup):
    journal, ledger, _, _ = setup
    command(journal)
    item = fact(keys=("session-a",), binding=("session-a",), venue="session-a", offset=None)
    assert ledger.ingest(item).reason == "TRADE_OFFSET_MISSING"
    assert ledger.position("s1", INSTRUMENT) is None
    with pytest.raises(DirectCommandJournalError, match="INVALID_INPUT"):
        ledger.read_events("s1", after_sequence=2**63)
    with pytest.raises(DirectCommandJournalError, match="INVALID_LIMIT"):
        ledger.reconcile_pending(limit=257)


def test_readonly_wrong_account_and_capacity(tmp_path):
    directory = tmp_path / "guards"
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, "acct", "owner")
    generation = guard.acquire()
    try:
        journal = GatewayDirectCommandJournal.create(
            tmp_path / "db", "acct", generation=generation, max_records=20, execution_max_facts=1
        )
        ledger = GatewayDirectExecutionLedger(journal, guard)
        command(journal)
        item = fact(keys=("session-a",), binding=("session-a",), venue="session-a")
        assert ledger.ingest(item).applied
        before = revision(journal)
        assert not ledger.ingest(item).applied and revision(journal) == before
        with pytest.raises(DirectCommandJournalError, match="EXECUTION_CAPACITY_EXCEEDED"):
            ledger.ingest(replace(item, trade_key=("SHFE", "other")))
        with pytest.raises(DirectCommandJournalError, match="ACCOUNT_MISMATCH"):
            ledger.ingest(replace(item, account_scope="wrong"))
        assert revision(journal) == before
    finally:
        guard.release()


def _downgrade_v3(path):
    with sqlite3.connect(path) as db:
        for name in (
            "direct_execution_consumers",
            "direct_execution_meta",
            "direct_execution_facts",
            "direct_execution_aliases",
            "direct_execution_trades",
            "direct_execution_positions",
            "direct_execution_totals",
            "direct_execution_events",
            "direct_execution_conflicts",
        ):
            db.execute(f"DROP TABLE {name}")
        db.execute("UPDATE direct_journal_meta SET schema_version=3")


def test_v3_explicit_upgrade_preserves_command_and_settlement(setup):
    from bt_api_base.direct_write_protocol import SettlementObservation, SettlementStatus

    journal, _, guard, path = setup
    row, native = command(journal)
    observed = SettlementObservation(
        "CTP", "binding", "20300101", 1, SettlementStatus.UNCONFIRMED, "obs"
    )
    settlement = journal.settlement_begin(
        observed, "marker", before_begin=lambda: None, before_commit=lambda: None
    ).record
    _downgrade_v3(path)
    journal._schema_version = 3
    assert journal.get("s1", "req1", "principal").status == "DISPATCHING"
    before = revision(journal)
    with pytest.raises(DirectCommandJournalError):
        GatewayDirectCommandJournal(
            path,
            "acct",
            generation=journal.generation,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=20,
            execution_max_facts=20,
        )
    upgraded = GatewayDirectCommandJournal.upgrade_v3(
        path,
        "acct",
        generation=journal.generation,
        guard=guard,
        expected_journal_id=journal.journal_id,
        minimum_revision=before,
        max_records=20,
        execution_max_facts=20,
    )
    assert upgraded.settlement_get("CTP", "20300101") == settlement
    assert upgraded.get("s1", "req1", "principal").strong_identity_keys == ("session-a",)
    assert revision(upgraded) == before + 1
    with pytest.raises(DirectCommandJournalError, match="SCHEMA_OR_CAPACITY_MISMATCH"):
        journal.get("s1", "req1", "principal")
    assert (
        upgraded.finish(
            "s1",
            "req1",
            row.reservation_id,
            row.digest,
            "principal",
            2,
            native,
            ("session-a",),
            "SENT",
        ).status
        == "SENT"
    )


@pytest.mark.parametrize("fault_index", range(11))
def test_v3_upgrade_each_ddl_failure_rolls_back(setup, monkeypatch, fault_index):
    from bt_api_gateway import direct_execution_journal as module

    journal, _, guard, path = setup
    command(journal)
    _downgrade_v3(path)
    with sqlite3.connect(path) as db:
        before = db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()

    def broken(db, account, maximum):
        for index, ddl in enumerate(module._EXECUTION_DDL.values()):
            db.execute(ddl)
            if index == fault_index:
                raise RuntimeError("synthetic ddl failure")

    monkeypatch.setattr(module, "_create_execution_tables", broken)
    with pytest.raises(RuntimeError, match="synthetic ddl failure"):
        GatewayDirectCommandJournal.upgrade_v3(
            path,
            "acct",
            generation=journal.generation,
            guard=guard,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=20,
            execution_max_facts=20,
        )
    with sqlite3.connect(path) as db:
        assert (
            db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
            == before
        )
        assert (
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE name LIKE 'direct_execution_%'"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "trigger",
        "extra_index",
        "core_status",
        "core_version",
        "core_digest",
        "orphan_release",
        "settlement_status",
        "fact_json",
        "fact_digest",
        "trade_digest",
        "trade_quantity",
        "trade_orphan",
        "event_sequence",
        "event_strategy",
        "position_nan",
        "position_changed",
        "total_changed",
        "total_missing",
        "alias_unsupported",
        "alias_missing_index",
        "fact_reason",
        "fact_capacity",
        "fact_count",
    ],
)
def test_reopen_rejects_schema_and_execution_projection_corruption(setup, mutation):
    from bt_api_base.direct_write_protocol import SettlementObservation, SettlementStatus

    journal, ledger, _, path = setup
    row, _ = command(journal)
    settlement = SettlementObservation(
        "CTP", "binding", "20300101", 1, SettlementStatus.UNCONFIRMED, "obs"
    )
    journal.settlement_begin(
        settlement, "marker", before_begin=lambda: None, before_commit=lambda: None
    )
    order = fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED)
    ledger.ingest(order)
    ledger.ingest(fact(keys=("venue-a",), binding=()))
    with sqlite3.connect(path) as db:
        if mutation == "trigger":
            db.execute(
                "CREATE TRIGGER bad_trigger AFTER INSERT ON direct_execution_facts BEGIN DELETE FROM direct_execution_positions; END"
            )
        elif mutation == "extra_index":
            db.execute("CREATE INDEX bad_extra ON direct_execution_positions(net_quantity)")
        elif mutation == "core_status":
            db.execute("UPDATE direct_journal_commands SET status='BROKEN'")
        elif mutation == "core_version":
            db.execute("UPDATE direct_journal_commands SET version=9")
        elif mutation == "core_digest":
            db.execute("UPDATE direct_journal_commands SET digest='wrong'")
        elif mutation == "orphan_release":
            db.execute(
                "INSERT INTO direct_journal_releases VALUES ('acct','bad','s','missing','none','bad','p',1)"
            )
        elif mutation == "settlement_status":
            db.execute("UPDATE direct_journal_settlement SET status='BROKEN'")
        elif mutation == "fact_json":
            db.execute(
                "UPDATE direct_execution_facts SET fact_json='{}' WHERE rowid=(SELECT min(rowid) FROM direct_execution_facts)"
            )
        elif mutation == "fact_digest":
            db.execute(
                "UPDATE direct_execution_facts SET fact_digest='bad' WHERE rowid=(SELECT min(rowid) FROM direct_execution_facts)"
            )
        elif mutation == "trade_digest":
            db.execute("UPDATE direct_execution_trades SET content_digest='bad'")
        elif mutation == "trade_quantity":
            db.execute("UPDATE direct_execution_trades SET quantity='9'")
        elif mutation == "trade_orphan":
            db.execute("UPDATE direct_execution_trades SET fact_digest='missing'")
        elif mutation == "event_sequence":
            sequence = db.execute("SELECT min(sequence) FROM direct_execution_events").fetchone()[0]
            db.execute(
                "UPDATE direct_execution_events SET sequence=-1 WHERE sequence=?", (sequence,)
            )
            db.execute(
                "UPDATE direct_execution_facts SET event_sequence=-1 WHERE event_sequence=?",
                (sequence,),
            )
        elif mutation == "event_strategy":
            db.execute("UPDATE direct_execution_events SET strategy='other'")
        elif mutation == "position_nan":
            db.execute("UPDATE direct_execution_positions SET net_quantity='NaN'")
        elif mutation == "position_changed":
            db.execute("UPDATE direct_execution_positions SET net_quantity='999'")
        elif mutation == "total_changed":
            db.execute("UPDATE direct_execution_totals SET total_quantity='999'")
        elif mutation == "total_missing":
            db.execute("DELETE FROM direct_execution_totals")
        elif mutation == "alias_unsupported":
            db.execute(
                "INSERT INTO direct_execution_aliases VALUES ('acct','venue-fake',?)",
                (row.reservation_id,),
            )
            db.execute(
                "INSERT INTO direct_journal_strong_keys VALUES ('acct','venue-fake',?)",
                (row.reservation_id,),
            )
        elif mutation == "alias_missing_index":
            db.execute("DELETE FROM direct_journal_strong_keys WHERE strong_key='venue-a'")
        elif mutation == "fact_reason":
            db.execute(
                "UPDATE direct_execution_facts SET reason='arbitrary' WHERE rowid=(SELECT min(rowid) FROM direct_execution_facts)"
            )
        elif mutation == "fact_count":
            db.execute("UPDATE direct_execution_meta SET fact_count=99")
        else:
            db.execute("UPDATE direct_execution_meta SET max_facts=1")
    with pytest.raises(DirectCommandJournalError):
        GatewayDirectCommandJournal(
            path,
            "acct",
            generation=journal.generation,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=20,
            execution_max_facts=20,
        )


def test_fair_pending_scan_passes_256_unmatchable_facts(tmp_path):
    directory = tmp_path / "guards"
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, "acct", "owner")
    generation = guard.acquire()
    try:
        journal = GatewayDirectCommandJournal.create(
            tmp_path / "db", "acct", generation=generation, max_records=10, execution_max_facts=300
        )
        ledger = GatewayDirectExecutionLedger(journal, guard)
        command(journal)
        for index in range(256):
            item = fact(
                keys=("unmatched",), binding=(), venue="unmatched", trade_key=("SHFE", str(index))
            )
            assert ledger.ingest(item).disposition == "UNATTRIBUTED"
        target = fact(
            keys=("session-a", "venue-a"),
            binding=("session-a",),
            venue="venue-a",
            trade_key=("SHFE", "target"),
        )
        assert ledger.ingest(target).disposition == "UNATTRIBUTED"
        ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
        assert not any(result.applied for result in ledger.reconcile_pending(limit=256))
        (result,) = ledger.reconcile_pending(limit=256)
        assert result.fact_digest == target.fact_digest() and result.applied
        assert ledger.position("s1", INSTRUMENT) == "1"
    finally:
        guard.release()


def test_reopen_rejects_orphan_reservation_in_conflicting_fact(setup):
    journal, ledger, _, path = setup
    command(journal)
    first = fact(keys=("session-a",), binding=("session-a",), venue="session-a")
    assert ledger.ingest(first).applied
    ledger.ingest(replace(first, trade_price="11"))
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE direct_execution_facts SET reservation_id='missing' WHERE disposition='CONFLICT'"
        )
    with pytest.raises(DirectCommandJournalError):
        GatewayDirectCommandJournal(
            path,
            "acct",
            generation=journal.generation,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=20,
            execution_max_facts=20,
        )


def test_reopen_rejects_duplicate_fact_when_original_trade_not_applied(setup):
    journal, ledger, _, path = setup
    row, _ = command(journal)
    item = fact(keys=("session-a",), binding=("session-a",), venue="session-a", quantity=None)
    assert ledger.ingest(item).disposition == "UNATTRIBUTED"
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE direct_execution_facts SET disposition='ATTRIBUTED', reason='TRADE_DUPLICATE', reservation_id=?",
            (row.reservation_id,),
        )
    with pytest.raises(DirectCommandJournalError):
        GatewayDirectCommandJournal(
            path,
            "acct",
            generation=journal.generation,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=20,
            execution_max_facts=20,
        )


def test_reopen_rejects_gap_or_maximum_event_sequence(setup):
    journal, ledger, _, path = setup
    command(journal)
    ledger.ingest(fact(keys=("session-a",), binding=("session-a",), venue="session-a"))
    with sqlite3.connect(path) as db:
        db.execute("UPDATE direct_execution_events SET sequence=?", (2**63 - 1,))
        db.execute("UPDATE direct_execution_facts SET event_sequence=?", (2**63 - 1,))
    with pytest.raises(DirectCommandJournalError):
        GatewayDirectCommandJournal(
            path,
            "acct",
            generation=journal.generation,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=20,
            execution_max_facts=20,
        )


def test_buy_sell_same_strategy_retains_explicit_zero(setup):
    journal, ledger, _, _ = setup
    command(journal)
    command(journal, strategy="s1", key="sell-req", anchor="session-b", side="sell")
    buy = fact(keys=("session-a",), binding=("session-a",), venue="session-a")
    sell = fact(
        keys=("session-b",),
        binding=("session-b",),
        venue="session-b",
        trade_key=("SHFE", "sell"),
        side="sell",
    )
    assert ledger.ingest(buy).applied and ledger.ingest(sell).applied
    assert ledger.position("s1", INSTRUMENT) == "0"


def test_day_scoped_identity_and_trade_keys_do_not_dedupe_across_days(setup):
    journal, ledger, _, _ = setup
    command(journal, key="d1", anchor="day1-session")
    command(journal, key="d2", anchor="day2-session")
    d1 = fact(
        keys=("day1-session",),
        binding=("day1-session",),
        venue="day1-session",
        trade_key=("20300101", "same-native-id"),
        day="20300101",
    )
    d2 = fact(
        keys=("day2-session",),
        binding=("day2-session",),
        venue="day2-session",
        trade_key=("20300102", "same-native-id"),
        day="20300102",
    )
    assert ledger.ingest(d1).applied and ledger.ingest(d2).applied
    assert ledger.position("s1", INSTRUMENT) == "2"


def test_unattributed_fact_cannot_claim_even_existing_reservation_on_reopen(setup):
    journal, ledger, _, path = setup
    row, _ = command(journal)
    unknown = fact(keys=("other",), binding=(), venue="other")
    assert ledger.ingest(unknown).disposition == "UNATTRIBUTED"
    with sqlite3.connect(path) as db:
        db.execute("UPDATE direct_execution_facts SET reservation_id=?", (row.reservation_id,))
    with pytest.raises(DirectCommandJournalError):
        GatewayDirectCommandJournal(
            path,
            "acct",
            generation=journal.generation,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=20,
            execution_max_facts=20,
        )


def test_partial_fills_use_indexed_total_without_scanning_trade_history(setup, monkeypatch):
    from contextlib import contextmanager

    journal, ledger, _, path = setup
    row, _ = command(journal)
    original_connection = journal._connection
    statements = []

    @contextmanager
    def traced_connection():
        with original_connection() as db:
            db.set_trace_callback(statements.append)
            yield db

    monkeypatch.setattr(journal, "_connection", traced_connection)
    for index in range(4):
        item = fact(
            keys=("session-a",),
            binding=("session-a",),
            venue="session-a",
            trade_key=("SHFE", f"trade-{index}"),
        )
        assert ledger.ingest(item).applied
    queries = [sql.lower() for sql in statements]
    assert any("select total_quantity from direct_execution_totals" in sql for sql in queries)
    assert not any("select quantity from direct_execution_trades" in sql for sql in queries)
    assert any("select fact_count from direct_execution_meta" in sql for sql in queries)
    assert not any("select count(*) from direct_execution_facts" in sql for sql in queries)
    with sqlite3.connect(path) as db:
        assert (
            db.execute(
                "SELECT total_quantity FROM direct_execution_totals WHERE reservation_id=?",
                (row.reservation_id,),
            ).fetchone()[0]
            == "4"
        )


def test_pagination_queries_use_account_scoped_indexes(setup):
    _, _, _, path = setup
    with sqlite3.connect(path) as db:
        pending = db.execute(
            "EXPLAIN QUERY PLAN SELECT rowid AS scan_rowid,* FROM direct_execution_facts "
            "WHERE account=? AND disposition='UNATTRIBUTED' AND rowid>? ORDER BY rowid LIMIT ?",
            ("acct", 0, 256),
        ).fetchall()
        events = db.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM direct_execution_events "
            "WHERE account=? AND strategy=? AND sequence>? ORDER BY sequence LIMIT ?",
            ("acct", "s1", 0, 256),
        ).fetchall()
    pending_plan = " ".join(row[3] for row in pending).lower()
    events_plan = " ".join(row[3] for row in events).lower()
    assert "direct_execution_facts_pending" in pending_plan
    assert "rowid>?" in pending_plan
    assert "temp b-tree" not in pending_plan
    assert "direct_execution_events_strategy" in events_plan
    assert "sequence>?" in events_plan or "rowid>?" in events_plan
    assert "temp b-tree" not in events_plan


def test_reopen_execution_audit_uses_linear_number_of_indexed_lookups(tmp_path):
    from bt_api_gateway.direct_execution_journal import _verify_execution_integrity

    directory = tmp_path / "guards"
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, "acct", "owner")
    generation = guard.acquire()
    try:
        journal = GatewayDirectCommandJournal.create(
            tmp_path / "db", "acct", generation=generation, max_records=10, execution_max_facts=300
        )
        ledger = GatewayDirectExecutionLedger(journal, guard)
        command(journal)
        order = fact(
            kind=DirectExecutionEventKind.ORDER,
            keys=("session-a",),
            binding=("session-a",),
            venue="session-a",
            status=DirectOrderStatus.ACCEPTED,
        )
        counts = []
        for start, stop in ((0, 100), (100, 200)):
            for index in range(start, stop):
                assert (
                    ledger.ingest(replace(order, error_code=f"E{index}")).disposition
                    == "ATTRIBUTED"
                )
            with sqlite3.connect(tmp_path / "db") as db:
                db.row_factory = sqlite3.Row
                sql = []
                db.set_trace_callback(sql.append)
                _verify_execution_integrity(db, "acct", 300)
                counts.append(len(sql))
        assert counts[0] > 100 and counts[1] <= 2 * counts[0] + 30
    finally:
        guard.release()


@pytest.mark.parametrize("mutation", ["bad_status", "missing_marker", "wrong_account"])
def test_v3_upgrade_rejects_corrupt_settlement_without_schema_change(setup, mutation):
    from bt_api_base.direct_write_protocol import SettlementObservation, SettlementStatus

    journal, _, guard, path = setup
    observed = SettlementObservation(
        "CTP", "binding", "20300101", 1, SettlementStatus.UNCONFIRMED, "obs"
    )
    journal.settlement_begin(
        observed, "marker", before_begin=lambda: None, before_commit=lambda: None
    )
    _downgrade_v3(path)
    with sqlite3.connect(path) as db:
        if mutation == "bad_status":
            db.execute("UPDATE direct_journal_settlement SET status='BROKEN'")
        elif mutation == "missing_marker":
            db.execute("UPDATE direct_journal_settlement SET marker_id=NULL")
        else:
            db.execute("UPDATE direct_journal_settlement SET account='other'")
        before = db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        GatewayDirectCommandJournal.upgrade_v3(
            path,
            "acct",
            generation=journal.generation,
            guard=guard,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=20,
            execution_max_facts=20,
        )
    with sqlite3.connect(path) as db:
        assert (
            db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
            == before
        )
        assert (
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE name LIKE 'direct_execution_%'"
            ).fetchone()[0]
            == 0
        )


def test_position_range_failure_retains_fact_without_rounding(setup):
    journal, ledger, guard, path = setup
    command(journal, quantity="999999999999999999999999999999999999")
    first = fact(
        keys=("session-a",),
        binding=("session-a",),
        venue="session-a",
        quantity="999999999999999999999999999999999999",
    )
    assert ledger.ingest(first).applied
    overflow = replace(first, trade_key=("SHFE", "overflow"), trade_quantity="1")
    assert ledger.ingest(overflow).reason == "POSITION_RANGE_CONFLICT"
    assert ledger.position("s1", INSTRUMENT) == first.trade_quantity
    assert ledger.ingest(overflow).disposition == "CONFLICT"
    reopened = GatewayDirectCommandJournal(
        path,
        "acct",
        generation=journal.generation,
        expected_journal_id=journal.journal_id,
        minimum_revision=0,
        max_records=20,
        execution_max_facts=20,
    )
    assert (
        GatewayDirectExecutionLedger(reopened, guard).position("s1", INSTRUMENT)
        == first.trade_quantity
    )


def test_conflicting_facts_count_towards_full_capacity(tmp_path):
    directory = tmp_path / "guards"
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, "acct", "owner")
    generation = guard.acquire()
    try:
        journal = GatewayDirectCommandJournal.create(
            tmp_path / "db", "acct", generation=generation, max_records=10, execution_max_facts=2
        )
        ledger = GatewayDirectExecutionLedger(journal, guard)
        command(journal)
        item = fact(keys=("session-a",), binding=("session-a",), venue="session-a")
        assert ledger.ingest(item).applied
        assert ledger.ingest(replace(item, trade_price="11")).disposition == "CONFLICT"
        before = revision(journal)
        assert ledger.ingest(item).disposition == "CONFLICT"
        with pytest.raises(DirectCommandJournalError, match="EXECUTION_CAPACITY_EXCEEDED"):
            ledger.ingest(replace(item, trade_key=("SHFE", "third")))
        assert revision(journal) == before
    finally:
        guard.release()


def test_learned_venue_key_blocks_later_command_dispatch(setup):
    journal, ledger, _, _ = setup
    command(journal)
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    second = journal.reserve("s2", "second", "principal", {"symbol": "rb2601"})
    native = {
        "exchange_name": "CTP",
        "client_order_id": "second",
        "session_generation": 1,
        "fields_json": "{}",
    }
    with pytest.raises(DirectCommandJournalError, match="IDENTITY_CONFLICT"):
        journal.begin_dispatch(
            "s2",
            "second",
            second.reservation_id,
            second.digest,
            "principal",
            1,
            native,
            ("venue-a",),
        )
    assert journal.get("s2", "second", "principal").status == "RESERVED"


def test_consumer_sparse_replay_ack_identity_and_reopen(setup):
    journal, ledger, guard, path = setup
    first_command, _ = command(journal)
    second_command, _ = command(journal, strategy="s2", key="req2", anchor="session-b")
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    ledger.ingest(
        fact(
            kind=DirectExecutionEventKind.ORDER,
            keys=("session-b", "venue-b"),
            binding=("session-b",),
            venue="venue-b",
            ref="other",
            status=DirectOrderStatus.ACCEPTED,
        )
    )
    ledger.ingest(fact(ref="trade"))
    before = revision(journal)
    empty = ledger.consumer_progress("s1", principal_id="p", consumer_ref="c")
    assert (empty.offered_sequence, empty.acknowledged_sequence) == (0, 0)
    page = ledger.read_for_consumer(
        "s1", principal_id="p", consumer_ref="c", limit=1, result_fits=lambda _: True
    )
    assert [event.sequence for event in page.events] == [1] and page.has_more
    with pytest.raises(DirectCommandJournalError):
        ledger.read_for_consumer(
            "s1",
            principal_id="p",
            consumer_ref="other",
            after_sequence=1,
            expected_epoch=page.epoch,
            result_fits=lambda _: True,
        )
    with pytest.raises(DirectCommandJournalError):
        ledger.acknowledge(
            "s1", principal_id="p", consumer_ref="c", sequence=2, expected_epoch=page.epoch
        )
    with pytest.raises(DirectCommandJournalError):
        ledger.read_for_consumer(
            "s1",
            principal_id="p",
            consumer_ref="c",
            after_sequence=3,
            expected_epoch=page.epoch,
            result_fits=lambda _: True,
        )
    second = ledger.read_for_consumer(
        "s1",
        principal_id="p",
        consumer_ref="c",
        after_sequence=1,
        expected_epoch=page.epoch,
        result_fits=lambda _: True,
    )
    assert [event.sequence for event in second.events] == [3]
    assert second.offered_sequence == 3 and not second.has_more
    assert (
        ledger.acknowledge(
            "s1", principal_id="p", consumer_ref="c", sequence=3, expected_epoch=page.epoch
        ).acknowledged_sequence
        == 3
    )
    assert (
        ledger.acknowledge(
            "s1", principal_id="p", consumer_ref="c", sequence=1, expected_epoch=page.epoch
        ).acknowledged_sequence
        == 3
    )
    replay = ledger.read_for_consumer(
        "s1", principal_id="p", consumer_ref="c", result_fits=lambda _: True
    )
    assert [event.sequence for event in replay.events] == [1, 3]
    for event in replay.events:
        assert (
            event.request_key,
            event.reservation_id,
            event.command_digest,
            event.command_principal,
        ) == (
            first_command.request_key,
            first_command.reservation_id,
            first_command.digest,
            first_command.principal,
        )
        assert event.command_principal != "p"
    other = ledger.read_events("s2")[0]
    assert (
        other.sequence,
        other.request_key,
        other.reservation_id,
        other.command_digest,
        other.command_principal,
    ) == (
        2,
        second_command.request_key,
        second_command.reservation_id,
        second_command.digest,
        second_command.principal,
    )
    assert revision(journal) == before
    reopened = GatewayDirectCommandJournal(
        path,
        "acct",
        generation=journal.generation,
        expected_journal_id=journal.journal_id,
        minimum_revision=before,
        max_records=20,
        execution_max_facts=20,
    )
    again = GatewayDirectExecutionLedger(reopened, guard).consumer_progress(
        "s1", principal_id="p", consumer_ref="c"
    )
    assert (again.epoch, again.offered_sequence, again.acknowledged_sequence) == (page.epoch, 3, 3)
    assert (
        ledger.consumer_progress("s1", principal_id="other", consumer_ref="c").offered_sequence == 0
    )


def test_consumer_fit_atomicity_capacity_and_thread(setup):
    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    ledger.ingest(fact(ref="trade"))
    with pytest.raises(DirectCommandJournalError, match="PAGE_TOO_LARGE"):
        ledger.read_for_consumer(
            "s1", principal_id="p", consumer_ref="c", result_fits=lambda p: False
        )
    assert ledger.consumer_progress("s1", principal_id="p", consumer_ref="c").offered_sequence == 0
    page = ledger.read_for_consumer(
        "s1", principal_id="p", consumer_ref="c", result_fits=lambda p: len(p.events) <= 1
    )
    assert len(page.events) == 1 and page.has_more and page.offered_sequence == 1
    with pytest.raises(DirectCommandJournalError, match="PAGE_TOO_LARGE"):
        ledger.read_for_consumer(
            "s1",
            principal_id="p",
            consumer_ref="c",
            after_sequence=1,
            expected_epoch=page.epoch,
            result_fits=lambda p: False,
        )
    assert ledger.consumer_progress("s1", principal_id="p", consumer_ref="c").offered_sequence == 1
    results = []
    t = threading.Thread(
        target=lambda: results.append(
            ledger.read_for_consumer(
                "s1",
                principal_id="p",
                consumer_ref="c",
                after_sequence=1,
                expected_epoch=page.epoch,
                result_fits=lambda _: True,
            )
        )
    )
    t.start()
    t.join()
    assert results[0].offered_sequence == 2
    with sqlite3.connect(path) as db:
        db.executemany(
            "INSERT INTO direct_execution_consumers VALUES ('acct', 'p', ?, 's1', 1, 0)",
            ((f"extra-{i}",) for i in range(8191)),
        )
    with pytest.raises(DirectCommandJournalError, match="CONSUMER_CAPACITY_EXCEEDED"):
        ledger.read_for_consumer(
            "s1", principal_id="p", consumer_ref="overflow", result_fits=lambda _: True
        )


@pytest.mark.parametrize("mutation", ["foreign", "ack", "ddl"])
def test_consumer_reopen_rejects_tampering(setup, mutation):
    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    ledger.read_for_consumer("s1", principal_id="p", consumer_ref="c", result_fits=lambda _: True)
    with sqlite3.connect(path) as db:
        if mutation == "foreign":
            db.execute("UPDATE direct_execution_consumers SET strategy='other'")
        elif mutation == "ack":
            db.execute("UPDATE direct_execution_consumers SET acknowledged_sequence=2")
        else:
            db.execute("CREATE INDEX extra_consumer ON direct_execution_consumers(consumer)")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        GatewayDirectCommandJournal(
            path,
            "acct",
            generation=journal.generation,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=20,
            execution_max_facts=20,
        )


def test_v4_migration_preserves_execution_and_rolls_back_on_failure(setup, monkeypatch):
    from bt_api_gateway import direct_execution_journal as module

    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    before = revision(journal)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE direct_execution_consumers")
        db.execute("UPDATE direct_journal_meta SET schema_version=4")
    args = {
        "generation": journal.generation,
        "guard": guard,
        "expected_journal_id": journal.journal_id,
        "minimum_revision": before,
        "max_records": 20,
        "execution_max_facts": 20,
    }
    with pytest.raises(DirectCommandJournalError):
        GatewayDirectCommandJournal(path, "acct", **{k: v for k, v in args.items() if k != "guard"})
    original = module._create_consumer_table

    def fail_after_create(db):
        original(db)
        raise RuntimeError("injected")

    monkeypatch.setattr(module, "_create_consumer_table", fail_after_create)
    with pytest.raises(RuntimeError, match="injected"):
        GatewayDirectCommandJournal.upgrade_v4(path, "acct", **args)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone() == (
            4,
            before,
        )
        assert (
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='direct_execution_consumers'"
            ).fetchone()[0]
            == 0
        )
    monkeypatch.setattr(module, "_create_consumer_table", original)
    upgraded = GatewayDirectCommandJournal.upgrade_v4(path, "acct", **args)
    upgraded_ledger = GatewayDirectExecutionLedger(upgraded, guard)
    assert [event.sequence for event in upgraded_ledger.read_events("s1")] == [1]
    assert revision(upgraded) == before + 1


def test_consumer_offer_commit_failure_and_empty_does_not_create(setup, monkeypatch):
    journal, ledger, guard, path = setup
    empty = ledger.read_for_consumer(
        "s1", principal_id="p", consumer_ref="c", result_fits=lambda _: True
    )
    assert not empty.events and not empty.has_more and empty.offered_sequence == 0
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM direct_execution_consumers").fetchone()[0] == 0
    command(journal)
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))

    def fail_commit(db):
        raise RuntimeError("commit failure")

    monkeypatch.setattr(journal, "_commit", fail_commit)
    with pytest.raises(RuntimeError, match="commit failure"):
        ledger.read_for_consumer(
            "s1", principal_id="p", consumer_ref="c", result_fits=lambda _: True
        )
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM direct_execution_consumers").fetchone()[0] == 0


def test_v4_upgrade_rejects_corrupt_execution_without_schema_change(setup):
    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    before = revision(journal)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE direct_execution_consumers")
        db.execute("UPDATE direct_journal_meta SET schema_version=4")
        db.execute("UPDATE direct_execution_events SET strategy='foreign'")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        GatewayDirectCommandJournal.upgrade_v4(
            path,
            "acct",
            generation=journal.generation,
            guard=guard,
            expected_journal_id=journal.journal_id,
            minimum_revision=before,
            max_records=20,
            execution_max_facts=20,
        )
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone() == (
            4,
            before,
        )
        assert (
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='direct_execution_consumers'"
            ).fetchone()[0]
            == 0
        )


def test_consumer_epoch_survives_guard_generation_change(setup):
    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    old = ledger.read_for_consumer(
        "s1", principal_id="p", consumer_ref="c", result_fits=lambda _: True
    )
    before = revision(journal)
    guard.release()
    generation = guard.acquire()
    assert generation != journal.generation
    reopened = GatewayDirectCommandJournal(
        path,
        "acct",
        generation=generation,
        expected_journal_id=journal.journal_id,
        minimum_revision=before,
        max_records=20,
        execution_max_facts=20,
    )
    resumed = GatewayDirectExecutionLedger(reopened, guard)
    progress = resumed.consumer_progress("s1", principal_id="p", consumer_ref="c")
    assert progress.epoch == old.epoch and progress.offered_sequence == 1


def test_consumer_requires_explicit_fits_before_any_progress(setup):
    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    for exists in (False, True):
        if exists:
            ledger.read_for_consumer(
                "s1", principal_id="p", consumer_ref="c", result_fits=lambda _: True
            )
        before = ledger.consumer_progress("s1", principal_id="p", consumer_ref="c")
        with pytest.raises(TypeError, match="result_fits"):
            ledger.read_for_consumer("s1", principal_id="p", consumer_ref="c")
        with pytest.raises(DirectCommandJournalError, match="INVALID_INPUT"):
            ledger.read_for_consumer("s1", principal_id="p", consumer_ref="c", result_fits=None)
        assert ledger.consumer_progress("s1", principal_id="p", consumer_ref="c") == before
        with sqlite3.connect(path) as db:
            assert db.execute("SELECT count(*) FROM direct_execution_consumers").fetchone()[
                0
            ] == int(exists)


def test_consumer_complete_envelope_budget_shrinks_page_and_rejects_first_atomically(setup):
    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    ledger.ingest(fact(ref="trade"))

    def encode(page, *, envelope=True):
        payload = {
            "events": [
                {
                    "sequence": event.sequence,
                    "strategy_scope": event.strategy_scope,
                    "fact_digest": event.fact_digest,
                    "request_key": event.request_key,
                    "reservation_id": event.reservation_id,
                    "command_digest": event.command_digest,
                    "command_principal": event.command_principal,
                    "fact": event.fact.to_mapping(),
                }
                for event in page.events
            ],
            "epoch": page.epoch,
            "offered_sequence": page.offered_sequence,
            "acknowledged_sequence": page.acknowledged_sequence,
            "has_more": page.has_more,
        }
        response = (
            {"request_id": "test-request", "result": payload, "metadata": "x" * 128}
            if envelope
            else payload
        )
        return json.dumps(
            response, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")

    probe = ledger.read_for_consumer(
        "s1", principal_id="p", consumer_ref="probe", result_fits=lambda _: True
    )
    first = replace(
        probe, events=probe.events[:1], offered_sequence=probe.events[0].sequence, has_more=True
    )
    budget = len(encode(first))
    assert len(encode(probe)) > budget > len(encode(first, envelope=False))
    offered = ledger.read_for_consumer(
        "s1",
        principal_id="p",
        consumer_ref="bounded",
        result_fits=lambda page: len(encode(page)) <= budget,
    )
    assert len(offered.events) == 1 and offered.has_more and len(encode(offered)) <= budget
    assert offered.offered_sequence == 1
    tail = replace(probe, events=probe.events[1:], offered_sequence=2)
    with pytest.raises(DirectCommandJournalError, match="PAGE_TOO_LARGE"):
        ledger.read_for_consumer(
            "s1",
            principal_id="p",
            consumer_ref="bounded",
            after_sequence=1,
            expected_epoch=offered.epoch,
            result_fits=lambda page: len(encode(page)) <= len(encode(tail, envelope=False)),
        )
    assert (
        ledger.consumer_progress("s1", principal_id="p", consumer_ref="bounded").offered_sequence
        == 1
    )
    with pytest.raises(DirectCommandJournalError, match="PAGE_TOO_LARGE"):
        ledger.read_for_consumer(
            "s1",
            principal_id="p",
            consumer_ref="too-small",
            result_fits=lambda page: len(encode(page)) <= len(encode(first, envelope=False)),
        )
    progress = ledger.consumer_progress("s1", principal_id="p", consumer_ref="too-small")
    assert (progress.offered_sequence, progress.acknowledged_sequence) == (0, 0)
    with sqlite3.connect(path) as db:
        assert (
            db.execute(
                "SELECT count(*) FROM direct_execution_consumers WHERE consumer='too-small'"
            ).fetchone()[0]
            == 0
        )


def test_consumer_integrity_rejects_over_capacity_with_bounded_scan(setup, monkeypatch):
    from bt_api_gateway import direct_execution_journal as module

    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    for index in range(3):
        ledger.read_for_consumer(
            "s1", principal_id="p", consumer_ref=f"c{index}", result_fits=lambda _: True
        )
    monkeypatch.setattr(module, "_MAX_CONSUMERS", 2)
    traces = []
    connect = sqlite3.connect

    def traced_connect(*args, **kwargs):
        db = connect(*args, **kwargs)
        db.set_trace_callback(traces.append)
        return db

    monkeypatch.setattr(sqlite3, "connect", traced_connect)
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        GatewayDirectCommandJournal(
            path,
            "acct",
            generation=journal.generation,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=20,
            execution_max_facts=20,
        )
    scans = [
        " ".join(sql.lower().split())
        for sql in traces
        if sql.lower().lstrip().startswith("select * from direct_execution_consumers")
    ]
    assert scans == ["select * from direct_execution_consumers limit 3"]


@pytest.mark.parametrize(
    "mutation",
    ["missing_fact", "missing_command", "foreign_reservation", "strategy", "digest", "sequence"],
)
def test_event_read_rejects_corrupt_command_association_without_advancing(setup, mutation):
    journal, ledger, guard, path = setup
    first, _ = command(journal)
    second, _ = command(journal, key="req2", anchor="session-b")
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    with sqlite3.connect(path) as db:
        if mutation == "missing_fact":
            db.execute("DELETE FROM direct_execution_facts")
        elif mutation == "missing_command":
            db.execute(
                "DELETE FROM direct_journal_commands WHERE reservation_id=?",
                (first.reservation_id,),
            )
        elif mutation == "foreign_reservation":
            db.execute(
                "UPDATE direct_execution_facts SET reservation_id=?", (second.reservation_id,)
            )
        elif mutation == "strategy":
            db.execute(
                "UPDATE direct_journal_commands SET strategy='other' WHERE reservation_id=?",
                (first.reservation_id,),
            )
        elif mutation == "digest":
            db.execute(
                "UPDATE direct_journal_commands SET digest=? WHERE reservation_id=?",
                ("0" * 64, first.reservation_id),
            )
        else:
            db.execute("UPDATE direct_execution_facts SET event_sequence=99")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        ledger.read_events("s1")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        ledger.read_for_consumer(
            "s1", principal_id="consumer", consumer_ref="c", result_fits=lambda _: True
        )
    assert (
        ledger.consumer_progress("s1", principal_id="consumer", consumer_ref="c").offered_sequence
        == 0
    )


def test_ledger_exact_journal_binding_same_pid_thread_and_wrong_pid(setup, monkeypatch):
    from bt_api_gateway import direct_execution_journal as module

    journal, ledger, guard, path = setup
    results = []
    thread = threading.Thread(
        target=lambda: results.extend([ledger.is_bound_to(journal), ledger.is_bound_to(object())])
    )
    thread.start()
    thread.join()
    assert results == [True, False]
    with monkeypatch.context() as patch:
        patch.setattr(module.os, "getpid", lambda: ledger._pid + 1)
        with pytest.raises(DirectCommandJournalError, match="WRONG_OWNER"):
            ledger.is_bound_to(journal)


def test_ack_response_budget_checked_before_update(setup):
    from dataclasses import asdict

    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    page = ledger.read_for_consumer(
        "s1", principal_id="consumer", consumer_ref="c", result_fits=lambda _: True
    )

    def response_size(progress):
        return len(
            json.dumps(
                {
                    "request_id": "r",
                    "status": "OK",
                    "progress": asdict(progress),
                    "metadata": "x" * 128,
                }
            ).encode("utf-8")
        )

    baseline = ledger.consumer_progress("s1", principal_id="consumer", consumer_ref="c")
    args = dict(principal_id="consumer", consumer_ref="c", sequence=1, expected_epoch=page.epoch)
    with pytest.raises(DirectCommandJournalError, match="PAGE_TOO_LARGE"):
        ledger.acknowledge(
            "s1",
            **args,
            result_fits=lambda progress: (
                response_size(progress) <= len(json.dumps(asdict(progress)).encode("utf-8"))
            ),
        )
    with pytest.raises(DirectCommandJournalError, match="INVALID_INPUT"):
        ledger.acknowledge("s1", **args, result_fits=lambda progress: 1)
    with pytest.raises(DirectCommandJournalError, match="INVALID_INPUT"):
        ledger.acknowledge("s1", **args, result_fits=1)

    def fail(progress):
        raise RuntimeError("budget failure")

    with pytest.raises(RuntimeError, match="budget failure"):
        ledger.acknowledge("s1", **args, result_fits=fail)
    assert ledger.consumer_progress("s1", principal_id="consumer", consumer_ref="c") == baseline
    assert (
        ledger.acknowledge(
            "s1", **args, result_fits=lambda progress: response_size(progress) < 10000
        ).acknowledged_sequence
        == 1
    )
