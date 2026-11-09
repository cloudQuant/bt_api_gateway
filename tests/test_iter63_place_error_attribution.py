"""Prepared PLACE journal and rejection attribution; no real account I/O."""

import sqlite3
from dataclasses import replace

import pytest
from bt_api_base.direct_place_protocol import PreparedPlaceRequest
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
from bt_api_gateway.direct_dispatch import _identity
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from bt_api_gateway.session_guard import LocalAccountSessionGuard


INSTRUMENT = MarketInstrumentKey("ctp", "SHFE", "simnow", "future", "rb2601", "rb2601")
SOURCE = {"schema": "test", "generation": 1, "active": True}


@pytest.fixture
def setup(tmp_path):
    directory = tmp_path / "guards"
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, "acct", "owner")
    generation = guard.acquire()
    journal = GatewayDirectCommandJournal.create(
        tmp_path / "db", "acct", generation=generation, max_records=20, execution_max_facts=20
    )
    yield journal, guard, tmp_path / "db"
    guard.release()


def reserve(
    journal, key="req1", strategy="s1", ref="ref-a", place_key="place-key-1", source=SOURCE
):
    order = journal.reserve(
        strategy,
        key,
        "principal",
        {"symbol": "rb2601", "side": "buy", "offset": "open", "quantity": "2"},
    )
    identity = NativeOrderIdentity("CTP", ref, {"trading_day": "20300101"}, 1)
    prep = PreparedPlaceRequest(
        "provider-" + key,
        identity,
        "rb2601",
        "20300101",
        1,
        {"RequestID": 11},
        (place_key,),
        source,
    )
    return order, identity, prep


def begin(journal, order, identity, prep, *, before_dispatch=None):
    return journal.begin_dispatch(
        order.strategy_scope,
        order.request_key,
        order.reservation_id,
        order.digest,
        order.principal,
        order.version,
        _identity(identity, "CTP"),
        ("session-" + identity.client_order_id,),
        before_dispatch=before_dispatch,
        prepared_place=prep,
    )


def make_fact(identity, key="place-key-1", *, error="ctp_order_error_20"):
    strong = "session-" + identity.client_order_id
    return GatewayReturnFact(
        "acct",
        "CTP",
        INSTRUMENT,
        "20300101",
        DirectExecutionEventKind.ORDER_ERROR,
        "synthetic-source",
        identity=identity,
        identity_keys=(strong,),
        binding_keys=(strong,),
        error_code=error,
        session_generation=1,
        schema_version=3,
        place_request_key=key,
    )


def ingest(ledger, fact, prep, *, source=SOURCE, before_commit=None):
    return ledger.ingest_place_error(
        fact,
        place_key=prep.request_keys[0],
        prepared_digest=prep.digest(),
        source_binding=source,
        before_commit=before_commit,
    )


def reopen(journal, path):
    return GatewayDirectCommandJournal(
        path,
        "acct",
        generation=journal.generation,
        expected_journal_id=journal.journal_id,
        minimum_revision=0,
        max_records=20,
        execution_max_facts=20,
    )


def test_prepared_dispatch_is_atomic_and_idempotent(setup):
    journal, guard, path = setup
    order, identity, prep = reserve(journal)

    def deny():
        raise RuntimeError("revoked")

    with pytest.raises(RuntimeError, match="revoked"):
        begin(journal, order, identity, prep, before_dispatch=deny)
    assert journal.get("s1", "req1", "principal") == order
    assert journal.get_prepared_place(order.reservation_id) is None
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM direct_place_keys").fetchone()[0] == 0
    result = begin(journal, order, identity, prep)
    assert result.newly_started and result.record.status == "DISPATCHING"
    assert journal.get_prepared_place(order.reservation_id) == prep
    assert journal.find_place_by_request_key("place-key-1") == result.record
    assert journal.find_place_by_request_key("session-ref-a") is None
    assert not begin(journal, order, identity, prep).newly_started
    with pytest.raises(DirectCommandJournalError, match="PLACE_PREPARATION_CONFLICT"):
        begin(journal, order, identity, replace(prep, request_fields={"RequestID": 12}))
    second, other, collision = reserve(journal, key="req2", strategy="s2", ref="ref-b")
    with pytest.raises(DirectCommandJournalError, match="PLACE_KEY_CONFLICT"):
        begin(journal, second, other, collision)
    assert journal.get("s2", "req2", "principal") == second
    assert reopen(journal, path).get_prepared_place(order.reservation_id) == prep


def test_error_two_requests_are_distinct_and_late_trade_applies(setup):
    journal, guard, path = setup
    first, id1, prep1 = reserve(journal)
    second, id2, prep2 = reserve(
        journal, key="req2", strategy="s2", ref="ref-b", place_key="place-key-2"
    )
    first_started = begin(journal, first, id1, prep1).record
    second_started = begin(journal, second, id2, prep2).record
    ledger = GatewayDirectExecutionLedger(journal, guard)
    fact1, fact2 = make_fact(id1), make_fact(id2, "place-key-2")
    assert fact1.fact_digest() != fact2.fact_digest()
    with pytest.raises(DirectCommandJournalError, match="INVALID_FACT"):
        ledger.ingest(fact1)
    assert ingest(ledger, fact1, prep1).event_sequence == 1
    assert ingest(ledger, fact2, prep2).event_sequence == 2
    assert ingest(ledger, fact1, prep1).event_sequence == 1
    event = ledger.read_events("s1")[0]
    assert (
        event.place_attribution.prepared_digest == prep1.digest()
        and event.cancel_attribution is None
    )
    assert ledger.read_for_consumer(
        "s1", principal_id="reader", consumer_ref="c", result_fits=lambda _: True
    ).events == (event,)
    assert journal.get("s1", "req1", "principal") == first_started
    assert journal.get("s2", "req2", "principal") == second_started
    order_event = GatewayReturnFact(
        "acct",
        "CTP",
        INSTRUMENT,
        "20300101",
        DirectExecutionEventKind.ORDER,
        "order-event",
        identity=id1,
        identity_keys=("session-ref-a", "venue-a"),
        binding_keys=("session-ref-a",),
        venue_key="venue-a",
        status=DirectOrderStatus.ACCEPTED,
    )
    assert ledger.ingest(order_event).disposition == "ATTRIBUTED"
    trade = GatewayReturnFact(
        "acct",
        "CTP",
        INSTRUMENT,
        "20300101",
        DirectExecutionEventKind.TRADE,
        "trade",
        identity=id1,
        identity_keys=("session-ref-a", "venue-a"),
        binding_keys=("session-ref-a",),
        venue_key="venue-a",
        trade_key=("SHFE", "trade-1"),
        side="buy",
        offset="open",
        trade_quantity="1",
        trade_price="10",
    )
    assert ledger.ingest(trade).applied and ledger.position("s1", INSTRUMENT) == "1"
    assert journal.get("s1", "req1", "principal") == first_started
    assert (
        GatewayDirectExecutionLedger(reopen(journal, path), guard)
        .read_events("s1")[0]
        .place_attribution.prepared_digest
        == prep1.digest()
    )


def test_error_before_commit_rolls_back_and_duplicate_rechecks(setup):
    journal, guard, path = setup
    order, identity, prep = reserve(journal)
    begin(journal, order, identity, prep)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    fact = make_fact(identity)

    def deny():
        with sqlite3.connect(path, timeout=0) as db:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                db.execute("BEGIN IMMEDIATE")
        raise RuntimeError("source changed")

    with pytest.raises(RuntimeError, match="source changed"):
        ingest(ledger, fact, prep, before_commit=deny)
    with sqlite3.connect(path) as db:
        for table in (
            "direct_execution_facts",
            "direct_execution_events",
            "direct_place_error_attribution",
        ):
            assert db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
    assert ingest(ledger, fact, prep).event_sequence == 1
    with pytest.raises(RuntimeError, match="source changed"):
        ingest(ledger, fact, prep, before_commit=deny)
    assert len(ledger.read_events("s1")) == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "key",
        "digest",
        "source",
        "bool-int",
        "symbol",
        "target",
        "generation",
        "day",
        "status",
        "kind",
        "error",
    ],
)
def test_wrong_attribution_fails_closed(setup, mutation):
    journal, guard, path = setup
    order, identity, prep = reserve(journal)
    begin(journal, order, identity, prep)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    fact, key, digest, source = make_fact(identity), prep.request_keys[0], prep.digest(), SOURCE
    if mutation == "key":
        key = "wrong"
    elif mutation == "digest":
        digest = "0" * 64
    elif mutation == "source":
        source = {**SOURCE, "schema": "other"}
    elif mutation == "bool-int":
        source = {**SOURCE, "active": 1}
    elif mutation == "symbol":
        fact = replace(fact, instrument=replace(INSTRUMENT, native_symbol="other"))
    elif mutation == "target":
        fact = replace(fact, identity=replace(identity, client_order_id="other"))
    elif mutation == "generation":
        fact = replace(fact, session_generation=2)
    elif mutation == "day":
        other_identity = replace(identity, fields={**identity.fields, "trading_day": "20300102"})
        fact = replace(fact, identity=other_identity, trading_day="20300102")
    elif mutation == "status":
        from bt_api_base.gateway_execution_protocol import GatewayExecutionProtocolError

        with pytest.raises(GatewayExecutionProtocolError):
            replace(fact, status=DirectOrderStatus.REJECTED)
        assert not ledger.read_events("s1")
        return
    elif mutation == "kind":
        fact = replace(
            fact, schema_version=1, place_request_key=None, kind=DirectExecutionEventKind.ORDER
        )
    elif mutation == "error":
        fact = replace(fact, error_code=None)
    with pytest.raises(DirectCommandJournalError):
        ledger.ingest_place_error(
            fact, place_key=key, prepared_digest=digest, source_binding=source
        )
    assert not ledger.read_events("s1")


@pytest.mark.parametrize(
    "mutation",
    ["side", "side-key", "side-source", "prepared", "place-key", "delete-fact", "delete-event"],
)
def test_corrupt_association_rejected_during_read_and_reopen(setup, mutation):
    journal, guard, path = setup
    order, identity, prep = reserve(journal)
    begin(journal, order, identity, prep)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    ingest(ledger, make_fact(identity), prep)
    with sqlite3.connect(path) as db:
        if mutation == "side":
            db.execute("DELETE FROM direct_place_error_attribution")
        elif mutation == "side-key":
            db.execute("UPDATE direct_place_error_attribution SET place_key='other'")
        elif mutation == "side-source":
            db.execute("UPDATE direct_place_error_attribution SET source_binding_json='{}'")
        elif mutation == "prepared":
            db.execute("UPDATE direct_place_preparations SET prepared_digest=?", ("0" * 64,))
        elif mutation == "place-key":
            db.execute("UPDATE direct_place_keys SET strong_key='other'")
        elif mutation == "delete-fact":
            db.execute("DELETE FROM direct_execution_facts")
        else:
            db.execute("DELETE FROM direct_execution_events")
    if mutation != "delete-event":
        with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
            ledger.read_events("s1")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        reopen(journal, path)


def test_commit_port_persists_preparation_before_native_and_legacy_unchanged(setup):
    from bt_api_base.direct_write_protocol import PreDispatchRecord, WriteOperation
    from bt_api_gateway.direct_dispatch import GatewayDirectDispatcher, NativeDispatchOutcome

    journal, guard, path = setup
    order, identity, prep = reserve(journal)
    calls = []

    def native(payload, port, scope):
        record = PreDispatchRecord(
            WriteOperation.PLACE,
            scope,
            "CTP",
            "rb2601",
            identity,
            None,
            payload,
            "20300101",
            1,
            "synthetic",
            prepared_place=prep,
        )
        marker = port.commit(record)
        assert journal.get_prepared_place(order.reservation_id) == prep
        calls.append("native")
        return NativeDispatchOutcome(True, identity, marker)

    dispatcher = GatewayDirectDispatcher(
        journal, "CTP", guard, native, lambda _: ("session-ref-a",), lambda _: True
    )
    result = dispatcher.dispatch("s1", "req1", "principal", order.reservation_id, order.digest, 1)
    assert result.status == "SENT" and calls == ["native"]
    assert (
        dispatcher.dispatch("s1", "req1", "principal", order.reservation_id, order.digest, 1)
        == result
    )
    assert calls == ["native"]


def test_commit_failure_leaves_no_preparation_and_no_native_send(setup, monkeypatch):
    from bt_api_base.direct_write_protocol import PreDispatchRecord, WriteOperation
    from bt_api_gateway.direct_dispatch import (
        DirectDispatchError,
        GatewayDirectDispatcher,
        NativeDispatchOutcome,
    )

    journal, guard, path = setup
    order, identity, prep = reserve(journal)
    calls = []

    def native(payload, port, scope):
        record = PreDispatchRecord(
            WriteOperation.PLACE,
            scope,
            "CTP",
            "rb2601",
            identity,
            None,
            payload,
            "20300101",
            1,
            "synthetic",
            prepared_place=prep,
        )
        marker = port.commit(record)
        calls.append("native")
        return NativeDispatchOutcome(True, identity, marker)

    dispatcher = GatewayDirectDispatcher(
        journal, "CTP", guard, native, lambda _: ("session-ref-a",), lambda _: True
    )
    original = journal._commit

    def fault(db):
        row = db.execute(
            "SELECT status FROM direct_journal_commands WHERE request_key='req1'"
        ).fetchone()
        if row is not None and row[0] == "DISPATCHING":
            raise RuntimeError("commit failure")
        original(db)

    monkeypatch.setattr(journal, "_commit", fault)
    with pytest.raises(DirectDispatchError, match="PRE_DISPATCH_FAILED"):
        dispatcher.dispatch("s1", "req1", "principal", order.reservation_id, order.digest, 1)
    assert not calls and journal.get("s1", "req1", "principal") == order
    assert journal.get_prepared_place(order.reservation_id) is None


def test_v7_upgrade_preserves_cancel_fact_bytes_without_fabricating_place(setup):
    from test_iter63_cancel_error_attribution import (
        make_fact as cancel_fact,
        start as cancel_start,
        ingest as cancel_ingest,
    )
    from test_iter63_direct_cancel_journal import make_order
    from bt_api_gateway.direct_cancel_journal import GatewayDirectCancelJournal

    journal, guard, path = setup
    cancel = GatewayDirectCancelJournal(journal)
    order, identity = make_order(journal)
    _, cancel_prep = cancel_start(cancel, order, identity)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    fact = cancel_fact(identity)
    cancel_ingest(ledger, fact, cancel_prep)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE direct_execution_trade_dates")
        db.execute("DROP TABLE direct_place_error_attribution")
        db.execute("DROP TABLE direct_place_keys")
        db.execute("DROP TABLE direct_place_preparations")
        db.execute("UPDATE direct_journal_meta SET schema_version=7")
        tables = (
            "direct_journal_commands",
            "direct_execution_facts",
            "direct_execution_events",
            "direct_cancel_attempts",
            "direct_cancel_keys",
            "direct_cancel_error_attribution",
        )
        before = {name: db.execute(f"SELECT * FROM {name}").fetchall() for name in tables}
        rev = db.execute("SELECT revision FROM direct_journal_meta").fetchone()[0]
    with pytest.raises(DirectCommandJournalError):
        reopen(journal, path)
    upgraded = GatewayDirectCommandJournal.upgrade_v7(
        path,
        "acct",
        generation=journal.generation,
        guard=guard,
        expected_journal_id=journal.journal_id,
        minimum_revision=rev,
        max_records=20,
        execution_max_facts=20,
    )
    with sqlite3.connect(path) as db:
        assert all(
            db.execute(f"SELECT * FROM {name}").fetchall() == rows for name, rows in before.items()
        )
        assert db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone() == (
            9,
            rev + 1,
        )
    assert upgraded.get_prepared_place(order.reservation_id) is None
    (event,) = GatewayDirectExecutionLedger(upgraded, guard).read_events("s")
    assert event.fact.fact_digest() == fact.fact_digest() and event.cancel_attribution is not None
    assert event.place_attribution is None


def test_v7_migration_fault_rolls_back_atomically(setup, monkeypatch):
    from bt_api_gateway import direct_place_journal as module

    journal, guard, path = setup
    order, identity, prep = reserve(journal)
    # Legacy unprepared dispatch remains valid after migration.
    journal.begin_dispatch(
        "s1",
        "req1",
        order.reservation_id,
        order.digest,
        "principal",
        1,
        _identity(identity, "CTP"),
        ("session-ref-a",),
    )
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE direct_execution_trade_dates")
        db.execute("DROP TABLE direct_place_error_attribution")
        db.execute("DROP TABLE direct_place_keys")
        db.execute("DROP TABLE direct_place_preparations")
        db.execute("UPDATE direct_journal_meta SET schema_version=7")
        before = db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
    original = module._create_place_tables

    def fail(db):
        original(db)
        raise RuntimeError("after ddl")

    monkeypatch.setattr(module, "_create_place_tables", fail)
    with pytest.raises(RuntimeError, match="after ddl"):
        GatewayDirectCommandJournal.upgrade_v7(
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
                "SELECT count(*) FROM sqlite_master WHERE name='direct_place_preparations'"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize("strategy", ["s1", "s2"])
def test_live_read_rejects_side_link_to_another_command(setup, strategy):
    journal, guard, path = setup
    first, id1, prep1 = reserve(journal)
    second, id2, prep2 = reserve(
        journal, key="req2", strategy=strategy, ref="ref-b", place_key="place-key-2"
    )
    begin(journal, first, id1, prep1)
    begin(journal, second, id2, prep2)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    ingest(ledger, make_fact(id1), prep1)
    with sqlite3.connect(path) as db:
        native1 = db.execute(
            "SELECT native_identity_json FROM direct_journal_commands WHERE request_key='req1'"
        ).fetchone()[0]
        native2 = db.execute(
            "SELECT native_identity_json FROM direct_journal_commands WHERE request_key='req2'"
        ).fetchone()[0]
        db.execute(
            "UPDATE direct_journal_commands SET native_identity_json=? WHERE request_key='req1'",
            ('{"temporary":true}',),
        )
        db.execute(
            "UPDATE direct_journal_commands SET native_identity_json=? WHERE request_key='req2'",
            (native1,),
        )
        db.execute(
            "UPDATE direct_journal_commands SET native_identity_json=? WHERE request_key='req1'",
            (native2,),
        )
        db.execute("DELETE FROM direct_place_keys WHERE reservation_id=?", (second.reservation_id,))
        db.execute(
            "DELETE FROM direct_place_preparations WHERE reservation_id=?", (second.reservation_id,)
        )
        db.execute(
            "UPDATE direct_place_keys SET reservation_id=? WHERE reservation_id=?",
            (second.reservation_id, first.reservation_id),
        )
        db.execute(
            "UPDATE direct_place_preparations SET reservation_id=? WHERE reservation_id=?",
            (second.reservation_id, first.reservation_id),
        )
        db.execute(
            "UPDATE direct_place_error_attribution SET reservation_id=?", (second.reservation_id,)
        )
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        ledger.read_events("s1")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        reopen(journal, path)


def test_orphan_preparation_keys_fail_even_for_get(setup):
    journal, guard, path = setup
    order, identity, prep = reserve(journal)
    begin(journal, order, identity, prep)
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM direct_place_preparations")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        journal.get_prepared_place(order.reservation_id)
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        journal.find_place_by_request_key("place-key-1")
