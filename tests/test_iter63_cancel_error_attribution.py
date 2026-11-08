"""Offline cancellation-error association in the original command database."""

import sqlite3
from dataclasses import replace

import pytest
from bt_api_base.direct_cancel_protocol import PreparedCancelRequest
from bt_api_base.direct_write_protocol import DirectExecutionEventKind
from bt_api_base.gateway_execution_protocol import GatewayReturnFact
from bt_api_base.market_protocol import MarketInstrumentKey

from bt_api_gateway.direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
)
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
import test_iter63_direct_cancel_journal as fixtures
from test_iter63_direct_cancel_journal import make_order, request

setup = fixtures.setup
SOURCE = {"account_binding": "native-acct", "source_generation": 2, "active": True}


def make_prepared(identity, key="cancel-key-1", source=SOURCE):
    return PreparedCancelRequest(
        "provider-" + key,
        identity,
        "X",
        "20300101",
        2,
        {"RequestID": 12},
        (key,),
        source_binding=source,
    )


def make_fact(identity, key="cancel-key-1", source_ref="source"):
    return GatewayReturnFact(
        "acct",
        "TEST",
        MarketInstrumentKey("test", "EX", "sim", "future", "X", "X"),
        "20300101",
        DirectExecutionEventKind.CANCEL_ERROR,
        source_ref,
        identity=identity,
        identity_keys=("order-key-ref",),
        binding_keys=("order-key-ref",),
        error_code="ctp_cancel_error_20",
        session_generation=2,
        schema_version=2,
        cancel_request_key=key,
    )


def start(cancel, order, identity, operation="cancel", key="cancel-key-1", source=SOURCE):
    request(cancel, order, identity, operation)
    prep = make_prepared(identity, key, source)
    result = cancel.begin_dispatch("s", operation, "p", 1, prep)
    return result.record, prep


def ingest(ledger, fact, prep, *, source=SOURCE, before_commit=None):
    return ledger.ingest_cancel_error(
        fact,
        cancel_key=prep.request_keys[0],
        prepared_digest=prep.digest(),
        source_binding=source,
        before_commit=before_commit,
    )


def reopened(journal, path):
    return GatewayDirectCommandJournal(
        path,
        "acct",
        generation=journal.generation,
        expected_journal_id=journal.journal_id,
        minimum_revision=0,
        max_records=10,
        execution_max_facts=20,
    )


def test_two_attempts_same_order_same_error_have_distinct_events(setup):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    first, p1 = start(cancel, order, identity, "one", "cancel-key-1")
    second, p2 = start(cancel, order, identity, "two", "cancel-key-2")
    ledger = GatewayDirectExecutionLedger(journal, guard)
    one, two = make_fact(identity), make_fact(identity, "cancel-key-2")
    assert one.fact_digest() != two.fact_digest()
    assert cancel.find_by_request_key("missing") is None
    assert cancel.find_by_request_key("cancel-key-1") == first
    with pytest.raises(DirectCommandJournalError, match="INVALID_FACT"):
        ledger.ingest(one)
    a, b = ingest(ledger, one, p1), ingest(ledger, two, p2)
    assert (a.event_sequence, b.event_sequence) == (1, 2)
    assert ingest(ledger, one, p1).event_sequence == 1
    events = ledger.read_events("s")
    assert [event.cancel_attribution.operation_id for event in events] == ["one", "two"]
    assert [event.cancel_attribution.attempt_id for event in events] == [
        first.attempt_id,
        second.attempt_id,
    ]
    page = ledger.read_for_consumer(
        "s", principal_id="reader", consumer_ref="c", result_fits=lambda _: True
    )
    assert page.events == events
    assert journal.get("s", "order", "p") == order and ledger.position("s", one.instrument) is None
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM direct_execution_positions").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM direct_execution_totals").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM direct_cancel_error_attribution").fetchone()[0] == 2
    again = GatewayDirectExecutionLedger(reopened(journal, path), guard)
    assert again.read_events("s") == events


def test_not_sent_contradiction_keeps_attempt_and_order(setup):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    started, prep = start(cancel, order, identity)
    final = cancel.finish(
        "s", "cancel", "p", 2, started.marker_id, prep.digest(), journal.generation, False
    )
    ledger = GatewayDirectExecutionLedger(journal, guard)
    result = ingest(ledger, make_fact(identity), prep)
    assert result.reason == "CANCEL_NOT_SENT_CONTRADICTION"
    assert cancel.get("s", "cancel", "p") == final
    assert journal.get("s", "order", "p") == order
    assert (
        GatewayDirectExecutionLedger(reopened(journal, path), guard)
        .read_events("s")[0]
        .cancel_attribution.operation_id
        == "cancel"
    )


def test_before_commit_rolls_back_new_and_duplicate(setup):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    _, prep = start(cancel, order, identity)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    fact = make_fact(identity)

    def reject():
        with sqlite3.connect(path, timeout=0) as db:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                db.execute("BEGIN IMMEDIATE")
        raise RuntimeError("source stale")

    with pytest.raises(RuntimeError, match="source stale"):
        ingest(ledger, fact, prep, before_commit=reject)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM direct_execution_facts").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM direct_execution_events").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM direct_cancel_error_attribution").fetchone()[0] == 0
    result = ingest(ledger, fact, prep)
    with pytest.raises(RuntimeError, match="source stale"):
        ingest(ledger, fact, prep, before_commit=reject)
    assert ledger.read_events("s")[0].sequence == result.event_sequence


@pytest.mark.parametrize(
    "mutation",
    [
        "key",
        "digest",
        "source",
        "source_bool_int",
        "symbol",
        "target",
        "kind",
        "empty_error",
        "legacy",
        "generation",
        "day",
    ],
)
def test_wrong_association_fails_without_event(setup, mutation):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    _, prep = start(cancel, order, identity)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    fact = make_fact(identity)
    key, digest, source = prep.request_keys[0], prep.digest(), SOURCE
    if mutation == "key":
        key = "wrong"
    elif mutation == "digest":
        digest = "0" * 64
    elif mutation == "source":
        source = {**SOURCE, "account_binding": "wrong"}
    elif mutation == "source_bool_int":
        source = {**SOURCE, "active": 1}
    elif mutation == "symbol":
        fact = replace(
            fact, instrument=MarketInstrumentKey("test", "EX", "sim", "future", "Y", "Y")
        )
    elif mutation == "target":
        fact = replace(fact, identity=replace(identity, client_order_id="other"))
    elif mutation == "kind":
        fact = replace(
            fact, kind=DirectExecutionEventKind.ORDER, schema_version=1, cancel_request_key=None
        )
    elif mutation == "empty_error":
        fact = replace(fact, error_code=None)
    elif mutation == "generation":
        fact = replace(fact, session_generation=3)
    elif mutation == "day":
        other_identity = replace(identity, fields={**identity.fields, "trading_day": "20300102"})
        fact = replace(fact, identity=other_identity, trading_day="20300102")
    else:
        fact = replace(fact, schema_version=1, cancel_request_key=None)
    with pytest.raises(DirectCommandJournalError):
        ledger.ingest_cancel_error(
            fact, cancel_key=key, prepared_digest=digest, source_binding=source
        )
    assert not ledger.read_events("s")


def test_v1_source_cannot_establish_attempt_binding(setup):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    row = request(cancel, order, identity)
    prep = PreparedCancelRequest(
        "provider", identity, "X", "20300101", 2, {"RequestID": 1}, ("cancel-key-1",)
    )
    cancel.begin_dispatch("s", "cancel", "p", row.version, prep)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    with pytest.raises(DirectCommandJournalError):
        ingest(ledger, make_fact(identity), prep)
    assert not ledger.read_events("s")


@pytest.mark.parametrize(
    "mutation", ["delete_side", "attempt", "source", "key", "digest", "delete_fact", "delete_event"]
)
def test_corrupt_side_is_rejected_on_read_and_reopen(setup, mutation):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    _, prep = start(cancel, order, identity)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    ingest(ledger, make_fact(identity), prep)
    with sqlite3.connect(path) as db:
        if mutation == "delete_side":
            db.execute("DELETE FROM direct_cancel_error_attribution")
        elif mutation == "attempt":
            db.execute("UPDATE direct_cancel_error_attribution SET attempt_id='wrong'")
        elif mutation == "source":
            db.execute("UPDATE direct_cancel_error_attribution SET source_binding_json='{}'")
        elif mutation == "key":
            db.execute("UPDATE direct_cancel_error_attribution SET cancel_key='other'")
        elif mutation == "digest":
            db.execute("UPDATE direct_cancel_error_attribution SET prepared_digest=?", ("0" * 64,))
        elif mutation == "delete_fact":
            db.execute("DELETE FROM direct_execution_facts")
        else:
            db.execute("DELETE FROM direct_execution_events")
    if mutation != "delete_event":
        with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
            ledger.read_events("s")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        reopened(journal, path)


def test_v6_upgrade_preserves_legacy_event_and_cancel_bytes(setup):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    row = request(cancel, order, identity)
    prep = PreparedCancelRequest(
        "legacy", identity, "X", "20300102", 2, {"RequestID": 1}, ("legacy-key",)
    )
    cancel.begin_dispatch("s", "cancel", "p", row.version, prep)
    # A v6 journal can also contain a sourceful v2 prepared request. Migration
    # preserves it without inventing a historical callback association.
    start(cancel, order, identity, "sourceful", "sourceful-key")
    ledger = GatewayDirectExecutionLedger(journal, guard)
    legacy = replace(make_fact(identity), schema_version=1, cancel_request_key=None)
    ledger.ingest(legacy)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE direct_cancel_error_attribution")
        db.execute("UPDATE direct_journal_meta SET schema_version=6")
        before = {
            name: db.execute(f"SELECT * FROM {name}").fetchall()
            for name in (
                "direct_journal_commands",
                "direct_execution_facts",
                "direct_execution_events",
                "direct_cancel_attempts",
                "direct_cancel_keys",
            )
        }
        revision = db.execute("SELECT revision FROM direct_journal_meta").fetchone()[0]
    with pytest.raises(DirectCommandJournalError):
        reopened(journal, path)
    upgraded = GatewayDirectCommandJournal.upgrade_v6(
        path,
        "acct",
        generation=journal.generation,
        guard=guard,
        expected_journal_id=journal.journal_id,
        minimum_revision=revision,
        max_records=10,
        execution_max_facts=20,
    )
    with sqlite3.connect(path) as db:
        assert all(
            db.execute(f"SELECT * FROM {name}").fetchall() == values
            for name, values in before.items()
        )
        assert db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone() == (
            7,
            revision + 1,
        )
    (event,) = GatewayDirectExecutionLedger(upgraded, guard).read_events("s")
    assert event.fact.fact_digest() == legacy.fact_digest() and event.cancel_attribution is None


def test_wrong_dispatch_day_and_generation_are_checked_independently_of_digest(setup):
    from bt_api_base.direct_write_protocol import NativeOrderIdentity
    from bt_api_gateway.direct_dispatch import _identity

    journal, cancel, guard, path = setup
    order = journal.reserve("s", "order", "p", {"symbol": "X", "side": "buy", "quantity": "1"})
    identity = NativeOrderIdentity("TEST", "ref", {"front_id": 1}, 1)
    order = journal.begin_dispatch(
        "s",
        "order",
        order.reservation_id,
        order.digest,
        "p",
        1,
        _identity(identity, "TEST"),
        ("order-key-ref",),
    ).record
    _, prep = start(cancel, order, identity)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    original = make_fact(identity)
    wrong_day = replace(original, trading_day="20300102")
    wrong_gen = replace(original, session_generation=3)
    assert (
        GatewayReturnFact.from_mapping(wrong_day.to_mapping()).fact_digest()
        == wrong_day.fact_digest()
    )
    assert (
        GatewayReturnFact.from_mapping(wrong_gen.to_mapping()).fact_digest()
        == wrong_gen.fact_digest()
    )
    assert wrong_gen.fact_digest() == original.fact_digest()
    for invalid in (wrong_day, wrong_gen):
        with pytest.raises(DirectCommandJournalError, match="CANCEL_ATTRIBUTION_CONFLICT"):
            ingest(ledger, invalid, prep)
    assert not ledger.read_events("s")


@pytest.mark.parametrize("strategy", ["s", "other"])
def test_live_read_rejects_side_attempt_for_another_original_command(setup, strategy):
    journal, cancel, guard, path = setup
    first, identity = make_order(journal)
    second, second_identity = make_order(journal, key="second", strategy=strategy, ref="ref2")
    _, prep = start(cancel, first, identity)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    ingest(ledger, make_fact(identity), prep)
    with sqlite3.connect(path) as db:
        native1 = db.execute(
            "SELECT native_identity_json FROM direct_journal_commands WHERE request_key='order'"
        ).fetchone()[0]
        native2 = db.execute(
            "SELECT native_identity_json FROM direct_journal_commands WHERE request_key='second'"
        ).fetchone()[0]
        # Keep each row internally unique, while making the attempt/command point
        # at order 2 and the event's order keys still point at order 1.
        db.execute(
            "UPDATE direct_journal_commands SET native_identity_json=? WHERE request_key='order'",
            ('{"temporary":true}',),
        )
        db.execute(
            "UPDATE direct_journal_commands SET native_identity_json=? WHERE request_key='second'",
            (native1,),
        )
        db.execute(
            "UPDATE direct_journal_commands SET native_identity_json=? WHERE request_key='order'",
            (native2,),
        )
        db.execute(
            "UPDATE direct_cancel_attempts SET strategy=?,request_key=?,target_reservation_id=?,target_digest=?",
            (strategy, second.request_key, second.reservation_id, second.digest),
        )
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        ledger.read_events("s")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        reopened(journal, path)


def test_v6_migration_failure_rolls_back_all_schema_changes(setup, monkeypatch):
    from bt_api_gateway import direct_execution_journal as module

    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    row = request(cancel, order, identity)
    prep = PreparedCancelRequest(
        "legacy", identity, "X", "20300101", 2, {"RequestID": 1}, ("legacy-key",)
    )
    cancel.begin_dispatch("s", "cancel", "p", row.version, prep)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE direct_cancel_error_attribution")
        db.execute("UPDATE direct_journal_meta SET schema_version=6")
        before = db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
        old = db.execute("SELECT * FROM direct_cancel_attempts").fetchall()
    original = module._create_cancel_error_table

    def fail(db):
        original(db)
        raise RuntimeError("migration failure after ddl")

    monkeypatch.setattr(module, "_create_cancel_error_table", fail)
    with pytest.raises(RuntimeError, match="migration failure"):
        GatewayDirectCommandJournal.upgrade_v6(
            path,
            "acct",
            generation=journal.generation,
            guard=guard,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=10,
            execution_max_facts=20,
        )
    with sqlite3.connect(path) as db:
        assert (
            db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
            == before
        )
        assert db.execute("SELECT * FROM direct_cancel_attempts").fetchall() == old
        assert (
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='direct_cancel_error_attribution'"
            ).fetchone()[0]
            == 0
        )


def test_find_cancel_key_isolated_from_order_keys_and_corruption_fails(setup):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    row, prep = start(cancel, order, identity)
    assert cancel.find_by_request_key("order-key-ref") is None
    assert cancel.find_by_request_key("cancel-key-1") == row
    with sqlite3.connect(path) as db:
        db.execute("UPDATE direct_cancel_attempts SET prepared_digest=?", ("0" * 64,))
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        cancel.find_by_request_key("cancel-key-1")


def test_commit_reply_loss_recovers_same_fact_without_duplicate_event(setup, monkeypatch):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    _, prep = start(cancel, order, identity)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    fact = make_fact(identity)
    original = journal._commit

    def committed_then_raise(db):
        original(db)
        raise RuntimeError("commit reply lost")

    monkeypatch.setattr(journal, "_commit", committed_then_raise)
    with pytest.raises(RuntimeError, match="commit reply lost"):
        ingest(ledger, fact, prep)
    monkeypatch.setattr(journal, "_commit", original)
    assert ingest(ledger, fact, prep).event_sequence == 1
    events = GatewayDirectExecutionLedger(reopened(journal, path), guard).read_events("s")
    assert len(events) == 1 and events[0].fact_digest == fact.fact_digest()


def test_v6_upgrade_rejects_impossible_v2_fact_without_side(setup):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    _, prep = start(cancel, order, identity)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    ingest(ledger, make_fact(identity), prep)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE direct_cancel_error_attribution")
        db.execute("UPDATE direct_journal_meta SET schema_version=6")
        before = db.execute("SELECT schema_version, revision FROM direct_journal_meta").fetchone()
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        GatewayDirectCommandJournal.upgrade_v6(
            path,
            "acct",
            generation=journal.generation,
            guard=guard,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=10,
            execution_max_facts=20,
        )
    with sqlite3.connect(path) as db:
        assert (
            db.execute("SELECT schema_version, revision FROM direct_journal_meta").fetchone()
            == before
        )
        assert (
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='direct_cancel_error_attribution'"
            ).fetchone()[0]
            == 0
        )
