"""Trade-date enrichment, migrations, and tamper rejection in real SQLite."""

import sqlite3
from dataclasses import replace

import pytest
from test_iter63_direct_execution_journal import INSTRUMENT, command, fact
from test_iter63_direct_execution_journal import setup as setup

from bt_api_gateway.direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
)
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger


def dated(value, day="20300102", **changes):
    return replace(value, schema_version=4, trade_date=day, **changes)


def reopen(journal, guard, path):
    reopened = GatewayDirectCommandJournal(
        path,
        "acct",
        generation=journal.generation,
        expected_journal_id=journal.journal_id,
        minimum_revision=0,
        max_records=20,
        execution_max_facts=20,
    )
    return GatewayDirectExecutionLedger(reopened, guard)


def base_trade():
    return fact(keys=("session-a",), binding=("session-a",), venue="session-a")


@pytest.mark.parametrize("first_v4", [False, True])
def test_enrichment_duplicate_conflict_and_reopen(setup, first_v4):
    journal, ledger, guard, path = setup
    command(journal)
    first = dated(base_trade(), None) if first_v4 else base_trade()
    assert ledger.ingest(first).applied
    known = dated(base_trade())
    result = ledger.ingest(known)
    assert (result.reason, result.applied) == ("TRADE_DATE_ENRICHED", False)
    events = ledger.read_events("s1")
    assert [event.trade_metadata_only for event in events] == [False, True]
    assert ledger.position("s1", INSTRUMENT) == "1"
    assert ledger.ingest(replace(known, source_ref="second")).reason == "TRADE_DUPLICATE"
    assert ledger.ingest(replace(base_trade(), source_ref="later")).reason == "TRADE_DUPLICATE"
    assert len(ledger.read_events("s1")) == 2
    assert reopen(journal, guard, path).position("s1", INSTRUMENT) == "1"
    conflict = ledger.ingest(dated(base_trade(), "20300103"))
    assert conflict.reason == "TRADE_DATE_CONFLICT" and not conflict.applied
    assert ledger.ingest(first).reason == "TRADE_CONFLICT_RETAINED"
    assert reopen(journal, guard, path).position("s1", INSTRUMENT) == "1"
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT trade_date FROM direct_execution_trade_dates").fetchone() == (
            "20300102",
        )
        assert db.execute("SELECT total_quantity FROM direct_execution_totals").fetchone() == ("1",)


def test_known_first_and_pending_replay(setup):
    journal, ledger, guard, path = setup
    known = dated(base_trade())
    assert ledger.ingest(known).disposition == "UNATTRIBUTED"
    command(journal)
    assert ledger.reconcile_pending()[0].applied
    assert [x.trade_metadata_only for x in ledger.read_events("s1")] == [False]
    assert (
        reopen(journal, guard, path).ingest(dated(base_trade(), None)).reason == "TRADE_DUPLICATE"
    )
    with sqlite3.connect(path) as db:
        date, current, original = db.execute(
            "SELECT trade_date,fact_digest,original_fact_digest FROM direct_execution_trade_dates"
        ).fetchone()
        assert date == "20300102" and current == original == known.fact_digest()


def test_wrong_identity_cannot_enrich(setup):
    journal, ledger, guard, path = setup
    command(journal)
    original = base_trade()
    ledger.ingest(original)
    wrong = dated(
        replace(original, identity_keys=("wrong",), binding_keys=("wrong",), venue_key="wrong")
    )
    assert ledger.ingest(wrong).reason == "TRADE_CONTENT_CONFLICT"
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM direct_execution_trade_dates").fetchone()[0] == 0
    reopen(journal, guard, path)


def test_enrichment_commit_failure_rolls_back(setup, monkeypatch):
    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(base_trade())

    def fail(_db):
        raise RuntimeError("failed commit")

    monkeypatch.setattr(journal, "_commit", fail)
    with pytest.raises(RuntimeError, match="failed commit"):
        ledger.ingest(dated(base_trade()))
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM direct_execution_trade_dates").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM direct_execution_events").fetchone()[0] == 1
    assert reopen(journal, guard, path).position("s1", INSTRUMENT) == "1"


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM direct_execution_trade_dates",
        "UPDATE direct_execution_trade_dates SET trade_date='20300103'",
        "UPDATE direct_execution_trade_dates SET original_fact_digest=fact_digest",
        "UPDATE direct_execution_trade_dates SET fact_digest=original_fact_digest",
        "UPDATE direct_execution_facts SET reason='MATCHED' WHERE reason='TRADE_DATE_ENRICHED'",
    ],
)
def test_corrupt_enrichment_rejected_on_reopen(setup, sql):
    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(base_trade())
    ledger.ingest(dated(base_trade()))
    with sqlite3.connect(path) as db:
        db.execute(sql)
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        reopen(journal, guard, path)


def test_explicit_v8_upgrade_preserves_fact_bytes_and_rolls_back(setup, monkeypatch):
    from bt_api_gateway import direct_execution_journal as module

    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(base_trade())
    with sqlite3.connect(path) as db:
        before = db.execute("SELECT fact_digest,fact_json FROM direct_execution_facts").fetchall()
        db.execute("DROP TABLE direct_execution_trade_dates")
        db.execute("UPDATE direct_journal_meta SET schema_version=8")
        revision = db.execute("SELECT revision FROM direct_journal_meta").fetchone()[0]
    kwargs = {
        "generation": journal.generation,
        "guard": guard,
        "expected_journal_id": journal.journal_id,
        "minimum_revision": revision,
        "max_records": 20,
        "execution_max_facts": 20,
    }
    with pytest.raises(DirectCommandJournalError):
        reopen(journal, guard, path)
    create = module._create_trade_date_table

    def fail(db):
        create(db)
        raise RuntimeError("injected")

    monkeypatch.setattr(module, "_create_trade_date_table", fail)
    with pytest.raises(RuntimeError, match="injected"):
        GatewayDirectCommandJournal.upgrade_v8(path, "acct", **kwargs)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone() == (
            8,
            revision,
        )
        assert db.execute(
            "SELECT count(*) FROM sqlite_master WHERE name='direct_execution_trade_dates'"
        ).fetchone() == (0,)
    monkeypatch.setattr(module, "_create_trade_date_table", create)
    upgraded = GatewayDirectCommandJournal.upgrade_v8(path, "acct", **kwargs)
    with sqlite3.connect(path) as db:
        assert (
            db.execute("SELECT fact_digest,fact_json FROM direct_execution_facts").fetchall()
            == before
        )
        assert db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone() == (
            9,
            revision + 1,
        )
    recovered = GatewayDirectExecutionLedger(upgraded, guard)
    assert recovered.ingest(dated(base_trade())).reason == "TRADE_DATE_ENRICHED"
    reopen(upgraded, guard, path)


def test_capacity_rejects_enrichment_without_partial_write(tmp_path):
    from bt_api_gateway.session_guard import LocalAccountSessionGuard

    directory = tmp_path / "guard"
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, "acct", "owner")
    generation = guard.acquire()
    try:
        journal = GatewayDirectCommandJournal.create(
            tmp_path / "db", "acct", generation=generation, max_records=20, execution_max_facts=1
        )
        ledger = GatewayDirectExecutionLedger(journal, guard)
        command(journal)
        ledger.ingest(base_trade())
        with pytest.raises(DirectCommandJournalError, match="EXECUTION_CAPACITY_EXCEEDED"):
            ledger.ingest(dated(base_trade()))
        assert ledger.ingest(base_trade()).reason == "TRADE_DUPLICATE"
        with sqlite3.connect(tmp_path / "db") as db:
            assert db.execute("SELECT count(*) FROM direct_execution_trade_dates").fetchone() == (
                0,
            )
            assert db.execute("SELECT count(*) FROM direct_execution_events").fetchone() == (1,)
        assert ledger.position("s1", INSTRUMENT) == "1"
    finally:
        guard.release()


def test_wrong_instrument_cannot_enrich(setup):
    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(base_trade())
    wrong = replace(INSTRUMENT, native_symbol="wrong")
    assert ledger.ingest(dated(replace(base_trade(), instrument=wrong))).disposition == "CONFLICT"
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM direct_execution_trade_dates").fetchone() == (0,)
    reopen(journal, guard, path)


def test_v8_upgrade_checks_existing_place_association(setup):
    from test_iter63_place_error_attribution import begin, ingest, make_fact, reserve

    journal, _, guard, path = setup
    order, identity, prep = reserve(journal)
    begin(journal, order, identity, prep)
    fact3 = make_fact(identity)
    ingest(GatewayDirectExecutionLedger(journal, guard), fact3, prep)
    with sqlite3.connect(path) as db:
        before = db.execute("SELECT fact_digest,fact_json FROM direct_execution_facts").fetchall()
        db.execute("DROP TABLE direct_execution_trade_dates")
        db.execute("UPDATE direct_journal_meta SET schema_version=8")
    upgraded = GatewayDirectCommandJournal.upgrade_from_v8(
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
            db.execute("SELECT fact_digest,fact_json FROM direct_execution_facts").fetchall()
            == before
        )
    assert (
        GatewayDirectExecutionLedger(upgraded, guard).read_events("s1")[0].place_attribution
        is not None
    )


def test_v8_rejects_v4_facts_without_migration(setup):
    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(dated(base_trade()))
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE direct_execution_trade_dates")
        db.execute("UPDATE direct_journal_meta SET schema_version=8")
        before = db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        GatewayDirectCommandJournal.upgrade_from_v8(
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


def test_retained_conflict_requires_original_conflict_evidence(setup):
    journal, ledger, guard, path = setup
    command(journal)
    first = dated(base_trade())
    conflict = dated(base_trade(), "20300103")
    assert ledger.ingest(first).applied
    assert ledger.ingest(conflict).reason == "TRADE_DATE_CONFLICT"
    # A later retained fact legitimately refers to the existing conflict evidence.
    retained = dated(base_trade(), "20300104")
    assert ledger.ingest(retained).reason == "TRADE_CONFLICT_RETAINED"
    reopen(journal, guard, path)
    with sqlite3.connect(path) as db:
        db.execute(
            "DELETE FROM direct_execution_facts WHERE fact_digest=?", (retained.fact_digest(),)
        )
        db.execute("UPDATE direct_execution_meta SET fact_count=fact_count-1")
        db.execute(
            "UPDATE direct_execution_facts SET reason='TRADE_CONFLICT_RETAINED' WHERE fact_digest=?",
            (conflict.fact_digest(),),
        )
        db.execute(
            "DELETE FROM direct_execution_conflicts WHERE fact_digest=?", (conflict.fact_digest(),)
        )
        db.execute("UPDATE direct_execution_trades SET conflict=0")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        reopen(journal, guard, path)


def test_unreconciled_date_disagreement_remains_pending(setup):
    journal, ledger, guard, path = setup
    command(journal)
    pending = dated(replace(base_trade(), identity_keys=("session-a", "unbound")), "20300103")
    assert ledger.ingest(pending).reason == "IDENTITY_KEYS_UNBOUND"
    assert ledger.ingest(dated(base_trade())).applied
    recovered = reopen(journal, guard, path)
    assert recovered.position("s1", INSTRUMENT) == "1"
    assert recovered.reconcile_pending()[0].reason == "IDENTITY_KEYS_UNBOUND"


def test_running_event_reads_reject_mutated_metadata_reason(setup):
    journal, ledger, guard, path = setup
    command(journal)
    ledger.ingest(base_trade())
    ledger.ingest(dated(base_trade()))
    assert [e.trade_metadata_only for e in ledger.read_events("s1")] == [False, True]
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE direct_execution_facts SET reason='MATCHED' WHERE reason='TRADE_DATE_ENRICHED'"
        )
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        ledger.read_events("s1")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        ledger.read_for_consumer(
            "s1", principal_id="p", consumer_ref="c", result_fits=lambda _: True
        )
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        reopen(journal, guard, path)


def test_running_event_reads_reject_mismatched_applied_pointer(setup):
    journal, ledger, _, path = setup
    command(journal)
    ledger.ingest(base_trade())
    ledger.ingest(dated(base_trade()))
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE direct_execution_trades SET fact_digest=(SELECT fact_digest FROM direct_execution_trade_dates)"
        )
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        ledger.read_events("s1")
