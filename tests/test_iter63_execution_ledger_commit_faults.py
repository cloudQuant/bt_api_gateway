"""Synthetic fault injection around real same-database SQLite ledger commits."""

import multiprocessing
import os
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from bt_api_base.direct_write_protocol import DirectExecutionEventKind, DirectOrderStatus
from test_iter63_direct_execution_journal import INSTRUMENT, command, fact
from test_iter63_direct_execution_journal import setup as setup

from bt_api_gateway.direct_command_journal import GatewayDirectCommandJournal
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from bt_api_gateway.session_guard import LocalAccountSessionGuard, LocalAccountSessionGuardError


class CommitFaultError(RuntimeError):
    pass


def _state(path):
    queries = {
        "direct_execution_meta": "SELECT * FROM direct_execution_meta ORDER BY rowid",
        "direct_execution_facts": "SELECT * FROM direct_execution_facts ORDER BY rowid",
        "direct_execution_trades": "SELECT * FROM direct_execution_trades ORDER BY rowid",
        "direct_execution_positions": "SELECT * FROM direct_execution_positions ORDER BY rowid",
        "direct_execution_totals": "SELECT * FROM direct_execution_totals ORDER BY rowid",
        "direct_execution_events": "SELECT * FROM direct_execution_events ORDER BY rowid",
        "direct_execution_aliases": "SELECT * FROM direct_execution_aliases ORDER BY rowid",
        "direct_execution_conflicts": "SELECT * FROM direct_execution_conflicts ORDER BY rowid",
    }
    with sqlite3.connect(path) as db:
        rows = {name: db.execute(query).fetchall() for name, query in queries.items()}
        rows["revision"] = db.execute("SELECT revision FROM direct_journal_meta").fetchone()[0]
    return rows


def _trade():
    return fact(keys=("session-a",), binding=("session-a",), venue="session-a")


def _crash_writer(root, stage, connection):
    """Own only this test's local files and exit at the real transaction boundary."""
    root = Path(root)
    guard = LocalAccountSessionGuard(root / "writer-guard", "acct", "writer")
    generation = guard.acquire()
    journal = GatewayDirectCommandJournal.create(
        root / "db", "acct", generation=generation, max_records=20, execution_max_facts=20
    )
    ledger = GatewayDirectExecutionLedger(journal, guard)
    command(journal)
    connection.send(("ready", journal.journal_id))
    if connection.recv() != "crash":
        os._exit(73)
    actual_commit = journal._commit

    def exit_at_commit(db):
        if stage == "after_commit":
            actual_commit(db)
        os._exit(72 if stage == "after_commit" else 71)

    journal._commit = exit_at_commit
    ledger.ingest(_trade())
    os._exit(74)


def test_ingest_commit_failure_rolls_back_entire_fact_and_projection(setup, monkeypatch):
    journal, ledger, _guard, path = setup
    command(journal)
    before = _state(path)
    assert before["direct_execution_meta"][0][2] == 0
    assert before["direct_execution_totals"] == []
    with monkeypatch.context() as patch:

        def fail_before_commit(_db):
            raise CommitFaultError("synthetic precommit failure")

        patch.setattr(journal, "_commit", fail_before_commit)
        with pytest.raises(CommitFaultError):
            ledger.ingest(_trade())
    assert _state(path) == before
    assert ledger.position("s1", INSTRUMENT) is None
    assert ledger.read_events("s1") == ()
    assert ledger.ingest(_trade()).applied is True
    assert ledger.position("s1", INSTRUMENT) == "1"


def test_ingest_lost_response_after_real_commit_reopens_once(setup, monkeypatch):
    journal, ledger, guard, path = setup
    command(journal)
    trade = _trade()
    commit = journal._commit
    with monkeypatch.context() as patch:

        def committed_then_lost(db):
            commit(db)
            raise CommitFaultError("synthetic lost response after actual commit")

        patch.setattr(journal, "_commit", committed_then_lost)
        with pytest.raises(CommitFaultError):
            ledger.ingest(trade)
    committed = _state(path)
    assert len(committed["direct_execution_facts"]) == 1
    assert len(committed["direct_execution_trades"]) == 1
    assert len(committed["direct_execution_events"]) == 1
    assert len(committed["direct_execution_totals"]) == 1
    assert committed["direct_execution_totals"][0][2] == "1"
    assert committed["direct_execution_meta"][0][2] == 1
    reopened = GatewayDirectCommandJournal(
        path,
        "acct",
        generation=journal.generation,
        expected_journal_id=journal.journal_id,
        minimum_revision=committed["revision"],
        max_records=20,
        execution_max_facts=20,
    )
    recovered = GatewayDirectExecutionLedger(reopened, guard)
    assert recovered.position("s1", INSTRUMENT) == "1"
    assert len(recovered.read_events("s1")) == 1
    assert recovered.ingest(trade).applied is False
    assert _state(path) == committed


def test_reconcile_commit_failure_retries_same_first_pending_fact(setup, monkeypatch):
    journal, ledger, _guard, path = setup
    command(journal)
    first = fact(keys=("venue-a",), binding=())
    second = replace(first, trade_key=("SHFE", "trade-2"))
    assert ledger.ingest(first).disposition == ledger.ingest(second).disposition == "UNATTRIBUTED"
    ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED))
    before = _state(path)
    with monkeypatch.context() as patch:

        def fail_before_commit(_db):
            raise CommitFaultError("synthetic reconcile commit failure")

        patch.setattr(journal, "_commit", fail_before_commit)
        with pytest.raises(CommitFaultError):
            ledger.reconcile_pending(limit=1)
    assert _state(path) == before
    assert ledger.position("s1", INSTRUMENT) is None
    (retried,) = ledger.reconcile_pending(limit=1)
    assert retried.fact_digest == first.fact_digest() and retried.applied is True
    assert ledger.position("s1", INSTRUMENT) == "1"
    (remaining,) = ledger.reconcile_pending(limit=1)
    assert remaining.fact_digest == second.fact_digest() and remaining.applied is True
    assert ledger.position("s1", INSTRUMENT) == "2"
    assert ledger.reconcile_pending(limit=1) == ()
    assert len(ledger.read_events("s1")) == 3


def test_guard_lost_at_precommit_recheck_rolls_back(setup, monkeypatch):
    journal, ledger, guard, path = setup
    command(journal)
    before = _state(path)
    original = guard.assert_owned
    calls = []
    with monkeypatch.context() as patch:

        def fail_last_recheck():
            calls.append(True)
            if len(calls) == 4:
                patch.setattr(guard, "_os_locked", False)
            original()

        patch.setattr(guard, "assert_owned", fail_last_recheck)
        with pytest.raises(LocalAccountSessionGuardError) as failure:
            ledger.ingest(_trade())
    assert failure.value.code == "SESSION_NOT_OWNED"
    assert len(calls) == 4
    assert _state(path) == before
    assert ledger.position("s1", INSTRUMENT) is None
    assert ledger.read_events("s1") == ()
    assert ledger.ingest(_trade()).applied is True


@pytest.mark.parametrize("stage,exit_code", [("before_commit", 71), ("after_commit", 72)])
def test_process_exit_sqlite_atomicity_with_isolated_guard_not_guard_takeover(
    tmp_path, stage, exit_code
):
    """New isolated guard tests storage only; the crashed guard is not recovered."""
    (tmp_path / "writer-guard").mkdir()
    (tmp_path / "reader-guard").mkdir()
    context = multiprocessing.get_context("spawn")
    parent, child_end = context.Pipe()
    child = context.Process(target=_crash_writer, args=(str(tmp_path), stage, child_end))
    child.start()
    child_end.close()
    reader = None
    try:
        assert parent.poll(15), "synthetic child failed to initialize"
        ready = parent.recv()
        assert ready[0] == "ready"
        before = _state(tmp_path / "db")
        assert before["direct_execution_meta"][0][2] == 0
        assert before["direct_execution_totals"] == []
        parent.send("crash")
        child.join(15)
        assert not child.is_alive() and child.exitcode == exit_code
        after_crash = _state(tmp_path / "db")
        if stage == "before_commit":
            assert after_crash == before
        else:
            assert after_crash["revision"] == before["revision"] + 1
            assert len(after_crash["direct_execution_facts"]) == 1
            assert len(after_crash["direct_execution_trades"]) == 1
            assert len(after_crash["direct_execution_positions"]) == 1
            assert len(after_crash["direct_execution_totals"]) == 1
            assert after_crash["direct_execution_totals"][0][2] == "1"
            assert len(after_crash["direct_execution_events"]) == 1
            assert after_crash["direct_execution_meta"][0][2] == 1
        stale = LocalAccountSessionGuard(tmp_path / "writer-guard", "acct", "other")
        with pytest.raises(LocalAccountSessionGuardError) as failure:
            stale.acquire()
        assert failure.value.code == "SESSION_RECONCILIATION_REQUIRED"
        # Separate synthetic lock root is deliberately not evidence of safe takeover.
        reader = LocalAccountSessionGuard(tmp_path / "reader-guard", "acct", "isolated-reader")
        generation = reader.acquire()
        journal = GatewayDirectCommandJournal(
            tmp_path / "db",
            "acct",
            generation=generation,
            expected_journal_id=ready[1],
            minimum_revision=before["revision"],
            max_records=20,
            execution_max_facts=20,
        )
        ledger = GatewayDirectExecutionLedger(journal, reader)
        before_replay = _state(tmp_path / "db")
        replay = ledger.ingest(_trade())
        assert replay.applied is (stage == "before_commit")
        assert ledger.position("s1", INSTRUMENT) == "1"
        assert len(ledger.read_events("s1")) == 1
        final = _state(tmp_path / "db")
        assert len(final["direct_execution_facts"]) == len(final["direct_execution_trades"]) == 1
        assert (
            len(final["direct_execution_positions"]) == len(final["direct_execution_totals"]) == 1
        )
        assert final["direct_execution_totals"][0][2] == "1"
        assert len(final["direct_execution_events"]) == 1
        assert final["direct_execution_meta"][0][2] == 1
        if stage == "after_commit":
            assert final == before_replay
        assert ledger.ingest(_trade()).applied is False
        assert _state(tmp_path / "db") == final
    finally:
        if child.is_alive():
            child.terminate()
            child.join(5)
        parent.close()
        if reader is not None:
            reader.release()
