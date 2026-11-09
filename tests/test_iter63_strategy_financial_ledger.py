"""Synthetic calculations and same-journal persistence; not provider evidence."""

import json
import sqlite3
from dataclasses import replace
from decimal import Decimal

import pytest

from bt_api_gateway.direct_command_journal import DirectCommandJournalError
from bt_api_gateway.strategy_financial_ledger import (
    StrategyFinancialSnapshot,
    _create_strategy_financial_tables,
    append_financial_snapshot,
    read_financial_snapshot,
    verify_strategy_financial_integrity,
)


@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("CREATE TABLE direct_journal_meta (account TEXT, journal_id TEXT)")
    conn.execute("INSERT INTO direct_journal_meta VALUES ('acct', 'journal')")
    conn.execute("BEGIN IMMEDIATE")
    _create_strategy_financial_tables(conn)
    yield conn
    conn.close()


def sample(**changes):
    refs = tuple(
        (item, f"{item}-reference")
        for item in sorted(
            (
                "budget",
                "adjustments",
                "realized_pnl",
                "unrealized_pnl",
                "fees",
                "margin",
                "reservations",
                "coverage",
            )
        )
    )
    values = {
        "account": "acct",
        "journal_id": "journal",
        "strategy": "A",
        "currency": "CNY",
        "revision": 1,
        "previous_digest": None,
        "cut_ref": "cut-1",
        "owner_generation": "generation-1",
        "source_refs": refs,
        "initial_budget": "100000",
        "adjustments": "0",
        "realized_pnl": "2000",
        "unrealized_pnl": "3000",
        "fees": "100",
        "margin": "20000",
        "reservations": "10000",
    }
    values.update(changes)
    return StrategyFinancialSnapshot(**values)


def publish(db, snapshot, verifier=lambda *_: True):
    return append_financial_snapshot(db, snapshot, verify_current=verifier)


def read(db, strategy="A", currency="CNY", verifier=lambda *_: True):
    return read_financial_snapshot(db, "acct", strategy, currency, verify_current=verifier)


def test_equity_cash_and_negative_values_match_contract(db):
    first = sample()
    assert publish(db, first) is True
    assert (read(db).value, read(db).cash) == (Decimal("104900"), Decimal("74900"))
    second = replace(
        first, revision=2, previous_digest=first.digest, cut_ref="cut-2", unrealized_pnl="-3000"
    )
    assert publish(db, second) is True
    assert (read(db).value, read(db).cash) == (Decimal("98900"), Decimal("68900"))
    third = replace(
        second, revision=3, previous_digest=second.digest, cut_ref="cut-3", reservations="0"
    )
    publish(db, third)
    assert (read(db).value, read(db).cash) == (Decimal("98900"), Decimal("78900"))
    fourth = replace(
        third, revision=4, previous_digest=third.digest, cut_ref="cut-4", unrealized_pnl="-200000"
    )
    publish(db, fourth)
    assert read(db).value < 0 and read(db).cash < 0
    verify_strategy_financial_integrity(db, "acct")


def test_replay_and_revisions_cannot_duplicate_or_rewrite_budget(db):
    first = sample()
    assert publish(db, first)
    assert publish(db, first) is False
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_FINANCIAL_UNAVAILABLE"):
        publish(db, replace(first, fees="200"))
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_FINANCIAL_UNAVAILABLE"):
        publish(
            db, replace(first, revision=2, previous_digest=first.digest, initial_budget="100001")
        )
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_FINANCIAL_UNAVAILABLE"):
        publish(db, replace(first, revision=3, previous_digest=first.digest))
    verify_strategy_financial_integrity(db, "acct")


def test_isolation_and_explicit_overallocation_without_account_inference(db):
    first = sample(initial_budget="600000")
    second = sample(strategy="B", initial_budget="600000")
    publish(db, first)
    publish(db, second)
    assert read(db, "A").initial_budget == "600000"
    assert read(db, "B").initial_budget == "600000"
    for strategy, currency in (("C", "CNY"), ("A", "USD")):
        with pytest.raises(DirectCommandJournalError, match="STRATEGY_FINANCIAL_UNAVAILABLE"):
            read(db, strategy, currency)


def test_sources_freshness_identity_and_complete_inputs_required(db):
    for changes in (
        {"fees": None},
        {"unrealized_pnl": None},
        {"initial_budget": None},
        {"source_refs": ()},
        {"model": "spot"},
        {"fees": "-1"},
        {"margin": "1e3"},
        {"reservations": 1.0},
        {"journal_id": "other"},
    ):
        with pytest.raises(DirectCommandJournalError, match="STRATEGY_FINANCIAL_UNAVAILABLE"):
            publish(db, sample(**changes))
    first = sample()
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_FINANCIAL_UNAVAILABLE"):
        publish(db, first, lambda *_: False)
    publish(db, first)
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_FINANCIAL_UNAVAILABLE"):
        read(db, verifier=lambda *_: False)
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_FINANCIAL_UNAVAILABLE"):
        publish(db, first, lambda *_: False)


def test_exact_precision_and_revision_integrity(db):
    large = "9" * 42 + "." + "9" * 42
    first = sample(
        initial_budget=large,
        adjustments="0.000000000000000000000000000000000000000001",
        realized_pnl="0",
        unrealized_pnl="0",
        fees="0",
        margin="0",
        reservations="0",
    )
    publish(db, first)
    assert format(read(db).value, "f") == "1" + "0" * 42 + "." + "0" * 42
    second = replace(first, revision=2, previous_digest=first.digest, cut_ref="second")
    publish(db, second)
    db.execute("DELETE FROM strategy_financial_snapshots WHERE revision=1")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        verify_strategy_financial_integrity(db, "acct")


def test_tampering_and_transaction_requirement(db):
    first = sample()
    publish(db, first)
    raw = json.loads(
        db.execute("SELECT snapshot_json FROM strategy_financial_snapshots").fetchone()[0]
    )
    raw["fees"] = "0"
    db.execute("UPDATE strategy_financial_snapshots SET snapshot_json=?", (json.dumps(raw),))
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        verify_strategy_financial_integrity(db, "acct")
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_FINANCIAL_UNAVAILABLE"):
        read(db)
    db.execute("ROLLBACK")
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_FINANCIAL_UNAVAILABLE"):
        publish(db, first)
