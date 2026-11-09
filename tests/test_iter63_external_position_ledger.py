"""Synthetic owner-transaction tests, without provider or account access."""
from dataclasses import replace
from decimal import Decimal

import pytest
from bt_api_base.direct_write_protocol import DirectExecutionEventKind, NativeOrderIdentity
from bt_api_base.gateway_execution_protocol import GatewayReturnFact
from bt_api_gateway.direct_command_journal import DirectCommandJournalError
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from bt_api_gateway.external_position_ledger import (
    _EXTERNAL_LEDGER_DDL, ExternalFactEvidence, external_fact_verified,
    external_identity_collision, external_net, record_external_fact, verify_external_integrity,
)
from bt_api_gateway.strategy_position_ledger import compare_account_net, strategy_position
from test_iter63_strategy_ledger_owner import owner, baseline, install, open_fill, KEY, BINDING  # noqa: F401


def external_trade():
    return GatewayReturnFact("acct", "CTP", KEY, "20300101", DirectExecutionEventKind.TRADE,
        "provider-source", identity=NativeOrderIdentity("CTP", "manual", {"trading_day": "20300101"}, 1),
        identity_keys=("external-venue",), venue_key="external-venue", trade_key=("SHFE", "manual-trade"),
        side="sell", offset="close_today", trade_quantity="1", trade_price="10")


def prepare(journal, guard):
    baseline(journal, guard)
    install(journal, guard)
    open_fill(journal, guard)
    fact = external_trade()
    assert GatewayDirectExecutionLedger(journal, guard).ingest(fact).disposition == "UNATTRIBUTED"
    evidence = ExternalFactEvidence("acct", journal.journal_id, journal.generation, 1, "CTP",
        "20300101", fact.fact_digest(), "provider-source", "after-baseline-cut", "system-orders-exclusion")
    return fact, evidence


def test_external_requires_verifier_and_retains_strategy_quantity(owner):  # noqa: F811
    journal, guard, _ = owner
    fact, evidence = prepare(journal, guard)
    duplicate = replace(fact, source_ref="replay-source", trade_time="09:30:00")
    assert GatewayDirectExecutionLedger(journal, guard).ingest(duplicate).disposition == "UNATTRIBUTED"
    with journal._transaction() as db:
        for ddl in _EXTERNAL_LEDGER_DDL.values():
            db.execute(ddl)
        with pytest.raises(DirectCommandJournalError, match="EXTERNAL_LEDGER_UNAVAILABLE"):
            record_external_fact(db, "acct", fact.fact_digest(), evidence, verify_source_and_exclusion=lambda *_: False)
        assert db.execute("SELECT count(*) FROM external_position_events").fetchone()[0] == 0
        db.execute("SAVEPOINT external_attempt")
        calls_before_failure = []
        def lost_fence(*_):
            calls_before_failure.append(True)
            return len(calls_before_failure) == 1
        with pytest.raises(DirectCommandJournalError, match="EXTERNAL_LEDGER_UNAVAILABLE"):
            record_external_fact(db, "acct", fact.fact_digest(), evidence, verify_source_and_exclusion=lost_fence)
        db.execute("ROLLBACK TO external_attempt")
        db.execute("RELEASE external_attempt")
        assert db.execute("SELECT count(*) FROM external_position_events").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM external_position_trades").fetchone()[0] == 0
        calls = []
        def verify(*args):
            calls.append(args)
            return True
        assert record_external_fact(db, "acct", fact.fact_digest(), evidence, verify_source_and_exclusion=verify)
        assert len(calls) == 2
        assert not record_external_fact(db, "acct", fact.fact_digest(), evidence, verify_source_and_exclusion=verify)
        duplicate_evidence = replace(evidence, fact_digest=duplicate.fact_digest(), source_ref="replay-source")
        assert record_external_fact(db, "acct", duplicate.fact_digest(), duplicate_evidence, verify_source_and_exclusion=verify)
        assert db.execute("SELECT count(*) FROM external_position_trades").fetchone()[0] == 1
        verify_external_integrity(db, "acct")
        assert external_identity_collision(db, "acct", ("external-venue",))
        assert external_net(db, "acct", KEY, trading_day="20300101", cut="current-cut", verify_current=lambda *_: True) == Decimal(-1)
        pos = strategy_position(db, "acct", "s1", BINDING, trading_day="20300101",
            resolve_binding=lambda _: BINDING, verify_day_transition=lambda *_: False,
            verify_current_continuity=lambda *_: True, verify_external_current=verify)
        assert pos.long_today == 1
        comparison = compare_account_net(db, "acct", BINDING, trading_day="20300101",
            account_net="0", external_net="-1", cut="current-cut", resolve_binding=lambda _: BINDING,
            verify_day_transition=lambda *_: False, verify_current_continuity=lambda *_: True,
            verify_account_cut=lambda *_: True,
            verify_external_cut=lambda db, account, binding, day, cut, net:
                external_net(db, account, binding.instrument, trading_day=day, cut=cut,
                             verify_current=lambda *_: True) == Decimal(net),
            verify_external_current=verify)
        assert comparison.status == "MATCH" and comparison.strategy_net == 1 and comparison.external_net == -1
        assert external_fact_verified(db, "acct", fact.fact_digest(), verify_current=verify)
        with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
            strategy_position(db, "acct", "s1", BINDING, trading_day="20300101",
                resolve_binding=lambda _: BINDING, verify_day_transition=lambda *_: False,
                verify_current_continuity=lambda *_: True)
        with pytest.raises(DirectCommandJournalError, match="EXTERNAL_LEDGER_UNAVAILABLE"):
            external_net(db, "acct", KEY, trading_day="20300101", cut="unknown", verify_current=lambda *_: False)
        # Keep the fixture journal's v11 schema unchanged after this focused transaction.
        for table in reversed(_EXTERNAL_LEDGER_DDL):
            db.execute("DROP TABLE " + table)


def test_external_record_rejects_bound_identity_and_changed_evidence(owner):  # noqa: F811
    journal, guard, _ = owner
    fact, evidence = prepare(journal, guard)
    with journal._transaction() as db:
        for ddl in _EXTERNAL_LEDGER_DDL.values():
            db.execute(ddl)
        with pytest.raises(DirectCommandJournalError, match="EXTERNAL_LEDGER_UNAVAILABLE"):
            record_external_fact(db, "acct", fact.fact_digest(), replace(evidence, source_ref="wrong"),
                                 verify_source_and_exclusion=lambda *_: True)
        db.execute("INSERT INTO direct_journal_strong_keys VALUES ('acct','external-venue','unknown')")
        with pytest.raises(DirectCommandJournalError, match="EXTERNAL_LEDGER_UNAVAILABLE"):
            record_external_fact(db, "acct", fact.fact_digest(), evidence, verify_source_and_exclusion=lambda *_: True)
        db.execute("DELETE FROM direct_journal_strong_keys WHERE strong_key='external-venue'")
        for table in reversed(_EXTERNAL_LEDGER_DDL):
            db.execute("DROP TABLE " + table)


def test_conflicting_trade_dates_do_not_replace_original_external_fact(owner):  # noqa: F811
    journal, guard, _ = owner
    baseline(journal, guard)
    original = replace(external_trade(), schema_version=4, trade_date="20300101")
    conflicting = replace(original, trade_date="20300102")
    ledger = GatewayDirectExecutionLedger(journal, guard)
    assert ledger.ingest(original).disposition == "UNATTRIBUTED"
    assert ledger.ingest(conflicting).disposition == "UNATTRIBUTED"
    evidence = ExternalFactEvidence("acct", journal.journal_id, journal.generation, 1, "CTP",
        "20300101", original.fact_digest(), "provider-source", "cut", "system-orders-exclusion")
    with journal._transaction() as db:
        for ddl in _EXTERNAL_LEDGER_DDL.values():
            db.execute(ddl)
        record_external_fact(db, "acct", original.fact_digest(), evidence, verify_source_and_exclusion=lambda *_: True)
        with pytest.raises(DirectCommandJournalError, match="EXTERNAL_FACT_CONFLICT"):
            record_external_fact(db, "acct", conflicting.fact_digest(),
                replace(evidence, fact_digest=conflicting.fact_digest()), verify_source_and_exclusion=lambda *_: True)
        assert db.execute("SELECT count(*) FROM external_position_trades").fetchone()[0] == 1
        verify_external_integrity(db, "acct")
        for table in reversed(_EXTERNAL_LEDGER_DDL):
            db.execute("DROP TABLE " + table)
