"""Explicit v14 upgrade, same-owner account facts and financial projections."""
from contextlib import contextmanager

import pytest
from bt_api_gateway.direct_command_journal import DirectCommandJournalError, GatewayDirectCommandJournal
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from test_iter63_strategy_ledger_owner import owner  # noqa: F401
from test_iter63_external_position_ledger import prepare
from test_iter63_strategy_financial_ledger import sample


@contextmanager
def admission():
    yield lambda: None


def test_v14_bootstrap_live_and_financial_owner_fence(owner):  # noqa: F811
    journal, guard, path = owner
    fact, evidence = prepare(journal, guard)
    journal.enable_account_extensions(guard)
    journal.enable_parent_authority(guard)
    journal.enable_account_facts_financial(guard)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    page = ledger.read_account_facts(principal_id='observer', consumer_ref='acct', admission_fence=admission,
                                     result_fits=lambda _: True)
    assert len(page.events) == 2 and all(event.phase == 'BOOTSTRAP' for event in page.events)
    @contextmanager
    def source():
        yield
    assert ledger.record_verified_external_fact(fact.fact_digest(), evidence, source_fence=source,
                                                  verify_source_and_exclusion=lambda *_: True)
    more = ledger.read_account_facts(principal_id='observer', consumer_ref='acct', admission_fence=admission,
        result_fits=lambda _: True, after_sequence=page.offered_sequence, expected_epoch=page.epoch)
    assert len(more.events) == 1 and more.events[0].disposition == 'VERIFIED_EXTERNAL' and more.events[0].phase == 'LIVE'
    snapshot = sample(account='acct', journal_id=journal.journal_id, owner_generation=journal.generation)
    with pytest.raises(DirectCommandJournalError, match='STRATEGY_FINANCIAL_UNAVAILABLE'):
        journal.read_strategy_financial('A', 'CNY', admission_fence=admission)
    @contextmanager
    def financial_source(account, strategy, currency):
        assert (account, strategy, currency) == ('acct', 'A', 'CNY')
        yield lambda _db, _snapshot: True
    journal.install_strategy_financial_port(guard=guard, source_fence=financial_source)
    assert journal.append_strategy_financial(snapshot, guard=guard)
    assert journal.read_strategy_financial('A', 'CNY', admission_fence=admission) == snapshot
    reopened = GatewayDirectCommandJournal(path, 'acct', generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=0, controls_enabled=True,
        strategy_ledger_enabled=True, account_extensions_enabled=True, parent_authority_enabled=True,
        account_facts_financial_enabled=True)
    assert reopened.account_scope == 'acct'
