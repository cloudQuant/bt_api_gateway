"""Synthetic account observer has a separate durable cursor and fence."""
from contextlib import contextmanager

import pytest
from bt_api_gateway.direct_command_journal import DirectCommandJournalError, GatewayDirectCommandJournal
from test_iter63_direct_execution_journal import setup, command, fact  # noqa: F401


@contextmanager
def admission():
    yield lambda: None


def test_account_observer_is_independent_of_strategy_ack_and_reopens(setup):  # noqa: F811
    journal, ledger, guard, path = setup
    journal.enable_controls(guard)
    journal.enable_strategy_ledger(guard)
    journal.enable_account_extensions(guard)
    command(journal, strategy='s1', key='one', anchor='a')
    command(journal, strategy='s2', key='two', anchor='b')
    first = ledger.ingest(fact(keys=('a',), binding=('a',), venue='a', trade_key=('SHFE', 'trade1')))
    second = ledger.ingest(fact(keys=('b',), binding=('b',), venue='b', trade_key=('SHFE', 'trade2')))
    assert (first.disposition, second.disposition) == ('ATTRIBUTED', 'ATTRIBUTED')
    strategy_page = ledger.read_for_consumer('s1', principal_id='strategy-principal', consumer_ref='strategy-consumer',
                                              result_fits=lambda _: True)
    before = ledger.consumer_progress('s1', principal_id='strategy-principal', consumer_ref='strategy-consumer')
    page = ledger.read_account_observer(principal_id='observer', consumer_ref='account-view',
                                         admission_fence=admission, result_fits=lambda _: True)
    assert [event.strategy_scope for event in page.events] == ['s1', 's2']
    assert page.epoch != strategy_page.epoch
    progress = ledger.acknowledge_account_observer(principal_id='observer', consumer_ref='account-view',
        sequence=page.offered_sequence, expected_epoch=page.epoch, admission_fence=admission)
    assert progress.acknowledged_sequence == page.offered_sequence
    assert ledger.consumer_progress('s1', principal_id='strategy-principal', consumer_ref='strategy-consumer') == before
    with pytest.raises(DirectCommandJournalError, match='EPOCH_MISMATCH'):
        ledger.acknowledge_account_observer(principal_id='observer', consumer_ref='account-view',
            sequence=1, expected_epoch=strategy_page.epoch, admission_fence=admission)
    reopened = GatewayDirectCommandJournal(path, 'acct', generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=0, max_records=20, execution_max_facts=20,
        controls_enabled=True, strategy_ledger_enabled=True, account_extensions_enabled=True)
    assert reopened.account_scope == 'acct'


def test_revoked_account_observer_never_commits_offer(setup):  # noqa: F811
    journal, ledger, guard, _ = setup
    journal.enable_controls(guard)
    journal.enable_strategy_ledger(guard)
    journal.enable_account_extensions(guard)
    command(journal, anchor='a')
    ledger.ingest(fact(keys=('a',), binding=('a',), venue='a'))
    @contextmanager
    def revoked():
        checks = []
        def check():
            checks.append(1)
            if len(checks) == 2:
                raise RuntimeError('revoked')
        yield check
    with pytest.raises(RuntimeError, match='revoked'):
        ledger.read_account_observer(principal_id='observer', consumer_ref='account-view',
                                     admission_fence=revoked, result_fits=lambda _: True)
    assert ledger.account_observer_progress(principal_id='observer', consumer_ref='account-view',
                                            admission_fence=admission).offered_sequence == 0
