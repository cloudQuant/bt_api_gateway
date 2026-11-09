"""Synthetic account event consumer handoff using the real journal owner."""
from contextlib import contextmanager

import pytest
from bt_api_gateway.account_event_consumer_ownership import AccountEventConsumerOwner
from bt_api_gateway.direct_command_journal import DirectCommandJournalError, GatewayDirectCommandJournal
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from test_iter63_direct_execution_journal import setup as execution_setup  # noqa: F401
from test_iter63_direct_execution_journal import command, fact


@contextmanager
def admission():
    yield lambda: None


def test_legacy_upgrade_reoffer_owner_fence_and_restart(execution_setup):  # noqa: F811
    journal, ledger, guard, path = execution_setup
    journal.enable_controls(guard)
    journal.enable_strategy_ledger(guard)
    journal.enable_account_extensions(guard)
    command(journal, strategy='s1', key='one', anchor='a')
    command(journal, strategy='s2', key='two', anchor='b')
    ledger.ingest(fact(keys=('a',), binding=('a',), venue='a', trade_key=('SHFE', 'trade1')))
    ledger.ingest(fact(keys=('b',), binding=('b',), venue='b', trade_key=('SHFE', 'trade2')))
    common = dict(principal_id='observer', consumer_ref='account-view', admission_fence=admission)
    old = ledger.read_account_observer(**common, result_fits=lambda _: True)
    assert len(old.events) == 2
    ledger.acknowledge_account_observer(**common, sequence=old.events[0].sequence, expected_epoch=old.epoch)
    journal.enable_parent_authority(guard)
    journal.enable_account_facts_financial(guard)
    journal.enable_actor_stream(guard)
    journal.enable_strategy_origin(guard)
    journal.enable_control_cancel(guard)
    journal.enable_account_fact_recovery(guard)
    journal.enable_account_event_recovery(guard)
    a = AccountEventConsumerOwner('reg-a', 'epoch', 'run-a')
    b = AccountEventConsumerOwner('reg-b', 'epoch', 'run-b')
    assert ledger.account_observer_progress(**common, consumer_owner=a).offered_sequence == old.events[0].sequence
    with pytest.raises(DirectCommandJournalError, match='CONSUMER_REPLAY_REQUIRED'):
        ledger.acknowledge_account_observer(**common, consumer_owner=a, sequence=old.offered_sequence, expected_epoch=old.epoch)
    with pytest.raises(DirectCommandJournalError, match='CONSUMER_REPLAY_REQUIRED'):
        ledger.read_account_observer(**common, consumer_owner=a, after_sequence=old.offered_sequence,
                                     expected_epoch=old.epoch, result_fits=lambda _: True)
    page_a = ledger.read_account_observer(**common, consumer_owner=a, after_sequence=old.events[0].sequence,
                                          expected_epoch=old.epoch, result_fits=lambda _: True)
    assert page_a.events == (old.events[1],)
    assert ledger.account_observer_progress(**common, consumer_owner=b).offered_sequence == old.events[0].sequence
    with pytest.raises(DirectCommandJournalError, match='CONSUMER_REPLAY_REQUIRED'):
        ledger.acknowledge_account_observer(**common, consumer_owner=b, sequence=page_a.offered_sequence, expected_epoch=old.epoch)
    page_b = ledger.read_account_observer(**common, consumer_owner=b, after_sequence=old.events[0].sequence,
                                          expected_epoch=old.epoch, result_fits=lambda _: True)
    c = AccountEventConsumerOwner('reg-c', 'epoch', 'run-c')
    @contextmanager
    def revoked_before_commit():
        calls = []
        def check():
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError('revoked')
        yield check
    with pytest.raises(RuntimeError, match='revoked'):
        ledger.read_account_observer(principal_id='observer', consumer_ref='account-view',
            admission_fence=revoked_before_commit, consumer_owner=c, after_sequence=old.events[0].sequence,
            expected_epoch=old.epoch, result_fits=lambda _: True)
    assert ledger.account_observer_progress(**common, consumer_owner=b).offered_sequence == page_b.offered_sequence
    with pytest.raises(DirectCommandJournalError, match='CONSUMER_REPLAY_REQUIRED'):
        ledger.acknowledge_account_observer(**common, consumer_owner=a, sequence=page_a.offered_sequence, expected_epoch=old.epoch)
    progress = ledger.acknowledge_account_observer(**common, consumer_owner=b, sequence=page_b.offered_sequence, expected_epoch=old.epoch)
    assert progress.acknowledged_sequence == old.offered_sequence
    reopened = GatewayDirectCommandJournal(path, 'acct', generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=0, max_records=20, execution_max_facts=20,
        controls_enabled=True, strategy_ledger_enabled=True, account_extensions_enabled=True, parent_authority_enabled=True,
        account_facts_financial_enabled=True, actor_stream_enabled=True, strategy_origin_enabled=True,
        control_cancel_enabled=True, account_fact_recovery_enabled=True, account_event_recovery_enabled=True)
    assert GatewayDirectExecutionLedger(reopened, guard).account_observer_progress(**common, consumer_owner=b) == progress
