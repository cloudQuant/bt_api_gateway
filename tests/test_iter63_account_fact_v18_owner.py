"""Same owner journal cursor handoff and retention, with synthetic facts only."""
from contextlib import contextmanager

import pytest
from bt_api_gateway.account_fact_consumer_ownership import AccountFactConsumerOwner
from bt_api_gateway.direct_command_journal import DirectCommandJournalError, GatewayDirectCommandJournal
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from test_iter63_external_position_ledger import prepare
from test_iter63_strategy_ledger_owner import owner as strategy_owner  # noqa: F401


@contextmanager
def admission():
    yield lambda: None


def test_real_owner_handoff_compaction_and_snapshot_recovery(strategy_owner):  # noqa: F811
    journal, guard, path = strategy_owner
    prepare(journal, guard)
    journal.enable_account_extensions(guard)
    journal.enable_parent_authority(guard)
    journal.enable_account_facts_financial(guard)
    journal.enable_actor_stream(guard)
    journal.enable_strategy_origin(guard)
    journal.enable_control_cancel(guard)
    journal.enable_account_fact_recovery(guard)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    a = AccountFactConsumerOwner('reg-a', 'epoch', 'run-a')
    b = AccountFactConsumerOwner('reg-b', 'epoch', 'run-b')
    common = dict(principal_id='observer', consumer_ref='consumer', admission_fence=admission)
    page_a = ledger.read_account_facts(**common, consumer_owner=a, result_fits=lambda _: True)
    assert len(page_a.events) == 2
    assert ledger.account_fact_progress(**common, consumer_owner=b).offered_sequence == 0
    with pytest.raises(DirectCommandJournalError, match='CONSUMER_REPLAY_REQUIRED'):
        ledger.acknowledge_account_facts(**common, consumer_owner=b, sequence=page_a.offered_sequence, expected_epoch=page_a.epoch)
    page_b = ledger.read_account_facts(**common, consumer_owner=b, result_fits=lambda _: True)
    assert page_b.events == page_a.events
    with pytest.raises(DirectCommandJournalError, match='CONSUMER_REPLAY_REQUIRED'):
        ledger.acknowledge_account_facts(**common, consumer_owner=a, sequence=page_a.offered_sequence, expected_epoch=page_a.epoch)
    meta = ledger.compact_account_facts()
    assert meta.retained_floor == page_a.offered_sequence and meta.snapshot_count == 2
    with pytest.raises(DirectCommandJournalError, match='RECOVERY_REQUIRED'):
        ledger.read_account_facts(**common, consumer_owner=b, result_fits=lambda _: True)
    snapshot = ledger.read_account_fact_snapshot(**common, consumer_owner=b, snapshot_id=meta.snapshot_id,
        result_fits=lambda _: True, limit=1)
    assert snapshot.has_more and len(snapshot.events) == 1
    with pytest.raises(DirectCommandJournalError, match='SNAPSHOT_NOT_OFFERED'):
        ledger.confirm_account_fact_snapshot(**common, consumer_owner=b, snapshot_id=meta.snapshot_id, snapshot_digest=meta.snapshot_digest)
    snapshot = ledger.read_account_fact_snapshot(**common, consumer_owner=b, snapshot_id=meta.snapshot_id,
        after_ordinal=1, result_fits=lambda _: True, limit=1)
    assert not snapshot.has_more
    ledger.confirm_account_fact_snapshot(**common, consumer_owner=b, snapshot_id=meta.snapshot_id, snapshot_digest=meta.snapshot_digest)
    assert ledger.account_fact_progress(**common, consumer_owner=b).acknowledged_sequence == meta.retained_floor
    reopened = GatewayDirectCommandJournal(path, 'acct', generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=0, controls_enabled=True, strategy_ledger_enabled=True,
        account_extensions_enabled=True, parent_authority_enabled=True, account_facts_financial_enabled=True,
        actor_stream_enabled=True, strategy_origin_enabled=True, control_cancel_enabled=True,
        account_fact_recovery_enabled=True)
    assert reopened.account_scope == 'acct'
