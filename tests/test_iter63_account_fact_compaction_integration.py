"""Account facts keep monotonic sequence and require explicit snapshot recovery."""
from dataclasses import replace
from contextlib import contextmanager

import pytest
from bt_api_gateway.direct_command_journal import DirectCommandJournalError, _json
from bt_api_gateway.account_observation_journal import (append_account_fact, read_account_facts,
    acknowledge_account_facts, verify_account_fact_stream)
from bt_api_gateway.account_fact_compaction import (initialize_account_fact_compaction, compact_account_facts,
    compaction_metadata, read_account_fact_snapshot, confirm_account_fact_snapshot)
from bt_api_gateway.account_fact_consumer_ownership import ACCOUNT_FACT_OWNER_DDL, AccountFactConsumerOwner, claim_account_fact_reader
from test_iter63_strategy_ledger_owner import owner, baseline, install, open_fill  # noqa: F401
from test_iter63_external_position_ledger import external_trade
from test_iter63_direct_execution_journal import setup, command, fact  # noqa: F401
from bt_api_base.direct_write_protocol import DirectExecutionEventKind, DirectOrderStatus
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger


def test_same_transaction_compaction_replay_and_no_sequence_reuse(owner):  # noqa: F811
    journal, guard, _ = owner
    baseline(journal, guard)
    install(journal, guard)
    open_fill(journal, guard)
    journal.enable_account_extensions(guard)
    journal.enable_parent_authority(guard)
    journal.enable_account_facts_financial(guard)
    with journal._transaction() as db:
        db.execute("SAVEPOINT compact_test")
        for ddl in ACCOUNT_FACT_OWNER_DDL.values():
            db.execute(ddl)
        initialize_account_fact_compaction(db, "acct", journal.journal_id)
        verify_account_fact_stream(db, "acct", journal.journal_id)
        offered_before_compaction = read_account_facts(db, "acct", "observer", "risk", result_fits=lambda _: True)
        assert offered_before_compaction.offered_sequence == 1 and offered_before_compaction.acknowledged_sequence == 0
        meta = compact_account_facts(db, "acct", journal.journal_id)
        assert meta.retained_floor == meta.high_sequence == 1 and meta.snapshot_count == 1
        verify_account_fact_stream(db, "acct", journal.journal_id)
        with pytest.raises(DirectCommandJournalError, match="RECOVERY_REQUIRED"):
            read_account_facts(db, "acct", "observer", "risk", result_fits=lambda _: True)
        with pytest.raises(DirectCommandJournalError, match="RECOVERY_REQUIRED"):
            read_account_facts(db, "acct", "observer", "risk", after_sequence=1,
                               expected_epoch=meta.epoch, result_fits=lambda _: True)
        with pytest.raises(DirectCommandJournalError, match="RECOVERY_REQUIRED"):
            acknowledge_account_facts(db, "acct", "observer", "risk", sequence=1, expected_epoch=meta.epoch)
        existing_digest = db.execute("SELECT fact_digest FROM direct_execution_facts").fetchone()[0]
        assert not append_account_fact(db, "acct", existing_digest)
        new_fact = replace(external_trade(), trade_key=("SHFE", "new-trade"))
        digest = new_fact.fact_digest()
        db.execute("INSERT INTO direct_execution_facts VALUES (?, ?, ?, 'UNATTRIBUTED', 'UNMATCHED', NULL, NULL, 0)",
                   ("acct", digest, _json(new_fact.to_mapping())))
        assert append_account_fact(db, "acct", digest)
        assert db.execute("SELECT sequence FROM account_fact_stream_events").fetchone()[0] == 2
        assert compaction_metadata(db, "acct").high_sequence == 2
        verify_account_fact_stream(db, "acct", journal.journal_id)
        current_owner = AccountFactConsumerOwner("registration", "service-epoch", "run")
        claim_account_fact_reader(db, "acct", "observer", "risk", current_owner, after_sequence=0)
        snapshot = read_account_fact_snapshot(db, "acct", "observer", "risk", owner=current_owner,
            snapshot_id=meta.snapshot_id, result_fits=lambda _: True, verify_consumer=lambda *_: True)
        assert snapshot.watermark == 1 and len(snapshot.events) == 1 and not snapshot.has_more
        confirm_account_fact_snapshot(db, "acct", "observer", "risk", owner=current_owner,
            snapshot_id=meta.snapshot_id, snapshot_digest=meta.snapshot_digest, verify_consumer=lambda *_: True)
        page = read_account_facts(db, "acct", "observer", "risk", after_sequence=1,
                                  expected_epoch=meta.epoch, result_fits=lambda _: True)
        assert [item.sequence for item in page.events] == [2]
        meta = compact_account_facts(db, "acct", journal.journal_id)
        assert meta.retained_floor == meta.high_sequence == 2 and meta.snapshot_count == 2
        verify_account_fact_stream(db, "acct", journal.journal_id)
        db.execute("ROLLBACK TO compact_test")
        db.execute("RELEASE compact_test")


def test_v18_owner_snapshot_replay_monotonicity_and_reopen(setup):  # noqa: F811
    journal, ledger, guard, path = setup
    command(journal)
    trade = fact(keys=("venue-a",), binding=())
    assert ledger.ingest(trade).disposition == "UNATTRIBUTED"
    for method in (journal.enable_controls, journal.enable_strategy_ledger, journal.enable_account_extensions,
                   journal.enable_parent_authority, journal.enable_account_facts_financial, journal.enable_actor_stream,
                   journal.enable_strategy_origin, journal.enable_control_cancel, journal.enable_account_fact_recovery):
        method(guard)
    @contextmanager
    def admission():
        yield lambda: None
    old = AccountFactConsumerOwner("old-registration", "service-epoch", "run")
    current = AccountFactConsumerOwner("new-registration", "service-epoch", "run")
    args = dict(principal_id="observer", consumer_ref="risk", admission_fence=admission, result_fits=lambda _: True)
    first = ledger.read_account_facts(**args, consumer_owner=old)
    assert [item.sequence for item in first.events] == [1] and first.acknowledged_sequence == 0
    with pytest.raises(DirectCommandJournalError, match="CONSUMER_REPLAY_REQUIRED"):
        ledger.read_account_facts(**args, consumer_owner=current, after_sequence=1, expected_epoch=first.epoch)
    replay = ledger.read_account_facts(**args, consumer_owner=current)
    assert [item.sequence for item in replay.events] == [1]
    with pytest.raises(DirectCommandJournalError):
        ledger.acknowledge_account_facts(principal_id="observer", consumer_ref="risk", admission_fence=admission,
            consumer_owner=old, sequence=1, expected_epoch=first.epoch)
    meta = ledger.compact_account_facts()
    assert meta.high_sequence == meta.retained_floor == 1
    with pytest.raises(DirectCommandJournalError, match="RECOVERY_REQUIRED"):
        ledger.read_account_facts(**args, consumer_owner=current)
    # An already offered but not durably acknowledged floor is not recovery.
    with pytest.raises(DirectCommandJournalError, match="RECOVERY_REQUIRED"):
        ledger.read_account_facts(**args, consumer_owner=current, after_sequence=1, expected_epoch=first.epoch)
    with pytest.raises(DirectCommandJournalError, match="RECOVERY_REQUIRED"):
        ledger.acknowledge_account_facts(principal_id="observer", consumer_ref="risk", admission_fence=admission,
            consumer_owner=current, sequence=1, expected_epoch=first.epoch)
    snapshot = ledger.read_account_fact_snapshot(**args, consumer_owner=current, snapshot_id=meta.snapshot_id)
    assert snapshot.watermark == 1 and [item.fact_digest for item in snapshot.events] == [trade.fact_digest()]
    ledger.confirm_account_fact_snapshot(principal_id="observer", consumer_ref="risk", admission_fence=admission,
        consumer_owner=current, snapshot_id=meta.snapshot_id, snapshot_digest=meta.snapshot_digest)
    order = fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED)
    assert ledger.ingest(order).disposition == "ATTRIBUTED"
    ledger.reconcile_pending()
    tail = ledger.read_account_facts(**args, consumer_owner=current, after_sequence=1, expected_epoch=first.epoch)
    assert [item.sequence for item in tail.events] == [2, 3]
    assert [item.disposition for item in tail.events] == ["ATTRIBUTED", "ATTRIBUTED"]
    ledger.acknowledge_account_facts(principal_id="observer", consumer_ref="risk", admission_fence=admission,
        consumer_owner=current, sequence=3, expected_epoch=first.epoch)
    caught_up = ledger.compact_account_facts()
    assert caught_up.retained_floor == 3
    empty = ledger.read_account_facts(**args, consumer_owner=current, after_sequence=3, expected_epoch=first.epoch)
    assert empty.events == () and empty.acknowledged_sequence == 3
    with journal._transaction() as db:
        revision = journal._assert_anchor(db)
    from bt_api_gateway.direct_command_journal import GatewayDirectCommandJournal
    reopened = GatewayDirectCommandJournal(path, "acct", generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=revision, max_records=20, execution_max_facts=20,
        controls_enabled=True, strategy_ledger_enabled=True, account_extensions_enabled=True,
        parent_authority_enabled=True, account_facts_financial_enabled=True, actor_stream_enabled=True,
        strategy_origin_enabled=True, control_cancel_enabled=True, account_fact_recovery_enabled=True)
    progress = GatewayDirectExecutionLedger(reopened, guard).account_fact_progress(
        principal_id="observer", consumer_ref="risk", admission_fence=admission, consumer_owner=current)
    assert progress.acknowledged_sequence == progress.offered_sequence == 3
