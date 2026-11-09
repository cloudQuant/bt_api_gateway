"""Synthetic owner-transaction tests; no provider or account is contacted."""
from contextlib import contextmanager

import pytest

from bt_api_gateway.account_fact_compaction import (
    ACCOUNT_FACT_COMPACTION_DDL,
    compact_account_facts,
    compaction_metadata,
    confirm_account_fact_snapshot,
    initialize_account_fact_compaction,
    iter_snapshot,
    read_account_fact_snapshot,
    snapshot_latest,
    verify_account_fact_compaction,
)
from bt_api_gateway.account_fact_consumer_ownership import (
    ACCOUNT_FACT_OWNER_DDL,
    AccountFactConsumerOwner,
    claim_account_fact_reader,
)
from bt_api_gateway.account_observation_journal import (
    _ACCOUNT_FACT_DDL,
    account_fact_progress,
    initialize_account_fact_stream,
)
from bt_api_gateway.direct_command_journal import DirectCommandJournalError
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from bt_api_gateway.external_position_ledger import ExternalFactEvidence, record_external_fact
from test_iter63_external_position_ledger import external_trade
from test_iter63_strategy_ledger_owner import baseline, install, open_fill, owner  # noqa: F401


@contextmanager
def synthetic_stream(fixture):
    journal, guard, _ = fixture
    baseline(journal, guard)
    install(journal, guard)
    open_fill(journal, guard)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    external = external_trade()
    assert ledger.ingest(external).disposition == "UNATTRIBUTED"
    journal.enable_account_extensions(guard)
    with journal._transaction() as db:
        epoch = initialize_account_fact_stream(db, "acct", journal.journal_id)
        for ddl in ACCOUNT_FACT_OWNER_DDL.values():
            db.execute(ddl)
        initialize_account_fact_compaction(db, "acct", journal.journal_id)
        try:
            yield journal, db, epoch, external
        finally:
            for name in reversed(ACCOUNT_FACT_COMPACTION_DDL):
                db.execute("DROP TABLE " + name)
            for name in reversed(ACCOUNT_FACT_OWNER_DDL):
                db.execute("DROP TABLE " + name)
            for name in reversed(_ACCOUNT_FACT_DDL):
                db.execute("DROP TABLE " + name)


def _current(*_):
    return True


def test_compaction_preserves_local_facts_epoch_and_bounded_pages(owner):  # noqa: F811
    with synthetic_stream(owner) as (journal, db, epoch, external):
        original = db.execute("SELECT count(*) FROM direct_execution_facts").fetchone()[0]
        meta = compact_account_facts(db, "acct", journal.journal_id)
        assert meta.epoch == epoch and meta.retained_floor == meta.high_sequence == 2
        assert meta.snapshot_count == original == 2
        assert db.execute("SELECT count(*) FROM account_fact_stream_events").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM direct_execution_facts").fetchone()[0] == original
        assert snapshot_latest(db, "acct", external.fact_digest()).disposition == "UNATTRIBUTED"
        assert len(tuple(iter_snapshot(db, "acct"))) == original
        assert compact_account_facts(db, "acct", journal.journal_id) == meta

        a = AccountFactConsumerOwner("registration-a", "epoch-a", "run-a")
        claim_account_fact_reader(db, "acct", "observer", "consumer", a, after_sequence=0)
        with pytest.raises(DirectCommandJournalError, match="SNAPSHOT_NOT_OFFERED"):
            confirm_account_fact_snapshot(db, "acct", "observer", "consumer", owner=a,
                snapshot_id=meta.snapshot_id, snapshot_digest=meta.snapshot_digest, verify_consumer=_current)
        first = read_account_fact_snapshot(db, "acct", "observer", "consumer", owner=a,
            snapshot_id=meta.snapshot_id, limit=1, result_fits=lambda _: True, verify_consumer=_current)
        assert first.watermark == 2 and first.total == 2 and first.has_more and len(first.events) == 1
        assert account_fact_progress(db, "acct", "observer", "consumer").acknowledged_sequence == 0
        with pytest.raises(DirectCommandJournalError, match="INVALID_SEQUENCE"):
            read_account_fact_snapshot(db, "acct", "observer", "consumer", owner=a,
                snapshot_id=meta.snapshot_id, after_ordinal=2, result_fits=lambda _: True, verify_consumer=_current)
        second = read_account_fact_snapshot(db, "acct", "observer", "consumer", owner=a,
            snapshot_id=meta.snapshot_id, after_ordinal=1, limit=1, result_fits=lambda _: True, verify_consumer=_current)
        assert not second.has_more and len(second.events) == 1
        confirm_account_fact_snapshot(db, "acct", "observer", "consumer", owner=a,
            snapshot_id=meta.snapshot_id, snapshot_digest=meta.snapshot_digest, verify_consumer=_current)
        progress = account_fact_progress(db, "acct", "observer", "consumer")
        assert (progress.offered_sequence, progress.acknowledged_sequence) == (2, 2)
        assert account_fact_progress(db, "acct", "observer", "other").acknowledged_sequence == 0


def test_new_owner_must_receive_snapshot_again_and_revoked_fence_rejects(owner):  # noqa: F811
    with synthetic_stream(owner) as (journal, db, _, _):
        meta = compact_account_facts(db, "acct", journal.journal_id)
        a = AccountFactConsumerOwner("registration-a", "epoch-a", "run-a")
        b = AccountFactConsumerOwner("registration-b", "epoch-b", "run-b")
        claim_account_fact_reader(db, "acct", "observer", "consumer", a, after_sequence=0)
        read_account_fact_snapshot(db, "acct", "observer", "consumer", owner=a,
            snapshot_id=meta.snapshot_id, result_fits=lambda _: True, verify_consumer=_current)
        claim_account_fact_reader(db, "acct", "observer", "consumer", b, after_sequence=0)
        with pytest.raises(DirectCommandJournalError, match="SNAPSHOT_NOT_OFFERED"):
            confirm_account_fact_snapshot(db, "acct", "observer", "consumer", owner=b,
                snapshot_id=meta.snapshot_id, snapshot_digest=meta.snapshot_digest, verify_consumer=_current)
        with pytest.raises(DirectCommandJournalError, match="CONSUMER_REPLAY_REQUIRED"):
            confirm_account_fact_snapshot(db, "acct", "observer", "consumer", owner=a,
                snapshot_id=meta.snapshot_id, snapshot_digest=meta.snapshot_digest, verify_consumer=_current)
        with pytest.raises(DirectCommandJournalError, match="CONSUMER_FENCE_UNAVAILABLE"):
            read_account_fact_snapshot(db, "acct", "observer", "consumer", owner=b,
                snapshot_id=meta.snapshot_id, result_fits=lambda _: True, verify_consumer=lambda *_: False)
        with pytest.raises(DirectCommandJournalError, match="INVALID_SEQUENCE"):
            read_account_fact_snapshot(db, "acct", "observer", "consumer", owner=b,
                snapshot_id=meta.snapshot_id, after_ordinal=1, result_fits=lambda _: True, verify_consumer=_current)
        read_account_fact_snapshot(db, "acct", "observer", "consumer", owner=b,
            snapshot_id=meta.snapshot_id, result_fits=lambda _: True, verify_consumer=_current)
        confirm_account_fact_snapshot(db, "acct", "observer", "consumer", owner=b,
            snapshot_id=meta.snapshot_id, snapshot_digest=meta.snapshot_digest, verify_consumer=_current)


def test_snapshot_offer_and_confirmation_roll_back_on_late_revocation(owner):  # noqa: F811
    with synthetic_stream(owner) as (journal, db, _, _):
        meta = compact_account_facts(db, "acct", journal.journal_id)
        identity = AccountFactConsumerOwner("registration", "epoch", "run")
        calls = []
        def revoke_on_final_check(*_):
            calls.append(None)
            return len(calls) < 3
        db.execute("SAVEPOINT cancelled_offer")
        with pytest.raises(DirectCommandJournalError, match="CONSUMER_FENCE_UNAVAILABLE"):
            read_account_fact_snapshot(db, "acct", "observer", "consumer", owner=identity,
                snapshot_id=meta.snapshot_id, result_fits=lambda _: True, verify_consumer=revoke_on_final_check)
        db.execute("ROLLBACK TO cancelled_offer")
        db.execute("RELEASE cancelled_offer")
        assert db.execute("SELECT count(*) FROM account_fact_snapshot_offers").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM account_fact_consumer_owners").fetchone()[0] == 0
        read_account_fact_snapshot(db, "acct", "observer", "consumer", owner=identity,
            snapshot_id=meta.snapshot_id, result_fits=lambda _: True, verify_consumer=_current)
        calls.clear()
        def revoke_during_confirm(*_):
            calls.append(None)
            return len(calls) < 2
        db.execute("SAVEPOINT cancelled_confirm")
        with pytest.raises(DirectCommandJournalError, match="CONSUMER_FENCE_UNAVAILABLE"):
            confirm_account_fact_snapshot(db, "acct", "observer", "consumer", owner=identity,
                snapshot_id=meta.snapshot_id, snapshot_digest=meta.snapshot_digest, verify_consumer=revoke_during_confirm)
        db.execute("ROLLBACK TO cancelled_confirm")
        db.execute("RELEASE cancelled_confirm")
        assert account_fact_progress(db, "acct", "observer", "consumer").acknowledged_sequence == 0


def test_incomplete_or_corrupted_snapshot_never_compacts(owner):  # noqa: F811
    with synthetic_stream(owner) as (journal, db, _, external):
        # Losing an observation row must not silently produce a partial baseline.
        row = db.execute("SELECT * FROM account_fact_stream_events WHERE sequence=2").fetchone()
        db.execute("DELETE FROM account_fact_stream_events WHERE sequence=2")
        with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
            compact_account_facts(db, "acct", journal.journal_id)
        assert compaction_metadata(db, "acct").retained_floor == 0
        db.execute("INSERT INTO account_fact_stream_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(row))
        meta = compact_account_facts(db, "acct", journal.journal_id)
        db.execute("UPDATE account_fact_compaction_items SET event_digest=? WHERE fact_digest=?", ("0" * 64, external.fact_digest()))
        with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
            verify_account_fact_compaction(db, "acct", journal.journal_id)
        assert compaction_metadata(db, "acct").snapshot_id == meta.snapshot_id


def test_compaction_rolls_back_if_snapshot_commit_fails(owner, monkeypatch):  # noqa: F811
    import bt_api_gateway.account_fact_compaction as compact_module

    with synthetic_stream(owner) as (journal, db, _, _):
        verify = compact_module.verify_account_fact_compaction
        count = []
        def fail_after_replace(*args):
            count.append(None)
            if len(count) == 2:
                raise RuntimeError("synthetic commit failure")
            return verify(*args)
        monkeypatch.setattr(compact_module, "verify_account_fact_compaction", fail_after_replace)
        db.execute("SAVEPOINT interrupted_compaction")
        with pytest.raises(RuntimeError, match="synthetic commit failure"):
            compact_account_facts(db, "acct", journal.journal_id)
        db.execute("ROLLBACK TO interrupted_compaction")
        db.execute("RELEASE interrupted_compaction")
        assert compaction_metadata(db, "acct").retained_floor == 0
        assert db.execute("SELECT count(*) FROM account_fact_stream_events").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM account_fact_compaction_items").fetchone()[0] == 0


def test_second_compaction_replaces_snapshot_and_old_pages_fail(owner):  # noqa: F811
    with synthetic_stream(owner) as (journal, db, _, external):
        first = compact_account_facts(db, "acct", journal.journal_id)
        evidence = ExternalFactEvidence("acct", journal.journal_id, journal.generation, 1, "CTP",
            "20300101", external.fact_digest(), "provider-source", "cut", "orders-excluded")
        assert record_external_fact(db, "acct", external.fact_digest(), evidence, verify_source_and_exclusion=lambda *_: True)
        # v18 append is provided by the stream owner; model its exact contract
        # here so this module's isolated atomic snapshot can be verified.
        from bt_api_gateway.account_observation_journal import _event_digest, _snapshot
        snap = _snapshot(db, "acct", external.fact_digest())
        sequence = first.high_sequence + 1
        db.execute("INSERT INTO account_fact_stream_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sequence, "acct", external.fact_digest(), *snap, "LIVE", _event_digest(sequence, "acct", external.fact_digest(), snap, "LIVE")))
        db.execute("UPDATE account_fact_compaction_meta SET high_sequence=? WHERE account=?", (sequence, "acct"))
        second = compact_account_facts(db, "acct", journal.journal_id)
        assert second.retained_floor == sequence and second.snapshot_id != first.snapshot_id
        assert snapshot_latest(db, "acct", external.fact_digest()).disposition == "VERIFIED_EXTERNAL"
        a = AccountFactConsumerOwner("registration-a", "epoch-a", "run-a")
        claim_account_fact_reader(db, "acct", "observer", "consumer", a, after_sequence=0)
        with pytest.raises(DirectCommandJournalError, match="SNAPSHOT_REPLACED"):
            read_account_fact_snapshot(db, "acct", "observer", "consumer", owner=a,
                snapshot_id=first.snapshot_id, result_fits=lambda _: True, verify_consumer=_current)
