"""Synthetic same-journal proof of venue alias attribution."""
import hashlib
from dataclasses import replace

import pytest
from bt_api_base.direct_write_protocol import DirectExecutionEventKind, DirectOrderStatus
from bt_api_gateway.direct_command_journal import DirectCommandJournalError, GatewayDirectCommandJournal
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger

from test_iter63_direct_execution_journal import command, fact, setup  # noqa: F401


def make_events(journal, ledger):
    record, _ = command(journal)
    anchor = fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED)
    trade = fact(keys=("venue-a",), binding=())
    assert ledger.ingest(anchor).disposition == "ATTRIBUTED"
    assert ledger.ingest(trade).applied
    return record, anchor, trade


def test_venue_only_trade_proof_uses_prior_order_and_original_key(setup):
    journal, ledger, guard, path = setup
    command_record, anchor, trade = make_events(journal, ledger)
    event = ledger.read_events("s1")[1]
    proof = event.trade_attribution
    assert event.fact == trade and event.fact.binding_keys == ()
    assert proof.account_scope == "acct" and proof.strategy_scope == "s1"
    assert proof.fact_digest == trade.fact_digest() and proof.anchor_fact_digest == anchor.fact_digest()
    assert proof.anchor_sequence == 1 and proof.anchor_sequence < event.sequence
    assert proof.reservation_id == command_record.reservation_id and proof.command_digest == command_record.digest
    assert proof.venue_key_digest == hashlib.sha256(b"venue-a").hexdigest()
    assert proof.original_binding_key_digests == (hashlib.sha256(b"session-a").hexdigest(),)
    with journal._transaction() as db:
        revision = journal._assert_anchor(db)
    reopened = GatewayDirectCommandJournal(path, "acct", generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=revision,
        max_records=20, execution_max_facts=20)
    assert GatewayDirectExecutionLedger(reopened, guard).read_events("s1")[1].trade_attribution == proof


def test_trade_without_alias_anchor_is_rejected_on_read_and_reopen(setup):
    journal, ledger, _, path = setup
    make_events(journal, ledger)
    with journal._transaction() as db:
        revision = journal._assert_anchor(db)
        db.execute("UPDATE direct_execution_events SET strategy='wrong' WHERE sequence=1")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        ledger.read_events("s1", after_sequence=1)
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        GatewayDirectCommandJournal(path, "acct", generation=journal.generation,
            expected_journal_id=journal.journal_id, minimum_revision=revision,
            max_records=20, execution_max_facts=20)


def test_missing_alias_cannot_be_replaced_by_attribution_claim(setup):
    journal, ledger, _, _ = setup
    make_events(journal, ledger)
    with journal._transaction() as db:
        db.execute("DELETE FROM direct_execution_aliases WHERE account='acct' AND strong_key='venue-a'")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        ledger.read_events("s1", after_sequence=1)


def test_date_enrichment_uses_anchor_earlier_than_original_trade(setup):
    journal, ledger, _, _ = setup
    command(journal)
    anchor = fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED)
    trade = replace(fact(keys=("venue-a",), binding=()), schema_version=4)
    enriched = replace(trade, trade_date="20300101")
    ledger.ingest(anchor)
    ledger.ingest(trade)
    ledger.ingest(enriched)
    events = ledger.read_events("s1")
    assert len(events) == 3 and events[2].trade_metadata_only
    assert events[1].trade_attribution.anchor_sequence == events[2].trade_attribution.anchor_sequence == 1
    assert events[2].trade_attribution.fact_digest == enriched.fact_digest()
