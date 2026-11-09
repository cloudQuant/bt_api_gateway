"""Synthetic account fact snapshots and independent owner cursor."""
from dataclasses import replace
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from bt_api_base.direct_write_protocol import DirectExecutionEventKind, DirectOrderStatus, NativeOrderIdentity
from bt_api_base.gateway_execution_protocol import GatewayReturnFact
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope
from bt_api_gateway.direct_command_journal import DirectCommandJournalError
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from bt_api_gateway.direct_strategy_origin import authorize_strategy_origin
from bt_api_gateway.external_position_ledger import ExternalFactEvidence, record_external_fact
from bt_api_gateway.account_observation_journal import (
    _ACCOUNT_FACT_DDL, initialize_account_fact_stream, append_account_fact,
    verify_account_fact_stream, read_account_facts, acknowledge_account_facts, account_fact_progress,
    _event_digest,
)
from test_iter63_strategy_ledger_owner import owner, baseline, install, open_fill  # noqa: F401
from test_iter63_external_position_ledger import external_trade
from test_iter63_strategy_ledger_owner import KEY
from test_iter63_direct_execution_journal import setup, command, fact  # noqa: F401
from test_iter63_direct_delegation import PAYLOAD as DELEGATED_PAYLOAD, permit as delegated_permit, fence as delegated_fence, command as delegated_command


def test_bootstrap_state_live_external_and_independent_consumer(owner):  # noqa: F811
    journal, guard, _ = owner
    baseline(journal, guard)
    install(journal, guard)
    open_fill(journal, guard)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    external = external_trade()
    assert ledger.ingest(external).disposition == "UNATTRIBUTED"
    unknown = replace(external, trade_key=("SHFE", "other"), identity_keys=("other-venue",), venue_key="other-venue")
    conflicting = replace(unknown, trade_price="11")
    assert ledger.ingest(unknown).disposition == "UNATTRIBUTED"
    assert ledger.ingest(conflicting).disposition == "CONFLICT"
    journal.enable_account_extensions(guard)
    evidence = ExternalFactEvidence("acct", journal.journal_id, journal.generation, 1, "CTP",
        "20300101", external.fact_digest(), "provider-source", "cut", "orders-excluded")
    with journal._transaction() as db:
        epoch = initialize_account_fact_stream(db, "acct", journal.journal_id)
        verify_account_fact_stream(db, "acct", journal.journal_id)
        page = read_account_facts(db, "acct", "observer", "risk", result_fits=lambda _: True)
        assert page.bootstrap_count == 4 and [item.disposition for item in page.events] == ["ATTRIBUTED", "UNATTRIBUTED", "UNATTRIBUTED", "CONFLICT"]
        assert all(item.phase == "BOOTSTRAP" for item in page.events)
        assert all((item.reservation_id, item.origin, item.parent_ref, item.child_id) == (None, None, None, None) for item in page.events)
        assert record_external_fact(db, "acct", external.fact_digest(), evidence, verify_source_and_exclusion=lambda *_: True)
        assert append_account_fact(db, "acct", external.fact_digest())
        assert not append_account_fact(db, "acct", external.fact_digest())
        verify_account_fact_stream(db, "acct", journal.journal_id)
        next_page = read_account_facts(db, "acct", "observer", "risk", after_sequence=4,
            expected_epoch=epoch, result_fits=lambda _: True)
        assert len(next_page.events) == 1 and next_page.events[0].disposition == "VERIFIED_EXTERNAL"
        assert next_page.events[0].phase == "LIVE" and next_page.events[0].fact.source_ref == "provider-source"
        assert next_page.events[0].external_receipt_digest == evidence.digest
        progress = acknowledge_account_facts(db, "acct", "observer", "risk", sequence=5, expected_epoch=epoch)
        assert progress.acknowledged_sequence == 5
        assert account_fact_progress(db, "acct", "observer", "other").acknowledged_sequence == 0
        with pytest.raises(DirectCommandJournalError, match="INVALID_SEQUENCE"):
            acknowledge_account_facts(db, "acct", "observer", "other", sequence=5, expected_epoch=epoch)
        with pytest.raises(DirectCommandJournalError, match="EPOCH_MISMATCH"):
            read_account_facts(db, "acct", "observer", "risk", after_sequence=4,
                expected_epoch="old-observer-epoch", result_fits=lambda _: True)
        db.execute("UPDATE account_fact_stream_events SET reason='forged' WHERE sequence=1")
        with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
            verify_account_fact_stream(db, "acct", journal.journal_id)
        for table in reversed(_ACCOUNT_FACT_DDL):
            db.execute("DROP TABLE " + table)


def test_duplicate_attributed_trade_has_strategy_without_fake_execution_sequence(owner):  # noqa: F811
    journal, guard, _ = owner
    baseline(journal, guard)
    install(journal, guard)
    open_fill(journal, guard)
    duplicate = GatewayReturnFact("acct", "CTP", KEY, "20300101", DirectExecutionEventKind.TRADE,
        "source", identity=NativeOrderIdentity("CTP", "ref", {"trading_day": "20300101"}, 1),
        identity_keys=("anchor",), binding_keys=("anchor",), venue_key="anchor",
        trade_key=("SHFE", "trade"), side="buy", offset="open", trade_quantity="1", trade_price="10",
        trade_time="09:30:00")
    result = GatewayDirectExecutionLedger(journal, guard).ingest(duplicate)
    assert result.disposition == "ATTRIBUTED" and result.event_sequence is None
    journal.enable_account_extensions(guard)
    with journal._transaction() as db:
        initialize_account_fact_stream(db, "acct", journal.journal_id)
        verify_account_fact_stream(db, "acct", journal.journal_id)
        page = read_account_facts(db, "acct", "observer", "risk", result_fits=lambda _: True)
        event = page.events[-1]
        assert event.reason == "TRADE_DUPLICATE" and event.strategy_scope == "s1"
        assert event.execution_sequence is None
        for table in reversed(_ACCOUNT_FACT_DDL):
            db.execute("DROP TABLE " + table)


def test_real_owner_migration_ingestion_and_reopen_preserve_account_stream(owner):  # noqa: F811
    journal, guard, path = owner
    baseline(journal, guard)
    install(journal, guard)
    open_fill(journal, guard)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    external = external_trade()
    assert ledger.ingest(external).disposition == "UNATTRIBUTED"
    journal.enable_account_extensions(guard)
    journal.enable_parent_authority(guard)
    journal.enable_account_facts_financial(guard)
    @contextmanager
    def admission():
        yield lambda: None
    page = ledger.read_account_facts(principal_id="observer", consumer_ref="risk", admission_fence=admission,
                                     result_fits=lambda _: True)
    assert page.bootstrap_count == 2 and [event.disposition for event in page.events] == ["ATTRIBUTED", "UNATTRIBUTED"]
    evidence = ExternalFactEvidence("acct", journal.journal_id, journal.generation, 1, "CTP",
        "20300101", external.fact_digest(), "provider-source", "cut", "orders-excluded")
    @contextmanager
    def source_fence():
        yield
    assert ledger.record_verified_external_fact(external.fact_digest(), evidence, source_fence=source_fence,
                                                verify_source_and_exclusion=lambda *_: True)
    page2 = ledger.read_account_facts(principal_id="observer", consumer_ref="risk", admission_fence=admission,
        result_fits=lambda _: True, after_sequence=2, expected_epoch=page.epoch)
    assert [event.disposition for event in page2.events] == ["VERIFIED_EXTERNAL"]
    unknown = replace(external, trade_key=("SHFE", "another"), identity_keys=("another-venue",), venue_key="another-venue")
    assert ledger.ingest(unknown).disposition == "UNATTRIBUTED"
    assert ledger.ingest(replace(unknown, trade_price="11")).disposition == "CONFLICT"
    page3 = ledger.read_account_facts(principal_id="observer", consumer_ref="risk", admission_fence=admission,
        result_fits=lambda _: True, after_sequence=3, expected_epoch=page.epoch)
    assert [event.disposition for event in page3.events] == ["UNATTRIBUTED", "CONFLICT"]
    ledger.acknowledge_account_facts(principal_id="observer", consumer_ref="risk", admission_fence=admission,
                                     sequence=5, expected_epoch=page.epoch)
    with journal._transaction() as db:
        revision = journal._assert_anchor(db)
    from bt_api_gateway.direct_command_journal import GatewayDirectCommandJournal
    reopened = GatewayDirectCommandJournal(path, "acct", generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=revision,
        controls_enabled=True, strategy_ledger_enabled=True, account_extensions_enabled=True,
        parent_authority_enabled=True, account_facts_financial_enabled=True)
    progress = GatewayDirectExecutionLedger(reopened, guard).account_fact_progress(
        principal_id="observer", consumer_ref="risk", admission_fence=admission)
    assert progress.epoch == page.epoch and progress.acknowledged_sequence == 5


def test_account_stream_records_later_strong_identity_attribution(setup):  # noqa: F811
    journal, ledger, guard, _ = setup
    command(journal)
    early = fact(keys=("venue-a",), binding=())
    assert ledger.ingest(early).disposition == "UNATTRIBUTED"
    journal.enable_controls(guard)
    journal.enable_strategy_ledger(guard)
    journal.enable_account_extensions(guard)
    journal.enable_parent_authority(guard)
    journal.enable_account_facts_financial(guard)
    @contextmanager
    def admission():
        yield lambda: None
    first = ledger.read_account_facts(principal_id="risk", consumer_ref="c", admission_fence=admission,
                                      result_fits=lambda _: True)
    assert first.events[0].disposition == "UNATTRIBUTED" and first.events[0].phase == "BOOTSTRAP"
    anchor = fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED)
    assert ledger.ingest(anchor).disposition == "ATTRIBUTED"
    ledger.reconcile_pending()
    second = ledger.read_account_facts(principal_id="risk", consumer_ref="c", admission_fence=admission,
        result_fits=lambda _: True, after_sequence=first.offered_sequence, expected_epoch=first.epoch)
    assert [event.disposition for event in second.events] == ["ATTRIBUTED", "ATTRIBUTED"]
    assert second.events[-1].fact_digest == early.fact_digest() and second.events[-1].strategy_scope == "s1"


@pytest.mark.parametrize("parent,child", [(None, None), ("parent-a", "child-a")])
def test_account_fact_delegation_labels_are_immutable_and_source_bound(owner, parent, child):  # noqa: F811
    journal, guard, path = owner
    baseline(journal, guard)
    install(journal, guard)
    journal.enable_account_extensions(guard)
    journal.enable_parent_authority(guard)
    journal.enable_account_facts_financial(guard)
    delegated = delegated_command(parent_ref=parent, child_id=child)
    verify_parent = lambda *_: True
    reserved = journal.reserve("strategy", "order-1", "risk-principal", DELEGATED_PAYLOAD,
        reservation_fence=delegated_fence, delegation_permit=delegated_permit(value=delegated, parent=verify_parent))
    identity = {"exchange_name": "CTP", "client_order_id": "order-1", "session_generation": 1, "fields_json": "{}"}
    journal.begin_dispatch("strategy", "order-1", reserved.reservation_id, reserved.digest, "risk-principal", 1,
        identity, ("order-key",), delegation_permit=delegated_permit(value=delegated, parent=verify_parent, operation="direct.dispatch"), delegation_fence=delegated_fence)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    early = fact(keys=("venue-a",), binding=())
    assert ledger.ingest(early).disposition == "UNATTRIBUTED"
    anchor = fact(kind=DirectExecutionEventKind.ORDER, keys=("order-key", "venue-a"),
                  binding=("order-key",), status=DirectOrderStatus.ACCEPTED)
    assert ledger.ingest(anchor).disposition == "ATTRIBUTED"
    ledger.reconcile_pending()
    @contextmanager
    def admission():
        yield lambda: None
    page = ledger.read_account_facts(principal_id="observer", consumer_ref="risk", admission_fence=admission,
                                     result_fits=lambda _: True)
    assert [item.disposition for item in page.events] == ["UNATTRIBUTED", "ATTRIBUTED", "ATTRIBUTED"]
    assert (page.events[0].reservation_id, page.events[0].origin, page.events[0].parent_ref, page.events[0].child_id) == (None, None, None, None)
    for item in page.events[1:]:
        assert (item.reservation_id, item.origin, item.parent_ref, item.child_id) == (reserved.reservation_id, "risk:risk-principal", parent, child)
    with journal._transaction() as db:
        revision = journal._assert_anchor(db)
    from bt_api_gateway.direct_command_journal import GatewayDirectCommandJournal
    reopened = GatewayDirectCommandJournal(path, "acct", generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=revision,
        controls_enabled=True, strategy_ledger_enabled=True, account_extensions_enabled=True,
        parent_authority_enabled=True, account_facts_financial_enabled=True)
    replay = GatewayDirectExecutionLedger(reopened, guard).read_account_facts(
        principal_id="observer", consumer_ref="risk", admission_fence=admission, result_fits=lambda _: True)
    assert replay.events == page.events
    with journal._transaction() as db:
        row = db.execute("SELECT * FROM account_fact_stream_events WHERE sequence=2").fetchone()
        forged = list(row[3:14])
        forged[8] = "risk:forged-principal"
        forged_digest = _event_digest(row[0], row[1], row[2], forged, row[14])
        db.execute("UPDATE account_fact_stream_events SET origin=?,event_digest=? WHERE sequence=2",
                   (forged[8], forged_digest))
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        GatewayDirectCommandJournal(path, "acct", generation=journal.generation,
            expected_journal_id=journal.journal_id, minimum_revision=revision,
            controls_enabled=True, strategy_ledger_enabled=True, account_extensions_enabled=True,
            parent_authority_enabled=True, account_facts_financial_enabled=True)


def test_self_origin_requires_owner_proof_and_never_relabels_history(setup):  # noqa: F811
    journal, ledger, guard, path = setup
    command(journal)
    legacy = fact(keys=("session-a",), binding=("session-a",), venue="session-a")
    assert ledger.ingest(legacy).disposition == "ATTRIBUTED"
    journal.enable_controls(guard)
    journal.enable_strategy_ledger(guard)
    journal.enable_account_extensions(guard)
    journal.enable_parent_authority(guard)
    journal.enable_account_facts_financial(guard)
    journal.enable_actor_stream(guard)
    journal.enable_strategy_origin(guard)
    payload = {"symbol": "rb2601", "exchange_id": "SHFE", "idempotency_key": "self-order",
               "offset": "open", "side": "buy", "quantity": "1", "quantity_unit": "lots"}
    identity = WireIdentity(WireRole.STRATEGY_CLIENT, "self-principal", "self-strategy")
    scope = WireScope("domain", account_ref="acct", strategy_ref="self-strategy", run_id="run")
    context = SimpleNamespace(identity=identity, scope=scope, principal_ref="self-principal", registration_id="reg")
    proof = authorize_strategy_origin(context, KEY, payload, account="acct", journal_id=journal.journal_id,
        generation=journal.generation, service_epoch="epoch", registry_recheck=lambda _: True,
        instrument_recheck=lambda value: value == KEY)
    @contextmanager
    def fence():
        yield
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_ORIGIN_UNAVAILABLE"):
        journal.reserve("self-strategy", "self-order", "self-principal", payload)
    reserved = journal.reserve("self-strategy", "self-order", "self-principal", payload,
                               reservation_fence=fence, strategy_origin_permit=proof)
    native = {"exchange_name": "CTP", "client_order_id": "self-order", "session_generation": 1, "fields_json": "{}"}
    journal.begin_dispatch("self-strategy", "self-order", reserved.reservation_id, reserved.digest,
                           "self-principal", reserved.version, native, ("self-key",))
    own = fact(keys=("self-key",), binding=("self-key",), venue="self-key", trade_key=("SHFE", "self-trade"))
    assert ledger.ingest(own).disposition == "ATTRIBUTED"
    @contextmanager
    def admission():
        yield lambda: None
    page = ledger.read_account_facts(principal_id="observer", consumer_ref="risk", admission_fence=admission,
                                     result_fits=lambda _: True)
    assert [(item.origin, item.reservation_id) for item in page.events] == [(None, None), ("self", reserved.reservation_id)]
    assert all(item.parent_ref is None and item.child_id is None for item in page.events)
    with journal._transaction() as db:
        revision = journal._assert_anchor(db)
    from bt_api_gateway.direct_command_journal import GatewayDirectCommandJournal
    reopened = GatewayDirectCommandJournal(path, "acct", generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=revision, max_records=20, execution_max_facts=20,
        controls_enabled=True, strategy_ledger_enabled=True, account_extensions_enabled=True,
        parent_authority_enabled=True, account_facts_financial_enabled=True,
        actor_stream_enabled=True, strategy_origin_enabled=True)
    replay = GatewayDirectExecutionLedger(reopened, guard).read_account_facts(
        principal_id="observer", consumer_ref="risk", admission_fence=admission, result_fits=lambda _: True)
    assert replay.events == page.events
