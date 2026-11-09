"""Real returned trade time may enrich one original fill, never add quantity."""
from dataclasses import replace
from bt_api_base.gateway_execution_stream_protocol import (GatewayExecutionObservation,
    project_gateway_execution_observation)

from bt_api_gateway.direct_command_journal import GatewayDirectCommandJournal
from test_iter63_direct_execution_journal import setup, command, fact, INSTRUMENT  # noqa: F401


def test_time_enrichment_is_single_event_conflicts_and_reopens(setup):  # noqa: F811
    journal, ledger, guard, path = setup
    journal.enable_controls(guard)
    journal.enable_strategy_ledger(guard)
    journal.enable_account_extensions(guard)
    journal.enable_parent_authority(guard)
    journal.enable_account_facts_financial(guard)
    command(journal)
    original = replace(fact(), schema_version=4, trade_date='20300101', trade_time=None)
    # The default fixture includes an unbound venue alias; use the original key.
    original = replace(original, identity_keys=('session-a',), binding_keys=('session-a',), venue_key='session-a')
    assert ledger.ingest(original).applied
    enriched = replace(original, source_ref='time-source', trade_time='09:30:01')
    outcome = ledger.ingest(enriched)
    assert outcome.disposition == 'ATTRIBUTED' and not outcome.applied
    assert len(ledger.read_events('s1')) == 2
    event = ledger.read_events('s1')[-1]
    assert event.trade_metadata_only and event.fact.trade_time == '09:30:01'
    assert ledger.position('s1', INSTRUMENT) == '1'
    assert not ledger.ingest(enriched).applied and len(ledger.read_events('s1')) == 2
    conflict = ledger.ingest(replace(enriched, source_ref='conflict-source', trade_time='09:31:01'))
    assert conflict.disposition == 'CONFLICT' and conflict.reason == 'TRADE_TIME_CONFLICT'
    reopened = GatewayDirectCommandJournal(path, 'acct', generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=0, max_records=20, execution_max_facts=20,
        controls_enabled=True, strategy_ledger_enabled=True, account_extensions_enabled=True,
        parent_authority_enabled=True, account_facts_financial_enabled=True)
    assert reopened.account_scope == 'acct'


def test_missing_date_then_real_date_and_time_is_one_enrichment(setup):  # noqa: F811
    journal, ledger, guard, _ = setup
    journal.enable_controls(guard)
    journal.enable_strategy_ledger(guard)
    journal.enable_account_extensions(guard)
    journal.enable_parent_authority(guard)
    journal.enable_account_facts_financial(guard)
    command(journal)
    original = replace(fact(), identity_keys=('session-a',), binding_keys=('session-a',), venue_key='session-a')
    assert ledger.ingest(original).applied
    enriched = replace(original, source_ref='new-source', schema_version=4,
                       trade_date='20300101', trade_time='09:30:01')
    assert ledger.ingest(enriched).disposition == 'ATTRIBUTED'
    assert ledger.read_events('s1')[-1].trade_metadata_only


def test_old_duplicate_time_can_be_reobserved_after_v14_upgrade(setup):  # noqa: F811
    journal, ledger, guard, _ = setup
    journal.enable_controls(guard)
    journal.enable_strategy_ledger(guard)
    journal.enable_account_extensions(guard)
    journal.enable_parent_authority(guard)
    command(journal)
    original = replace(fact(), schema_version=4, trade_date='20300101', trade_time=None,
                       identity_keys=('session-a',), binding_keys=('session-a',), venue_key='session-a')
    assert ledger.ingest(original).applied
    replay = replace(original, source_ref='time-source', trade_date=None, trade_time='09:30:01')
    assert ledger.ingest(replay).reason == 'TRADE_DUPLICATE'
    assert len(ledger.read_events('s1')) == 1
    journal.enable_account_facts_financial(guard)
    assert ledger.ingest(replay).reason == 'TRADE_TIME_ENRICHED'
    assert len(ledger.read_events('s1')) == 2 and ledger.read_events('s1')[-1].trade_metadata_only


def test_date_then_time_only_never_fabricates_date(setup):  # noqa: F811
    journal, ledger, guard, path = setup
    for upgrade in (journal.enable_controls, journal.enable_strategy_ledger, journal.enable_account_extensions,
                    journal.enable_parent_authority, journal.enable_account_facts_financial):
        upgrade(guard)
    command(journal)
    original = replace(fact(), schema_version=4, trade_date='20300101', trade_time=None,
                       identity_keys=('session-a',), binding_keys=('session-a',), venue_key='session-a')
    assert ledger.ingest(original).applied
    later = replace(original, source_ref='time-source', trade_date=None, trade_time='09:30:01')
    assert not ledger.ingest(later).applied and len(ledger.read_events('s1')) == 2
    assert ledger.read_events('s1')[-1].fact.trade_date is None
    assert ledger.read_events('s1')[-1].fact.trade_time == '09:30:01'
    wire = project_gateway_execution_observation(ledger.read_events('s1')[-1].fact, trade_metadata_only=True)
    assert GatewayExecutionObservation.from_mapping(wire.to_mapping()).trade_date is None
    assert not ledger.ingest(later).applied and len(ledger.read_events('s1')) == 2
    conflict = replace(later, source_ref='different', trade_time='09:31:01')
    assert ledger.ingest(conflict).reason == 'TRADE_TIME_CONFLICT'
    GatewayDirectCommandJournal(path, 'acct', generation=journal.generation, expected_journal_id=journal.journal_id,
        minimum_revision=0, max_records=20, execution_max_facts=20, controls_enabled=True, strategy_ledger_enabled=True,
        account_extensions_enabled=True, parent_authority_enabled=True, account_facts_financial_enabled=True)


def test_time_then_date_only_preserves_distinct_sources(setup):  # noqa: F811
    journal, ledger, guard, path = setup
    for upgrade in (journal.enable_controls, journal.enable_strategy_ledger, journal.enable_account_extensions,
                    journal.enable_parent_authority, journal.enable_account_facts_financial):
        upgrade(guard)
    command(journal)
    original = replace(fact(), schema_version=4, trade_date=None, trade_time=None,
                       identity_keys=('session-a',), binding_keys=('session-a',), venue_key='session-a')
    assert ledger.ingest(original).applied
    time_fact = replace(original, source_ref='time-source', trade_time='09:30:01')
    assert ledger.ingest(time_fact).reason == 'TRADE_TIME_ENRICHED'
    date_fact = replace(original, source_ref='date-source', trade_date='20300101')
    assert ledger.ingest(date_fact).reason == 'TRADE_DATE_ENRICHED'
    events = ledger.read_events('s1')
    assert len(events) == 3 and events[-2].fact.trade_date is None and events[-2].fact.trade_time == '09:30:01'
    assert events[-1].fact.trade_date == '20300101' and events[-1].fact.trade_time is None
    GatewayDirectCommandJournal(path, 'acct', generation=journal.generation, expected_journal_id=journal.journal_id,
        minimum_revision=0, max_records=20, execution_max_facts=20, controls_enabled=True, strategy_ledger_enabled=True,
        account_extensions_enabled=True, parent_authority_enabled=True, account_facts_financial_enabled=True)
