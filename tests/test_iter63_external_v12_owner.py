"""An external trade cannot later become a strategy fill via another source."""
from contextlib import contextmanager
from dataclasses import replace

import pytest
from bt_api_gateway.direct_command_journal import DirectCommandJournalError
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from test_iter63_strategy_ledger_owner import owner  # noqa: F401
from test_iter63_external_position_ledger import prepare


@contextmanager
def fence():
    yield


def test_external_replay_cannot_bind_a_system_order(owner):  # noqa: F811
    journal, guard, _ = owner
    fact, evidence = prepare(journal, guard)
    journal.enable_account_extensions(guard)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    assert ledger.record_verified_external_fact(fact.fact_digest(), evidence, source_fence=fence,
                                                 verify_source_and_exclusion=lambda *_: True)
    duplicate = replace(fact, source_ref='new-source')
    assert ledger.ingest(duplicate).disposition == 'UNATTRIBUTED'
    collision = replace(fact, source_ref='other', identity_keys=('anchor', 'external-venue'),
                        binding_keys=('anchor',))
    with pytest.raises(DirectCommandJournalError, match='EXTERNAL_IDENTITY_CONFLICT'):
        ledger.ingest(collision)
    conflicting = replace(fact, source_ref='other', trade_quantity='2')
    with pytest.raises(DirectCommandJournalError, match='EXTERNAL_TRADE_CONFLICT'):
        ledger.ingest(conflicting)
