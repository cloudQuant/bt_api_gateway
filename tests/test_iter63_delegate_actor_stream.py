"""Synthetic delegated execution and an independent actor cursor."""
from contextlib import contextmanager

import pytest

from bt_api_base.direct_write_protocol import DirectExecutionEventKind, DirectOrderStatus
from bt_api_gateway.delegate_actor_stream import GatewayDelegateActorStream
from bt_api_gateway.direct_command_journal import DirectCommandJournalError, GatewayDirectCommandJournal
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger

from test_iter63_direct_delegation import PAYLOAD, command, fence, owner, permit  # noqa: F401
from test_iter63_direct_execution_journal import fact


@contextmanager
def admission():
    yield lambda: None


def _setup(actor_owner):
    journal, guard, path = actor_owner
    journal.enable_account_extensions(guard)
    journal.enable_parent_authority(guard)
    journal.enable_account_facts_financial(guard)
    journal.enable_actor_stream(guard)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    row = journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD,
                          reservation_fence=fence, delegation_permit=permit())
    native = {'exchange_name': 'CTP', 'client_order_id': 'order-1', 'session_generation': 1, 'fields_json': '{}'}
    journal.begin_dispatch('strategy', 'order-1', row.reservation_id, row.digest, 'risk-principal', 1,
        native, ('session-a',), delegation_permit=permit(operation='direct.dispatch'), delegation_fence=fence)
    assert ledger.ingest(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED)).disposition == 'ATTRIBUTED'
    assert ledger.ingest(fact(keys=('venue-a',), binding=())).applied
    return journal, guard, path, ledger, GatewayDelegateActorStream(ledger, journal)


def _kwargs():
    return dict(principal='risk-principal', consumer='consumer', strategy='strategy', actor_ref='risk-actor',
                run_id='run', revision='grant-v1', admission_fence=admission)


def _read(stream, **changes):
    return stream.read(**_kwargs(), after_sequence=changes.get('after_sequence', 0),
                       expected_epoch=changes.get('expected_epoch'), limit=changes.get('limit', 256),
                       authorize_command=lambda _: True, result_fits=lambda _: True)


def test_actor_stream_ack_is_independent_and_reopens(owner):  # noqa: F811
    journal, guard, path, ledger, stream = _setup(owner)
    page = _read(stream, limit=1)
    assert len(page.events) == 1 and page.has_more
    assert page.events[0].command == command()
    assert page.events[0].event.command_principal == 'risk-principal'
    progress = stream.acknowledge(**_kwargs(), sequence=page.events[0].event.sequence,
                                  expected_epoch=page.progress.epoch, result_fits=lambda _: True)
    assert progress.acknowledged_sequence == page.events[0].event.sequence
    next_page = _read(stream, after_sequence=progress.acknowledged_sequence, expected_epoch=progress.epoch)
    assert len(next_page.events) == 1 and not next_page.has_more
    with journal._transaction() as db:
        assert db.execute('SELECT count(*) FROM direct_execution_consumers').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM direct_account_observer_consumers').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM account_fact_stream_consumers').fetchone()[0] == 0
        revision = journal._assert_anchor(db)
    reopened = GatewayDirectCommandJournal(path, 'acct', generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=revision, controls_enabled=True,
        strategy_ledger_enabled=True, account_extensions_enabled=True, parent_authority_enabled=True,
        account_facts_financial_enabled=True, actor_stream_enabled=True)
    restored = GatewayDelegateActorStream(GatewayDirectExecutionLedger(reopened, guard), reopened)
    assert restored.progress(**_kwargs()).acknowledged_sequence == progress.acknowledged_sequence


def test_actor_scope_epoch_permission_and_commit_failure(owner):  # noqa: F811
    _, _, _, _, stream = _setup(owner)
    with pytest.raises(DirectCommandJournalError, match='ACTOR_STREAM_UNAVAILABLE'):
        stream.read(**_kwargs(), after_sequence=0, expected_epoch=None, limit=2,
                    authorize_command=lambda _: False, result_fits=lambda _: True)
    assert stream.progress(**_kwargs()).offered_sequence == 0
    with pytest.raises(DirectCommandJournalError, match='PAGE_TOO_LARGE'):
        stream.read(**_kwargs(), after_sequence=0, expected_epoch=None, limit=2,
                    authorize_command=lambda _: True, result_fits=lambda _: False)
    assert stream.progress(**_kwargs()).offered_sequence == 0
    calls = []
    def revoked_before_commit(_command):
        calls.append(1)
        return len(calls) < 3
    with pytest.raises(DirectCommandJournalError, match='ACTOR_STREAM_UNAVAILABLE'):
        stream.read(**_kwargs(), after_sequence=0, expected_epoch=None, limit=2,
                    authorize_command=revoked_before_commit, result_fits=lambda _: True)
    assert stream.progress(**_kwargs()).offered_sequence == 0
    page = _read(stream)
    with pytest.raises(DirectCommandJournalError, match='EPOCH_MISMATCH'):
        _read(stream, after_sequence=page.events[0].event.sequence, expected_epoch='0' * 64)
    with pytest.raises(DirectCommandJournalError, match='INVALID_SEQUENCE'):
        stream.acknowledge(**_kwargs(), sequence=page.progress.offered_sequence + 1,
                           expected_epoch=page.progress.epoch, result_fits=lambda _: True)
    other = dict(_kwargs(), principal='other', consumer='other')
    assert not stream.read(**other, after_sequence=0, expected_epoch=None, limit=10,
                           authorize_command=lambda _: True, result_fits=lambda _: True).events
    other_run = dict(_kwargs(), consumer='other-run', run_id='replacement')
    assert not stream.read(**other_run, after_sequence=0, expected_epoch=None, limit=10,
                           authorize_command=lambda _: True, result_fits=lambda _: True).events


def test_missing_anchor_is_explicit_gap(owner):  # noqa: F811
    journal, _, _, _, stream = _setup(owner)
    page = _read(stream)
    # Simulates an unsupported compactor deleting an offered event.
    with journal._transaction() as db:
        db.execute('DELETE FROM direct_execution_events WHERE sequence=?', (page.progress.offered_sequence,))
    with pytest.raises(DirectCommandJournalError, match='ACTOR_STREAM_GAP|INVALID_DATABASE'):
        stream.progress(**_kwargs())
