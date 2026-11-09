import pytest

from bt_api_gateway.direct_command_journal import DirectCommandJournalError, GatewayDirectCommandJournal
from bt_api_gateway.direct_control import GatewayDirectControl
from bt_api_gateway.session_guard import LocalAccountSessionGuard


@pytest.fixture
def setup(tmp_path):
    directory = tmp_path / 'guards'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'account', 'owner')
    generation = guard.acquire()
    journal = GatewayDirectCommandJournal.create(tmp_path / 'db', 'account', generation=generation, clock=lambda: 100.0)
    control = journal.enable_controls(guard)
    yield journal, control, guard, tmp_path / 'db'
    guard.release()


def test_control_fences_new_reservations_and_dispatch(setup):
    journal, control, guard, path = setup
    old = journal.reserve('one', 'old', 'principal', {'symbol': 'X'})
    control.apply('freeze-one', 'FREEZE', scope_kind='strategy', scope_value='one', origin='operator')
    with pytest.raises(DirectCommandJournalError, match='CONTROL_FREEZE'):
        journal.reserve('one', 'new', 'principal', {'symbol': 'X'})
    assert journal.reserve('one', 'old', 'principal', {'symbol': 'X'}) == old
    assert journal.reserve('two', 'new', 'principal', {'symbol': 'X'}).strategy_scope == 'two'
    with pytest.raises(DirectCommandJournalError, match='CONTROL_PREVIOUSLY_BLOCKED'):
        journal.begin_dispatch('one', 'old', old.reservation_id, old.digest, 'principal', old.version,
                               {'exchange': 'TEST'}, ('key',))
    control.resume('freeze-one', expected_version=1, operation_id='resume-freeze')
    assert journal.reserve('one', 'new', 'principal', {'symbol': 'X'}).status == 'RESERVED'
    with pytest.raises(DirectCommandJournalError, match='CONTROL_PREVIOUSLY_BLOCKED'):
        journal.begin_dispatch('one', 'old', old.reservation_id, old.digest, 'principal', old.version,
                               {'exchange': 'TEST'}, ('key',))
    reopened = GatewayDirectCommandJournal(path, 'account', generation=journal.generation,
                   expected_journal_id=journal.journal_id, minimum_revision=0,
                   clock=lambda: 100.0, controls_enabled=True)
    assert reopened.get('one', 'old', 'principal') == old
    GatewayDirectControl(reopened, guard)


def test_drain_freezes_targets_and_resume_cancels_only_pending(setup):
    journal, control, _, _ = setup
    old = journal.reserve('one', 'old', 'principal', {'symbol': 'X'})
    journal.begin_dispatch('one', 'old', old.reservation_id, old.digest, 'principal', old.version,
                           {'exchange': 'TEST'}, ('key',))
    control.apply('drain-one', 'DRAIN', scope_kind='strategy', scope_value='one', origin='operator')
    first, = control.targets('drain-one')
    assert first['request_key'] == 'old' and first['state'] == 'PENDING'
    observed = []
    control.issue_next('drain-one', lambda row: observed.append(row['operation_id']))
    assert control.targets('drain-one')[0]['state'] == 'UNKNOWN'
    assert control.issue_next('drain-one', lambda row: observed.append(row)) is None
    control.resume('drain-one', expected_version=1, operation_id='resume-drain')
    assert control.targets('drain-one')[0]['state'] == 'UNKNOWN'
    assert len(observed) == 1


def test_resume_recovery_proof_uses_same_transaction_and_rolls_back(setup):
    _, control, _, _ = setup
    control.apply('lease-one', 'DRAIN', scope_kind='strategy', scope_value='one', origin='system')
    seen = []
    def deny(db):
        seen.append(db.in_transaction)
        return False
    with pytest.raises(DirectCommandJournalError, match='CONTROL_RECOVERY_UNVERIFIED'):
        control.resume('lease-one', expected_version=1, operation_id='resume', before_commit_db=deny)
    assert seen == [True]
    assert control.get('lease-one')['active'] == 1
    control.resume('lease-one', expected_version=1, operation_id='resume', before_commit_db=lambda db: db.in_transaction)
    assert control.get('lease-one')['active'] == 0


def test_frozen_drain_dispatches_original_order_once_through_existing_cancel_dispatcher(setup):
    from bt_api_gateway.direct_cancel_dispatch import GatewayDirectCancelDispatcher
    from bt_api_gateway.direct_cancel_journal import GatewayDirectCancelJournal
    from bt_api_gateway.direct_dispatch import GatewayDirectDispatcher, NativeDispatchOutcome
    from test_iter63_direct_cancel_dispatch import record
    from test_iter63_direct_cancel_journal import make_order, prepared

    journal, control, guard, _ = setup
    order, identity = make_order(journal)
    owner = GatewayDirectDispatcher(journal, 'TEST', guard, lambda *_: None, lambda _: ('unused',), lambda _: True)
    calls = []
    def native(target, symbol, port, scope):
        marker = port.commit(record(target, symbol, scope, prepared(target)))
        calls.append(marker)
        return NativeDispatchOutcome(True, target, marker)
    dispatcher = GatewayDirectCancelDispatcher(GatewayDirectCancelJournal(journal), owner, guard, 'TEST', native, lambda _: True)
    control.apply('drain', 'DRAIN', scope_kind='strategy', scope_value='s', origin='operator')
    target, = control.targets('drain')
    claimed, token = control.claim_target('drain', target['reservation_id'])
    with pytest.raises(DirectCommandJournalError, match='CONTROL_CANCEL_PROOF_REQUIRED'):
        control.dispatch_claimed_cancel(claimed, dispatcher, token)
    assert journal.get('s', 'order', 'p').status == order.status
    assert control.targets('drain')[0]['state'] == 'UNKNOWN'
    assert control.claim_target('drain', target['reservation_id'])[1] is None
    assert not calls


def test_terminal_target_tracks_only_attributed_order_and_reverts_on_later_nonterminal(setup):
    from dataclasses import replace
    from bt_api_base.direct_write_protocol import DirectExecutionEventKind, DirectOrderStatus
    from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
    from test_iter63_direct_execution_journal import command, fact

    journal, control, guard, _ = setup
    row, _ = command(journal)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    control.apply('drain-terminal', 'DRAIN', scope_kind='strategy', scope_value='s1', origin='operator')
    terminal = replace(fact(kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.CANCELLED),
                       account_scope='account', order_quantity='2', filled_quantity='1')
    result = ledger.ingest(terminal)
    assert result.disposition == 'ATTRIBUTED'
    assert control.reconcile_targets('drain-terminal') is True
    target, = control.targets('drain-terminal')
    assert target['state'] == 'OBSERVED_TERMINAL' and target['terminal_fact_digest'] == terminal.fact_digest()
    assert target['reservation_id'] == row.reservation_id
    later = replace(terminal, status=DirectOrderStatus.ACCEPTED, source_ref='later-source')
    assert ledger.ingest(later).disposition == 'ATTRIBUTED'
    assert control.reconcile_targets('drain-terminal') is True
    target, = control.targets('drain-terminal')
    assert target['state'] == 'UNKNOWN' and target['terminal_fact_digest'] is None
