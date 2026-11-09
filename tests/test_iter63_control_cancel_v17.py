"""Synthetic DRAIN authorization against one actual journal; no provider I/O."""
from contextlib import contextmanager

import pytest
from bt_api_base.direct_cancel_protocol import PreparedCancelRequest
from bt_api_base.direct_write_protocol import NativeOrderIdentity
from bt_api_gateway.direct_cancel_journal import GatewayDirectCancelJournal
from bt_api_gateway.direct_command_journal import DirectCommandJournalError, GatewayDirectCommandJournal
from bt_api_gateway.direct_control import GatewayDirectControl
from bt_api_gateway.direct_control_cancel import authorize_control_cancel
from bt_api_gateway.direct_dispatch import _identity
from test_iter63_direct_parent_authority import owner as parent_owner  # noqa: F401
from test_iter63_direct_parent_authority import spec, kwargs, reserve, delegated, fence


@contextmanager
def admission():
    yield lambda: None


def test_parent_drain_operator_proof_marker_and_reopen(parent_owner, tmp_path):  # noqa: F811
    journal, guard, authority, _ = parent_owner
    authority.register_parent(spec(), **kwargs())
    order = reserve(journal, authority, 'child', '2')
    _, parent_permit = delegated(authority, 'child', '2', operation='direct.dispatch')
    identity = NativeOrderIdentity('ctp', 'native', {'trading_day': '20261109', 'front_id': 1}, 1)
    native = _identity(identity, 'ctp')
    args = (order.strategy_scope, order.request_key, order.reservation_id, order.digest, order.principal)
    started = journal.begin_dispatch(*args, order.version, native, ('native-key',), delegation_permit=parent_permit, delegation_fence=fence)
    journal.finish(*args, started.record.version, native, ('native-key',), 'SENT')
    journal.enable_account_facts_financial(guard)
    journal.enable_actor_stream(guard)
    journal.enable_strategy_origin(guard)
    journal.enable_control_cancel(guard)
    control = GatewayDirectControl(journal, guard)
    control.apply('manual-drain', 'DRAIN', scope_kind='strategy', scope_value='strategy', origin='operator')
    target, token = control.claim_target('manual-drain', order.reservation_id)
    assert token is not None
    active = [True]
    with journal._transaction() as db:
        permit = authorize_control_cancel(db, account='acct', journal_id=journal.journal_id, generation=journal.generation,
            cause_id='manual-drain', reservation_id=order.reservation_id, requester='operator-principal',
            source={'kind': 'operator', 'actor': 'operator', 'registration': 'reg', 'epoch': 'epoch', 'event_id': None},
            verify_current=lambda db, binding: active[0])
    cancel = GatewayDirectCancelJournal(journal)
    call = ('strategy', target['operation_id'], 'operator-principal', 'child', order.reservation_id, order.digest)
    options = dict(target_identity=identity, symbol='rb2601', target_principal='exec',
                   strategy_admission_fence=admission, control_cancel_permit=permit)
    attempt = cancel.request(*call, **options)
    assert attempt.principal == 'operator-principal' and attempt.target_principal == 'exec'
    assert cancel.request(*call, **options) == attempt
    prepared = PreparedCancelRequest('native-reservation', identity, 'rb2601', '20261109', 2, {'request_id': 12}, ('cancel-key',))
    active[0] = False
    with pytest.raises(DirectCommandJournalError, match='CONTROL_CANCEL_DENIED'):
        cancel.begin_dispatch('strategy', target['operation_id'], 'operator-principal', 1, prepared,
                              strategy_admission_fence=admission, control_cancel_permit=permit)
    assert cancel.get('strategy', target['operation_id'], 'operator-principal').status == 'REQUESTED'
    active[0] = True
    with pytest.raises(DirectCommandJournalError, match='CONTROL_CANCEL_DENIED'):
        cancel.begin_dispatch('strategy', target['operation_id'], 'operator-principal', 1, prepared,
                              strategy_admission_fence=admission)
    def revoke_at_marker():
        active[0] = False
    with pytest.raises(DirectCommandJournalError, match='CONTROL_CANCEL_DENIED'):
        cancel.begin_dispatch('strategy', target['operation_id'], 'operator-principal', 1, prepared,
                              strategy_admission_fence=admission, control_cancel_permit=permit,
                              before_dispatch=revoke_at_marker)
    assert cancel.get('strategy', target['operation_id'], 'operator-principal').status == 'REQUESTED'
    active[0] = True
    marker = cancel.begin_dispatch('strategy', target['operation_id'], 'operator-principal', 1, prepared,
                                   strategy_admission_fence=admission, control_cancel_permit=permit)
    assert marker.newly_started
    reopened = GatewayDirectCommandJournal(tmp_path / 'db', 'acct', generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=0, controls_enabled=True, strategy_ledger_enabled=True,
        account_extensions_enabled=True, parent_authority_enabled=True, account_facts_financial_enabled=True,
        actor_stream_enabled=True, strategy_origin_enabled=True, control_cancel_enabled=True)
    assert GatewayDirectCancelJournal(reopened).get('strategy', target['operation_id'], 'operator-principal').status == 'DISPATCHING'
    journal.enable_account_fact_recovery(guard)
    reopened18 = GatewayDirectCommandJournal(tmp_path / 'db', 'acct', generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=0, controls_enabled=True, strategy_ledger_enabled=True,
        account_extensions_enabled=True, parent_authority_enabled=True, account_facts_financial_enabled=True,
        actor_stream_enabled=True, strategy_origin_enabled=True, control_cancel_enabled=True,
        account_fact_recovery_enabled=True)
    assert GatewayDirectCancelJournal(reopened18).get('strategy', target['operation_id'], 'operator-principal').status == 'DISPATCHING'


def test_parent_drain_dispatches_once_under_current_operator_fence(parent_owner):  # noqa: F811
    from bt_api_base.direct_write_protocol import PreDispatchRecord, WriteOperation
    from bt_api_gateway.direct_cancel_dispatch import GatewayDirectCancelDispatcher
    from bt_api_gateway.direct_dispatch import GatewayDirectDispatcher, NativeDispatchOutcome

    journal, guard, authority, _ = parent_owner
    authority.register_parent(spec(), **kwargs())
    order = reserve(journal, authority, 'child', '2')
    _, auth = delegated(authority, 'child', '2', operation='direct.dispatch')
    identity = NativeOrderIdentity('ctp', 'native', {'trading_day': '20261109', 'front_id': 1}, 1)
    mapping = _identity(identity, 'ctp')
    args = (order.strategy_scope, order.request_key, order.reservation_id, order.digest, order.principal)
    begun = journal.begin_dispatch(*args, order.version, mapping, ('native-key',), delegation_permit=auth, delegation_fence=fence)
    journal.finish(*args, begun.record.version, mapping, ('native-key',), 'SENT')
    journal.enable_account_facts_financial(guard)
    journal.enable_actor_stream(guard)
    journal.enable_strategy_origin(guard)
    journal.enable_control_cancel(guard)
    control = GatewayDirectControl(journal, guard)
    control.apply('drain', 'DRAIN', scope_kind='strategy', scope_value='strategy', origin='operator')
    claimed, token = control.claim_target('drain', order.reservation_id)
    calls = []
    @contextmanager
    def operator_fence(_record):
        yield lambda: None
    def native_cancel(target, symbol, port, scope):
        prepared = PreparedCancelRequest('provider-reservation', target, symbol, '20261109', 2,
                                         {'request_id': 12}, ('cancel-key',))
        marker = port.commit(PreDispatchRecord(WriteOperation.CANCEL, scope, 'ctp', symbol,
            None, target, {}, prepared.trading_day, prepared.session_generation, 'synthetic', prepared))
        calls.append(marker)
        return NativeDispatchOutcome(True, target, marker)
    direct = GatewayDirectDispatcher(journal, 'ctp', guard, lambda *_: None, lambda _: (), lambda _: True)
    cancel = GatewayDirectCancelDispatcher(GatewayDirectCancelJournal(journal), direct, guard, 'ctp', native_cancel, lambda _: True)
    result = control.dispatch_claimed_cancel(claimed, cancel, token, request_fence=operator_fence,
        requester='operator-principal', authority_source={'kind': 'operator', 'actor': 'operator',
        'registration': 'reg', 'epoch': 'epoch', 'event_id': None})
    assert (result.status, result.principal, result.target_principal) == ('SENT', 'operator-principal', 'exec')
    assert calls == [result.attempt_id]
    assert control.claim_target('drain', order.reservation_id)[1] is None
