"""Synthetic checks against the actual account journal; no provider I/O."""
from contextlib import contextmanager
from decimal import Decimal
import sqlite3
from types import SimpleNamespace

import pytest

from bt_api_base.gateway_delegation_protocol import GatewayDelegatedCommand
from bt_api_base.gateway_direct_protocol import gateway_payload_digest
from bt_api_base.direct_write_protocol import NativeOrderIdentity
from bt_api_base.market_protocol import MarketInstrumentKey
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope
from bt_api_gateway.direct_command_journal import DirectCommandJournalError, GatewayDirectCommandJournal
from bt_api_gateway.direct_cancel_journal import GatewayDirectCancelJournal
from bt_api_gateway.direct_delegation import GatewayDelegateGrant, GatewayDelegationDenied, authorize_delegated_command
from bt_api_gateway.direct_dispatch import _identity
from bt_api_gateway.direct_parent_authority import GatewayParentAuthority, GatewayParentError
from bt_api_gateway.session_guard import LocalAccountSessionGuard
from bt_api_py._contracts.models import OrderRequest, Side, OrderType
from bt_api_py.gateway_order_contract import decode_gateway_order_request

KEY = MarketInstrumentKey('ctp', 'SHFE', 'simnow', 'future', 'rb2601', 'rb2601')
IDENTITY = WireIdentity(WireRole.SERVICE, 'exec', 'actor')
SCOPE = WireScope('domain', account_ref='acct', strategy_ref='strategy', run_id='run')


@contextmanager
def fence():
    yield


def spec():
    return dict(account_scope='acct', strategy_scope='strategy', parent_ref='parent',
        registration_operation_id='register', execution_domain_ref='domain', instrument=KEY.to_dict(),
        quantity='10', quantity_unit='lots', side='buy', offset='open', limit_price='100',
        creation_trading_day='20261109', allowed_trading_days=['20261109', '20261110'],
        expires_at_ns=1000, grant_revision='v1', target_position_ref=None,
        plan_digest='a' * 64, plan_version='v1', time_in_force='GTD')


@pytest.fixture
def owner(tmp_path):
    directory = tmp_path / 'guard'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'acct', 'owner')
    generation = guard.acquire()
    journal = GatewayDirectCommandJournal.create(tmp_path / 'db', 'acct', generation=generation)
    journal.enable_controls(guard)
    journal.enable_strategy_ledger(guard)
    journal.enable_account_extensions(guard)
    journal.enable_parent_authority(guard)
    state = {'day': '20261109', 'now': 100}
    authority = GatewayParentAuthority(journal, guard, now_ns=lambda: state['now'],
        trading_day=lambda: state['day'], transfer_completed=lambda db, spec: '0')
    yield journal, guard, authority, state
    guard.release()


def kwargs():
    return dict(principal='exec', actor_ref='actor', fence=fence, recheck=lambda: True)


def delegated(authority, child, qty, operation='direct.reserve', **payload_changes):
    payload = OrderRequest(symbol='rb2601', side=Side.BUY, order_type=OrderType.LIMIT,
        quantity=Decimal(qty), account_id='acct', client_order_id=child, price=Decimal('100'),
        idempotency_key=child, quantity_unit='lots', offset='open', exchange_id='SHFE').to_dict()
    payload.update(payload_changes)
    decode_gateway_order_request(payload, 'acct')
    cmd = GatewayDelegatedCommand('acct', 'strategy', 'domain', 'exec', 'actor',
        'execution', 'run', child, gateway_payload_digest(payload), KEY, 'v1', 'parent', child)
    grant = GatewayDelegateGrant(IDENTITY, 'acct', 'strategy', 'domain', 'execution', 'v1',
        frozenset({KEY}), frozenset({'direct.reserve', 'direct.dispatch', 'direct.release'}))
    ctx = SimpleNamespace(identity=IDENTITY, scope=SCOPE, principal_ref='exec', registration_id='reg')
    permit = authorize_delegated_command(ctx, grant, cmd, operation, payload,
        registry_recheck=lambda _: True, current_grant=lambda: grant, instrument_recheck=lambda _: True,
        parent_recheck=authority.recheck_child)
    return payload, permit


def reserve(journal, authority, child, qty, **payload_changes):
    payload, permit = delegated(authority, child, qty, **payload_changes)
    return journal.reserve('strategy', child, 'exec', payload, reservation_fence=fence, delegation_permit=permit)


def test_parent_original_keys_cancel_and_reopen(owner, tmp_path):
    journal, _, authority, state = owner
    first = authority.register_parent(spec(), **kwargs())
    assert first['state'] == 'ACTIVE' and first['version'] == 1
    assert authority.register_parent(spec(), **kwargs()) == first
    with pytest.raises(GatewayParentError, match='REQUEST_CONFLICT'):
        authority.register_parent(dict(spec(), quantity='11'), **kwargs())
    assert authority.query_operation('acct', 'strategy', 'parent', 'register', **kwargs())['result'] == first
    cancel = authority.cancel_parent('acct', 'strategy', 'parent', 'register', 'cancel', 1, **kwargs())
    assert cancel['state'] == 'CANCEL_REQUESTED' and cancel['version'] == 2
    assert authority.cancel_parent('acct', 'strategy', 'parent', 'register', 'cancel', 1, **kwargs()) == cancel
    assert authority.query_operation('acct', 'strategy', 'parent', 'cancel', **kwargs())['result'] == cancel
    with pytest.raises(GatewayDelegationDenied):
        reserve(journal, authority, 'after-cancel', '1')
    reopened = GatewayDirectCommandJournal(tmp_path / 'db', 'acct', generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=0, controls_enabled=True,
        strategy_ledger_enabled=True, account_extensions_enabled=True, parent_authority_enabled=True)
    assert reopened.journal_id == journal.journal_id


def test_transaction_capacity_idempotence_and_cross_day(owner):
    journal, _, authority, state = owner
    authority.register_parent(spec(), **kwargs())
    first = reserve(journal, authority, 'one', '6')
    assert reserve(journal, authority, 'one', '6') == first
    _, permit = delegated(authority, 'one', '6', operation='direct.dispatch')
    args = (first.strategy_scope, first.request_key, first.reservation_id, first.digest, first.principal)
    started = journal.begin_dispatch(*args, first.version, {'ref': 'native'}, ('native',),
                                     delegation_permit=permit, delegation_fence=fence)
    journal.finish(*args, started.record.version, {'ref': 'native'}, ('native',), 'UNKNOWN')
    state['day'] = '20261110'
    with pytest.raises(GatewayDelegationDenied):
        reserve(journal, authority, 'too-large', '5')
    with pytest.raises(DirectCommandJournalError, match='NOT_FOUND'):
        journal.get('strategy', 'too-large', 'exec')
    payload, remaining_permit = delegated(authority, 'two', '4')
    with journal._transaction() as db:
        assert authority.recheck_child(db, remaining_permit.command, payload)
    # The independent UNKNOWN scope fence may conservatively block even the
    # remaining capacity until it can establish instrument independence.
    with pytest.raises(DirectCommandJournalError, match='UNKNOWN_SCOPE_UNAVAILABLE'):
        reserve(journal, authority, 'two', '4')
    state['now'] = 1000
    assert authority.query_parent('acct', 'strategy', 'parent', 'register', **kwargs())['state'] == 'EXPIRED'
    with pytest.raises(GatewayDelegationDenied):
        reserve(journal, authority, 'expired', '1')


def test_missing_transfer_source_and_price_reject(owner):
    journal, guard, authority, state = owner
    authority.register_parent(spec(), **kwargs())
    no_source = GatewayParentAuthority(journal, guard, now_ns=lambda: 100, trading_day=lambda: state['day'])
    with pytest.raises(GatewayDelegationDenied):
        reserve(journal, no_source, 'no-source', '1')
    with pytest.raises(GatewayDelegationDenied):
        reserve(journal, authority, 'over-price', '1', price='101')


def test_acl_recheck_failure_rolls_back(owner):
    _, _, authority, _ = owner
    calls = []
    def check():
        calls.append(1)
        return len(calls) == 1
    with pytest.raises(GatewayParentError, match='AUTHORITY_UNAVAILABLE'):
        authority.register_parent(spec(), principal='exec', actor_ref='actor', fence=fence, recheck=check)
    with pytest.raises(GatewayParentError, match='NOT_FOUND'):
        authority.query_operation('acct', 'strategy', 'parent', 'register', **kwargs())


def test_rollover_requires_trusted_original_target_and_mapping(owner, monkeypatch, tmp_path):
    journal, guard, authority, state = owner
    original = dict(spec(), offset='close_today', target_position_ref='original-position')
    authority.register_parent(original, **kwargs())
    state['day'] = '20261110'
    payload, permit = delegated(authority, 'close-one', '3', offset='close_yesterday',
                                position_id='original-position')
    with journal._transaction() as db:
        assert authority.recheck_child(db, permit.command, payload) is False
    mapping = {'version': 'map-v1', 'real_close': '3'}
    def verified_target(db, parent, command, child, trading_day):
        return (parent['target_position_ref'] == 'original-position'
                and child['position_id'] == 'original-position')
    def verified_mapping(db, parent, command, child, trading_day):
        return dict(account_scope='acct', strategy_scope='strategy', parent_ref='parent',
            child_id=command.child_id, target_position_ref='original-position',
            position_id=child['position_id'], source_trading_day='20261109', trading_day=trading_day,
            source_bucket='today', target_bucket='yesterday', provider_rule_ref='rule',
            provider_rule_version='rule-v1', observation_ref='snapshot', observation_source_ref='provider',
            observation_account_scope='acct', observation_trading_day=trading_day,
            observation_session_ref='session', mapping_version=mapping['version'],
            quantity=child['quantity'], real_close_available=mapping['real_close'],
            observed_at_ns=50, valid_until_ns=900)
    trusted = GatewayParentAuthority(journal, guard, now_ns=lambda: state['now'],
        trading_day=lambda: state['day'], transfer_completed=lambda db, parent: '0',
        target_recheck=verified_target, rollover_recheck=verified_mapping)
    # This synthetic test supplies the strategy-capacity proof separately; it
    # tests journal/evidence atomicity, not provider or strategy-ledger truth.
    monkeypatch.setattr(journal, '_check_strategy_capacity', lambda *args, **kwargs: None)
    first = reserve(journal, trusted, 'close-one', '3', offset='close_yesterday', position_id='original-position')
    with journal._transaction() as db:
        row = db.execute('SELECT evidence_json,evidence_digest FROM direct_execution_rollover_evidence').fetchone()
        assert 'map-v1' in row['evidence_json'] and len(row['evidence_digest']) == 64
    reopened = GatewayDirectCommandJournal(tmp_path / 'db', 'acct', generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=0, controls_enabled=True,
        strategy_ledger_enabled=True, account_extensions_enabled=True, parent_authority_enabled=True)
    assert reopened.get('strategy', 'close-one', 'exec') == first
    mapping['version'] = 'unknown'
    with pytest.raises(GatewayDelegationDenied):
        reserve(journal, trusted, 'close-one', '3', offset='close_yesterday', position_id='original-position')
    with pytest.raises(GatewayDelegationDenied):
        reserve(journal, trusted, 'wrong-target', '1', offset='close_yesterday', position_id='new-position')
    with sqlite3.connect(tmp_path / 'db') as db:
        db.execute("UPDATE direct_execution_rollover_evidence SET evidence_digest=?", ('0' * 64,))
    with pytest.raises(DirectCommandJournalError, match='INVALID_DATABASE'):
        GatewayDirectCommandJournal(tmp_path / 'db', 'acct', generation=journal.generation,
            expected_journal_id=journal.journal_id, minimum_revision=0, controls_enabled=True,
            strategy_ledger_enabled=True, account_extensions_enabled=True, parent_authority_enabled=True)
    with sqlite3.connect(tmp_path / 'db') as db:
        db.execute('DELETE FROM direct_execution_rollover_evidence')
    with pytest.raises(DirectCommandJournalError, match='INVALID_DATABASE'):
        GatewayDirectCommandJournal(tmp_path / 'db', 'acct', generation=journal.generation,
            expected_journal_id=journal.journal_id, minimum_revision=0, controls_enabled=True,
            strategy_ledger_enabled=True, account_extensions_enabled=True, parent_authority_enabled=True)


def test_transfer_completion_occupies_parent_quantity(owner):
    journal, guard, authority, state = owner
    authority.register_parent(spec(), **kwargs())
    trusted = GatewayParentAuthority(journal, guard, now_ns=lambda: state['now'],
        trading_day=lambda: state['day'], transfer_completed=lambda db, parent: '4')
    reserve(journal, trusted, 'six', '6')
    with pytest.raises(GatewayDelegationDenied):
        reserve(journal, trusted, 'excess', '1')


def test_post_insert_capacity_recheck_rolls_back_reservation(owner):
    journal, guard, authority, state = owner
    authority.register_parent(spec(), **kwargs())
    calls = []
    def changing_transfer(db, parent):
        calls.append(True)
        return '0' if len(calls) == 1 else '10'
    trusted = GatewayParentAuthority(journal, guard, now_ns=lambda: state['now'],
        trading_day=lambda: state['day'], transfer_completed=changing_transfer)
    with pytest.raises(GatewayDelegationDenied):
        reserve(journal, trusted, 'rollback', '1')
    with pytest.raises(DirectCommandJournalError, match='NOT_FOUND'):
        journal.get('strategy', 'rollback', 'exec')


def test_cancel_freezes_only_parent_children_with_stable_original_identities(owner, tmp_path):
    journal, _, authority, _ = owner
    authority.register_parent(spec(), **kwargs())
    sent = reserve(journal, authority, 'sent', '4')
    reserved = reserve(journal, authority, 'reserved', '3')
    confirmed = reserve(journal, authority, 'confirmed', '2')
    # A normal strategy's separate command must not be captured.
    journal.reserve('strategy', 'unrelated', 'other', {'symbol': 'rb2601', 'offset': 'open'})
    _, confirmed_permit = delegated(authority, 'confirmed', '2', operation='direct.dispatch')
    confirmed_args = (confirmed.strategy_scope, confirmed.request_key, confirmed.reservation_id,
                      confirmed.digest, confirmed.principal)
    native_confirmed = NativeOrderIdentity('ctp', 'native-confirmed', {'trading_day': '20261109', 'front_id': 1}, 1)
    native_mapping = _identity(native_confirmed, 'ctp')
    started_confirmed = journal.begin_dispatch(*confirmed_args, confirmed.version,
        native_mapping, ('native-confirmed',), delegation_permit=confirmed_permit, delegation_fence=fence)
    journal.finish(*confirmed_args, started_confirmed.record.version,
                   native_mapping, ('native-confirmed',), 'SENT')
    _, permit = delegated(authority, 'sent', '4', operation='direct.dispatch')
    args = (sent.strategy_scope, sent.request_key, sent.reservation_id, sent.digest, sent.principal)
    started = journal.begin_dispatch(*args, sent.version, {'ref': 'native'}, ('native',),
                                     delegation_permit=permit, delegation_fence=fence)
    journal.finish(*args, started.record.version, {'ref': 'native'}, ('native',), 'UNKNOWN')
    result = authority.cancel_parent('acct', 'strategy', 'parent', 'register', 'cancel', 1, **kwargs())
    targets = {item['child_id']: item for item in result['targets']}
    assert set(targets) == {'sent', 'reserved', 'confirmed'}
    assert targets['sent']['phase'] == 'CANCEL_PENDING'
    assert targets['sent']['reservation_id'] == sent.reservation_id
    assert targets['sent']['payload_digest'] == sent.digest
    assert targets['sent']['native_identity'] == {'ref': 'native'}
    assert targets['reserved']['phase'] == 'RELEASE_PENDING'
    assert targets['reserved']['reservation_id'] == reserved.reservation_id
    assert targets['reserved']['native_identity'] is None
    with journal._transaction() as db:
        assert not authority.check_cancel_target(db, permit.command, targets['sent']['cancel_operation_id'], sent.reservation_id, sent.digest)
        assert authority.check_cancel_target(db, confirmed_permit.command, targets['confirmed']['cancel_operation_id'], confirmed.reservation_id, confirmed.digest)
        assert not authority.check_cancel_target(db, confirmed_permit.command, 'wrong-operation', confirmed.reservation_id, confirmed.digest)
    cancel_journal = GatewayDirectCancelJournal(journal)
    cancel_args = ('strategy', targets['confirmed']['cancel_operation_id'], 'exec', 'confirmed',
                   confirmed.reservation_id, confirmed.digest)
    attempt = cancel_journal.request(*cancel_args, target_identity=native_confirmed, symbol='rb2601',
        parent_command=confirmed_permit.command, parent_cancel_recheck=authority.check_cancel_target)
    assert attempt.status == 'REQUESTED'
    assert cancel_journal.request(*cancel_args, target_identity=native_confirmed, symbol='rb2601',
        parent_command=confirmed_permit.command, parent_cancel_recheck=authority.check_cancel_target) == attempt
    with pytest.raises(DirectCommandJournalError, match='PARENT_CANCEL_DENIED'):
        cancel_journal.request('strategy', 'wrong-operation', 'exec', 'confirmed', confirmed.reservation_id,
            confirmed.digest, target_identity=native_confirmed, symbol='rb2601',
            parent_command=confirmed_permit.command, parent_cancel_recheck=authority.check_cancel_target)
    with pytest.raises(DirectCommandJournalError, match='PARENT_CANCEL_DENIED'):
        cancel_journal.request('strategy', targets['sent']['cancel_operation_id'], 'exec', 'sent', sent.reservation_id,
            sent.digest, target_identity=native_confirmed, symbol='rb2601',
            parent_command=permit.command, parent_cancel_recheck=authority.check_cancel_target)
    _, release_permit = delegated(authority, 'reserved', '3', operation='direct.release')
    release_args = (reserved.strategy_scope, reserved.request_key, reserved.reservation_id,
                    reserved.digest, reserved.principal)
    with pytest.raises(DirectCommandJournalError, match='PARENT_RELEASE_DENIED'):
        journal.release(*release_args, 'not-the-frozen-operation', reserved.version,
            delegation_permit=release_permit, delegation_fence=fence,
            release_target_recheck=authority.check_release_target)
    released = journal.release(*release_args, targets['reserved']['cancel_operation_id'], reserved.version,
        delegation_permit=release_permit, delegation_fence=fence,
        release_target_recheck=authority.check_release_target)
    assert released.status == 'RELEASED'
    assert journal.release(*release_args, targets['reserved']['cancel_operation_id'], reserved.version,
        delegation_permit=release_permit, delegation_fence=fence,
        release_target_recheck=authority.check_release_target) == released
    assert authority.query_operation('acct', 'strategy', 'parent', 'cancel', **kwargs())['result'] == result
    assert authority.cancel_parent('acct', 'strategy', 'parent', 'register', 'cancel', 1, **kwargs()) == result
    reopened = GatewayDirectCommandJournal(tmp_path / 'db', 'acct', generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=0, controls_enabled=True,
        strategy_ledger_enabled=True, account_extensions_enabled=True, parent_authority_enabled=True)
    assert reopened.get('strategy', 'sent', 'exec').status == 'UNKNOWN'
