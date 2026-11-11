"""Child orders of an Execution parent through the Gateway dispatcher (63.13 base).

Real account journal, guard and parent authority; the claim port is the
synthetic one of these package tests and the native call is a synthetic
function. UNIT/FAKE evidence only: no provider, no venue, no account.
"""
from contextlib import contextmanager
from decimal import Decimal
from types import SimpleNamespace

import pytest
from bt_api_base.direct_write_protocol import NativeOrderIdentity, PreDispatchRecord, WriteOperation
from bt_api_base.gateway_delegation_protocol import GatewayDelegatedCommand
from bt_api_base.gateway_direct_protocol import gateway_payload_digest
from bt_api_base.market_protocol import MarketInstrumentKey
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope
from bt_api_py._contracts.models import OrderRequest, OrderType, Side
from iter63_claim_support import SyntheticClaimPort

from bt_api_gateway import direct_dispatch
from bt_api_gateway.direct_command_journal import GatewayDirectCommandJournal
from bt_api_gateway.direct_delegation import (
    GatewayDelegateGrant,
    GatewayDelegationDenied,
    authorize_delegated_command,
)
from bt_api_gateway.direct_dispatch import (
    DirectDispatchError,
    GatewayDirectDispatcher,
    NativeDispatchOutcome,
)
from bt_api_gateway.direct_parent_authority import GatewayParentAuthority
from bt_api_gateway.session_guard import LocalAccountSessionGuard

DAY = '20300101'
KEY = MarketInstrumentKey('ctp', 'SHFE', 'simnow', 'future', 'rb2601', 'rb2601')
IDENTITY = WireIdentity(WireRole.SERVICE, 'exec', 'actor')
SCOPE = WireScope('domain', account_ref='acct', strategy_ref='strategy', run_id='run')
OPERATIONS = frozenset({'direct.reserve', 'direct.dispatch', 'direct.release'})


@contextmanager
def _open():
    yield


def _spec(**changes):
    return {'account_scope': 'acct', 'strategy_scope': 'strategy', 'parent_ref': 'parent',
            'registration_operation_id': 'register', 'execution_domain_ref': 'domain',
            'instrument': KEY.to_dict(), 'quantity': '5', 'quantity_unit': 'lots', 'side': 'buy',
            'offset': 'open', 'limit_price': '100', 'creation_trading_day': DAY,
            'allowed_trading_days': [DAY], 'expires_at_ns': 10_000, 'grant_revision': 'v1',
            'target_position_ref': None, 'plan_digest': 'a' * 64, 'plan_version': 'v1',
            'time_in_force': 'DAY', **changes}


class Native:
    """Synthetic provider path: commit, then the native fence, then one send."""

    def __init__(self):
        self.sends = []
        self.before_commit = lambda: None
        self.before_send = lambda: None
        self.after_send = lambda: None

    def __call__(self, payload, port, account):
        self.before_commit()
        identity = NativeOrderIdentity('CTP', payload['client_order_id'], {'trading_day': DAY}, 1)
        try:
            marker = port.commit(PreDispatchRecord(WriteOperation.PLACE, account, 'CTP', payload['symbol'],
                                                   identity, None, payload, DAY, 1, 'synthetic'))
        except Exception:
            marker = None  # as the SDK coordinator: a refused commit sends nothing
        if marker is None:
            return NativeDispatchOutcome(False, identity, None, 'pre_dispatch_commit_failed')
        with port.native_fence() as check:
            # Inside the fence models the provider holding its session lock.
            try:
                self.before_send()
                check()
                self.sends.append(payload['client_order_id'])
            finally:
                self.after_send()
        return NativeDispatchOutcome(True, identity, marker)


@pytest.fixture
def case(tmp_path):
    directory = tmp_path / 'guard'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'acct', 'owner')
    journal = GatewayDirectCommandJournal.create(tmp_path / 'db', 'acct', generation=guard.acquire())
    journal.enable_controls(guard)
    journal.enable_strategy_ledger(guard)
    journal.enable_account_extensions(guard)
    journal.enable_parent_authority(guard)
    state = {'day': DAY, 'now': 100, 'lease': True}
    authority = GatewayParentAuthority(journal, guard, now_ns=lambda: state['now'],
        trading_day=lambda: state['day'], transfer_completed=lambda _db, _spec: '0')
    grant = GatewayDelegateGrant(IDENTITY, 'acct', 'strategy', 'domain', 'execution', 'v1',
                                 frozenset({KEY}), OPERATIONS)
    state['grant'] = grant
    native, port = Native(), SyntheticClaimPort()
    dispatcher = GatewayDirectDispatcher(journal, 'CTP', guard, native,
        lambda identity: ('native-' + identity.client_order_id,), lambda _row: True, claim_port=port)
    value = SimpleNamespace(journal=journal, guard=guard, state=state, authority=authority, grant=grant,
                            native=native, port=port, dispatcher=dispatcher, parent_recheck=authority.recheck_child)
    yield value
    guard.release()


def _permit(case, child, operation):
    payload = OrderRequest(symbol='rb2601', side=Side.BUY, order_type=OrderType.LIMIT, quantity=Decimal('1'),
        account_id='acct', client_order_id=child, price=Decimal('100'), idempotency_key=child,
        quantity_unit='lots', offset='open', exchange_id='SHFE').to_dict()
    command = GatewayDelegatedCommand('acct', 'strategy', 'domain', 'exec', 'actor', 'execution', 'run', child,
                                      gateway_payload_digest(payload), KEY, 'v1', 'parent', child)
    ctx = SimpleNamespace(identity=IDENTITY, scope=SCOPE, principal_ref='exec', registration_id='reg')
    state = case.state
    permit = authorize_delegated_command(ctx, case.grant, command, operation, payload,
        registry_recheck=lambda _ctx: state['lease'], current_grant=lambda: state['grant'],
        instrument_recheck=lambda value: value == KEY,
        parent_recheck=lambda db, cmd, order: case.parent_recheck(db, cmd, order))
    return payload, permit


def _register(case):
    return case.authority.register_parent(_spec(), principal='exec', actor_ref='actor', fence=_open,
                                          recheck=lambda: True)


def _freeze(case):
    return case.authority.cancel_parent('acct', 'strategy', 'parent', 'register', 'freeze', 1,
                                        principal='exec', actor_ref='actor', fence=_open, recheck=lambda: True)


def _reserve(case, child='child-1'):
    payload, permit = _permit(case, child, 'direct.reserve')
    return case.journal.reserve('strategy', child, 'exec', payload, reservation_fence=_open,
                                delegation_permit=permit)


def _fence(state):
    @contextmanager
    def fence(_row):
        if not state['lease']:
            raise RuntimeError('LEASE_EXPIRED')

        def recheck():
            if not state['lease']:
                raise RuntimeError('LEASE_EXPIRED')
        yield recheck
    return fence


def _dispatch(case, row):
    _, permit = _permit(case, row.request_key, 'direct.dispatch')
    return case.dispatcher.dispatch(row.strategy_scope, row.request_key, row.principal, row.reservation_id,
                                    row.digest, row.version, request_fence=_fence(case.state),
                                    delegation_permit=permit)


def _at_claim_validation(case, action):
    """Run ``action`` after the dispatch entry checks, right before the claim validation."""
    original = case.port.claim_native

    def claim_native(record, identity, validate):
        action()
        return original(record, identity, validate)
    case.port.claim_native = claim_native


def test_parent_child_is_sent_once_through_the_claim(case):
    _register(case)
    row = _reserve(case)
    result = _dispatch(case, row)
    assert result.status == 'SENT' and case.native.sends == ['child-1']
    assert (case.port.claims, case.port.retired) == (1, 1)
    # The marker left RESERVED: a second dispatch of the same child only observes.
    again = _dispatch(case, row)
    assert again.status == 'SENT' and case.native.sends == ['child-1'] and case.port.claims == 1
    assert case.authority.query_parent('acct', 'strategy', 'parent', 'register', principal='exec',
        actor_ref='actor', fence=_open, recheck=lambda: True)['state'] == 'ACTIVE'


@pytest.mark.parametrize('change', ['frozen', 'expired', 'other_day', 'lease', 'grant'])
def test_parent_or_authority_change_before_the_claim_is_refused_without_a_marker(case, change):
    _register(case)
    row = _reserve(case)

    def apply():
        if change == 'frozen':
            _freeze(case)
        elif change == 'expired':
            case.state['now'] = 10_000
        elif change == 'other_day':
            case.state['day'] = '20300102'
        elif change == 'lease':
            case.state['lease'] = False
        else:
            case.state['grant'] = GatewayDelegateGrant(IDENTITY, 'acct', 'strategy', 'domain', 'execution',
                                                       'v2', frozenset({KEY}), OPERATIONS)
    _at_claim_validation(case, apply)
    expected = 'DISPATCH_CLAIM_UNAVAILABLE' if change == 'lease' else 'DELEGATION_DENIED'
    with pytest.raises(DirectDispatchError, match=expected):
        _dispatch(case, row)
    current = case.journal.get('strategy', 'child-1', 'exec')
    assert current.status == 'RESERVED' and current.version == row.version
    assert current.native_identity_json is None and case.native.sends == [] and case.port.claims == 0


@pytest.mark.parametrize('change', ['frozen', 'expired', 'grant'])
def test_change_after_the_claim_is_refused_by_the_marker_transaction(case, change):
    _register(case)
    row = _reserve(case)

    def apply():
        if change == 'frozen':
            _freeze(case)
        elif change == 'expired':
            case.state['now'] = 10_000
        else:
            case.state['grant'] = GatewayDelegateGrant(IDENTITY, 'acct', 'strategy', 'domain', 'execution',
                                                       'v2', frozenset({KEY}), OPERATIONS)
    case.native.before_commit = apply
    with pytest.raises(DirectDispatchError, match='PRE_DISPATCH_FAILED'):
        _dispatch(case, row)
    current = case.journal.get('strategy', 'child-1', 'exec')
    assert current.status == 'RESERVED' and current.native_identity_json is None
    assert case.native.sends == [] and case.port.claims == 1 and case.port.retired == 1


def test_frozen_parent_is_refused_at_the_dispatch_entry(case):
    _register(case)
    row = _reserve(case)
    _freeze(case)
    with pytest.raises(GatewayDelegationDenied):
        _dispatch(case, row)
    assert case.journal.get('strategy', 'child-1', 'exec').status == 'RESERVED'
    assert case.native.sends == [] and case.port.claims == 0


def test_parent_read_in_the_claim_validation_is_read_only(case):
    """A parent check that tries to write is refused in the claim validation (fail closed)."""
    _register(case)
    row = _reserve(case)
    original = case.authority.recheck_child

    def writing_recheck(db, command, payload):
        db.execute("UPDATE direct_execution_parents SET version=version")
        return original(db, command, payload)
    case.parent_recheck = writing_recheck
    with pytest.raises(DirectDispatchError, match='DELEGATION_DENIED'):
        _dispatch(case, row)
    assert case.journal.get('strategy', 'child-1', 'exec').status == 'RESERVED'
    assert case.native.sends == [] and case.port.claims == 0


def test_parent_is_read_before_the_claim_and_never_inside_the_native_fence(case, monkeypatch):
    _register(case)
    row = _reserve(case)
    events = []
    original_snapshot = direct_dispatch._read_only_snapshot

    @contextmanager
    def recording_snapshot(journal):
        events.append('parent-snapshot')
        with original_snapshot(journal) as db:
            yield db

    def forbidden_connection(*args, **kwargs):
        events.append('journal-in-native')
        raise AssertionError('journal opened inside the native fence')

    def enter_native():
        events.append('native')
        case.journal._connection = forbidden_connection

    original_claim = case.port.claim_native

    def claim_native(record, identity, validate):
        claim = original_claim(record, identity, validate)
        events.append('claim')
        return claim
    case.port.claim_native = claim_native
    monkeypatch.setattr(direct_dispatch, '_read_only_snapshot', recording_snapshot)
    case.native.before_send = enter_native
    case.native.after_send = lambda: vars(case.journal).pop('_connection', None)
    result = _dispatch(case, row)
    assert result.status == 'SENT' and case.native.sends == ['child-1']
    assert events == ['parent-snapshot', 'claim', 'native']


def test_crash_inside_the_parent_read_leaves_the_child_reserved_and_dispatchable_once(case):
    class Crash(BaseException):
        pass

    _register(case)
    row = _reserve(case)
    armed = []
    original = case.authority.recheck_child

    def crashing_recheck(db, command, payload):
        if armed:
            raise Crash()
        return original(db, command, payload)
    case.parent_recheck = crashing_recheck
    _at_claim_validation(case, lambda: armed.append(True))
    with pytest.raises(Crash):
        _dispatch(case, row)
    current = case.journal.get('strategy', 'child-1', 'exec')
    assert current.status == 'RESERVED' and current.version == row.version
    assert current.native_identity_json is None and case.native.sends == [] and case.port.claims == 0
    # Same process after the fault: the same child is sent exactly once.
    case.parent_recheck = original
    del case.port.claim_native
    assert _dispatch(case, row).status == 'SENT' and case.native.sends == ['child-1']


def test_same_day_only_refuses_cross_day_parents_and_their_later_children(case):
    from bt_api_gateway.direct_parent_authority import GatewayParentError

    state = case.state
    with pytest.raises(GatewayParentError, match='INVALID_AUTHORITY'):
        GatewayParentAuthority(case.journal, case.guard, now_ns=lambda: 1, trading_day=lambda: DAY,
                               same_day_only='yes')
    strict = GatewayParentAuthority(case.journal, case.guard, now_ns=lambda: state['now'],
        trading_day=lambda: state['day'], transfer_completed=lambda _db, _spec: '0', same_day_only=True)
    two_days = _spec(allowed_trading_days=[DAY, '20300102'], time_in_force='GTD')
    with pytest.raises(GatewayParentError, match='CROSS_DAY_UNAVAILABLE'):
        strict.register_parent(two_days, principal='exec', actor_ref='actor', fence=_open, recheck=lambda: True)
    # A two-day parent written earlier by a lenient authority (another composition) stays
    # in the journal; a strict authority admits its children on the creation day only.
    case.authority.register_parent(two_days, principal='exec', actor_ref='actor', fence=_open,
                                   recheck=lambda: True)
    _reserve(case)
    payload, permit = _permit(case, 'child-1', 'direct.dispatch')
    with case.journal._transaction() as db:
        assert strict.recheck_child(db, permit.command, payload) is True
    state['day'] = '20300102'
    with case.journal._transaction() as db:
        assert case.authority.recheck_child(db, permit.command, payload) is True
        assert strict.recheck_child(db, permit.command, payload) is False
