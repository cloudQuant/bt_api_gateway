"""Contract STOP_NEW and DRAIN (G64-01) and cancel-only operations (G64-04) on one real journal.

Synthetic owner thread, provider callbacks and returns; no CTP, account or network.
"""
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from bt_api_base.direct_cancel_protocol import PreparedCancelRequest
from bt_api_base.direct_write_protocol import (
    DirectExecutionEventKind,
    DirectOrderStatus,
    NativeOrderIdentity,
    PreDispatchRecord,
    WriteOperation,
)
from bt_api_base.gateway_execution_protocol import GatewayReturnFact
from bt_api_base.market_protocol import MarketInstrumentKey

from bt_api_gateway.direct_cancel_dispatch import GatewayDirectCancelDispatcher
from bt_api_gateway.direct_cancel_journal import GatewayDirectCancelJournal
from bt_api_gateway.direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
)
from bt_api_gateway.direct_control import cancel_scope_cause_id
from bt_api_gateway.direct_dispatch import GatewayDirectDispatcher, NativeDispatchOutcome, _identity
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from bt_api_gateway.session_guard import LocalAccountSessionGuard
from bt_api_gateway.strategy_position_ledger import (
    StrategyBaselineEvidence,
    StrategyInstrumentBinding,
)

RB = {'symbol': 'rb2701', 'exchange_id': 'SHFE'}
HC = {'symbol': 'hc2701', 'exchange_id': 'SHFE'}
SCOPE = 'SHFE:rb2701'
KEY = MarketInstrumentKey('ctp', 'SHFE', 'simnow', 'future', 'rb2701', 'rb2701')
BINDING = StrategyInstrumentBinding(KEY, 'ctp', 'lots', True)
DAY = '20300101'
SOURCE = {'kind': 'operator', 'actor': 'risk', 'registration': 'reg', 'epoch': 'epoch', 'event_id': None}


def _order(payload, offset, quantity='1'):
    return dict(payload, side='buy' if offset == 'open' else 'sell', offset=offset, quantity=quantity,
                quantity_unit='lots')


@pytest.fixture
def site(tmp_path):
    directory = tmp_path / 'guards'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'acct', 'owner')
    journal = GatewayDirectCommandJournal.create(tmp_path / 'db', 'acct', generation=guard.acquire())
    control = journal.enable_controls(guard)
    yield journal, control, guard, tmp_path / 'db'
    guard.release()


def _ledger(journal, guard):
    """Schema 11 with an empty baseline, ledger ports and strategy s1 one lot long on rb2701."""
    journal.enable_strategy_ledger(guard)
    evidence = StrategyBaselineEvidence('acct', journal.journal_id, DAY, 'ctp', journal.generation, 1, 'source',
        'position-snapshot', 'orders-snapshot', 'cut', ('resource',), 100, 200, True, True, True, True)

    @contextmanager
    def fence():
        yield
    journal.initialize_empty_strategy_ledger(evidence, guard=guard, baseline_fence=fence,
                                           verify_current_empty=lambda actual: actual == evidence)
    journal.install_strategy_ledger_ports(guard=guard, resolve_binding=lambda _: BINDING,
                                          current_trading_day=lambda: DAY, verify_day_transition=lambda *_: False,
                                          verify_current_continuity=lambda *_: True)
    record = journal.reserve('s1', 'fill', 'p-s1', _order(RB, 'open'))
    native = {'exchange_name': 'ctp', 'client_order_id': 'fill', 'session_generation': 1, 'fields_json': '{}'}
    journal.begin_dispatch('s1', 'fill', record.reservation_id, record.digest, 'p-s1', 1, native, ('fill-key',))
    fact = GatewayReturnFact('acct', 'ctp', KEY, DAY, DirectExecutionEventKind.TRADE, 'source',
        identity=NativeOrderIdentity('ctp', 'ref', {'trading_day': DAY}, 1), identity_keys=('fill-key',),
        binding_keys=('fill-key',), venue_key='fill-key', trade_key=('SHFE', 'trade'), side='buy', offset='open',
        trade_quantity='1', trade_price='10')
    assert GatewayDirectExecutionLedger(journal, guard).ingest(fact).applied


def _native(key):
    return NativeOrderIdentity('ctp', 'native-' + key, {'trading_day': '20261109', 'front_id': 1}, 1)


def _sent(journal, strategy, key, payload):
    record = journal.reserve(strategy, key, 'p-' + strategy, _order(payload, 'open'))
    native = _identity(_native(key), 'ctp')
    args = (strategy, key, record.reservation_id, record.digest, 'p-' + strategy)
    started = journal.begin_dispatch(*args, record.version, native, ('nk-' + key,))
    journal.finish(*args, started.record.version, native, ('nk-' + key,), 'SENT')
    return journal.get(strategy, key, 'p-' + strategy)


def _to_v13(journal, guard):
    journal.enable_strategy_ledger(guard)
    journal.enable_account_extensions(guard)
    journal.enable_parent_authority(guard)


def _to_v17(journal, guard):
    journal.enable_account_facts_financial(guard)
    journal.enable_actor_stream(guard)
    journal.enable_strategy_origin(guard)
    journal.enable_control_cancel(guard)


def _reopen(journal, path, **flags):
    return GatewayDirectCommandJournal(path, 'acct', generation=journal.generation,
                                       expected_journal_id=journal.journal_id, minimum_revision=0,
                                       controls_enabled=True, **flags)


V13 = {'strategy_ledger_enabled': True, 'account_extensions_enabled': True, 'parent_authority_enabled': True}
V17 = {**V13, 'account_facts_financial_enabled': True, 'actor_stream_enabled': True,
       'strategy_origin_enabled': True, 'control_cancel_enabled': True}


def _canceller(journal, guard, calls):
    def native_cancel(target, symbol, port, scope):
        prepared = PreparedCancelRequest('provider-reservation', target, symbol, '20261109', 2,
                                         {'request_id': 12}, ('cancel-key-' + str(len(calls)),))
        marker = port.commit(PreDispatchRecord(WriteOperation.CANCEL, scope, 'ctp', symbol, None, target, {},
                                               prepared.trading_day, prepared.session_generation, 'synthetic',
                                               prepared))
        calls.append(symbol)
        return NativeDispatchOutcome(True, target, marker)
    direct = GatewayDirectDispatcher(journal, 'ctp', guard, lambda *_: None, lambda _: (), lambda _: True)
    return GatewayDirectCancelDispatcher(GatewayDirectCancelJournal(journal), direct, guard, 'ctp', native_cancel,
                                         lambda _: True)


@contextmanager
def _fence(_record):
    yield lambda: None


def _issue(control, cause_id, reservation_id, dispatcher):
    claimed, token = control.claim_target(cause_id, reservation_id)
    assert token is not None
    return control.dispatch_claimed_cancel(claimed, dispatcher, token, request_fence=_fence,
                                           requester='risk-principal', authority_source=SOURCE)


# -- G64-01: contract STOP_NEW ------------------------------------------------------------------

def test_contract_stop_new_refuses_opens_of_every_strategy_and_admits_only_a_proved_close(site):
    journal, control, guard, _ = site
    _ledger(journal, guard)
    cause = control.apply('risk-rb', 'STOP_NEW', scope_kind='instrument', scope_value=SCOPE, origin='risk:x')
    assert (cause['scope_kind'], cause['scope_value'], cause['mode'], cause['active']) == (
        'instrument', SCOPE, 'STOP_NEW', 1)
    for strategy in ('s1', 's2'):
        with pytest.raises(DirectCommandJournalError, match='^CONTROL_STOP_NEW$'):
            journal.reserve(strategy, 'rb-open-' + strategy, 'p-' + strategy, _order(RB, 'open'))
    # Other contracts, and the same symbol at another venue, go on.
    assert journal.reserve('s1', 'hc-open', 'p-s1', _order(HC, 'open')).status == 'RESERVED'
    assert journal.reserve('s2', 'ine-open', 'p-s2',
                           _order({'symbol': 'rb2701', 'exchange_id': 'INE'}, 'open')).status == 'RESERVED'
    # A close passes only through the trusted capacity proof: s1 holds one lot, s2 none.
    assert journal.reserve('s1', 'rb-close', 'p-s1', _order(RB, 'close_today')).status == 'RESERVED'
    for strategy, key in (('s1', 'rb-close-2'), ('s2', 'rb-close-s2')):
        with pytest.raises(DirectCommandJournalError, match='^STRATEGY_CLOSE_EXCEEDS$'):
            journal.reserve(strategy, key, 'p-' + strategy, _order(RB, 'close_today'))
    # Released, the contract admits opens again.
    control.resume('risk-rb', expected_version=1, operation_id='release-rb')
    assert journal.reserve('s2', 'rb-open-after', 'p-s2', _order(RB, 'open')).status == 'RESERVED'


def test_contract_stop_new_without_a_capacity_proof_refuses_closes_too(site):
    journal, control, _, _ = site
    control.apply('risk-rb', 'STOP_NEW', scope_kind='instrument', scope_value=SCOPE, origin='risk:x')
    for offset in ('open', 'close', 'close_today'):
        with pytest.raises(DirectCommandJournalError, match='^CONTROL_STOP_NEW$'):
            journal.reserve('s1', 'rb-' + offset, 'p-s1', _order(RB, offset))
    # An order that does not say where it trades is not let through.
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_STOP_NEW$'):
        journal.reserve('s1', 'no-venue', 'p-s1', {'symbol': 'rb2701', 'side': 'buy', 'offset': 'open'})
    assert journal.reserve('s1', 'hc', 'p-s1', _order(HC, 'open')).status == 'RESERVED'


def test_reserved_orders_on_the_contract_keep_the_stop_new_rule_at_dispatch(site):
    journal, control, guard, _ = site
    _ledger(journal, guard)
    opened = journal.reserve('s2', 'rb-open', 'p-s2', _order(RB, 'open'))
    closing = journal.reserve('s1', 'rb-close', 'p-s1', _order(RB, 'close_today'))
    other = journal.reserve('s2', 'hc-open', 'p-s2', _order(HC, 'open'))
    control.apply('risk-rb', 'STOP_NEW', scope_kind='instrument', scope_value=SCOPE, origin='risk:x')
    native = {'exchange_name': 'ctp', 'client_order_id': 'x', 'session_generation': 1, 'fields_json': '{}'}
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_PREVIOUSLY_BLOCKED$'):
        journal.begin_dispatch('s2', 'rb-open', opened.reservation_id, opened.digest, 'p-s2', 1, native, ('a',))
    assert journal.begin_dispatch('s1', 'rb-close', closing.reservation_id, closing.digest, 'p-s1', 1,
                                  dict(native, client_order_id='y'), ('b',)).newly_started
    assert journal.begin_dispatch('s2', 'hc-open', other.reservation_id, other.digest, 'p-s2', 1,
                                  dict(native, client_order_id='z'), ('c',)).newly_started


def test_the_strictest_applicable_cause_answers(site):
    journal, control, _, _ = site
    control.apply('rb-stop', 'STOP_NEW', scope_kind='instrument', scope_value=SCOPE, origin='risk:x')
    control.apply('s1-freeze', 'FREEZE', scope_kind='strategy', scope_value='s1', origin='operator:x')
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_FREEZE$'):
        journal.reserve('s1', 'rb', 'p-s1', _order(RB, 'open'))
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_STOP_NEW$'):
        journal.reserve('s2', 'rb', 'p-s2', _order(RB, 'open'))
    control.apply('hc-drain', 'DRAIN', scope_kind='instrument', scope_value='SHFE:hc2701', origin='risk:x')
    control.apply('acct-stop', 'STOP_NEW', scope_kind='account', origin='operator:x')
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_DRAIN$'):
        journal.reserve('s2', 'hc', 'p-s2', _order(HC, 'close'))


# -- G64-01: contract DRAIN ---------------------------------------------------------------------

def test_contract_drain_blocks_the_contract_and_targets_only_its_orders(site, tmp_path):
    journal, control, guard, path = site
    control.apply('rb-drain', 'DRAIN', scope_kind='instrument', scope_value=SCOPE, origin='risk:x')
    for offset in ('open', 'close'):
        with pytest.raises(DirectCommandJournalError, match='^CONTROL_DRAIN$'):
            journal.reserve('s1', 'rb-' + offset, 'p-s1', _order(RB, offset))
    assert journal.reserve('s1', 'hc', 'p-s1', _order(HC, 'open')).status == 'RESERVED'
    control.resume('rb-drain', expected_version=1, operation_id='release-rb-drain')
    _to_v13(journal, guard)
    rb1, rb2 = _sent(journal, 's1', 'rb-1', RB), _sent(journal, 's2', 'rb-2', RB)
    _sent(journal, 's1', 'hc-1', HC)
    pending = journal.reserve('s2', 'rb-pending', 'p-s2', _order(RB, 'open'))
    control.apply('rb-drain-2', 'DRAIN', scope_kind='instrument', scope_value=SCOPE, origin='risk:x')
    targets = control.targets('rb-drain-2')
    assert {row['reservation_id'] for row in targets} == {rb1.reservation_id, rb2.reservation_id}
    with journal._transaction() as db:
        blocked = [row[0] for row in db.execute("SELECT reservation_id FROM direct_control_blocked "
                                                "WHERE cause_id='rb-drain-2'")]
    assert blocked == [pending.reservation_id]
    _to_v17(journal, guard)
    calls = []
    dispatcher = _canceller(journal, guard, calls)
    sent = _issue(control, 'rb-drain-2', rb2.reservation_id, dispatcher)
    assert (sent.status, sent.principal, sent.target_principal) == ('SENT', 'risk-principal', 'p-s2')
    assert calls == ['rb2701']
    # The stored contract proof is checked again on every open of the journal.
    _reopen(journal, path, **V17)


def test_a_stored_contract_drain_target_on_another_contract_is_refused(site):
    journal, control, guard, path = site
    _to_v13(journal, guard)
    _sent(journal, 's1', 'rb-1', RB)
    hc = _sent(journal, 's1', 'hc-1', HC)
    control.apply('rb-drain', 'DRAIN', scope_kind='instrument', scope_value=SCOPE, origin='risk:x')
    flags = V13
    _reopen(journal, path, **flags)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE direct_control_targets SET reservation_id=?, request_key='hc-1', operation_id=?",
                   (hc.reservation_id, 'drain:' + hashlib.sha256(json.dumps(
                       ['rb-drain', hc.reservation_id], separators=(',', ':')).encode()).hexdigest()))
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_INVALID_DATABASE$'):
        _reopen(journal, path, **flags)


@pytest.mark.parametrize('mode', ['PAUSE', 'RESUME', ''])
def test_a_stored_contract_cause_with_an_unknown_mode_is_refused(site, mode):
    journal, control, _, path = site
    control.apply('rb', 'STOP_NEW', scope_kind='instrument', scope_value=SCOPE, origin='risk:x')
    _reopen(journal, path)
    with sqlite3.connect(path) as db:
        assert db.execute('UPDATE direct_control_causes SET mode=?', (mode,)).rowcount == 1
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_INVALID_DATABASE$'):
        _reopen(journal, path)


# -- G64-04: cancel-only operations -------------------------------------------------------------

def test_cancel_only_operation_freezes_working_orders_once_and_blocks_nothing(site):
    journal, control, guard, path = site
    _to_v13(journal, guard)
    rb1, rb2, hc1 = (_sent(journal, 's1', 'rb-1', RB), _sent(journal, 's2', 'rb-2', RB),
                     _sent(journal, 's1', 'hc-1', HC))
    reserved = journal.reserve('s1', 'hc-reserved', 'p-s1', _order(HC, 'open'))
    row = control.cancel_scope('op-1', scope_kind='account', origin='risk:x')
    assert (row['cause_id'], row['mode'], row['scope_kind'], row['active']) == (
        cancel_scope_cause_id('op-1'), 'CANCEL_ONLY', 'account', 1)
    # Nothing is blocked: a new open in the scope is admitted and the reserved order goes out.
    assert journal.reserve('s2', 'rb-new', 'p-s2', _order(RB, 'open')).status == 'RESERVED'
    native = {'exchange_name': 'ctp', 'client_order_id': 'r', 'session_generation': 1, 'fields_json': '{}'}
    assert journal.begin_dispatch('s1', 'hc-reserved', reserved.reservation_id, reserved.digest, 'p-s1', 1,
                                  native, ('r-key',)).newly_started
    with journal._transaction() as db:
        assert db.execute('SELECT count(*) FROM direct_control_blocked').fetchone()[0] == 0
    # It is not a cause: not listed, not readable or releasable as one.
    assert control.list_causes(scope_kind='account') == ()
    for call in (lambda: control.get(cancel_scope_cause_id('op-1')),
                 lambda: control.resume(cancel_scope_cause_id('op-1'), expected_version=1, operation_id='r')):
        with pytest.raises(DirectCommandJournalError, match='^CONTROL_NOT_FOUND$'):
            call()
    # Frozen once: the same operation again returns the stored row and the same targets.
    expected = {rb1.reservation_id, rb2.reservation_id, hc1.reservation_id}
    assert {target['reservation_id'] for target in control.targets(row['cause_id'])} == expected
    _sent(journal, 's2', 'rb-later', RB)
    assert control.cancel_scope('op-1', scope_kind='account', origin='risk:x') == row
    assert {target['reservation_id'] for target in control.targets(row['cause_id'])} == expected
    _, page, counts = control.cancel_scope_status('op-1')
    assert counts == {'QUEUED': 3, 'SENT': 0, 'NOT_SENT': 0, 'UNKNOWN': 0, 'TERMINAL': 0}
    assert {item['state'] for item in page} == {'QUEUED'} and all(item['cancel'] is None for item in page)
    # The same id with another scope or origin is a conflict, never a second operation.
    for kwargs in ({'scope_kind': 'strategy', 'scope_value': 's1', 'origin': 'risk:x'},
                   {'scope_kind': 'account', 'origin': 'operator:y'}):
        with pytest.raises(DirectCommandJournalError, match='^CONTROL_CAUSE_CONFLICT$'):
            control.cancel_scope('op-1', **kwargs)
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_CAUSE_CONFLICT$'):
        control.apply(cancel_scope_cause_id('op-1'), 'DRAIN', scope_kind='account', origin='risk:x')
    # A cancel-only operation is made only through cancel_scope, never applied as a cause.
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_INVALID_INPUT$'):
        control.apply('other', 'CANCEL_ONLY', scope_kind='account', origin='risk:x')
    # Each target is cancelled once, by its original identity; its state is reported per target.
    _to_v17(journal, guard)
    calls = []
    dispatcher = _canceller(journal, guard, calls)
    sent = _issue(control, row['cause_id'], rb1.reservation_id, dispatcher)
    assert sent.status == 'SENT' and sent.target_reservation_id == rb1.reservation_id
    claimed, token = control.claim_target(row['cause_id'], rb2.reservation_id)
    assert token is not None                     # claimed, then the issuer stopped before any cancel
    assert control.claim_target(row['cause_id'], rb2.reservation_id)[1] is None   # never claimed twice
    states = {item['reservation_id']: (item['state'], item['cancel'])
              for item in control.cancel_scope_status('op-1')[1]}
    assert states == {rb1.reservation_id: ('SENT', 'SENT'), rb2.reservation_id: ('NOT_SENT', None),
                      hc1.reservation_id: ('QUEUED', None)}
    assert calls == ['rb2701']
    # The stored operation and its proof are checked on every open.
    _reopen(journal, path, **V17)


def test_cancel_only_target_observed_terminal_is_reported_terminal(site):
    journal, control, guard, _ = site
    _to_v13(journal, guard)
    rb = _sent(journal, 's1', 'rb-1', RB)
    control.cancel_scope('op-t', scope_kind='instrument', scope_value=SCOPE, origin='risk:x')
    ledger = GatewayDirectExecutionLedger(journal, guard)
    ledger.ingest(GatewayReturnFact('acct', 'ctp', KEY, '20261109', DirectExecutionEventKind.ORDER, 'source',
        identity=_native('rb-1'), identity_keys=('nk-rb-1',), binding_keys=('nk-rb-1',), venue_key='nk-rb-1',
        side='buy', offset='open', status=DirectOrderStatus.CANCELLED, order_quantity='1', filled_quantity='0',
        remaining_quantity='1'))
    _, page, counts = control.cancel_scope_status('op-t')
    assert [(item['reservation_id'], item['state']) for item in page] == [(rb.reservation_id, 'TERMINAL')]
    assert counts['TERMINAL'] == 1


def test_cancel_only_scopes_select_their_own_orders(site):
    journal, control, guard, _ = site
    _to_v13(journal, guard)
    rb1, rb2, hc1 = (_sent(journal, 's1', 'rb-1', RB), _sent(journal, 's2', 'rb-2', RB),
                     _sent(journal, 's1', 'hc-1', HC))
    for operation, scope in (('op-rb', {'scope_kind': 'instrument', 'scope_value': SCOPE}),
                             ('op-s1', {'scope_kind': 'strategy', 'scope_value': 's1'})):
        row = control.cancel_scope(operation, origin='risk:x', **scope)
        selected = {target['reservation_id'] for target in control.targets(row['cause_id'])}
        assert selected == ({rb1.reservation_id, rb2.reservation_id} if operation == 'op-rb'
                            else {rb1.reservation_id, hc1.reservation_id})
    assert control.cancel_scope_status('absent') is None


@pytest.mark.parametrize('statements', [
    # released like a cause
    ["DELETE FROM direct_control_targets", "UPDATE direct_control_causes SET active=0, version=2, resume_id='r'"],
    # a target cancelled although the operation is never released
    ["UPDATE direct_control_targets SET state='CANCELLED'"],
    # not named by its operation
    ["DELETE FROM direct_control_targets", "UPDATE direct_control_causes SET cause_id='op-1'"],
    # a block, which a cancel-only operation never makes
    ["INSERT INTO direct_control_blocked SELECT account, cause_id, (SELECT reservation_id FROM "
     "direct_journal_commands WHERE request_key='hc-reserved') FROM direct_control_causes"],
])
def test_a_stored_cancel_only_operation_that_does_not_add_up_is_refused(site, statements):
    journal, control, guard, path = site
    _to_v13(journal, guard)
    _sent(journal, 's1', 'rb-1', RB)
    journal.reserve('s1', 'hc-reserved', 'p-s1', _order(HC, 'open'))
    control.cancel_scope('op-1', scope_kind='account', origin='risk:x')
    flags = V13
    _reopen(journal, path, **flags)
    with sqlite3.connect(path) as db:
        for statement in statements:
            assert db.execute(statement).rowcount == 1
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_INVALID_DATABASE$'):
        _reopen(journal, path, **flags)


def test_delegated_reservation_enters_the_trading_fence_after_an_existing_key_is_ruled_out(site):
    """G64-09 at the journal: the same fence point as the strategy's own reservation."""
    from bt_api_base.gateway_delegation_protocol import GatewayDelegatedCommand
    from bt_api_base.gateway_direct_protocol import gateway_payload_digest
    from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope

    from bt_api_gateway.direct_delegation import GatewayDelegateGrant, authorize_delegated_command

    journal, _, guard, _ = site
    _to_v13(journal, guard)
    identity = WireIdentity(WireRole.SERVICE, 'risk-principal', 'risk')
    payload = dict(_order(RB, 'open'), idempotency_key='k')
    command = GatewayDelegatedCommand('acct', 's1', 'domain', 'risk-principal', 'risk', 'risk', 'run', 'k',
                                      gateway_payload_digest(payload), KEY, 'rev1')
    grant = GatewayDelegateGrant(identity, 'acct', 's1', 'domain', 'risk', 'rev1', frozenset({KEY}),
                                 frozenset({'direct.reserve'}))
    context = SimpleNamespace(identity=identity, principal_ref='risk-principal', registration_id='registration',
                              scope=WireScope('domain', account_ref='acct', strategy_ref='s1', run_id='run'))
    permit = authorize_delegated_command(context, grant, command, 'direct.reserve', payload,
        registry_recheck=lambda _: True, current_grant=lambda: grant, instrument_recheck=lambda key: key == KEY)
    entered = []

    @contextmanager
    def trading(refuse):
        entered.append(refuse)
        if refuse:
            raise DirectCommandJournalError('STRATEGY_LEDGER_UNAVAILABLE')
        yield

    def reserve(refuse):
        return journal.reserve('s1', 'k', 'risk-principal', payload, reservation_fence=_null,
                               delegation_permit=permit, origin_trading_fence=lambda: trading(refuse))
    with pytest.raises(DirectCommandJournalError, match='^STRATEGY_LEDGER_UNAVAILABLE$'):
        reserve(True)
    with pytest.raises(DirectCommandJournalError, match='^NOT_FOUND$'):
        journal.get('s1', 'k', 'risk-principal')
    assert reserve(False).status == 'RESERVED'
    assert reserve(True).status == 'RESERVED'          # an existing key does not enter the fence again
    assert len(entered) == 2
    with pytest.raises(DirectCommandJournalError, match='^STRATEGY_ORIGIN_UNAVAILABLE$'):
        journal.reserve('s1', 'other', 'p-s1', _order(RB, 'open'), origin_trading_fence=lambda: trading(False))


@contextmanager
def _null():
    yield


def test_cancel_only_targets_are_reconciled_like_drain_targets(site):
    journal, control, guard, _ = site
    _to_v13(journal, guard)
    _sent(journal, 's1', 'rb-1', RB)
    row = control.cancel_scope('op-r', scope_kind='account', origin='risk:x')
    GatewayDirectExecutionLedger(journal, guard).ingest(GatewayReturnFact(
        'acct', 'ctp', KEY, '20261109', DirectExecutionEventKind.ORDER, 'source', identity=_native('rb-1'),
        identity_keys=('nk-rb-1',), binding_keys=('nk-rb-1',), venue_key='nk-rb-1', side='buy', offset='open',
        status=DirectOrderStatus.CANCELLED, order_quantity='1', filled_quantity='0', remaining_quantity='1'))
    assert control.reconcile_targets(row['cause_id']) is True
    assert [target['state'] for target in control.targets(row['cause_id'])] == ['OBSERVED_TERMINAL']


def test_a_contract_target_must_still_be_on_its_contract_when_its_cancel_is_authorised(site):
    from bt_api_gateway.direct_control_cancel import authorize_control_cancel

    journal, control, guard, _ = site
    _to_v13(journal, guard)
    rb = _sent(journal, 's1', 'rb-1', RB)
    control.apply('rb-drain', 'DRAIN', scope_kind='instrument', scope_value=SCOPE, origin='risk:x')
    _to_v17(journal, guard)
    control.claim_target('rb-drain', rb.reservation_id)

    def authorise(db):
        return authorize_control_cancel(db, account='acct', journal_id=journal.journal_id,
            generation=journal.generation, cause_id='rb-drain', reservation_id=rb.reservation_id,
            requester='risk-principal', source=SOURCE, verify_current=lambda *_: True)
    with journal._transaction() as db:
        assert authorise(db).binding['scope_kind'] == 'instrument'
        # Within one transaction (the periodic whole-journal check is not due between two of
        # them) a command that no longer names the contract is not authorised for cancel.
        db.execute('UPDATE direct_journal_commands SET payload_json=replace(payload_json, ?, ?) '
                   'WHERE reservation_id=?', ('rb2701', 'hc2701', rb.reservation_id))
        with pytest.raises(DirectCommandJournalError, match='^CONTROL_CANCEL_DENIED$'):
            authorise(db)
        db.execute('UPDATE direct_journal_commands SET payload_json=replace(payload_json, ?, ?) '
                   'WHERE reservation_id=?', ('hc2701', 'rb2701', rb.reservation_id))


def test_a_stored_contract_cancel_proof_is_checked_against_its_command(site):
    from bt_api_gateway.direct_control_cancel import verify_control_cancel_integrity

    journal, control, guard, path = site
    _to_v13(journal, guard)
    rb = _sent(journal, 's1', 'rb-1', RB)
    control.apply('rb-drain', 'DRAIN', scope_kind='instrument', scope_value=SCOPE, origin='risk:x')
    _to_v17(journal, guard)
    _issue(control, 'rb-drain', rb.reservation_id, _canceller(journal, guard, []))
    with journal._transaction() as db:
        verify_control_cancel_integrity(db, 'acct', journal.journal_id, 100)
        db.execute('UPDATE direct_journal_commands SET payload_json=replace(payload_json, ?, ?) '
                   'WHERE reservation_id=?', ('rb2701', 'hc2701', rb.reservation_id))
        with pytest.raises(DirectCommandJournalError, match='^INVALID_DATABASE$'):
            verify_control_cancel_integrity(db, 'acct', journal.journal_id, 100)
        db.execute('UPDATE direct_journal_commands SET payload_json=replace(payload_json, ?, ?) '
                   'WHERE reservation_id=?', ('hc2701', 'rb2701', rb.reservation_id))
