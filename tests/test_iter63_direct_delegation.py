"""Synthetic owner tests for explicit delegated source identity; no provider I/O."""
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace
import sqlite3

import pytest
from bt_api_base.gateway_delegation_protocol import GatewayDelegatedCommand, GatewayDelegationProtocolError
from bt_api_base.gateway_direct_protocol import gateway_payload_digest
from bt_api_base.market_protocol import MarketInstrumentKey
from bt_api_base.direct_cancel_protocol import PreparedCancelRequest
from bt_api_base.direct_write_protocol import NativeOrderIdentity, PreDispatchRecord, WriteOperation
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope
from bt_api_gateway.direct_command_journal import DirectCommandJournalError, GatewayDirectCommandJournal
from bt_api_gateway.direct_delegation import (GatewayDelegateGrant, GatewayDelegationDenied,
                                              authorize_delegated_command)
from bt_api_gateway.direct_cancel_journal import GatewayDirectCancelJournal
from bt_api_gateway.direct_cancel_dispatch import GatewayDirectCancelDispatcher
from bt_api_gateway.direct_dispatch import (_identity, DirectDispatchError, GatewayDirectDispatcher,
                                            NativeDispatchOutcome)
from bt_api_gateway.session_guard import LocalAccountSessionGuard

KEY = MarketInstrumentKey('ctp', 'SHFE', 'simnow', 'future', 'rb2601', 'rb2601')
IDENTITY = WireIdentity(WireRole.SERVICE, 'risk-principal', 'risk-actor')
SCOPE = WireScope('domain', account_ref='acct', strategy_ref='strategy', run_id='run')
PAYLOAD = {'symbol': 'rb2601', 'exchange_id': 'SHFE', 'idempotency_key': 'order-1',
           'offset': 'open', 'side': 'buy', 'quantity': '1', 'quantity_unit': 'lots'}


@pytest.fixture
def owner(tmp_path):
    directory = tmp_path / 'guard'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'acct', 'owner')
    generation = guard.acquire()
    journal = GatewayDirectCommandJournal.create(tmp_path / 'db', 'acct', generation=generation)
    journal.enable_controls(guard)
    journal.enable_strategy_ledger(guard)
    yield journal, guard, tmp_path / 'db'
    guard.release()


def command(**changes):
    value = GatewayDelegatedCommand('acct', 'strategy', 'domain', 'risk-principal', 'risk-actor',
        'risk', 'run', 'order-1', gateway_payload_digest(PAYLOAD), KEY, 'grant-v1')
    return replace(value, **changes)


def permit(*, value=None, current=None, registry=None, parent=None, operation='direct.reserve'):
    value = value or command()
    grant = GatewayDelegateGrant(IDENTITY, 'acct', 'strategy', 'domain', 'risk', 'grant-v1',
                                 frozenset({KEY}), frozenset({'direct.reserve', 'direct.dispatch'}))
    context = SimpleNamespace(identity=IDENTITY, scope=SCOPE, principal_ref='risk-principal',
                              registration_id='registration')
    return authorize_delegated_command(context, grant, value, operation, dict(PAYLOAD),
        registry_recheck=registry or (lambda _: True), current_grant=current or (lambda: grant),
        instrument_recheck=lambda instrument: instrument == KEY, parent_recheck=parent)


@contextmanager
def fence():
    yield


def test_protocol_roundtrip_and_claim_conflict():
    one = command()
    assert GatewayDelegatedCommand.from_mapping(one.to_mapping()) == one
    assert one.origin == 'risk:risk-principal'
    assert len(one.digest) == 64 and replace(one, actor_ref='other').digest != one.digest
    mapping = one.to_mapping()
    mapping['origin'] = 'execution:evil'
    with pytest.raises(GatewayDelegationProtocolError):
        GatewayDelegatedCommand.from_mapping(mapping)
    with pytest.raises(GatewayDelegationProtocolError):
        replace(one, actor_kind='execution')


def test_rejects_other_identity_scope_grant_instrument_or_payload():
    context = SimpleNamespace(identity=IDENTITY, scope=SCOPE, principal_ref='risk-principal',
                              registration_id='registration')
    grant = GatewayDelegateGrant(IDENTITY, 'acct', 'strategy', 'domain', 'risk', 'grant-v1',
                                 frozenset({KEY}), frozenset({'direct.reserve'}))
    def check(ctx=context, obj=None, payload=None, **kw):
        return authorize_delegated_command(ctx, grant, obj or command(), 'direct.reserve',
            PAYLOAD if payload is None else payload, registry_recheck=kw.get('registry', lambda _: True),
            current_grant=kw.get('current', lambda: grant), instrument_recheck=lambda _: True)
    with pytest.raises(GatewayDelegationDenied):
        check(ctx=SimpleNamespace(identity=IDENTITY, scope=replace(SCOPE, strategy_ref='other'),
                                  principal_ref='risk-principal', registration_id='registration'))
    with pytest.raises(GatewayDelegationDenied):
        check(obj=command(instrument=replace(KEY, venue='DCE')))
    with pytest.raises(GatewayDelegationDenied):
        check(payload=dict(PAYLOAD, quantity='2'))
    with pytest.raises(GatewayDelegationDenied):
        check(registry=lambda _: False)
    with pytest.raises(GatewayDelegationDenied):
        check(current=lambda: replace(grant, revision='revoked'))


def test_v12_atomic_delegation_original_actor_and_reopen(owner):
    journal, guard, path = owner
    prior = journal.reserve('other', 'original', 'strategy-principal', {'symbol': 'X', 'offset':'open'})
    journal.enable_account_extensions(guard)
    auth = permit()
    with pytest.raises(DirectCommandJournalError, match='DELEGATION_FENCE_REQUIRED'):
        journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD, delegation_permit=auth)
    first = journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD,
                            reservation_fence=fence, delegation_permit=auth)
    assert first.principal == 'risk-principal'
    assert journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD,
                           reservation_fence=fence, delegation_permit=auth) == first
    with pytest.raises(DirectCommandJournalError, match='REQUEST_CONFLICT'):
        journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD)
    with journal._transaction() as db:
        saved = db.execute('SELECT envelope_json,envelope_digest FROM direct_delegated_commands').fetchone()
        assert GatewayDelegatedCommand.from_mapping(__import__('json').loads(saved[0])) == command()
        assert saved[1] == command().digest
    reopened = GatewayDirectCommandJournal(path, 'acct', generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=0, controls_enabled=True,
        strategy_ledger_enabled=True, account_extensions_enabled=True)
    assert reopened.get('strategy', 'order-1', 'risk-principal') == first
    assert reopened.get('other', 'original', 'strategy-principal') == prior
    with pytest.raises(DirectCommandJournalError):
        GatewayDirectCommandJournal(path, 'acct', generation=journal.generation,
            expected_journal_id=journal.journal_id, minimum_revision=0,
            controls_enabled=True, strategy_ledger_enabled=True)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE direct_delegated_commands SET actor_principal='tampered'")
    with pytest.raises(DirectCommandJournalError, match='INVALID_DATABASE'):
        GatewayDirectCommandJournal(path, 'acct', generation=journal.generation,
            expected_journal_id=journal.journal_id, minimum_revision=0, controls_enabled=True,
            strategy_ledger_enabled=True, account_extensions_enabled=True)


def test_delegate_revoked_before_commit_rolls_back(owner):
    journal, guard, _ = owner
    journal.enable_account_extensions(guard)
    calls = []
    def registry(_):
        calls.append(1)
        return len(calls) < 3
    auth = permit(registry=registry)
    with pytest.raises(GatewayDelegationDenied):
        journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD,
                        reservation_fence=fence, delegation_permit=auth)
    with pytest.raises(DirectCommandJournalError, match='NOT_FOUND'):
        journal.get('strategy', 'order-1', 'risk-principal')


def test_execution_parent_checked_on_same_connection(owner):
    journal, guard, _ = owner
    journal.enable_account_extensions(guard)
    seen = []
    def parent(db, cmd, payload):
        seen.append((db.in_transaction, cmd.parent_ref, cmd.child_id))
        assert payload['quantity'] == '1'
        with pytest.raises(TypeError):
            payload['quantity'] = '2'
        return True
    auth = permit(value=command(parent_ref='parent', child_id='child'), parent=parent)
    journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD,
                    reservation_fence=fence, delegation_permit=auth)
    assert seen == [(True, 'parent', 'child'), (True, 'parent', 'child')]


def test_dispatch_rechecks_current_delegate_on_every_attempt(owner):
    journal, guard, _ = owner
    journal.enable_account_extensions(guard)
    row = journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD,
                          reservation_fence=fence, delegation_permit=permit())
    args = ('strategy', 'order-1', row.reservation_id, row.digest, 'risk-principal',
            row.version, {'exchange': 'SHFE'}, ('strong-key',))
    with pytest.raises(DirectCommandJournalError, match='DELEGATION_MISMATCH'):
        journal.begin_dispatch(*args)
    auth = permit(operation='direct.dispatch')
    first = journal.begin_dispatch(*args, delegation_permit=auth, delegation_fence=fence)
    assert first.newly_started and first.record.principal == 'risk-principal'
    assert not journal.begin_dispatch(*args, delegation_permit=auth, delegation_fence=fence).newly_started
    with pytest.raises(GatewayDelegationDenied):
        revoked = permit(operation='direct.dispatch', registry=lambda _: False)
        journal.begin_dispatch(*args, delegation_permit=revoked, delegation_fence=fence)


def test_strategy_reader_retains_actor_and_rechecks_admission(owner):
    journal, guard, _ = owner
    journal.enable_account_extensions(guard)
    original = journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD,
                               reservation_fence=fence, delegation_permit=permit())
    calls = []
    @contextmanager
    def admission():
        def check():
            calls.append('check')
        yield check
    assert journal.read_delegated_strategy_command('strategy', 'order-1',
                                                    admission_fence=admission) == original
    assert calls == ['check', 'check']
    with pytest.raises(DirectCommandJournalError, match='NOT_FOUND'):
        journal.read_delegated_strategy_command('other', 'order-1', admission_fence=admission)
    @contextmanager
    def revoked():
        checks = []
        def check():
            checks.append(1)
            if len(checks) == 2:
                raise RuntimeError('revoked')
        yield check
    with pytest.raises(RuntimeError, match='revoked'):
        journal.read_delegated_strategy_command('strategy', 'order-1', admission_fence=revoked)


def test_strategy_cancel_retains_separate_target_actor(owner):
    journal, guard, path = owner
    journal.enable_account_extensions(guard)
    row = journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD,
                          reservation_fence=fence, delegation_permit=permit())
    native = NativeOrderIdentity('CTP', 'order-ref', {'trading_day': '20300101'}, 1)
    journal.begin_dispatch('strategy', 'order-1', row.reservation_id, row.digest,
        'risk-principal', 1, _identity(native, 'CTP'), ('order-key',),
        delegation_permit=permit(operation='direct.dispatch'), delegation_fence=fence)
    cancel = GatewayDirectCancelJournal(journal)
    @contextmanager
    def admission():
        yield lambda: None
    kwargs = dict(target_identity=native, symbol='rb2601', target_principal='risk-principal')
    with pytest.raises(DirectCommandJournalError, match='DELEGATION_UNAVAILABLE'):
        cancel.request('strategy', 'cancel-1', 'strategy-principal', 'order-1',
                       row.reservation_id, row.digest, **kwargs)
    first = cancel.request('strategy', 'cancel-1', 'strategy-principal', 'order-1',
                           row.reservation_id, row.digest, strategy_admission_fence=admission, **kwargs)
    assert first.principal == 'strategy-principal' and first.target_principal == 'risk-principal'
    prep = PreparedCancelRequest('provider-reservation', native, 'rb2601', '20300102', 2,
                                 {'request_id': 12}, ('cancel-key',))
    with pytest.raises(DirectCommandJournalError, match='DELEGATION_UNAVAILABLE'):
        cancel.begin_dispatch('strategy', 'cancel-1', 'strategy-principal', 1, prep)
    started = cancel.begin_dispatch('strategy', 'cancel-1', 'strategy-principal', 1, prep,
                                    strategy_admission_fence=admission)
    assert started.newly_started and started.record.target_principal == 'risk-principal'
    reopened = GatewayDirectCommandJournal(path, 'acct', generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=0, controls_enabled=True,
        strategy_ledger_enabled=True, account_extensions_enabled=True)
    assert GatewayDirectCancelJournal(reopened).get('strategy', 'cancel-1', 'strategy-principal') == started.record


def test_dispatcher_commits_delegate_under_the_original_fence(owner):
    journal, guard, _ = owner
    journal.enable_account_extensions(guard)
    row = journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD,
                          reservation_fence=fence, delegation_permit=permit())
    state = {'held': False, 'rechecks': 0, 'sent': 0}
    @contextmanager
    def admission(_row):
        assert not state['held']
        state['held'] = True
        def recheck():
            assert state['held']
            state['rechecks'] += 1
        try:
            yield recheck
        finally:
            state['held'] = False
    native = NativeOrderIdentity('CTP', 'order-ref', {'trading_day': '20300101'}, 1)
    def place(payload, port, account):
        marker = port.commit(PreDispatchRecord(operation=WriteOperation.PLACE, host_scope=account,
            exchange_name='CTP', symbol='rb2601', identity=native, target_identity=None,
            request_summary=payload, trading_day='20300101', session_generation=1, created_at_utc='synthetic'))
        assert marker and not state['held']
        state['sent'] += 1
        return NativeDispatchOutcome(True, native, marker)
    dispatcher = GatewayDirectDispatcher(journal, 'CTP', guard, place, lambda _: ('order-key',), lambda _: True)
    result = dispatcher.dispatch('strategy', 'order-1', 'risk-principal', row.reservation_id,
        row.digest, row.version, request_fence=admission, delegation_permit=permit(operation='direct.dispatch'))
    assert result.status == 'SENT' and state['sent'] == 1 and state['rechecks'] >= 1


def test_delegate_revoked_at_native_commit_never_sends(owner):
    journal, guard, _ = owner
    journal.enable_account_extensions(guard)
    row = journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD,
                          reservation_fence=fence, delegation_permit=permit())
    calls, sent = [], []
    def registry(_):
        calls.append(1)
        return len(calls) < 5
    auth = permit(operation='direct.dispatch', registry=registry)
    @contextmanager
    def admission(_row):
        yield lambda: None
    native = NativeOrderIdentity('CTP', 'order-ref', {'trading_day': '20300101'}, 1)
    def place(payload, port, account):
        marker = port.commit(PreDispatchRecord(operation=WriteOperation.PLACE, host_scope=account,
            exchange_name='CTP', symbol='rb2601', identity=native, target_identity=None,
            request_summary=payload, trading_day='20300101', session_generation=1, created_at_utc='synthetic'))
        sent.append(marker)
        return NativeDispatchOutcome(True, native, marker)
    dispatcher = GatewayDirectDispatcher(journal, 'CTP', guard, place, lambda _: ('order-key',), lambda _: True)
    with pytest.raises(DirectDispatchError, match='PRE_DISPATCH_FAILED'):
        dispatcher.dispatch('strategy', 'order-1', 'risk-principal', row.reservation_id,
            row.digest, row.version, request_fence=admission, delegation_permit=auth)
    assert sent == [] and journal.get('strategy', 'order-1', 'risk-principal').status == 'RESERVED'


def test_strategy_cancel_dispatch_uses_original_actor_and_live_fence(owner):
    journal, guard, _ = owner
    journal.enable_account_extensions(guard)
    row = journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD,
                          reservation_fence=fence, delegation_permit=permit())
    native = NativeOrderIdentity('CTP', 'order-ref', {'trading_day': '20300101'}, 1)
    journal.begin_dispatch('strategy', 'order-1', row.reservation_id, row.digest,
        'risk-principal', 1, _identity(native, 'CTP'), ('order-key',),
        delegation_permit=permit(operation='direct.dispatch'), delegation_fence=fence)
    cancel = GatewayDirectCancelJournal(journal)
    @contextmanager
    def admission():
        yield lambda: None
    attempt = cancel.request('strategy', 'cancel-1', 'strategy-principal', 'order-1',
        row.reservation_id, row.digest, target_identity=native, symbol='rb2601',
        target_principal='risk-principal', strategy_admission_fence=admission)
    checks, sent = [], []
    @contextmanager
    def request_fence(_row):
        yield lambda: checks.append(1)
    def place_cancel(target, symbol, port, scope):
        prep = PreparedCancelRequest('provider-reservation', target, symbol, '20300102', 2,
                                     {'request_id': 12}, ('cancel-key',))
        marker = port.commit(PreDispatchRecord(WriteOperation.CANCEL, scope, 'CTP', symbol,
            None, target, {}, prep.trading_day, prep.session_generation, 'synthetic', prep))
        sent.append(marker)
        return NativeDispatchOutcome(True, target, marker)
    direct = GatewayDirectDispatcher(journal, 'CTP', guard, lambda *_: None, lambda _: (), lambda _: True)
    dispatcher = GatewayDirectCancelDispatcher(cancel, direct, guard, 'CTP', place_cancel, lambda _: True)
    result = dispatcher.dispatch('strategy', 'cancel-1', 'strategy-principal',
                                 expected_version=attempt.version, request_fence=request_fence)
    assert result.status == 'SENT' and result.target_principal == 'risk-principal'
    assert sent == [attempt.attempt_id] and len(checks) >= 2


def test_strategy_cancel_revocation_rolls_back_attempt(owner):
    journal, guard, _ = owner
    journal.enable_account_extensions(guard)
    row = journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD,
                          reservation_fence=fence, delegation_permit=permit())
    native = NativeOrderIdentity('CTP', 'order-ref', {'trading_day': '20300101'}, 1)
    journal.begin_dispatch('strategy', 'order-1', row.reservation_id, row.digest,
        'risk-principal', 1, _identity(native, 'CTP'), ('order-key',),
        delegation_permit=permit(operation='direct.dispatch'), delegation_fence=fence)
    cancel = GatewayDirectCancelJournal(journal)
    @contextmanager
    def revoked():
        calls = []
        def check():
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError('revoked')
        yield check
    with pytest.raises(RuntimeError, match='revoked'):
        cancel.request('strategy', 'cancel-1', 'strategy-principal', 'order-1',
            row.reservation_id, row.digest, target_identity=native, symbol='rb2601',
            target_principal='risk-principal', strategy_admission_fence=revoked)
    with pytest.raises(DirectCommandJournalError, match='NOT_FOUND'):
        cancel.get('strategy', 'cancel-1', 'strategy-principal')


def test_parent_authority_is_explicit_guarded_upgrade(owner):
    journal, guard, path = owner
    journal.enable_account_extensions(guard)
    original = journal.reserve('strategy', 'order-1', 'risk-principal', PAYLOAD,
                               reservation_fence=fence, delegation_permit=permit())
    journal.enable_parent_authority(guard)
    reopened = GatewayDirectCommandJournal(path, 'acct', generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=0, controls_enabled=True,
        strategy_ledger_enabled=True, account_extensions_enabled=True, parent_authority_enabled=True)
    assert reopened.get('strategy', 'order-1', 'risk-principal') == original
    with pytest.raises(DirectCommandJournalError):
        GatewayDirectCommandJournal(path, 'acct', generation=journal.generation,
            expected_journal_id=journal.journal_id, minimum_revision=0, controls_enabled=True,
            strategy_ledger_enabled=True, account_extensions_enabled=True)
