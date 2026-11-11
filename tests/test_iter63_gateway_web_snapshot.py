"""Web API v1 account snapshot: shown only with a provenance that matches the control view.

A real Registry, CURVE transport, control journal and account read port (with its own
read journal and account read model, as the trading composition installs them).
Synthetic account and observations; no venue, no provider and no real account. The
account read model is fed directly, as the owner's completed account read would.
"""
import pytest

pytest.importorskip('zmq')
pytest.importorskip('bt_api_py')

from bt_api_base.account_protocol import AccountKey
from bt_api_base.service_protocol import WireScope
from bt_api_py.service_runtime import ServiceRuntimeError
from bt_api_py.service_runtime_thread import ThreadedRuntimeError
from test_iter63_gateway_web_gateway_authority import (
    ACCOUNT,
    DOMAIN,
    MAIN,
    Gateway,
    WebHost,
    cli_call,
    observation,
)

from bt_api_gateway.account_read_model import GatewayAccountReadModel
from bt_api_gateway.event_journal import GatewayEventJournal
from bt_api_gateway.router import GatewayCommandKind, GatewayPrincipal
from bt_api_gateway.service_component import (
    GatewayReadService,
    GatewayServiceAccountScope,
    GatewayServiceError,
)

TYPED = frozenset({'account.snapshot.typed'})
READS = {'account': TYPED}


def unavailable(reason):
    return {'status': 'UNAVAILABLE', 'reason': reason}


async def snapshot(browser, user):
    response = await browser.client.get('/api/v1/scopes/desk/snapshot', headers=await browser.headers(user))
    return response.status_code, response.json()


class Wrapped:
    """The operator's real runtime with one change applied to what the Web layer sees."""

    def __init__(self, runtime, *, reply=None, status=None, fail=None):
        self.runtime, self.reply, self.change_status, self.fail = runtime, reply, status, fail
        self.calls = []

    def status(self):
        state = self.runtime.status()
        return state if self.change_status is None else self.change_status(state)

    def call(self, mount, operation, arguments, **kwargs):
        self.calls.append(operation)
        if self.fail is not None and operation == 'account.snapshot.typed':
            raise self.fail
        result = self.runtime.call(mount, operation, arguments, **kwargs)
        if self.reply is not None and operation == 'account.snapshot.typed':
            return self.reply(result)
        return result


def test_account_operator_sees_the_current_account_view_with_its_provenance(tmp_path):
    with Gateway(tmp_path, account_reads=READS) as gateway:
        cli = gateway.runtime('cli')
        journal_id = cli_call(cli, 'cli', 'direct.control.identity', {}, gateway)['journal_id']
        owner_generation = gateway.on_owner(lambda: gateway.journal.generation)
        gateway.publish(available='90')
        web = WebHost(gateway, ('account',))

        async def check(browser):
            code, view = await snapshot(browser, 'account')
            assert code == 200 and view['status'] == 'OBSERVED', view
            assert (view['view'], view['account_ref']) == ('account', ACCOUNT)
            assert view['source']['journal_id'] == journal_id
            assert view['source']['owner_generation'] == view['source']['read_generation'] == owner_generation
            assert 0 < view['fresh_for_seconds'] <= 30
            balance, = view['account']['balances']
            # Values as the Gateway holds them: a value it does not have stays null, never 0.
            assert (balance['currency'], balance['total'], balance['available'], balance['locked']) == (
                'CNY', '100', '90', None)
            assert 'account_key' not in view['account']
            assert view['account']['balances_complete'] is True
            # A newer read of the owner replaces it; the route shows the current one.
            gateway.publish(available='80')
            code, again = await snapshot(browser, 'account')
            assert again['account']['balances'][0]['available'] == '80'
            assert again['source']['cursor'] > view['source']['cursor']

        web.run(check)


def test_account_view_is_unavailable_while_the_read_model_is_not_ready(tmp_path):
    with Gateway(tmp_path, account_reads=READS) as gateway:
        web = WebHost(gateway, ('account',))

        async def check(browser):
            assert await snapshot(browser, 'account') == (200, unavailable('ACCOUNT_VIEW_NOT_READY'))
            gateway.publish()
            assert (await snapshot(browser, 'account'))[1]['status'] == 'OBSERVED'
            # The owner's next read fails or the link changes: the older view is not shown as current.
            gateway.on_host(lambda _host: gateway.read_model.invalidate())
            assert await snapshot(browser, 'account') == (200, unavailable('ACCOUNT_VIEW_NOT_READY'))

        web.run(check)


def test_read_of_another_owner_generation_is_never_shown(tmp_path):
    with Gateway(tmp_path, account_reads=READS) as gateway:
        owner_generation = gateway.on_owner(lambda: gateway.journal.generation)
        web = WebHost(gateway, ('account',))

        async def check(browser):
            gateway.read_generation('another-owner')
            gateway.publish()
            assert await snapshot(browser, 'account') == (200, unavailable('SOURCE_PROVENANCE_MISMATCH'))
            # After a change of the venue link the read generation continues the owner generation.
            relinked = owner_generation + ':native:2:attempt:1'
            gateway.read_generation(relinked)
            gateway.publish(available='85')
            code, view = await snapshot(browser, 'account')
            assert view['status'] == 'OBSERVED' and view['source']['read_generation'] == relinked, view

        web.run(check)


def test_strategy_operator_never_sees_the_account_view(tmp_path):
    with Gateway(tmp_path, account_reads={'account': TYPED, 'strategy': TYPED}) as gateway:
        gateway.publish()
        wrapped = Wrapped(gateway.runtime('strategy'))
        web = WebHost(gateway, ('account', 'strategy'), runtimes={'strategy': wrapped})

        async def check(browser):
            assert await snapshot(browser, 'strategy') == (200, unavailable('STRATEGY_VIEW_UNAVAILABLE'))
            assert (await snapshot(browser, 'account'))[1]['status'] == 'OBSERVED'

        web.run(check)
        assert 'account.snapshot.typed' not in wrapped.calls


def test_without_the_account_read_port_the_route_answers_as_before(tmp_path):
    with Gateway(tmp_path) as gateway:
        web = WebHost(gateway, ('account',))

        async def check(browser):
            assert await snapshot(browser, 'account') == (403, {'detail': 'GATEWAY_SCOPE_OR_GRANT_UNAVAILABLE'})

        web.run(check)


def _changed_provenance(name, value):
    def change(reply):
        return {**reply, 'source_provenance': {**reply['source_provenance'], name: value}}
    return change


def _other_epoch(state):
    from dataclasses import replace
    return replace(state, bindings=tuple(replace(b, service_epoch='another-epoch')
                                         if b.mount == 'application.account' else b for b in state.bindings))


def _other_key(state):
    from dataclasses import replace
    return replace(state, bindings=tuple(replace(b, server_key_fingerprint='0' * 64)
                                         if b.mount == 'application.account' else b for b in state.bindings))


@pytest.mark.parametrize(('change', 'answer'), [
    ({'reply': _changed_provenance('journal_id', 'another-journal')}, unavailable('SOURCE_PROVENANCE_MISMATCH')),
    ({'reply': _changed_provenance('account_scope', 'another-account')}, unavailable('SOURCE_PROVENANCE_MISMATCH')),
    ({'reply': _changed_provenance('owner_generation', 'another-owner')}, unavailable('SOURCE_PROVENANCE_MISMATCH')),
    ({'reply': lambda reply: {**reply, 'source_provenance': None}}, unavailable('SOURCE_PROVENANCE_UNAVAILABLE')),
    ({'reply': _changed_provenance('schema_version', 2)}, unavailable('ACCOUNT_VIEW_UNAVAILABLE')),
    ({'reply': lambda reply: {**reply, 'events': []}}, unavailable('ACCOUNT_VIEW_UNAVAILABLE')),
    # Data next to a status that says it is not ready or not current is never shown.
    ({'reply': lambda reply: {**reply, 'state_status': {**reply['state_status'], 'ready': False}}},
     unavailable('ACCOUNT_VIEW_NOT_READY')),
    ({'reply': lambda reply: {**reply, 'state_status': {**reply['state_status'], 'fresh_for_seconds': 0.0}}},
     unavailable('ACCOUNT_VIEW_NOT_READY')),
    ({'status': _other_epoch}, unavailable('SOURCE_PROVENANCE_MISMATCH')),
    ({'status': _other_key}, unavailable('SOURCE_PROVENANCE_MISMATCH')),
    ({'fail': TimeoutError('reply lost')}, unavailable('ACCOUNT_VIEW_UNAVAILABLE')),
    ({'fail': ThreadedRuntimeError('TIMEOUT_AFTER_START')}, unavailable('ACCOUNT_VIEW_UNAVAILABLE')),
    ({'fail': ServiceRuntimeError('DENIED')}, unavailable('ACCOUNT_VIEW_UNAVAILABLE')),
])
def test_account_view_without_a_matching_provenance_is_never_shown(tmp_path, change, answer):
    with Gateway(tmp_path, account_reads=READS) as gateway:
        gateway.publish()
        wrapped = Wrapped(gateway.runtime('account'), **change)
        web = WebHost(gateway, ('account',), runtimes={'account': wrapped})

        async def check(browser):
            return await snapshot(browser, 'account')

        assert web.run(check) == (200, answer)


@pytest.mark.parametrize('mount', ['application.direct_write', 'application.account'])
def test_registration_that_changes_during_the_read_is_never_shown(tmp_path, mount):
    from dataclasses import replace

    with Gateway(tmp_path, account_reads=READS) as gateway:
        gateway.publish()
        read = []

        def renewed_after_the_read(state):
            if not read:
                return state
            return replace(state, bindings=tuple(replace(b, registration_id='another-registration')
                                                 if b.mount == mount else b for b in state.bindings))

        wrapped = Wrapped(gateway.runtime('account'), status=renewed_after_the_read,
                          reply=lambda reply: read.append(1) or reply)
        web = WebHost(gateway, ('account',), runtimes={'account': wrapped})

        async def check(browser):
            return await snapshot(browser, 'account')

        assert web.run(check) == (200, unavailable('ACCOUNT_VIEW_UNAVAILABLE'))
        assert read == [1]


@pytest.mark.parametrize(('how', 'code'), [('revoked', 'DENIED'), ('expired', 'NOT_REGISTERED')])
def test_refused_account_read_is_a_refusal(tmp_path, how, code):
    with Gateway(tmp_path, account_reads=READS) as gateway:
        gateway.publish()
        web = WebHost(gateway, ('account',))
        if how == 'revoked':
            gateway.on_host(lambda host: host._registry.revoke_principal('web-account-op'))
        else:
            def expire(host):
                import time
                now = time.time() + 3600
                host._registry._clock = lambda: now
            gateway.on_host(expire)

        async def check(browser):
            return await snapshot(browser, 'account')

        assert web.run(check) == (200, {'status': 'REQUEST_REJECTED', 'code': code})


# The account read port itself.

def _read_service(tmp_path):
    journal = GatewayEventJournal(tmp_path / 'read.sqlite')
    model = GatewayAccountReadModel(
        journal, account_key=AccountKey('synthetic', 'venue', 'test', ACCOUNT), journal_account_scope=ACCOUNT,
        state_scope='state-a', required_coverage=(MAIN,), assert_current_generation=lambda _: None,
        max_staleness_seconds=30)
    model.start_generation('owner-1')
    account = GatewayServiceAccountScope(account_ref=ACCOUNT, execution_domain_ref=DOMAIN,
                                         journal_account_scope=ACCOUNT, account_read_strategy_scope='state-a')
    principal = GatewayPrincipal('reader', frozenset({ACCOUNT}), frozenset({'state-a'}),
                                 frozenset({GatewayCommandKind.READ}))
    return model, GatewayReadService(journal, accounts={ACCOUNT: account}, principals={'reader': principal},
                                     state_worker=model)


def _typed(service, **arguments):
    return service.handle('account.snapshot.typed', principal_ref='reader',
                          scope=WireScope(DOMAIN, account_ref=ACCOUNT), arguments=arguments)


def test_read_port_returns_provenance_only_when_asked_and_no_data_without_it(tmp_path):
    model, service = _read_service(tmp_path)
    model.finish_refresh(model.begin_refresh(), observation(model.account_key))
    plain = _typed(service)
    # Existing callers see the reply they always saw.
    assert set(plain) == {'requested_cursor', 'snapshot', 'events', 'next_cursor', 'latest_cursor',
                          'recovered_from_snapshot', 'snapshot_source', 'state_status'}
    # Nothing bound yet: asked for, the provenance is absent and no account data is returned.
    unbound = _typed(service, with_source_provenance=True)
    assert unbound['source_provenance'] is None and unbound['snapshot'] is None
    service.bind_source_provenance(account_scope=ACCOUNT, journal_id='journal-1', owner_generation='owner-1')
    bound = _typed(service, with_source_provenance=True)
    assert set(bound) == {'state_status', 'source_provenance', 'snapshot'}
    assert bound['source_provenance'] == {'schema_version': 1, 'account_scope': ACCOUNT,
                                          'journal_id': 'journal-1', 'owner_generation': 'owner-1'}
    assert bound['snapshot']['payload']['session_generation'] == 'owner-1'
    assert bound['state_status']['ready'] is True
    # Not ready: the provenance, but no older data.
    model.invalidate()
    stale = _typed(service, with_source_provenance=True)
    assert stale['snapshot'] is None and stale['state_status']['ready'] is False
    for wrong in (False, 1, 'yes'):
        with pytest.raises(GatewayServiceError):
            _typed(service, with_source_provenance=wrong)
    with pytest.raises(GatewayServiceError):
        service.handle('account.snapshot', principal_ref='reader', scope=WireScope(DOMAIN, account_ref=ACCOUNT),
                       arguments={'with_source_provenance': True})


def test_provenance_is_bound_once_and_only_for_the_read_models_account(tmp_path):
    _, service = _read_service(tmp_path)
    for values in ({'account_scope': 'another-account', 'journal_id': 'j', 'owner_generation': 'g'},
                   {'account_scope': ACCOUNT, 'journal_id': '', 'owner_generation': 'g'},
                   {'account_scope': ACCOUNT, 'journal_id': 'j', 'owner_generation': ' g'}):
        with pytest.raises(GatewayServiceError, match='SOURCE_PROVENANCE_INVALID'):
            service.bind_source_provenance(**values)
    service.bind_source_provenance(account_scope=ACCOUNT, journal_id='j', owner_generation='g')
    service.bind_source_provenance(account_scope=ACCOUNT, journal_id='j', owner_generation='g')
    with pytest.raises(GatewayServiceError, match='SOURCE_PROVENANCE_ALREADY_BOUND'):
        service.bind_source_provenance(account_scope=ACCOUNT, journal_id='other', owner_generation='g')


def test_composition_binds_the_journal_of_the_control_binding(tmp_path):
    # The harness never binds a provenance itself: the ServiceHost's component assembly does,
    # from the journal of the binding that answers direct.control.identity.
    with Gateway(tmp_path, account_reads=READS) as gateway:
        journal_id, generation = gateway.on_owner(lambda: (gateway.journal.journal_id, gateway.journal.generation))
        provenance = gateway.on_host(lambda _host: dict(gateway.read_service._source_provenance))
        assert provenance == {'schema_version': 1, 'account_scope': ACCOUNT, 'journal_id': journal_id,
                              'owner_generation': generation}
