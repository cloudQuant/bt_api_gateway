"""A refusal by the Gateway is answered as a refusal; an unknown outcome stays UNKNOWN.

The first tests run against a real Registry, CURVE transport and control journal
(synthetic account, no venue). The last ones use stand-in runtimes to show that a
timeout, a lost reply, a local error of the runtime or a refusal that arrives after a
write was answered never becomes a refusal.
"""
from dataclasses import replace
from types import MappingProxyType

import pytest

pytest.importorskip('zmq')
pytest.importorskip('bt_api_py')

from bt_api_py.service_registry import PrincipalGrant
from bt_api_py.service_runtime import (
    ServiceCallOutcomeUnknownError,
    ServiceRuntimeError,
)
from bt_api_py.service_runtime_thread import ThreadedRuntimeError
from test_iter63_gateway_web import Runtime, run_requests
from test_iter63_gateway_web_gateway_authority import Gateway, WebHost, cli_call

UNKNOWN = {'status': 'UNKNOWN', 'code': 'IDENTITY_UNAVAILABLE'}


def refused(code):
    return {'status': 'REQUEST_REJECTED', 'code': code}


def _revoke(gateway, name):
    assert gateway.on_host(lambda host: host._registry.revoke_principal(gateway.operators[name][0])) is True


def _expire(gateway, _name):
    def expire(host):
        import time
        now = time.time() + 3600
        host._registry._clock = lambda: now
    gateway.on_host(expire)


def _withdraw(gateway, name, operation):
    """The Registry stops granting one operation to this operator (its registration still lists it)."""
    principal = gateway.operators[name][0]

    def change(host):
        registry = host._registry
        with registry._lock:
            entry, = registry._grants[principal]
            resources = tuple(replace(item, operations=item.operations - {operation}) for item in entry.resources)
            registry._grants = MappingProxyType({**registry._grants,
                                                 principal: (PrincipalGrant(entry.identity, resources),)})
    gateway.on_host(change)


@pytest.mark.parametrize(('how', 'code'), [(_revoke, 'DENIED'), (_expire, 'NOT_REGISTERED')])
def test_revoked_or_expired_operator_is_refused_with_the_gateway_code_and_nothing_changes(tmp_path, how, code):
    with Gateway(tmp_path) as gateway:
        cli = gateway.runtime('cli')
        assert cli_call(cli, 'cli', 'direct.control.apply', {'cause_id': 'cli-freeze', 'mode': 'FREEZE'},
                        gateway)['active'] is True
        web = WebHost(gateway, ('account',))

        async def prepare(browser):
            apply = await browser.apply_command('account', 'freeze-after')
            release = await browser.resume_command('account', 'release-after', 'cli-freeze')
            receipts = [(await browser.prepare('account', body))['receipt'] for body in (apply, release)]
            code_, view = await browser.causes('account')
            return receipts, view['scope_receipt']

        (apply_receipt, release_receipt), scope_receipt = web.run(prepare)
        before = gateway.causes()
        how(gateway, 'account')

        async def check(browser):
            for _ in range(2):
                for receipt in (apply_receipt, release_receipt):
                    assert await browser.run('account', receipt) == refused(code)
                    assert await browser.status('account', receipt) == refused(code)
                assert await browser.causes('account') == (200, refused(code))
                assert await browser.prepare('account', {'request_id': 'freeze-new', 'mode': 'FREEZE', 'cause_id': '',
                                                         'expected_version': 0, 'view_receipt': scope_receipt}) == refused(code)

        web.run(check)
        # Nothing was applied or released: the journal holds exactly what it held before.
        assert gateway.causes() == before
        assert before['cli-freeze']['active'] == 1 and before['cli-freeze']['resume_id'] is None
        if how is _revoke:
            assert cli_call(cli, 'cli', 'direct.control.list', {'after': '', 'limit': 10}, gateway)['status'] == 'OBSERVED'


def test_operator_of_another_account_is_refused_with_scope_denied(tmp_path):
    with Gateway(tmp_path) as gateway:
        web = WebHost(gateway, ('account', 'other_account'))

        async def check(browser):
            # The Gateway's control handler refuses the other account's operator itself.
            assert await browser.causes('other_account') == (200, refused('SCOPE_DENIED'))
            # A receipt of this account's operator is the Web's own refusal of a foreign receipt:
            # it was never sent, and stays UNKNOWN as before.
            receipt = (await browser.prepare('account', await browser.apply_command('account', 'cross')))['receipt']
            assert await browser.run('other_account', receipt) == UNKNOWN
            assert await browser.status('other_account', receipt) == UNKNOWN

        web.run(check)
        assert gateway.causes() == {}


def test_operation_the_gateway_no_longer_grants_is_refused_and_not_applied(tmp_path):
    with Gateway(tmp_path) as gateway:
        web = WebHost(gateway, ('account',))

        async def prepare(browser):
            return (await browser.prepare('account', await browser.apply_command('account', 'freeze-1')))['receipt']

        receipt = web.run(prepare)
        _withdraw(gateway, 'account', 'direct.control.apply')

        async def check(browser):
            # The lookup is still granted (NOT_FOUND); the apply itself is refused by the Registry.
            assert await browser.status('account', receipt) == {'status': 'NOT_FOUND', 'cause_id': 'freeze-1'}
            assert await browser.run('account', receipt) == refused('SCOPE_DENIED')
            assert await browser.status('account', receipt) == {'status': 'NOT_FOUND', 'cause_id': 'freeze-1'}

        web.run(check)
        assert gateway.causes() == {}


class RevokeAfterWrite:
    """The real runtime; the Registry revokes the operator right after the write was answered."""

    def __init__(self, runtime, gateway, operation):
        self.runtime, self.gateway, self.operation, self.answered = runtime, gateway, operation, []

    def status(self):
        return self.runtime.status()

    def call(self, mount, operation, arguments, **kwargs):
        result = self.runtime.call(mount, operation, arguments, **kwargs)
        if operation == self.operation and not self.answered:
            self.answered.append(result)
            _revoke(self.gateway, 'account')
        return result


def test_refusal_after_the_write_was_answered_stays_unknown(tmp_path):
    with Gateway(tmp_path) as gateway:
        lossy = RevokeAfterWrite(gateway.runtime('account'), gateway, 'direct.control.apply')
        web = WebHost(gateway, ('account',), runtimes={'account': lossy})

        async def check(browser):
            receipt = (await browser.prepare('account', await browser.apply_command('account', 'freeze-1')))['receipt']
            # The apply was made; the identity check after it is refused. Never a refusal of the apply.
            assert await browser.run('account', receipt) == UNKNOWN
            assert lossy.answered == [{'status': 'OBSERVED', 'cause_id': 'freeze-1', 'version': 1, 'active': True}]
            # A lookup refused now is a refusal of the lookup only: the cause stays applied.
            assert await browser.status('account', receipt) == refused('DENIED')

        web.run(check)
        assert gateway.causes()['freeze-1']['active'] == 1


# Stand-in runtimes: what is not the Gateway's own refusal of the call stays UNKNOWN.

def _marked(code, reply=None):
    error = ServiceRuntimeError(code)
    error.service_reply_code = code if reply is None else reply
    return error


class Failing(Runtime):
    def __init__(self, failures, results=None):
        super().__init__()
        self.binding.scope.strategy_ref = None
        self.failures, self.results = dict(failures), dict(results or {})

    def call(self, mount, operation, arguments, **kwargs):
        self.calls.append((mount, operation, arguments, kwargs))
        if operation in self.results:
            return self.results[operation]
        failure = self.failures.get(operation)
        if failure is not None and self.calls_of(operation) >= failure[0]:
            raise failure[1]
        if operation == 'direct.control.status':
            return {'status': 'NOT_FOUND', 'cause_id': arguments['cause_id']}
        if operation == 'direct.control.apply':
            return {'status': 'OBSERVED', 'cause_id': arguments['cause_id'], 'version': 1, 'active': True}
        return Runtime.call(self, mount, operation, arguments, **kwargs)

    def calls_of(self, operation):
        return sum(1 for call in self.calls if call[1] == operation)


def _account_app(runtime):
    from bt_api_gateway.web.app import AuthenticatedWebSession, WebScope, create_app

    scope = WebScope('desk', 'account-a', 'scope-a', None)
    session = AuthenticatedWebSession('operator-a', 'actor-a', 'c' * 32, (scope,))
    return create_app(origin='http://127.0.0.1:8000', authenticate=lambda request: session,
                      resolve_runtime=lambda identity, selected: runtime)


async def _freeze(client, request_id='freeze-1'):
    route = (await client.get('/api/v1/session')).json()['scopes'][0]['route_fingerprint']
    headers = {'Origin': 'http://127.0.0.1:8000', 'X-CSRF-Token': 'c' * 32, 'X-Gateway-Route': route}
    view = (await client.get('/api/v1/scopes/desk/causes')).json()
    prepared = (await client.post('/api/v1/scopes/desk/requests/prepare', headers=headers, json={
        'request_id': request_id, 'mode': 'FREEZE', 'cause_id': '', 'expected_version': 0,
        'view_receipt': view['scope_receipt']})).json()
    assert prepared['status'] == 'PREPARED', prepared
    return headers, prepared['receipt']


@pytest.mark.parametrize('error', [
    ServiceRuntimeError('DENIED'),                      # same code, raised locally: not a reply
    ServiceRuntimeError('CAPABILITY_UNAVAILABLE'),      # a local code that is also a Registry code
    _marked('UNAVAILABLE'),                             # the Registry's reply, but not a known refusal
    _marked('INVALID_REQUEST'),
    _marked('HANDLER_FAILED'),
    _marked('DENIED', reply='SCOPE_DENIED'),            # marker and code disagree
    ServiceCallOutcomeUnknownError('message', 'direct.control.apply'),
    ThreadedRuntimeError('TIMEOUT_AFTER_START'),
    ThreadedRuntimeError('TIMEOUT_BEFORE_START'),
    TimeoutError('reply lost'),
])
def test_only_the_gateways_own_refusal_of_the_write_is_a_refusal(error):
    runtime = Failing({'direct.control.apply': (1, error)})
    app = _account_app(runtime)

    async def check(client):
        headers, receipt = await _freeze(client)
        return (await client.post('/api/v1/scopes/desk/requests/run', headers=headers,
                                  json={'receipt': receipt})).json()

    assert run_requests(app, check) == UNKNOWN
    assert runtime.calls_of('direct.control.apply') == 1


def test_the_gateways_own_refusal_of_the_write_is_a_refusal():
    runtime = Failing({'direct.control.apply': (1, _marked('DENIED'))})
    app = _account_app(runtime)

    async def check(client):
        headers, receipt = await _freeze(client)
        return (await client.post('/api/v1/scopes/desk/requests/run', headers=headers,
                                  json={'receipt': receipt})).json()

    assert run_requests(app, check) == refused('DENIED')


def test_refusal_of_the_identity_check_after_a_write_stays_unknown():
    runtime = Failing({})
    answer = runtime.call

    def refuse_after_the_write(mount, operation, arguments, **kwargs):
        if operation == 'direct.control.identity' and runtime.calls_of('direct.control.apply'):
            runtime.calls.append((mount, operation, arguments, kwargs))
            raise _marked('NOT_REGISTERED')
        return answer(mount, operation, arguments, **kwargs)

    runtime.call = refuse_after_the_write
    app = _account_app(runtime)

    async def check(client):
        headers, receipt = await _freeze(client)
        return (await client.post('/api/v1/scopes/desk/requests/run', headers=headers,
                                  json={'receipt': receipt})).json()

    assert run_requests(app, check) == UNKNOWN
    assert runtime.calls_of('direct.control.apply') == 1


def test_refusal_is_not_trusted_when_the_binding_changed_during_the_call():
    runtime = Failing({})

    def refuse_and_reregister(mount, operation, arguments, **kwargs):
        runtime.calls.append((mount, operation, arguments, kwargs))
        runtime.binding.registration_id = 'reg-2'  # a new registration took over meanwhile
        raise _marked('DENIED')

    runtime.call = refuse_and_reregister
    app = _account_app(runtime)

    async def check(client):
        return (await client.get('/api/v1/scopes/desk/causes')).json()

    assert run_requests(app, check) == UNKNOWN


@pytest.mark.parametrize('reply', [
    {'status': 'REQUEST_REJECTED', 'code': 'SCOPE_DENIED', 'cause_id': ''},  # not the refusal shape
    {'status': 'REQUEST_REJECTED', 'code': 'scope denied'},                  # not a finite code
    {'status': 'REQUEST_REJECTED'},
    {'status': 'UNKNOWN', 'cause_id': ''},                                   # the owner did not answer
])
def test_identity_reply_that_is_not_an_exact_refusal_stays_unknown(reply):
    runtime = Failing({}, results={'direct.control.identity': reply})
    app = _account_app(runtime)

    async def check(client):
        return (await client.get('/api/v1/scopes/desk/causes')).json()

    assert run_requests(app, check) == UNKNOWN


def test_exact_refusal_of_a_read_after_the_identity_check_is_a_refusal():
    # The control handler accepts the identity read but refuses the list itself.
    runtime = Failing({}, results={'direct.control.list': {'status': 'REQUEST_REJECTED', 'code': 'SCOPE_DENIED'}})
    app = _account_app(runtime)

    async def check(client):
        return (await client.get('/api/v1/scopes/desk/causes')).json()

    assert run_requests(app, check) == refused('SCOPE_DENIED')


def test_exact_refusal_of_the_identity_read_is_a_refusal():
    runtime = Failing({}, results={'direct.control.identity': {'status': 'REQUEST_REJECTED',
                                                               'code': 'SCOPE_DENIED'}})
    app = _account_app(runtime)

    async def check(client):
        return (await client.get('/api/v1/scopes/desk/causes')).json()

    assert run_requests(app, check) == refused('SCOPE_DENIED')
    assert [call[1] for call in runtime.calls] == ['direct.control.identity']
