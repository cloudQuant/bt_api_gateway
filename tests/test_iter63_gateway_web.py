"""Bounded local HTTP tests; fake runtimes are trusted host test fixtures."""
import asyncio
from types import SimpleNamespace

import httpx
import pytest
from bt_api_base.service_protocol import WireIdentity, WireRole

from bt_api_gateway.web.app import AuthenticatedWebSession, WebScope, create_app


class Runtime:
    def __init__(self):
        scope = SimpleNamespace(account_ref='account-a', strategy_ref='strategy-a')
        self.identity = SimpleNamespace(role=WireRole.APPLICATION_CLIENT,
                                        principal_ref='operator-a', actor_ref='actor-a', delegate_ref=None)
        self.binding = SimpleNamespace(active=True, mount='application.direct_write', scope_ref='scope-a',
            scope=scope, operations=frozenset({'direct.control.list', 'direct.control.status',
                                               'direct.control.resume_status',
                                               'direct.control.apply', 'direct.control.resume', 'direct.control.identity',
                                               'direct.control.targets', 'direct.control.drain_target'}))
        self.binding.authenticated_peer = WireIdentity(WireRole.SERVICE, 'gateway-p', 'gateway-a')
        self.binding.server_key_fingerprint = 'a' * 64
        self.binding.registration_id = 'reg-1'; self.binding.service_epoch = 'epoch-1'
        self.calls = []
        self.fail = False
        self.closed = False

    def status(self):
        return SimpleNamespace(state='running', thread_alive=True, healthy=True,
                               identity=self.identity, bindings=(self.binding,))

    def call(self, mount, operation, arguments, **kwargs):
        self.calls.append((mount, operation, arguments, kwargs))
        if self.fail:
            raise TimeoutError('private diagnostic must not leave adapter')
        if operation == 'direct.control.identity':
            return {'status': 'OBSERVED', 'schema_version': 1, 'account_scope': self.binding.scope.account_ref, 'journal_id': 'journal-1'}
        if operation == 'direct.control.list':
            return {'status': 'OBSERVED', 'causes': [{'cause_id': 'historical', 'mode': 'FREEZE', 'active': 1, 'version': 3}]}
        if operation == 'direct.control.resume_status':
            return {'status': 'NOT_FOUND', 'operation_id': arguments['operation_id']}
        return {'status': 'OBSERVED', 'cause_id': arguments['cause_id'], 'version': 1}

    def close(self):
        self.closed = True


def make_app(runtime=None):
    runtime = runtime or Runtime()
    scope = WebScope('desk', 'account-a', 'scope-a', 'strategy-a')
    session = AuthenticatedWebSession('operator-a', 'actor-a', 'c' * 32, (scope,))
    app = create_app(origin='http://127.0.0.1:8000', authenticate=lambda request: session,
                     resolve_runtime=lambda identity, selected: runtime)
    return app, runtime


def run_requests(app, callback, client=('127.0.0.1', 1234)):
    async def run():
        transport = httpx.ASGITransport(app=app, client=client)
        async with httpx.AsyncClient(transport=transport, base_url='http://127.0.0.1:8000') as browser:
            return await callback(browser)
    return asyncio.run(run())


def test_apply_resume_scope_and_stable_ids():
    app, runtime = make_app()
    async def check(client):
        scope = (await client.get('/api/v1/session')).json()['scopes'][0]
        assert scope['scope_id'] == 'desk'
        assert (await client.get('/api/v1/scopes/desk/causes')).json()['status'] == 'OBSERVED'
        headers = {'Origin': 'http://127.0.0.1:8000', 'X-CSRF-Token': 'c' * 32, 'X-Gateway-Route': scope['route_fingerprint']}
        body = {'request_id': 'request-1', 'mode': 'DRAIN'}
        assert (await client.post('/api/v1/scopes/desk/causes', headers=headers, json=body)).status_code == 405
        resume = {'request_id': 'resume-1', 'cause_id': 'request-1', 'expected_version': 1}
        assert (await client.post('/api/v1/scopes/desk/resume', headers=headers, json=resume)).status_code == 404
        assert (await client.get('/api/v1/scopes/desk/resume-status', params={'operation_id': 'resume-1'})).status_code == 404
        assert (await client.post('/api/v1/scopes/desk/requests/prepare', headers={**headers, 'X-Gateway-Route': '0' * 64}, json={**body, 'view_receipt': 'x'})).status_code == 409
        assert (await client.get('/api/v1/scopes/desk/cause', params={'cause_id': '原因/一'})).status_code == 404
        assert (await client.get('/api/v1/scopes/desk/targets', params={'cause_id': '原因/一'})).status_code == 404
        assert (await client.post('/api/v1/scopes/desk/targets/drain', headers=headers,
                                 json={'cause_id': '原因/一', 'reservation_id': 'target/1'})).status_code == 404
        assert (await client.get('/api/v1/scopes/other/causes')).status_code == 403
        assert (await client.post('/api/v1/scopes/desk/requests/prepare', headers=headers,
                                  json={**resume, 'mode': 'RESUME', 'view_receipt': 'x', 'expected_version': True})).status_code == 422
    run_requests(app, check)
    applies = [c for c in runtime.calls if c[1] == 'direct.control.apply']
    assert not applies
    assert all(c[3]['account_ref'] == 'account-a' and c[3]['scope_ref'] == 'scope-a' for c in runtime.calls)
    assert not runtime.closed


def test_host_origin_csrf_identity_grant_and_unknown():
    app, runtime = make_app()
    async def check(client):
        path = '/api/v1/scopes/desk/requests/prepare'
        body = {'request_id': 'stable', 'mode': 'FREEZE', 'view_receipt': 'x'}
        assert (await client.post(path, json=body)).status_code == 403
        assert (await client.post(path, json=body, headers={'Origin': 'http://evil.invalid', 'X-CSRF-Token': 'c' * 32})).status_code == 403
        assert (await client.post(path, json=body, headers={'Origin': 'http://127.0.0.1:8000', 'X-CSRF-Token': 'bad'})).status_code == 403
        assert (await client.get('/api/v1/session', headers={'Host': 'attacker.invalid'})).status_code == 403
        runtime.identity.principal_ref = 'other'
        assert (await client.get('/api/v1/scopes/desk/causes')).status_code == 403
        runtime.identity.principal_ref = 'operator-a'
        runtime.binding.operations = frozenset()
        assert (await client.get('/api/v1/scopes/desk/causes')).status_code == 403
        runtime.binding.operations = frozenset({'direct.control.apply'})
        runtime.fail = True
        route = (await client.get('/api/v1/session')).json()['scopes'][0]['route_fingerprint']
        response = await client.post(path, json=body, headers={'Origin': 'http://127.0.0.1:8000', 'X-CSRF-Token': 'c' * 32, 'X-Gateway-Route': route})
        assert response.json() == {'status': 'UNKNOWN', 'code': 'IDENTITY_UNAVAILABLE'}
        assert 'private diagnostic' not in response.text
    run_requests(app, check)
    async def remote(client):
        assert (await client.get('/api/v1/session')).status_code == 403
    run_requests(app, remote, client=('192.0.2.1', 1234))
    with pytest.raises(ValueError, match='INVALID_LOCAL_ORIGIN'):
        create_app(origin='http://0.0.0.0:8000', authenticate=lambda r: None, resolve_runtime=lambda s, r: None)


def test_drain_rejects_missing_or_stale_scope_fingerprint():
    from bt_api_base.service_protocol import WireIdentity, WireRole

    runtime = Runtime()
    runtime.identity = WireIdentity(WireRole.APPLICATION_CLIENT, 'operator-a', 'actor-a')
    runtime.binding.authenticated_peer = WireIdentity(WireRole.SERVICE, 'gateway-p', 'gateway-a')
    runtime.binding.server_key_fingerprint = 'a' * 64
    runtime.binding.registration_id = 'reg-1'; runtime.binding.service_epoch = 'epoch-1'
    runtime.binding.operations = frozenset({'direct.control.identity', 'direct.control.list', 'direct.control.targets', 'direct.control.drain_target', 'direct.control.target_status'})
    target_state = ['PENDING']
    def call(mount, operation, args, **kwargs):
        runtime.calls.append((mount, operation, args, kwargs))
        if operation == 'direct.control.identity':
            return {'status': 'OBSERVED', 'schema_version': 1, 'account_scope': runtime.binding.scope.account_ref, 'journal_id': 'journal-1'}
        if operation == 'direct.control.list':
            return {'status': 'OBSERVED', 'causes': [{'cause_id': 'cause-1', 'mode': 'DRAIN', 'active': 1, 'version': 1}]}
        if operation == 'direct.control.targets':
            return {'status': 'OBSERVED', 'targets': [{'cause_id': 'cause-1', 'reservation_id': 'reservation-1', 'operation_id': 'operation-1', 'state': 'PENDING'}]}
        if operation == 'direct.control.target_status':
            return {'status': 'OBSERVED', 'target': {'cause_id': 'cause-1', 'reservation_id': 'reservation-1', 'operation_id': 'operation-1', 'state': target_state[0]}}
        if operation == 'direct.control.drain_target':
            assert args['expected_journal_id'] == 'journal-1'
            target_state[0] = 'UNKNOWN'
            return {'status': 'UNKNOWN'}
        raise AssertionError(operation)
    runtime.call = call
    first = WebScope('desk', 'account-a', 'scope-a', 'strategy-a')
    second = WebScope('desk', 'account-b', 'scope-b', 'strategy-b')
    current = [AuthenticatedWebSession('operator-a', 'actor-a', 'c' * 32, (first,))]
    app = create_app(origin='http://127.0.0.1:8000', authenticate=lambda request: current[0],
                     resolve_runtime=lambda session, scope: runtime)

    async def check(client):
        path = '/api/v1/scopes/desk/targets/prepare'
        headers = {'Origin': 'http://127.0.0.1:8000', 'X-CSRF-Token': 'c' * 32}
        old_route = (await client.get('/api/v1/session')).json()['scopes'][0]['route_fingerprint']
        old_headers = {**headers, 'X-Gateway-Route': old_route}
        old_cause = (await client.get('/api/v1/scopes/desk/causes')).json()['causes'][0]
        query = '/api/v1/scopes/desk/targets/query'
        old_target = (await client.post(query, headers=old_headers, json={'view_receipt': old_cause['view_receipt']})).json()['targets'][0]
        body = {'cause_id': 'cause-1', 'reservation_id': 'reservation-1', 'operation_id': 'operation-1', 'view_receipt': old_target['view_receipt']}
        runtime.binding.authenticated_peer = WireIdentity(WireRole.SERVICE, 'gateway-p', 'new-service')
        runtime.binding.server_key_fingerprint = 'b' * 64
        assert (await client.post(query, headers=old_headers, json={'view_receipt': old_cause['view_receipt']})).json()['status'] == 'UNKNOWN'
        assert (await client.post(path, headers=old_headers, json=body)).json()['status'] == 'UNKNOWN'
        assert not [c for c in runtime.calls if c[1] == 'direct.control.drain_target']
        runtime.binding.authenticated_peer = WireIdentity(WireRole.SERVICE, 'gateway-p', 'gateway-a')
        runtime.binding.server_key_fingerprint = 'a' * 64
        assert (await client.post(path, headers=headers, json=body)).status_code == 409
        prepared = (await client.post(path, headers={**headers, 'X-Gateway-Route': old_route}, json=body)).json()
        assert prepared['status'] == 'PREPARED'
        receipt = {'receipt': prepared['receipt']}
        prior_calls = len(runtime.calls)
        current[0] = AuthenticatedWebSession('operator-a', 'actor-a', 'c' * 32, (second,))
        runtime.binding.scope_ref = 'scope-b'
        runtime.binding.scope.account_ref = 'account-b'
        runtime.binding.scope.strategy_ref = 'strategy-b'
        assert (await client.post(path, headers={**headers, 'X-Gateway-Route': old_route}, json=body)).status_code == 409
        assert len(runtime.calls) == prior_calls
        run_path = '/api/v1/scopes/desk/requests/run'
        assert (await client.post(run_path, headers={**headers, 'X-Gateway-Route': old_route}, json=receipt)).status_code == 409
        new_route = (await client.get('/api/v1/session')).json()['scopes'][0]['route_fingerprint']
        assert (await client.post(run_path, headers={**headers, 'X-Gateway-Route': new_route}, json=receipt)).json()['status'] == 'UNKNOWN'
        assert not [c for c in runtime.calls if c[1] == 'direct.control.drain_target']
        new_headers = {**headers, 'X-Gateway-Route': new_route}
        new_cause = (await client.get('/api/v1/scopes/desk/causes')).json()['causes'][0]
        new_target = (await client.post(query, headers=new_headers, json={'view_receipt': new_cause['view_receipt']})).json()['targets'][0]
        body['view_receipt'] = new_target['view_receipt']
        prepared = (await client.post(path, headers={**headers, 'X-Gateway-Route': new_route}, json=body)).json()
        assert prepared['status'] == 'PREPARED'
        target_receipt = {'receipt': prepared['receipt']}
        assert (await client.post(run_path, headers={**headers, 'X-Gateway-Route': new_route}, json=target_receipt)).json()['status'] == 'UNKNOWN'
        assert (await client.post(run_path, headers={**headers, 'X-Gateway-Route': new_route}, json=target_receipt)).json()['status'] == 'UNKNOWN'
        assert len([c for c in runtime.calls if c[1] == 'direct.control.drain_target']) == 1
    run_requests(app, check)


def test_signed_request_binds_journal_peer_identity_and_content():
    from bt_api_base.service_protocol import WireIdentity, WireRole

    runtime = Runtime()
    runtime.identity = WireIdentity(WireRole.APPLICATION_CLIENT, 'operator-a', 'actor-a')
    runtime.binding.authenticated_peer = WireIdentity(WireRole.SERVICE, 'gateway-p', 'gateway-a')
    runtime.binding.server_key_fingerprint = 'a' * 64
    runtime.binding.registration_id = 'registration-1'
    runtime.binding.service_epoch = 'epoch-1'
    runtime.binding.operations = frozenset({'direct.control.identity', 'direct.control.list', 'direct.control.status',
                                           'direct.control.resume_status', 'direct.control.apply', 'direct.control.resume'})
    runtime.journal = 'journal-1'
    runtime.records = {}
    runtime.lose_reply = False
    runtime.change_binding_on_status = False
    def call(mount, operation, arguments, **kwargs):
        runtime.calls.append((mount, operation, arguments, kwargs))
        if operation == 'direct.control.identity':
            return {'status': 'OBSERVED', 'schema_version': 1, 'account_scope': 'account-a', 'journal_id': runtime.journal}
        if operation == 'direct.control.list':
            return {'status': 'OBSERVED', 'causes': [{'cause_id': 'historical', 'mode': 'FREEZE', 'active': 1, 'version': 3}]}
        if operation == 'direct.control.status':
            key = arguments['cause_id']
            if runtime.change_binding_on_status:
                runtime.binding.service_epoch = 'epoch-interrupted'
            return {'status': 'OBSERVED', 'cause': runtime.records[key]} if key in runtime.records else {'status': 'NOT_FOUND', 'cause_id': key}
        if operation == 'direct.control.apply':
            assert arguments['expected_journal_id'] == runtime.journal
            runtime.records[arguments['cause_id']] = {'cause_id': arguments['cause_id'], 'mode': arguments['mode']}
            if runtime.lose_reply:
                raise TimeoutError()
            return {'status': 'OBSERVED', 'cause_id': arguments['cause_id']}
        raise AssertionError(operation)
    runtime.call = call
    scope = WebScope('desk', 'account-a', 'scope-a', 'strategy-a')
    session = AuthenticatedWebSession('operator-a', 'actor-a', 'c' * 32, (scope,))
    def make(key, key_id='host-v1'):
        return create_app(origin='http://127.0.0.1:8000', authenticate=lambda request: session,
                          resolve_runtime=lambda identity, selected: runtime, receipt_key=key, receipt_key_id=key_id)

    async def check(client):
        route = (await client.get('/api/v1/session')).json()['scopes'][0]['route_fingerprint']
        headers = {'Origin': 'http://127.0.0.1:8000', 'X-CSRF-Token': 'c' * 32, 'X-Gateway-Route': route}
        visible = (await client.get('/api/v1/scopes/desk/causes')).json()
        view = visible['scope_receipt']
        command = {'request_id': 'original-1', 'mode': 'FREEZE', 'cause_id': '', 'expected_version': 0, 'view_receipt': view}
        runtime.binding.authenticated_peer = WireIdentity(WireRole.SERVICE, 'other-p', 'other-gateway')
        runtime.binding.server_key_fingerprint = 'b' * 64
        runtime.journal = 'journal-2'
        assert (await client.post('/api/v1/scopes/desk/requests/prepare', headers=headers, json=command)).json()['status'] == 'UNKNOWN'
        resume = {'request_id': 'original-resume', 'mode': 'RESUME', 'cause_id': 'historical', 'expected_version': 3, 'view_receipt': visible['causes'][0]['view_receipt']}
        assert (await client.post('/api/v1/scopes/desk/requests/prepare', headers=headers, json=resume)).json()['status'] == 'UNKNOWN'
        assert not [c for c in runtime.calls if c[1] == 'direct.control.apply']
        runtime.binding.authenticated_peer = WireIdentity(WireRole.SERVICE, 'gateway-p', 'gateway-a')
        runtime.binding.server_key_fingerprint = 'a' * 64
        runtime.journal = 'journal-1'
        runtime.journal = 'journal-2'
        assert (await client.post('/api/v1/scopes/desk/requests/prepare', headers=headers, json=command)).json()['status'] == 'UNKNOWN'
        runtime.journal = 'journal-1'
        prepared = (await client.post('/api/v1/scopes/desk/requests/prepare', headers=headers, json=command)).json()
        assert prepared['status'] == 'PREPARED'
        receipt = {'receipt': prepared['receipt']}
        path = '/api/v1/scopes/desk/requests/'
        assert (await client.post(path + 'status', headers=headers, json=receipt)).json()['status'] == 'NOT_FOUND'
        altered = {'receipt': prepared['receipt'][:-3] + 'AAA'}
        assert (await client.post(path + 'run', headers=headers, json=altered)).json()['status'] == 'UNKNOWN'
        runtime.binding.server_key_fingerprint = 'b' * 64
        assert (await client.post(path + 'run', headers=headers, json=receipt)).json()['status'] == 'UNKNOWN'
        runtime.binding.server_key_fingerprint = 'a' * 64
        runtime.binding.authenticated_peer = WireIdentity(WireRole.SERVICE, 'gateway-p', 'other-gateway')
        assert (await client.post(path + 'run', headers=headers, json=receipt)).json()['status'] == 'UNKNOWN'
        runtime.binding.authenticated_peer = WireIdentity(WireRole.SERVICE, 'gateway-p', 'gateway-a')
        runtime.journal = 'journal-2'
        assert (await client.post(path + 'run', headers=headers, json=receipt)).json()['status'] == 'UNKNOWN'
        runtime.journal = 'journal-1'
        runtime.change_binding_on_status = True
        assert (await client.post(path + 'status', headers=headers, json=receipt)).json()['status'] == 'UNKNOWN'
        runtime.change_binding_on_status = False
        runtime.binding.registration_id = 'registration-2'
        runtime.binding.service_epoch = 'epoch-2'
        runtime.lose_reply = True
        assert (await client.post(path + 'run', headers=headers, json=receipt)).json()['status'] == 'UNKNOWN'
        runtime.lose_reply = False
        assert (await client.post(path + 'status', headers=headers, json=receipt)).json()['status'] == 'OBSERVED'
        assert (await client.post(path + 'run', headers=headers, json=receipt)).json()['status'] == 'OBSERVED'
        assert len([c for c in runtime.calls if c[1] == 'direct.control.apply']) == 1
        return headers, receipt
    headers, receipt = run_requests(make(b'k' * 32), check)
    async def check_restart(client):
        return (await client.post('/api/v1/scopes/desk/requests/status', headers=headers, json=receipt)).json()['status']
    assert run_requests(make(b'k' * 32), check_restart) == 'OBSERVED'
    assert run_requests(make(b'z' * 32), check_restart) == 'UNKNOWN'
    assert run_requests(make(b'k' * 32, 'host-v2'), check_restart) == 'UNKNOWN'


def test_snapshot_requires_separate_read_authority_and_secret_redaction():
    app, runtime = make_app()
    async def denied(client):
        assert (await client.get('/api/v1/scopes/desk/snapshot')).status_code == 403
    run_requests(app, denied)
    runtime.binding.mount = 'application.account'
    runtime.binding.operations = frozenset({'account.snapshot'})
    scope = WebScope('desk', 'account-a', 'scope-a', 'strategy-a')
    session = AuthenticatedWebSession('operator-a', 'actor-a', 'c' * 32, (scope,))
    seen = []
    app = create_app(origin='http://127.0.0.1:8000', authenticate=lambda r: session,
        resolve_runtime=lambda s, r: runtime, read_snapshot=lambda s, r: seen.append(True) or {'status': 'OBSERVED'})
    async def no_secret(client):
        r = await client.get('/api/v1/scopes/desk/snapshot')
        assert r.json() == {'status': 'UNAVAILABLE', 'reason': 'SOURCE_PROVENANCE_UNAVAILABLE'}
        assert not seen
        # A same-scope account binding switches peer/journal after the first read.
        runtime.binding.authenticated_peer = WireIdentity(WireRole.SERVICE, 'other-p', 'other-service')
        runtime.binding.server_key_fingerprint = 'b' * 64
        r = await client.get('/api/v1/scopes/desk/snapshot')
        assert r.json() == {'status': 'UNAVAILABLE', 'reason': 'SOURCE_PROVENANCE_UNAVAILABLE'}
        assert not seen
    run_requests(app, no_secret)


def test_bundled_assets_are_present_and_missing_assets_fail_closed(tmp_path, monkeypatch):
    import bt_api_gateway.web.app as module

    assert (module.bundled_static_dir() / 'index.html').is_file()
    monkeypatch.setattr(module, '__file__', str(tmp_path / 'app.py'))
    with pytest.raises(RuntimeError, match='GATEWAY_WEB_STATIC_NOT_BUILT'):
        module.bundled_static_dir()
