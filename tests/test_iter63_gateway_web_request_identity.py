"""A request id already used by another command is never reported as this request.

Fake runtimes are trusted host test fixtures; each case changes exactly one
field of the record the Gateway returns for the request id.
"""
import hashlib

import pytest
from test_iter63_gateway_web import Runtime, run_requests

from bt_api_gateway.web.app import AuthenticatedWebSession, WebScope, create_app

ORIGIN = 'http://127.0.0.1:8000'
CONFLICT = {'status': 'REQUEST_REJECTED', 'code': 'REQUEST_ID_CONFLICT'}


def _origin(principal, actor):
    return 'operator:' + hashlib.sha256(f'["{principal}","{actor}"]'.encode()).hexdigest()


def _own_cause(strategy):
    return {'cause_id': 'request-1', 'mode': 'FREEZE', 'active': 1, 'version': 1,
            'scope_kind': 'account' if strategy is None else 'strategy',
            'scope_value': '' if strategy is None else strategy,
            'origin': _origin('operator-a', 'actor-a')}


OWN_RELEASE = {'status': 'OBSERVED', 'cause_id': 'cause-1', 'operation_id': 'request-1',
               'version': 2, 'active': False}


def _app(strategy, status_reply):
    runtime = Runtime()
    runtime.binding.scope.strategy_ref = strategy
    writes = []

    def call(mount, operation, arguments, **kwargs):
        runtime.calls.append((mount, operation, arguments, kwargs))
        if operation == 'direct.control.identity':
            return {'status': 'OBSERVED', 'schema_version': 1, 'account_scope': 'account-a', 'journal_id': 'journal-1'}
        if operation == 'direct.control.list':
            return {'status': 'OBSERVED', 'causes': [{'cause_id': 'cause-1', 'mode': 'FREEZE', 'active': 1,
                                                      'version': 1}]}
        if operation in {'direct.control.status', 'direct.control.resume_status'}:
            return status_reply
        writes.append(operation)
        return {'status': 'OBSERVED'}
    runtime.call = call
    session = AuthenticatedWebSession('operator-a', 'actor-a', 'c' * 32,
                                      (WebScope('desk', 'account-a', 'scope-a', strategy),))
    app = create_app(origin=ORIGIN, authenticate=lambda request: session,
                     resolve_runtime=lambda identity, selected: runtime)
    return app, writes


def _status_and_run(app, mode):
    async def check(client):
        route = (await client.get('/api/v1/session')).json()['scopes'][0]['route_fingerprint']
        headers = {'Origin': ORIGIN, 'X-CSRF-Token': 'c' * 32, 'X-Gateway-Route': route}
        view = (await client.get('/api/v1/scopes/desk/causes')).json()
        if mode == 'RESUME':
            command = {'request_id': 'request-1', 'mode': 'RESUME', 'cause_id': 'cause-1', 'expected_version': 1,
                       'view_receipt': view['causes'][0]['view_receipt']}
        else:
            command = {'request_id': 'request-1', 'mode': mode, 'view_receipt': view['scope_receipt']}
        prepared = (await client.post('/api/v1/scopes/desk/requests/prepare', headers=headers, json=command)).json()
        assert prepared['status'] == 'PREPARED', prepared
        receipt = {'receipt': prepared['receipt']}
        status = (await client.post('/api/v1/scopes/desk/requests/status', headers=headers, json=receipt)).json()
        run = (await client.post('/api/v1/scopes/desk/requests/run', headers=headers, json=receipt)).json()
        return status, run
    return run_requests(app, check)


@pytest.mark.parametrize('strategy', [None, 'strategy-a'])
@pytest.mark.parametrize('field, value', [
    pytest.param(None, None, id='own'), pytest.param('cause_id', 'request-2', id='cause_id'),
    pytest.param('mode', 'STOP_NEW', id='mode'), pytest.param('scope_kind', 'instrument', id='scope_kind'),
    pytest.param('scope_value', 'strategy-b', id='scope_value'),
    pytest.param('origin', _origin('operator-b', 'actor-a'), id='other-principal'),
    pytest.param('origin', _origin('operator-a', 'actor-b'), id='other-actor'),
])
def test_observed_cause_must_be_this_operators_request(strategy, field, value):
    cause = _own_cause(strategy)
    if field is not None:
        cause[field] = value
    reply = {'status': 'OBSERVED', 'cause': cause}
    app, writes = _app(strategy, reply)
    status, run = _status_and_run(app, 'FREEZE')
    expected = reply if field is None else CONFLICT
    assert status == expected and run == expected
    assert writes == []


@pytest.mark.parametrize('field, value', [
    (None, None), ('cause_id', 'cause-2'), ('operation_id', 'request-2'), ('version', 3), ('active', True),
])
def test_observed_release_must_be_this_release(field, value):
    reply = dict(OWN_RELEASE)
    if field is not None:
        reply[field] = value
    app, writes = _app(None, reply)
    status, run = _status_and_run(app, 'RESUME')
    expected = reply if field is None else CONFLICT
    assert status == expected and run == expected
    assert writes == []


def test_observed_cause_without_its_record_is_a_conflict():
    app, writes = _app(None, {'status': 'OBSERVED', 'cause_id': 'request-1'})
    assert _status_and_run(app, 'FREEZE') == (CONFLICT, CONFLICT)
    assert writes == []
