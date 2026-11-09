"""Synthetic Web -> authenticated CURVE -> Gateway owner/journal integration."""
import queue
import socket
import threading

import pytest

zmq = pytest.importorskip('zmq')
pytest.importorskip('bt_api_py')

from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope
from bt_api_gateway.direct_command_journal import GatewayDirectCommandJournal
from bt_api_gateway.direct_dispatch import GatewayDirectDispatcher
from bt_api_gateway.session_guard import LocalAccountSessionGuard
from bt_api_gateway.web.app import AuthenticatedWebSession, WebScope, create_app
from bt_api_py.gateway_direct_owner import GatewayDirectOwner, GatewayDirectOwnerResources
from bt_api_py.gateway_direct_service import GatewayControlGrant, GatewayDirectGrant, GatewayDirectServiceBinding
from bt_api_py.service_components import ComponentResources
from bt_api_py.service_config import parse_client_config, parse_service_config
from bt_api_py.service_host import ServiceHost, TrustedServiceAuthority
from bt_api_py.service_registry import PrincipalGrant, ResourceGrant
from bt_api_py.service_runtime import ClientCurveKeys, ServiceClientRuntime, ZmqTransportFactory
from bt_api_py.service_runtime_thread import ThreadedServiceClientRuntime
from test_iter63_gateway_web import run_requests

OPS = frozenset({'direct.control.identity', 'direct.control.apply', 'direct.control.resume',
                 'direct.control.status', 'direct.control.list', 'direct.control.resume_status'})
ACCOUNT = 'synthetic-account'
DOMAIN = 'paper:synthetic-web'
CLIENT = WireIdentity(WireRole.APPLICATION_CLIENT, 'synthetic-operator', 'synthetic-app')
SERVICE = WireIdentity(WireRole.SERVICE, 'synthetic-gateway', 'synthetic-service')


def test_web_signed_original_request_over_curve_owner(tmp_path):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        endpoint = f'tcp://127.0.0.1:{probe.getsockname()[1]}'
    server_keys, client_keys = zmq.curve_keypair(), zmq.curve_keypair()
    service_config = parse_service_config({
        'service_config_schema_version': 1, 'process_role': 'service', 'service_id': SERVICE.actor_ref,
        'scope_ref': 'scope-a', 'transport_ref': 'server', 'registration_policy_ref': 'policy',
        'service_requirements_ref': 'requirements',
        'components': {'gateway': {'config_schema_version': 2, 'settings': {'instance_id': 'gateway-a',
            'bind_ports': ['service.direct_write'], 'options': {'role': 'trading_owner', 'dispatch_enabled': True, 'control_enabled': True}}}},
        'communication': {'config_schema_version': 1, 'profiles': {'server': {'backend': 'zmq',
            'config_schema_version': 1, 'endpoints': {'rpc_bind': endpoint}, 'security_profile_ref': 'key-a'}}},
    })
    client_config = parse_client_config({
        'client_config_schema_version': 1, 'process_role': 'application_client',
        'registration': {'application_ref': CLIENT.actor_ref},
        'clients': {'gateway': {'config_schema_version': 1, 'settings': {'bindings': [{
            'mount': 'application.direct_write', 'service_id': SERVICE.actor_ref, 'instance_id': 'gateway-a',
            'scope_ref': 'scope-a', 'account_ref': ACCOUNT, 'transport_ref': 'client'}],
            'options': {'request_timeout_ms': 2000}}}},
        'communication': {'config_schema_version': 1, 'profiles': {'client': {'backend': 'zmq',
            'config_schema_version': 1, 'endpoints': {'rpc_connect': endpoint}, 'security_profile_ref': 'key-a'}}},
    })
    scope = WireScope(DOMAIN, account_ref=ACCOUNT)
    grant = ResourceGrant('gateway-a', 'service.direct_write', 'scope-a', scope, OPS)
    authority = TrustedServiceAuthority(identity=SERVICE, scope=WireScope(DOMAIN), scope_ref='scope-a',
        scope_version='v1', security_ref='key-a', security_version='v1', registration_policy_ref='policy',
        registration_policy_version='v1', service_requirements_ref='requirements', service_requirements_version='v1',
        curve_public_key=server_keys[0], curve_secret_key=server_keys[1],
        principals={client_keys[0]: CLIENT.principal_ref}, grants={CLIENT.principal_ref: (PrincipalGrant(CLIENT, (grant,)),)})
    ready = queue.Queue()
    stop = threading.Event()
    (tmp_path / 'guard').mkdir()

    def serve():
        owner = host = None
        try:
            owned = []
            def factory():
                guard = LocalAccountSessionGuard(tmp_path / 'guard', ACCOUNT, 'synthetic-owner')
                journal = GatewayDirectCommandJournal.create(tmp_path / 'journal.sqlite', ACCOUNT, generation=guard.acquire())
                dispatcher = GatewayDirectDispatcher(journal, 'TEST', guard, lambda *_: None, lambda _: (), lambda _: True)
                owned.append((journal, guard))
                return GatewayDirectOwnerResources(dispatcher, journal, guard.release)
            owner = GatewayDirectOwner(factory, queue_size=4, max_queue_wait_seconds=10, busy_timeout_seconds=10)
            assert owner.start(10)
            journal, guard = owned[0]
            control = owner.submit_service_call(lambda: journal.enable_controls(guard)).result(timeout_seconds=5)
            binding = GatewayDirectServiceBinding(journal, {'strategy-p': GatewayDirectGrant('strategy-a', frozenset({'X'}))},
                owner=owner, control=control, control_grants={CLIENT.principal_ref: GatewayControlGrant(CLIENT.actor_ref, True, frozenset(), OPS)})
            host = ServiceHost(service_config, authority, tmp_path / 'registry.sqlite',
                lambda *_: ComponentResources.borrowed({'binding': binding}, ready=lambda: True))
            host.start()
            ready.put(('ready', journal.journal_id))
            while not stop.is_set():
                host.serve_once(10)
        except BaseException as exc:
            ready.put(('error', type(exc).__name__, str(exc)))
        finally:
            if host is not None and host.state == 'started':
                host.close()
            if owner is not None:
                owner.close(10)

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    runtime = None
    try:
        started = ready.get(timeout=20)
        assert started[0] == 'ready', started
        def runtime_factory():
            return ServiceClientRuntime(client_config, identity=CLIENT, scope_resolver=lambda _: scope,
                peer_resolver=lambda _: SERVICE, transport_factory=ZmqTransportFactory({
                    'key-a': ClientCurveKeys(server_keys[0], client_keys[0], client_keys[1])}),
                requested_operations={'application.direct_write': OPS})
        runtime = ThreadedServiceClientRuntime(runtime_factory)
        state = runtime.start(timeout_seconds=10)
        assert state.healthy and state.bindings[0].authenticated_peer == SERVICE
        identity_result = runtime.call('application.direct_write', 'direct.control.identity', {},
            account_ref=ACCOUNT, scope_ref='scope-a', timeout_seconds=5)
        assert identity_result.get('journal_id') == started[1], identity_result
        web_scope = WebScope('desk', ACCOUNT, 'scope-a')
        web_session = AuthenticatedWebSession(CLIENT.principal_ref, CLIENT.actor_ref, 'c' * 32, (web_scope,))
        app = create_app(origin='http://127.0.0.1:8000', authenticate=lambda request: web_session,
            resolve_runtime=lambda session, selected: runtime, receipt_key=b'k' * 32, receipt_key_id='test-v1')
        async def check(browser):
            route = (await browser.get('/api/v1/session')).json()['scopes'][0]['route_fingerprint']
            headers = {'Origin': 'http://127.0.0.1:8000', 'X-CSRF-Token': 'c' * 32, 'X-Gateway-Route': route}
            root = '/api/v1/scopes/desk/requests/'
            view = (await browser.get('/api/v1/scopes/desk/causes')).json()
            command = {'request_id': 'synthetic-freeze-1', 'mode': 'FREEZE', 'cause_id': '', 'expected_version': 0, 'view_receipt': view['scope_receipt']}
            prepared = (await browser.post(root + 'prepare', headers=headers, json=command)).json()
            assert prepared['status'] == 'PREPARED', prepared
            receipt = {'receipt': prepared['receipt']}
            assert (await browser.post(root + 'status', headers=headers, json=receipt)).json()['status'] == 'NOT_FOUND'
            result = (await browser.post(root + 'run', headers=headers, json=receipt)).json()
            assert result['status'] == 'OBSERVED' and result['active'] is True, result
            observed = (await browser.post(root + 'run', headers=headers, json=receipt)).json()
            assert observed['status'] == 'OBSERVED' and observed['cause']['cause_id'] == command['request_id']
            view = (await browser.get('/api/v1/scopes/desk/causes')).json()
            cause, = view['causes']
            resume = {'request_id': 'synthetic-resume-1', 'mode': 'RESUME',
                      'cause_id': command['request_id'], 'expected_version': 1, 'view_receipt': cause['view_receipt']}
            prepared = (await browser.post(root + 'prepare', headers=headers, json=resume)).json()
            assert prepared['status'] == 'PREPARED', prepared
            resume_receipt = {'receipt': prepared['receipt']}
            assert (await browser.post(root + 'status', headers=headers, json=resume_receipt)).json()['status'] == 'NOT_FOUND'
            result = (await browser.post(root + 'run', headers=headers, json=resume_receipt)).json()
            assert result['status'] == 'OBSERVED' and result['active'] is False, result
            result = (await browser.post(root + 'status', headers=headers, json=resume_receipt)).json()
            assert result['status'] == 'OBSERVED' and result['operation_id'] == resume['request_id'], result
            view = (await browser.get('/api/v1/scopes/desk/causes')).json()
            pending = {'request_id': 'synthetic-freeze-2', 'mode': 'FREEZE', 'cause_id': '', 'expected_version': 0, 'view_receipt': view['scope_receipt']}
            prepared = (await browser.post(root + 'prepare', headers=headers, json=pending)).json()
            assert prepared['status'] == 'PREPARED', prepared
            return headers, {'receipt': prepared['receipt']}
        headers, pending_receipt = run_requests(app, check)
        original_registration = state.bindings[0].registration_id
        runtime.close(timeout_seconds=10)
        runtime = ThreadedServiceClientRuntime(runtime_factory)
        state = runtime.start(timeout_seconds=10)
        assert state.healthy and state.bindings[0].registration_id != original_registration
        restarted_app = create_app(origin='http://127.0.0.1:8000', authenticate=lambda request: web_session,
            resolve_runtime=lambda session, selected: runtime, receipt_key=b'k' * 32, receipt_key_id='test-v1')
        async def check_restarted(browser):
            root = '/api/v1/scopes/desk/requests/'
            assert (await browser.post(root + 'status', headers=headers, json=pending_receipt)).json()['status'] == 'NOT_FOUND'
            result = (await browser.post(root + 'run', headers=headers, json=pending_receipt)).json()
            assert result['status'] == 'OBSERVED' and result['active'] is True, result
        run_requests(restarted_app, check_restarted)
    finally:
        if runtime is not None:
            runtime.close(timeout_seconds=10)
        stop.set()
        server.join(15)
        assert not server.is_alive()
