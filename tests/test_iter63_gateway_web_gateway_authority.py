"""Web API v1 against a real Gateway control plane over authenticated CURVE.

Synthetic account, journal and operators only; no venue and no real account.
Every operation still goes through the Gateway's Registry and control grants:
these tests check that the Web layer neither widens nor hides that authority.
"""
import asyncio
import hashlib
import json
import queue
import socket
import threading
import time
from datetime import UTC, datetime

import pytest

zmq = pytest.importorskip('zmq')
pytest.importorskip('bt_api_py')

import httpx  # noqa: E402
from bt_api_base.account_protocol import (  # noqa: E402
    AccountBalance,
    AccountKey,
    AccountObservation,
    AccountResourceKey,
)
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope  # noqa: E402
from bt_api_py.gateway_direct_owner import (  # noqa: E402
    GatewayDirectOwner,
    GatewayDirectOwnerResources,
)
from bt_api_py.gateway_direct_service import (  # noqa: E402
    GatewayControlGrant,
    GatewayDirectGrant,
    GatewayDirectServiceBinding,
)
from bt_api_py.service_components import ComponentResources  # noqa: E402
from bt_api_py.service_config import parse_client_config, parse_service_config  # noqa: E402
from bt_api_py.service_host import ServiceHost, TrustedServiceAuthority  # noqa: E402
from bt_api_py.service_registry import PrincipalGrant, ResourceGrant  # noqa: E402
from bt_api_py.service_runtime import (  # noqa: E402
    ClientCurveKeys,
    ServiceClientRuntime,
    ZmqTransportFactory,
)
from bt_api_py.service_runtime_thread import ThreadedServiceClientRuntime  # noqa: E402

from bt_api_gateway.account_read_model import GatewayAccountReadModel  # noqa: E402
from bt_api_gateway.direct_command_journal import GatewayDirectCommandJournal  # noqa: E402
from bt_api_gateway.direct_dispatch import GatewayDirectDispatcher  # noqa: E402
from bt_api_gateway.event_journal import GatewayEventJournal  # noqa: E402
from bt_api_gateway.router import GatewayCommandKind, GatewayPrincipal  # noqa: E402
from bt_api_gateway.service_component import (  # noqa: E402
    GatewayReadService,
    GatewayServiceAccountScope,
)
from bt_api_gateway.session_guard import LocalAccountSessionGuard  # noqa: E402
from bt_api_gateway.web.app import AuthenticatedWebSession, WebScope, create_app  # noqa: E402

ACCOUNT = 'synthetic-account'
DOMAIN = 'paper:synthetic-web'
ORIGIN = 'http://127.0.0.1:8000'
OPS = frozenset({'direct.control.identity', 'direct.control.apply', 'direct.control.resume',
                 'direct.control.status', 'direct.control.list', 'direct.control.resume_status'})
SERVICE = WireIdentity(WireRole.SERVICE, 'synthetic-gateway', 'synthetic-service')
RB = {'symbol': 'rb', 'exchange_id': 'SHFE'}
CONTRACT_SCOPE = 'SHFE:rb'
CONTRACT_CAUSE = 'unresolved-return:SHFE:rb:0123456789abcdef'
NATIVE = {'exchange_name': 'CTP', 'client_order_id': 'o1', 'session_generation': 1, 'fields_json': '{}'}

# name -> (principal, actor, account, strategy, control grant: account scope allowed, strategies)
OPERATORS = {
    'account': ('web-account-op', 'web-account-app', ACCOUNT, None, True, frozenset()),
    'strategy': ('web-strategy-op', 'web-strategy-app', ACCOUNT, 'strategy-a', False, frozenset({'strategy-a'})),
    'cli': ('cli-op', 'cli-app', ACCOUNT, None, True, frozenset()),
    'other_account': ('web-other-op', 'web-other-app', 'other-account', None, True, frozenset()),
    'viewer': ('web-viewer-op', 'web-viewer-app', ACCOUNT, None, True, frozenset()),
}
# Operations granted in the Registry and the control grant; every other operator gets OPS.
VIEW_OPS = frozenset({'direct.control.identity', 'direct.control.list', 'direct.control.status',
                      'direct.control.resume_status'})
GRANTED = {'viewer': VIEW_OPS}


MAIN = AccountResourceKey('future', 'main')


def observation(account_key, available='90'):
    """One complete synthetic account read, observed now."""
    now = datetime.now(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z')
    return AccountObservation(
        account_key=account_key, observation_id='synthetic-' + available, coverage=(MAIN,),
        balances=(AccountBalance(MAIN, 'CNY', '100', available, None, now),), positions=(), valuation=None,
        started_at_utc=now, completed_at_utc=now, consistency='multi_query', balances_complete=True,
        positions_complete=True, open_orders=None, open_orders_complete=False)


def operator_origin(principal, actor):
    """The control-cause origin the Gateway records for an operator's own apply."""
    return 'operator:' + hashlib.sha256(json.dumps([principal, actor], separators=(',', ':')).encode()).hexdigest()


class Gateway:
    """One synthetic trading-owner Gateway serving on a loopback CURVE endpoint.

    ``account_reads`` (operator name -> operations) also binds the account read port with
    its own read journal and account read model, as the trading composition does; only the
    named operators get a registry resource on it. ``release_audit`` installs the journal's
    release audit (who released each cause is stored with the release).
    """

    def __init__(self, tmp_path, operators=OPERATORS, account_reads=None, release_audit=False):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            self.endpoint = f'tcp://127.0.0.1:{probe.getsockname()[1]}'
        self.server_keys = zmq.curve_keypair()
        self.operators = operators
        self.account_reads = dict(account_reads or {})
        self.release_audit = release_audit
        self.keys = {name: zmq.curve_keypair() for name in operators}
        self.tmp_path = tmp_path
        self.commands = queue.Queue()
        self.ready = queue.Queue()
        self.stop = threading.Event()
        self.runtimes = []
        self.owner = self.journal = self.control = self.read_model = self.read_service = None
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def identity(self, name):
        principal, actor = self.operators[name][:2]
        return WireIdentity(WireRole.APPLICATION_CLIENT, principal, actor)

    def scope(self, name):
        account, strategy = self.operators[name][2:4]
        return WireScope(DOMAIN, account_ref=account, strategy_ref=strategy)

    def _serve(self):
        owner = host = None
        try:
            config = parse_service_config({
                'service_config_schema_version': 1, 'process_role': 'service', 'service_id': SERVICE.actor_ref,
                'scope_ref': 'scope-a', 'transport_ref': 'server', 'registration_policy_ref': 'policy',
                'service_requirements_ref': 'requirements',
                'components': {'gateway': {'config_schema_version': 2, 'settings': {'instance_id': 'gateway-a',
                    'bind_ports': ['service.direct_write'] + (['service.account_read'] if self.account_reads else []),
                    'options': {'role': 'trading_owner', 'dispatch_enabled': True, 'control_enabled': True}}}},
                'communication': {'config_schema_version': 1, 'profiles': {'server': {'backend': 'zmq',
                    'config_schema_version': 1, 'endpoints': {'rpc_bind': self.endpoint},
                    'security_profile_ref': 'key-a'}}},
            })
            grants = {}
            principals = {}
            control_grants = {}
            for name, (principal, actor, _, _, account_allowed, strategies) in self.operators.items():
                ops = GRANTED.get(name, OPS)
                principals[self.keys[name][0]] = principal
                resources = (ResourceGrant('gateway-a', 'service.direct_write', 'scope-a', self.scope(name), ops),)
                if name in self.account_reads:
                    resources += (ResourceGrant('gateway-a', 'service.account_read', 'scope-a', self.scope(name),
                                                frozenset(self.account_reads[name])),)
                grants[principal] = (PrincipalGrant(self.identity(name), resources),)
                control_grants[principal] = GatewayControlGrant(actor, account_allowed, strategies, ops)
            authority = TrustedServiceAuthority(identity=SERVICE, scope=WireScope(DOMAIN), scope_ref='scope-a',
                scope_version='v1', security_ref='key-a', security_version='v1', registration_policy_ref='policy',
                registration_policy_version='v1', service_requirements_ref='requirements',
                service_requirements_version='v1', curve_public_key=self.server_keys[0],
                curve_secret_key=self.server_keys[1], principals=principals, grants=grants)
            (self.tmp_path / 'guard').mkdir()
            owned = []

            def factory():
                guard = LocalAccountSessionGuard(self.tmp_path / 'guard', ACCOUNT, 'synthetic-owner')
                journal = GatewayDirectCommandJournal.create(self.tmp_path / 'journal.sqlite', ACCOUNT,
                                                             generation=guard.acquire())
                dispatcher = GatewayDirectDispatcher(journal, 'TEST', guard, lambda *_: None, lambda _: (),
                                                     lambda _: True)
                owned.append((journal, guard))
                return GatewayDirectOwnerResources(dispatcher, journal, guard.release)

            owner = GatewayDirectOwner(factory, queue_size=8, max_queue_wait_seconds=10, busy_timeout_seconds=10)
            assert owner.start(10)
            journal, guard = owned[0]
            control = owner.submit_service_call(lambda: journal.enable_controls(guard)).result(timeout_seconds=5)
            if self.release_audit:
                owner.submit_service_call(
                    lambda: journal.enable_control_release_audit(guard)).result(timeout_seconds=5)
            binding = GatewayDirectServiceBinding(
                journal, {'strategy-p': GatewayDirectGrant('strategy-a', frozenset({'rb'}))},
                owner=owner, control=control, control_grants=control_grants)
            values = {'binding': binding}
            if self.account_reads:
                values['read_service'] = self._read_service(journal.generation)
            host = ServiceHost(config, authority, self.tmp_path / 'registry.sqlite',
                               lambda *_: ComponentResources.borrowed(values, ready=lambda: True))
            host.start()
            self.owner, self.journal, self.control = owner, journal, control
            self.ready.put(('ready',))
            while not self.stop.is_set():
                try:
                    callback, reply = self.commands.get_nowait()
                except queue.Empty:
                    pass
                else:
                    try:
                        reply.put(('ok', callback(host)))
                    except BaseException as exc:  # reported to the test thread
                        reply.put(('error', exc))
                host.serve_once(10)
        except BaseException as exc:
            self.ready.put(('error', type(exc).__name__, str(exc)))
        finally:
            if host is not None and host.state == 'started':
                host.close()
            if owner is not None:
                owner.close(10)

    def __enter__(self):
        self.thread.start()
        started = self.ready.get(timeout=20)
        assert started[0] == 'ready', started
        return self

    def __exit__(self, *exc):
        for runtime in self.runtimes:
            runtime.close(timeout_seconds=10)
        self.stop.set()
        self.thread.join(15)
        assert not self.thread.is_alive()

    def on_host(self, callback):
        """Run ``callback(host)`` on the serve thread, between two requests."""
        reply = queue.Queue()
        self.commands.put((callback, reply))
        kind, value = reply.get(timeout=10)
        if kind == 'error':
            raise value
        return value

    def on_owner(self, callback):
        return self.owner.submit_service_call(callback).result(timeout_seconds=5)

    def _read_service(self, owner_generation):
        """Account read port pieces, built on the serve thread (the read model's owner thread)."""
        journal = GatewayEventJournal(self.tmp_path / 'account-read.sqlite')
        model = GatewayAccountReadModel(
            journal, account_key=AccountKey('synthetic', 'venue', 'test', ACCOUNT),
            journal_account_scope=ACCOUNT, state_scope='state-a', required_coverage=(MAIN,),
            assert_current_generation=lambda _: None, max_staleness_seconds=30)
        model.start_generation(owner_generation)
        strategies = frozenset(self.operators[name][3] for name in self.account_reads
                               if self.operators[name][3] is not None)
        account = GatewayServiceAccountScope(
            account_ref=ACCOUNT, execution_domain_ref=DOMAIN, journal_account_scope=ACCOUNT,
            account_read_strategy_scope='state-a', shared_account_facts_scope='state-a' if strategies else None,
            shared_fact_strategy_refs=strategies)
        principals = {self.operators[name][0]: GatewayPrincipal(
            self.operators[name][0], frozenset({ACCOUNT}), frozenset({'state-a'}),
            frozenset({GatewayCommandKind.READ})) for name in self.account_reads}
        self.read_model = model
        self.read_service = GatewayReadService(journal, accounts={ACCOUNT: account}, principals=principals,
                                               state_worker=model)
        return self.read_service

    def publish(self, available='90'):
        """The owner's account read completes: one current observation enters the read model."""
        def run(_host):
            model = self.read_model
            model.finish_refresh(model.begin_refresh(), observation(model.account_key, available))
        self.on_host(run)

    def read_generation(self, generation):
        """The read model starts another generation (for example after a change of the venue link)."""
        self.on_host(lambda _host: self.read_model.start_generation(generation))

    def cause(self, cause_id):
        return self.on_owner(lambda: self.control.get(cause_id))

    def causes(self):
        def read():
            with self.journal._transaction() as db:
                return {row['cause_id']: dict(row) for row in db.execute('SELECT * FROM direct_control_causes')}
        return self.on_owner(read)

    def runtime(self, name):
        account = self.operators[name][2]
        binding = {'mount': 'application.direct_write', 'service_id': SERVICE.actor_ref, 'instance_id': 'gateway-a',
                   'scope_ref': 'scope-a', 'account_ref': account, 'transport_ref': 'client'}
        bindings = [binding] + ([{**binding, 'mount': 'application.account'}] if name in self.account_reads else [])
        requested = {'application.direct_write': GRANTED.get(name, OPS)}
        if name in self.account_reads:
            requested['application.account'] = frozenset(self.account_reads[name])
        client_config = parse_client_config({
            'client_config_schema_version': 1, 'process_role': 'application_client',
            'registration': {'application_ref': self.identity(name).actor_ref},
            'clients': {'gateway': {'config_schema_version': 1, 'settings': {'bindings': bindings,
                'options': {'request_timeout_ms': 2000}}}},
            'communication': {'config_schema_version': 1, 'profiles': {'client': {'backend': 'zmq',
                'config_schema_version': 1, 'endpoints': {'rpc_connect': self.endpoint},
                'security_profile_ref': 'key-a'}}},
        })
        keys = ClientCurveKeys(self.server_keys[0], self.keys[name][0], self.keys[name][1])
        identity, scope = self.identity(name), self.scope(name)
        runtime = ThreadedServiceClientRuntime(lambda: ServiceClientRuntime(
            client_config, identity=identity, scope_resolver=lambda _: scope, peer_resolver=lambda _: SERVICE,
            transport_factory=ZmqTransportFactory({'key-a': keys}),
            requested_operations=requested))
        self.runtimes.append(runtime)
        assert runtime.start(timeout_seconds=10).healthy
        return runtime


def cli_call(runtime, name, operation, arguments, gateway):
    """An operator's own SDK client (the CLI path): same mount, same Registry, no Web layer."""
    return runtime.call('application.direct_write', operation, arguments,
                        account_ref=gateway.operators[name][2], scope_ref='scope-a', timeout_seconds=5)


class WebHost:
    """A trusted test host: one session per operator, selected by a test header."""

    def __init__(self, gateway, names, runtimes=None, receipt_key=b'k' * 32):
        self.sessions = {}
        self.runtimes = dict(runtimes or {})
        for index, name in enumerate(names):
            principal, actor, account, strategy = gateway.operators[name][:4]
            self.sessions[name] = AuthenticatedWebSession(
                principal, actor, (str(index) * 40)[:40], (WebScope('desk', account, 'scope-a', strategy),))
            if name not in self.runtimes:
                self.runtimes[name] = gateway.runtime(name)
        by_principal = {self.sessions[name].principal_ref: name for name in names}

        def authenticate(request):
            return self.sessions[request.headers['x-test-user']]

        def resolve_runtime(session, scope):
            return self.runtimes[by_principal[session.principal_ref]]

        self.app = create_app(origin=ORIGIN, authenticate=authenticate, resolve_runtime=resolve_runtime,
                              receipt_key=receipt_key, receipt_key_id='test-v1')

    def run(self, callback):
        async def run():
            transport = httpx.ASGITransport(app=self.app, client=('127.0.0.1', 1234))
            async with httpx.AsyncClient(transport=transport, base_url=ORIGIN) as client:
                return await callback(Browser(client, self))
        return asyncio.run(run())


class Browser:
    def __init__(self, client, host):
        self.client, self.host = client, host

    async def headers(self, user, write=False):
        headers = {'X-Test-User': user}
        if write:
            route = (await self.client.get('/api/v1/session', headers=headers)).json()['scopes'][0]
            headers.update({'Origin': ORIGIN, 'X-CSRF-Token': self.host.sessions[user].csrf_token,
                            'X-Gateway-Route': route['route_fingerprint']})
        return headers

    async def causes(self, user):
        response = await self.client.get('/api/v1/scopes/desk/causes', headers=await self.headers(user))
        return response.status_code, response.json()

    async def post(self, user, path, body):
        response = await self.client.post('/api/v1/scopes/desk/' + path, headers=await self.headers(user, True),
                                          json=body)
        assert response.status_code == 200, (response.status_code, response.text)
        return response.json()

    async def prepare(self, user, body):
        return await self.post(user, 'requests/prepare', body)

    async def status(self, user, receipt):
        return await self.post(user, 'requests/status', {'receipt': receipt})

    async def run(self, user, receipt):
        return await self.post(user, 'requests/run', {'receipt': receipt})

    async def apply_command(self, user, request_id, mode='FREEZE'):
        code, view = await self.causes(user)
        assert code == 200 and view['status'] == 'OBSERVED', view
        return {'request_id': request_id, 'mode': mode, 'cause_id': '', 'expected_version': 0,
                'view_receipt': view['scope_receipt']}

    async def resume_command(self, user, request_id, cause_id):
        code, view = await self.causes(user)
        assert code == 200 and view['status'] == 'OBSERVED', view
        row, = [row for row in view['causes'] if row['cause_id'] == cause_id]
        return {'request_id': request_id, 'mode': 'RESUME', 'cause_id': cause_id,
                'expected_version': row['version'], 'view_receipt': row['view_receipt']}


def _undecided_order(gateway, request_key='going-out'):
    """One strategy order on the contract on its way to the venue, outcome not known yet."""
    def run():
        sent = gateway.journal.reserve('strategy-a', request_key, 'strategy-p', RB)
        gateway.journal.begin_dispatch('strategy-a', request_key, sent.reservation_id, sent.digest,
                                       'strategy-p', 1, NATIVE, ('anchor',))
        return sent
    return gateway.on_owner(run)


def _decide_order(gateway, sent, request_key='going-out'):
    gateway.on_owner(lambda: gateway.journal.finish('strategy-a', request_key, sent.reservation_id, sent.digest,
                                                    'strategy-p', 2, NATIVE, ('anchor',), 'SENT'))


def _block_contract(gateway):
    """What the unresolved-return watcher does (D63-59): a FREEZE cause scoped to one contract."""
    return gateway.on_owner(lambda: gateway.control.apply(
        CONTRACT_CAUSE, 'FREEZE', scope_kind='instrument', scope_value=CONTRACT_SCOPE,
        origin='system:unresolved_return:' + 'a' * 64))


def test_contract_cause_is_listed_released_only_by_account_scope_and_refusal_code_is_shown(tmp_path):
    with Gateway(tmp_path) as gateway:
        sent = _undecided_order(gateway)
        _block_contract(gateway)
        cli = gateway.runtime('cli')
        assert cli_call(cli, 'cli', 'direct.control.apply', {'cause_id': 'cli-freeze', 'mode': 'FREEZE'},
                        gateway)['active'] is True
        web = WebHost(gateway, ('account', 'strategy'))

        async def check(browser):
            code, account_view = await browser.causes('account')
            assert code == 200 and account_view['status'] == 'OBSERVED', account_view
            listed = {row['cause_id']: row for row in account_view['causes']}
            assert set(listed) == {'cli-freeze', CONTRACT_CAUSE}
            contract = listed[CONTRACT_CAUSE]
            assert (contract['scope_kind'], contract['scope_value'], contract['mode'], contract['active'],
                    contract['version']) == ('instrument', CONTRACT_SCOPE, 'FREEZE', 1, 1)

            # A strategy-scope operator does not see the cause and cannot release it through the Web.
            code, strategy_view = await browser.causes('strategy')
            assert code == 200 and strategy_view['status'] == 'OBSERVED' and strategy_view['causes'] == []
            stolen = {'request_id': 'strategy-release', 'mode': 'RESUME', 'cause_id': CONTRACT_CAUSE,
                      'expected_version': 1, 'view_receipt': contract['view_receipt']}
            assert await browser.prepare('strategy', stolen) == {'status': 'UNKNOWN', 'code': 'IDENTITY_UNAVAILABLE'}
            own_scope = {**stolen, 'view_receipt': strategy_view['scope_receipt']}
            assert await browser.prepare('strategy', own_scope) == {
                'status': 'UNKNOWN', 'code': 'IDENTITY_UNAVAILABLE'}
            # Bypassing the Web does not help: the Gateway refuses the same operator's own call.
            direct = cli_call(web.runtimes['strategy'], 'strategy', 'direct.control.resume',
                              {'cause_id': CONTRACT_CAUSE, 'expected_version': 1, 'operation_id': 'strategy-direct'},
                              gateway)
            assert direct['status'] != 'OBSERVED'
            assert gateway.cause(CONTRACT_CAUSE)['active'] == 1

            # The account-scope operator prepares the release; it is refused while an own order on
            # the contract has no known outcome, and the refusal code reaches the client.
            release = await browser.resume_command('account', 'web-release-rb', CONTRACT_CAUSE)
            prepared = await browser.prepare('account', release)
            assert prepared['status'] == 'PREPARED', prepared
            receipt = prepared['receipt']
            assert (await browser.status('account', receipt))['status'] == 'NOT_FOUND'
            assert await browser.run('account', receipt) == {
                'status': 'REQUEST_REJECTED', 'code': 'CONTRACT_ORDERS_UNDECIDED'}
            assert (await browser.status('account', receipt))['status'] == 'NOT_FOUND'
            assert gateway.cause(CONTRACT_CAUSE)['active'] == 1
            # The strategy-scope operator cannot use the account operator's prepared receipt either.
            assert await browser.run('strategy', receipt) == {'status': 'UNKNOWN', 'code': 'IDENTITY_UNAVAILABLE'}

            _decide_order(gateway, sent)
            released = await browser.run('account', receipt)
            assert released == {'status': 'OBSERVED', 'cause_id': CONTRACT_CAUSE, 'version': 2, 'active': False}
            again = await browser.run('account', receipt)
            assert again == {'status': 'OBSERVED', 'cause_id': CONTRACT_CAUSE, 'operation_id': 'web-release-rb',
                             'version': 2, 'active': False}
            assert await browser.status('account', receipt) == again

            # Releasing one cause is not shown as everything released: the other cause stays active.
            _, after = await browser.causes('account')
            state = {row['cause_id']: (row['active'], row['version']) for row in after['causes']}
            assert state == {'cli-freeze': (1, 1), CONTRACT_CAUSE: (0, 2)}

        web.run(check)
        stored = gateway.cause(CONTRACT_CAUSE)
        assert (stored['active'], stored['version'], stored['resume_id']) == (0, 2, 'web-release-rb')
        assert gateway.cause('cli-freeze')['active'] == 1


def test_web_and_cli_share_operations_and_the_journal_records_each_operator(tmp_path):
    with Gateway(tmp_path) as gateway:
        cli = gateway.runtime('cli')
        journal_id = cli_call(cli, 'cli', 'direct.control.identity', {}, gateway)['journal_id']
        web = WebHost(gateway, ('account',))

        async def check(browser):
            command = await browser.apply_command('account', 'web-freeze-1')
            prepared = await browser.prepare('account', command)
            assert prepared['status'] == 'PREPARED', prepared
            applied = await browser.run('account', prepared['receipt'])
            assert applied == {'status': 'OBSERVED', 'cause_id': 'web-freeze-1', 'version': 1, 'active': True}
            # The CLI sees the Web's cause and the Web sees the CLI's: one control plane.
            assert cli_call(cli, 'cli', 'direct.control.apply', {'cause_id': 'cli-stop-1', 'mode': 'STOP_NEW',
                            'expected_journal_id': journal_id}, gateway)['active'] is True
            listed = cli_call(cli, 'cli', 'direct.control.list', {'after': '', 'limit': 10}, gateway)
            assert {row['cause_id'] for row in listed['causes']} == {'web-freeze-1', 'cli-stop-1'}
            # The Web releases the CLI's cause through the same Gateway operation.
            release = await browser.resume_command('account', 'web-release-cli', 'cli-stop-1')
            prepared = await browser.prepare('account', release)
            assert (await browser.run('account', prepared['receipt']))['active'] is False
            # And the CLI releases the Web's cause.
            assert cli_call(cli, 'cli', 'direct.control.resume', {'cause_id': 'web-freeze-1', 'expected_version': 1,
                            'operation_id': 'cli-release-web', 'expected_journal_id': journal_id},
                            gateway)['active'] is False

        web.run(check)
        causes = gateway.causes()
        # Each apply is recorded with the identity of the operator who made it, computed by the
        # Gateway from the authenticated registration; the Web host adds no identity of its own.
        assert causes['web-freeze-1']['origin'] == operator_origin('web-account-op', 'web-account-app')
        assert causes['cli-stop-1']['origin'] == operator_origin('cli-op', 'cli-app')
        assert causes['web-freeze-1']['origin'] != causes['cli-stop-1']['origin']
        assert (causes['cli-stop-1']['resume_id'], causes['web-freeze-1']['resume_id']) == (
            'web-release-cli', 'cli-release-web')


class LoseReply:
    """The real runtime, except that the reply of chosen operations is lost after the Gateway ran them."""

    def __init__(self, runtime, operations):
        self.runtime, self.operations, self.lost = runtime, set(operations), []

    def status(self):
        return self.runtime.status()

    def call(self, mount, operation, arguments, **kwargs):
        result = self.runtime.call(mount, operation, arguments, **kwargs)
        if operation in self.operations:
            self.operations.discard(operation)
            self.lost.append((operation, result))
            raise TimeoutError('reply lost')
        return result


def test_lost_reply_double_click_and_several_tabs_apply_once(tmp_path):
    with Gateway(tmp_path) as gateway:
        lossy = LoseReply(gateway.runtime('account'), {'direct.control.apply', 'direct.control.resume'})
        web = WebHost(gateway, ('account',), runtimes={'account': lossy})

        async def check(browser):
            command = await browser.apply_command('account', 'freeze-lost')
            receipt = (await browser.prepare('account', command))['receipt']
            # The Gateway applied the cause but the reply never arrived: the outcome is UNKNOWN.
            assert await browser.run('account', receipt) == {'status': 'UNKNOWN', 'code': 'IDENTITY_UNAVAILABLE'}
            assert lossy.lost == [('direct.control.apply',
                                   {'status': 'OBSERVED', 'cause_id': 'freeze-lost', 'version': 1, 'active': True})]
            # Looking up the same receipt finds the applied cause; running it again does not apply twice.
            status = await browser.status('account', receipt)
            assert status['status'] == 'OBSERVED' and status['cause']['cause_id'] == 'freeze-lost', status
            assert (await browser.run('account', receipt))['status'] == 'OBSERVED'

            # Two tabs click the same prepared release at the same time: one release, both see it.
            release = await browser.resume_command('account', 'release-lost', 'freeze-lost')
            receipt = (await browser.prepare('account', release))['receipt']
            assert await browser.run('account', receipt) == {'status': 'UNKNOWN', 'code': 'IDENTITY_UNAVAILABLE'}
            results = await asyncio.gather(*(browser.run('account', receipt) for _ in range(4)))
            assert all(result['status'] == 'OBSERVED' and result['cause_id'] == 'freeze-lost'
                       and result['active'] is False and result['version'] == 2 for result in results), results

            # Two tabs prepare and run the same new request concurrently: one cause.
            command = await browser.apply_command('account', 'freeze-tabs')
            receipts = [(await browser.prepare('account', command))['receipt'] for _ in range(2)]
            results = await asyncio.gather(*(browser.run('account', r) for r in receipts + receipts))
            assert all(result['status'] == 'OBSERVED' for result in results), results

        web.run(check)
        causes = gateway.causes()
        assert set(causes) == {'freeze-lost', 'freeze-tabs'}
        assert (causes['freeze-lost']['active'], causes['freeze-lost']['version'],
                causes['freeze-lost']['resume_id']) == (0, 2, 'release-lost')
        assert causes['freeze-tabs']['active'] == 1


def test_request_id_of_another_command_is_never_reported_as_this_request(tmp_path):
    with Gateway(tmp_path) as gateway:
        cli = gateway.runtime('cli')
        journal_id = cli_call(cli, 'cli', 'direct.control.identity', {}, gateway)['journal_id']
        for cause_id, mode in (('shared-id', 'STOP_NEW'), ('cli-x', 'FREEZE'), ('web-y', 'FREEZE')):
            cli_call(cli, 'cli', 'direct.control.apply', {'cause_id': cause_id, 'mode': mode,
                     'expected_journal_id': journal_id}, gateway)
        cli_call(cli, 'cli', 'direct.control.resume', {'cause_id': 'cli-x', 'expected_version': 1,
                 'operation_id': 'release-1', 'expected_journal_id': journal_id}, gateway)
        _block_contract(gateway)
        web = WebHost(gateway, ('account',))
        conflict = {'status': 'REQUEST_REJECTED', 'code': 'REQUEST_ID_CONFLICT'}

        async def check(browser):
            # Another operator's STOP_NEW cause already has this id: a FREEZE request with the same
            # id is not that cause, so it must not be reported as observed (nor applied).
            for request_id in ('shared-id', CONTRACT_CAUSE):
                command = await browser.apply_command('account', request_id)
                receipt = (await browser.prepare('account', command))['receipt']
                assert await browser.status('account', receipt) == conflict
                assert await browser.run('account', receipt) == conflict
            # Operation id 'release-1' already released cause 'cli-x': a release of 'web-y' with the
            # same id must not be shown as done while 'web-y' is still active.
            release = await browser.resume_command('account', 'release-1', 'web-y')
            receipt = (await browser.prepare('account', release))['receipt']
            assert await browser.status('account', receipt) == conflict
            assert await browser.run('account', receipt) == conflict

        web.run(check)
        causes = gateway.causes()
        assert (causes['shared-id']['mode'], causes['shared-id']['origin']) == (
            'STOP_NEW', operator_origin('cli-op', 'cli-app'))
        assert causes[CONTRACT_CAUSE]['scope_kind'] == 'instrument' and causes[CONTRACT_CAUSE]['active'] == 1
        assert causes['web-y']['active'] == 1


@pytest.mark.parametrize('how', ['revoked', 'expired'])
def test_revoked_or_expired_registration_refuses_the_next_call_and_applies_nothing(tmp_path, how):
    with Gateway(tmp_path) as gateway:
        cli = gateway.runtime('cli')
        web = WebHost(gateway, ('account',))

        async def prepare(browser):
            command = await browser.apply_command('account', 'freeze-after-' + how)
            prepared = await browser.prepare('account', command)
            assert prepared['status'] == 'PREPARED', prepared
            return prepared['receipt']

        receipt = web.run(prepare)
        if how == 'revoked':
            assert gateway.on_host(lambda host: host._registry.revoke_principal('web-account-op')) is True
        else:
            # Only the Registry's clock moves: every lease it issued is now past its expiry.
            def expire(host):
                now = time.time() + 3600
                host._registry._clock = lambda: now
            gateway.on_host(expire)

        async def refused(browser):
            for _ in range(2):
                assert (await browser.run('account', receipt))['status'] != 'OBSERVED'
                assert (await browser.status('account', receipt))['status'] != 'OBSERVED'
                code, view = await browser.causes('account')
                assert code == 403 or view.get('status') != 'OBSERVED', view
                command = {'request_id': 'freeze-new', 'mode': 'FREEZE', 'cause_id': '', 'expected_version': 0,
                           'view_receipt': 'x'}
                assert (await browser.prepare('account', command))['status'] != 'PREPARED'

        web.run(refused)
        assert gateway.causes() == {}
        if how == 'revoked':
            # Revoking one operator leaves another operator's CLI working.
            assert cli_call(cli, 'cli', 'direct.control.list', {'after': '', 'limit': 10}, gateway)['status'] == 'OBSERVED'


def test_operator_of_another_account_sees_and_applies_nothing(tmp_path):
    with Gateway(tmp_path) as gateway:
        web = WebHost(gateway, ('account', 'other_account'))

        async def check(browser):
            code, other = await browser.causes('other_account')
            assert code == 403 or other.get('status') != 'OBSERVED', other
            # A view of this account taken by its own operator is no use to the other operator.
            command = await browser.apply_command('account', 'cross-account')
            for user in ('other_account',):
                assert (await browser.prepare(user, command))['status'] != 'PREPARED'
            receipt = (await browser.prepare('account', command))['receipt']
            assert (await browser.run('other_account', receipt))['status'] != 'OBSERVED'
            assert (await browser.status('other_account', receipt))['status'] != 'OBSERVED'

        web.run(check)
        assert gateway.causes() == {}


def test_view_and_manage_are_granted_separately(tmp_path):
    with Gateway(tmp_path) as gateway:
        cli = gateway.runtime('cli')
        cli_call(cli, 'cli', 'direct.control.apply', {'cause_id': 'cli-freeze', 'mode': 'FREEZE'}, gateway)
        web = WebHost(gateway, ('viewer',))

        async def check(browser):
            # A view-only operator reads the same causes ...
            code, view = await browser.causes('viewer')
            assert code == 200 and view['status'] == 'OBSERVED', view
            assert [(row['cause_id'], row['active']) for row in view['causes']] == [('cli-freeze', 1)]
            # ... but cannot prepare an apply or a release: its registration has no such grant.
            for body in ({'request_id': 'viewer-freeze', 'mode': 'FREEZE', 'cause_id': '', 'expected_version': 0,
                          'view_receipt': view['scope_receipt']},
                         {'request_id': 'viewer-release', 'mode': 'RESUME', 'cause_id': 'cli-freeze',
                          'expected_version': 1, 'view_receipt': view['causes'][0]['view_receipt']}):
                assert await browser.prepare('viewer', body) == {'status': 'UNKNOWN', 'code': 'IDENTITY_UNAVAILABLE'}

        web.run(check)
        # Its own SDK client cannot send the write either.
        with pytest.raises(Exception, match='ACTION_NOT_GRANTED|AMBIGUOUS_OR_MISSING_ROUTE'):
            cli_call(web.runtimes['viewer'], 'viewer', 'direct.control.apply',
                     {'cause_id': 'viewer-direct', 'mode': 'FREEZE'}, gateway)
        assert set(gateway.causes()) == {'cli-freeze'}
