"""Synthetic local journal writer invalidation; no provider or account I/O."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from bt_api_gateway.direct_command_journal import DirectCommandJournalError, GatewayDirectCommandJournal
from bt_api_gateway.session_guard import LocalAccountSessionGuard


class Port:
    def __init__(self):
        self.events = []
    def matches_owner(self, account, generation):
        return account == 'acct' and bool(generation)
    def begin_change(self, domain):
        token = object()
        self.events.append(('begin', domain, token))
        return token
    def finish_change(self, token, status):
        self.events.append(('finish', token, status))
    def poison(self, token):
        self.events.append(('poison', token))
    def poison_domain(self, domain):
        self.events.append(('poison_domain', domain))


@pytest.fixture
def owner(tmp_path):
    directory = tmp_path / 'guard'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'acct', 'owner')
    journal = GatewayDirectCommandJournal.create(tmp_path / 'db', 'acct', generation=guard.acquire())
    port = Port()
    journal.install_dispatch_change_port(guard=guard, port=port)
    yield journal, port
    guard.release()


def test_read_only_and_idempotent_do_not_invalidate(owner):
    journal, port = owner
    journal.recovery_page(limit=10)
    assert port.events == []
    first = journal.reserve('s', 'key', 'principal', {'symbol': 'X'})
    assert len(port.events) == 2
    begin, finish = port.events
    assert begin[:2] == ('begin', 'parent_facts') and finish == ('finish', begin[2], 'UNAVAILABLE')
    port.events.clear()
    assert journal.get('s', 'key', 'principal') == first
    assert journal.reserve('s', 'key', 'principal', {'symbol': 'X'}) == first
    assert port.events == []


def test_writer_is_invalidated_before_commit_and_failure_poisons(owner):
    journal, port = owner
    entered, release = Event(), Event()
    def denied():
        assert len(port.events) == 1 and port.events[0][0] == 'begin'
        entered.set()
        assert release.wait(5)
        raise RuntimeError('denied')
    with ThreadPoolExecutor(max_workers=1) as pool:
        write = pool.submit(journal.reserve, 's', 'key', 'principal', {'symbol': 'X'},
                            before_reservation_commit=denied)
        assert entered.wait(5)
        assert len(port.events) == 1
        release.set()
        with pytest.raises(RuntimeError, match='denied'):
            write.result(timeout=5)
    assert port.events[1] == ('poison', port.events[0][2])
    with pytest.raises(DirectCommandJournalError, match='NOT_FOUND'):
        journal.get('s', 'key', 'principal')


def test_begin_failure_denies_write_and_poisons_domain(owner):
    journal, port = owner
    def fail(_domain):
        raise RuntimeError('coordinator unavailable')
    port.begin_change = fail
    with pytest.raises(Exception, match='not authorized'):
        journal.reserve('s', 'key', 'principal', {'symbol': 'X'})
    assert port.events == [('poison_domain', 'parent_facts')]
    with pytest.raises(DirectCommandJournalError, match='NOT_FOUND'):
        journal.get('s', 'key', 'principal')


def test_real_coordinator_fences_inflight_write_and_stays_unavailable(tmp_path):
    from bt_api_py.gateway_dispatch_claim import DispatchClaimError, GatewayDispatchClaimCoordinator

    directory = tmp_path / 'guard-real'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'acct', 'owner')
    journal = GatewayDirectCommandJournal.create(tmp_path / 'db-real', 'acct', generation=guard.acquire())
    core = GatewayDispatchClaimCoordinator._for_test('acct', journal.generation)
    try:
        for domain in ('registry', 'market', 'parent_facts', 'control', 'session_source', 'risk'):
            token = core.begin_change(domain)
            core.finish_change(token, 'NOT_SELECTED' if domain == 'risk' else 'READY')
        journal.install_dispatch_change_port(guard=guard, port=core)
        baseline = core.capture()
        journal.recovery_page(limit=1)
        assert core.capture().versions == baseline.versions
        entered, proceed = Event(), Event()
        def after_insert():
            entered.set()
            assert proceed.wait(5)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(journal.reserve, 's', 'key', 'principal', {'symbol': 'X'},
                                  before_reservation_commit=after_insert)
            assert entered.wait(5)
            with pytest.raises(DispatchClaimError, match='DOMAIN_UNAVAILABLE'):
                core.capture()
            proceed.set()
            assert pending.result(timeout=5).status == 'RESERVED'
        with pytest.raises(DispatchClaimError, match='DOMAIN_UNAVAILABLE'):
            core.capture()
    finally:
        guard.release()


def test_parent_and_control_writers_invalidate_under_owner(tmp_path):
    from bt_api_gateway.direct_control import GatewayDirectControl
    from bt_api_gateway.direct_parent_authority import GatewayParentAuthority
    from test_iter63_direct_parent_authority import spec, kwargs

    directory = tmp_path / 'parent-guard'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'acct', 'owner')
    journal = GatewayDirectCommandJournal.create(tmp_path / 'parent-db', 'acct', generation=guard.acquire())
    try:
        journal.enable_controls(guard)
        journal.enable_strategy_ledger(guard)
        journal.enable_account_extensions(guard)
        journal.enable_parent_authority(guard)
        port = Port()
        journal.install_dispatch_change_port(guard=guard, port=port)
        authority = GatewayParentAuthority(journal, guard, now_ns=lambda: 100,
            trading_day=lambda: '20261109', transfer_completed=lambda _db, _spec: '0')
        authority.register_parent(spec(), **kwargs())
        assert [event[0] for event in port.events] == ['begin', 'finish']
        port.events.clear()
        authority.query_parent('acct', 'strategy', 'parent', 'register', **kwargs())
        assert port.events == []
        control = GatewayDirectControl(journal, guard)
        control.apply('cause', 'STOP_NEW', scope_kind='strategy', scope_value='strategy', origin='operator')
        assert [event[0] for event in port.events] == ['begin', 'finish']
        port.events.clear()
        authority.cancel_parent('acct', 'strategy', 'parent', 'register', 'cancel', 1, **kwargs())
        assert [event[0] for event in port.events] == ['begin', 'finish']
    finally:
        guard.release()


def test_position_and_fact_ingest_use_same_invalidation_port(tmp_path):
    from test_iter63_strategy_ledger_owner import baseline, install, open_fill

    directory = tmp_path / 'ledger-guard'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'acct', 'owner')
    journal = GatewayDirectCommandJournal.create(tmp_path / 'ledger-db', 'acct', generation=guard.acquire())
    try:
        journal.enable_controls(guard)
        journal.enable_strategy_ledger(guard)
        port = Port()
        journal.install_dispatch_change_port(guard=guard, port=port)
        baseline(journal, guard)
        assert [event[0] for event in port.events] == ['begin', 'finish']
        port.events.clear()
        install(journal, guard)
        open_fill(journal, guard)
        assert [event[0] for event in port.events] == ['begin', 'finish'] * 3
    finally:
        guard.release()


def test_reused_connection_statement_cache_still_invalidates_each_transaction(owner):
    journal, port = owner
    with journal._connection() as db:
        for _ in range(2):
            with journal._transaction_on(db):
                db.execute('UPDATE direct_journal_meta SET revision=revision+1 WHERE account=?', ('acct',))
    assert [event[0] for event in port.events] == ['begin', 'finish', 'begin', 'finish']


def test_reopened_marker_keeps_identity_and_never_becomes_new_dispatch(tmp_path):
    from bt_api_py.gateway_dispatch_claim import DispatchClaimError, GatewayDispatchClaimCoordinator

    directory = tmp_path / 'restart-guard'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'acct', 'owner')
    journal = GatewayDirectCommandJournal.create(tmp_path / 'restart-db', 'acct', generation=guard.acquire())
    try:
        first = journal.reserve('s', 'key', 'principal', {'symbol': 'X'})
        args = ('s', 'key', first.reservation_id, first.digest, 'principal', first.version)
        identity, keys = {'exchange': 'synthetic', 'ref': 'unchanged'}, ('native-key',)
        marker = journal.begin_dispatch(*args, identity, keys)
        assert marker.newly_started and marker.record.status == 'DISPATCHING'
        reopened = GatewayDirectCommandJournal(tmp_path / 'restart-db', 'acct', generation=journal.generation,
            expected_journal_id=journal.journal_id, minimum_revision=0)
        restarted_core = GatewayDispatchClaimCoordinator('acct', journal.generation)
        reopened.install_dispatch_change_port(guard=guard, port=restarted_core)
        with pytest.raises(DispatchClaimError, match='COVERAGE_UNAVAILABLE'):
            restarted_core.capture()
        repeated = reopened.begin_dispatch(*args, identity, keys)
        assert not repeated.newly_started and repeated.record == marker.record
    finally:
        guard.release()


def test_install_rejects_existing_transaction_without_holding_a_lock_across_sqlite(tmp_path):
    directory = tmp_path / 'install-guard'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'acct', 'owner')
    journal = GatewayDirectCommandJournal.create(tmp_path / 'install-db', 'acct', generation=guard.acquire())
    port = Port()
    entered, proceed = Event(), Event()
    def existing_transaction():
        with journal._transaction() as db:
            db.execute('SELECT revision FROM direct_journal_meta').fetchone()
            entered.set()
            assert proceed.wait(5)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            task = pool.submit(existing_transaction)
            assert entered.wait(5)
            with pytest.raises(DirectCommandJournalError, match='DISPATCH_CHANGE_PORT_BUSY'):
                journal.install_dispatch_change_port(guard=guard, port=port)
            proceed.set()
            task.result(timeout=5)
        journal.install_dispatch_change_port(guard=guard, port=port)
        journal.reserve('s', 'key', 'principal', {'symbol': 'X'})
        assert [event[0] for event in port.events] == ['begin', 'finish']
    finally:
        guard.release()
