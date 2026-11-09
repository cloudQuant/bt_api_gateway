"""Synthetic account journal admission at the reservation commit boundary."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Event

import pytest
from bt_api_gateway.direct_command_journal import DirectCommandJournalError, GatewayDirectCommandJournal
from bt_api_gateway.direct_strategy_origin import authorize_strategy_origin
from bt_api_gateway.session_guard import LocalAccountSessionGuard
from test_iter63_direct_strategy_origin import context
from test_iter63_direct_execution_journal import INSTRUMENT


@contextmanager
def fence():
    yield


def make_journal(tmp_path, version):
    directory = tmp_path / 'guard'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'acct', 'owner')
    journal = GatewayDirectCommandJournal.create(tmp_path / 'db', 'acct', generation=guard.acquire())
    if version >= 15:
        journal.enable_controls(guard)
        journal.enable_strategy_ledger(guard)
        journal.enable_account_extensions(guard)
        journal.enable_parent_authority(guard)
        journal.enable_account_facts_financial(guard)
        journal.enable_actor_stream(guard)
    if version >= 16:
        journal.enable_strategy_origin(guard)
    return journal, guard


@pytest.mark.parametrize('version', [9, 15])
def test_final_admission_rejects_after_insert_and_replay_is_unchanged(tmp_path, version):
    journal, guard = make_journal(tmp_path, version)
    entered, release = Event(), Event()
    revision = journal.recovery_page(limit=10).revision
    payload = {'symbol': 'rb2601', 'offset': 'open'}
    state = {'held': False}
    @contextmanager
    def held_fence():
        state['held'] = True
        try:
            yield
        finally:
            state['held'] = False
    try:
        def denied():
            assert state['held']
            entered.set()
            assert release.wait(5)
            raise RuntimeError('admission-closed')
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(journal.reserve, 's1', 'key', 'principal', payload,
                                  reservation_fence=held_fence, before_reservation_commit=denied)
            assert entered.wait(5)
            release.set()
            with pytest.raises(RuntimeError, match='admission-closed'):
                pending.result(timeout=5)
        assert journal.recovery_page(limit=10).revision == revision
        with pytest.raises(DirectCommandJournalError, match='NOT_FOUND'):
            journal.get('s1', 'key', 'principal')
        checks = []
        first = journal.reserve('s1', 'key', 'principal', payload,
                                reservation_fence=fence, before_reservation_commit=lambda: checks.append(1))
        assert checks == [1]
        replay = journal.reserve('s1', 'key', 'principal', payload,
                                 before_reservation_commit=lambda: (_ for _ in ()).throw(RuntimeError('must not run')))
        assert replay == first and checks == [1]
    finally:
        guard.release()


def test_final_admission_keeps_v16_origin_atomic(tmp_path):
    journal, guard = make_journal(tmp_path, 16)
    payload = {'symbol': 'rb2601', 'exchange_id': 'SHFE', 'idempotency_key': 'req1',
               'side': 'buy', 'offset': 'open', 'quantity': '1'}
    permit = authorize_strategy_origin(context(), INSTRUMENT, payload, account='acct', journal_id=journal.journal_id,
        generation=journal.generation, service_epoch='epoch', registry_recheck=lambda _: True,
        instrument_recheck=lambda _: True)
    try:
        def deny():
            raise RuntimeError('admission-closed')
        with pytest.raises(RuntimeError, match='admission-closed'):
            journal.reserve('s1', 'req1', 'principal', payload, reservation_fence=fence,
                            strategy_origin_permit=permit, before_reservation_commit=deny)
        with journal._transaction() as db:
            assert db.execute('SELECT count(*) FROM direct_journal_commands').fetchone()[0] == 0
            assert db.execute('SELECT count(*) FROM direct_strategy_origins').fetchone()[0] == 0
        row = journal.reserve('s1', 'req1', 'principal', payload, reservation_fence=fence,
                              strategy_origin_permit=permit, before_reservation_commit=lambda: None)
        assert row.status == 'RESERVED'
        assert journal.reserve('s1', 'req1', 'principal', payload, reservation_fence=fence,
            strategy_origin_permit=permit, before_reservation_commit=deny) == row
    finally:
        guard.release()
