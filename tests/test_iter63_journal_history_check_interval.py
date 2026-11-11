"""Whole-table integrity checks of the journal can be spaced out by a trusted owner (I63-E135)."""
import sqlite3

import pytest

from bt_api_gateway.direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
)
from bt_api_gateway.session_guard import LocalAccountSessionGuard


@pytest.fixture
def setup(tmp_path, monkeypatch):
    directory = tmp_path / 'guards'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'account', 'owner')
    generation = guard.acquire()
    path = tmp_path / 'db'
    journal = GatewayDirectCommandJournal.create(path, 'account', generation=generation, clock=lambda: 100.0)
    journal.enable_controls(guard)
    checks, clock = [], [1000.0]
    original = GatewayDirectCommandJournal._verify_history

    def counted(self, db):
        checks.append(self)
        return original(self, db)

    monkeypatch.setattr(GatewayDirectCommandJournal, '_verify_history', counted)
    journal._deep_clock = lambda: clock[0]
    yield journal, guard, path, checks, clock
    guard.release()


def _read(journal):
    with journal._transaction() as db:
        return db.execute('SELECT count(*) FROM direct_journal_commands').fetchone()[0]


def _foreign_write(path, statement, arguments=()):
    """A write that does not go through this journal object (another connection)."""
    db = sqlite3.connect(path)
    try:
        db.execute(statement, arguments)
        db.commit()
    finally:
        db.close()


def test_by_default_every_transaction_checks_the_whole_history(setup):
    journal, _, _, checks, _ = setup
    for _ in range(3):
        _read(journal)
    assert len(checks) == 3


def test_with_an_interval_unchanged_storage_is_checked_once_per_interval(setup):
    journal, _, _, checks, clock = setup
    journal.set_deep_verification_interval(30)
    for _ in range(5):
        _read(journal)
    assert len(checks) == 1
    clock[0] += 29.9
    _read(journal)
    assert len(checks) == 1
    clock[0] += 0.2
    _read(journal)
    assert len(checks) == 2
    for _ in range(3):
        _read(journal)
    assert len(checks) == 2


def test_own_writes_wait_for_the_next_full_check(setup):
    journal, _, _, checks, clock = setup
    journal.set_deep_verification_interval(30)
    _read(journal)
    journal.reserve('strategy', 'one', 'principal', {'symbol': 'X'})
    journal.reserve('strategy', 'two', 'principal', {'symbol': 'X'})
    assert _read(journal) == 2 and len(checks) == 1
    clock[0] += 31
    _read(journal)
    assert len(checks) == 2


def test_a_write_by_another_connection_is_checked_at_the_next_transaction(setup):
    journal, _, path, checks, _ = setup
    journal.set_deep_verification_interval(30)
    _read(journal)
    _read(journal)
    assert len(checks) == 1
    # Harmless foreign write: checked at once, and passes.
    _foreign_write(path, 'UPDATE direct_journal_meta SET revision=revision+1 WHERE account=?', ('account',))
    _read(journal)
    assert len(checks) == 2
    _read(journal)
    assert len(checks) == 2
    # Damaging foreign write: refused at once, without waiting for the interval.
    journal.reserve('strategy', 'one', 'principal', {'symbol': 'X'})
    _foreign_write(path, "UPDATE direct_control_causes SET mode='BOGUS'")
    _foreign_write(path, "INSERT INTO direct_control_causes VALUES ('account','c','strategy','s','BOGUS','operator','g',1,1,NULL)")
    with pytest.raises(DirectCommandJournalError, match='INVALID_DATABASE'):
        _read(journal)
    with pytest.raises(DirectCommandJournalError, match='INVALID_DATABASE'):
        _read(journal)                                    # stays refused: nothing was trusted


def test_damage_written_through_the_object_itself_is_reported_at_the_next_full_check(setup):
    journal, _, _, checks, clock = setup
    journal.set_deep_verification_interval(30)
    _read(journal)
    with journal._transaction() as db:
        db.execute("INSERT INTO direct_control_causes VALUES ('account','c','strategy','s','BOGUS','operator','g',1,1,NULL)")
    assert _read(journal) == 0                            # not noticed inside the interval
    clock[0] += 31
    with pytest.raises(DirectCommandJournalError, match='INVALID_DATABASE'):
        _read(journal)


def test_a_slow_full_check_spaces_the_next_one_out(setup, monkeypatch):
    journal, _, _, checks, clock = setup
    journal.set_deep_verification_interval(30)
    original = GatewayDirectCommandJournal._verify_history

    def slow(self, db):
        original(self, db)
        clock[0] += 4.0                                   # the check itself took four seconds

    monkeypatch.setattr(GatewayDirectCommandJournal, '_verify_history', slow)
    _read(journal)                                        # next full check not before 20 x 4 s
    clock[0] += 79.0
    _read(journal)
    assert len(checks) == 1
    clock[0] += 1.5
    _read(journal)
    assert len(checks) == 2


def test_a_rolled_back_transaction_keeps_the_checked_state(setup):
    journal, _, _, checks, _ = setup
    journal.set_deep_verification_interval(30)
    _read(journal)
    with pytest.raises(RuntimeError), journal._transaction() as db:
        db.execute("INSERT INTO direct_control_causes VALUES ('account','c','strategy','s','BOGUS','operator','g',1,1,NULL)")
        raise RuntimeError('abandon')
    _read(journal)
    assert len(checks) == 1


def test_a_connection_that_skipped_the_gate_leaves_nothing_trusted(setup):
    journal, _, _, checks, _ = setup
    journal.set_deep_verification_interval(30)
    _read(journal)
    with journal._connection() as db:                     # a path that does not run the transaction checks
        db.execute('SELECT 1').fetchone()
    _read(journal)
    assert len(checks) == 2


def test_setting_or_clearing_the_interval_forces_a_full_check(setup):
    journal, _, _, checks, _ = setup
    journal.set_deep_verification_interval(30)
    _read(journal)
    _read(journal)
    journal.set_deep_verification_interval(30)
    _read(journal)
    assert len(checks) == 2
    journal.set_deep_verification_interval(0)
    _read(journal)
    _read(journal)
    assert len(checks) == 4


@pytest.mark.parametrize('bad', [-1, 3601, float('inf'), float('nan'), True, '30', None])
def test_invalid_intervals_are_refused(setup, bad):
    journal = setup[0]
    with pytest.raises(DirectCommandJournalError, match='INVALID_INPUT'):
        journal.set_deep_verification_interval(bad)
    assert journal._deep_interval == 0.0


def test_a_reopened_journal_checks_in_full_whatever_the_first_object_trusted(setup):
    journal, guard, path, checks, _ = setup
    journal.set_deep_verification_interval(30)
    _read(journal)
    reopened = GatewayDirectCommandJournal(path, 'account', generation=journal.generation,
                                           expected_journal_id=journal.journal_id, minimum_revision=0,
                                           clock=lambda: 100.0, controls_enabled=True)
    assert reopened._deep_interval == 0.0
    _read(reopened)
    _read(reopened)
    assert [item for item in checks if item is reopened] == [reopened, reopened]


def test_a_foreign_write_that_only_reached_the_write_ahead_log_is_noticed(setup):
    journal, _, path, checks, _ = setup
    journal.set_deep_verification_interval(30)
    _read(journal)
    holder = sqlite3.connect(path)                        # keeps the log from being folded into the file
    try:
        holder.execute('SELECT count(*) FROM direct_journal_meta').fetchone()
        _read(journal)
        before = len(checks)
        _foreign_write(path, 'UPDATE direct_journal_meta SET revision=revision+1 WHERE account=?', ('account',))
        _read(journal)
        assert len(checks) == before + 1
    finally:
        holder.close()
