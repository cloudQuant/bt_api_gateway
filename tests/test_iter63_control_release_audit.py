"""Who released a control cause, stored with the release (I63-E144); synthetic journal only."""
import hashlib
import json
import sqlite3

import pytest

from bt_api_gateway.direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
)
from bt_api_gateway.direct_control import GatewayDirectControl
from bt_api_gateway.session_guard import LocalAccountSessionGuard


def operator(principal, actor):
    # The origin an operator's own cause gets at apply time (gateway_direct_service).
    return 'operator:' + hashlib.sha256(json.dumps([principal, actor], separators=(',', ':')).encode()).hexdigest()


ALICE, BOB = operator('alice-p', 'alice-a'), operator('bob-p', 'bob-a')
V17 = {name + '_enabled': True for name in (
    'controls', 'strategy_ledger', 'account_extensions', 'parent_authority', 'account_facts_financial',
    'actor_stream', 'strategy_origin', 'control_cancel')}


@pytest.fixture
def setup(tmp_path):
    directory = tmp_path / 'guards'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'account', 'owner')
    generation = guard.acquire()
    path = tmp_path / 'db'
    journal = GatewayDirectCommandJournal.create(path, 'account', generation=generation, clock=lambda: 100.0)
    control = journal.enable_controls(guard)
    yield journal, control, guard, path
    guard.release()


def reopen(journal, path, **options):
    return GatewayDirectCommandJournal(path, 'account', generation=journal.generation,
                                       expected_journal_id=journal.journal_id, minimum_revision=0,
                                       clock=lambda: 100.0, **options)


def stored(path):
    db = sqlite3.connect(path)
    try:
        return db.execute('SELECT account,cause_id,resume_id,releaser FROM direct_control_releases '
                          'ORDER BY cause_id').fetchall()
    finally:
        db.close()


def test_a_release_stores_its_releaser_with_it_and_every_read_carries_it(setup):
    journal, control, guard, path = setup
    control.apply('old', 'FREEZE', scope_kind='account', origin=ALICE)
    control.resume('old', expected_version=1, operation_id='resume-old')       # before the upgrade
    control.apply('stop', 'STOP_NEW', scope_kind='account', origin=ALICE)
    control.apply('freeze', 'FREEZE', scope_kind='account', origin=ALICE)
    journal.enable_control_release_audit(guard)
    # A release from before the upgrade has a record, but no releaser is invented for it.
    assert stored(path) == [('account', 'old', 'resume-old', None)]
    assert 'releaser' not in control.get('old')
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_RELEASER_REQUIRED$'):
        control.resume('stop', expected_version=1, operation_id='resume-stop')
    assert control.get('stop')['active'] == 1

    released = control.resume('stop', expected_version=1, operation_id='resume-stop', releaser=ALICE)
    assert (released['active'], released['version'], released['resume_id'], released['releaser']) == (
        0, 2, 'resume-stop', ALICE)
    assert control.get('stop')['releaser'] == ALICE
    assert control.resume_status('resume-stop', scope_kind='account')['releaser'] == ALICE
    listed = {row['cause_id']: row for row in control.list_causes(scope_kind='account')}
    assert listed['stop']['releaser'] == ALICE
    assert 'releaser' not in listed['freeze'] and 'releaser' not in listed['old']   # active / unrecorded
    assert 'releaser' not in control.get('freeze')

    # A replay by another operator who may release returns the stored record; nothing changes.
    replay = control.resume('stop', expected_version=1, operation_id='resume-stop', releaser=BOB)
    assert replay == released
    assert stored(path) == [('account', 'old', 'resume-old', None), ('account', 'stop', 'resume-stop', ALICE)]

    # A system mechanism names itself.
    control.resume('freeze', expected_version=1, operation_id='resolved:freeze', releaser='system:instrument-block')
    assert control.get('freeze')['releaser'] == 'system:instrument-block'
    reopened = reopen(journal, path, controls_enabled=True, control_release_audit_enabled=True)
    assert GatewayDirectControl(reopened, guard).get('stop')['releaser'] == ALICE


def test_the_releaser_is_written_in_the_transaction_of_the_release(setup):
    journal, control, guard, path = setup
    journal.enable_control_release_audit(guard)
    control.apply('lease', 'DRAIN', scope_kind='strategy', scope_value='one', origin='system:lease:x')
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_RECOVERY_UNVERIFIED$'):
        control.resume('lease', expected_version=1, operation_id='lease-resume:1', releaser='system:lease-drain',
                       before_commit_db=lambda db: False)
    assert stored(path) == [] and control.get('lease')['active'] == 1

    seen = []

    def inside(db):
        seen.append(db.execute("SELECT releaser FROM direct_control_releases WHERE cause_id='lease'").fetchone()[0])
        return True

    control.resume('lease', expected_version=1, operation_id='lease-resume:1', releaser='system:lease-drain',
                   before_commit_db=inside)
    assert seen == ['system:lease-drain'] and stored(path) == [('account', 'lease', 'lease-resume:1', 'system:lease-drain')]


@pytest.mark.parametrize('bad', [None, '', 'operator', 'operator:' + 'A' * 64, 'operator:' + 'a' * 63, 'system:',
                                 'system:Lease', 'system:x-', 'origin', 7, ALICE + ' '])
def test_an_unknown_releaser_is_refused_before_anything_is_written(setup, bad):
    journal, control, guard, path = setup
    journal.enable_control_release_audit(guard)
    control.apply('stop', 'STOP_NEW', scope_kind='account', origin=ALICE)
    expected = 'CONTROL_RELEASER_REQUIRED' if bad is None else 'CONTROL_INVALID_INPUT'
    with pytest.raises(DirectCommandJournalError, match='^' + expected + '$'):
        control.resume('stop', expected_version=1, operation_id='resume', releaser=bad)
    assert control.get('stop')['active'] == 1 and stored(path) == []


def test_a_journal_without_the_audit_works_as_before(setup):
    journal, control, guard, path = setup
    control.apply('stop', 'STOP_NEW', scope_kind='account', origin=ALICE)
    released = control.resume('stop', expected_version=1, operation_id='resume', releaser=ALICE)
    assert 'releaser' not in released and 'releaser' not in control.get('stop')
    assert 'releaser' not in control.resume_status('resume', scope_kind='account')
    assert all('releaser' not in row for row in control.list_causes(scope_kind='account'))
    db = sqlite3.connect(path)
    try:
        assert db.execute("SELECT 1 FROM sqlite_master WHERE name='direct_control_releases'").fetchone() is None
    finally:
        db.close()
    reopen(journal, path, controls_enabled=True)
    # The option asks for an audit the journal does not have: named, not opened.
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_RELEASE_AUDIT_UPGRADE_REQUIRED$'):
        reopen(journal, path, controls_enabled=True, control_release_audit_enabled=True)
    with pytest.raises(DirectCommandJournalError, match='^INVALID_INPUT$'):
        reopen(journal, path, control_release_audit_enabled=True)
    with pytest.raises(DirectCommandJournalError, match='^INVALID_INPUT$'):
        reopen(journal, path, controls_enabled=True, control_release_audit_enabled=1)


def test_the_upgrade_is_explicit_one_way_and_needs_controls(tmp_path):
    directory = tmp_path / 'guards'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'account', 'owner')
    try:
        journal = GatewayDirectCommandJournal.create(tmp_path / 'db', 'account', generation=guard.acquire())
        with pytest.raises(DirectCommandJournalError, match='^CONTROL_UPGRADE_REQUIRED$'):
            journal.enable_control_release_audit(guard)
        journal.enable_controls(guard)
        with pytest.raises(DirectCommandJournalError, match='^INVALID_GUARD$'):
            journal.enable_control_release_audit(object())
        journal.enable_control_release_audit(guard)
        with pytest.raises(DirectCommandJournalError, match='^CONTROL_RELEASE_AUDIT_ALREADY_ENABLED$'):
            journal.enable_control_release_audit(guard)
        # Once upgraded, an owner that does not install the audit is refused by name.
        with pytest.raises(DirectCommandJournalError, match='^CONTROL_RELEASE_AUDIT_MISMATCH$'):
            reopen(journal, tmp_path / 'db', controls_enabled=True)
    finally:
        guard.release()


def test_a_v17_journal_takes_the_audit_without_any_later_schema(setup):
    journal, control, guard, path = setup
    for upgrade in ('enable_strategy_ledger', 'enable_account_extensions', 'enable_parent_authority',
                    'enable_account_facts_financial', 'enable_actor_stream', 'enable_strategy_origin',
                    'enable_control_cancel'):
        getattr(journal, upgrade)(guard)
    control.apply('drain', 'DRAIN', scope_kind='account', origin=ALICE)
    journal.enable_control_release_audit(guard)
    db = sqlite3.connect(path)
    try:
        assert db.execute('SELECT schema_version FROM direct_journal_meta').fetchone()[0] == 17
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        db.close()
    assert 'direct_control_releases' in tables
    assert not tables & {'account_fact_consumer_owners', 'account_fact_compaction_meta', 'account_event_consumer_owners'}
    reopened = reopen(journal, path, **V17, control_release_audit_enabled=True)
    assert reopened._schema_version == 17
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_RELEASE_AUDIT_MISMATCH$'):
        reopen(journal, path, **V17)
    control = GatewayDirectControl(reopened, guard)
    assert control.resume('drain', expected_version=1, operation_id='resume', releaser=BOB)['releaser'] == BOB
    # The later schemas still come one by one, and the audit stays with them.
    reopened.enable_account_fact_recovery(guard)
    reopened.enable_account_event_recovery(guard)
    at19 = reopen(journal, path, **V17, account_fact_recovery_enabled=True, account_event_recovery_enabled=True,
                  control_release_audit_enabled=True)
    assert GatewayDirectControl(at19, guard).get('drain')['releaser'] == BOB


def _tamper(path, statement, arguments=()):
    db = sqlite3.connect(path)
    try:
        db.execute(statement, arguments)
        db.commit()
    finally:
        db.close()


@pytest.mark.parametrize('statement', [
    "DELETE FROM direct_control_releases WHERE cause_id='stop'",                       # a release without a record
    "UPDATE direct_control_releases SET resume_id='other' WHERE cause_id='stop'",
    "UPDATE direct_control_releases SET releaser='someone' WHERE cause_id='stop'",
    "UPDATE direct_control_releases SET releaser=7 WHERE cause_id='stop'",
    "UPDATE direct_control_releases SET account='other' WHERE cause_id='stop'",
    "INSERT INTO direct_control_releases VALUES ('account','active','x',NULL)",          # an active cause
    "INSERT INTO direct_control_releases VALUES ('account','missing','y',NULL)",         # no such cause
    "UPDATE direct_control_causes SET active=0,version=2,resume_id='z' WHERE cause_id='active'",
])
def test_every_stored_release_record_is_verified(setup, statement):
    journal, control, guard, path = setup
    journal.enable_control_release_audit(guard)
    control.apply('stop', 'STOP_NEW', scope_kind='account', origin=ALICE)
    control.apply('active', 'FREEZE', scope_kind='account', origin=ALICE)
    control.resume('stop', expected_version=1, operation_id='resume-stop', releaser=ALICE)
    reopen(journal, path, controls_enabled=True, control_release_audit_enabled=True)
    _tamper(path, statement)
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_INVALID_DATABASE$'):
        reopen(journal, path, controls_enabled=True, control_release_audit_enabled=True)
    # The owner's own next transaction finds it as well.
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_INVALID_DATABASE$'):
        control.get('stop')


def test_the_audit_table_itself_is_part_of_the_exact_schema(setup):
    journal, control, guard, path = setup
    journal.enable_control_release_audit(guard)
    _tamper(path, 'DROP TABLE direct_control_releases')
    _tamper(path, 'CREATE TABLE direct_control_releases (account TEXT NOT NULL, cause_id TEXT NOT NULL, '
                  'resume_id TEXT NOT NULL, releaser TEXT NOT NULL, PRIMARY KEY(account, cause_id))')
    with pytest.raises(DirectCommandJournalError, match='^INVALID_DATABASE$'):
        reopen(journal, path, controls_enabled=True, control_release_audit_enabled=True)
