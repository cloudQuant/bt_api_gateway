"""Contract-scoped FREEZE causes (D63-59): one contract is blocked for every strategy, nothing else."""
import sqlite3

import pytest

from bt_api_gateway.direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
)
from bt_api_gateway.direct_control import GatewayDirectControl, instrument_scope_value
from bt_api_gateway.session_guard import LocalAccountSessionGuard

RB, HC = {'symbol': 'rb2701', 'exchange_id': 'SHFE'}, {'symbol': 'hc2701', 'exchange_id': 'SHFE'}
SCOPE = 'SHFE:rb2701'


@pytest.fixture
def setup(tmp_path):
    directory = tmp_path / 'guards'
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, 'account', 'owner')
    journal = GatewayDirectCommandJournal.create(tmp_path / 'db', 'account', generation=guard.acquire(),
                                                 clock=lambda: 100.0)
    control = journal.enable_controls(guard)
    yield journal, control, guard, tmp_path / 'db'
    guard.release()


def _order(payload, offset):
    return dict(payload, side='buy' if offset == 'open' else 'sell', offset=offset, quantity='1')


def _reopen(journal, guard, path):
    reopened = GatewayDirectCommandJournal(path, 'account', generation=journal.generation,
                                           expected_journal_id=journal.journal_id, minimum_revision=0,
                                           clock=lambda: 100.0, controls_enabled=True)
    return reopened, GatewayDirectControl(reopened, guard)


def test_a_blocked_contract_refuses_opens_and_closes_of_every_strategy_and_nothing_else(setup):
    journal, control, guard, path = setup
    cause = control.apply('unresolved-rb', 'FREEZE', scope_kind='instrument', scope_value=SCOPE,
                          origin='system:unresolved_return')
    assert (cause['scope_kind'], cause['scope_value'], cause['mode'], cause['active']) == (
        'instrument', SCOPE, 'FREEZE', 1)
    for strategy in ('one', 'two'):
        for offset in ('open', 'close', 'close_today'):
            with pytest.raises(DirectCommandJournalError, match='^CONTROL_FREEZE$'):
                journal.reserve(strategy, 'rb-' + offset, 'principal', _order(RB, offset))
    # Other contracts go on, for the same strategies.
    assert journal.reserve('one', 'hc-open', 'principal', _order(HC, 'open')).status == 'RESERVED'
    assert journal.reserve('two', 'hc-close', 'principal', _order(HC, 'close')).status == 'RESERVED'
    # The same symbol at another venue is another contract.
    assert journal.reserve('one', 'other-venue', 'principal',
                           _order({'symbol': 'rb2701', 'exchange_id': 'INE'}, 'open')).status == 'RESERVED'
    # An order that does not say where it trades is not let through a block on its symbol.
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_FREEZE$'):
        journal.reserve('one', 'no-venue', 'principal', {'symbol': 'rb2701'})
    # The cause survives a restart, and so does the block.
    reopened, _ = _reopen(journal, guard, path)
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_FREEZE$'):
        reopened.reserve('one', 'after-restart', 'principal', _order(RB, 'open'))


def test_orders_reserved_before_the_block_are_not_dispatched_on_that_contract_only(setup):
    journal, control, _, _ = setup
    old_rb = journal.reserve('one', 'old-rb', 'principal', _order(RB, 'open'))
    old_hc = journal.reserve('one', 'old-hc', 'principal', _order(HC, 'open'))
    control.apply('unresolved-rb', 'FREEZE', scope_kind='instrument', scope_value=SCOPE, origin='system')
    with pytest.raises(DirectCommandJournalError, match='CONTROL_'):
        journal.begin_dispatch('one', 'old-rb', old_rb.reservation_id, old_rb.digest, 'principal', old_rb.version,
                               {'exchange': 'TEST', 'order': 'rb'}, ('rb-key',))
    journal.begin_dispatch('one', 'old-hc', old_hc.reservation_id, old_hc.digest, 'principal',
                           old_hc.version, {'exchange': 'TEST', 'order': 'hc'}, ('hc-key',))
    assert journal.get('one', 'old-hc', 'principal').status == 'DISPATCHING'
    assert journal.get('one', 'old-rb', 'principal').status == 'RESERVED'
    # After the release the old reservation still never goes out; a new one does.
    control.resume('unresolved-rb', expected_version=1, operation_id='release-rb')
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_PREVIOUSLY_BLOCKED$'):
        journal.begin_dispatch('one', 'old-rb', old_rb.reservation_id, old_rb.digest, 'principal', old_rb.version,
                               {'exchange': 'TEST', 'order': 'rb'}, ('rb-key',))
    assert journal.reserve('one', 'new-rb', 'principal', _order(RB, 'open')).status == 'RESERVED'


def test_an_operator_release_admits_the_contract_again_and_is_recorded(setup):
    journal, control, guard, path = setup
    control.apply('unresolved-rb', 'FREEZE', scope_kind='instrument', scope_value=SCOPE, origin='system')
    control.apply('unresolved-hc', 'FREEZE', scope_kind='instrument', scope_value='SHFE:hc2701', origin='system')
    control.apply('freeze-one', 'FREEZE', scope_kind='strategy', scope_value='one', origin='operator')
    assert [row['cause_id'] for row in control.list_causes(scope_kind='instrument')] == [
        'unresolved-hc', 'unresolved-rb']
    assert [row['cause_id'] for row in control.list_causes(scope_kind='instrument', scope_value=SCOPE)] == [
        'unresolved-rb']
    assert [row['cause_id'] for row in control.list_causes(scope_kind='instrument', after='unresolved-hc')] == [
        'unresolved-rb']
    assert control.list_causes(scope_kind='account') == ()                 # each scope lists its own causes
    released = control.resume('unresolved-rb', expected_version=1, operation_id='release-rb')
    assert (released['active'], released['version'], released['resume_id']) == (0, 2, 'release-rb')
    assert control.resume_status('release-rb', scope_kind='instrument', scope_value=SCOPE)['cause_id'] == (
        'unresolved-rb')
    assert control.resume_status('release-rb', scope_kind='instrument', scope_value='SHFE:hc2701') is None
    # Without a contract: any contract of the account, and only contract causes.
    assert control.resume_status('release-rb', scope_kind='instrument')['cause_id'] == 'unresolved-rb'
    assert control.resume_status('release-rb', scope_kind='account') is None
    control.resume('freeze-one', expected_version=1, operation_id='release-one')
    assert control.resume_status('release-one', scope_kind='instrument') is None
    control.apply('freeze-one-again', 'FREEZE', scope_kind='strategy', scope_value='one', origin='operator')
    assert journal.reserve('two', 'rb-open', 'principal', _order(RB, 'open')).status == 'RESERVED'
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_FREEZE$'):
        journal.reserve('two', 'hc-open', 'principal', _order(HC, 'open'))   # the other contract stays blocked
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_FREEZE$'):
        journal.reserve('one', 'rb-open', 'principal', _order(RB, 'open'))   # and so does the frozen strategy
    # Applying the same cause again does not block the contract again: it was released.
    again = control.apply('unresolved-rb', 'FREEZE', scope_kind='instrument', scope_value=SCOPE, origin='system')
    assert again['active'] == 0
    assert journal.reserve('two', 'rb-open-2', 'principal', _order(RB, 'open')).status == 'RESERVED'
    _reopen(journal, guard, path)                                           # the stored state is consistent


@pytest.mark.parametrize('mode, value', [
    ('PAUSE', SCOPE), ('RESUME', SCOPE),             # not a mode (STOP_NEW and DRAIN are allowed since G64-01)
    ('FREEZE', ''), ('FREEZE', 'rb2701'), ('FREEZE', 'SHFE:'), ('FREEZE', ':rb2701'), ('FREEZE', 'SHFE:rb 2701'),
    ('FREEZE', 'SHFE:rb2701:x'), ('FREEZE', 7),
])
def test_invalid_contract_scopes_are_refused(setup, mode, value):
    journal, control, _, _ = setup
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_INVALID_INPUT$'):
        control.apply('cause', mode, scope_kind='instrument', scope_value=value, origin='system')
    assert journal.reserve('one', 'open', 'principal', _order(RB, 'open')).status == 'RESERVED'
    for call in (lambda: control.list_causes(scope_kind='instrument', scope_value='rb2701'),
                 lambda: control.resume_status('op', scope_kind='instrument', scope_value='rb2701')):
        with pytest.raises(DirectCommandJournalError, match='^CONTROL_INVALID_INPUT$'):
            call()


def test_scope_value_of_a_contract():
    assert instrument_scope_value('SHFE', 'rb2701') == SCOPE
    assert instrument_scope_value('CZCE', 'SA701') == 'CZCE:SA701'
    for venue, symbol in (('SHFE', ''), ('', 'rb2701'), ('SH:FE', 'rb2701'), ('SHFE', 'rb:2701'), (None, 'rb2701'),
                          ('SHFE', 2701)):
        with pytest.raises(DirectCommandJournalError, match='^CONTROL_INVALID_INPUT$'):
            instrument_scope_value(venue, symbol)


@pytest.mark.parametrize('statement', [
    "UPDATE direct_control_causes SET mode='PAUSE' WHERE cause_id='unresolved-rb'",
    "UPDATE direct_control_causes SET scope_value='rb2701' WHERE cause_id='unresolved-rb'",
    "UPDATE direct_control_blocked SET reservation_id=(SELECT reservation_id FROM direct_journal_commands "
    "WHERE request_key='old-hc') WHERE cause_id='unresolved-rb'",
])
def test_a_stored_contract_cause_that_does_not_add_up_is_refused(setup, statement):
    journal, control, guard, path = setup
    journal.reserve('one', 'old-rb', 'principal', _order(RB, 'open'))
    journal.reserve('one', 'old-hc', 'principal', _order(HC, 'open'))
    control.apply('unresolved-rb', 'FREEZE', scope_kind='instrument', scope_value=SCOPE, origin='system')
    with sqlite3.connect(path) as db:
        assert db.execute(statement).rowcount == 1
    with pytest.raises(DirectCommandJournalError):
        reopened, rebuilt = _reopen(journal, guard, path)
        rebuilt.list_causes(scope_kind='instrument')


def test_a_stored_contract_scope_is_checked_even_when_nothing_was_reserved(setup):
    journal, control, guard, path = setup
    control.apply('unresolved-rb', 'FREEZE', scope_kind='instrument', scope_value=SCOPE, origin='system')
    with sqlite3.connect(path) as db:
        assert db.execute("UPDATE direct_control_causes SET scope_value='rb2701'").rowcount == 1
    with pytest.raises(DirectCommandJournalError, match='^CONTROL_INVALID_DATABASE$'):
        _reopen(journal, guard, path)
