"""Synthetic durable cursor owner handoff; no provider or network operations."""
import sqlite3

import pytest

from bt_api_gateway.account_fact_consumer_ownership import (
    ACCOUNT_FACT_OWNER_DDL, AccountFactConsumerOwner, account_fact_visible_cursors,
    claim_account_fact_reader, require_account_fact_owner, verify_account_fact_consumer_owners,
)
from bt_api_gateway.direct_command_journal import DirectCommandJournalError


@pytest.fixture
def db(tmp_path):
    connection = sqlite3.connect(tmp_path / 'journal.sqlite')
    connection.execute('CREATE TABLE account_fact_stream_consumers (account TEXT NOT NULL, '
        'principal TEXT NOT NULL, consumer TEXT NOT NULL, offered_sequence INTEGER NOT NULL, '
        'acknowledged_sequence INTEGER NOT NULL, PRIMARY KEY(account,principal,consumer))')
    connection.execute(ACCOUNT_FACT_OWNER_DDL['account_fact_consumer_owners'])
    connection.execute('INSERT INTO account_fact_stream_consumers VALUES (?,?,?,?,?)', ('acct', 'p', 'c', 8, 3))
    connection.commit()
    yield connection
    connection.close()


def test_legacy_and_new_owner_require_reoffer_then_forbid_old_ack(db):
    a = AccountFactConsumerOwner('registration-a', 'epoch', 'run-a')
    b = AccountFactConsumerOwner('registration-b', 'epoch', 'run-b')
    with db:
        db.execute('BEGIN IMMEDIATE')
        assert account_fact_visible_cursors(db, 'acct', 'p', 'c', a) == (3, 3)
        with pytest.raises(DirectCommandJournalError, match='CONSUMER_REPLAY_REQUIRED'):
            require_account_fact_owner(db, 'acct', 'p', 'c', a)
        with pytest.raises(DirectCommandJournalError, match='CONSUMER_REPLAY_REQUIRED'):
            claim_account_fact_reader(db, 'acct', 'p', 'c', a, after_sequence=8)
        assert claim_account_fact_reader(db, 'acct', 'p', 'c', a, after_sequence=3) == 3
        assert account_fact_visible_cursors(db, 'acct', 'p', 'c', a) == (3, 3)
        db.execute('UPDATE account_fact_stream_consumers SET offered_sequence=7 WHERE account=?', ('acct',))
        assert claim_account_fact_reader(db, 'acct', 'p', 'c', a, after_sequence=7) == 3
        assert account_fact_visible_cursors(db, 'acct', 'p', 'c', b) == (3, 3)
        with pytest.raises(DirectCommandJournalError, match='CONSUMER_REPLAY_REQUIRED'):
            require_account_fact_owner(db, 'acct', 'p', 'c', b)
        with pytest.raises(DirectCommandJournalError, match='CONSUMER_REPLAY_REQUIRED'):
            claim_account_fact_reader(db, 'acct', 'p', 'c', b, after_sequence=7)
        assert claim_account_fact_reader(db, 'acct', 'p', 'c', b, after_sequence=3) == 3
        assert account_fact_visible_cursors(db, 'acct', 'p', 'c', b) == (3, 3)
        with pytest.raises(DirectCommandJournalError, match='CONSUMER_REPLAY_REQUIRED'):
            require_account_fact_owner(db, 'acct', 'p', 'c', a)
        require_account_fact_owner(db, 'acct', 'p', 'c', b)
        verify_account_fact_consumer_owners(db, 'acct')


def test_owner_reclaim_survives_restart_and_never_uses_wire_offered(tmp_path):
    path = tmp_path / 'db'
    owner_a = AccountFactConsumerOwner('a', 'epoch-a', '')
    owner_b = AccountFactConsumerOwner('b', 'epoch-b', '')
    con = sqlite3.connect(path)
    with con:
        con.execute('CREATE TABLE account_fact_stream_consumers (account TEXT,principal TEXT,consumer TEXT, '
                    'offered_sequence INTEGER,acknowledged_sequence INTEGER,PRIMARY KEY(account,principal,consumer))')
        con.execute(ACCOUNT_FACT_OWNER_DDL['account_fact_consumer_owners'])
        con.execute('INSERT INTO account_fact_stream_consumers VALUES (?,?,?,?,?)', ('acct', 'p', 'c', 3, 3))
        claim_account_fact_reader(con, 'acct', 'p', 'c', owner_a, after_sequence=3)
        con.execute('UPDATE account_fact_stream_consumers SET offered_sequence=6')
    con.close()
    con = sqlite3.connect(path)
    try:
        with con:
            con.execute('BEGIN IMMEDIATE')
            assert account_fact_visible_cursors(con, 'acct', 'p', 'c', owner_b) == (3, 3)
            claim_account_fact_reader(con, 'acct', 'p', 'c', owner_b, after_sequence=3)
            assert con.execute('SELECT offered_sequence,acknowledged_sequence FROM account_fact_stream_consumers').fetchone() == (3, 3)
            require_account_fact_owner(con, 'acct', 'p', 'c', owner_b)
            with pytest.raises(DirectCommandJournalError, match='CONSUMER_REPLAY_REQUIRED'):
                require_account_fact_owner(con, 'acct', 'p', 'c', owner_a)
    finally:
        con.close()


def test_empty_first_claim_and_invalid_database_fail_closed(db):
    owner = AccountFactConsumerOwner('reg', 'epoch', '')
    with db:
        db.execute('BEGIN IMMEDIATE')
        assert claim_account_fact_reader(db, 'acct', 'p', 'new', owner, after_sequence=0) == 0
        assert account_fact_visible_cursors(db, 'acct', 'p', 'new', owner) == (0, 0)
        require_account_fact_owner(db, 'acct', 'p', 'new', owner)
        with pytest.raises(DirectCommandJournalError, match='INVALID_SEQUENCE'):
            claim_account_fact_reader(db, 'acct', 'p', 'new', owner, after_sequence=1)
        db.execute("INSERT INTO account_fact_consumer_owners VALUES ('other','p','x','reg','epoch','')")
        with pytest.raises(DirectCommandJournalError, match='INVALID_DATABASE'):
            verify_account_fact_consumer_owners(db, 'acct')
