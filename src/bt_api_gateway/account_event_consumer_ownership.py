"""Fence account-event cursor offers to a Registry-authenticated registration.

Call only inside the existing account journal transaction and Registry admission
scope. The token is assembled by the trusted service from its authenticated
context; it must never be accepted as a client request argument.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .direct_command_journal import DirectCommandJournalError, _text

ACCOUNT_EVENT_OWNER_DDL = {
    'account_event_consumer_owners': (
        'CREATE TABLE account_event_consumer_owners ('
        'account TEXT NOT NULL, principal TEXT NOT NULL, consumer TEXT NOT NULL, '
        'registration_id TEXT NOT NULL, service_epoch TEXT NOT NULL, run_id TEXT NOT NULL, '
        'PRIMARY KEY(account,principal,consumer))'
    ),
}
_MAX_CONSUMERS = 8192


@dataclass(frozen=True, slots=True)
class AccountEventConsumerOwner:
    """Owner derived from current server-side Registry admission, never wire data."""

    registration_id: str
    service_epoch: str
    run_id: str

    def __post_init__(self):
        _text(self.registration_id)
        _text(self.service_epoch)
        if type(self.run_id) is not str or (self.run_id and _text(self.run_id) != self.run_id):
            raise DirectCommandJournalError('INVALID_ACCOUNT_EVENT_OWNER')


def _inputs(db, account, principal, consumer, owner):
    if not isinstance(db, sqlite3.Connection) or not db.in_transaction:
        raise DirectCommandJournalError('INVALID_ACCOUNT_EVENT_OWNER')
    account, principal, consumer = _text(account), _text(principal), _text(consumer)
    if type(owner) is not AccountEventConsumerOwner:
        raise DirectCommandJournalError('INVALID_ACCOUNT_EVENT_OWNER')
    owner.__post_init__()
    return account, principal, consumer


def _cursor(db, account, principal, consumer):
    row = db.execute('SELECT offered_sequence,acknowledged_sequence FROM direct_account_observer_consumers '
                     'WHERE account=? AND principal=? AND consumer=?', (account, principal, consumer)).fetchone()
    if row is None:
        return 0, 0
    offered, acknowledged = row
    if (type(offered) is not int or type(acknowledged) is not int
            or not 0 <= acknowledged <= offered < 2**63):
        raise DirectCommandJournalError('INVALID_DATABASE')
    return offered, acknowledged


def _owner(db, account, principal, consumer):
    return db.execute('SELECT registration_id,service_epoch,run_id FROM account_event_consumer_owners '
                      'WHERE account=? AND principal=? AND consumer=?', (account, principal, consumer)).fetchone()


def claim_account_event_reader(db, account, principal, consumer, owner, *, after_sequence):
    """Claim/reclaim on read; a new owner must resume at/before durable ACK.

    A valid Registry admission and sole active registration must be held for the
    whole transaction. Repeated reads by the same owner retain its offered cursor.
    No consumer row is necessary for an empty stream.
    """
    account, principal, consumer = _inputs(db, account, principal, consumer, owner)
    if type(after_sequence) is not int or not 0 <= after_sequence < 2**63:
        raise DirectCommandJournalError('INVALID_SEQUENCE')
    offered, acknowledged = _cursor(db, account, principal, consumer)
    row = _owner(db, account, principal, consumer)
    wanted = (owner.registration_id, owner.service_epoch, owner.run_id)
    if row is not None and tuple(row) == wanted:
        if after_sequence > offered:
            raise DirectCommandJournalError('INVALID_SEQUENCE')
        return acknowledged
    if after_sequence > acknowledged:
        raise DirectCommandJournalError('CONSUMER_REPLAY_REQUIRED')
    if row is None and db.execute('SELECT count(*) FROM account_event_consumer_owners WHERE account=?',
                                  (account,)).fetchone()[0] >= _MAX_CONSUMERS:
        raise DirectCommandJournalError('CONSUMER_CAPACITY_EXCEEDED')
    # Re-offering and its owner transition are in the same transaction. Old
    # unacknowledged offers cannot be acknowledged by a later registration.
    db.execute('UPDATE direct_account_observer_consumers SET offered_sequence=acknowledged_sequence '
               'WHERE account=? AND principal=? AND consumer=?', (account, principal, consumer))
    db.execute('INSERT INTO account_event_consumer_owners VALUES (?,?,?,?,?,?) '
               'ON CONFLICT(account,principal,consumer) DO UPDATE SET '
               'registration_id=excluded.registration_id,service_epoch=excluded.service_epoch,run_id=excluded.run_id',
               (account, principal, consumer, *wanted))
    return acknowledged


def require_account_event_owner(db, account, principal, consumer, owner):
    """Require the exact claimant before ACK/snapshot confirmation/continuation."""
    account, principal, consumer = _inputs(db, account, principal, consumer, owner)
    row = _owner(db, account, principal, consumer)
    if row is None or tuple(row) != (owner.registration_id, owner.service_epoch, owner.run_id):
        raise DirectCommandJournalError('CONSUMER_REPLAY_REQUIRED')


def account_event_visible_cursors(db, account, principal, consumer, owner):
    """Expose a prior registration's durable ACK, never its unacknowledged offer."""
    account, principal, consumer = _inputs(db, account, principal, consumer, owner)
    offered, acknowledged = _cursor(db, account, principal, consumer)
    row = _owner(db, account, principal, consumer)
    if row is None or tuple(row) != (owner.registration_id, owner.service_epoch, owner.run_id):
        offered = acknowledged
    return offered, acknowledged


def verify_account_event_consumer_owners(db, account):
    """Check bounded ownership rows, allowing legacy consumers without owners."""
    account = _text(account)
    rows = db.execute('SELECT account,principal,consumer,registration_id,service_epoch,run_id '
                      'FROM account_event_consumer_owners LIMIT ?', (_MAX_CONSUMERS + 1,)).fetchall()
    if len(rows) > _MAX_CONSUMERS:
        raise DirectCommandJournalError('INVALID_DATABASE')
    try:
        for row in rows:
            if row[0] != account:
                raise ValueError
            _text(row[1]); _text(row[2])
            AccountEventConsumerOwner(row[3], row[4], row[5])
            _cursor(db, *row[:3])
    except Exception as error:
        raise DirectCommandJournalError('INVALID_DATABASE') from error
