"""Owner-local, durable DRAIN cancellation authority.

Only the service owner may construct permits.  The source verifier and its
Registry/expiry fence are trusted local capabilities, never wire arguments.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .direct_command_journal import DirectCommandJournalError, _json, _text
from .direct_control import _TARGET_MODES, _instrument_scope, _names_instrument

_CONTROL_CANCEL_DDL = {
    'direct_control_cancel_proofs': 'CREATE TABLE direct_control_cancel_proofs (account TEXT NOT NULL, strategy TEXT NOT NULL, operation_id TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE, proof_json TEXT NOT NULL, proof_digest TEXT NOT NULL, PRIMARY KEY(account, strategy, operation_id))',
}


def _deny():
    raise DirectCommandJournalError('CONTROL_CANCEL_DENIED')


def _snapshot(db, account, journal_id, generation, cause_id, reservation_id, requester, source):
    if not db.in_transaction or type(source) is not dict or set(source) != {'kind', 'actor', 'registration', 'epoch', 'event_id'}:
        _deny()
    if source['kind'] not in ('operator', 'lease'):
        _deny()
    for name in ('actor', 'registration', 'epoch'):
        _text(source[name])
    if source['kind'] == 'lease':
        _text(source['event_id'])
    elif source['event_id'] is not None:
        _deny()
    meta = db.execute('SELECT journal_id FROM direct_journal_meta WHERE account=?', (account,)).fetchone()
    cause = db.execute('SELECT * FROM direct_control_causes WHERE account=? AND cause_id=?', (account, cause_id)).fetchone()
    target = db.execute('SELECT * FROM direct_control_targets WHERE account=? AND cause_id=? AND reservation_id=?', (account, cause_id, reservation_id)).fetchone()
    row = db.execute('SELECT * FROM direct_journal_commands WHERE account=? AND reservation_id=?', (account, reservation_id)).fetchone()
    if (meta is None or meta[0] != journal_id or cause is None or target is None or row is None
            or cause['mode'] not in _TARGET_MODES or cause['active'] != 1 or cause['generation'] != generation
            or target['state'] != 'UNKNOWN' or row['status'] != 'SENT'
            or (target['strategy'], target['request_key']) != (row['strategy'], row['request_key'])
            or (cause['scope_kind'] == 'strategy' and cause['scope_value'] != row['strategy'])
            or (cause['scope_kind'] == 'instrument'
                and not _names_instrument(cause['scope_value'], json.loads(row['payload_json'])))
            or row['native_identity_json'] is None):
        _deny()
    keys = [r[0] for r in db.execute('SELECT strong_key FROM direct_journal_strong_keys WHERE account=? AND reservation_id=? ORDER BY strong_key', (account, reservation_id))]
    if not keys:
        _deny()
    return {'schema_version': 1, 'account': account, 'journal_id': journal_id, 'generation': generation,
            'cause_id': cause_id, 'cause_version': cause['version'], 'scope_kind': cause['scope_kind'],
            'scope_value': cause['scope_value'], 'strategy': row['strategy'], 'request_key': row['request_key'],
            'reservation_id': reservation_id, 'operation_id': target['operation_id'], 'requester': requester,
            'target_principal': row['principal'], 'digest': row['digest'], 'native_identity_json': row['native_identity_json'],
            'strong_keys': keys, 'symbol': json.loads(row['payload_json'])['symbol'], 'source': dict(source)}


@dataclass(frozen=True, slots=True)
class GatewayControlCancelPermit:
    binding_json: str
    verify_current: object

    @property
    def binding(self):
        return json.loads(self.binding_json)

    def recheck(self, db):
        b = self.binding
        if (not callable(self.verify_current) or self.verify_current(db, b) is not True
                or _snapshot(db, b['account'], b['journal_id'], b['generation'], b['cause_id'],
                             b['reservation_id'], b['requester'], b['source']) != b
                or self.verify_current(db, b) is not True):
            _deny()

    def append(self, db, attempt_id):
        self.recheck(db)
        b = self.binding
        db.execute('INSERT INTO direct_control_cancel_proofs VALUES (?, ?, ?, ?, ?, ?)',
                   (b['account'], b['strategy'], b['operation_id'], _text(attempt_id), self.binding_json,
                    hashlib.sha256(self.binding_json.encode('ascii')).hexdigest()))
        self.recheck(db)


def authorize_control_cancel(db, *, account, journal_id, generation, cause_id, reservation_id,
                             requester, source, verify_current):
    """Snapshot the already claimed target under a held trusted admission fence."""
    for item in (account, journal_id, generation, cause_id, reservation_id, requester):
        _text(item)
    permit = GatewayControlCancelPermit(_json(_snapshot(db, account, journal_id, generation,
        cause_id, reservation_id, requester, source)), verify_current)
    permit.recheck(db)
    return permit


def verify_control_cancel_integrity(db, account, journal_id, capacity):
    try:
        rows = db.execute('SELECT * FROM direct_control_cancel_proofs LIMIT ?', (capacity + 1,)).fetchall()
        if len(rows) > capacity:
            raise ValueError
        for row in rows:
            b = json.loads(row['proof_json'])
            fields = {'schema_version', 'account', 'journal_id', 'generation', 'cause_id', 'cause_version',
                      'scope_kind', 'scope_value', 'strategy', 'request_key', 'reservation_id', 'operation_id',
                      'requester', 'target_principal', 'digest', 'native_identity_json', 'strong_keys', 'symbol', 'source'}
            source = b.get('source') if type(b) is dict else None
            if (type(b) is not dict or set(b) != fields or type(b['schema_version']) is not int or b['schema_version'] != 1
                    or type(b['cause_version']) is not int or b['cause_version'] != 1
                    or b['scope_kind'] not in ('account', 'strategy', 'instrument')
                    or (b['scope_kind'] == 'account' and b['scope_value'] != '')
                    or (b['scope_kind'] == 'strategy' and b['scope_value'] != b['strategy'])
                    or type(b['strong_keys']) is not list or not b['strong_keys']
                    or b['strong_keys'] != sorted(set(b['strong_keys']))
                    or type(source) is not dict or set(source) != {'kind', 'actor', 'registration', 'epoch', 'event_id'}
                    or source['kind'] not in ('operator', 'lease')
                    or (source['kind'] == 'operator' and source['event_id'] is not None)
                    or (source['kind'] == 'lease' and not source['event_id'])
                    or _json(b) != row['proof_json'] or hashlib.sha256(row['proof_json'].encode('ascii')).hexdigest() != row['proof_digest']
                    or b['account'] != account or b['journal_id'] != journal_id
                    or (row['account'], row['strategy'], row['operation_id']) != (account, b['strategy'], b['operation_id'])):
                raise ValueError
            for value in (b['generation'], b['cause_id'], b['strategy'], b['request_key'], b['reservation_id'],
                          b['operation_id'], b['requester'], b['target_principal'], b['digest'], b['symbol'],
                          source['actor'], source['registration'], source['epoch'], *b['strong_keys']):
                _text(value)
            if source['kind'] == 'lease':
                _text(source['event_id'])
            if b['scope_kind'] == 'instrument':
                _instrument_scope(b['scope_value'])
            cause = db.execute('SELECT * FROM direct_control_causes WHERE account=? AND cause_id=?', (account, b['cause_id'])).fetchone()
            target = db.execute('SELECT * FROM direct_control_targets WHERE account=? AND cause_id=? AND reservation_id=?', (account, b['cause_id'], b['reservation_id'])).fetchone()
            cmd = db.execute('SELECT * FROM direct_journal_commands WHERE account=? AND reservation_id=?', (account, b['reservation_id'])).fetchone()
            attempt = db.execute('SELECT * FROM direct_cancel_attempts WHERE account=? AND attempt_id=?', (account, row['attempt_id'])).fetchone()
            keys = [r[0] for r in db.execute('SELECT strong_key FROM direct_journal_strong_keys WHERE account=? AND reservation_id=? ORDER BY strong_key', (account, b['reservation_id']))]
            if (cause is None or target is None or cmd is None or attempt is None or cause['mode'] not in _TARGET_MODES
                    or (b['scope_kind'] == 'instrument'
                        and not _names_instrument(b['scope_value'], json.loads(cmd['payload_json'])))
                    or cause['generation'] != b['generation'] or cause['scope_kind'] != b['scope_kind'] or cause['scope_value'] != b['scope_value']
                    or cause['version'] < b['cause_version'] or (target['strategy'], target['request_key'], target['operation_id']) != (b['strategy'], b['request_key'], b['operation_id'])
                    or (cmd['strategy'], cmd['request_key'], cmd['principal'], cmd['digest'], cmd['native_identity_json']) != (b['strategy'], b['request_key'], b['target_principal'], b['digest'], b['native_identity_json'])
                    or not set(b['strong_keys']).issubset(keys) or not b['strong_keys']
                    or (attempt['account'], attempt['strategy'], attempt['operation_id'], attempt['request_key']) != (account, b['strategy'], b['operation_id'], b['request_key'])
                    or (attempt['principal'], attempt['target_principal'], attempt['target_reservation_id'], attempt['target_digest'], attempt['target_identity_json'], attempt['symbol']) != (b['requester'], b['target_principal'], b['reservation_id'], b['digest'], b['native_identity_json'], b['symbol'])):
                raise ValueError
    except Exception as exc:
        raise DirectCommandJournalError('INVALID_DATABASE') from exc
