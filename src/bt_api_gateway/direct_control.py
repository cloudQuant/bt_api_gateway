"""Same-journal, owner-thread control causes and frozen DRAIN targets.

The methods in this module are trusted owner operations, not an authentication
boundary.  Transport and operator authorization must be established first.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

from .direct_command_journal import DirectCommandJournalError
from .session_guard import LocalAccountSessionGuard

_CONTROL_DDL = {
    'direct_control_causes': 'CREATE TABLE direct_control_causes (account TEXT NOT NULL, cause_id TEXT NOT NULL, scope_kind TEXT NOT NULL, scope_value TEXT NOT NULL, mode TEXT NOT NULL, origin TEXT NOT NULL, generation TEXT NOT NULL, version INTEGER NOT NULL, active INTEGER NOT NULL, resume_id TEXT, PRIMARY KEY(account, cause_id))',
    'direct_control_targets': 'CREATE TABLE direct_control_targets (account TEXT NOT NULL, cause_id TEXT NOT NULL, strategy TEXT NOT NULL, request_key TEXT NOT NULL, reservation_id TEXT NOT NULL, operation_id TEXT NOT NULL, state TEXT NOT NULL, terminal_fact_digest TEXT, terminal_sequence INTEGER, PRIMARY KEY(account, cause_id, reservation_id))',
    'direct_control_blocked': 'CREATE TABLE direct_control_blocked (account TEXT NOT NULL, cause_id TEXT NOT NULL, reservation_id TEXT NOT NULL, PRIMARY KEY(account, cause_id, reservation_id))',
}


# An instrument scope names one contract of the account: "<venue>:<native symbol>".
# Its causes are always FREEZE: every new order on that contract is refused for
# every strategy, opens and closes alike; cancellation is never a new order.
_INSTRUMENT_SCOPE = re.compile(r"[A-Za-z0-9]{1,16}:[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def instrument_scope_value(venue, symbol):
    """The scope value of one contract; invalid parts are refused, never normalised."""
    if type(venue) is not str or type(symbol) is not str or _INSTRUMENT_SCOPE.fullmatch(venue + ':' + symbol) is None:
        raise DirectCommandJournalError('CONTROL_INVALID_INPUT')
    return venue + ':' + symbol


def _instrument_scope(value):
    if type(value) is not str or _INSTRUMENT_SCOPE.fullmatch(value) is None:
        raise DirectCommandJournalError('CONTROL_INVALID_INPUT')
    return value


def _names_instrument(scope_value, payload):
    """Whether an order payload is for the contract of an instrument scope.

    A payload without a venue is matched by its symbol alone: an order that does
    not say where it trades is not let through a block on that symbol.
    """
    if not isinstance(payload, Mapping):
        return True
    venue, symbol = scope_value.split(':', 1)
    return payload.get('symbol') == symbol and payload.get('exchange_id') in (None, '', venue)


def _text(value):
    if type(value) is not str or not value or value != value.strip() or len(value) > 512:
        raise DirectCommandJournalError('CONTROL_INVALID_INPUT')
    return value


def verify_controls(db, account, capacity):
    causes = db.execute('SELECT * FROM direct_control_causes').fetchall()
    targets = db.execute("SELECT t.*,c.strategy AS original_strategy,c.request_key AS original_request_key, f.disposition AS fact_disposition,f.reason AS fact_reason,f.reservation_id AS fact_reservation,f.event_sequence AS fact_sequence,f.fact_json AS evidence_json FROM direct_control_targets t LEFT JOIN direct_journal_commands c ON c.account=t.account AND c.reservation_id=t.reservation_id LEFT JOIN direct_execution_facts f ON f.account=t.account AND f.fact_digest=t.terminal_fact_digest").fetchall()
    blocked = db.execute("SELECT b.*,c.strategy AS original_strategy,c.payload_json AS original_payload FROM direct_control_blocked b LEFT JOIN direct_journal_commands c ON c.account=b.account AND c.reservation_id=b.reservation_id").fetchall()
    if len(causes) > capacity or len(targets) > capacity or len(blocked) > capacity:
        raise DirectCommandJournalError('CONTROL_INVALID_DATABASE')
    indexed = {}
    resume_ids = set()
    for row in causes:
        try:
            if (row['account'] != account or row['scope_kind'] not in ('account', 'strategy', 'instrument')
                    or row['mode'] not in ('STOP_NEW', 'FREEZE', 'DRAIN')
                    or (row['scope_kind'] == 'instrument' and row['mode'] != 'FREEZE')
                    or type(row['version']) is not int or row['version'] not in (1, 2)
                    or row['active'] not in (0, 1) or row['version'] != (1 if row['active'] else 2)
                    or (row['active'] == 1 and row['resume_id'] is not None)
                    or (row['active'] == 0 and not row['resume_id'])):
                raise ValueError
            for key in ('cause_id', 'origin', 'generation'):
                _text(row[key])
            if row['scope_kind'] == 'account' and row['scope_value'] != '':
                raise ValueError
            if row['scope_kind'] == 'strategy':
                _text(row['scope_value'])
            if row['scope_kind'] == 'instrument':
                _instrument_scope(row['scope_value'])
            if row['resume_id'] is not None:
                _text(row['resume_id'])
                if row['resume_id'] in resume_ids:
                    raise ValueError
                resume_ids.add(row['resume_id'])
            indexed[row['cause_id']] = row
        except (ValueError, TypeError, DirectCommandJournalError):
            raise DirectCommandJournalError('CONTROL_INVALID_DATABASE') from None
    for row in blocked:
        cause = indexed.get(row['cause_id'])
        if (row['account'] != account or cause is None or row['original_strategy'] is None
                or (cause['scope_kind'] == 'strategy' and cause['scope_value'] != row['original_strategy'])):
            raise DirectCommandJournalError('CONTROL_INVALID_DATABASE')
        if cause['scope_kind'] == 'instrument':
            try:
                named = _names_instrument(cause['scope_value'], json.loads(row['original_payload']))
            except (ValueError, TypeError):
                named = False
            if not named:
                raise DirectCommandJournalError('CONTROL_INVALID_DATABASE')
    for row in targets:
        cause = indexed.get(row['cause_id'])
        expected = 'drain:' + hashlib.sha256(json.dumps([row['cause_id'], row['reservation_id']], separators=(',', ':')).encode()).hexdigest()
        if (row['account'] != account or cause is None or cause['mode'] != 'DRAIN' or row['original_strategy'] is None
                or (row['original_strategy'], row['original_request_key']) != (row['strategy'], row['request_key']) or row['operation_id'] != expected
                or row['state'] not in ('PENDING', 'UNKNOWN', 'CANCELLED', 'OBSERVED_TERMINAL')
                or ((row['state'] == 'OBSERVED_TERMINAL') != (row['terminal_fact_digest'] is not None and row['terminal_sequence'] is not None))
                or (row['state'] != 'OBSERVED_TERMINAL' and (row['terminal_fact_digest'] is not None or row['terminal_sequence'] is not None))
                or (not cause['active'] and row['state'] == 'PENDING')
                or (cause['scope_kind'] == 'strategy' and cause['scope_value'] != row['strategy'])):
            raise DirectCommandJournalError('CONTROL_INVALID_DATABASE')
        if row['state'] == 'OBSERVED_TERMINAL':
            if (row['evidence_json'] is None or row['fact_disposition'] != 'ATTRIBUTED' or row['fact_reason'] != 'MATCHED'
                    or row['fact_reservation'] != row['reservation_id'] or row['fact_sequence'] != row['terminal_sequence']):
                raise DirectCommandJournalError('CONTROL_INVALID_DATABASE')
            from bt_api_base.gateway_execution_protocol import GatewayReturnFact
            from bt_api_base.direct_write_protocol import DirectExecutionEventKind, DirectOrderStatus
            try:
                fact = GatewayReturnFact.from_mapping(json.loads(row['evidence_json']))
                if (fact.fact_digest() != row['terminal_fact_digest'] or fact.kind is not DirectExecutionEventKind.ORDER
                        or fact.status not in (DirectOrderStatus.CANCELLED, DirectOrderStatus.FILLED, DirectOrderStatus.REJECTED)):
                    raise ValueError
            except (ValueError, TypeError, KeyError):
                raise DirectCommandJournalError('CONTROL_INVALID_DATABASE') from None


def _terminal_observation(db, account, command):
    """The command's latest order return when it is an attributed, consistent terminal one.

    Returns ``(fact_digest, event_sequence)`` or ``None``. It is an observation,
    not proof of a complete provider snapshot: a later order return that is not
    terminal takes it back.
    """
    from decimal import Decimal, InvalidOperation

    from bt_api_base.direct_write_protocol import DirectExecutionEventKind, DirectOrderStatus
    from bt_api_base.gateway_execution_protocol import GatewayReturnFact

    rows = db.execute("SELECT f.* FROM direct_execution_facts f WHERE f.account=? AND f.reservation_id=? "
                      "AND f.event_sequence IS NOT NULL ORDER BY f.event_sequence DESC",
                      (account, command['reservation_id'])).fetchall()
    for row in rows:
        fact = GatewayReturnFact.from_mapping(json.loads(row['fact_json']))
        if fact.kind is not DirectExecutionEventKind.ORDER:
            continue
        try:
            native, payload = json.loads(command['native_identity_json']), json.loads(command['payload_json'])
            total, filled = Decimal(fact.order_quantity), Decimal(fact.filled_quantity)
            valid = (row['disposition'] == 'ATTRIBUTED' and row['reason'] == 'MATCHED'
                and fact.fact_digest() == row['fact_digest'] and fact.account_scope == account
                and fact.route == native['exchange_name'] and fact.instrument.native_symbol == payload['symbol']
                and total.is_finite() and filled.is_finite() and total == Decimal(payload['quantity']) and 0 <= filled <= total
                and fact.status in (DirectOrderStatus.CANCELLED, DirectOrderStatus.FILLED, DirectOrderStatus.REJECTED)
                and (fact.status is not DirectOrderStatus.FILLED or filled == total)
                and (fact.status is not DirectOrderStatus.REJECTED or filled == 0))
        except (ValueError, TypeError, KeyError, InvalidOperation):
            valid = False
        return (row['fact_digest'], row['event_sequence']) if valid else None
    return None


def check_controls(db, account, strategy, payload, *, allow_verified_close=None):
    """Check the same write transaction used for reserve/begin_dispatch.

    A close is admitted under STOP_NEW only when the caller's same-transaction
    trusted capacity verifier succeeds. FREEZE and DRAIN always block it. An
    instrument cause blocks every strategy's order on its contract, and only
    those: orders on other contracts do not see it.
    """
    rows = db.execute(
        'SELECT cause_id,mode FROM direct_control_causes WHERE account=? AND active=1 '
        'AND (scope_kind=? OR (scope_kind=? AND scope_value=?)) '
        'ORDER BY CASE mode WHEN ? THEN 0 WHEN ? THEN 0 ELSE 1 END,cause_id',
        (account, 'account', 'strategy', strategy, 'FREEZE', 'DRAIN'),
    ).fetchall()
    if any(_names_instrument(row['scope_value'], payload) for row in db.execute(
            "SELECT scope_value FROM direct_control_causes WHERE account=? AND active=1 AND scope_kind='instrument'",
            (account,))):
        raise DirectCommandJournalError('CONTROL_FREEZE')
    if rows:
        if (all(row['mode'] == 'STOP_NEW' for row in rows) and callable(allow_verified_close)
                and allow_verified_close() is True):
            return
        raise DirectCommandJournalError('CONTROL_' + rows[0]['mode'])


class GatewayDirectControl:
    """Control state bound to one journal and its held account-session guard."""

    def __init__(self, journal, guard):
        from .direct_command_journal import GatewayDirectCommandJournal
        if type(journal) is not GatewayDirectCommandJournal or type(guard) is not LocalAccountSessionGuard:
            raise DirectCommandJournalError('CONTROL_INVALID_BINDING')
        self._journal, self._guard = journal, guard
        self._generation = journal.generation
        self._busy = False
        self._claims = {}
        self._owned()
        if journal._schema_version < 10:
            raise DirectCommandJournalError('CONTROL_UPGRADE_REQUIRED')

    def _owned(self):
        self._guard.assert_owned()
        if (self._guard.account_key_digest != hashlib.sha256(self._journal.account_scope.encode('utf-8')).hexdigest()
                or self._guard.acquire() != self._generation):
            raise DirectCommandJournalError('CONTROL_GUARD_MISMATCH')
        if self._busy:
            raise DirectCommandJournalError('CONTROL_REENTRANT')

    def apply(self, cause_id, mode, *, scope_kind, scope_value='', origin, before_commit=None):
        self._owned()
        cause_id, origin = _text(cause_id), _text(origin)
        if mode not in ('STOP_NEW', 'FREEZE', 'DRAIN') or scope_kind not in ('account', 'strategy', 'instrument'):
            raise DirectCommandJournalError('CONTROL_INVALID_INPUT')
        if scope_kind == 'account':
            if scope_value != '':
                raise DirectCommandJournalError('CONTROL_INVALID_INPUT')
        elif scope_kind == 'instrument':
            if mode != 'FREEZE':
                raise DirectCommandJournalError('CONTROL_INVALID_INPUT')
            scope_value = _instrument_scope(scope_value)
        else:
            scope_value = _text(scope_value)
        j = self._journal
        with j._transaction() as db:
            old = db.execute('SELECT * FROM direct_control_causes WHERE account=? AND cause_id=?',
                             (j.account_scope, cause_id)).fetchone()
            if old is not None:
                if (old['scope_kind'], old['scope_value'], old['mode'], old['origin']) != (scope_kind, scope_value, mode, origin):
                    raise DirectCommandJournalError('CONTROL_CAUSE_CONFLICT')
                if before_commit is not None:
                    before_commit()
                return dict(old)
            if db.execute('SELECT count(*) FROM direct_control_causes WHERE account=?', (j.account_scope,)).fetchone()[0] >= j._max_records:
                raise DirectCommandJournalError('CONTROL_CAPACITY_EXCEEDED')
            db.execute('INSERT INTO direct_control_causes VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, NULL)',
                       (j.account_scope, cause_id, scope_kind, scope_value, mode, origin, self._generation))
            pending_query = "SELECT reservation_id FROM direct_journal_commands WHERE account=? AND status='RESERVED'"
            pending_args = [j.account_scope]
            if scope_kind == 'strategy':
                pending_query += ' AND strategy=?'
                pending_args.append(scope_value)
            if scope_kind == 'instrument':
                pending_query = pending_query.replace('SELECT reservation_id', 'SELECT reservation_id,payload_json')
            pending = db.execute(pending_query, pending_args).fetchall()
            if scope_kind == 'instrument':
                # Only what was reserved for this contract; other contracts go on.
                pending = [row for row in pending if _names_instrument(scope_value, json.loads(row['payload_json']))]
            total_blocked = db.execute('SELECT count(*) FROM direct_control_blocked WHERE account=?', (j.account_scope,)).fetchone()[0]
            if total_blocked + len(pending) > j._max_records:
                raise DirectCommandJournalError('CONTROL_CAPACITY_EXCEEDED')
            for pending_row in pending:
                db.execute('INSERT INTO direct_control_blocked VALUES (?, ?, ?)', (j.account_scope, cause_id, pending_row['reservation_id']))
            if mode == 'DRAIN':
                query = ('SELECT strategy,request_key,reservation_id,native_identity_json,payload_json '
                         'FROM direct_journal_commands WHERE account=? AND status IN (?, ?, ?)')
                args = [j.account_scope, 'DISPATCHING', 'SENT', 'UNKNOWN']
                if scope_kind == 'strategy':
                    query += ' AND strategy=?'
                    args.append(scope_value)
                # An order the journal already saw end (cancelled, filled or rejected) needs no
                # cancel and is not frozen as a target. Freezing every order ever sent made each
                # DRAIN add one row per historical order: the table has a fixed capacity, and a
                # DRAIN that no longer fits is refused exactly when it is needed (I63-E131).
                # Limit: the choice is made once, here. An order left out because it had ended
                # is not looked at again by this cause; should a non-terminal return for it be
                # stored later (a stale query answer, for instance), this DRAIN does not turn
                # UNKNOWN for it as it would for a target. The account comparison and the
                # return ledger are the checks for that case.
                targets = [row for row in db.execute(query, args).fetchall()
                           if _terminal_observation(db, j.account_scope, row) is None]
                prior = db.execute('SELECT count(*) FROM direct_control_targets WHERE account=?', (j.account_scope,)).fetchone()[0]
                if len(targets) + prior > j._max_records:
                    raise DirectCommandJournalError('CONTROL_CAPACITY_EXCEEDED')
                for row in targets:
                    op = 'drain:' + hashlib.sha256(json.dumps([cause_id, row['reservation_id']], separators=(',', ':')).encode()).hexdigest()
                    db.execute('INSERT INTO direct_control_targets VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)',
                               (j.account_scope, cause_id, row['strategy'], row['request_key'], row['reservation_id'], op, 'PENDING'))
            if before_commit is not None:
                before_commit()
            j._bump(db)
            return dict(db.execute('SELECT * FROM direct_control_causes WHERE account=? AND cause_id=?', (j.account_scope, cause_id)).fetchone())

    def resume(self, cause_id, *, expected_version, operation_id, before_commit=None, before_commit_db=None):
        self._owned()
        cause_id, operation_id = _text(cause_id), _text(operation_id)
        if (type(expected_version) is not int or expected_version < 1
                or (before_commit_db is not None and not callable(before_commit_db))):
            raise DirectCommandJournalError('CONTROL_INVALID_INPUT')
        j = self._journal
        with j._transaction() as db:
            row = db.execute('SELECT * FROM direct_control_causes WHERE account=? AND cause_id=?', (j.account_scope, cause_id)).fetchone()
            if row is None:
                raise DirectCommandJournalError('CONTROL_NOT_FOUND')
            if row['active'] == 0:
                if row['version'] == expected_version + 1 and row['resume_id'] == operation_id:
                    if before_commit_db is not None and before_commit_db(db) is not True:
                        raise DirectCommandJournalError('CONTROL_RECOVERY_UNVERIFIED')
                    if before_commit is not None:
                        before_commit()
                    return dict(row)
                raise DirectCommandJournalError('CONTROL_VERSION_CONFLICT')
            if row['version'] != expected_version:
                raise DirectCommandJournalError('CONTROL_VERSION_CONFLICT')
            if db.execute('SELECT 1 FROM direct_control_causes WHERE account=? AND resume_id=?', (j.account_scope, operation_id)).fetchone():
                raise DirectCommandJournalError('CONTROL_OPERATION_CONFLICT')
            db.execute('UPDATE direct_control_causes SET active=0,version=version+1,resume_id=? WHERE account=? AND cause_id=?', (operation_id, j.account_scope, cause_id))
            db.execute("UPDATE direct_control_targets SET state='CANCELLED' WHERE account=? AND cause_id=? AND state='PENDING'", (j.account_scope, cause_id))
            if before_commit_db is not None and before_commit_db(db) is not True:
                raise DirectCommandJournalError('CONTROL_RECOVERY_UNVERIFIED')
            if before_commit is not None:
                before_commit()
            j._bump(db)
            return dict(db.execute('SELECT * FROM direct_control_causes WHERE account=? AND cause_id=?', (j.account_scope, cause_id)).fetchone())

    def get(self, cause_id):
        self._owned()
        with self._journal._transaction() as db:
            row = db.execute('SELECT * FROM direct_control_causes WHERE account=? AND cause_id=?', (self._journal.account_scope, _text(cause_id))).fetchone()
            if row is None:
                raise DirectCommandJournalError('CONTROL_NOT_FOUND')
            return dict(row)

    def active_system_causes(self, origin):
        """Owner-only lookup; callers must supply their installed system origin."""
        self._owned()
        origin = _text(origin)
        with self._journal._transaction() as db:
            return tuple(dict(row) for row in db.execute(
                "SELECT * FROM direct_control_causes WHERE account=? AND origin=? AND active=1 ORDER BY cause_id",
                (self._journal.account_scope, origin)))

    def active_drain_causes(self, *, after='', limit=64):
        """Owner-only page of the account's active DRAIN causes, whoever applied them."""
        self._owned()
        if (type(after) is not str or (after and _text(after) != after)
                or type(limit) is not int or not 1 <= limit <= 256):
            raise DirectCommandJournalError('CONTROL_INVALID_INPUT')
        with self._journal._transaction() as db:
            return tuple(dict(row) for row in db.execute(
                "SELECT * FROM direct_control_causes WHERE account=? AND mode='DRAIN' AND active=1 "
                "AND cause_id>? ORDER BY cause_id LIMIT ?", (self._journal.account_scope, after, limit)))

    def list_causes(self, *, scope_kind, scope_value='', after='', limit=128):
        """Read a bounded page for the caller's already-authorized exact scope."""
        self._owned()
        if (scope_kind not in ('account', 'strategy', 'instrument') or type(after) is not str
                or (after and _text(after) != after) or type(limit) is not int or not 1 <= limit <= 256):
            raise DirectCommandJournalError('CONTROL_INVALID_INPUT')
        if scope_kind == 'account':
            if scope_value != '':
                raise DirectCommandJournalError('CONTROL_INVALID_INPUT')
        elif scope_kind == 'instrument':
            if scope_value == '':
                # Every contract of the account, for a caller authorised for the whole account.
                with self._journal._transaction() as db:
                    return tuple(dict(row) for row in db.execute(
                        "SELECT * FROM direct_control_causes WHERE account=? AND scope_kind='instrument' "
                        'AND cause_id>? ORDER BY cause_id LIMIT ?',
                        (self._journal.account_scope, after, limit)))
            scope_value = _instrument_scope(scope_value)
        else:
            scope_value = _text(scope_value)
        with self._journal._transaction() as db:
            return tuple(dict(row) for row in db.execute(
                'SELECT * FROM direct_control_causes WHERE account=? AND scope_kind=? AND scope_value=? '
                'AND cause_id>? ORDER BY cause_id LIMIT ?',
                (self._journal.account_scope, scope_kind, scope_value, after, limit)))

    def resume_status(self, operation_id, *, scope_kind, scope_value=''):
        self._owned()
        operation_id = _text(operation_id)
        if (scope_kind not in ('account', 'strategy', 'instrument')
                or (scope_kind == 'account' and scope_value != '')):
            raise DirectCommandJournalError('CONTROL_INVALID_INPUT')
        if scope_kind == 'strategy':
            scope_value = _text(scope_value)
        if scope_kind == 'instrument' and scope_value != '':
            scope_value = _instrument_scope(scope_value)
        with self._journal._transaction() as db:
            if scope_kind == 'instrument' and scope_value == '':
                # Any contract of the account, for a caller authorised for the whole account.
                row = db.execute("SELECT * FROM direct_control_causes WHERE account=? AND scope_kind='instrument' "
                                 'AND resume_id=?', (self._journal.account_scope, operation_id)).fetchone()
                return None if row is None else dict(row)
            row = db.execute('SELECT * FROM direct_control_causes WHERE account=? AND scope_kind=? '
                             'AND scope_value=? AND resume_id=?',
                             (self._journal.account_scope, scope_kind, scope_value, operation_id)).fetchone()
            return None if row is None else dict(row)

    def target_status(self, cause_id, operation_id):
        self._owned()
        with self._journal._transaction() as db:
            row = db.execute('SELECT * FROM direct_control_targets WHERE account=? AND cause_id=? AND operation_id=?',
                (self._journal.account_scope, _text(cause_id), _text(operation_id))).fetchone()
            return None if row is None else dict(row)

    def reconcile_targets(self, cause_id, *, before_commit=None):
        """Track the latest attributable terminal ORDER fact for frozen targets.

        The observation is not proof of a complete provider snapshot; later
        contradictory order facts cause the next reconciliation to return UNKNOWN.
        """
        self._owned()
        cause_id = _text(cause_id)
        j = self._journal
        with j._transaction() as db:
            cause = db.execute('SELECT * FROM direct_control_causes WHERE account=? AND cause_id=?', (j.account_scope, cause_id)).fetchone()
            if cause is None or cause['mode'] != 'DRAIN':
                raise DirectCommandJournalError('CONTROL_NOT_FOUND')
            changed = False
            targets = db.execute("SELECT * FROM direct_control_targets WHERE account=? AND cause_id=? AND state!='CANCELLED'", (j.account_scope, cause_id)).fetchall()
            for target in targets:
                command = db.execute('SELECT * FROM direct_journal_commands WHERE account=? AND reservation_id=?', (j.account_scope, target['reservation_id'])).fetchone()
                observed = _terminal_observation(db, j.account_scope, command)
                if observed is not None:
                    state, (digest, seq) = 'OBSERVED_TERMINAL', observed
                elif target['state'] == 'OBSERVED_TERMINAL':
                    state, digest, seq = 'UNKNOWN', None, None
                else:
                    continue
                if (target['state'], target['terminal_fact_digest'], target['terminal_sequence']) != (state, digest, seq):
                    db.execute('UPDATE direct_control_targets SET state=?,terminal_fact_digest=?,terminal_sequence=? WHERE account=? AND cause_id=? AND reservation_id=?', (state, digest, seq, j.account_scope, cause_id, target['reservation_id']))
                    changed = True
            if before_commit is not None:
                before_commit()
            if changed:
                j._bump(db)
            return changed

    def targets(self, cause_id, *, after='', limit=128):
        self._owned()
        if type(limit) is not int or not 1 <= limit <= 256 or type(after) is not str or (after and _text(after) != after):
            raise DirectCommandJournalError('CONTROL_INVALID_INPUT')
        with self._journal._transaction() as db:
            return tuple(dict(row) for row in db.execute('SELECT * FROM direct_control_targets WHERE account=? AND cause_id=? AND reservation_id>? ORDER BY reservation_id LIMIT ?', (self._journal.account_scope, _text(cause_id), after, limit)))

    def issue_next(self, cause_id, cancel):
        """Attempt one frozen target; an exception/lost result is never retried.

        ``cancel`` is a trusted synchronous owner callback that creates and
        dispatches the existing durable cancellation using the supplied stable
        operation ID. It must not call this controller recursively.
        """
        self._owned()
        if not callable(cancel):
            raise DirectCommandJournalError('CONTROL_INVALID_INPUT')
        j = self._journal
        with j._transaction() as db:
            cause = db.execute('SELECT * FROM direct_control_causes WHERE account=? AND cause_id=?', (j.account_scope, _text(cause_id))).fetchone()
            if cause is None or cause['active'] != 1 or cause['mode'] != 'DRAIN':
                raise DirectCommandJournalError('CONTROL_INACTIVE')
            row = db.execute("SELECT * FROM direct_control_targets WHERE account=? AND cause_id=? AND state='PENDING' ORDER BY reservation_id LIMIT 1", (j.account_scope, cause_id)).fetchone()
            if row is None:
                return None
            db.execute("UPDATE direct_control_targets SET state='UNKNOWN' WHERE account=? AND cause_id=? AND reservation_id=?", (j.account_scope, cause_id, row['reservation_id']))
            j._bump(db)
            target = dict(row)
        self._busy = True
        try:
            cancel(target)
        finally:
            self._busy = False
        return target

    def issue_next_cancel(self, cause_id, dispatcher):
        """Legacy unbound caller cannot authorize a durable control cancellation."""
        raise DirectCommandJournalError('CONTROL_CANCEL_PROOF_REQUIRED')

    def claim_target(self, cause_id, reservation_id, *, before_commit=None):
        """Claim an exact frozen target once, within the local journal transaction."""
        self._owned()
        cause_id, reservation_id = _text(cause_id), _text(reservation_id)
        j = self._journal
        with j._transaction() as db:
            cause = db.execute('SELECT * FROM direct_control_causes WHERE account=? AND cause_id=?', (j.account_scope, cause_id)).fetchone()
            if cause is None or cause['active'] != 1 or cause['mode'] != 'DRAIN':
                raise DirectCommandJournalError('CONTROL_INACTIVE')
            row = db.execute('SELECT * FROM direct_control_targets WHERE account=? AND cause_id=? AND reservation_id=?', (j.account_scope, cause_id, reservation_id)).fetchone()
            if row is None:
                raise DirectCommandJournalError('CONTROL_TARGET_NOT_FOUND')
            target = dict(row)
            if row['state'] in ('UNKNOWN', 'OBSERVED_TERMINAL'):
                if before_commit is not None:
                    before_commit()
                return target, None
            if row['state'] != 'PENDING':
                raise DirectCommandJournalError('CONTROL_TARGET_INACTIVE')
            db.execute("UPDATE direct_control_targets SET state='UNKNOWN' WHERE account=? AND cause_id=? AND reservation_id=?", (j.account_scope, cause_id, reservation_id))
            if before_commit is not None:
                before_commit()
            j._bump(db)
            target['state'] = 'UNKNOWN'
        token = object()
        self._claims[reservation_id] = (token, target)
        return target, token

    def dispatch_claimed_cancel(self, target, dispatcher, token, *, request_fence=None,
                                requester=None, authority_source=None):
        """Dispatch a just-claimed cancellation on the same owner call stack."""
        from bt_api_base.direct_write_protocol import NativeOrderIdentity
        from .direct_cancel_dispatch import GatewayDirectCancelDispatcher
        self._owned()
        if type(target) is not dict or type(dispatcher) is not GatewayDirectCancelDispatcher or dispatcher.journal.journal is not self._journal:
            raise DirectCommandJournalError('CONTROL_INVALID_CANCEL_DISPATCHER')
        if (self._journal._schema_version < 17 or not callable(request_fence)
                or type(requester) is not str or not requester or type(authority_source) is not dict):
            raise DirectCommandJournalError('CONTROL_CANCEL_PROOF_REQUIRED')
        dispatcher._owned()
        claim = self._claims.pop(target.get('reservation_id'), None)
        if claim is None or claim[0] is not token or claim[1] != target:
            raise DirectCommandJournalError('CONTROL_CLAIM_INVALID')
        j = self._journal
        with j._transaction() as db:
            stored = db.execute('SELECT * FROM direct_control_targets WHERE account=? AND cause_id=? AND reservation_id=?', (j.account_scope, target['cause_id'], target['reservation_id'])).fetchone()
            cause = db.execute('SELECT * FROM direct_control_causes WHERE account=? AND cause_id=?', (j.account_scope, target['cause_id'])).fetchone()
            row = db.execute('SELECT * FROM direct_journal_commands WHERE account=? AND reservation_id=?', (j.account_scope, target['reservation_id'])).fetchone()
            if (stored is None or dict(stored) != target or stored['state'] != 'UNKNOWN'
                    or cause is None or cause['active'] != 1 or row is None
                    or row['status'] not in ('DISPATCHING', 'SENT', 'UNKNOWN')):
                raise DirectCommandJournalError('CONTROL_TARGET_UNAVAILABLE')
            raw = json.loads(row['native_identity_json'])
            identity = NativeOrderIdentity(raw['exchange_name'], raw['client_order_id'], json.loads(raw['fields_json']), raw['session_generation'])
            symbol = json.loads(row['payload_json'])['symbol']
            principal, digest = row['principal'], row['digest']
        self._busy = True
        try:
            from contextlib import contextmanager
            from .direct_control_cancel import authorize_control_cancel
            active = [None]
            @contextmanager
            def fenced(record):
                with request_fence(record) as check:
                    if not callable(check):
                        raise DirectCommandJournalError('CONTROL_CANCEL_DENIED')
                    active[0] = check
                    try:
                        check()
                        yield check
                    finally:
                        active[0] = None
            def verify(_db, proof):
                if active[0] is None:
                    return False
                active[0]()
                return (proof['requester'] == requester and proof['source'] == authority_source
                        and proof['target_principal'] == principal and proof['digest'] == digest)
            with fenced(None):
                with j._transaction() as db:
                    permit = authorize_control_cancel(db, account=j.account_scope, journal_id=j.journal_id,
                        generation=j.generation, cause_id=target['cause_id'], reservation_id=target['reservation_id'],
                        requester=requester, source=authority_source, verify_current=verify)
            attempt = dispatcher.journal.request(target['strategy'], target['operation_id'], requester,
                target['request_key'], target['reservation_id'], digest, target_identity=identity, symbol=symbol,
                target_principal=principal, strategy_admission_fence=lambda: fenced(None), control_cancel_permit=permit)
            return dispatcher.dispatch(target['strategy'], target['operation_id'], requester,
                expected_version=attempt.version, request_fence=fenced, control_cancel_permit=permit)
        finally:
            self._busy = False
