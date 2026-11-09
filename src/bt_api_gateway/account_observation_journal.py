"""Durable account fact observations, separate from strategy event cursors.

Only the guarded account owner calls these functions inside its existing SQLite
transaction.  A snapshot records a classification at that time; neither its
receipt digest nor stream sequence proves provider source or a venue cut.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass

from bt_api_base.gateway_execution_protocol import GatewayReturnFact
from .direct_command_journal import DirectCommandJournalError, _json, _text

_ACCOUNT_FACT_DDL = {
    "account_fact_stream_meta": "CREATE TABLE account_fact_stream_meta (account TEXT PRIMARY KEY, epoch TEXT NOT NULL, bootstrap_count INTEGER NOT NULL)",
    "account_fact_stream_events": "CREATE TABLE account_fact_stream_events (sequence INTEGER PRIMARY KEY, account TEXT NOT NULL, fact_digest TEXT NOT NULL, fact_json TEXT NOT NULL, disposition TEXT NOT NULL, reason TEXT NOT NULL, strategy TEXT, execution_sequence INTEGER, receipt_digest TEXT, receipt_json TEXT, reservation_id TEXT, origin TEXT, parent_ref TEXT, child_id TEXT, phase TEXT NOT NULL, event_digest TEXT NOT NULL)",
    "account_fact_stream_consumers": "CREATE TABLE account_fact_stream_consumers (account TEXT NOT NULL, principal TEXT NOT NULL, consumer TEXT NOT NULL, offered_sequence INTEGER NOT NULL, acknowledged_sequence INTEGER NOT NULL, PRIMARY KEY(account, principal, consumer))",
}
_MAX_FACTS = 1_000_000
_MAX_CONSUMERS = 8192


@dataclass(frozen=True, slots=True)
class AccountFactEvent:
    sequence: int
    account_scope: str
    fact_digest: str
    fact: GatewayReturnFact
    disposition: str
    reason: str
    strategy_scope: str | None
    execution_sequence: int | None
    external_receipt_digest: str | None
    external_receipt_json: str | None
    reservation_id: str | None
    origin: str | None
    parent_ref: str | None
    child_id: str | None
    phase: str
    event_digest: str


@dataclass(frozen=True, slots=True)
class AccountFactProgress:
    principal_id: str
    consumer_ref: str
    epoch: str
    offered_sequence: int
    acknowledged_sequence: int
    bootstrap_count: int


@dataclass(frozen=True, slots=True)
class AccountFactPage:
    events: tuple[AccountFactEvent, ...]
    epoch: str
    offered_sequence: int
    acknowledged_sequence: int
    has_more: bool
    bootstrap_count: int


def _fail(code="INVALID_DATABASE"):
    raise DirectCommandJournalError(code)


def _sequence(value):
    if type(value) is not int or not 0 <= value < 2**63:
        _fail("INVALID_SEQUENCE")
    return value


def _epoch(db, account):
    row = db.execute("SELECT epoch,bootstrap_count FROM account_fact_stream_meta WHERE account=?", (account,)).fetchone()
    if row is None:
        _fail("ACCOUNT_FACT_STREAM_UNAVAILABLE")
    return row[0], row[1]


def _fact(raw):
    try:
        fact = GatewayReturnFact.from_mapping(json.loads(raw))
        if _json(fact.to_mapping()) != raw:
            _fail()
        return fact
    except Exception as exc:
        raise DirectCommandJournalError("INVALID_DATABASE") from exc


def _delegation_labels(db, account, reservation_id, strategy, fact):
    """Resolve immutable labels exclusively through the persisted command."""
    from bt_api_base.gateway_delegation_protocol import GatewayDelegatedCommand
    from bt_api_base.gateway_direct_protocol import gateway_payload_digest
    row = db.execute(
        "SELECT c.strategy,c.request_key,c.principal,c.digest,c.payload_json,"
        "d.account,d.strategy,d.request_key,d.reservation_id,d.actor_principal,d.envelope_json,d.envelope_digest "
        "FROM direct_journal_commands c LEFT JOIN direct_delegated_commands d "
        "ON d.account=c.account AND d.reservation_id=c.reservation_id "
        "WHERE c.account=? AND c.reservation_id=?", (account, reservation_id),
    ).fetchone()
    if row is None or row[0] != strategy:
        _fail()
    if row[5] is None:
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='direct_strategy_origins'").fetchone() is not None:
            from .direct_strategy_origin import read_verified_self_origin
            if read_verified_self_origin(db, account, reservation_id, strategy, fact) is True:
                return (reservation_id, "self", None, None)
        return (None, None, None, None)
    command = GatewayDelegatedCommand.from_mapping(json.loads(row[10]))
    payload = json.loads(row[4])
    if (row[5] != account or row[6] != strategy or row[7] != row[1] or row[8] != reservation_id
            or row[9] != row[2] or command.account_scope != account or command.strategy_scope != strategy
            or command.request_key != row[1] or command.actor_principal != row[2]
            or command.payload_digest != row[3] or command.instrument != fact.instrument
            or command.canonical_json != row[10] or command.digest != row[11]
            or _json(payload) != row[4] or gateway_payload_digest(payload) != row[3]
            or payload.get("idempotency_key") != command.request_key
            or payload.get("symbol") != command.instrument.native_symbol
            or (payload.get("exchange_id") is not None and payload["exchange_id"] != command.instrument.venue)):
        _fail()
    return (reservation_id, command.origin, command.parent_ref, command.child_id)


def _snapshot(db, account, fact_digest):
    row = db.execute("SELECT fact_json,disposition,reason,reservation_id,event_sequence,applied FROM direct_execution_facts WHERE account=? AND fact_digest=?", (account, fact_digest)).fetchone()
    if row is None:
        _fail()
    fact = _fact(row[0])
    if fact.account_scope != account or fact.fact_digest() != fact_digest or row[1] not in {"ATTRIBUTED", "UNATTRIBUTED", "CONFLICT"}:
        _fail()
    _text(row[2])
    disposition, strategy, execution_sequence, receipt_digest, receipt_json = row[1], None, None, None, None
    labels = (None, None, None, None)
    if disposition == "ATTRIBUTED":
        if row[3] is None:
            _fail()
        if row[4] is None:
            if row[2] != "TRADE_DUPLICATE" or row[5] != 0:
                _fail()
            command = db.execute("SELECT strategy FROM direct_journal_commands WHERE account=? AND reservation_id=?", (account, row[3])).fetchone()
            if command is None:
                _fail()
            strategy = _text(command[0])
        else:
            if type(row[4]) is not int or row[4] < 1:
                _fail()
            event = db.execute("SELECT strategy,fact_digest,fact_json FROM direct_execution_events WHERE account=? AND sequence=?", (account, row[4])).fetchone()
            if event is None or event[1] != fact_digest or event[2] != row[0]:
                _fail()
            strategy, execution_sequence = _text(event[0]), row[4]
        labels = _delegation_labels(db, account, row[3], strategy, fact)
    elif disposition == "UNATTRIBUTED":
        external = db.execute("SELECT receipt_digest,receipt_json FROM external_position_events WHERE account=? AND fact_digest=?", (account, fact_digest)).fetchone()
        if external is not None:
            from .external_position_ledger import ExternalFactEvidence
            evidence = ExternalFactEvidence.from_mapping(json.loads(external[1]))
            if (evidence.account_scope != account or evidence.fact_digest != fact_digest
                    or evidence.digest != external[0] or _json(evidence.to_mapping()) != external[1]):
                _fail()
            disposition, receipt_digest, receipt_json = "VERIFIED_EXTERNAL", external[0], external[1]
    return (row[0], disposition, row[2], strategy, execution_sequence, receipt_digest, receipt_json, *labels)


def _event_digest(sequence, account, fact_digest, snapshot, phase):
    return hashlib.sha256(_json([sequence, account, fact_digest, *snapshot, phase]).encode("ascii")).hexdigest()


def initialize_account_fact_stream(db: sqlite3.Connection, account: str, journal_id: str):
    """Create a new epoch; initial rows are current snapshots, not old history."""
    if not db.in_transaction:
        _fail("ACCOUNT_FACT_STREAM_UNAVAILABLE")
    _text(account)
    _text(journal_id)
    meta = db.execute("SELECT journal_id FROM direct_journal_meta WHERE account=?", (account,)).fetchone()
    if meta is None or meta[0] != journal_id:
        _fail()
    for ddl in _ACCOUNT_FACT_DDL.values():
        db.execute(ddl)
    epoch = hashlib.sha256(_json(["account-facts-v1", journal_id, account]).encode("ascii")).hexdigest()
    db.execute("INSERT INTO account_fact_stream_meta VALUES (?,?,0)", (account, epoch))
    rows = db.execute("SELECT fact_digest FROM direct_execution_facts WHERE account=? ORDER BY rowid LIMIT ?", (account, _MAX_FACTS + 1)).fetchall()
    if len(rows) > _MAX_FACTS:
        _fail("ACCOUNT_FACT_CAPACITY_EXCEEDED")
    for row in rows:
        append_account_fact(db, account, row[0], bootstrap=True)
    db.execute("UPDATE account_fact_stream_meta SET bootstrap_count=? WHERE account=?", (len(rows), account))
    return epoch


def append_account_fact(db: sqlite3.Connection, account: str, fact_digest: str, *, bootstrap=False):
    """Append one changed fact state before the original owner commit.

    Call after normal ingest/rematch/conflict or external attribution and before
    committing the same transaction. Repeated unchanged state is idempotent.
    """
    if not db.in_transaction or type(bootstrap) is not bool:
        _fail("ACCOUNT_FACT_STREAM_UNAVAILABLE")
    _epoch(db, account)
    snapshot = _snapshot(db, account, fact_digest)
    from .account_fact_compaction import compaction_metadata, snapshot_latest
    meta = compaction_metadata(db, account)
    previous = db.execute("SELECT fact_json,disposition,reason,strategy,execution_sequence,receipt_digest,receipt_json,reservation_id,origin,parent_ref,child_id FROM account_fact_stream_events WHERE account=? AND fact_digest=? ORDER BY sequence DESC LIMIT 1", (account, fact_digest)).fetchone()
    if previous is None and meta is not None:
        old = snapshot_latest(db, account, fact_digest)
        if old is not None:
            previous = _event_snapshot(old)
    if previous is not None and tuple(previous) == snapshot:
        return False
    if bootstrap and previous is not None:
        _fail()
    latest = (db.execute("SELECT COALESCE(MAX(sequence),0) FROM account_fact_stream_events").fetchone()[0]
              if meta is None else meta.high_sequence)
    retained = db.execute("SELECT count(*) FROM account_fact_stream_events").fetchone()[0]
    if type(latest) is not int or latest >= 2**63 - 2 or retained >= _MAX_FACTS:
        _fail("ACCOUNT_FACT_CAPACITY_EXCEEDED")
    sequence = latest + 1
    phase = "BOOTSTRAP" if bootstrap else "LIVE"
    digest = _event_digest(sequence, account, fact_digest, snapshot, phase)
    db.execute("INSERT INTO account_fact_stream_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (sequence, account, fact_digest, *snapshot, phase, digest))
    if meta is not None:
        updated = db.execute("UPDATE account_fact_compaction_meta SET high_sequence=? WHERE account=? AND high_sequence=?",
                             (sequence, account, latest))
        if updated.rowcount != 1:
            _fail()
    return True


def _event(row):
    fact = _fact(row[3])
    snapshot = tuple(row[3:14])
    if row[15] != _event_digest(row[0], row[1], row[2], snapshot, row[14]):
        _fail()
    return AccountFactEvent(row[0], row[1], row[2], fact, row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11], row[12], row[13], row[14], row[15])


def _event_snapshot(item):
    return (_json(item.fact.to_mapping()), item.disposition, item.reason, item.strategy_scope,
            item.execution_sequence, item.external_receipt_digest, item.external_receipt_json,
            item.reservation_id, item.origin, item.parent_ref, item.child_id)


def verify_account_fact_stream(db: sqlite3.Connection, account: str, journal_id: str):
    """Check every immutable event, current-state coverage and cursor bounds."""
    try:
        epoch, bootstrap_count = _epoch(db, account)
        expected_epoch = hashlib.sha256(_json(["account-facts-v1", journal_id, account]).encode("ascii")).hexdigest()
        if (db.execute("SELECT count(*) FROM account_fact_stream_meta").fetchone()[0] != 1
                or epoch != expected_epoch or type(bootstrap_count) is not int or not 0 <= bootstrap_count <= _MAX_FACTS):
            _fail()
        from .account_fact_compaction import compaction_metadata, iter_snapshot, verify_account_fact_compaction
        meta = compaction_metadata(db, account)
        if meta is not None:
            verify_account_fact_compaction(db, account, journal_id)
        floor = 0 if meta is None else meta.retained_floor
        high = None if meta is None else meta.high_sequence
        rows = db.execute("SELECT * FROM account_fact_stream_events ORDER BY sequence LIMIT ?", (_MAX_FACTS + 1,)).fetchall()
        if len(rows) > _MAX_FACTS or (meta is None and bootstrap_count > len(rows)) or (meta is not None and bootstrap_count > high):
            _fail()
        latest = {}
        bootstrap_facts = set()
        snapshot_items = [] if meta is None else list(iter_snapshot(db, account))
        items = [(item, _event_snapshot(item), True) for item in snapshot_items]
        items.extend((_event(row), tuple(row[3:14]), False) for row in rows)
        expected_sequence = floor
        for item, snapshot, from_compaction in items:
            if not from_compaction:
                expected_sequence += 1
            if ((not from_compaction and item.sequence != expected_sequence)
                    or (from_compaction and not 0 < item.sequence <= floor)
                    or item.account_scope != account or item.fact.account_scope != account
                    or item.fact.fact_digest() != item.fact_digest
                    or item.phase != ("BOOTSTRAP" if item.sequence <= bootstrap_count else "LIVE")
                    or item.disposition not in {"ATTRIBUTED", "UNATTRIBUTED", "CONFLICT", "VERIFIED_EXTERNAL"}):
                _fail()
            _text(item.reason)
            if item.phase == "BOOTSTRAP":
                if item.fact_digest in bootstrap_facts:
                    _fail()
                bootstrap_facts.add(item.fact_digest)
            elif latest.get(item.fact_digest) == snapshot:
                _fail()
            if item.disposition == "ATTRIBUTED":
                if item.execution_sequence is None:
                    fact_row = db.execute("SELECT reason,reservation_id,applied FROM direct_execution_facts WHERE account=? AND fact_digest=?", (account, item.fact_digest)).fetchone()
                    command = None if fact_row is None else db.execute("SELECT strategy FROM direct_journal_commands WHERE account=? AND reservation_id=?", (account, fact_row[1])).fetchone()
                    if item.reason != "TRADE_DUPLICATE" or fact_row is None or fact_row[2] != 0 or command is None or command[0] != item.strategy_scope:
                        _fail()
                else:
                    event = db.execute("SELECT strategy,fact_digest,fact_json FROM direct_execution_events WHERE account=? AND sequence=?", (account, item.execution_sequence)).fetchone()
                    if event is None or tuple(event) != (item.strategy_scope, item.fact_digest, snapshot[0]):
                        _fail()
                if item.external_receipt_digest is not None or item.external_receipt_json is not None:
                    _fail()
                if item.reservation_id is not None:
                    if _delegation_labels(db, account, item.reservation_id, item.strategy_scope, item.fact) != (item.reservation_id, item.origin, item.parent_ref, item.child_id):
                        _fail()
                elif any(value is not None for value in (item.origin, item.parent_ref, item.child_id)):
                    _fail()
            elif item.disposition == "VERIFIED_EXTERNAL":
                ext = db.execute("SELECT receipt_digest,receipt_json FROM external_position_events WHERE account=? AND fact_digest=?", (account, item.fact_digest)).fetchone()
                if ext is None or tuple(ext) != (item.external_receipt_digest, item.external_receipt_json) or item.strategy_scope is not None or item.execution_sequence is not None:
                    _fail()
            elif (item.strategy_scope is not None or item.execution_sequence is not None
                  or item.external_receipt_digest is not None or item.external_receipt_json is not None):
                _fail()
            if item.disposition != "ATTRIBUTED" and any(value is not None for value in (item.reservation_id, item.origin, item.parent_ref, item.child_id)):
                _fail()
            latest[item.fact_digest] = snapshot
        if meta is not None and expected_sequence != high:
            _fail()
        facts = db.execute("SELECT fact_digest FROM direct_execution_facts WHERE account=? LIMIT ?", (account, _MAX_FACTS + 1)).fetchall()
        if len(facts) > _MAX_FACTS or set(latest) != {row[0] for row in facts}:
            _fail()
        for fact in facts:
            if latest[fact[0]] != _snapshot(db, account, fact[0]):
                _fail()
        consumers = db.execute("SELECT account,principal,consumer,offered_sequence,acknowledged_sequence FROM account_fact_stream_consumers LIMIT ?", (_MAX_CONSUMERS + 1,)).fetchall()
        if len(consumers) > _MAX_CONSUMERS:
            _fail()
        for row in consumers:
            if row[0] != account:
                _fail()
            _text(row[1]); _text(row[2])
            if type(row[3]) is not int or type(row[4]) is not int or not 0 <= row[4] <= row[3] <= (len(rows) if high is None else high):
                _fail()
    except Exception as exc:
        raise DirectCommandJournalError("INVALID_DATABASE") from exc


def account_fact_progress(db: sqlite3.Connection, account: str, principal: str, consumer: str):
    if not db.in_transaction:
        _fail("ACCOUNT_FACT_STREAM_UNAVAILABLE")
    principal, consumer = _text(principal), _text(consumer)
    epoch, bootstrap_count = _epoch(db, account)
    row = db.execute("SELECT offered_sequence,acknowledged_sequence FROM account_fact_stream_consumers WHERE account=? AND principal=? AND consumer=?", (account, principal, consumer)).fetchone()
    return AccountFactProgress(principal, consumer, epoch, *(tuple(row) if row else (0, 0)), bootstrap_count)


def read_account_facts(db: sqlite3.Connection, account: str, principal: str, consumer: str, *,
                       after_sequence=0, expected_epoch=None, limit=256, result_fits):
    """Offer a bounded page; caller must hold an authenticated read fence."""
    _sequence(after_sequence)
    if not db.in_transaction or type(limit) is not int or not 1 <= limit <= 1024 or not callable(result_fits):
        _fail("INVALID_INPUT")
    progress = account_fact_progress(db, account, principal, consumer)
    if expected_epoch is not None and expected_epoch != progress.epoch:
        _fail("EPOCH_MISMATCH")
    from .account_fact_compaction import compaction_metadata
    meta = compaction_metadata(db, account)
    if meta is not None and (after_sequence < meta.retained_floor
                             or progress.acknowledged_sequence < meta.retained_floor):
        _fail("RECOVERY_REQUIRED")
    if after_sequence and (expected_epoch != progress.epoch or after_sequence > progress.offered_sequence):
        _fail("INVALID_SEQUENCE")
    rows = db.execute("SELECT * FROM account_fact_stream_events WHERE account=? AND sequence>? ORDER BY sequence LIMIT ?", (account, after_sequence, limit + 1)).fetchall()
    events = tuple(_event(row) for row in rows[:limit])
    count = len(events)
    while True:
        selected = events[:count]
        offered = max(progress.offered_sequence, selected[-1].sequence) if selected else progress.offered_sequence
        page = AccountFactPage(selected, progress.epoch, offered, progress.acknowledged_sequence,
                               len(rows) > count, progress.bootstrap_count)
        fits = result_fits(page)
        if type(fits) is not bool:
            _fail("INVALID_INPUT")
        if fits:
            break
        if count <= 1:
            _fail("PAGE_TOO_LARGE")
        count -= 1
    if selected and offered > progress.offered_sequence:
        row = db.execute("SELECT 1 FROM account_fact_stream_consumers WHERE account=? AND principal=? AND consumer=?", (account, progress.principal_id, progress.consumer_ref)).fetchone()
        if row is None:
            if db.execute("SELECT count(*) FROM account_fact_stream_consumers WHERE account=?", (account,)).fetchone()[0] >= _MAX_CONSUMERS:
                _fail("CONSUMER_CAPACITY_EXCEEDED")
            db.execute("INSERT INTO account_fact_stream_consumers VALUES (?,?,?,?,0)", (account, progress.principal_id, progress.consumer_ref, offered))
        else:
            db.execute("UPDATE account_fact_stream_consumers SET offered_sequence=? WHERE account=? AND principal=? AND consumer=?", (offered, account, progress.principal_id, progress.consumer_ref))
    return page


def acknowledge_account_facts(db: sqlite3.Connection, account: str, principal: str, consumer: str, *,
                              sequence, expected_epoch, result_fits=None):
    """Advance only this authenticated consumer's previously offered cursor."""
    _sequence(sequence)
    if result_fits is not None and not callable(result_fits):
        _fail("INVALID_INPUT")
    progress = account_fact_progress(db, account, principal, consumer)
    if expected_epoch != progress.epoch:
        _fail("EPOCH_MISMATCH")
    from .account_fact_compaction import compaction_metadata
    meta = compaction_metadata(db, account)
    if meta is not None and (sequence < meta.retained_floor
                             or progress.acknowledged_sequence < meta.retained_floor):
        _fail("RECOVERY_REQUIRED")
    row = db.execute("SELECT 1 FROM account_fact_stream_consumers WHERE account=? AND principal=? AND consumer=?", (account, progress.principal_id, progress.consumer_ref)).fetchone()
    if row is None or sequence > progress.offered_sequence:
        _fail("INVALID_SEQUENCE")
    ack = max(progress.acknowledged_sequence, sequence)
    updated = AccountFactProgress(progress.principal_id, progress.consumer_ref, progress.epoch,
                                  progress.offered_sequence, ack, progress.bootstrap_count)
    if result_fits is not None:
        fits = result_fits(updated)
        if type(fits) is not bool:
            _fail("INVALID_INPUT")
        if not fits:
            _fail("PAGE_TOO_LARGE")
    if ack != progress.acknowledged_sequence:
        db.execute("UPDATE account_fact_stream_consumers SET acknowledged_sequence=? WHERE account=? AND principal=? AND consumer=?", (ack, account, progress.principal_id, progress.consumer_ref))
    return updated
