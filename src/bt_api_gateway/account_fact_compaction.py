"""Account-fact retention snapshots inside the existing Gateway journal.

These helpers require the account owner's transaction and an independently
authenticated consumer fence.  They do not prove a provider snapshot or a
venue-wide event cut.  Installing this module alone does not enable compaction.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from dataclasses import dataclass

from .direct_command_journal import DirectCommandJournalError, _json, _text


ACCOUNT_FACT_COMPACTION_DDL = {
    "account_fact_compaction_meta": "CREATE TABLE account_fact_compaction_meta (account TEXT PRIMARY KEY, epoch TEXT NOT NULL, high_sequence INTEGER NOT NULL, retained_floor INTEGER NOT NULL, snapshot_id TEXT, snapshot_digest TEXT, snapshot_count INTEGER NOT NULL)",
    "account_fact_compaction_items": "CREATE TABLE account_fact_compaction_items (account TEXT NOT NULL, snapshot_id TEXT NOT NULL, ordinal INTEGER NOT NULL, fact_digest TEXT NOT NULL, event_json TEXT NOT NULL, event_digest TEXT NOT NULL, PRIMARY KEY(account, snapshot_id, ordinal), UNIQUE(account, snapshot_id, fact_digest))",
    "account_fact_snapshot_offers": "CREATE TABLE account_fact_snapshot_offers (account TEXT NOT NULL, principal TEXT NOT NULL, consumer TEXT NOT NULL, registration_id TEXT NOT NULL, service_epoch TEXT NOT NULL, run_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, offered_ordinal INTEGER NOT NULL, completed INTEGER NOT NULL, PRIMARY KEY(account, principal, consumer))",
}
_MAX_SEQUENCE = 2**63 - 1


@dataclass(frozen=True, slots=True)
class AccountFactCompactionMetadata:
    epoch: str
    high_sequence: int
    retained_floor: int
    snapshot_id: str | None
    snapshot_digest: str | None
    snapshot_count: int


@dataclass(frozen=True, slots=True)
class AccountFactSnapshotPage:
    epoch: str
    snapshot_id: str
    snapshot_digest: str
    watermark: int
    total: int
    after_ordinal: int
    events: tuple
    has_more: bool


def _fail(code="INVALID_DATABASE"):
    raise DirectCommandJournalError(code)


def _transaction(db):
    if not isinstance(db, sqlite3.Connection) or not db.in_transaction:
        _fail("ACCOUNT_FACT_STREAM_UNAVAILABLE")


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _fence(db, check, account, principal, consumer, owner):
    # This hook is supplied by trusted owner code.  A remote caller cannot
    # choose it; scope and the current consumer lease must be checked inside it.
    from .account_fact_consumer_ownership import require_account_fact_owner

    if not callable(check):
        _fail("CONSUMER_FENCE_UNAVAILABLE")
    try:
        require_account_fact_owner(db, account, principal, consumer, owner)
        if check(account, principal, consumer, owner) is not True:
            _fail("CONSUMER_FENCE_UNAVAILABLE")
    except DirectCommandJournalError:
        raise
    except Exception:
        _fail("CONSUMER_FENCE_UNAVAILABLE")


def initialize_account_fact_compaction(db, account, journal_id):
    """Migrate an existing stream without deleting or renumbering history."""
    from .account_observation_journal import _epoch, verify_account_fact_stream

    _transaction(db)
    _text(account)
    _text(journal_id)
    verify_account_fact_stream(db, account, journal_id)
    epoch, _ = _epoch(db, account)
    high = db.execute("SELECT COALESCE(MAX(sequence),0) FROM account_fact_stream_events WHERE account=?", (account,)).fetchone()[0]
    for ddl in ACCOUNT_FACT_COMPACTION_DDL.values():
        db.execute(ddl)
    db.execute("INSERT INTO account_fact_compaction_meta VALUES (?,?,?,0,NULL,NULL,0)", (account, epoch, high))


def compaction_metadata(db, account):
    """Return v18 metadata; None means the stream has not been upgraded."""
    _transaction(db)
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='account_fact_compaction_meta'").fetchone() is None:
        return None
    rows = db.execute("SELECT account,epoch,high_sequence,retained_floor,snapshot_id,snapshot_digest,snapshot_count FROM account_fact_compaction_meta").fetchall()
    if len(rows) != 1 or rows[0][0] != account:
        _fail()
    _, epoch, high, floor, sid, digest, count = rows[0]
    if (not _digest(epoch) or type(high) is not int or type(floor) is not int
            or not 0 <= floor <= high < _MAX_SEQUENCE or type(count) is not int or not 0 <= count <= 1_000_000
            or ((sid is None or digest is None) and (sid is not None or digest is not None or floor != 0 or count != 0))
            or (sid is not None and (not _digest(sid) or not _digest(digest)))):
        _fail()
    return AccountFactCompactionMetadata(epoch, high, floor, sid, digest, count)


def _snapshot_hash(account, journal_id, epoch, watermark):
    digest = hashlib.sha256()
    digest.update((_json(["account-facts-snapshot-v1", account, journal_id, epoch, watermark]) + "\n").encode("ascii"))
    return digest


def _snapshot_id(account, journal_id, epoch, watermark, count, digest):
    return hashlib.sha256(_json(["account-facts-snapshot-id-v1", account, journal_id, epoch, watermark, count, digest]).encode("ascii")).hexdigest()


def _parse_event(raw, digest, account, floor):
    from .account_observation_journal import _event

    try:
        row = json.loads(raw)
        if type(row) is not list or len(row) != 16 or _json(row) != raw or row[15] != digest:
            _fail()
        event = _event(row)
        if event.account_scope != account or not 0 < event.sequence <= floor or event.fact.fact_digest() != event.fact_digest:
            _fail()
        return event
    except (ValueError, TypeError, KeyError) as exc:
        raise DirectCommandJournalError("INVALID_DATABASE") from exc


def verify_account_fact_compaction(db, account, journal_id):
    """Verify retained snapshot bytes and its binding to this exact journal."""
    from .account_observation_journal import _epoch

    _transaction(db)
    meta = compaction_metadata(db, account)
    if meta is None:
        _fail("ACCOUNT_FACT_STREAM_UNAVAILABLE")
    epoch, _ = _epoch(db, account)
    row = db.execute("SELECT journal_id FROM direct_journal_meta WHERE account=?", (account,)).fetchone()
    if epoch != meta.epoch or row is None or row[0] != journal_id:
        _fail()
    rows = db.execute("SELECT account,snapshot_id,ordinal,fact_digest,event_json,event_digest FROM account_fact_compaction_items ORDER BY ordinal")
    digest = _snapshot_hash(account, journal_id, epoch, meta.retained_floor)
    count, last_fact = 0, None
    for row in rows:
        count += 1
        if row[0] != account or row[1] != meta.snapshot_id or row[2] != count or not _digest(row[3]):
            _fail()
        event = _parse_event(row[4], row[5], account, meta.retained_floor)
        if event.fact_digest != row[3] or (last_fact is not None and row[3] <= last_fact):
            _fail()
        last_fact = row[3]
        digest.update((row[4] + "\n").encode("ascii"))
    if count != meta.snapshot_count:
        _fail()
    if meta.snapshot_id is not None:
        actual = digest.hexdigest()
        if actual != meta.snapshot_digest or meta.snapshot_id != _snapshot_id(account, journal_id, epoch, meta.retained_floor, count, actual):
            _fail()
    elif count:
        _fail()
    from .account_fact_consumer_ownership import AccountFactConsumerOwner
    offers = db.execute("SELECT account,principal,consumer,registration_id,service_epoch,run_id,snapshot_id,offered_ordinal,completed FROM account_fact_snapshot_offers LIMIT 8193").fetchall()
    if len(offers) > 8192:
        _fail()
    for row in offers:
        if (row[0] != account or not row[1] or not row[2] or row[6] != meta.snapshot_id
                or type(row[7]) is not int or not 0 <= row[7] <= count or type(row[8]) is not int or row[8] not in (0, 1)
                or (row[8] == 1 and row[7] != count)):
            _fail()
        _text(row[1]); _text(row[2])
        AccountFactConsumerOwner(row[3], row[4], row[5])
    return meta


def iter_snapshot(db, account):
    """Iterate the frozen events only after checking their complete digest."""
    meta = compaction_metadata(db, account)
    if meta is None or meta.snapshot_id is None:
        return iter(())
    journal = db.execute("SELECT journal_id FROM direct_journal_meta WHERE account=?", (account,)).fetchone()
    if journal is None:
        _fail()
    verify_account_fact_compaction(db, account, journal[0])
    return (_parse_event(row[0], row[1], account, meta.retained_floor) for row in db.execute(
        "SELECT event_json,event_digest FROM account_fact_compaction_items WHERE account=? AND snapshot_id=? ORDER BY ordinal",
        (account, meta.snapshot_id)))


def snapshot_latest(db, account, fact_digest):
    meta = compaction_metadata(db, account)
    if meta is None or meta.snapshot_id is None:
        return None
    row = db.execute("SELECT event_json,event_digest FROM account_fact_compaction_items WHERE account=? AND snapshot_id=? AND fact_digest=?", (account, meta.snapshot_id, fact_digest)).fetchone()
    return None if row is None else _parse_event(row[0], row[1], account, meta.retained_floor)


def compact_account_facts(db, account, journal_id):
    """Freeze current local facts and remove only covered observation events.

    The caller holds the single account-owner fence and commits the transaction.
    Commands, native facts, attribution and consumer ACKs are never deleted.
    """
    from .account_observation_journal import _event, _snapshot

    _transaction(db)
    meta = verify_account_fact_compaction(db, account, journal_id)
    if meta.high_sequence == meta.retained_floor:
        return meta
    name = "af_compact_" + secrets.token_hex(12)
    db.execute(f"CREATE TEMP TABLE {name} (fact_digest TEXT PRIMARY KEY, sequence INTEGER NOT NULL, event_json TEXT NOT NULL, event_digest TEXT NOT NULL)")
    try:
        if meta.snapshot_id is not None:
            for fact_digest, raw, digest in db.execute("SELECT fact_digest,event_json,event_digest FROM account_fact_compaction_items WHERE account=? AND snapshot_id=? ORDER BY ordinal", (account, meta.snapshot_id)):
                event = _parse_event(raw, digest, account, meta.retained_floor)
                db.execute(f"INSERT INTO {name} VALUES (?,?,?,?)", (fact_digest, event.sequence, raw, digest))
        expected = meta.retained_floor
        for row in db.execute("SELECT * FROM account_fact_stream_events WHERE account=? ORDER BY sequence", (account,)):
            event = _event(row)
            expected += 1
            if event.sequence != expected or event.account_scope != account or event.fact.fact_digest() != event.fact_digest:
                _fail()
            db.execute(f"INSERT INTO {name} VALUES (?,?,?,?) ON CONFLICT(fact_digest) DO UPDATE SET sequence=excluded.sequence,event_json=excluded.event_json,event_digest=excluded.event_digest", (event.fact_digest, event.sequence, _json(list(row)), event.event_digest))
        if expected != meta.high_sequence:
            _fail()
        # The current canonical fact set is required to match exactly.  This
        # checks local state at the watermark, not a provider-wide snapshot.
        count = 0
        digest = _snapshot_hash(account, journal_id, meta.epoch, meta.high_sequence)
        for fact_digest, raw, event_digest in db.execute(f"SELECT fact_digest,event_json,event_digest FROM {name} ORDER BY fact_digest"):
            event = _parse_event(raw, event_digest, account, meta.high_sequence)
            if tuple(json.loads(raw)[3:14]) != _snapshot(db, account, fact_digest):
                _fail("ACCOUNT_FACT_SNAPSHOT_INCOMPLETE")
            count += 1
            digest.update((raw + "\n").encode("ascii"))
        canonical_count = db.execute("SELECT count(*) FROM direct_execution_facts WHERE account=?", (account,)).fetchone()[0]
        if count != canonical_count:
            _fail("ACCOUNT_FACT_SNAPSHOT_INCOMPLETE")
        digest = digest.hexdigest()
        sid = _snapshot_id(account, journal_id, meta.epoch, meta.high_sequence, count, digest)
        # Atomically replace the previously frozen snapshot.  Interrupted or
        # failed callers roll back both snapshot replacement and event deletion.
        db.execute("DELETE FROM account_fact_snapshot_offers WHERE account=?", (account,))
        db.execute("DELETE FROM account_fact_compaction_items WHERE account=?", (account,))
        ordinal = 0
        for fact_digest, raw, event_digest in db.execute(f"SELECT fact_digest,event_json,event_digest FROM {name} ORDER BY fact_digest"):
            ordinal += 1
            db.execute("INSERT INTO account_fact_compaction_items VALUES (?,?,?,?,?,?)", (account, sid, ordinal, fact_digest, raw, event_digest))
        db.execute("UPDATE account_fact_compaction_meta SET retained_floor=?,snapshot_id=?,snapshot_digest=?,snapshot_count=? WHERE account=?", (meta.high_sequence, sid, digest, count, account))
        db.execute("DELETE FROM account_fact_stream_events WHERE account=? AND sequence<=?", (account, meta.high_sequence))
        return verify_account_fact_compaction(db, account, journal_id)
    finally:
        db.execute(f"DROP TABLE IF EXISTS {name}")


def read_account_fact_snapshot(db, account, principal, consumer, *, owner, snapshot_id, after_ordinal=0, limit=256, result_fits, verify_consumer):
    """Offer an ordered bounded page to a currently fenced consumer."""
    from .account_fact_consumer_ownership import claim_account_fact_reader

    _transaction(db)
    principal, consumer = _text(principal), _text(consumer)
    if not _digest(snapshot_id) or type(after_ordinal) is not int or after_ordinal < 0 or type(limit) is not int or not 1 <= limit <= 1024 or not callable(result_fits):
        _fail("INVALID_INPUT")
    # A read-after below the retention floor may have rolled back its claim.
    # Claim from the durable ACK in this same transaction, under the current
    # Registry admission, before offering the first snapshot page.
    try:
        if not callable(verify_consumer) or verify_consumer(account, principal, consumer, owner) is not True:
            _fail("CONSUMER_FENCE_UNAVAILABLE")
    except DirectCommandJournalError:
        raise
    except Exception:
        _fail("CONSUMER_FENCE_UNAVAILABLE")
    current = db.execute("SELECT acknowledged_sequence FROM account_fact_stream_consumers WHERE account=? AND principal=? AND consumer=?", (account, principal, consumer)).fetchone()
    claim_account_fact_reader(db, account, principal, consumer, owner, after_sequence=0 if current is None else current[0])
    _fence(db, verify_consumer, account, principal, consumer, owner)
    meta = compaction_metadata(db, account)
    if meta is None or meta.snapshot_id is None:
        _fail("ACCOUNT_FACT_STREAM_UNAVAILABLE")
    if snapshot_id != meta.snapshot_id:
        _fail("SNAPSHOT_REPLACED")
    journal = db.execute("SELECT journal_id FROM direct_journal_meta WHERE account=?", (account,)).fetchone()
    if journal is None:
        _fail()
    verify_account_fact_compaction(db, account, journal[0])
    offer = db.execute("SELECT snapshot_id,offered_ordinal,completed,registration_id,service_epoch,run_id FROM account_fact_snapshot_offers WHERE account=? AND principal=? AND consumer=?", (account, principal, consumer)).fetchone()
    if offer is not None and tuple(offer[3:]) != (owner.registration_id, owner.service_epoch, owner.run_id):
        # A successor may not acknowledge a snapshot merely offered to the old
        # registration; it must receive every page under its own admission.
        offer = None
    if (offer is None and after_ordinal != 0) or (offer is not None and (offer[0] != snapshot_id or after_ordinal > offer[1])):
        _fail("INVALID_SEQUENCE")
    rows = db.execute("SELECT ordinal,event_json,event_digest FROM account_fact_compaction_items WHERE account=? AND snapshot_id=? AND ordinal>? ORDER BY ordinal LIMIT ?", (account, snapshot_id, after_ordinal, limit + 1)).fetchall()
    events = tuple(_parse_event(row[1], row[2], account, meta.retained_floor) for row in rows[:limit])
    count = len(events)
    while True:
        selected = events[:count]
        page = AccountFactSnapshotPage(meta.epoch, snapshot_id, meta.snapshot_digest, meta.retained_floor, meta.snapshot_count, after_ordinal, selected, after_ordinal + count < meta.snapshot_count)
        fits = result_fits(page)
        if type(fits) is not bool:
            _fail("INVALID_INPUT")
        if fits:
            break
        if count <= 1:
            _fail("PAGE_TOO_LARGE")
        count -= 1
    offered = max(offer[1] if offer else 0, after_ordinal + count)
    completed = int(offered == meta.snapshot_count)
    db.execute("INSERT INTO account_fact_snapshot_offers VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(account,principal,consumer) DO UPDATE SET registration_id=excluded.registration_id,service_epoch=excluded.service_epoch,run_id=excluded.run_id,snapshot_id=excluded.snapshot_id,offered_ordinal=excluded.offered_ordinal,completed=excluded.completed", (account, principal, consumer, owner.registration_id, owner.service_epoch, owner.run_id, snapshot_id, offered, completed))
    _fence(db, verify_consumer, account, principal, consumer, owner)
    return page


def confirm_account_fact_snapshot(db, account, principal, consumer, *, owner, snapshot_id, snapshot_digest, verify_consumer):
    """Record a consumer's explicit assertion that it durably installed a full snapshot."""
    _transaction(db)
    principal, consumer = _text(principal), _text(consumer)
    _fence(db, verify_consumer, account, principal, consumer, owner)
    meta = compaction_metadata(db, account)
    if meta is None or meta.snapshot_id is None:
        _fail("ACCOUNT_FACT_STREAM_UNAVAILABLE")
    if snapshot_id != meta.snapshot_id or snapshot_digest != meta.snapshot_digest:
        _fail("SNAPSHOT_REPLACED")
    journal = db.execute("SELECT journal_id FROM direct_journal_meta WHERE account=?", (account,)).fetchone()
    if journal is None:
        _fail()
    verify_account_fact_compaction(db, account, journal[0])
    offer = db.execute("SELECT snapshot_id,offered_ordinal,completed,registration_id,service_epoch,run_id FROM account_fact_snapshot_offers WHERE account=? AND principal=? AND consumer=?", (account, principal, consumer)).fetchone()
    if offer is None or tuple(offer) != (snapshot_id, meta.snapshot_count, 1, owner.registration_id, owner.service_epoch, owner.run_id):
        _fail("SNAPSHOT_NOT_OFFERED")
    current = db.execute("SELECT offered_sequence,acknowledged_sequence FROM account_fact_stream_consumers WHERE account=? AND principal=? AND consumer=?", (account, principal, consumer)).fetchone()
    offered = max(current[0] if current else 0, meta.retained_floor)
    ack = max(current[1] if current else 0, meta.retained_floor)
    db.execute("INSERT INTO account_fact_stream_consumers VALUES (?,?,?,?,?) ON CONFLICT(account,principal,consumer) DO UPDATE SET offered_sequence=excluded.offered_sequence,acknowledged_sequence=excluded.acknowledged_sequence", (account, principal, consumer, offered, ack))
    _fence(db, verify_consumer, account, principal, consumer, owner)
    return meta
