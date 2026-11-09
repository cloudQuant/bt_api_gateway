"""Independent, durable SERVICE actor cursor over its own delegated events.

Only the account owner uses this module, under the authenticated Registry
admission fence. Event data remains in the original execution journal. The
global event sequence is sparse per actor; no account/strategy cursor is read
or advanced. This version assumes execution events are never compacted.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from bt_api_base.gateway_delegation_protocol import GatewayDelegatedCommand
from .direct_command_journal import DirectCommandJournalError, _json, _text

_ACTOR_STREAM_DDL = {
    "direct_actor_stream_consumers": "CREATE TABLE direct_actor_stream_consumers (account TEXT NOT NULL, principal TEXT NOT NULL, consumer TEXT NOT NULL, strategy TEXT NOT NULL, actor_ref TEXT NOT NULL, run_id TEXT NOT NULL, grant_revision TEXT NOT NULL, offered_sequence INTEGER NOT NULL, acknowledged_sequence INTEGER NOT NULL, PRIMARY KEY(account,principal,consumer,strategy))",
}
_MAX_CONSUMERS = 8192


@dataclass(frozen=True, slots=True)
class ActorEvent:
    event: object
    command: GatewayDelegatedCommand


@dataclass(frozen=True, slots=True)
class ActorProgress:
    epoch: str
    offered_sequence: int
    acknowledged_sequence: int


@dataclass(frozen=True, slots=True)
class ActorPage:
    events: tuple[ActorEvent, ...]
    progress: ActorProgress
    has_more: bool


def _epoch(journal_id, account, principal, consumer, strategy):
    return hashlib.sha256(_json(["delegate-actor-stream-v1", journal_id, account,
                                 principal, consumer, strategy]).encode("ascii")).hexdigest()


def _sequence(value):
    if type(value) is not int or not 0 <= value < 2**63:
        raise DirectCommandJournalError("INVALID_SEQUENCE")
    return value


def _matches(db, account, principal, strategy, actor_ref, run_id, sequence):
    """The cursor must identify an event of this actor, strategy and run."""
    if not sequence:
        return True
    return db.execute(
        "SELECT 1 FROM direct_execution_events e "
        "JOIN direct_execution_facts f ON f.account=e.account AND f.fact_digest=e.fact_digest "
        "JOIN direct_delegated_commands d ON d.account=f.account AND d.reservation_id=f.reservation_id "
        "WHERE e.account=? AND e.strategy=? AND e.sequence=? AND d.strategy=e.strategy "
        "AND d.actor_principal=? AND json_extract(d.envelope_json,'$.actor_ref')=? "
        "AND json_extract(d.envelope_json,'$.run_id')=?",
        (account, strategy, sequence, principal, actor_ref, run_id),
    ).fetchone() is not None


def verify_actor_stream(db, account, journal_id, max_records):
    """Validate the cursor table on reopen; missing anchor means a stream gap."""
    try:
        _text(account), _text(journal_id)
        rows = db.execute("SELECT * FROM direct_actor_stream_consumers LIMIT ?",
                          (min(max_records, _MAX_CONSUMERS) + 1,)).fetchall()
        if len(rows) > min(max_records, _MAX_CONSUMERS):
            raise ValueError
        for row in rows:
            if row["account"] != account:
                raise ValueError
            principal, consumer, strategy, actor_ref, run_id, revision = (
                _text(row[k]) for k in ("principal", "consumer", "strategy", "actor_ref", "run_id", "grant_revision"))
            offered, ack = _sequence(row["offered_sequence"]), _sequence(row["acknowledged_sequence"])
            if ack > offered or any(not _matches(db, account, principal, strategy, actor_ref, run_id, seq)
                                    for seq in (offered, ack)):
                raise ValueError
    except Exception:
        raise DirectCommandJournalError("INVALID_DATABASE") from None


class GatewayDelegateActorStream:
    """Actor-scoped projection over the authoritative execution event table."""

    def __init__(self, ledger, journal):
        from .direct_execution_journal import GatewayDirectExecutionLedger
        if type(ledger) is not GatewayDirectExecutionLedger or not ledger.is_bound_to(journal):
            raise ValueError("INVALID_ACTOR_STREAM")
        self.ledger, self.journal = ledger, journal

    def _identity(self, principal, consumer, strategy, actor_ref, run_id, revision):
        values = tuple(map(_text, (principal, consumer, strategy, actor_ref, run_id, revision)))
        if self.journal._schema_version < 15:
            raise DirectCommandJournalError("ACTOR_STREAM_UNAVAILABLE")
        return values

    def _progress(self, db, principal, consumer, strategy, actor_ref, run_id, revision):
        account = self.journal.account_scope
        row = db.execute("SELECT * FROM direct_actor_stream_consumers WHERE account=? AND principal=? "
                         "AND consumer=? AND strategy=?", (account, principal, consumer, strategy)).fetchone()
        if row is not None and (row["actor_ref"], row["run_id"], row["grant_revision"]) != (actor_ref, run_id, revision):
            raise DirectCommandJournalError("INVALID_DATABASE")
        progress = ActorProgress(_epoch(self.journal.journal_id, account, principal, consumer, strategy),
                                 row["offered_sequence"] if row else 0,
                                 row["acknowledged_sequence"] if row else 0)
        for seq in (progress.offered_sequence, progress.acknowledged_sequence):
            if not _matches(db, account, principal, strategy, actor_ref, run_id, seq):
                raise DirectCommandJournalError("ACTOR_STREAM_GAP")
        return row, progress

    def progress(self, *, principal, consumer, strategy, actor_ref, run_id, revision, admission_fence):
        self._identity(principal, consumer, strategy, actor_ref, run_id, revision)
        with self.ledger._account_observer_transaction(admission_fence) as db:
            return self._progress(db, principal, consumer, strategy, actor_ref, run_id, revision)[1]

    def read(self, *, principal, consumer, strategy, actor_ref, run_id, revision, admission_fence,
             after_sequence, expected_epoch, limit, authorize_command, result_fits):
        self._identity(principal, consumer, strategy, actor_ref, run_id, revision)
        _sequence(after_sequence)
        if type(limit) is not int or not 1 <= limit <= 256 or not callable(result_fits) or not callable(authorize_command):
            raise DirectCommandJournalError("INVALID_INPUT")
        account = self.journal.account_scope
        with self.ledger._account_observer_transaction(admission_fence) as db:
            row, progress = self._progress(db, principal, consumer, strategy, actor_ref, run_id, revision)
            if expected_epoch is not None and expected_epoch != progress.epoch:
                raise DirectCommandJournalError("EPOCH_MISMATCH")
            if after_sequence and (row is None or expected_epoch is None or after_sequence > progress.offered_sequence
                    or not _matches(db, account, principal, strategy, actor_ref, run_id, after_sequence)):
                raise DirectCommandJournalError("INVALID_SEQUENCE")
            rows = db.execute(
                "SELECT e.sequence,d.envelope_json,d.envelope_digest,d.reservation_id FROM direct_execution_events e "
                "JOIN direct_execution_facts f ON f.account=e.account AND f.fact_digest=e.fact_digest "
                "JOIN direct_delegated_commands d ON d.account=f.account AND d.reservation_id=f.reservation_id "
                "WHERE e.account=? AND e.strategy=? AND e.sequence>? AND d.strategy=e.strategy "
                "AND d.actor_principal=? AND json_extract(d.envelope_json,'$.actor_ref')=? "
                "AND json_extract(d.envelope_json,'$.run_id')=? ORDER BY e.sequence LIMIT ?",
                (account, strategy, after_sequence, principal, actor_ref, run_id, limit + 1)).fetchall()
            events = []
            for candidate in rows[:limit]:
                command = GatewayDelegatedCommand.from_mapping(json.loads(candidate["envelope_json"]))
                if (command.canonical_json != candidate["envelope_json"] or command.digest != candidate["envelope_digest"]
                        or command.actor_principal != principal or command.actor_ref != actor_ref
                        or command.account_scope != account or command.strategy_scope != strategy
                        or command.run_id != run_id or authorize_command(command) is not True):
                    raise DirectCommandJournalError("ACTOR_STREAM_UNAVAILABLE")
                event_row = self.ledger._event_rows(db, strategy, candidate["sequence"] - 1, 1)
                if len(event_row) != 1 or event_row[0]["sequence"] != candidate["sequence"]:
                    raise DirectCommandJournalError("ACTOR_STREAM_GAP")
                event = self.ledger._event_from_row(db, event_row[0])
                if (event.reservation_id != candidate["reservation_id"] or event.request_key != command.request_key
                        or event.command_digest != command.payload_digest or event.command_principal != principal):
                    raise DirectCommandJournalError("INVALID_DATABASE")
                events.append(ActorEvent(event, command))
            count = len(events)
            while True:
                selected = tuple(events[:count])
                offered = max(progress.offered_sequence, selected[-1].event.sequence) if selected else progress.offered_sequence
                page = ActorPage(selected, ActorProgress(progress.epoch, offered, progress.acknowledged_sequence), len(rows) > count)
                fits = result_fits(page)
                if type(fits) is not bool:
                    raise DirectCommandJournalError("INVALID_INPUT")
                if fits:
                    break
                if count <= 1:
                    raise DirectCommandJournalError("PAGE_TOO_LARGE")
                count -= 1
            if selected and offered > progress.offered_sequence:
                if row is None:
                    if db.execute("SELECT count(*) FROM direct_actor_stream_consumers WHERE account=?", (account,)).fetchone()[0] >= _MAX_CONSUMERS:
                        raise DirectCommandJournalError("CONSUMER_CAPACITY_EXCEEDED")
                    db.execute("INSERT INTO direct_actor_stream_consumers VALUES (?,?,?,?,?,?,?,?,?)",
                               (account, principal, consumer, strategy, actor_ref, run_id, revision, offered, 0))
                else:
                    db.execute("UPDATE direct_actor_stream_consumers SET offered_sequence=? WHERE account=? AND principal=? AND consumer=? AND strategy=?",
                               (offered, account, principal, consumer, strategy))
                self.journal._bump(db)
            # Recheck the installed grant/source policy after projection and
            # response sizing, before the original owner transaction commits.
            if any(authorize_command(item.command) is not True for item in selected):
                raise DirectCommandJournalError("ACTOR_STREAM_UNAVAILABLE")
            return page

    def acknowledge(self, *, principal, consumer, strategy, actor_ref, run_id, revision, admission_fence,
                    sequence, expected_epoch, result_fits):
        self._identity(principal, consumer, strategy, actor_ref, run_id, revision)
        _sequence(sequence)
        if not callable(result_fits):
            raise DirectCommandJournalError("INVALID_INPUT")
        account = self.journal.account_scope
        with self.ledger._account_observer_transaction(admission_fence) as db:
            row, progress = self._progress(db, principal, consumer, strategy, actor_ref, run_id, revision)
            if expected_epoch != progress.epoch:
                raise DirectCommandJournalError("EPOCH_MISMATCH")
            if row is None or sequence > progress.offered_sequence or not _matches(db, account, principal, strategy, actor_ref, run_id, sequence):
                raise DirectCommandJournalError("INVALID_SEQUENCE")
            ack = max(progress.acknowledged_sequence, sequence)
            result = ActorProgress(progress.epoch, progress.offered_sequence, ack)
            if result_fits(result) is not True:
                raise DirectCommandJournalError("PAGE_TOO_LARGE")
            if ack != progress.acknowledged_sequence:
                db.execute("UPDATE direct_actor_stream_consumers SET acknowledged_sequence=? WHERE account=? AND principal=? AND consumer=? AND strategy=?",
                           (ack, account, principal, consumer, strategy))
                self.journal._bump(db)
            return result
