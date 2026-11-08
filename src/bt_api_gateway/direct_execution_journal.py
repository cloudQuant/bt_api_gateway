"""Internal same-database execution facts and strategy net-delta ledger.

Inputs are trusted labels, not provider authentication. A position is only the
net delta of applied trades in this journal, never an account baseline.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal, localcontext

from bt_api_base.direct_write_protocol import DirectExecutionEventKind
from bt_api_base.gateway_execution_protocol import GatewayReturnFact
from bt_api_base.market_protocol import MarketInstrumentKey

from .direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
    _json,
    _text,
)
from .session_guard import LocalAccountSessionGuard

_EXECUTION_DDL = {
    "direct_execution_meta": "CREATE TABLE direct_execution_meta (account TEXT PRIMARY KEY, max_facts INTEGER NOT NULL, fact_count INTEGER NOT NULL)",
    "direct_execution_facts": "CREATE TABLE direct_execution_facts (account TEXT NOT NULL, fact_digest TEXT NOT NULL, fact_json TEXT NOT NULL, disposition TEXT NOT NULL, reason TEXT NOT NULL, reservation_id TEXT, event_sequence INTEGER, applied INTEGER NOT NULL, PRIMARY KEY(account, fact_digest))",
    "direct_execution_aliases": "CREATE TABLE direct_execution_aliases (account TEXT NOT NULL, strong_key TEXT NOT NULL, reservation_id TEXT NOT NULL, PRIMARY KEY(account, strong_key))",
    "direct_execution_trades": "CREATE TABLE direct_execution_trades (account TEXT NOT NULL, route TEXT NOT NULL, trade_key_json TEXT NOT NULL, content_digest TEXT NOT NULL, applied INTEGER NOT NULL, reservation_id TEXT, fact_digest TEXT NOT NULL, conflict INTEGER NOT NULL, quantity TEXT, PRIMARY KEY(account, route, trade_key_json))",
    "direct_execution_positions": "CREATE TABLE direct_execution_positions (account TEXT NOT NULL, strategy TEXT NOT NULL, instrument_json TEXT NOT NULL, net_quantity TEXT NOT NULL, PRIMARY KEY(account, strategy, instrument_json))",
    "direct_execution_totals": "CREATE TABLE direct_execution_totals (account TEXT NOT NULL, reservation_id TEXT NOT NULL, total_quantity TEXT NOT NULL, PRIMARY KEY(account, reservation_id))",
    "direct_execution_events": "CREATE TABLE direct_execution_events (sequence INTEGER PRIMARY KEY, account TEXT NOT NULL, strategy TEXT NOT NULL, fact_digest TEXT NOT NULL, fact_json TEXT NOT NULL)",
    "direct_execution_conflicts": "CREATE TABLE direct_execution_conflicts (account TEXT NOT NULL, fact_digest TEXT NOT NULL, route TEXT NOT NULL, trade_key_json TEXT NOT NULL, original_content_digest TEXT NOT NULL, conflicting_content_digest TEXT NOT NULL, PRIMARY KEY(account, fact_digest))",
    "direct_execution_trade_reservation": "CREATE INDEX direct_execution_trade_reservation ON direct_execution_trades(account, reservation_id)",
    "direct_execution_facts_pending": "CREATE INDEX direct_execution_facts_pending ON direct_execution_facts(account, disposition)",
    "direct_execution_events_strategy": "CREATE INDEX direct_execution_events_strategy ON direct_execution_events(account, strategy, sequence)",
}


_CONSUMER_DDL = "CREATE TABLE direct_execution_consumers (account TEXT NOT NULL, principal TEXT NOT NULL, consumer TEXT NOT NULL, strategy TEXT NOT NULL, offered_sequence INTEGER NOT NULL, acknowledged_sequence INTEGER NOT NULL, PRIMARY KEY(account, principal, consumer, strategy))"
_MAX_CONSUMERS = 8192


def _create_consumer_table(db: sqlite3.Connection) -> None:
    db.execute(_CONSUMER_DDL)


def _verify_consumer_integrity(db: sqlite3.Connection, account: str) -> None:
    try:
        rows = db.execute(
            "SELECT * FROM direct_execution_consumers LIMIT ?", (_MAX_CONSUMERS + 1,)
        ).fetchall()
        if len(rows) > _MAX_CONSUMERS:
            raise ValueError("consumer capacity")
        for row in rows:
            if row["account"] != account:
                raise ValueError("consumer account")
            for name in ("principal", "consumer", "strategy"):
                _text(row[name])
            offered, ack = row["offered_sequence"], row["acknowledged_sequence"]
            if type(offered) is not int or type(ack) is not int or not 0 <= ack <= offered < 2**63:
                raise ValueError("consumer sequence")
            for sequence in (offered, ack):
                if (
                    sequence
                    and db.execute(
                        "SELECT 1 FROM direct_execution_events WHERE account=? AND strategy=? AND sequence=?",
                        (account, row["strategy"], sequence),
                    ).fetchone()
                    is None
                ):
                    raise ValueError("consumer event")
    except Exception as exc:
        raise DirectCommandJournalError("INVALID_DATABASE") from exc


def _create_execution_tables(db: sqlite3.Connection, account: str, max_facts: int) -> None:
    for ddl in _EXECUTION_DDL.values():
        db.execute(ddl)
    db.execute("INSERT INTO direct_execution_meta VALUES (?, ?, 0)", (account, max_facts))


def _verify_execution_schema(db: sqlite3.Connection, account: str, max_facts: int) -> None:
    del account, max_facts
    for name, sql in _EXECUTION_DDL.items():
        row = db.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()
        if (
            row is None
            or not isinstance(row[0], str)
            or "".join(row[0].split()).lower() != "".join(sql.split()).lower()
        ):
            raise DirectCommandJournalError("INVALID_DATABASE")


@dataclass(frozen=True)
class ExecutionIngestResult:
    disposition: str
    fact_digest: str
    strategy_scope: str | None
    event_sequence: int | None
    applied: bool
    reason: str


@dataclass(frozen=True)
class ExecutionEvent:
    sequence: int
    strategy_scope: str
    fact_digest: str
    fact: GatewayReturnFact


@dataclass(frozen=True)
class ExecutionConsumerProgress:
    strategy_scope: str
    principal_id: str
    consumer_ref: str
    epoch: str
    offered_sequence: int
    acknowledged_sequence: int


@dataclass(frozen=True)
class ExecutionEventPage:
    events: tuple[ExecutionEvent, ...]
    epoch: str
    offered_sequence: int
    acknowledged_sequence: int
    has_more: bool


@dataclass(frozen=True)
class ExecutionPending:
    fact_digest: str
    reason: str
    fact: GatewayReturnFact


def _canonical_quantity(value: Decimal, *, integer_limit: int = 36) -> str:
    with localcontext() as ctx:
        ctx.prec = 160
        if not value.is_finite():
            raise ValueError("quantity range")
        raw = format(value, "f")
        if "." in raw:
            raw = raw.rstrip("0").rstrip(".")
        if raw in ("", "-0"):
            raw = "0"
        unsigned = raw.lstrip("-")
        integer, _, fractional = unsigned.partition(".")
        if len(integer) > integer_limit or len(fractional) > 18 or len(raw) > 128:
            raise ValueError("quantity range")
        return raw


def _limit(limit: int) -> int:
    if type(limit) is not int or not 1 <= limit <= 256:
        raise DirectCommandJournalError("INVALID_LIMIT")
    return limit


class GatewayDirectExecutionLedger:
    """One guard-bound same-DB ledger; reads are trusted local, not ACLs."""

    def __init__(
        self, journal: GatewayDirectCommandJournal, guard: LocalAccountSessionGuard
    ) -> None:
        if (
            type(journal) is not GatewayDirectCommandJournal
            or type(guard) is not LocalAccountSessionGuard
        ):
            raise DirectCommandJournalError("INVALID_GUARD")
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self._journal, self._guard = journal, guard
        self._pending_cursor = 0
        self._owned()
        with journal._transaction() as db:
            self._owned()
            journal._verify_v2_upgrade_integrity(db, schema_version=5)
            journal._verify_v4_identity_integrity(db)
            _verify_execution_integrity(db, journal.account_scope, journal._execution_max_facts)
            _verify_consumer_integrity(db, journal.account_scope)
            self._owned()

    def _owned(self) -> None:
        import hashlib

        if os.getpid() != self._pid or threading.current_thread() is not self._thread:
            raise DirectCommandJournalError("WRONG_OWNER")
        self._guard.assert_owned()
        if (
            self._guard.account_key_digest
            != hashlib.sha256(self._journal.account_scope.encode("utf-8")).hexdigest()
            or self._guard.acquire() != self._journal.generation
        ):
            raise DirectCommandJournalError("GUARD_BINDING_MISMATCH")

    def _check_pid(self) -> None:
        if os.getpid() != self._pid:
            raise DirectCommandJournalError("WRONG_OWNER")

    @property
    def account_scope(self) -> str:
        """Return the bound account only while the original owner holds its guard."""
        self._owned()
        return self._journal.account_scope

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        self._owned()
        with self._journal._transaction() as db:
            self._owned()
            yield db
            self._owned()

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        self._check_pid()
        with self._journal._transaction() as db:
            yield db

    def ingest(self, fact: GatewayReturnFact) -> ExecutionIngestResult:
        self._owned()
        if type(fact) is not GatewayReturnFact:
            raise DirectCommandJournalError("INVALID_FACT")
        try:
            fact = GatewayReturnFact.from_mapping(fact.to_mapping())
        except Exception as exc:
            raise DirectCommandJournalError("INVALID_FACT") from exc
        if fact.account_scope != self._journal.account_scope:
            raise DirectCommandJournalError("ACCOUNT_MISMATCH")
        digest = fact.fact_digest()
        with self._write() as db:
            row = db.execute(
                "SELECT * FROM direct_execution_facts WHERE account=? AND fact_digest=?",
                (self._journal.account_scope, digest),
            ).fetchone()
            if row is not None:
                result = self._result(db, row, applied=False)
                if fact.kind is DirectExecutionEventKind.TRADE and fact.trade_key is not None:
                    trade = db.execute(
                        "SELECT conflict FROM direct_execution_trades WHERE account=? AND route=? AND trade_key_json=?",
                        (self._journal.account_scope, fact.route, _json(list(fact.trade_key))),
                    ).fetchone()
                    if trade is not None and trade[0]:
                        return ExecutionIngestResult(
                            "CONFLICT",
                            digest,
                            result.strategy_scope,
                            result.event_sequence,
                            False,
                            "TRADE_CONFLICT_RETAINED",
                        )
                return result
            count = db.execute(
                "SELECT fact_count FROM direct_execution_meta WHERE account=?",
                (self._journal.account_scope,),
            ).fetchone()[0]
            if count >= self._journal._execution_max_facts:
                raise DirectCommandJournalError("EXECUTION_CAPACITY_EXCEEDED")
            db.execute(
                "INSERT INTO direct_execution_facts VALUES (?, ?, ?, 'UNATTRIBUTED', 'UNMATCHED', NULL, NULL, 0)",
                (self._journal.account_scope, digest, _json(fact.to_mapping())),
            )
            db.execute(
                "UPDATE direct_execution_meta SET fact_count=fact_count+1 WHERE account=?",
                (self._journal.account_scope,),
            )
            self._process(db, digest, fact)
            self._journal._bump(db)
            row = db.execute(
                "SELECT * FROM direct_execution_facts WHERE account=? AND fact_digest=?",
                (self._journal.account_scope, digest),
            ).fetchone()
            return self._result(db, row, applied=bool(row["applied"]))

    def reconcile_pending(self, *, limit: int = 256) -> tuple[ExecutionIngestResult, ...]:
        self._owned()
        _limit(limit)
        with self._write() as db:
            rows = db.execute(
                "SELECT rowid AS scan_rowid,* FROM direct_execution_facts WHERE account=? AND disposition='UNATTRIBUTED' AND rowid>? ORDER BY rowid LIMIT ?",
                (self._journal.account_scope, self._pending_cursor, limit),
            ).fetchall()
            if not rows and self._pending_cursor:
                rows = db.execute(
                    "SELECT rowid AS scan_rowid,* FROM direct_execution_facts WHERE account=? AND disposition='UNATTRIBUTED' ORDER BY rowid LIMIT ?",
                    (self._journal.account_scope, limit),
                ).fetchall()
            changed = False
            results = []
            for row in rows:
                before = (
                    row["disposition"],
                    row["reason"],
                    row["reservation_id"],
                    row["event_sequence"],
                    row["applied"],
                )
                fact = GatewayReturnFact.from_mapping(json.loads(row["fact_json"]))
                self._process(db, row["fact_digest"], fact)
                current = db.execute(
                    "SELECT * FROM direct_execution_facts WHERE account=? AND fact_digest=?",
                    (self._journal.account_scope, row["fact_digest"]),
                ).fetchone()
                after = (
                    current["disposition"],
                    current["reason"],
                    current["reservation_id"],
                    current["event_sequence"],
                    current["applied"],
                )
                modified = before != after
                changed = changed or modified
                results.append(
                    self._result(db, current, applied=modified and bool(current["applied"]))
                )
            if changed:
                self._journal._bump(db)
            next_cursor = rows[-1]["scan_rowid"] if rows else 0
        # A failed COMMIT must leave this volatile scan cursor unchanged.
        self._pending_cursor = next_cursor
        return tuple(results)

    def position(self, strategy_scope: str, instrument: MarketInstrumentKey) -> str | None:
        """Return this journal's applied-trade net delta, not an initial position baseline."""
        strategy = _text(strategy_scope)
        if type(instrument) is not MarketInstrumentKey:
            raise DirectCommandJournalError("INVALID_INPUT")
        try:
            checked = MarketInstrumentKey.from_dict(instrument.to_dict())
        except (TypeError, ValueError, KeyError) as exc:
            raise DirectCommandJournalError("INVALID_INPUT") from exc
        encoded = _json(checked.to_dict())
        with self._read() as db:
            row = db.execute(
                "SELECT net_quantity FROM direct_execution_positions WHERE account=? AND strategy=? AND instrument_json=?",
                (self._journal.account_scope, strategy, encoded),
            ).fetchone()
            return None if row is None else row[0]

    def read_events(
        self, strategy_scope: str, *, after_sequence: int = 0, limit: int = 256
    ) -> tuple[ExecutionEvent, ...]:
        strategy = _text(strategy_scope)
        if type(after_sequence) is not int or not 0 <= after_sequence < 2**63:
            raise DirectCommandJournalError("INVALID_INPUT")
        _limit(limit)
        with self._read() as db:
            rows = db.execute(
                "SELECT * FROM direct_execution_events WHERE account=? AND strategy=? AND sequence>? ORDER BY sequence LIMIT ?",
                (self._journal.account_scope, strategy, after_sequence, limit),
            ).fetchall()
            return tuple(
                ExecutionEvent(
                    row["sequence"],
                    row["strategy"],
                    row["fact_digest"],
                    GatewayReturnFact.from_mapping(json.loads(row["fact_json"])),
                )
                for row in rows
            )

    def _consumer_identity(self, strategy_scope: str, principal_id: str, consumer_ref: str):
        strategy, principal, consumer = map(_text, (strategy_scope, principal_id, consumer_ref))
        epoch = hashlib.sha256(
            _json([self._journal.journal_id, self._journal.account_scope, strategy]).encode("ascii")
        ).hexdigest()
        return strategy, principal, consumer, epoch

    @staticmethod
    def _consumer_row(db, account, strategy, principal, consumer):
        return db.execute(
            "SELECT offered_sequence,acknowledged_sequence FROM direct_execution_consumers WHERE account=? AND principal=? AND consumer=? AND strategy=?",
            (account, principal, consumer, strategy),
        ).fetchone()

    @staticmethod
    def _sequence(value):
        if type(value) is not int or not 0 <= value < 2**63:
            raise DirectCommandJournalError("INVALID_INPUT")
        return value

    @staticmethod
    def _require_event(db, account, strategy, sequence):
        if (
            sequence
            and db.execute(
                "SELECT 1 FROM direct_execution_events WHERE account=? AND strategy=? AND sequence=?",
                (account, strategy, sequence),
            ).fetchone()
            is None
        ):
            raise DirectCommandJournalError("INVALID_SEQUENCE")

    def consumer_progress(
        self, strategy_scope: str, *, principal_id: str, consumer_ref: str
    ) -> ExecutionConsumerProgress:
        """Return local cursor state; labels do not authenticate the consumer."""
        strategy, principal, consumer, epoch = self._consumer_identity(
            strategy_scope, principal_id, consumer_ref
        )
        with self._read() as db:
            row = self._consumer_row(db, self._journal.account_scope, strategy, principal, consumer)
            return ExecutionConsumerProgress(
                strategy, principal, consumer, epoch, *(tuple(row) if row else (0, 0))
            )

    def read_for_consumer(
        self,
        strategy_scope: str,
        *,
        principal_id: str,
        consumer_ref: str,
        result_fits: Callable[[ExecutionEventPage], bool],
        after_sequence: int = 0,
        expected_epoch: str | None = None,
        limit: int = 256,
    ) -> ExecutionEventPage:
        """Offer a bounded page transactionally; result_fits must be trusted and pure.

        The callback runs inside the SQLite transaction and must not perform I/O
        or reenter this journal. An empty page creates no consumer and needs no
        acknowledgment. No authorization or guard freshness is implied.
        """
        strategy, principal, consumer, epoch = self._consumer_identity(
            strategy_scope, principal_id, consumer_ref
        )
        self._sequence(after_sequence)
        _limit(limit)
        if expected_epoch is not None and expected_epoch != epoch:
            raise DirectCommandJournalError("EPOCH_MISMATCH")
        if not callable(result_fits):
            raise DirectCommandJournalError("INVALID_INPUT")
        account = self._journal.account_scope
        with self._read() as db:
            row = self._consumer_row(db, account, strategy, principal, consumer)
            offered, ack = tuple(row) if row else (0, 0)
            if after_sequence:
                if row is None or expected_epoch != epoch or after_sequence > offered:
                    raise DirectCommandJournalError("INVALID_SEQUENCE")
                self._require_event(db, account, strategy, after_sequence)
            rows = db.execute(
                "SELECT * FROM direct_execution_events WHERE account=? AND strategy=? AND sequence>? ORDER BY sequence LIMIT ?",
                (account, strategy, after_sequence, limit + 1),
            ).fetchall()
            events = tuple(
                ExecutionEvent(
                    r["sequence"],
                    r["strategy"],
                    r["fact_digest"],
                    GatewayReturnFact.from_mapping(json.loads(r["fact_json"])),
                )
                for r in rows[:limit]
            )
            count = len(events)
            while True:
                selected = events[:count]
                new_offer = max(offered, selected[-1].sequence) if selected else offered
                page = ExecutionEventPage(selected, epoch, new_offer, ack, len(rows) > count)
                fits = result_fits(page)
                if type(fits) is not bool:
                    raise DirectCommandJournalError("INVALID_INPUT")
                if fits:
                    break
                if count <= 1:
                    raise DirectCommandJournalError("PAGE_TOO_LARGE")
                count -= 1
            if selected and (row is None or new_offer > offered):
                if row is None:
                    if (
                        db.execute(
                            "SELECT count(*) FROM direct_execution_consumers WHERE account=?",
                            (account,),
                        ).fetchone()[0]
                        >= _MAX_CONSUMERS
                    ):
                        raise DirectCommandJournalError("CONSUMER_CAPACITY_EXCEEDED")
                    db.execute(
                        "INSERT INTO direct_execution_consumers VALUES (?, ?, ?, ?, ?, 0)",
                        (account, principal, consumer, strategy, new_offer),
                    )
                else:
                    db.execute(
                        "UPDATE direct_execution_consumers SET offered_sequence=? WHERE account=? AND principal=? AND consumer=? AND strategy=?",
                        (new_offer, account, principal, consumer, strategy),
                    )
            return page

    def acknowledge(
        self,
        strategy_scope: str,
        *,
        principal_id: str,
        consumer_ref: str,
        sequence: int,
        expected_epoch: str,
    ) -> ExecutionConsumerProgress:
        """Persist a monotonic local acknowledgment without granting authority."""
        strategy, principal, consumer, epoch = self._consumer_identity(
            strategy_scope, principal_id, consumer_ref
        )
        self._sequence(sequence)
        if expected_epoch != epoch:
            raise DirectCommandJournalError("EPOCH_MISMATCH")
        account = self._journal.account_scope
        with self._read() as db:
            row = self._consumer_row(db, account, strategy, principal, consumer)
            if row is None or sequence > row[0]:
                raise DirectCommandJournalError("INVALID_SEQUENCE")
            self._require_event(db, account, strategy, sequence)
            ack = max(row[1], sequence)
            if ack != row[1]:
                db.execute(
                    "UPDATE direct_execution_consumers SET acknowledged_sequence=? WHERE account=? AND principal=? AND consumer=? AND strategy=?",
                    (ack, account, principal, consumer, strategy),
                )
            return ExecutionConsumerProgress(strategy, principal, consumer, epoch, row[0], ack)

    def pending(self, *, limit: int = 256) -> tuple[ExecutionPending, ...]:
        _limit(limit)
        with self._read() as db:
            rows = db.execute(
                "SELECT * FROM direct_execution_facts WHERE account=? AND disposition='UNATTRIBUTED' ORDER BY rowid LIMIT ?",
                (self._journal.account_scope, limit),
            ).fetchall()
            return tuple(
                ExecutionPending(
                    row["fact_digest"],
                    row["reason"],
                    GatewayReturnFact.from_mapping(json.loads(row["fact_json"])),
                )
                for row in rows
            )

    def _result(
        self, db: sqlite3.Connection, row: sqlite3.Row, *, applied: bool
    ) -> ExecutionIngestResult:
        strategy = None
        if row["reservation_id"] is not None:
            command = db.execute(
                "SELECT strategy FROM direct_journal_commands WHERE account=? AND reservation_id=?",
                (self._journal.account_scope, row["reservation_id"]),
            ).fetchone()
            if command is not None:
                strategy = command[0]
        return ExecutionIngestResult(
            row["disposition"],
            row["fact_digest"],
            strategy,
            row["event_sequence"],
            applied,
            row["reason"],
        )

    def _fact_update(
        self, db, digest, disposition, reason, reservation=None, sequence=None, applied=False
    ):
        db.execute(
            "UPDATE direct_execution_facts SET disposition=?,reason=?,reservation_id=?,event_sequence=?,applied=? WHERE account=? AND fact_digest=?",
            (
                disposition,
                reason,
                reservation,
                sequence,
                int(applied),
                self._journal.account_scope,
                digest,
            ),
        )

    def _conflict_trade(self, db, fact, digest, trade_key, original, reason):
        db.execute(
            "UPDATE direct_execution_trades SET conflict=1 WHERE account=? AND route=? AND trade_key_json=?",
            (self._journal.account_scope, fact.route, trade_key),
        )
        db.execute(
            "INSERT OR IGNORE INTO direct_execution_conflicts VALUES (?, ?, ?, ?, ?, ?)",
            (
                self._journal.account_scope,
                digest,
                fact.route,
                trade_key,
                original,
                fact.trade_content_digest(),
            ),
        )
        self._fact_update(db, digest, "CONFLICT", reason)

    def _process(self, db: sqlite3.Connection, digest: str, fact: GatewayReturnFact) -> None:
        account = self._journal.account_scope
        trade_key = _json(list(fact.trade_key)) if fact.trade_key is not None else None
        trade = None
        if fact.kind is DirectExecutionEventKind.TRADE and trade_key is not None:
            trade = db.execute(
                "SELECT * FROM direct_execution_trades WHERE account=? AND route=? AND trade_key_json=?",
                (account, fact.route, trade_key),
            ).fetchone()
            if trade is None:
                db.execute(
                    "INSERT INTO direct_execution_trades VALUES (?, ?, ?, ?, 0, NULL, ?, 0, NULL)",
                    (account, fact.route, trade_key, fact.trade_content_digest(), digest),
                )
                trade = db.execute(
                    "SELECT * FROM direct_execution_trades WHERE account=? AND route=? AND trade_key_json=?",
                    (account, fact.route, trade_key),
                ).fetchone()
            elif trade["content_digest"] != fact.trade_content_digest():
                self._conflict_trade(
                    db, fact, digest, trade_key, trade["content_digest"], "TRADE_CONTENT_CONFLICT"
                )
                return
            elif trade["conflict"]:
                self._fact_update(
                    db, digest, "CONFLICT", "TRADE_CONFLICT_RETAINED", trade["reservation_id"]
                )
                return
        matches = {}
        for key in fact.identity_keys:
            row = db.execute(
                "SELECT reservation_id FROM direct_journal_strong_keys WHERE account=? AND strong_key=?",
                (account, key),
            ).fetchone()
            if row is not None:
                matches[key] = row[0]
        reservations = set(matches.values())
        if len(reservations) > 1:
            if trade is not None:
                self._conflict_trade(
                    db, fact, digest, trade_key, trade["content_digest"], "IDENTITY_CONFLICT"
                )
            else:
                self._fact_update(db, digest, "CONFLICT", "IDENTITY_CONFLICT")
            return
        if not reservations:
            if trade is not None and trade["reservation_id"] is not None and fact.binding_keys:
                self._conflict_trade(
                    db, fact, digest, trade_key, trade["content_digest"], "BINDING_CONFLICT"
                )
                return
            self._fact_update(db, digest, "UNATTRIBUTED", "UNMATCHED")
            return
        reservation = next(iter(reservations))
        command = db.execute(
            "SELECT * FROM direct_journal_commands WHERE account=? AND reservation_id=?",
            (account, reservation),
        ).fetchone()
        if command is None or command["status"] not in {
            "DISPATCHING",
            "SENT",
            "UNKNOWN",
            "NOT_SENT",
        }:
            self._fact_update(db, digest, "CONFLICT", "COMMAND_STATE_CONFLICT")
            return
        original_keys = set(json.loads(command["strong_keys_json"]))
        if any(
            key not in original_keys or matches.get(key) != reservation for key in fact.binding_keys
        ):
            if trade is not None:
                self._conflict_trade(
                    db, fact, digest, trade_key, trade["content_digest"], "BINDING_CONFLICT"
                )
            else:
                self._fact_update(db, digest, "CONFLICT", "BINDING_CONFLICT")
            return
        unbound = set(fact.identity_keys) - set(matches)
        learnable = (
            {fact.venue_key}
            if (fact.kind is DirectExecutionEventKind.ORDER and fact.venue_key is not None)
            else set()
        )
        if unbound - learnable:
            self._fact_update(db, digest, "UNATTRIBUTED", "IDENTITY_KEYS_UNBOUND")
            return
        identity = json.loads(command["native_identity_json"])
        payload = json.loads(command["payload_json"])
        if (
            identity.get("exchange_name") != fact.route
            or payload.get("symbol") != fact.instrument.native_symbol
        ):
            if trade is not None:
                self._conflict_trade(
                    db, fact, digest, trade_key, trade["content_digest"], "ROUTE_OR_SYMBOL_CONFLICT"
                )
            else:
                self._fact_update(db, digest, "CONFLICT", "ROUTE_OR_SYMBOL_CONFLICT")
            return
        if trade is not None and trade["reservation_id"] not in (None, reservation):
            self._conflict_trade(
                db, fact, digest, trade_key, trade["content_digest"], "TRADE_BINDING_CONFLICT"
            )
            return
        if fact.kind is DirectExecutionEventKind.ORDER and fact.venue_key is not None:
            venue_owner = matches.get(fact.venue_key)
            if venue_owner is None:
                if not any(
                    key in original_keys and key != fact.venue_key for key in fact.identity_keys
                ):
                    self._fact_update(db, digest, "UNATTRIBUTED", "ORIGINAL_ANCHOR_REQUIRED")
                    return
                db.execute(
                    "INSERT INTO direct_journal_strong_keys VALUES (?, ?, ?)",
                    (account, fact.venue_key, reservation),
                )
                db.execute(
                    "INSERT INTO direct_execution_aliases VALUES (?, ?, ?)",
                    (account, fact.venue_key, reservation),
                )
        reason = "NOT_SENT_CONTRADICTION" if command["status"] == "NOT_SENT" else "MATCHED"
        applied = False
        if fact.kind is DirectExecutionEventKind.TRADE:
            if (
                trade_key is None
                or fact.venue_key is None
                or fact.side is None
                or fact.trade_quantity is None
                or fact.trade_price is None
            ):
                self._fact_update(db, digest, "UNATTRIBUTED", "TRADE_INCOMPLETE")
                return
            command_side = payload.get("side")
            if command_side not in ("buy", "sell"):
                self._fact_update(db, digest, "UNATTRIBUTED", "COMMAND_SIDE_MISSING")
                return
            if payload.get("offset") is not None and fact.offset is None:
                self._fact_update(db, digest, "UNATTRIBUTED", "TRADE_OFFSET_MISSING")
                return
            if fact.side != command_side or (
                payload.get("offset") is not None and fact.offset != payload["offset"]
            ):
                self._conflict_trade(
                    db,
                    fact,
                    digest,
                    trade_key,
                    trade["content_digest"],
                    "TRADE_SIDE_OR_OFFSET_CONFLICT",
                )
                return
            if trade["applied"]:
                self._fact_update(db, digest, "ATTRIBUTED", "TRADE_DUPLICATE", reservation)
                return
            instrument = _json(fact.instrument.to_dict())
            row = db.execute(
                "SELECT net_quantity FROM direct_execution_positions WHERE account=? AND strategy=? AND instrument_json=?",
                (account, command["strategy"], instrument),
            ).fetchone()
            try:
                with localcontext() as ctx:
                    ctx.prec = 160
                    quantity = Decimal(fact.trade_quantity)
                    net = (Decimal(row[0]) if row is not None else Decimal(0)) + (
                        quantity if fact.side == "buy" else -quantity
                    )
                    net_text = _canonical_quantity(net)
                    previous = db.execute(
                        "SELECT total_quantity FROM direct_execution_totals WHERE account=? AND reservation_id=?",
                        (account, reservation),
                    ).fetchone()
                    total = (
                        Decimal(previous[0]) if previous is not None else Decimal(0)
                    ) + quantity
                    total_text = _canonical_quantity(total, integer_limit=42)
                    requested = payload.get("quantity")
                    try:
                        requested_value = Decimal(requested) if type(requested) is str else None
                        if requested_value is not None and (
                            not requested_value.is_finite() or requested_value <= 0
                        ):
                            requested_value = None
                    except Exception:
                        requested_value = None
                    if requested_value is not None and total > requested_value:
                        reason = (
                            "NOT_SENT_OVERFILL" if command["status"] == "NOT_SENT" else "OVERFILL"
                        )
            except Exception:
                self._conflict_trade(
                    db, fact, digest, trade_key, trade["content_digest"], "POSITION_RANGE_CONFLICT"
                )
                return
            db.execute(
                "INSERT INTO direct_execution_positions VALUES (?, ?, ?, ?) ON CONFLICT(account,strategy,instrument_json) DO UPDATE SET net_quantity=excluded.net_quantity",
                (account, command["strategy"], instrument, net_text),
            )
            db.execute(
                "INSERT INTO direct_execution_totals VALUES (?, ?, ?) ON CONFLICT(account,reservation_id) DO UPDATE SET total_quantity=excluded.total_quantity",
                (account, reservation, total_text),
            )
            db.execute(
                "UPDATE direct_execution_trades SET applied=1,reservation_id=?,fact_digest=?,quantity=? WHERE account=? AND route=? AND trade_key_json=?",
                (reservation, digest, fact.trade_quantity, account, fact.route, trade_key),
            )
            applied = True
        sequence = db.execute(
            "SELECT COALESCE(MAX(sequence), 0)+1 FROM direct_execution_events"
        ).fetchone()[0]
        db.execute(
            "INSERT INTO direct_execution_events VALUES (?, ?, ?, ?, ?)",
            (sequence, account, command["strategy"], digest, _json(fact.to_mapping())),
        )
        self._fact_update(db, digest, "ATTRIBUTED", reason, reservation, sequence, applied)


_VALID_REASONS = {
    "UNATTRIBUTED": {
        "UNMATCHED",
        "ORIGINAL_ANCHOR_REQUIRED",
        "TRADE_INCOMPLETE",
        "COMMAND_SIDE_MISSING",
        "TRADE_OFFSET_MISSING",
        "IDENTITY_KEYS_UNBOUND",
    },
    "ATTRIBUTED": {
        "MATCHED",
        "NOT_SENT_CONTRADICTION",
        "TRADE_DUPLICATE",
        "OVERFILL",
        "NOT_SENT_OVERFILL",
    },
    "CONFLICT": {
        "TRADE_CONTENT_CONFLICT",
        "TRADE_CONFLICT_RETAINED",
        "IDENTITY_CONFLICT",
        "BINDING_CONFLICT",
        "ROUTE_OR_SYMBOL_CONFLICT",
        "TRADE_BINDING_CONFLICT",
        "COMMAND_STATE_CONFLICT",
        "TRADE_SIDE_OR_OFFSET_CONFLICT",
        "POSITION_RANGE_CONFLICT",
    },
}


def _verify_execution_integrity(db: sqlite3.Connection, account: str, capacity: int) -> None:
    """Reconstruct persisted execution projections on open, without provider I/O."""
    try:
        count = db.execute("SELECT count(*) FROM direct_execution_facts").fetchone()[0]
        meta = db.execute(
            "SELECT account,max_facts,fact_count FROM direct_execution_meta"
        ).fetchall()
        if (
            len(meta) != 1
            or meta[0][0] != account
            or meta[0][1] != capacity
            or type(meta[0][2]) is not int
            or meta[0][2] != count
            or count > capacity
        ):
            raise ValueError("fact capacity")
        facts = {}
        alias_support = set()
        for row in db.execute("SELECT * FROM direct_execution_facts"):
            if (
                row["account"] != account
                or row["disposition"] not in _VALID_REASONS
                or row["reason"] not in _VALID_REASONS[row["disposition"]]
                or row["applied"] not in (0, 1)
            ):
                raise ValueError("fact status")
            raw = json.loads(row["fact_json"])
            fact = GatewayReturnFact.from_mapping(raw)
            if (
                fact.account_scope != account
                or fact.fact_digest() != row["fact_digest"]
                or _json(fact.to_mapping()) != row["fact_json"]
            ):
                raise ValueError("fact identity")
            if row["applied"] and (
                fact.kind is not DirectExecutionEventKind.TRADE
                or row["disposition"] != "ATTRIBUTED"
            ):
                raise ValueError("fact application")
            if row["disposition"] == "UNATTRIBUTED" and row["reservation_id"] is not None:
                raise ValueError("unattributed reservation")
            if row["reservation_id"] is not None:
                _text(row["reservation_id"])
                if (
                    db.execute(
                        "SELECT 1 FROM direct_journal_commands WHERE account=? AND reservation_id=?",
                        (account, row["reservation_id"]),
                    ).fetchone()
                    is None
                ):
                    raise ValueError("fact reservation orphan")
            if row["disposition"] == "ATTRIBUTED":
                command = db.execute(
                    "SELECT * FROM direct_journal_commands WHERE account=? AND reservation_id=?",
                    (account, row["reservation_id"]),
                ).fetchone()
                if command is None or command["status"] not in {
                    "DISPATCHING",
                    "SENT",
                    "UNKNOWN",
                    "NOT_SENT",
                }:
                    raise ValueError("fact command")
                original_keys = set(json.loads(command["strong_keys_json"]))
                owners = [
                    x[0]
                    for key in fact.identity_keys
                    for x in db.execute(
                        "SELECT reservation_id FROM direct_journal_strong_keys WHERE account=? AND strong_key=?",
                        (account, key),
                    )
                ]
                if (
                    len(owners) != len(fact.identity_keys)
                    or set(owners) != {row["reservation_id"]}
                    or not set(fact.binding_keys) <= original_keys
                ):
                    raise ValueError("fact binding")
                native = json.loads(command["native_identity_json"])
                payload = json.loads(command["payload_json"])
                if (
                    native.get("exchange_name") != fact.route
                    or payload.get("symbol") != fact.instrument.native_symbol
                ):
                    raise ValueError("fact route")
                if (
                    fact.kind is DirectExecutionEventKind.ORDER
                    and fact.venue_key is not None
                    and any(
                        key in original_keys and key != fact.venue_key for key in fact.identity_keys
                    )
                ):
                    alias_support.add((row["reservation_id"], fact.venue_key))
                if fact.kind is DirectExecutionEventKind.TRADE and row["applied"]:
                    if (
                        fact.trade_key is None
                        or fact.venue_key is None
                        or fact.side is None
                        or fact.trade_quantity is None
                        or fact.trade_price is None
                        or payload.get("side") != fact.side
                        or (
                            payload.get("offset") is not None
                            and payload.get("offset") != fact.offset
                        )
                    ):
                        raise ValueError("trade economics")
                if row["reason"] == "TRADE_DUPLICATE":
                    if row["event_sequence"] is not None or row["applied"]:
                        raise ValueError("duplicate event")
                elif row["event_sequence"] is None:
                    raise ValueError("missing event")
            elif row["event_sequence"] is not None or row["applied"]:
                raise ValueError("unattributed event")
            facts[row["fact_digest"]] = (row, fact)

        event_ids = set()
        expected_sequence = 1
        for event in db.execute("SELECT * FROM direct_execution_events ORDER BY sequence"):
            item = facts.get(event["fact_digest"])
            if (
                event["account"] != account
                or item is None
                or type(event["sequence"]) is not int
                or event["sequence"] != expected_sequence
            ):
                raise ValueError("event orphan")
            expected_sequence += 1
            row, fact = item
            command = db.execute(
                "SELECT strategy FROM direct_journal_commands WHERE account=? AND reservation_id=?",
                (account, row["reservation_id"]),
            ).fetchone()
            if (
                row["disposition"] != "ATTRIBUTED"
                or row["event_sequence"] != event["sequence"]
                or command is None
                or command["strategy"] != event["strategy"]
                or event["fact_json"] != row["fact_json"]
                or event["fact_digest"] in event_ids
            ):
                raise ValueError("event link")
            event_ids.add(event["fact_digest"])
        if any(
            row["event_sequence"] is not None and digest not in event_ids
            for digest, (row, _) in facts.items()
        ):
            raise ValueError("missing event")

        conflicts = {}
        conflict_fact_ids = set()
        for row in db.execute("SELECT * FROM direct_execution_conflicts"):
            item = facts.get(row["fact_digest"])
            if row["account"] != account or item is None:
                raise ValueError("conflict orphan")
            fact_row, fact = item
            if (
                fact.kind is not DirectExecutionEventKind.TRADE
                or fact.trade_key is None
                or fact_row["disposition"] != "CONFLICT"
                or fact.route != row["route"]
                or _json(list(fact.trade_key)) != row["trade_key_json"]
                or fact.trade_content_digest() != row["conflicting_content_digest"]
            ):
                raise ValueError("conflict link")
            conflicts.setdefault((row["route"], row["trade_key_json"]), []).append(row)
            conflict_fact_ids.add(row["fact_digest"])

        applied_facts = set()
        nets = {}
        totals = {}
        trade_keys = {}
        with localcontext() as context:
            context.prec = 160
            for trade in db.execute("SELECT * FROM direct_execution_trades"):
                item = facts.get(trade["fact_digest"])
                if (
                    trade["account"] != account
                    or item is None
                    or trade["applied"] not in (0, 1)
                    or trade["conflict"] not in (0, 1)
                ):
                    raise ValueError("trade orphan")
                fact_row, fact = item
                key = (trade["route"], trade["trade_key_json"])
                trade_keys[key] = trade
                if (
                    fact.kind is not DirectExecutionEventKind.TRADE
                    or fact.trade_key is None
                    or fact.route != trade["route"]
                    or _json(list(fact.trade_key)) != trade["trade_key_json"]
                    or fact.trade_content_digest() != trade["content_digest"]
                ):
                    raise ValueError("trade content")
                audit = conflicts.get(key, [])
                if bool(trade["conflict"]) != bool(audit) or any(
                    x["original_content_digest"] != trade["content_digest"] for x in audit
                ):
                    raise ValueError("trade conflict")
                if trade["applied"]:
                    if (
                        not fact_row["applied"]
                        or trade["quantity"] != fact.trade_quantity
                        or trade["reservation_id"] != fact_row["reservation_id"]
                    ):
                        raise ValueError("trade application")
                    command = db.execute(
                        "SELECT strategy FROM direct_journal_commands WHERE account=? AND reservation_id=?",
                        (account, trade["reservation_id"]),
                    ).fetchone()
                    if command is None:
                        raise ValueError("trade command")
                    identity = (command["strategy"], _json(fact.instrument.to_dict()))
                    amount = Decimal(fact.trade_quantity)
                    nets[identity] = nets.get(identity, Decimal(0)) + (
                        amount if fact.side == "buy" else -amount
                    )
                    totals[trade["reservation_id"]] = (
                        totals.get(trade["reservation_id"], Decimal(0)) + amount
                    )
                    applied_facts.add(trade["fact_digest"])
                elif trade["reservation_id"] is not None or trade["quantity"] is not None:
                    raise ValueError("unapplied trade")
        if {digest for digest, (row, _) in facts.items() if row["applied"]} != applied_facts:
            raise ValueError("applied fact orphan")
        if any(key not in trade_keys for key in conflicts):
            raise ValueError("conflict trade orphan")
        for digest, (row, fact) in facts.items():
            if fact.kind is not DirectExecutionEventKind.TRADE or fact.trade_key is None:
                continue
            trade = trade_keys.get((fact.route, _json(list(fact.trade_key))))
            if trade is None:
                raise ValueError("fact trade orphan")
            if (
                fact.trade_content_digest() != trade["content_digest"]
                and digest not in conflict_fact_ids
            ):
                raise ValueError("unaudited content conflict")
            if row["reason"] == "TRADE_DUPLICATE" and (
                not trade["applied"]
                or trade["reservation_id"] != row["reservation_id"]
                or trade["content_digest"] != fact.trade_content_digest()
            ):
                raise ValueError("invalid duplicate trade")
        positions = {}
        for row in db.execute("SELECT * FROM direct_execution_positions"):
            if row["account"] != account:
                raise ValueError("position account")
            key = (row["strategy"], row["instrument_json"])
            positions[key] = row["net_quantity"]
        if positions != {key: _canonical_quantity(value) for key, value in nets.items()}:
            raise ValueError("position mismatch")
        stored_totals = {}
        for row in db.execute("SELECT * FROM direct_execution_totals"):
            if row["account"] != account:
                raise ValueError("total account")
            stored_totals[row["reservation_id"]] = row["total_quantity"]
        if stored_totals != {
            key: _canonical_quantity(value, integer_limit=42) for key, value in totals.items()
        }:
            raise ValueError("trade total mismatch")
        for alias in db.execute("SELECT * FROM direct_execution_aliases"):
            if (alias["reservation_id"], alias["strong_key"]) not in alias_support:
                raise ValueError("unsupported alias")
    except Exception as exc:
        raise DirectCommandJournalError("INVALID_DATABASE") from exc
