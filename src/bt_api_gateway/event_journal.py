"""Durable account-scoped event cursors with snapshot-based gap recovery.

This module is a provider- and transport-neutral read-model primitive. An
account owner supplies already-redacted events and a snapshot captured at an
explicit event cursor. It does not connect to a provider or authenticate a
remote client.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Union

from .router import (
    GatewayCommandKind,
    GatewayPrincipal,
    _canonical_json,
    _freeze_json,
    _validate_redacted,
)


class GatewayEventJournalError(RuntimeError):
    """A cursor, snapshot, or event could not be accepted safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class GatewayAccountEvent:
    """One immutable event in an account/strategy stream."""

    account_scope: str
    strategy_scope: str
    sequence: int
    event_id: str
    kind: str
    payload: Mapping[str, Any]
    observed_at: float

    def __post_init__(self) -> None:
        _require_text(self.account_scope, "account_scope")
        _require_text(self.strategy_scope, "strategy_scope")
        _require_text(self.event_id, "event_id")
        _require_text(self.kind, "kind")
        if type(self.sequence) is not int or self.sequence <= 0:
            raise ValueError("sequence must be a positive integer")
        _require_time(self.observed_at, "observed_at")
        if not isinstance(self.payload, Mapping):
            raise ValueError("payload must be a mapping")
        _validate_redacted(self.payload)
        object.__setattr__(self, "payload", _freeze_json(json.loads(_canonical_json(self.payload))))

    @property
    def payload_json(self) -> str:
        return _canonical_json(self.payload)


@dataclass(frozen=True)
class GatewayAccountSnapshot:
    """An account-owner snapshot tied to the stream cursor it covers."""

    account_scope: str
    strategy_scope: str
    snapshot_id: str
    cursor: int
    payload: Mapping[str, Any]
    captured_at: float

    def __post_init__(self) -> None:
        _require_text(self.account_scope, "account_scope")
        _require_text(self.strategy_scope, "strategy_scope")
        _require_text(self.snapshot_id, "snapshot_id")
        if type(self.cursor) is not int or self.cursor < 0:
            raise ValueError("snapshot cursor must be a non-negative integer")
        _require_time(self.captured_at, "captured_at")
        if not isinstance(self.payload, Mapping):
            raise ValueError("snapshot payload must be a mapping")
        _validate_redacted(self.payload)
        object.__setattr__(self, "payload", _freeze_json(json.loads(_canonical_json(self.payload))))

    @property
    def payload_json(self) -> str:
        return _canonical_json(self.payload)


@dataclass(frozen=True)
class GatewayReadBatch:
    """Snapshot/replay response with a cursor clients can persist and resume."""

    account_scope: str
    strategy_scope: str
    requested_cursor: Optional[int]  # noqa: UP045 -- Python 3.9 is supported.
    snapshot: Optional[GatewayAccountSnapshot]  # noqa: UP045 -- Python 3.9 is supported.
    events: tuple[GatewayAccountEvent, ...]
    next_cursor: int
    latest_cursor: int


class GatewayEventJournal:
    """SQLite-backed event sequencing, deduplication, and snapshot compaction.

    Streams are keyed by opaque account and strategy scopes so one strategy
    client cannot read another strategy's events or snapshot through this API.
    Event producers and snapshot providers remain injected account-owner code.
    """

    MAX_BATCH_SIZE = 1000

    def __init__(
        self,
        database_path: Union[Path, str],  # noqa: UP007 -- Python 3.9 is supported.
        clock: Optional[Callable[[], float]] = None,  # noqa: UP045 -- Python 3.9 is supported.
        timeout_seconds: float = 5.0,
    ) -> None:
        self._database_path = Path(database_path)
        self._clock = clock or time.time
        self._timeout_seconds = timeout_seconds
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    def append(
        self,
        account_scope: str,
        strategy_scope: str,
        event_id: str,
        kind: str,
        payload: Mapping[str, Any],
        observed_at: Optional[float] = None,  # noqa: UP045 -- Python 3.9 is supported.
    ) -> GatewayAccountEvent:
        """Persist an event once; identical redelivery returns its original cursor."""
        event_time = self._clock() if observed_at is None else observed_at
        _require_time(event_time, "observed_at")
        candidate = GatewayAccountEvent(
            account_scope=account_scope,
            strategy_scope=strategy_scope,
            sequence=1,
            event_id=event_id,
            kind=kind,
            payload=payload,
            observed_at=event_time,
        )
        fingerprint = _event_fingerprint(candidate)
        with self._transaction() as connection:
            existing = connection.execute(
                """
                SELECT * FROM gateway_event_dedupe
                WHERE account_scope = ? AND strategy_scope = ? AND event_id = ?
                """,
                (account_scope, strategy_scope, event_id),
            ).fetchone()
            if existing is not None:
                if str(existing["fingerprint"]) != fingerprint:
                    raise GatewayEventJournalError(
                        "EVENT_ID_REUSED", "event id was reused with different content"
                    )
                return GatewayAccountEvent(
                    account_scope=account_scope,
                    strategy_scope=strategy_scope,
                    sequence=int(existing["sequence"]),
                    event_id=event_id,
                    kind=kind,
                    payload=payload,
                    observed_at=float(existing["observed_at"]),
                )

            sequence_row = connection.execute(
                """
                SELECT latest_sequence FROM gateway_event_sequences
                WHERE account_scope = ? AND strategy_scope = ?
                """,
                (account_scope, strategy_scope),
            ).fetchone()
            sequence = int(sequence_row["latest_sequence"]) + 1 if sequence_row else 1
            connection.execute(
                """
                INSERT INTO gateway_event_sequences
                    (account_scope, strategy_scope, latest_sequence)
                VALUES (?, ?, ?)
                ON CONFLICT(account_scope, strategy_scope)
                DO UPDATE SET latest_sequence = excluded.latest_sequence
                """,
                (account_scope, strategy_scope, sequence),
            )
            event = GatewayAccountEvent(
                account_scope=account_scope,
                strategy_scope=strategy_scope,
                sequence=sequence,
                event_id=event_id,
                kind=kind,
                payload=payload,
                observed_at=event_time,
            )
            connection.execute(
                """
                INSERT INTO gateway_events (
                    account_scope, strategy_scope, sequence, event_id, kind,
                    payload_json, observed_at, fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    account_scope,
                    strategy_scope,
                    sequence,
                    event_id,
                    kind,
                    event.payload_json,
                    event_time,
                    fingerprint,
                ),
            )
            connection.execute(
                """
                INSERT INTO gateway_event_dedupe (
                    account_scope, strategy_scope, event_id, sequence, fingerprint, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (account_scope, strategy_scope, event_id, sequence, fingerprint, event_time),
            )
        return event

    def capture_snapshot(
        self,
        account_scope: str,
        strategy_scope: str,
        snapshot_id: str,
        expected_cursor: int,
        payload: Mapping[str, Any],
        captured_at: Optional[float] = None,  # noqa: UP045 -- Python 3.9 is supported.
    ) -> GatewayAccountSnapshot:
        """Store a caller-supplied snapshot only if its declared cursor is current.

        Events through that cursor are compacted in the same SQLite transaction.
        The owner must build the payload from the same read-model version as
        ``expected_cursor``; this equality check rejects an intervening append.
        """
        snapshot_time = self._clock() if captured_at is None else captured_at
        candidate = GatewayAccountSnapshot(
            account_scope=account_scope,
            strategy_scope=strategy_scope,
            snapshot_id=snapshot_id,
            cursor=expected_cursor,
            payload=payload,
            captured_at=snapshot_time,
        )
        digest = _snapshot_fingerprint(candidate)
        with self._transaction() as connection:
            latest = self._latest_cursor(connection, account_scope, strategy_scope)
            if expected_cursor != latest:
                raise GatewayEventJournalError(
                    "SNAPSHOT_CURSOR_STALE", "snapshot cursor does not match current stream"
                )
            existing = connection.execute(
                """
                SELECT snapshot_id, cursor, fingerprint FROM gateway_event_snapshots
                WHERE account_scope = ? AND strategy_scope = ?
                """,
                (account_scope, strategy_scope),
            ).fetchone()
            if existing is not None and str(existing["snapshot_id"]) == snapshot_id:
                if str(existing["fingerprint"]) != digest:
                    raise GatewayEventJournalError(
                        "SNAPSHOT_ID_REUSED", "snapshot id was reused with different content"
                    )
                return self._snapshot_from_row(
                    connection.execute(
                        """
                        SELECT * FROM gateway_event_snapshots
                        WHERE account_scope = ? AND strategy_scope = ?
                        """,
                        (account_scope, strategy_scope),
                    ).fetchone()
                )
            if existing is not None and int(existing["cursor"]) == expected_cursor:
                raise GatewayEventJournalError(
                    "SNAPSHOT_CURSOR_CONFLICT",
                    "different snapshot content cannot claim the same stream cursor",
                )
            connection.execute(
                """
                INSERT INTO gateway_event_snapshots (
                    account_scope, strategy_scope, snapshot_id, cursor,
                    payload_json, captured_at, fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(account_scope, strategy_scope) DO UPDATE SET
                    snapshot_id = excluded.snapshot_id,
                    cursor = excluded.cursor,
                    payload_json = excluded.payload_json,
                    captured_at = excluded.captured_at,
                    fingerprint = excluded.fingerprint
                """,
                (
                    account_scope,
                    strategy_scope,
                    snapshot_id,
                    expected_cursor,
                    candidate.payload_json,
                    snapshot_time,
                    digest,
                ),
            )
            connection.execute(
                """
                DELETE FROM gateway_events
                WHERE account_scope = ? AND strategy_scope = ? AND sequence <= ?
                """,
                (account_scope, strategy_scope, expected_cursor),
            )
        return candidate

    def read_after(
        self,
        principal: GatewayPrincipal,
        account_scope: str,
        strategy_scope: str,
        cursor: Optional[int] = None,  # noqa: UP045 -- Python 3.9 is supported.
        limit: int = 100,
    ) -> GatewayReadBatch:
        """Return replay events or a compacted snapshot followed by replay."""
        self._authorize_read(principal, account_scope, strategy_scope)
        if cursor is not None and (type(cursor) is not int or cursor < 0):
            raise GatewayEventJournalError(
                "CURSOR_INVALID", "cursor must be a non-negative integer or None"
            )
        if type(limit) is not int or not 1 <= limit <= self.MAX_BATCH_SIZE:
            raise GatewayEventJournalError(
                "BATCH_SIZE_INVALID", "limit must be between 1 and the maximum batch size"
            )

        connection = self._connect()
        try:
            connection.execute("BEGIN")
            latest = self._latest_cursor(connection, account_scope, strategy_scope)
            if cursor is not None and cursor > latest:
                raise GatewayEventJournalError("CURSOR_AHEAD", "cursor is ahead of the stream")
            snapshot_row = connection.execute(
                """
                SELECT * FROM gateway_event_snapshots
                WHERE account_scope = ? AND strategy_scope = ?
                """,
                (account_scope, strategy_scope),
            ).fetchone()
            snapshot = None
            base_cursor = 0 if cursor is None else cursor
            if snapshot_row is not None and (
                cursor is None or cursor < int(snapshot_row["cursor"])
            ):
                snapshot = self._snapshot_from_row(snapshot_row)
                base_cursor = snapshot.cursor
            rows = connection.execute(
                """
                SELECT * FROM gateway_events
                WHERE account_scope = ? AND strategy_scope = ? AND sequence > ?
                ORDER BY sequence LIMIT ?
                """,
                (account_scope, strategy_scope, base_cursor, limit),
            ).fetchall()
            events = tuple(self._event_from_row(row) for row in rows)
            next_cursor = events[-1].sequence if events else base_cursor
            batch = GatewayReadBatch(
                account_scope=account_scope,
                strategy_scope=strategy_scope,
                requested_cursor=cursor,
                snapshot=snapshot,
                events=events,
                next_cursor=next_cursor,
                latest_cursor=latest,
            )
            connection.execute("COMMIT")
            return batch
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _authorize_read(
        self, principal: GatewayPrincipal, account_scope: str, strategy_scope: str
    ) -> None:
        if account_scope not in principal.account_scopes:
            raise GatewayEventJournalError(
                "ACCOUNT_SCOPE_DENIED", "principal is not authorized for account"
            )
        if strategy_scope not in principal.strategy_scopes:
            raise GatewayEventJournalError(
                "STRATEGY_SCOPE_DENIED", "principal is not authorized for strategy"
            )
        if GatewayCommandKind.READ not in principal.allowed_kinds:
            raise GatewayEventJournalError(
                "COMMAND_KIND_DENIED", "principal is not authorized to read events"
            )

    def _event_from_row(self, row: sqlite3.Row) -> GatewayAccountEvent:
        return GatewayAccountEvent(
            account_scope=str(row["account_scope"]),
            strategy_scope=str(row["strategy_scope"]),
            sequence=int(row["sequence"]),
            event_id=str(row["event_id"]),
            kind=str(row["kind"]),
            payload=json.loads(str(row["payload_json"])),
            observed_at=float(row["observed_at"]),
        )

    def _snapshot_from_row(self, row: sqlite3.Row) -> GatewayAccountSnapshot:
        return GatewayAccountSnapshot(
            account_scope=str(row["account_scope"]),
            strategy_scope=str(row["strategy_scope"]),
            snapshot_id=str(row["snapshot_id"]),
            cursor=int(row["cursor"]),
            payload=json.loads(str(row["payload_json"])),
            captured_at=float(row["captured_at"]),
        )

    def _latest_cursor(
        self, connection: sqlite3.Connection, account_scope: str, strategy_scope: str
    ) -> int:
        row = connection.execute(
            """
            SELECT latest_sequence FROM gateway_event_sequences
            WHERE account_scope = ? AND strategy_scope = ?
            """,
            (account_scope, strategy_scope),
        ).fetchone()
        return int(row["latest_sequence"]) if row else 0

    def _initialize_schema(self) -> None:
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS gateway_event_sequences (
                    account_scope TEXT NOT NULL,
                    strategy_scope TEXT NOT NULL,
                    latest_sequence INTEGER NOT NULL,
                    PRIMARY KEY (account_scope, strategy_scope)
                );
                CREATE TABLE IF NOT EXISTS gateway_events (
                    account_scope TEXT NOT NULL,
                    strategy_scope TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    fingerprint TEXT NOT NULL,
                    PRIMARY KEY (account_scope, strategy_scope, sequence),
                    UNIQUE (account_scope, strategy_scope, event_id)
                );
                CREATE TABLE IF NOT EXISTS gateway_event_dedupe (
                    account_scope TEXT NOT NULL,
                    strategy_scope TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    PRIMARY KEY (account_scope, strategy_scope, event_id)
                );
                CREATE TABLE IF NOT EXISTS gateway_event_snapshots (
                    account_scope TEXT NOT NULL,
                    strategy_scope TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    cursor INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    captured_at REAL NOT NULL,
                    fingerprint TEXT NOT NULL,
                    PRIMARY KEY (account_scope, strategy_scope)
                );
                """
            )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self._database_path), timeout=self._timeout_seconds, isolation_level=None
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")


def _event_fingerprint(event: GatewayAccountEvent) -> str:
    return _digest(
        _canonical_json(
            {
                "account_scope": event.account_scope,
                "event_id": event.event_id,
                "kind": event.kind,
                "payload": json.loads(event.payload_json),
                "strategy_scope": event.strategy_scope,
            }
        )
    )


def _snapshot_fingerprint(snapshot: GatewayAccountSnapshot) -> str:
    return _digest(
        _canonical_json(
            {
                "account_scope": snapshot.account_scope,
                "captured_at": snapshot.captured_at,
                "cursor": snapshot.cursor,
                "payload": json.loads(snapshot.payload_json),
                "snapshot_id": snapshot.snapshot_id,
                "strategy_scope": snapshot.strategy_scope,
            }
        )
    )


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(name + " must be a non-empty trimmed string")


def _require_time(value: float, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(name + " must be a finite number")
    try:
        finite = math.isfinite(float(value))
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError(name + " must be a finite number")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
