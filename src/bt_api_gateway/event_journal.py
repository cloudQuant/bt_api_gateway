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
import uuid
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


@dataclass(frozen=True)
class GatewayConsumerProgress:
    """Durable per-principal consumer offer and acknowledgement positions."""

    stream_epoch: str
    offered_cursor: int
    acknowledged_cursor: int

    def __post_init__(self) -> None:
        if not _valid_bounded_identifier(self.stream_epoch):
            raise ValueError("stream_epoch must be a bounded identifier")
        if type(self.offered_cursor) is not int or self.offered_cursor < 0:
            raise ValueError("offered_cursor must be a non-negative integer")
        if (
            type(self.acknowledged_cursor) is not int
            or self.acknowledged_cursor < 0
            or self.acknowledged_cursor > self.offered_cursor
        ):
            raise ValueError("acknowledged_cursor must be within the offered range")


class GatewayEventJournal:
    """SQLite-backed event sequencing, deduplication, and snapshot compaction.

    Streams are keyed by opaque account and strategy scopes so one strategy
    client cannot read another strategy's events or snapshot through this API.
    Event producers and snapshot providers remain injected account-owner code.
    """

    MAX_BATCH_SIZE = 1000
    MAX_STATE_SNAPSHOT_BYTES = 512 * 1024
    MAX_CONSUMER_PROGRESS_RECORDS = 8192
    MAX_CONSUMER_STREAMS = 8192

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
            self._reject_state_stream(connection, account_scope, strategy_scope)
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
            self._reject_state_stream(connection, account_scope, strategy_scope)
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

    def replace_state_snapshot(
        self,
        account_scope: str,
        strategy_scope: str,
        snapshot_id: str,
        payload: Mapping[str, Any],
        *,
        expected_cursor: int,
        captured_at: Optional[float] = None,  # noqa: UP045 -- Python 3.9 is supported.
    ) -> GatewayAccountSnapshot:
        """Atomically replace a bounded account-state snapshot and advance its cursor.

        State streams retain only the latest replacement snapshot and sequence.
        They do not create event or deduplication rows. The first replacement can
        claim only an unused stream pair; state and event/snapshot APIs cannot be
        mixed for the same pair.

        Retrying the latest replacement with the same id, canonical payload,
        capture time, and original expected cursor returns the stored snapshot.
        """
        if type(expected_cursor) is not int or expected_cursor < 0:
            raise ValueError("expected_cursor must be a non-negative integer")
        snapshot_time_value = self._clock() if captured_at is None else captured_at
        _require_time(snapshot_time_value, "captured_at")
        snapshot_time = float(snapshot_time_value)
        candidate = GatewayAccountSnapshot(
            account_scope=account_scope,
            strategy_scope=strategy_scope,
            snapshot_id=snapshot_id,
            cursor=expected_cursor + 1,
            payload=payload,
            captured_at=snapshot_time,
        )
        payload_json = candidate.payload_json
        if len(payload_json.encode("utf-8")) > self.MAX_STATE_SNAPSHOT_BYTES:
            raise GatewayEventJournalError(
                "STATE_SNAPSHOT_TOO_LARGE",
                "state snapshot exceeds the maximum canonical JSON size",
            )
        fingerprint = _snapshot_fingerprint(candidate)

        with self._transaction() as connection:
            mode_row = connection.execute(
                """
                SELECT mode FROM gateway_event_stream_modes
                WHERE account_scope = ? AND strategy_scope = ?
                """,
                (account_scope, strategy_scope),
            ).fetchone()
            if mode_row is not None and str(mode_row["mode"]) != "state":
                raise self._stream_mode_conflict()

            existing = connection.execute(
                """
                SELECT * FROM gateway_event_snapshots
                WHERE account_scope = ? AND strategy_scope = ?
                """,
                (account_scope, strategy_scope),
            ).fetchone()
            if (
                mode_row is not None
                and existing is not None
                and str(existing["snapshot_id"]) == snapshot_id
            ):
                if (
                    int(existing["cursor"]) == expected_cursor + 1
                    and str(existing["fingerprint"]) == fingerprint
                ):
                    return self._snapshot_from_row(existing)
                raise GatewayEventJournalError(
                    "SNAPSHOT_ID_REUSED",
                    "snapshot id was reused with different content",
                )

            latest = self._latest_cursor(connection, account_scope, strategy_scope)
            if expected_cursor != latest:
                raise GatewayEventJournalError(
                    "SNAPSHOT_CURSOR_STALE", "snapshot cursor does not match current stream"
                )

            if mode_row is None:
                if self._has_stream_rows(connection, account_scope, strategy_scope):
                    raise self._stream_mode_conflict()
                connection.execute(
                    """
                    INSERT INTO gateway_event_stream_modes
                        (account_scope, strategy_scope, mode)
                    VALUES (?, ?, 'state')
                    """,
                    (account_scope, strategy_scope),
                )

            next_cursor = latest + 1
            connection.execute(
                """
                INSERT INTO gateway_event_sequences
                    (account_scope, strategy_scope, latest_sequence)
                VALUES (?, ?, ?)
                ON CONFLICT(account_scope, strategy_scope)
                DO UPDATE SET latest_sequence = excluded.latest_sequence
                """,
                (account_scope, strategy_scope, next_cursor),
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
                    next_cursor,
                    payload_json,
                    snapshot_time,
                    fingerprint,
                ),
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
        self._validate_read_request(cursor, limit)

        connection = self._connect()
        try:
            connection.execute("BEGIN")
            batch = self._read_batch_in_transaction(
                connection, account_scope, strategy_scope, cursor, limit
            )
            connection.execute("COMMIT")
            return batch
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def read_for_consumer(
        self,
        principal: GatewayPrincipal,
        account_scope: str,
        strategy_scope: str,
        consumer_ref: str,
        *,
        cursor: Optional[int] = None,  # noqa: UP045 -- Python 3.9 is supported.
        limit: int = 100,
        stream_epoch: Optional[str] = None,  # noqa: UP045 -- Python 3.9 is supported.
    ) -> tuple[GatewayReadBatch, GatewayConsumerProgress]:
        """Offer a read range and persist its cursor with the same SQLite commit.

        ``offered_cursor`` records the greatest range prepared for return. It
        does not assert that a transport delivered or consumed that range.
        ``consumer_ref`` must be a bounded identifier derived by trusted
        server-side code, not an arbitrary client-selected progress key.
        """
        self._authorize_read(principal, account_scope, strategy_scope)
        self._validate_consumer_ref(consumer_ref)
        self._validate_read_request(cursor, limit)
        if stream_epoch is not None:
            self._validate_stream_epoch(stream_epoch)
        if cursor is not None and cursor > 0 and stream_epoch is None:
            raise GatewayEventJournalError(
                "STREAM_EPOCH_REQUIRED", "a positive resume cursor requires its stream epoch"
            )

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            progress_key = (principal.principal_id, consumer_ref, account_scope, strategy_scope)
            progress_row = connection.execute(
                """
                SELECT * FROM gateway_consumer_progress
                WHERE principal_id = ? AND consumer_ref = ?
                    AND account_scope = ? AND strategy_scope = ?
                """,
                progress_key,
            ).fetchone()
            stream_row = connection.execute(
                """
                SELECT stream_epoch FROM gateway_consumer_streams
                WHERE account_scope = ? AND strategy_scope = ?
                """,
                (account_scope, strategy_scope),
            ).fetchone()
            if progress_row is not None and stream_row is None:
                raise self._consumer_progress_corrupt()

            if stream_row is None:
                if stream_epoch is not None:
                    raise self._stream_epoch_mismatch()
                stream_count = int(
                    connection.execute("SELECT COUNT(*) FROM gateway_consumer_streams").fetchone()[
                        0
                    ]
                )
                if stream_count >= self.MAX_CONSUMER_STREAMS:
                    raise GatewayEventJournalError(
                        "CONSUMER_STREAM_CAPACITY", "consumer stream capacity is exhausted"
                    )
                current_epoch = uuid.uuid4().hex
                connection.execute(
                    """
                    INSERT INTO gateway_consumer_streams
                        (account_scope, strategy_scope, stream_epoch)
                    VALUES (?, ?, ?)
                    """,
                    (account_scope, strategy_scope, current_epoch),
                )
            else:
                current_epoch = stream_row["stream_epoch"]
                if not _valid_bounded_identifier(current_epoch):
                    raise self._consumer_progress_corrupt()
                if stream_epoch is not None and stream_epoch != current_epoch:
                    raise self._stream_epoch_mismatch()

            if progress_row is not None:
                current_progress = self._consumer_progress_from_row(progress_row)
                if current_progress.stream_epoch != current_epoch:
                    raise self._consumer_progress_corrupt()
                offered = current_progress.offered_cursor
                acknowledged = current_progress.acknowledged_cursor
                if cursor is not None and cursor > offered:
                    raise GatewayEventJournalError(
                        "CONSUMER_CURSOR_UNOFFERED",
                        "resume cursor was not previously offered to this consumer",
                    )
            else:
                offered = 0
                acknowledged = 0
                if cursor is not None and cursor > 0:
                    raise GatewayEventJournalError(
                        "CONSUMER_CURSOR_UNOFFERED",
                        "a new consumer may start only at cursor zero or the current baseline",
                    )
                progress_count = int(
                    connection.execute("SELECT COUNT(*) FROM gateway_consumer_progress").fetchone()[
                        0
                    ]
                )
                if progress_count >= self.MAX_CONSUMER_PROGRESS_RECORDS:
                    raise GatewayEventJournalError(
                        "CONSUMER_PROGRESS_CAPACITY", "consumer progress capacity is exhausted"
                    )

            batch = self._read_batch_in_transaction(
                connection, account_scope, strategy_scope, cursor, limit
            )
            offered = max(offered, batch.next_cursor)
            if progress_row is None:
                connection.execute(
                    """
                    INSERT INTO gateway_consumer_progress (
                        principal_id, consumer_ref, account_scope, strategy_scope,
                        stream_epoch, offered_cursor, acknowledged_cursor
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (*progress_key, current_epoch, offered, acknowledged),
                )
            else:
                connection.execute(
                    """
                    UPDATE gateway_consumer_progress
                    SET offered_cursor = ?
                    WHERE principal_id = ? AND consumer_ref = ?
                        AND account_scope = ? AND strategy_scope = ?
                    """,
                    (offered, *progress_key),
                )
            progress = GatewayConsumerProgress(current_epoch, offered, acknowledged)
            connection.execute("COMMIT")
            return batch, progress
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def consumer_progress(
        self,
        principal: GatewayPrincipal,
        account_scope: str,
        strategy_scope: str,
        consumer_ref: str,
    ) -> GatewayConsumerProgress:
        """Read existing consumer progress without creating a stream or consumer.

        The caller supplies ``consumer_ref`` from trusted server-side identity
        or registration state; it is not a client-created progress namespace.
        """
        self._authorize_read(principal, account_scope, strategy_scope)
        self._validate_consumer_ref(consumer_ref)
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            row = connection.execute(
                """
                SELECT progress.stream_epoch, progress.offered_cursor,
                    progress.acknowledged_cursor, streams.stream_epoch AS current_epoch
                FROM gateway_consumer_progress AS progress
                JOIN gateway_consumer_streams AS streams
                    ON streams.account_scope = progress.account_scope
                    AND streams.strategy_scope = progress.strategy_scope
                WHERE progress.principal_id = ? AND progress.consumer_ref = ?
                    AND progress.account_scope = ? AND progress.strategy_scope = ?
                """,
                (principal.principal_id, consumer_ref, account_scope, strategy_scope),
            ).fetchone()
            if row is None:
                raise GatewayEventJournalError(
                    "CONSUMER_NOT_FOUND", "consumer progress does not exist"
                )
            if (
                not _valid_bounded_identifier(row["current_epoch"])
                or row["stream_epoch"] != row["current_epoch"]
            ):
                raise self._consumer_progress_corrupt()
            progress = self._consumer_progress_from_row(row)
            connection.execute("COMMIT")
            return progress
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def acknowledge(
        self,
        principal: GatewayPrincipal,
        account_scope: str,
        strategy_scope: str,
        consumer_ref: str,
        *,
        stream_epoch: str,
        cursor: int,
    ) -> GatewayConsumerProgress:
        """Advance consumer acknowledgement without deleting or compacting data.

        The caller supplies ``consumer_ref`` from trusted server-side identity
        or registration state; it is not a client-created progress namespace.
        """
        self._authorize_read(principal, account_scope, strategy_scope)
        self._validate_consumer_ref(consumer_ref)
        self._validate_stream_epoch(stream_epoch)
        if type(cursor) is not int or cursor < 0:
            raise GatewayEventJournalError(
                "ACK_CURSOR_INVALID", "acknowledgement cursor must be a non-negative integer"
            )
        progress_key = (principal.principal_id, consumer_ref, account_scope, strategy_scope)
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT progress.stream_epoch, progress.offered_cursor,
                    progress.acknowledged_cursor, streams.stream_epoch AS current_epoch
                FROM gateway_consumer_progress AS progress
                JOIN gateway_consumer_streams AS streams
                    ON streams.account_scope = progress.account_scope
                    AND streams.strategy_scope = progress.strategy_scope
                WHERE progress.principal_id = ? AND progress.consumer_ref = ?
                    AND progress.account_scope = ? AND progress.strategy_scope = ?
                """,
                progress_key,
            ).fetchone()
            if row is None:
                raise GatewayEventJournalError(
                    "CONSUMER_NOT_FOUND", "consumer progress does not exist"
                )
            current = self._consumer_progress_from_row(row)
            if (
                not _valid_bounded_identifier(row["current_epoch"])
                or current.stream_epoch != row["current_epoch"]
            ):
                raise self._consumer_progress_corrupt()
            if stream_epoch != current.stream_epoch:
                raise self._stream_epoch_mismatch()
            if cursor > current.offered_cursor:
                raise GatewayEventJournalError(
                    "ACK_CURSOR_AHEAD", "acknowledgement exceeds the offered cursor"
                )
            if cursor <= current.acknowledged_cursor:
                return current
            connection.execute(
                """
                UPDATE gateway_consumer_progress SET acknowledged_cursor = ?
                WHERE principal_id = ? AND consumer_ref = ?
                    AND account_scope = ? AND strategy_scope = ?
                """,
                (cursor, *progress_key),
            )
            return GatewayConsumerProgress(current.stream_epoch, current.offered_cursor, cursor)

    def _read_batch_in_transaction(
        self,
        connection: sqlite3.Connection,
        account_scope: str,
        strategy_scope: str,
        cursor: Optional[int],  # noqa: UP045 -- Python 3.9 is supported.
        limit: int,
    ) -> GatewayReadBatch:
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
        if snapshot_row is not None and (cursor is None or cursor < int(snapshot_row["cursor"])):
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
        return GatewayReadBatch(
            account_scope=account_scope,
            strategy_scope=strategy_scope,
            requested_cursor=cursor,
            snapshot=snapshot,
            events=events,
            next_cursor=next_cursor,
            latest_cursor=latest,
        )

    def _validate_read_request(
        self,
        cursor: Optional[int],  # noqa: UP045 -- Python 3.9 is supported.
        limit: int,
    ) -> None:
        if cursor is not None and (type(cursor) is not int or cursor < 0):
            raise GatewayEventJournalError(
                "CURSOR_INVALID", "cursor must be a non-negative integer or None"
            )
        if type(limit) is not int or not 1 <= limit <= self.MAX_BATCH_SIZE:
            raise GatewayEventJournalError(
                "BATCH_SIZE_INVALID", "limit must be between 1 and the maximum batch size"
            )

    def _validate_consumer_ref(self, consumer_ref: str) -> None:
        if not _valid_bounded_identifier(consumer_ref):
            raise GatewayEventJournalError(
                "CONSUMER_REF_INVALID", "consumer reference must be a bounded identifier"
            )

    def _validate_stream_epoch(self, stream_epoch: str) -> None:
        if not _valid_bounded_identifier(stream_epoch):
            raise GatewayEventJournalError(
                "STREAM_EPOCH_INVALID", "stream epoch must be a bounded identifier"
            )

    def _stream_epoch_mismatch(self) -> GatewayEventJournalError:
        return GatewayEventJournalError(
            "STREAM_EPOCH_MISMATCH", "stream epoch does not match this journal stream"
        )

    def _consumer_progress_corrupt(self) -> GatewayEventJournalError:
        return GatewayEventJournalError(
            "CONSUMER_PROGRESS_CORRUPT", "consumer progress does not match its stream"
        )

    def _consumer_progress_from_row(self, row: sqlite3.Row) -> GatewayConsumerProgress:
        try:
            return GatewayConsumerProgress(
                stream_epoch=row["stream_epoch"],
                offered_cursor=row["offered_cursor"],
                acknowledged_cursor=row["acknowledged_cursor"],
            )
        except (IndexError, KeyError, TypeError, ValueError):
            raise self._consumer_progress_corrupt() from None

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

    def _reject_state_stream(
        self, connection: sqlite3.Connection, account_scope: str, strategy_scope: str
    ) -> None:
        row = connection.execute(
            """
            SELECT mode FROM gateway_event_stream_modes
            WHERE account_scope = ? AND strategy_scope = ?
            """,
            (account_scope, strategy_scope),
        ).fetchone()
        if row is not None and str(row["mode"]) == "state":
            raise self._stream_mode_conflict()

    def _has_stream_rows(
        self, connection: sqlite3.Connection, account_scope: str, strategy_scope: str
    ) -> bool:
        row = connection.execute(
            """
            SELECT
                EXISTS (
                    SELECT 1 FROM gateway_events
                    WHERE account_scope = ? AND strategy_scope = ?
                ) AS has_events,
                EXISTS (
                    SELECT 1 FROM gateway_event_snapshots
                    WHERE account_scope = ? AND strategy_scope = ?
                ) AS has_snapshots,
                EXISTS (
                    SELECT 1 FROM gateway_event_sequences
                    WHERE account_scope = ? AND strategy_scope = ?
                ) AS has_sequences
            """,
            (account_scope, strategy_scope) * 3,
        ).fetchone()
        return bool(row["has_events"] or row["has_snapshots"] or row["has_sequences"])

    def _stream_mode_conflict(self) -> GatewayEventJournalError:
        return GatewayEventJournalError(
            "STREAM_MODE_CONFLICT",
            "state replacement and event snapshot streams cannot be mixed",
        )

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
                CREATE TABLE IF NOT EXISTS gateway_event_stream_modes (
                    account_scope TEXT NOT NULL,
                    strategy_scope TEXT NOT NULL,
                    mode TEXT NOT NULL CHECK (mode = 'state'),
                    PRIMARY KEY (account_scope, strategy_scope)
                );
                CREATE TABLE IF NOT EXISTS gateway_consumer_streams (
                    account_scope TEXT NOT NULL,
                    strategy_scope TEXT NOT NULL,
                    stream_epoch TEXT NOT NULL,
                    PRIMARY KEY (account_scope, strategy_scope)
                );
                CREATE TABLE IF NOT EXISTS gateway_consumer_progress (
                    principal_id TEXT NOT NULL,
                    consumer_ref TEXT NOT NULL,
                    account_scope TEXT NOT NULL,
                    strategy_scope TEXT NOT NULL,
                    stream_epoch TEXT NOT NULL,
                    offered_cursor INTEGER NOT NULL CHECK (offered_cursor >= 0),
                    acknowledged_cursor INTEGER NOT NULL CHECK (
                        acknowledged_cursor >= 0 AND acknowledged_cursor <= offered_cursor
                    ),
                    PRIMARY KEY (principal_id, consumer_ref, account_scope, strategy_scope)
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


def _valid_bounded_identifier(value: object) -> bool:
    if type(value) is not str or not value or value != value.strip():
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= 128 and not any(
        ord(char) < 32 or 0x7F <= ord(char) <= 0x9F for char in value
    )


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
