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
import re
import sqlite3
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Optional, Union

from bt_api_base.account_protocol import AccountObservation, AccountResourceKey

from .account_view_projection import (
    AccountViewProjectionError,
    GatewayAccountViewPolicy,
    project_account_view,
    validate_policy_set,
    view_delta,
)
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
    MAX_ACCOUNT_VIEW_EVENTS = 1000
    MAX_ACCOUNT_VIEW_EVENT_BYTES = 4 * 1024 * 1024
    MAX_ACCOUNT_VIEW_POLICY_SET_BYTES = 1024 * 1024
    MAX_ACCOUNT_VIEW_SOURCE_BINDINGS = 64
    MAX_SQLITE_INTEGER = 9_223_372_036_854_775_807

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
            self._reject_managed_view_write(connection, account_scope, strategy_scope)
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
            sequence = self._next_sequence(
                int(sequence_row["latest_sequence"]) if sequence_row else 0
            )
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
            self._reject_managed_view_write(connection, account_scope, strategy_scope)
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
        view_policies: tuple[GatewayAccountViewPolicy, ...] = (),
    ) -> GatewayAccountSnapshot:
        """Atomically replace a bounded account-state snapshot and advance its cursor.

        State streams retain only the latest replacement snapshot and sequence.
        They do not create event or deduplication rows. The first replacement can
        claim only an unused stream pair; state and event/snapshot APIs cannot be
        mixed for the same pair.

        Retrying the latest replacement with the same id, canonical payload,
        capture time, and original expected cursor returns the stored snapshot.
        """
        if type(expected_cursor) is not int or not 0 <= expected_cursor <= self.MAX_SQLITE_INTEGER:
            raise ValueError("expected_cursor must be a non-negative integer")
        policies = self._validated_view_policies(view_policies)
        if expected_cursor == self.MAX_SQLITE_INTEGER:
            raise GatewayEventJournalError(
                "SEQUENCE_OVERFLOW", "journal sequence reached its storage limit"
            )
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

        source_observation: Optional[AccountObservation] = None  # noqa: UP045
        account_key_digest: Optional[str] = None  # noqa: UP045
        if policies:
            source_observation, account_key_digest = self._parse_view_source_payload(candidate)

        with self._transaction() as connection:
            self._reject_managed_view_write(connection, account_scope, strategy_scope)
            mode_row = connection.execute(
                """
                SELECT mode FROM gateway_event_stream_modes
                WHERE account_scope = ? AND strategy_scope = ?
                """,
                (account_scope, strategy_scope),
            ).fetchone()
            if mode_row is not None and str(mode_row["mode"]) != "state":
                raise self._stream_mode_conflict()

            source_binding = self._state_view_source_binding(
                connection, account_scope, strategy_scope
            )
            policy_set_json = self._policy_set_json(policies)
            policy_set_digest = _digest(policy_set_json)
            if source_binding is not None:
                self._validate_source_view_binding(
                    source_binding,
                    policies,
                    policy_set_json,
                    policy_set_digest,
                    account_key_digest,
                )
                self._validate_existing_managed_views(
                    connection,
                    account_scope,
                    strategy_scope,
                    policies,
                    int(source_binding["source_cursor"]),
                )
            elif policies:
                latest_for_policy = self._latest_cursor(connection, account_scope, strategy_scope)
                if (
                    mode_row is not None
                    or latest_for_policy
                    or self._has_stream_artifacts(connection, account_scope, strategy_scope)
                ):
                    raise GatewayEventJournalError(
                        "VIEW_POLICY_SET_REQUIRED",
                        "view policies must be bound before the source stream is used",
                    )
                assert account_key_digest is not None
                self._validate_view_targets(connection, account_scope, strategy_scope, policies)

            if source_binding is not None and account_key_digest is None:
                # Existing managed streams cannot be updated using an arbitrary
                # legacy payload or by omitting the source-view policy tuple.
                raise GatewayEventJournalError(
                    "VIEW_POLICY_MISMATCH", "configured view policies do not match the source"
                )

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
                    if source_binding is not None:
                        self._validate_existing_managed_views(
                            connection,
                            account_scope,
                            strategy_scope,
                            policies,
                            int(existing["cursor"]),
                        )
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

            next_cursor = self._next_sequence(latest)
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
            if policies:
                assert source_observation is not None and account_key_digest is not None
                if source_binding is None:
                    connection.execute(
                        """
                        INSERT INTO gateway_state_view_sources (
                            account_scope, source_scope, policy_set_json,
                            policy_set_digest, account_key_digest, source_cursor
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            account_scope,
                            strategy_scope,
                            policy_set_json,
                            policy_set_digest,
                            account_key_digest,
                            next_cursor,
                        ),
                    )
                    for policy in policies:
                        self._create_account_view_baseline(
                            connection,
                            account_scope,
                            strategy_scope,
                            policy,
                            source_observation,
                            next_cursor,
                            snapshot_time,
                        )
                else:
                    self._update_account_views(
                        connection,
                        account_scope,
                        strategy_scope,
                        policies,
                        source_observation,
                        next_cursor,
                        snapshot_time,
                    )
                    connection.execute(
                        """
                        UPDATE gateway_state_view_sources SET source_cursor = ?
                        WHERE account_scope = ? AND source_scope = ?
                        """,
                        (next_cursor, account_scope, strategy_scope),
                    )
        return candidate

    def validate_state_view_policies(
        self,
        account_scope: str,
        source_scope: str,
        view_policies: tuple[GatewayAccountViewPolicy, ...],
    ) -> None:
        """Preflight a trusted view policy set before opening a provider session."""
        _require_text(account_scope, "account_scope")
        _require_text(source_scope, "source_scope")
        policies = self._validated_view_policies(view_policies)
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._reject_managed_view_write(connection, account_scope, source_scope)
            binding = self._state_view_source_binding(connection, account_scope, source_scope)
            policy_json = self._policy_set_json(policies)
            policy_digest = _digest(policy_json)
            if binding is not None:
                self._validate_source_view_binding(
                    binding, policies, policy_json, policy_digest, account_key_digest=None
                )
                self._validate_existing_managed_views(
                    connection,
                    account_scope,
                    source_scope,
                    policies,
                    int(binding["source_cursor"]),
                )
            elif policies:
                mode_row = connection.execute(
                    """
                    SELECT mode FROM gateway_event_stream_modes
                    WHERE account_scope = ? AND strategy_scope = ?
                    """,
                    (account_scope, source_scope),
                ).fetchone()
                if mode_row is not None or self._has_stream_artifacts(
                    connection, account_scope, source_scope
                ):
                    raise GatewayEventJournalError(
                        "VIEW_POLICY_SET_REQUIRED",
                        "view policies must be bound before the source stream is used",
                    )
                self._validate_view_targets(connection, account_scope, source_scope, policies)
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def account_view_is_current(
        self,
        account_scope: str,
        source_scope: str,
        view_scope: str,
        policy_digest: str,
        source_cursor: int,
        view_cursor: int,
    ) -> bool:
        """Check private source/view freshness without returning source metadata."""
        if (
            not _valid_bounded_identifier(account_scope)
            or not _valid_bounded_identifier(source_scope)
            or not _valid_bounded_identifier(view_scope)
            or type(policy_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", policy_digest) is None
            or type(source_cursor) is not int
            or type(view_cursor) is not int
            or not 0 <= source_cursor <= self.MAX_SQLITE_INTEGER
            or not 0 <= view_cursor <= self.MAX_SQLITE_INTEGER
        ):
            return False
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            source = self._state_view_source_binding(connection, account_scope, source_scope)
            view = connection.execute(
                """
                SELECT policy_digest, source_cursor, view_cursor
                FROM gateway_account_views
                WHERE account_scope = ? AND source_scope = ? AND view_scope = ?
                """,
                (account_scope, source_scope, view_scope),
            ).fetchone()
            current = False
            if source is not None and view is not None:
                policies = self._policy_set_from_binding(source)
                matching = next(
                    (policy for policy in policies if policy.view_scope == view_scope), None
                )
                if (
                    matching is not None
                    and matching.digest == policy_digest
                    and int(source["source_cursor"]) == source_cursor
                    and int(view["source_cursor"]) == source_cursor
                    and int(view["view_cursor"]) == view_cursor
                    and self._latest_cursor(connection, account_scope, source_scope)
                    == source_cursor
                ):
                    observation = self._load_bound_source_observation(
                        connection, account_scope, source_scope, source
                    )
                    self._validate_one_managed_view(
                        connection,
                        account_scope,
                        source_scope,
                        source_cursor,
                        matching,
                        observation,
                    )
                    current = (
                        self._latest_cursor(connection, account_scope, view_scope) == view_cursor
                    )
            connection.execute("COMMIT")
            return current
        except (GatewayEventJournalError, TypeError, ValueError, sqlite3.Error):
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            return False
        finally:
            connection.close()

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
        page_fits: Optional[  # noqa: UP045 -- Python 3.9 is supported.
            Callable[[GatewayReadBatch, GatewayConsumerProgress], bool]
        ] = None,
    ) -> tuple[GatewayReadBatch, GatewayConsumerProgress]:
        """Offer a read range and persist its cursor with the same SQLite commit.

        ``offered_cursor`` records the greatest range prepared for return. It
        does not assert that a transport delivered or consumed that range.
        ``consumer_ref`` must be a bounded identifier derived by trusted
        server-side code, not an arbitrary client-selected progress key.
        A ``page_fits`` callback is a trusted, deterministic, monotone size
        predicate over contiguous event prefixes. When supplied, the largest
        fitting prefix is selected before any progress write is committed.
        """
        self._authorize_read(principal, account_scope, strategy_scope)
        self._validate_consumer_ref(consumer_ref)
        self._validate_read_request(cursor, limit)
        if page_fits is not None and not callable(page_fits):
            raise GatewayEventJournalError(
                "CONSUMER_PAGE_FIT_INVALID", "page fit callback must be callable"
            )
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
                create_stream = True
            else:
                create_stream = False
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

            full_batch = self._read_batch_in_transaction(
                connection, account_scope, strategy_scope, cursor, limit
            )
            if page_fits is None:
                batch = full_batch
                next_offered = max(offered, batch.next_cursor)
                progress = GatewayConsumerProgress(current_epoch, next_offered, acknowledged)
            else:
                batch, progress = self._fit_consumer_page(
                    full_batch,
                    stream_epoch=current_epoch,
                    previous_offered=offered,
                    acknowledged=acknowledged,
                    page_fits=page_fits,
                )

            # Do not create either durable key until the exact response shape
            # has passed the caller's bounded serializer for this candidate.
            if create_stream:
                connection.execute(
                    """
                    INSERT INTO gateway_consumer_streams
                        (account_scope, strategy_scope, stream_epoch)
                    VALUES (?, ?, ?)
                    """,
                    (account_scope, strategy_scope, current_epoch),
                )
            if progress_row is None:
                connection.execute(
                    """
                    INSERT INTO gateway_consumer_progress (
                        principal_id, consumer_ref, account_scope, strategy_scope,
                        stream_epoch, offered_cursor, acknowledged_cursor
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        *progress_key,
                        current_epoch,
                        progress.offered_cursor,
                        progress.acknowledged_cursor,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE gateway_consumer_progress
                    SET offered_cursor = ?
                    WHERE principal_id = ? AND consumer_ref = ?
                        AND account_scope = ? AND strategy_scope = ?
                    """,
                    (progress.offered_cursor, *progress_key),
                )
            connection.execute("COMMIT")
            return batch, progress
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _fit_consumer_page(
        self,
        batch: GatewayReadBatch,
        *,
        stream_epoch: str,
        previous_offered: int,
        acknowledged: int,
        page_fits: Callable[[GatewayReadBatch, GatewayConsumerProgress], bool],
    ) -> tuple[GatewayReadBatch, GatewayConsumerProgress]:
        """Choose the largest fitting contiguous prefix without advancing on a stall."""
        if not batch.events and batch.latest_cursor > batch.next_cursor:
            raise GatewayEventJournalError(
                "CURSOR_GAP", "journal page has an unavailable cursor range"
            )

        base_cursor = (
            batch.snapshot.cursor
            if batch.snapshot is not None
            else (batch.requested_cursor if batch.requested_cursor is not None else 0)
        )
        expected_sequence = base_cursor + 1
        for event in batch.events:
            if event.sequence != expected_sequence:
                raise GatewayEventJournalError(
                    "CURSOR_GAP", "journal page has a non-contiguous cursor range"
                )
            expected_sequence += 1

        maximum_prefix = len(batch.events)
        minimum_prefix = 0 if batch.snapshot is not None or not batch.events else 1

        def candidate_for(
            prefix_length: int,
        ) -> tuple[GatewayReadBatch, GatewayConsumerProgress]:
            events = batch.events[:prefix_length]
            next_cursor = events[-1].sequence if events else base_cursor
            candidate = replace(batch, events=events, next_cursor=next_cursor)
            candidate_progress = GatewayConsumerProgress(
                stream_epoch,
                max(previous_offered, candidate.next_cursor),
                acknowledged,
            )
            return candidate, candidate_progress

        def fits_candidate(candidate: GatewayReadBatch, progress: GatewayConsumerProgress) -> bool:
            try:
                fits = page_fits(candidate, progress)
            except Exception:
                raise GatewayEventJournalError(
                    "CONSUMER_PAGE_CHECK_FAILED", "consumer page fit check failed"
                ) from None
            if type(fits) is not bool:
                raise GatewayEventJournalError(
                    "CONSUMER_PAGE_FIT_INVALID", "page fit callback must return bool"
                )
            return fits

        smallest, smallest_progress = candidate_for(minimum_prefix)
        if not fits_candidate(smallest, smallest_progress):
            raise GatewayEventJournalError(
                "CONSUMER_PAGE_TOO_LARGE", "no contiguous consumer page fits the response limit"
            )

        if minimum_prefix == maximum_prefix:
            return smallest, smallest_progress

        largest, largest_progress = candidate_for(maximum_prefix)
        if fits_candidate(largest, largest_progress):
            return largest, largest_progress

        # The callback is a monotone response-size predicate. Keep a known-fit
        # lower bound and a known-too-large upper bound, so work is logarithmic
        # in the journal's maximum page length rather than serializing every
        # progressively smaller candidate.
        low = minimum_prefix
        high = maximum_prefix - 1
        while low < high:
            middle = (low + high + 1) // 2
            middle_batch, middle_progress = candidate_for(middle)
            if fits_candidate(middle_batch, middle_progress):
                low = middle
            else:
                high = middle - 1

        selected, selected_progress = candidate_for(low)
        # Leave adapter-side one-candidate caches aligned with the exact page
        # that will be returned. The adapter must freeze non-page state (for
        # example, a freshness sample) for the duration of this callback.
        if not fits_candidate(selected, selected_progress):
            raise GatewayEventJournalError(
                "CONSUMER_PAGE_TOO_LARGE",
                "no contiguous consumer page fits the response limit",
            )
        return selected, selected_progress

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
        self._validate_managed_view_for_read(connection, account_scope, strategy_scope)
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

    def _validated_view_policies(
        self, policies: tuple[GatewayAccountViewPolicy, ...]
    ) -> tuple[GatewayAccountViewPolicy, ...]:
        try:
            return validate_policy_set(policies)
        except AccountViewProjectionError:
            raise GatewayEventJournalError(
                "VIEW_POLICY_INVALID", "account view policy set is invalid"
            ) from None

    def _policy_set_json(self, policies: tuple[GatewayAccountViewPolicy, ...]) -> str:
        result = _canonical_json([policy.to_dict() for policy in policies])
        if len(result.encode("utf-8")) > self.MAX_ACCOUNT_VIEW_POLICY_SET_BYTES:
            raise GatewayEventJournalError(
                "VIEW_POLICY_SET_TOO_LARGE", "account view policy set exceeds its storage bound"
            )
        return result

    def _parse_view_source_payload(
        self, snapshot: GatewayAccountSnapshot
    ) -> tuple[AccountObservation, str]:
        payload = snapshot.payload
        if (
            not isinstance(payload, Mapping)
            or set(payload) != {"schema_id", "schema_version", "session_generation", "observation"}
            or payload.get("schema_id") != "sdk.account.state"
            or type(payload.get("schema_version")) is not int
            or payload.get("schema_version") not in {1, 2}
            or type(payload.get("session_generation")) is not str
            or re.fullmatch(r"[0-9a-f]{32}", payload["session_generation"]) is None
        ):
            raise GatewayEventJournalError(
                "VIEW_SOURCE_SCHEMA_INVALID", "managed view source state is invalid"
            )
        try:
            observation = AccountObservation.from_dict(payload["observation"])
        except (KeyError, TypeError, ValueError):
            raise GatewayEventJournalError(
                "VIEW_SOURCE_SCHEMA_INVALID", "managed view source state is invalid"
            ) from None
        expected_version = 2 if observation.open_orders is not None else 1
        if payload["schema_version"] != expected_version:
            raise GatewayEventJournalError(
                "VIEW_SOURCE_SCHEMA_INVALID", "managed view source state is invalid"
            )
        account_key_digest = _digest(_canonical_json(observation.account_key.to_dict()))
        return observation, account_key_digest

    def _state_view_source_binding(
        self, connection: sqlite3.Connection, account_scope: str, source_scope: str
    ) -> Optional[sqlite3.Row]:  # noqa: UP045 -- Python 3.9 support.
        row = connection.execute(
            """
            SELECT policy_set_json, policy_set_digest, account_key_digest, source_cursor
            FROM gateway_state_view_sources
            WHERE account_scope = ? AND source_scope = ?
            """,
            (account_scope, source_scope),
        ).fetchone()
        if row is None:
            return None
        try:
            policy_json = str(row["policy_set_json"])
            if len(policy_json.encode("utf-8")) > self.MAX_ACCOUNT_VIEW_POLICY_SET_BYTES:
                raise ValueError
            parsed = json.loads(policy_json)
            if (
                not isinstance(parsed, list)
                or _canonical_json(parsed) != policy_json
                or str(row["policy_set_digest"]) != _digest(policy_json)
                or re.fullmatch(r"[0-9a-f]{64}", str(row["account_key_digest"])) is None
                or type(row["source_cursor"]) is not int
                or not 1 <= int(row["source_cursor"]) <= self.MAX_SQLITE_INTEGER
            ):
                raise ValueError
            self._policy_set_from_binding(row)
        except (KeyError, TypeError, ValueError, UnicodeEncodeError):
            raise GatewayEventJournalError(
                "VIEW_BINDING_CORRUPT", "managed account view binding is corrupt"
            ) from None
        return row

    def _policy_set_from_binding(
        self, binding: sqlite3.Row
    ) -> tuple[GatewayAccountViewPolicy, ...]:
        try:
            raw_policies = json.loads(str(binding["policy_set_json"]))
            if (
                type(raw_policies) is not list
                or not 1 <= len(raw_policies) <= self.MAX_ACCOUNT_VIEW_SOURCE_BINDINGS
            ):
                raise ValueError
            policies = []
            for raw in raw_policies:
                if (
                    not isinstance(raw, Mapping)
                    or set(raw)
                    != {
                        "schema_id",
                        "schema_version",
                        "view_scope",
                        "resources",
                        "fact_kinds",
                        "include_valuation",
                    }
                    or raw.get("schema_id") != "gateway.account.view_policy"
                    or type(raw.get("schema_version")) is not int
                    or raw.get("schema_version") != 1
                    or type(raw.get("resources")) is not list
                    or type(raw.get("fact_kinds")) is not list
                    or type(raw.get("include_valuation")) is not bool
                ):
                    raise ValueError
                policy = GatewayAccountViewPolicy(
                    raw["view_scope"],
                    tuple(AccountResourceKey.from_dict(item) for item in raw["resources"]),
                    frozenset(raw["fact_kinds"]),
                    raw["include_valuation"],
                )
                if policy.to_dict() != raw:
                    raise ValueError
                policies.append(policy)
            normalized = validate_policy_set(tuple(policies))
            if self._policy_set_json(normalized) != str(binding["policy_set_json"]):
                raise ValueError
            return normalized
        except (AccountViewProjectionError, KeyError, TypeError, ValueError):
            raise GatewayEventJournalError(
                "VIEW_BINDING_CORRUPT", "managed account view policy binding is corrupt"
            ) from None

    def _validate_source_view_binding(
        self,
        binding: sqlite3.Row,
        policies: tuple[GatewayAccountViewPolicy, ...],
        policy_set_json: str,
        policy_set_digest: str,
        account_key_digest: Optional[str],  # noqa: UP045 -- Python 3.9 support.
    ) -> None:
        if (
            str(binding["policy_set_json"]) != policy_set_json
            or str(binding["policy_set_digest"]) != policy_set_digest
            or not policies
        ):
            raise GatewayEventJournalError(
                "VIEW_POLICY_MISMATCH", "configured view policies do not match the source"
            )
        if (
            account_key_digest is not None
            and str(binding["account_key_digest"]) != account_key_digest
        ):
            raise GatewayEventJournalError(
                "VIEW_ACCOUNT_MISMATCH", "managed view source account identity changed"
            )

    def _validate_view_targets(
        self,
        connection: sqlite3.Connection,
        account_scope: str,
        source_scope: str,
        policies: tuple[GatewayAccountViewPolicy, ...],
    ) -> None:
        current_view_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM gateway_account_views WHERE account_scope = ?",
                (account_scope,),
            ).fetchone()[0]
        )
        if current_view_count + len(policies) > self.MAX_ACCOUNT_VIEW_SOURCE_BINDINGS:
            raise GatewayEventJournalError(
                "VIEW_CAPACITY", "account has reached its managed view limit"
            )
        for policy in policies:
            view_scope = policy.view_scope
            if view_scope == source_scope:
                raise GatewayEventJournalError(
                    "VIEW_SCOPE_CONFLICT", "view scope cannot reuse its source scope"
                )
            source_for_view = connection.execute(
                """
                SELECT 1 FROM gateway_state_view_sources
                WHERE account_scope = ? AND source_scope = ?
                """,
                (account_scope, view_scope),
            ).fetchone()
            if source_for_view is not None:
                raise GatewayEventJournalError(
                    "VIEW_SCOPE_CONFLICT", "view scope is already used as a source"
                )
            existing_view = connection.execute(
                """
                SELECT source_scope FROM gateway_account_views
                WHERE account_scope = ? AND view_scope = ?
                """,
                (account_scope, view_scope),
            ).fetchone()
            if existing_view is not None:
                raise GatewayEventJournalError(
                    "VIEW_SCOPE_CONFLICT", "view scope is already managed by another source"
                )
            if self._has_stream_artifacts(connection, account_scope, view_scope):
                raise GatewayEventJournalError(
                    "VIEW_SCOPE_CONFLICT", "view scope already contains journal data"
                )

    def _validate_existing_managed_views(
        self,
        connection: sqlite3.Connection,
        account_scope: str,
        source_scope: str,
        policies: tuple[GatewayAccountViewPolicy, ...],
        source_cursor: int,
    ) -> None:
        source_latest = self._latest_cursor(connection, account_scope, source_scope)
        if source_latest != source_cursor:
            raise GatewayEventJournalError(
                "VIEW_BINDING_CORRUPT", "managed account view source cursor is inconsistent"
            )
        observation = self._load_bound_source_observation(
            connection,
            account_scope,
            source_scope,
            self._state_view_source_binding(connection, account_scope, source_scope),
        )
        rows = connection.execute(
            """
            SELECT * FROM gateway_account_views
            WHERE account_scope = ? AND source_scope = ?
            ORDER BY view_scope
            """,
            (account_scope, source_scope),
        ).fetchall()
        if len(rows) != len(policies):
            raise GatewayEventJournalError(
                "VIEW_BINDING_CORRUPT", "managed account view set is incomplete"
            )
        rows_by_scope = {str(row["view_scope"]): row for row in rows}
        for policy in policies:
            row = rows_by_scope.get(policy.view_scope)
            if row is None or str(row["policy_digest"]) != policy.digest:
                raise GatewayEventJournalError(
                    "VIEW_BINDING_CORRUPT", "managed account view policy is inconsistent"
                )
            self._validate_one_managed_view(
                connection,
                account_scope,
                source_scope,
                source_cursor,
                policy,
                observation,
            )

    def _validate_managed_view_for_read(
        self, connection: sqlite3.Connection, account_scope: str, view_scope: str
    ) -> None:
        managed = connection.execute(
            """
            SELECT source_scope FROM gateway_account_views
            WHERE account_scope = ? AND view_scope = ?
            """,
            (account_scope, view_scope),
        ).fetchone()
        source_rows = connection.execute(
            """
            SELECT source_scope FROM gateway_state_view_sources
            WHERE account_scope = ? ORDER BY source_scope
            LIMIT ?
            """,
            (account_scope, self.MAX_ACCOUNT_VIEW_SOURCE_BINDINGS + 1),
        ).fetchall()
        if len(source_rows) > self.MAX_ACCOUNT_VIEW_SOURCE_BINDINGS:
            raise GatewayEventJournalError(
                "VIEW_BINDING_CORRUPT", "account has too many managed view source bindings"
            )
        bound_source = None
        bound_binding = None
        bound_policies = None
        policy_count = 0
        for source_row in source_rows:
            source_scope = str(source_row["source_scope"])
            binding = self._state_view_source_binding(connection, account_scope, source_scope)
            if binding is None:
                raise GatewayEventJournalError(
                    "VIEW_BINDING_CORRUPT", "managed account view source binding is missing"
                )
            policies = self._policy_set_from_binding(binding)
            policy_count += len(policies)
            if policy_count > self.MAX_ACCOUNT_VIEW_SOURCE_BINDINGS:
                raise GatewayEventJournalError(
                    "VIEW_BINDING_CORRUPT", "account has too many managed account views"
                )
            if any(policy.view_scope == view_scope for policy in policies):
                if bound_source is not None:
                    raise GatewayEventJournalError(
                        "VIEW_BINDING_CORRUPT", "view scope is bound to multiple sources"
                    )
                bound_source = source_scope
                bound_binding = binding
                bound_policies = policies
        if managed is None:
            if bound_source is not None:
                raise GatewayEventJournalError(
                    "VIEW_BINDING_CORRUPT", "managed account view metadata is missing"
                )
            if self._has_managed_view_stream_marker(connection, account_scope, view_scope):
                raise GatewayEventJournalError(
                    "VIEW_BINDING_CORRUPT", "managed account view binding metadata is missing"
                )
            return
        if bound_source is None or bound_source != str(managed["source_scope"]):
            raise GatewayEventJournalError(
                "VIEW_BINDING_CORRUPT", "managed account view metadata is inconsistent"
            )
        assert bound_binding is not None and bound_policies is not None
        self._validate_existing_managed_views(
            connection,
            account_scope,
            bound_source,
            bound_policies,
            int(bound_binding["source_cursor"]),
        )

    def _has_managed_view_stream_marker(
        self, connection: sqlite3.Connection, account_scope: str, view_scope: str
    ) -> bool:
        mode = connection.execute(
            """
            SELECT mode FROM gateway_event_stream_modes
            WHERE account_scope = ? AND strategy_scope = ?
            """,
            (account_scope, view_scope),
        ).fetchone()
        if mode is None or str(mode["mode"]) != "state":
            return False
        snapshot = connection.execute(
            """
            SELECT snapshot_id, length(CAST(payload_json AS BLOB)) AS payload_bytes
            FROM gateway_event_snapshots
            WHERE account_scope = ? AND strategy_scope = ?
            """,
            (account_scope, view_scope),
        ).fetchone()
        if snapshot is None:
            return False
        # Managed views always have one state-mode baseline. Its generated id
        # remains a finite marker even when the payload itself was truncated.
        if str(snapshot["snapshot_id"]).startswith("account-view:"):
            return True
        if int(snapshot["payload_bytes"]) <= self.MAX_STATE_SNAPSHOT_BYTES:
            payload_row = connection.execute(
                """
                SELECT payload_json FROM gateway_event_snapshots
                WHERE account_scope = ? AND strategy_scope = ?
                """,
                (account_scope, view_scope),
            ).fetchone()
            raw_snapshot = str(payload_row["payload_json"])
            try:
                value = json.loads(raw_snapshot)
            except (TypeError, ValueError):
                value = None
            if isinstance(value, Mapping) and value.get("schema_id") == "sdk.account.view":
                return True

        # Inspect at most the first retained event (the journal primary key
        # orders this lookup). Every managed-view delta carries a reserved
        # kind/schema marker, so detection stays bounded even on long streams.
        event = connection.execute(
            """
            SELECT kind, sequence, length(CAST(payload_json AS BLOB)) AS payload_bytes
            FROM gateway_events
            WHERE account_scope = ? AND strategy_scope = ?
            ORDER BY sequence LIMIT 1
            """,
            (account_scope, view_scope),
        ).fetchone()
        if event is None:
            return False
        if str(event["kind"]) == "account.view_delta":
            return True
        if int(event["payload_bytes"]) > self.MAX_ACCOUNT_VIEW_EVENT_BYTES:
            return False
        event_payload = connection.execute(
            """
            SELECT payload_json FROM gateway_events
            WHERE account_scope = ? AND strategy_scope = ? AND sequence = ?
            """,
            (account_scope, view_scope, int(event["sequence"])),
        ).fetchone()
        raw_event = str(event_payload["payload_json"])
        try:
            value = json.loads(raw_event)
        except (TypeError, ValueError):
            return False
        return isinstance(value, Mapping) and value.get("schema_id") == "sdk.account.view.delta"

    def _load_bound_source_observation(
        self,
        connection: sqlite3.Connection,
        account_scope: str,
        source_scope: str,
        binding: Optional[sqlite3.Row],  # noqa: UP045 -- Python 3.9 support.
    ) -> AccountObservation:
        if binding is None:
            raise GatewayEventJournalError(
                "VIEW_BINDING_CORRUPT", "managed account view source binding is missing"
            )
        row = connection.execute(
            """
            SELECT * FROM gateway_event_snapshots
            WHERE account_scope = ? AND strategy_scope = ?
            """,
            (account_scope, source_scope),
        ).fetchone()
        if row is None:
            raise GatewayEventJournalError(
                "VIEW_BINDING_CORRUPT", "managed account view source snapshot is missing"
            )
        try:
            raw_snapshot_json = str(row["payload_json"])
            if len(raw_snapshot_json.encode("utf-8")) > self.MAX_STATE_SNAPSHOT_BYTES:
                raise ValueError
            snapshot = self._snapshot_from_row(row)
            if snapshot.cursor != int(binding["source_cursor"]) or str(
                row["fingerprint"]
            ) != _snapshot_fingerprint(snapshot):
                raise ValueError
            observation, account_key_digest = self._parse_view_source_payload(snapshot)
            if account_key_digest != str(binding["account_key_digest"]):
                raise ValueError
            return observation
        except (KeyError, TypeError, ValueError, UnicodeEncodeError, GatewayEventJournalError):
            raise GatewayEventJournalError(
                "VIEW_BINDING_CORRUPT", "managed account view source snapshot is corrupt"
            ) from None

    def _validate_one_managed_view(
        self,
        connection: sqlite3.Connection,
        account_scope: str,
        source_scope: str,
        source_cursor: int,
        policy: GatewayAccountViewPolicy,
        source_observation: AccountObservation,
    ) -> None:
        row = connection.execute(
            """
            SELECT * FROM gateway_account_views
            WHERE account_scope = ? AND source_scope = ? AND view_scope = ?
            """,
            (account_scope, source_scope, policy.view_scope),
        ).fetchone()
        if row is None or str(row["policy_digest"]) != policy.digest:
            raise GatewayEventJournalError(
                "VIEW_BINDING_CORRUPT", "managed account view policy is inconsistent"
            )
        try:
            row_source_cursor = int(row["source_cursor"])
            view_cursor = int(row["view_cursor"])
            if (
                row_source_cursor != source_cursor
                or not 1 <= view_cursor <= self.MAX_SQLITE_INTEGER
                or self._latest_cursor(connection, account_scope, policy.view_scope) != view_cursor
            ):
                raise ValueError
            raw_projection = str(row["projected_state_json"])
            if len(raw_projection.encode("utf-8")) > self.MAX_STATE_SNAPSHOT_BYTES:
                raise ValueError
            projection = json.loads(raw_projection)
            if _canonical_json(projection) != raw_projection:
                raise ValueError
            self._validate_stored_projection(projection, policy)
            fresh_projection = self._project_account_view(source_observation, policy)
            if _canonical_json(fresh_projection) != raw_projection:
                raise ValueError
            mode = connection.execute(
                """
                SELECT mode FROM gateway_event_stream_modes
                WHERE account_scope = ? AND strategy_scope = ?
                """,
                (account_scope, policy.view_scope),
            ).fetchone()
            snapshot_row = connection.execute(
                """
                SELECT * FROM gateway_event_snapshots
                WHERE account_scope = ? AND strategy_scope = ?
                """,
                (account_scope, policy.view_scope),
            ).fetchone()
            if mode is None or str(mode["mode"]) != "state" or snapshot_row is None:
                raise ValueError
            snapshot_payload_json = str(snapshot_row["payload_json"])
            if len(snapshot_payload_json.encode("utf-8")) > self.MAX_STATE_SNAPSHOT_BYTES:
                raise ValueError
            snapshot = self._snapshot_from_row(snapshot_row)
            if (
                not 1 <= snapshot.cursor <= view_cursor
                or snapshot.strategy_scope != policy.view_scope
                or str(snapshot_row["fingerprint"]) != _snapshot_fingerprint(snapshot)
            ):
                raise ValueError
            self._validate_stored_projection(snapshot.payload, policy)
            if snapshot.cursor == view_cursor and snapshot.payload_json != raw_projection:
                raise ValueError
            event_rows = connection.execute(
                """
                SELECT * FROM gateway_events
                WHERE account_scope = ? AND strategy_scope = ? ORDER BY sequence
                LIMIT ?
                """,
                (account_scope, policy.view_scope, self.MAX_ACCOUNT_VIEW_EVENTS + 1),
            ).fetchall()
            if len(event_rows) > self.MAX_ACCOUNT_VIEW_EVENTS:
                raise ValueError
            event_bytes = 0
            expected_sequence = snapshot.cursor + 1
            for event_row in event_rows:
                event_bytes += len(str(event_row["payload_json"]).encode("utf-8"))
                if event_bytes > self.MAX_ACCOUNT_VIEW_EVENT_BYTES:
                    raise ValueError
                event = self._event_from_row(event_row)
                if (
                    event.sequence != expected_sequence
                    or event.kind != "account.view_delta"
                    or event_row["fingerprint"] != _event_fingerprint(event)
                    or event.payload.get("schema_id") != "sdk.account.view.delta"
                    or event.payload.get("schema_version") != 1
                    or event.payload.get("view_scope") != policy.view_scope
                ):
                    raise ValueError
                expected_sequence += 1
            if (
                expected_sequence - 1 != view_cursor
                or event_bytes > self.MAX_ACCOUNT_VIEW_EVENT_BYTES
                or not math.isfinite(float(row["view_captured_at"]))
            ):
                raise ValueError
        except (
            AccountViewProjectionError,
            GatewayEventJournalError,
            KeyError,
            TypeError,
            ValueError,
            UnicodeEncodeError,
        ):
            raise GatewayEventJournalError(
                "VIEW_BINDING_CORRUPT", "managed account view state is corrupt"
            ) from None

    def _validate_stored_projection(
        self, projection: Any, policy: GatewayAccountViewPolicy
    ) -> None:
        if not isinstance(projection, Mapping):
            raise ValueError
        expected_fields = {
            "schema_id",
            "schema_version",
            "view_scope",
            "consistency",
            "coverage",
            "fact_kinds",
        }
        expected_fields.update(policy.fact_kinds)
        if policy.include_valuation:
            expected_fields.add("valuation")
        if (
            set(projection) != expected_fields
            or projection.get("schema_id") != "sdk.account.view"
            or type(projection.get("schema_version")) is not int
            or projection.get("schema_version") != 1
            or projection.get("view_scope") != policy.view_scope
            or projection.get("consistency") != "multi_query"
            or _canonical_json(projection.get("coverage"))
            != _canonical_json([resource.to_dict() for resource in policy.resources])
            or _canonical_json(projection.get("fact_kinds"))
            != _canonical_json(sorted(policy.fact_kinds))
        ):
            raise ValueError
        try:
            if view_delta(projection, projection) is not None:
                raise ValueError
        except AccountViewProjectionError:
            raise ValueError from None

    def _create_account_view_baseline(
        self,
        connection: sqlite3.Connection,
        account_scope: str,
        source_scope: str,
        policy: GatewayAccountViewPolicy,
        observation: AccountObservation,
        source_cursor: int,
        captured_at: float,
    ) -> None:
        projection = self._project_account_view(observation, policy)
        payload_json = _canonical_json(projection)
        snapshot = GatewayAccountSnapshot(
            account_scope=account_scope,
            strategy_scope=policy.view_scope,
            snapshot_id="account-view:" + uuid.uuid4().hex,
            cursor=1,
            payload=projection,
            captured_at=captured_at,
        )
        if len(payload_json.encode("utf-8")) > self.MAX_STATE_SNAPSHOT_BYTES:
            raise GatewayEventJournalError(
                "STATE_SNAPSHOT_TOO_LARGE", "account view exceeds the snapshot size limit"
            )
        connection.execute(
            """
            INSERT INTO gateway_event_stream_modes(account_scope, strategy_scope, mode)
            VALUES (?, ?, 'state')
            """,
            (account_scope, policy.view_scope),
        )
        connection.execute(
            """
            INSERT INTO gateway_event_sequences(account_scope, strategy_scope, latest_sequence)
            VALUES (?, ?, 1)
            """,
            (account_scope, policy.view_scope),
        )
        connection.execute(
            """
            INSERT INTO gateway_event_snapshots (
                account_scope, strategy_scope, snapshot_id, cursor,
                payload_json, captured_at, fingerprint
            ) VALUES (?, ?, ?, 1, ?, ?, ?)
            """,
            (
                account_scope,
                policy.view_scope,
                snapshot.snapshot_id,
                payload_json,
                captured_at,
                _snapshot_fingerprint(snapshot),
            ),
        )
        connection.execute(
            """
            INSERT INTO gateway_account_views (
                account_scope, source_scope, view_scope, policy_digest,
                source_cursor, view_cursor, projected_state_json, view_captured_at
            ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                account_scope,
                source_scope,
                policy.view_scope,
                policy.digest,
                source_cursor,
                payload_json,
                captured_at,
            ),
        )

    def _update_account_views(
        self,
        connection: sqlite3.Connection,
        account_scope: str,
        source_scope: str,
        policies: tuple[GatewayAccountViewPolicy, ...],
        observation: AccountObservation,
        source_cursor: int,
        captured_at: float,
    ) -> None:
        for policy in policies:
            row = connection.execute(
                """
                SELECT * FROM gateway_account_views
                WHERE account_scope = ? AND source_scope = ? AND view_scope = ?
                """,
                (account_scope, source_scope, policy.view_scope),
            ).fetchone()
            if row is None:
                raise GatewayEventJournalError(
                    "VIEW_BINDING_CORRUPT", "managed account view state is missing"
                )
            try:
                previous = json.loads(str(row["projected_state_json"]))
                self._validate_stored_projection(previous, policy)
                if int(row["source_cursor"]) != source_cursor - 1 or int(
                    row["view_cursor"]
                ) != self._latest_cursor(connection, account_scope, policy.view_scope):
                    raise ValueError
            except (KeyError, TypeError, ValueError, UnicodeEncodeError):
                raise GatewayEventJournalError(
                    "VIEW_BINDING_CORRUPT", "managed account view state is corrupt"
                ) from None

            current = self._project_account_view(observation, policy)
            delta = self._view_delta(previous, current)
            view_cursor = int(row["view_cursor"])
            if delta is None:
                connection.execute(
                    """
                    UPDATE gateway_account_views SET source_cursor = ?
                    WHERE account_scope = ? AND source_scope = ? AND view_scope = ?
                    """,
                    (source_cursor, account_scope, source_scope, policy.view_scope),
                )
                continue

            next_view_cursor = self._next_sequence(view_cursor)
            self._compact_account_view_if_needed(
                connection,
                account_scope,
                policy.view_scope,
                previous,
                view_cursor,
                float(row["view_captured_at"]),
                len(_canonical_json(delta).encode("utf-8")),
            )
            event = GatewayAccountEvent(
                account_scope=account_scope,
                strategy_scope=policy.view_scope,
                sequence=next_view_cursor,
                event_id="account-view:" + uuid.uuid4().hex,
                kind="account.view_delta",
                payload=delta,
                observed_at=captured_at,
            )
            if len(event.payload_json.encode("utf-8")) > self.MAX_ACCOUNT_VIEW_EVENT_BYTES:
                raise GatewayEventJournalError(
                    "VIEW_EVENT_TOO_LARGE", "account view delta exceeds the replay bound"
                )
            connection.execute(
                """
                INSERT INTO gateway_event_sequences(account_scope, strategy_scope, latest_sequence)
                VALUES (?, ?, ?)
                ON CONFLICT(account_scope, strategy_scope)
                DO UPDATE SET latest_sequence = excluded.latest_sequence
                """,
                (account_scope, policy.view_scope, next_view_cursor),
            )
            fingerprint = _event_fingerprint(event)
            connection.execute(
                """
                INSERT INTO gateway_events (
                    account_scope, strategy_scope, sequence, event_id, kind,
                    payload_json, observed_at, fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    account_scope,
                    policy.view_scope,
                    next_view_cursor,
                    event.event_id,
                    event.kind,
                    event.payload_json,
                    captured_at,
                    fingerprint,
                ),
            )
            connection.execute(
                """
                INSERT INTO gateway_event_dedupe (
                    account_scope, strategy_scope, event_id, sequence, fingerprint, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    account_scope,
                    policy.view_scope,
                    event.event_id,
                    next_view_cursor,
                    fingerprint,
                    captured_at,
                ),
            )
            projection_json = _canonical_json(current)
            if len(projection_json.encode("utf-8")) > self.MAX_STATE_SNAPSHOT_BYTES:
                raise GatewayEventJournalError(
                    "STATE_SNAPSHOT_TOO_LARGE", "account view exceeds the snapshot size limit"
                )
            connection.execute(
                """
                UPDATE gateway_account_views SET
                    source_cursor = ?, view_cursor = ?, projected_state_json = ?,
                    view_captured_at = ?
                WHERE account_scope = ? AND source_scope = ? AND view_scope = ?
                """,
                (
                    source_cursor,
                    next_view_cursor,
                    projection_json,
                    captured_at,
                    account_scope,
                    source_scope,
                    policy.view_scope,
                ),
            )

    def _compact_account_view_if_needed(
        self,
        connection: sqlite3.Connection,
        account_scope: str,
        view_scope: str,
        previous_projection: Mapping[str, Any],
        cursor: int,
        captured_at: float,
        next_event_bytes: int,
    ) -> None:
        row = connection.execute(
            """
            SELECT COUNT(*) AS event_count,
                COALESCE(SUM(length(CAST(payload_json AS BLOB))), 0) AS payload_bytes
            FROM gateway_events
            WHERE account_scope = ? AND strategy_scope = ?
            """,
            (account_scope, view_scope),
        ).fetchone()
        event_count = int(row["event_count"])
        payload_bytes = int(row["payload_bytes"])
        if (
            event_count < self.MAX_ACCOUNT_VIEW_EVENTS
            and payload_bytes + next_event_bytes <= self.MAX_ACCOUNT_VIEW_EVENT_BYTES
        ):
            return
        snapshot = GatewayAccountSnapshot(
            account_scope=account_scope,
            strategy_scope=view_scope,
            snapshot_id="account-view:" + uuid.uuid4().hex,
            cursor=cursor,
            payload=previous_projection,
            captured_at=captured_at,
        )
        snapshot_json = snapshot.payload_json
        if len(snapshot_json.encode("utf-8")) > self.MAX_STATE_SNAPSHOT_BYTES:
            raise GatewayEventJournalError(
                "STATE_SNAPSHOT_TOO_LARGE", "account view exceeds the snapshot size limit"
            )
        connection.execute(
            """
            UPDATE gateway_event_snapshots SET
                snapshot_id = ?, cursor = ?, payload_json = ?, captured_at = ?, fingerprint = ?
            WHERE account_scope = ? AND strategy_scope = ?
            """,
            (
                snapshot.snapshot_id,
                cursor,
                snapshot_json,
                captured_at,
                _snapshot_fingerprint(snapshot),
                account_scope,
                view_scope,
            ),
        )
        connection.execute(
            """
            DELETE FROM gateway_events
            WHERE account_scope = ? AND strategy_scope = ? AND sequence <= ?
            """,
            (account_scope, view_scope, cursor),
        )
        connection.execute(
            """
            DELETE FROM gateway_event_dedupe
            WHERE account_scope = ? AND strategy_scope = ? AND sequence <= ?
            """,
            (account_scope, view_scope, cursor),
        )

    def _project_account_view(
        self, observation: AccountObservation, policy: GatewayAccountViewPolicy
    ) -> Mapping[str, Any]:
        try:
            return project_account_view(observation, policy)
        except AccountViewProjectionError as exc:
            raise GatewayEventJournalError(
                exc.code, "provider state cannot produce the configured account view"
            ) from None

    def _view_delta(
        self, previous: Mapping[str, Any], current: Mapping[str, Any]
    ) -> Optional[Mapping[str, Any]]:  # noqa: UP045 -- Python 3.9 support.
        try:
            return view_delta(previous, current)
        except AccountViewProjectionError as exc:
            raise GatewayEventJournalError(
                exc.code, "managed account view projection is inconsistent"
            ) from None

    def _reject_managed_view_write(
        self, connection: sqlite3.Connection, account_scope: str, strategy_scope: str
    ) -> None:
        row = connection.execute(
            """
            SELECT 1 FROM gateway_account_views
            WHERE account_scope = ? AND view_scope = ?
            """,
            (account_scope, strategy_scope),
        ).fetchone()
        if row is not None:
            raise GatewayEventJournalError(
                "MANAGED_VIEW_WRITE_DENIED", "managed account view is journal-owned"
            )

    def _has_stream_artifacts(
        self, connection: sqlite3.Connection, account_scope: str, strategy_scope: str
    ) -> bool:
        row = connection.execute(
            """
            SELECT
                EXISTS (SELECT 1 FROM gateway_events WHERE account_scope=? AND strategy_scope=?)
                    AS has_events,
                EXISTS (SELECT 1 FROM gateway_event_dedupe WHERE account_scope=? AND strategy_scope=?)
                    AS has_dedupe,
                EXISTS (SELECT 1 FROM gateway_event_snapshots WHERE account_scope=? AND strategy_scope=?)
                    AS has_snapshots,
                EXISTS (SELECT 1 FROM gateway_event_sequences WHERE account_scope=? AND strategy_scope=?)
                    AS has_sequences,
                EXISTS (SELECT 1 FROM gateway_event_stream_modes WHERE account_scope=? AND strategy_scope=?)
                    AS has_mode,
                EXISTS (SELECT 1 FROM gateway_consumer_streams WHERE account_scope=? AND strategy_scope=?)
                    AS has_consumer_stream,
                EXISTS (SELECT 1 FROM gateway_consumer_progress WHERE account_scope=? AND strategy_scope=?)
                    AS has_progress
            """,
            (account_scope, strategy_scope) * 7,
        ).fetchone()
        return any(bool(value) for value in row)

    def _next_sequence(self, latest: int) -> int:
        if type(latest) is not int or not 0 <= latest < self.MAX_SQLITE_INTEGER:
            raise GatewayEventJournalError(
                "SEQUENCE_OVERFLOW", "journal sequence reached its storage limit"
            )
        return latest + 1

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
                ) AS has_sequences,
                EXISTS (
                    SELECT 1 FROM gateway_event_dedupe
                    WHERE account_scope = ? AND strategy_scope = ?
                ) AS has_dedupe
            """,
            (account_scope, strategy_scope) * 4,
        ).fetchone()
        return bool(
            row["has_events"] or row["has_snapshots"] or row["has_sequences"] or row["has_dedupe"]
        )

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
                CREATE TABLE IF NOT EXISTS gateway_state_view_sources (
                    account_scope TEXT NOT NULL,
                    source_scope TEXT NOT NULL,
                    policy_set_json TEXT NOT NULL,
                    policy_set_digest TEXT NOT NULL,
                    account_key_digest TEXT NOT NULL,
                    source_cursor INTEGER NOT NULL CHECK (source_cursor > 0),
                    PRIMARY KEY (account_scope, source_scope)
                );
                CREATE TABLE IF NOT EXISTS gateway_account_views (
                    account_scope TEXT NOT NULL,
                    source_scope TEXT NOT NULL,
                    view_scope TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    source_cursor INTEGER NOT NULL CHECK (source_cursor > 0),
                    view_cursor INTEGER NOT NULL CHECK (view_cursor > 0),
                    projected_state_json TEXT NOT NULL,
                    view_captured_at REAL NOT NULL,
                    PRIMARY KEY (account_scope, source_scope, view_scope),
                    UNIQUE (account_scope, view_scope)
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
