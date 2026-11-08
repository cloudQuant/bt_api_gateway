"""Internal durable direct-command storage, without authentication or provider I/O.

Monotonic times are seconds within the caller's process generation. This journal
is not a writer fence, grant, source proof, or evidence that a command was unsent.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .database_identity import SQLiteFileIdentity
from .router import _validate_redacted


class DirectCommandJournalError(RuntimeError):
    """Finite storage error; no error implies a provider outcome."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class DirectCommandRecord:
    account_scope: str
    strategy_scope: str
    request_key: str
    reservation_id: str
    principal: str
    digest: str
    payload_json: str
    generation: str
    expires_at: float
    status: str
    version: int
    native_identity_json: str | None
    strong_identity_keys: tuple[str, ...]
    release_operation_id: str | None
    release_expected_version: int | None


@dataclass(frozen=True)
class DispatchStart:
    record: DirectCommandRecord
    newly_started: bool


@dataclass(frozen=True)
class RecoveryCursor:
    journal_id: str
    revision: int
    strategy_scope: str
    request_key: str


@dataclass(frozen=True)
class RecoveryPage:
    journal_id: str
    revision: int
    records: tuple[DirectCommandRecord, ...]
    next_cursor: RecoveryCursor | None


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 256:
        raise DirectCommandJournalError("INVALID_INPUT")
    return value


def _json(value: object, *, scalar_map: bool = False) -> str:
    count = 0

    def check(item: Any, depth: int) -> None:
        nonlocal count
        count += 1
        if count > 4096 or depth > 16:
            raise DirectCommandJournalError("INVALID_PAYLOAD")
        if item is None or type(item) in (bool, int, str):
            if isinstance(item, str) and len(item) > 16384:
                raise DirectCommandJournalError("INVALID_PAYLOAD")
            if type(item) is int and not -(2**63) <= item < 2**63:
                raise DirectCommandJournalError("INVALID_PAYLOAD")
            return
        if type(item) is list and not scalar_map:
            for nested in item:
                check(nested, depth + 1)
            return
        if type(item) is dict and (not scalar_map or depth == 0):
            for key, nested in item.items():
                if not isinstance(key, str) or not key or len(key) > 256:
                    raise DirectCommandJournalError("INVALID_PAYLOAD")
                check(nested, depth + 1)
            return
        raise DirectCommandJournalError("INVALID_PAYLOAD")

    check(value, 0)
    if scalar_map and (type(value) is not dict or not value):
        raise DirectCommandJournalError("INVALID_PAYLOAD")
    try:
        _validate_redacted(value)
        result = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (ValueError, TypeError, RecursionError) as exc:
        raise DirectCommandJournalError("INVALID_PAYLOAD") from exc
    if len(result.encode("ascii")) > 65536:
        raise DirectCommandJournalError("INVALID_PAYLOAD")
    return result


def payload_digest(payload: object) -> str:
    return hashlib.sha256(_json(payload).encode("ascii")).hexdigest()


def _strong_keys(value: object) -> tuple[str, ...]:
    if type(value) is not tuple or not 1 <= len(value) <= 16:
        raise DirectCommandJournalError("INVALID_IDENTITY_KEYS")
    try:
        keys = tuple(_text(key) for key in value)
        _validate_redacted({"keys": list(keys)})
    except ValueError as exc:
        raise DirectCommandJournalError("INVALID_IDENTITY_KEYS") from exc
    if len(set(keys)) != len(keys) or keys != tuple(sorted(keys)):
        raise DirectCommandJournalError("INVALID_IDENTITY_KEYS")
    return keys


class GatewayDirectCommandJournal:
    """One account's bounded local journal; generation is supplied by its owner.

    The owner must arrange single-writer fencing and expire old generations before
    readiness. This class does not establish that ownership or authenticate labels.
    """

    def __init__(
        self,
        database_path: str | Path,
        account_scope: str,
        *,
        generation: str,
        expected_journal_id: str,
        minimum_revision: int,
        max_records: int = 100000,
        clock: Callable[[], float] = time.monotonic,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._configure(
            database_path, account_scope, generation, max_records, clock, timeout_seconds
        )
        self._journal_id = _text(expected_journal_id)
        if type(minimum_revision) is not int or minimum_revision < 0:
            raise DirectCommandJournalError("INVALID_REVISION")
        self._minimum_revision = minimum_revision
        try:
            with self._connection() as db, self._transaction_on(db):
                self._verify_schema(db)
                self._assert_anchor(db)
        except sqlite3.DatabaseError as exc:
            raise DirectCommandJournalError("INVALID_DATABASE") from exc

    @classmethod
    def create(
        cls,
        database_path: str | Path,
        account_scope: str,
        *,
        generation: str,
        max_records: int = 100000,
        clock: Callable[[], float] = time.monotonic,
        timeout_seconds: float = 5.0,
    ) -> GatewayDirectCommandJournal:
        """Exclusively create a new journal; the owner must durably save its ID/anchor."""
        self = cls.__new__(cls)
        self._configure(
            database_path, account_scope, generation, max_records, clock, timeout_seconds
        )
        self._journal_id = str(uuid.uuid4())
        self._minimum_revision = 0
        try:
            fd = os.open(os.fspath(database_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise DirectCommandJournalError("DATABASE_EXISTS") from exc
        os.close(fd)
        self._identity.verify()
        with self._connection() as db:
            db.execute("PRAGMA journal_mode = WAL")
            with self._transaction_on(db):
                db.execute(
                    "CREATE TABLE direct_journal_meta (account TEXT PRIMARY KEY, schema_version INTEGER NOT NULL, max_records INTEGER NOT NULL, journal_id TEXT NOT NULL, revision INTEGER NOT NULL)"
                )
                db.execute(
                    "CREATE TABLE direct_journal_commands (account TEXT NOT NULL, strategy TEXT NOT NULL, request_key TEXT NOT NULL, reservation_id TEXT NOT NULL UNIQUE, principal TEXT NOT NULL, digest TEXT NOT NULL, payload_json TEXT NOT NULL, generation TEXT NOT NULL, expires_at REAL NOT NULL, status TEXT NOT NULL, version INTEGER NOT NULL, native_identity_json TEXT, strong_keys_json TEXT, PRIMARY KEY(account, strategy, request_key))"
                )
                db.execute(
                    "CREATE TABLE direct_journal_releases (account TEXT NOT NULL, operation_id TEXT NOT NULL, strategy TEXT NOT NULL, request_key TEXT NOT NULL, reservation_id TEXT NOT NULL, digest TEXT NOT NULL, principal TEXT NOT NULL, expected_version INTEGER NOT NULL, PRIMARY KEY(account, operation_id))"
                )
                db.execute(
                    "CREATE TABLE direct_journal_strong_keys (account TEXT NOT NULL, strong_key TEXT NOT NULL, reservation_id TEXT NOT NULL, PRIMARY KEY(account, strong_key))"
                )
                db.execute(
                    "CREATE UNIQUE INDEX direct_journal_release_command ON direct_journal_releases(account, strategy, request_key)"
                )
                db.execute(
                    "CREATE UNIQUE INDEX direct_journal_native_identity ON direct_journal_commands(account, native_identity_json) WHERE native_identity_json IS NOT NULL"
                )
                db.execute(
                    "INSERT INTO direct_journal_meta VALUES (?, 2, ?, ?, 0)",
                    (self._account, max_records, self._journal_id),
                )
        return self

    def _configure(
        self,
        database_path: str | Path,
        account_scope: str,
        generation: str,
        max_records: int,
        clock: Callable[[], float],
        timeout_seconds: float,
    ) -> None:
        self._account = _text(account_scope)
        self._generation = _text(generation)
        if type(max_records) is not int or not 1 <= max_records <= 1000000:
            raise DirectCommandJournalError("INVALID_CAPACITY")
        if (
            not isinstance(timeout_seconds, (float, int))
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 60
        ):
            raise DirectCommandJournalError("INVALID_INPUT")
        self._max_records = max_records
        self._clock = clock
        self._timeout = timeout_seconds
        self._identity = SQLiteFileIdentity(Path(database_path))

    @property
    def journal_id(self) -> str:
        return self._journal_id

    def _verify_schema(self, db: sqlite3.Connection) -> None:
        objects = {
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type IN ('table','index')")
        }
        expected = {
            "direct_journal_meta",
            "direct_journal_commands",
            "direct_journal_releases",
            "direct_journal_strong_keys",
            "direct_journal_release_command",
            "direct_journal_native_identity",
        }
        if not expected.issubset(objects):
            raise DirectCommandJournalError("INVALID_DATABASE")
        columns = {
            "direct_journal_meta": (
                "account",
                "schema_version",
                "max_records",
                "journal_id",
                "revision",
            ),
            "direct_journal_commands": (
                "account",
                "strategy",
                "request_key",
                "reservation_id",
                "principal",
                "digest",
                "payload_json",
                "generation",
                "expires_at",
                "status",
                "version",
                "native_identity_json",
                "strong_keys_json",
            ),
            "direct_journal_releases": (
                "account",
                "operation_id",
                "strategy",
                "request_key",
                "reservation_id",
                "digest",
                "principal",
                "expected_version",
            ),
            "direct_journal_strong_keys": ("account", "strong_key", "reservation_id"),
        }
        for table, names in columns.items():
            info = db.execute(f"PRAGMA table_info({table})").fetchall()
            actual = tuple(row[1] for row in info)
            if actual != names:
                raise DirectCommandJournalError("INVALID_DATABASE")
            pk = tuple(row[1] for row in sorted(info, key=lambda item: item[5]) if row[5])
            expected_pk = {
                "direct_journal_meta": ("account",),
                "direct_journal_commands": ("account", "strategy", "request_key"),
                "direct_journal_releases": ("account", "operation_id"),
                "direct_journal_strong_keys": ("account", "strong_key"),
            }
            if pk != expected_pk[table]:
                raise DirectCommandJournalError("INVALID_DATABASE")
        for table, index, index_columns in (
            (
                "direct_journal_commands",
                "direct_journal_native_identity",
                ("account", "native_identity_json"),
            ),
            (
                "direct_journal_releases",
                "direct_journal_release_command",
                ("account", "strategy", "request_key"),
            ),
        ):
            if not any(
                row[1] == index and row[2] == 1 for row in db.execute(f"PRAGMA index_list({table})")
            ):
                raise DirectCommandJournalError("INVALID_DATABASE")
            if tuple(row[2] for row in db.execute(f"PRAGMA index_info({index})")) != index_columns:
                raise DirectCommandJournalError("INVALID_DATABASE")

    def _assert_anchor(self, db: sqlite3.Connection) -> int:
        rows = db.execute(
            "SELECT account, schema_version, max_records, journal_id, revision FROM direct_journal_meta"
        ).fetchall()
        if len(rows) != 1:
            raise DirectCommandJournalError("INVALID_DATABASE")
        account, schema, capacity, journal_id, revision = tuple(rows[0])
        if account != self._account:
            raise DirectCommandJournalError("ACCOUNT_MISMATCH")
        if schema != 2 or capacity != self._max_records:
            raise DirectCommandJournalError("SCHEMA_OR_CAPACITY_MISMATCH")
        if journal_id != self._journal_id:
            raise DirectCommandJournalError("JOURNAL_ID_MISMATCH")
        if type(revision) is not int or revision < self._minimum_revision:
            raise DirectCommandJournalError("REVISION_ROLLBACK")
        return revision

    def _bump(self, db: sqlite3.Connection) -> None:
        db.execute(
            "UPDATE direct_journal_meta SET revision=revision+1 WHERE account=?", (self._account,)
        )

    def _now(self) -> float:
        now = self._clock()
        if (
            isinstance(now, bool)
            or not isinstance(now, (int, float))
            or not math.isfinite(now)
            or now < 0
        ):
            raise DirectCommandJournalError("CLOCK_INVALID")
        return float(now)

    def reserve(
        self,
        strategy: str,
        request_key: str,
        principal: str,
        payload: object,
        *,
        ttl_seconds: float = 10.0,
    ) -> DirectCommandRecord:
        strategy, request_key, principal = map(_text, (strategy, request_key, principal))
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(ttl_seconds)
            or not 0 < ttl_seconds <= 30
        ):
            raise DirectCommandJournalError("INVALID_TTL")
        encoded = _json(payload)
        digest = hashlib.sha256(encoded.encode("ascii")).hexdigest()
        with self._transaction() as db:
            row = self._find(db, strategy, request_key)
            if row is not None:
                if (
                    row["principal"] != principal
                    or row["digest"] != digest
                    or row["payload_json"] != encoded
                ):
                    raise DirectCommandJournalError("REQUEST_CONFLICT")
                return self._record(row)
            if (
                db.execute(
                    "SELECT count(*) FROM direct_journal_commands WHERE account=?", (self._account,)
                ).fetchone()[0]
                >= self._max_records
            ):
                raise DirectCommandJournalError("CAPACITY_EXCEEDED")
            now = self._now()
            db.execute(
                "INSERT INTO direct_journal_commands VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', 1, NULL, NULL)",
                (
                    self._account,
                    strategy,
                    request_key,
                    str(uuid.uuid4()),
                    principal,
                    digest,
                    encoded,
                    self._generation,
                    now + ttl_seconds,
                ),
            )
            self._bump(db)
            return self._record(self._require(db, strategy, request_key, principal))

    def get(self, strategy: str, request_key: str, principal: str) -> DirectCommandRecord:
        strategy, request_key, principal = map(_text, (strategy, request_key, principal))
        with self._transaction() as db:
            row = self._require(db, strategy, request_key, principal)
            return self._record(row)

    def recovery_page(self, *, limit: int, cursor: RecoveryCursor | None = None) -> RecoveryPage:
        """Read every account row for trusted owner recovery at one revision.

        A mutation between pages requires a fresh scan. This is not an authorization
        interface. The external owner's anchor may lag later committed writes.
        """
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise DirectCommandJournalError("INVALID_INPUT")
        with self._transaction() as db:
            revision = self._assert_anchor(db)
            if cursor is not None:
                if not isinstance(cursor, RecoveryCursor) or cursor.journal_id != self._journal_id:
                    raise DirectCommandJournalError("INVALID_CURSOR")
                if cursor.revision != revision:
                    raise DirectCommandJournalError("RESTART_REQUIRED")
                strategy, key = _text(cursor.strategy_scope), _text(cursor.request_key)
            else:
                strategy, key = "", ""
            rows = db.execute(
                "SELECT c.*, r.operation_id AS release_operation_id, r.expected_version AS release_expected_version FROM direct_journal_commands c LEFT JOIN direct_journal_releases r ON c.account=r.account AND c.strategy=r.strategy AND c.request_key=r.request_key WHERE c.account=? AND (c.strategy>? OR (c.strategy=? AND c.request_key>?)) ORDER BY c.strategy, c.request_key LIMIT ?",
                (self._account, strategy, strategy, key, limit + 1),
            ).fetchall()
            records = tuple(self._record(row) for row in rows[:limit])
            next_cursor = None
            if len(rows) > limit:
                last = records[-1]
                next_cursor = RecoveryCursor(
                    self._journal_id, revision, last.strategy_scope, last.request_key
                )
            return RecoveryPage(self._journal_id, revision, records, next_cursor)

    def release(
        self,
        strategy: str,
        request_key: str,
        reservation_id: str,
        digest: str,
        principal: str,
        operation_id: str,
        expected_version: int,
    ) -> DirectCommandRecord:
        strategy, request_key, reservation_id, digest, principal, operation_id = map(
            _text, (strategy, request_key, reservation_id, digest, principal, operation_id)
        )
        self._version(expected_version)
        with self._transaction() as db:
            args = (strategy, request_key, reservation_id, digest, principal, expected_version)
            old = db.execute(
                "SELECT strategy, request_key, reservation_id, digest, principal, expected_version FROM direct_journal_releases WHERE account=? AND operation_id=?",
                (self._account, operation_id),
            ).fetchone()
            if old is not None and tuple(old) != args:
                raise DirectCommandJournalError("OPERATION_CONFLICT")
            row = self._bound(db, strategy, request_key, reservation_id, digest, principal)
            if old is not None:
                return self._record(row)
            prior = db.execute(
                "SELECT operation_id FROM direct_journal_releases WHERE account=? AND strategy=? AND request_key=?",
                (self._account, strategy, request_key),
            ).fetchone()
            if prior is not None:
                raise DirectCommandJournalError("OPERATION_CONFLICT")
            if row["status"] == "RESERVED":
                if row["version"] != expected_version:
                    raise DirectCommandJournalError("VERSION_CONFLICT")
                status = (
                    "EXPIRED"
                    if row["generation"] != self._generation or self._now() >= row["expires_at"]
                    else "RELEASED"
                )
                db.execute(
                    "UPDATE direct_journal_commands SET status=?, version=version+1 WHERE account=? AND strategy=? AND request_key=?",
                    (status, self._account, strategy, request_key),
                )
            elif row["status"] != "EXPIRED":
                raise DirectCommandJournalError("STATE_CONFLICT")
            elif expected_version not in (row["version"], row["version"] - 1):
                raise DirectCommandJournalError("VERSION_CONFLICT")
            db.execute(
                "INSERT INTO direct_journal_releases VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (self._account, operation_id, *args),
            )
            self._bump(db)
            return self._record(self._require(db, strategy, request_key, principal))

    def expire(self, strategy: str, request_key: str, principal: str) -> DirectCommandRecord:
        strategy, request_key, principal = map(_text, (strategy, request_key, principal))
        with self._transaction() as db:
            row = self._require(db, strategy, request_key, principal)
            if row["status"] == "RESERVED" and (
                row["generation"] != self._generation or self._now() >= row["expires_at"]
            ):
                db.execute(
                    "UPDATE direct_journal_commands SET status='EXPIRED', version=version+1 WHERE account=? AND strategy=? AND request_key=?",
                    (self._account, strategy, request_key),
                )
                self._bump(db)
                row = self._require(db, strategy, request_key, principal)
            return self._record(row)

    def begin_dispatch(
        self,
        strategy: str,
        request_key: str,
        reservation_id: str,
        digest: str,
        principal: str,
        expected_version: int,
        native_identity: object,
        strong_identity_keys: tuple[str, ...],
    ) -> DispatchStart:
        strategy, request_key, reservation_id, digest, principal = map(
            _text, (strategy, request_key, reservation_id, digest, principal)
        )
        self._version(expected_version)
        identity = _json(native_identity, scalar_map=True)
        keys = _strong_keys(strong_identity_keys)
        keys_json = _json(list(keys))
        with self._transaction() as db:
            row = self._bound(db, strategy, request_key, reservation_id, digest, principal)
            if row["status"] in ("DISPATCHING", "SENT", "NOT_SENT", "UNKNOWN"):
                if row["native_identity_json"] != identity or row["strong_keys_json"] != keys_json:
                    raise DirectCommandJournalError("IDENTITY_CONFLICT")
                prior_version = row["version"] - (1 if row["status"] == "DISPATCHING" else 2)
                if expected_version != prior_version:
                    raise DirectCommandJournalError("VERSION_CONFLICT")
                return DispatchStart(self._record(row), False)
            if row["status"] != "RESERVED":
                raise DirectCommandJournalError("STATE_CONFLICT")
            if row["version"] != expected_version:
                raise DirectCommandJournalError("VERSION_CONFLICT")
            if row["generation"] != self._generation or self._now() >= row["expires_at"]:
                db.execute(
                    "UPDATE direct_journal_commands SET status='EXPIRED', version=version+1 WHERE account=? AND strategy=? AND request_key=?",
                    (self._account, strategy, request_key),
                )
                self._bump(db)
                return DispatchStart(
                    self._record(self._require(db, strategy, request_key, principal)), False
                )
            collision = db.execute(
                "SELECT 1 FROM direct_journal_commands WHERE account=? AND native_identity_json=?",
                (self._account, identity),
            ).fetchone()
            if collision is not None:
                raise DirectCommandJournalError("IDENTITY_CONFLICT")
            for key in keys:
                if (
                    db.execute(
                        "SELECT 1 FROM direct_journal_strong_keys WHERE account=? AND strong_key=?",
                        (self._account, key),
                    ).fetchone()
                    is not None
                ):
                    raise DirectCommandJournalError("IDENTITY_CONFLICT")
            db.execute(
                "UPDATE direct_journal_commands SET status='DISPATCHING', version=version+1, native_identity_json=?, strong_keys_json=? WHERE account=? AND strategy=? AND request_key=?",
                (identity, keys_json, self._account, strategy, request_key),
            )
            for key in keys:
                db.execute(
                    "INSERT INTO direct_journal_strong_keys VALUES (?, ?, ?)",
                    (self._account, key, reservation_id),
                )
            self._bump(db)
            return DispatchStart(
                self._record(self._require(db, strategy, request_key, principal)), True
            )

    def finish(
        self,
        strategy: str,
        request_key: str,
        reservation_id: str,
        digest: str,
        principal: str,
        expected_version: int,
        native_identity: object,
        strong_identity_keys: tuple[str, ...],
        result: str,
    ) -> DirectCommandRecord:
        strategy, request_key, reservation_id, digest, principal = map(
            _text, (strategy, request_key, reservation_id, digest, principal)
        )
        self._version(expected_version)
        if result not in ("SENT", "NOT_SENT", "UNKNOWN"):
            raise DirectCommandJournalError("INVALID_INPUT")
        identity = _json(native_identity, scalar_map=True)
        keys_json = _json(list(_strong_keys(strong_identity_keys)))
        with self._transaction() as db:
            row = self._bound(db, strategy, request_key, reservation_id, digest, principal)
            if row["native_identity_json"] != identity or row["strong_keys_json"] != keys_json:
                raise DirectCommandJournalError("IDENTITY_CONFLICT")
            if row["status"] == result and row["version"] == expected_version + 1:
                return self._record(row)
            if row["status"] != "DISPATCHING":
                raise DirectCommandJournalError("STATE_CONFLICT")
            if row["version"] != expected_version:
                raise DirectCommandJournalError("VERSION_CONFLICT")
            db.execute(
                "UPDATE direct_journal_commands SET status=?, version=version+1 WHERE account=? AND strategy=? AND request_key=?",
                (result, self._account, strategy, request_key),
            )
            self._bump(db)
            return self._record(self._require(db, strategy, request_key, principal))

    @staticmethod
    def _version(value: int) -> None:
        if type(value) is not int or value < 1:
            raise DirectCommandJournalError("INVALID_INPUT")

    def _find(self, db: sqlite3.Connection, strategy: str, request_key: str) -> sqlite3.Row | None:
        return db.execute(
            "SELECT c.*, r.operation_id AS release_operation_id, r.expected_version AS release_expected_version FROM direct_journal_commands c LEFT JOIN direct_journal_releases r ON c.account=r.account AND c.strategy=r.strategy AND c.request_key=r.request_key WHERE c.account=? AND c.strategy=? AND c.request_key=?",
            (self._account, strategy, request_key),
        ).fetchone()

    def _require(
        self, db: sqlite3.Connection, strategy: str, request_key: str, principal: str
    ) -> sqlite3.Row:
        row = self._find(db, strategy, request_key)
        if row is None:
            raise DirectCommandJournalError("NOT_FOUND")
        if row["principal"] != principal:
            raise DirectCommandJournalError("REQUEST_CONFLICT")
        return row

    def _bound(
        self,
        db: sqlite3.Connection,
        strategy: str,
        request_key: str,
        reservation_id: str,
        digest: str,
        principal: str,
    ) -> sqlite3.Row:
        row = self._require(db, strategy, request_key, principal)
        if row["reservation_id"] != reservation_id or row["digest"] != digest:
            raise DirectCommandJournalError("REQUEST_CONFLICT")
        return row

    @staticmethod
    def _record(row: sqlite3.Row) -> DirectCommandRecord:
        return DirectCommandRecord(
            row["account"],
            row["strategy"],
            row["request_key"],
            row["reservation_id"],
            row["principal"],
            row["digest"],
            row["payload_json"],
            row["generation"],
            row["expires_at"],
            row["status"],
            row["version"],
            row["native_identity_json"],
            tuple(json.loads(row["strong_keys_json"])) if row["strong_keys_json"] else (),
            row["release_operation_id"],
            row["release_expected_version"],
        )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self._identity.verify()
        try:
            db = sqlite3.connect(
                self._identity.path.as_uri() + "?mode=rw",
                uri=True,
                timeout=self._timeout,
                isolation_level=None,
            )
        except sqlite3.OperationalError as exc:
            raise DirectCommandJournalError("DATABASE_UNAVAILABLE") from exc
        try:
            db.row_factory = sqlite3.Row
            self._identity.verify()
            db.execute("PRAGMA synchronous = FULL")
            self._identity.verify()
            yield db
        finally:
            db.close()

    @staticmethod
    def _commit(db: sqlite3.Connection) -> None:
        db.execute("COMMIT")

    @contextmanager
    def _transaction_on(self, db: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
        db.execute("BEGIN IMMEDIATE")
        try:
            yield db
            self._identity.verify()
            self._commit(db)
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as db, self._transaction_on(db):
            self._assert_anchor(db)
            yield db
