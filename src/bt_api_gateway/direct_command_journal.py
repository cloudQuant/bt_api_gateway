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
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import ContextManager

from bt_api_base.direct_write_protocol import SettlementObservation, SettlementStatus
from bt_api_base.gateway_direct_protocol import canonical_gateway_payload

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
class DirectCommandObservation:
    """Read-only TTL observation, not evidence that a command was not sent."""

    record: DirectCommandRecord
    generation_current: bool
    remaining_ttl_seconds: float | None


@dataclass(frozen=True)
class DispatchStart:
    record: DirectCommandRecord
    newly_started: bool


@dataclass(frozen=True)
class SettlementRecord:
    account_scope: str
    exchange_name: str
    trading_day: str
    account_binding: str
    owner_generation: str
    initial_session_generation: int
    initial_observation_id: str
    marker_id: str | None
    status: str
    version: int
    confirmation_observation_id: str | None


@dataclass(frozen=True)
class SettlementStart:
    record: SettlementRecord
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
    try:
        if scalar_map and (
            type(value) is not dict
            or not value
            or any(
                item is not None and type(item) not in (bool, int, str) for item in value.values()
            )
        ):
            raise ValueError("invalid scalar map")
        result = canonical_gateway_payload(value)
        _validate_redacted(value)
    except (ValueError, TypeError, RecursionError) as exc:
        raise DirectCommandJournalError("INVALID_PAYLOAD") from exc
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
        execution_max_facts: int = 100000,
        clock: Callable[[], float] = time.monotonic,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._configure(
            database_path,
            account_scope,
            generation,
            max_records,
            execution_max_facts,
            clock,
            timeout_seconds,
        )
        self._journal_id = _text(expected_journal_id)
        if type(minimum_revision) is not int or minimum_revision < 0:
            raise DirectCommandJournalError("INVALID_REVISION")
        self._minimum_revision = minimum_revision
        try:
            with self._connection() as db, self._transaction_on(db):
                self._verify_schema(db)
                self._assert_anchor(db)
                self._verify_v2_upgrade_integrity(db, schema_version=7)
                self._verify_v4_identity_integrity(db)
                from .direct_execution_journal import _verify_execution_integrity

                _verify_execution_integrity(db, self._account, self._execution_max_facts)
                from .direct_execution_journal import _verify_consumer_integrity

                _verify_consumer_integrity(db, self._account)
                from .direct_cancel_journal import _verify_cancel_integrity

                _verify_cancel_integrity(db, self._account, self._max_records)
                from .direct_execution_journal import _verify_cancel_error_integrity

                _verify_cancel_error_integrity(db, self._account, self._execution_max_facts)
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
        execution_max_facts: int = 100000,
        clock: Callable[[], float] = time.monotonic,
        timeout_seconds: float = 5.0,
    ) -> GatewayDirectCommandJournal:
        """Exclusively create a new journal; the owner must durably save its ID/anchor."""
        self = cls.__new__(cls)
        self._configure(
            database_path,
            account_scope,
            generation,
            max_records,
            execution_max_facts,
            clock,
            timeout_seconds,
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
                cls._create_settlement_table(db)
                from .direct_execution_journal import _create_execution_tables

                _create_execution_tables(db, self._account, self._execution_max_facts)
                from .direct_execution_journal import _create_consumer_table

                _create_consumer_table(db)
                from .direct_cancel_journal import _create_cancel_tables

                _create_cancel_tables(db)
                from .direct_execution_journal import _create_cancel_error_table

                _create_cancel_error_table(db)
                db.execute(
                    "INSERT INTO direct_journal_meta VALUES (?, 7, ?, ?, 0)",
                    (self._account, max_records, self._journal_id),
                )
        return self

    def _configure(
        self,
        database_path: str | Path,
        account_scope: str,
        generation: str,
        max_records: int,
        execution_max_facts: int,
        clock: Callable[[], float],
        timeout_seconds: float,
    ) -> None:
        self._account = _text(account_scope)
        self._generation = _text(generation)
        if type(max_records) is not int or not 1 <= max_records <= 1000000:
            raise DirectCommandJournalError("INVALID_CAPACITY")
        if type(execution_max_facts) is not int or not 1 <= execution_max_facts <= 1000000:
            raise DirectCommandJournalError("INVALID_CAPACITY")
        if (
            not isinstance(timeout_seconds, (float, int))
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 60
        ):
            raise DirectCommandJournalError("INVALID_INPUT")
        self._max_records = max_records
        self._schema_version = 7
        self._execution_max_facts = execution_max_facts
        self._clock = clock
        self._timeout = timeout_seconds
        self._identity = SQLiteFileIdentity(Path(database_path))

    @property
    def journal_id(self) -> str:
        return self._journal_id

    @property
    def account_scope(self) -> str:
        return self._account

    @property
    def generation(self) -> str:
        return self._generation

    @staticmethod
    def _create_settlement_table(db: sqlite3.Connection) -> None:
        db.execute(
            "CREATE TABLE direct_journal_settlement (account TEXT NOT NULL, exchange_name TEXT NOT NULL, trading_day TEXT NOT NULL, account_binding TEXT NOT NULL, owner_generation TEXT NOT NULL, initial_session_generation INTEGER NOT NULL, initial_observation_id TEXT NOT NULL, marker_id TEXT, status TEXT NOT NULL, version INTEGER NOT NULL, confirmation_observation_id TEXT, PRIMARY KEY(account, exchange_name, trading_day))"
        )

    @classmethod
    def upgrade_v2(
        cls,
        database_path: str | Path,
        account_scope: str,
        *,
        generation: str,
        guard: object,
        expected_journal_id: str,
        minimum_revision: int,
        max_records: int = 100000,
        execution_max_facts: int = 100000,
        clock: Callable[[], float] = time.monotonic,
        timeout_seconds: float = 5.0,
    ) -> GatewayDirectCommandJournal:
        """Explicitly upgrade an anchored v2 journal to v7 under the account guard."""
        return cls._upgrade_legacy(
            database_path,
            account_scope,
            generation=generation,
            guard=guard,
            expected_journal_id=expected_journal_id,
            minimum_revision=minimum_revision,
            max_records=max_records,
            execution_max_facts=execution_max_facts,
            clock=clock,
            timeout_seconds=timeout_seconds,
            old_version=2,
        )

    @classmethod
    def upgrade_v3(
        cls,
        database_path: str | Path,
        account_scope: str,
        *,
        generation: str,
        guard: object,
        expected_journal_id: str,
        minimum_revision: int,
        max_records: int = 100000,
        execution_max_facts: int = 100000,
        clock: Callable[[], float] = time.monotonic,
        timeout_seconds: float = 5.0,
    ) -> GatewayDirectCommandJournal:
        """Explicitly upgrade an anchored v3 journal to v7 under the account guard."""
        return cls._upgrade_legacy(
            database_path,
            account_scope,
            generation=generation,
            guard=guard,
            expected_journal_id=expected_journal_id,
            minimum_revision=minimum_revision,
            max_records=max_records,
            execution_max_facts=execution_max_facts,
            clock=clock,
            timeout_seconds=timeout_seconds,
            old_version=3,
        )

    @classmethod
    def upgrade_v4(
        cls,
        database_path,
        account_scope,
        *,
        generation,
        guard,
        expected_journal_id,
        minimum_revision,
        max_records=100000,
        execution_max_facts=100000,
        clock=time.monotonic,
        timeout_seconds=5.0,
    ) -> GatewayDirectCommandJournal:
        """Explicitly upgrade an anchored v4 journal under the account guard."""
        return cls._upgrade_legacy(
            database_path,
            account_scope,
            generation=generation,
            guard=guard,
            expected_journal_id=expected_journal_id,
            minimum_revision=minimum_revision,
            max_records=max_records,
            execution_max_facts=execution_max_facts,
            clock=clock,
            timeout_seconds=timeout_seconds,
            old_version=4,
        )

    @classmethod
    def upgrade_v5(
        cls,
        database_path,
        account_scope,
        *,
        generation,
        guard,
        expected_journal_id,
        minimum_revision,
        max_records=100000,
        execution_max_facts=100000,
        clock=time.monotonic,
        timeout_seconds=5.0,
    ) -> GatewayDirectCommandJournal:
        """Upgrade an anchored v5 journal under the same account guard."""
        return cls._upgrade_legacy(
            database_path,
            account_scope,
            generation=generation,
            guard=guard,
            expected_journal_id=expected_journal_id,
            minimum_revision=minimum_revision,
            max_records=max_records,
            execution_max_facts=execution_max_facts,
            clock=clock,
            timeout_seconds=timeout_seconds,
            old_version=5,
        )

    @classmethod
    def upgrade_v6(
        cls,
        database_path,
        account_scope,
        *,
        generation,
        guard,
        expected_journal_id,
        minimum_revision,
        max_records=100000,
        execution_max_facts=100000,
        clock=time.monotonic,
        timeout_seconds=5.0,
    ) -> GatewayDirectCommandJournal:
        """Explicitly upgrade a verified v6 database under the account guard."""
        return cls._upgrade_legacy(
            database_path,
            account_scope,
            generation=generation,
            guard=guard,
            expected_journal_id=expected_journal_id,
            minimum_revision=minimum_revision,
            max_records=max_records,
            execution_max_facts=execution_max_facts,
            clock=clock,
            timeout_seconds=timeout_seconds,
            old_version=6,
        )

    @classmethod
    def _upgrade_legacy(
        cls,
        database_path,
        account_scope,
        *,
        generation,
        guard,
        expected_journal_id,
        minimum_revision,
        max_records,
        execution_max_facts,
        clock,
        timeout_seconds,
        old_version,
    ):
        from .session_guard import LocalAccountSessionGuard

        if type(guard) is not LocalAccountSessionGuard:
            raise DirectCommandJournalError("INVALID_GUARD")
        self = cls.__new__(cls)
        self._configure(
            database_path,
            account_scope,
            generation,
            max_records,
            execution_max_facts,
            clock,
            timeout_seconds,
        )
        self._journal_id = _text(expected_journal_id)
        if type(minimum_revision) is not int or minimum_revision < 0:
            raise DirectCommandJournalError("INVALID_REVISION")
        self._minimum_revision = minimum_revision

        def owned():
            guard.assert_owned()
            if (
                guard.account_key_digest
                != hashlib.sha256(self._account.encode("utf-8")).hexdigest()
                or guard.acquire() != self._generation
            ):
                raise DirectCommandJournalError("GUARD_BINDING_MISMATCH")

        owned()
        try:
            with self._connection() as db, self._transaction_on(db):
                self._verify_schema(db, schema_version=old_version)
                self._assert_anchor(db, schema_version=old_version)
                self._verify_v2_upgrade_integrity(db, schema_version=old_version)
                owned()
                from .direct_execution_journal import (
                    _create_consumer_table,
                    _create_execution_tables,
                    _verify_execution_integrity,
                    _verify_consumer_integrity,
                    _create_cancel_error_table,
                )
                from .direct_cancel_journal import _create_cancel_tables, _verify_cancel_integrity

                if old_version >= 4:
                    self._verify_v4_identity_integrity(db)
                    _verify_execution_integrity(
                        db, self._account, self._execution_max_facts, allow_v2=False
                    )
                    if old_version >= 5:
                        _verify_consumer_integrity(db, self._account)
                    if old_version >= 6:
                        _verify_cancel_integrity(db, self._account, self._max_records)
                else:
                    if old_version == 2:
                        self._create_settlement_table(db)
                    _create_execution_tables(db, self._account, self._execution_max_facts)
                if old_version < 5:
                    _create_consumer_table(db)
                if old_version < 6:
                    _create_cancel_tables(db)
                _create_cancel_error_table(db)
                db.execute(
                    "UPDATE direct_journal_meta SET schema_version=7, revision=revision+1 WHERE account=?",
                    (self._account,),
                )
                owned()
        except sqlite3.DatabaseError as exc:
            raise DirectCommandJournalError("INVALID_DATABASE") from exc
        return self

    @staticmethod
    def _verify_exact_ddl(db: sqlite3.Connection, schema_version: int) -> None:
        expected = {
            "direct_journal_meta": "CREATE TABLE direct_journal_meta (account TEXT PRIMARY KEY, schema_version INTEGER NOT NULL, max_records INTEGER NOT NULL, journal_id TEXT NOT NULL, revision INTEGER NOT NULL)",
            "direct_journal_commands": "CREATE TABLE direct_journal_commands (account TEXT NOT NULL, strategy TEXT NOT NULL, request_key TEXT NOT NULL, reservation_id TEXT NOT NULL UNIQUE, principal TEXT NOT NULL, digest TEXT NOT NULL, payload_json TEXT NOT NULL, generation TEXT NOT NULL, expires_at REAL NOT NULL, status TEXT NOT NULL, version INTEGER NOT NULL, native_identity_json TEXT, strong_keys_json TEXT, PRIMARY KEY(account, strategy, request_key))",
            "direct_journal_releases": "CREATE TABLE direct_journal_releases (account TEXT NOT NULL, operation_id TEXT NOT NULL, strategy TEXT NOT NULL, request_key TEXT NOT NULL, reservation_id TEXT NOT NULL, digest TEXT NOT NULL, principal TEXT NOT NULL, expected_version INTEGER NOT NULL, PRIMARY KEY(account, operation_id))",
            "direct_journal_strong_keys": "CREATE TABLE direct_journal_strong_keys (account TEXT NOT NULL, strong_key TEXT NOT NULL, reservation_id TEXT NOT NULL, PRIMARY KEY(account, strong_key))",
            "direct_journal_release_command": "CREATE UNIQUE INDEX direct_journal_release_command ON direct_journal_releases(account, strategy, request_key)",
            "direct_journal_native_identity": "CREATE UNIQUE INDEX direct_journal_native_identity ON direct_journal_commands(account, native_identity_json) WHERE native_identity_json IS NOT NULL",
        }
        automatic = {
            "sqlite_autoindex_direct_journal_meta_1",
            "sqlite_autoindex_direct_journal_commands_1",
            "sqlite_autoindex_direct_journal_commands_2",
            "sqlite_autoindex_direct_journal_releases_1",
            "sqlite_autoindex_direct_journal_strong_keys_1",
        }
        if schema_version >= 3:
            expected["direct_journal_settlement"] = (
                "CREATE TABLE direct_journal_settlement (account TEXT NOT NULL, exchange_name TEXT NOT NULL, trading_day TEXT NOT NULL, account_binding TEXT NOT NULL, owner_generation TEXT NOT NULL, initial_session_generation INTEGER NOT NULL, initial_observation_id TEXT NOT NULL, marker_id TEXT, status TEXT NOT NULL, version INTEGER NOT NULL, confirmation_observation_id TEXT, PRIMARY KEY(account, exchange_name, trading_day))"
            )
            automatic.add("sqlite_autoindex_direct_journal_settlement_1")
        if schema_version >= 4:
            from .direct_execution_journal import _EXECUTION_DDL

            expected.update(_EXECUTION_DDL)
            automatic.update(
                {
                    "sqlite_autoindex_direct_execution_meta_1",
                    "sqlite_autoindex_direct_execution_facts_1",
                    "sqlite_autoindex_direct_execution_aliases_1",
                    "sqlite_autoindex_direct_execution_trades_1",
                    "sqlite_autoindex_direct_execution_positions_1",
                    "sqlite_autoindex_direct_execution_totals_1",
                    "sqlite_autoindex_direct_execution_conflicts_1",
                }
            )
        if schema_version >= 5:
            from .direct_execution_journal import _CONSUMER_DDL

            expected["direct_execution_consumers"] = _CONSUMER_DDL
            automatic.add("sqlite_autoindex_direct_execution_consumers_1")
        if schema_version >= 6:
            from .direct_cancel_journal import _CANCEL_DDL

            expected.update(_CANCEL_DDL)
            automatic.update(
                {
                    "sqlite_autoindex_direct_cancel_attempts_1",
                    "sqlite_autoindex_direct_cancel_attempts_2",
                    "sqlite_autoindex_direct_cancel_keys_1",
                }
            )
        if schema_version >= 7:
            from .direct_execution_journal import _CANCEL_ERROR_DDL

            expected["direct_cancel_error_attribution"] = _CANCEL_ERROR_DDL
            automatic.add("sqlite_autoindex_direct_cancel_error_attribution_1")
        actual = {row[0] for row in db.execute("SELECT name FROM sqlite_master")}
        if actual != set(expected) | automatic:
            raise DirectCommandJournalError("INVALID_DATABASE")
        for name, sql in expected.items():
            row = db.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()
            if (
                row is None
                or not isinstance(row[0], str)
                or "".join(row[0].split()).lower() != "".join(sql.split()).lower()
            ):
                raise DirectCommandJournalError("INVALID_DATABASE")

    def _verify_v2_upgrade_integrity(
        self, db: sqlite3.Connection, *, schema_version: int = 2
    ) -> None:
        """Reject altered legacy DDL and inconsistent records before migration."""
        self._verify_exact_ddl(db, schema_version)
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise DirectCommandJournalError("INVALID_DATABASE")
        rows = db.execute("SELECT * FROM direct_journal_commands").fetchall()
        if len(rows) > self._max_records:
            raise DirectCommandJournalError("INVALID_DATABASE")
        if schema_version >= 3:
            self._verify_legacy_settlement(db, len(rows))
        expected_keys, expected_releases = set(), {}
        try:
            for row in rows:
                if row["account"] != self._account:
                    raise ValueError
                for key in ("strategy", "request_key", "reservation_id", "principal", "generation"):
                    _text(row[key])
                payload = json.loads(row["payload_json"])
                if (
                    _json(payload) != row["payload_json"]
                    or payload_digest(payload) != row["digest"]
                ):
                    raise ValueError
                if (
                    type(row["expires_at"]) not in (int, float)
                    or not math.isfinite(row["expires_at"])
                    or row["expires_at"] < 0
                ):
                    raise ValueError
                state = row["status"]
                version = {
                    "RESERVED": 1,
                    "DISPATCHING": 2,
                    "RELEASED": 2,
                    "EXPIRED": 2,
                    "SENT": 3,
                    "NOT_SENT": 3,
                    "UNKNOWN": 3,
                }.get(state)
                if version is None or row["version"] != version:
                    raise ValueError
                if state in {"DISPATCHING", "SENT", "NOT_SENT", "UNKNOWN"}:
                    identity = json.loads(row["native_identity_json"])
                    if _json(identity, scalar_map=True) != row["native_identity_json"]:
                        raise ValueError
                    keys = tuple(json.loads(row["strong_keys_json"]))
                    if _strong_keys(keys) != keys:
                        raise ValueError
                    expected_keys.update(
                        (self._account, key, row["reservation_id"]) for key in keys
                    )
                elif row["native_identity_json"] is not None or row["strong_keys_json"] is not None:
                    raise ValueError
                if state in {"RELEASED", "EXPIRED"}:
                    expected_releases[(row["strategy"], row["request_key"])] = row
            actual_keys = {
                tuple(row)
                for row in db.execute(
                    "SELECT account, strong_key, reservation_id FROM direct_journal_strong_keys"
                )
            }
            if schema_version >= 4:
                for alias in db.execute(
                    "SELECT account,strong_key,reservation_id FROM direct_execution_aliases"
                ):
                    _text(alias["strong_key"])
                    expected_keys.add(tuple(alias))
            if actual_keys != expected_keys:
                raise ValueError
            seen = set()
            for release in db.execute("SELECT * FROM direct_journal_releases"):
                _text(release["operation_id"])
                key = (release["strategy"], release["request_key"])
                row = expected_releases.get(key)
                if (
                    row is None
                    or release["account"] != self._account
                    or any(
                        release[name] != row[name]
                        for name in ("reservation_id", "digest", "principal")
                    )
                    or release["expected_version"]
                    not in ((1, 2) if row["status"] == "EXPIRED" else (1,))
                ):
                    raise ValueError
                seen.add(key)
            if any(
                row["status"] == "RELEASED" and key not in seen
                for key, row in expected_releases.items()
            ):
                raise ValueError
        except (TypeError, ValueError, KeyError, DirectCommandJournalError) as exc:
            raise DirectCommandJournalError("INVALID_DATABASE") from exc

    def _verify_legacy_settlement(self, db: sqlite3.Connection, command_count: int) -> None:
        rows = db.execute("SELECT * FROM direct_journal_settlement").fetchall()
        if command_count + len(rows) > self._max_records:
            raise DirectCommandJournalError("INVALID_DATABASE")
        bindings = {}
        try:
            for row in rows:
                if row["account"] != self._account:
                    raise ValueError
                for name in (
                    "exchange_name",
                    "account_binding",
                    "owner_generation",
                    "initial_observation_id",
                ):
                    _text(row[name])
                prior = bindings.setdefault(row["exchange_name"], row["account_binding"])
                if prior != row["account_binding"]:
                    raise ValueError
                SettlementObservation(
                    row["exchange_name"],
                    row["account_binding"],
                    row["trading_day"],
                    row["initial_session_generation"],
                    SettlementStatus.UNCONFIRMED,
                    row["initial_observation_id"],
                )
                status, version, marker, confirmed = (
                    row["status"],
                    row["version"],
                    row["marker_id"],
                    row["confirmation_observation_id"],
                )
                if (
                    status == "ATTEMPTING"
                    and version == 1
                    and marker is not None
                    and confirmed is None
                ):
                    _text(marker)
                elif (
                    status == "UNKNOWN"
                    and version == 2
                    and marker is not None
                    and confirmed is None
                ):
                    _text(marker)
                elif (
                    status == "CONFIRMED"
                    and marker is None
                    and version == 1
                    and confirmed == row["initial_observation_id"]
                ):
                    _text(confirmed)
                elif (
                    status == "CONFIRMED"
                    and marker is not None
                    and version in (2, 3)
                    and confirmed != row["initial_observation_id"]
                ):
                    _text(marker)
                    _text(confirmed)
                else:
                    raise ValueError
        except (TypeError, ValueError, KeyError, DirectCommandJournalError) as exc:
            raise DirectCommandJournalError("INVALID_DATABASE") from exc

    def _verify_v4_identity_integrity(self, db: sqlite3.Connection) -> None:
        """Check original dispatch keys plus separately learned aliases bidirectionally."""
        try:
            commands = db.execute(
                "SELECT account,reservation_id,status,strong_keys_json FROM direct_journal_commands"
            ).fetchall()
            initial = set()
            allowed = set()
            for row in commands:
                if row["account"] != self._account:
                    raise ValueError
                if row["status"] in {"DISPATCHING", "SENT", "NOT_SENT", "UNKNOWN"}:
                    keys = tuple(json.loads(row["strong_keys_json"]))
                    _strong_keys(keys)
                    allowed.add(row["reservation_id"])
                    initial.update((self._account, key, row["reservation_id"]) for key in keys)
                elif row["strong_keys_json"] is not None:
                    raise ValueError
            aliases = set()
            for row in db.execute(
                "SELECT account,strong_key,reservation_id FROM direct_execution_aliases"
            ):
                _text(row["strong_key"])
                value = tuple(row)
                if (
                    row["account"] != self._account
                    or row["reservation_id"] not in allowed
                    or value in initial
                ):
                    raise ValueError
                aliases.add(value)
            actual = {
                tuple(row)
                for row in db.execute(
                    "SELECT account,strong_key,reservation_id FROM direct_journal_strong_keys"
                )
            }
            if actual != initial | aliases:
                raise ValueError
        except (ValueError, TypeError, KeyError, DirectCommandJournalError) as exc:
            raise DirectCommandJournalError("INVALID_DATABASE") from exc

    def _verify_schema(self, db: sqlite3.Connection, *, schema_version: int = 7) -> None:
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
        if schema_version >= 3:
            expected.add("direct_journal_settlement")
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
        if schema_version >= 3:
            columns["direct_journal_settlement"] = (
                "account",
                "exchange_name",
                "trading_day",
                "account_binding",
                "owner_generation",
                "initial_session_generation",
                "initial_observation_id",
                "marker_id",
                "status",
                "version",
                "confirmation_observation_id",
            )
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
                "direct_journal_settlement": ("account", "exchange_name", "trading_day"),
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
        if schema_version >= 4:
            self._verify_exact_ddl(db, schema_version)
            from .direct_execution_journal import _verify_execution_schema

            _verify_execution_schema(db, self._account, self._execution_max_facts)

    def _assert_anchor(self, db: sqlite3.Connection, *, schema_version: int | None = None) -> int:
        rows = db.execute(
            "SELECT account, schema_version, max_records, journal_id, revision FROM direct_journal_meta"
        ).fetchall()
        if len(rows) != 1:
            raise DirectCommandJournalError("INVALID_DATABASE")
        account, schema, capacity, journal_id, revision = tuple(rows[0])
        if account != self._account:
            raise DirectCommandJournalError("ACCOUNT_MISMATCH")
        if (
            schema != (self._schema_version if schema_version is None else schema_version)
            or capacity != self._max_records
        ):
            raise DirectCommandJournalError("SCHEMA_OR_CAPACITY_MISMATCH")
        if journal_id != self._journal_id:
            raise DirectCommandJournalError("JOURNAL_ID_MISMATCH")
        if type(revision) is not int or revision < self._minimum_revision:
            raise DirectCommandJournalError("REVISION_ROLLBACK")
        if (self._schema_version if schema_version is None else schema_version) >= 4:
            row = db.execute("SELECT account,max_facts FROM direct_execution_meta").fetchall()
            if len(row) != 1 or tuple(row[0]) != (self._account, self._execution_max_facts):
                raise DirectCommandJournalError("EXECUTION_CAPACITY_MISMATCH")
        return revision

    def _bump(self, db: sqlite3.Connection) -> None:
        db.execute(
            "UPDATE direct_journal_meta SET revision=revision+1 WHERE account=?", (self._account,)
        )

    @staticmethod
    def _settlement_row(row: sqlite3.Row) -> SettlementRecord:
        return SettlementRecord(
            row["account"],
            row["exchange_name"],
            row["trading_day"],
            row["account_binding"],
            row["owner_generation"],
            row["initial_session_generation"],
            row["initial_observation_id"],
            row["marker_id"],
            row["status"],
            row["version"],
            row["confirmation_observation_id"],
        )

    @staticmethod
    def _settlement_input(observation: SettlementObservation, status: SettlementStatus) -> None:
        if type(observation) is not SettlementObservation or observation.status is not status:
            raise DirectCommandJournalError("INVALID_SETTLEMENT_OBSERVATION")
        try:
            checked = SettlementObservation(
                observation.exchange_name,
                observation.account_binding,
                observation.trading_day,
                observation.session_generation,
                observation.status,
                observation.observation_id,
            )
        except (TypeError, ValueError) as exc:
            raise DirectCommandJournalError("INVALID_SETTLEMENT_OBSERVATION") from exc
        if checked != observation:
            raise DirectCommandJournalError("INVALID_SETTLEMENT_OBSERVATION")

    def _settlement_existing(self, db, exchange_name, trading_day, account_binding=None):
        if account_binding is not None:
            mismatch = db.execute(
                "SELECT 1 FROM direct_journal_settlement WHERE account=? AND exchange_name=? AND account_binding<>? LIMIT 1",
                (self._account, exchange_name, account_binding),
            ).fetchone()
            if mismatch is not None:
                raise DirectCommandJournalError("SETTLEMENT_ACCOUNT_MISMATCH")
        return db.execute(
            "SELECT * FROM direct_journal_settlement WHERE account=? AND exchange_name=? AND trading_day=?",
            (self._account, exchange_name, trading_day),
        ).fetchone()

    def _settlement_capacity(self, db):
        count = db.execute(
            "SELECT (SELECT count(*) FROM direct_journal_commands WHERE account=?) + "
            "(SELECT count(*) FROM direct_journal_settlement WHERE account=?)",
            (self._account, self._account),
        ).fetchone()[0]
        if count >= self._max_records:
            raise DirectCommandJournalError("CAPACITY_EXCEEDED")

    def settlement_get(self, exchange_name: str, trading_day: str) -> SettlementRecord | None:
        exchange_name, trading_day = _text(exchange_name), _text(trading_day)
        with self._transaction() as db:
            row = self._settlement_existing(db, exchange_name, trading_day)
            return None if row is None else self._settlement_row(row)

    def settlement_begin(
        self,
        observation: SettlementObservation,
        marker_id: str,
        *,
        before_begin: Callable[[], None],
        before_commit: Callable[[], None],
    ) -> SettlementStart:
        """Durably claim one daily attempt; an existing claim never grants another marker."""
        self._settlement_input(observation, SettlementStatus.UNCONFIRMED)
        marker_id = _text(marker_id)
        if not callable(before_begin) or not callable(before_commit):
            raise DirectCommandJournalError("INVALID_SETTLEMENT_FENCE")
        with self._transaction() as db:
            before_begin()
            row = self._settlement_existing(
                db, observation.exchange_name, observation.trading_day, observation.account_binding
            )
            if row is not None:
                before_commit()
                return SettlementStart(self._settlement_row(row), False)
            self._settlement_capacity(db)
            db.execute(
                "INSERT INTO direct_journal_settlement VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ATTEMPTING', 1, NULL)",
                (
                    self._account,
                    observation.exchange_name,
                    observation.trading_day,
                    observation.account_binding,
                    self._generation,
                    observation.session_generation,
                    observation.observation_id,
                    marker_id,
                ),
            )
            self._bump(db)
            before_commit()
            row = self._settlement_existing(
                db, observation.exchange_name, observation.trading_day, observation.account_binding
            )
            return SettlementStart(self._settlement_row(row), True)

    def settlement_mark_unknown(
        self,
        observation: SettlementObservation,
        marker_id: str,
        *,
        before_commit: Callable[[], None] | None = None,
    ) -> SettlementRecord:
        self._settlement_input(observation, SettlementStatus.UNCONFIRMED)
        marker_id = _text(marker_id)
        if before_commit is not None and not callable(before_commit):
            raise DirectCommandJournalError("INVALID_SETTLEMENT_FENCE")
        with self._transaction() as db:
            row = self._settlement_existing(
                db, observation.exchange_name, observation.trading_day, observation.account_binding
            )
            if (
                row is None
                or row["marker_id"] != marker_id
                or row["initial_observation_id"] != observation.observation_id
                or row["initial_session_generation"] != observation.session_generation
            ):
                raise DirectCommandJournalError("SETTLEMENT_ATTEMPT_MISMATCH")
            if row["status"] == "ATTEMPTING":
                db.execute(
                    "UPDATE direct_journal_settlement SET status='UNKNOWN', version=version+1 WHERE account=? AND exchange_name=? AND trading_day=?",
                    (self._account, observation.exchange_name, observation.trading_day),
                )
                self._bump(db)
                row = self._settlement_existing(
                    db,
                    observation.exchange_name,
                    observation.trading_day,
                    observation.account_binding,
                )
            if before_commit is not None:
                before_commit()
            return self._settlement_row(row)

    def settlement_confirm(
        self,
        observation: SettlementObservation,
        *,
        before_begin: Callable[[], None] | None = None,
        before_commit: Callable[[], None] | None = None,
    ) -> SettlementRecord:
        """Record a caller-verified observation; this storage does not attest it."""
        self._settlement_input(observation, SettlementStatus.CONFIRMED)
        if before_begin is not None and not callable(before_begin):
            raise DirectCommandJournalError("INVALID_SETTLEMENT_FENCE")
        if before_commit is not None and not callable(before_commit):
            raise DirectCommandJournalError("INVALID_SETTLEMENT_FENCE")
        with self._transaction() as db:
            if before_begin is not None:
                before_begin()
            row = self._settlement_existing(
                db, observation.exchange_name, observation.trading_day, observation.account_binding
            )
            if row is None:
                self._settlement_capacity(db)
                db.execute(
                    "INSERT INTO direct_journal_settlement VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'CONFIRMED', 1, ?)",
                    (
                        self._account,
                        observation.exchange_name,
                        observation.trading_day,
                        observation.account_binding,
                        self._generation,
                        observation.session_generation,
                        observation.observation_id,
                        observation.observation_id,
                    ),
                )
                self._bump(db)
            elif row["status"] != "CONFIRMED":
                if observation.observation_id == row["initial_observation_id"]:
                    raise DirectCommandJournalError("SETTLEMENT_OBSERVATION_REUSED")
                db.execute(
                    "UPDATE direct_journal_settlement SET status='CONFIRMED', version=version+1, confirmation_observation_id=? WHERE account=? AND exchange_name=? AND trading_day=?",
                    (
                        observation.observation_id,
                        self._account,
                        observation.exchange_name,
                        observation.trading_day,
                    ),
                )
                self._bump(db)
            row = self._settlement_existing(
                db, observation.exchange_name, observation.trading_day, observation.account_binding
            )
            if before_commit is not None:
                before_commit()
            return self._settlement_row(row)

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
        reservation_fence: Callable[[], ContextManager[None]] | None = None,
    ) -> DirectCommandRecord:
        """Create a reservation; repeated keys never renew its original TTL.

        TTL is a first-creation lifecycle option, not part of the payload digest.
        The optional trusted local fence stays held through the SQLite commit;
        it must not perform native or network I/O. Existing keys bypass it.
        """
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
        if reservation_fence is not None and not callable(reservation_fence):
            raise DirectCommandJournalError("INVALID_INPUT")
        with ExitStack() as fence_stack, self._transaction() as db:
            row = self._find(db, strategy, request_key)
            if row is not None:
                if (
                    row["principal"] != principal
                    or row["digest"] != digest
                    or row["payload_json"] != encoded
                ):
                    raise DirectCommandJournalError("REQUEST_CONFLICT")
                return self._record(row)
            if reservation_fence is not None:
                manager = reservation_fence()
                # Ignore a context manager's suppression result: a failed
                # transaction must never be reported as a successful reserve.
                enter, exit_ = type(manager).__enter__, type(manager).__exit__
                enter(manager)
                fence_stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            if (
                db.execute(
                    "SELECT count(*) FROM direct_journal_commands WHERE account=?", (self._account,)
                ).fetchone()[0]
                + db.execute(
                    "SELECT count(*) FROM direct_journal_settlement WHERE account=?",
                    (self._account,),
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

    def observe(self, strategy: str, request_key: str, principal: str) -> DirectCommandObservation:
        """Observe the same row and local monotonic clock in one transaction.

        Zero TTL is pending expiry, not a persisted EXPIRED or NOT_SENT result.
        """
        strategy, request_key, principal = map(_text, (strategy, request_key, principal))
        with self._transaction() as db:
            record = self._record(self._require(db, strategy, request_key, principal))
            now = self._now()
            current = record.generation == self._generation
            remaining = None
            if record.status == "RESERVED":
                remaining = max(0.0, record.expires_at - now) if current else 0.0
            return DirectCommandObservation(record, current, remaining)

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
        *,
        before_dispatch: Callable[[], None] | None = None,
    ) -> DispatchStart:
        """Begin dispatch under the write transaction and an optional local recheck.

        The trusted recheck runs with SQLite's write lock held; it must not do
        provider I/O, enter another journal transaction, or reenter its fence.
        """
        if before_dispatch is not None and not callable(before_dispatch):
            raise DirectCommandJournalError("INVALID_INPUT")
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
            if before_dispatch is not None:
                before_dispatch()
            if self._now() >= row["expires_at"]:
                db.execute(
                    "UPDATE direct_journal_commands SET status='EXPIRED', version=version+1 WHERE account=? AND strategy=? AND request_key=?",
                    (self._account, strategy, request_key),
                )
                self._bump(db)
                return DispatchStart(
                    self._record(self._require(db, strategy, request_key, principal)), False
                )
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
            if self._schema_version >= 4:
                self._verify_exact_ddl(db, self._schema_version)
            yield db
