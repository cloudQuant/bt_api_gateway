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
import stat
import threading
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
from .session_guard import LocalAccountSessionGuard


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
        controls_enabled: bool = False,
        strategy_ledger_enabled: bool = False,
        account_extensions_enabled: bool = False,
        parent_authority_enabled: bool = False,
        account_facts_financial_enabled: bool = False,
        actor_stream_enabled: bool = False,
        strategy_origin_enabled: bool = False,
        control_cancel_enabled: bool = False,
        account_fact_recovery_enabled: bool = False,
        account_event_recovery_enabled: bool = False,
        control_release_audit_enabled: bool = False,
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
        if (type(controls_enabled) is not bool or type(strategy_ledger_enabled) is not bool
                or type(account_extensions_enabled) is not bool or type(parent_authority_enabled) is not bool
                or type(account_facts_financial_enabled) is not bool
                or type(actor_stream_enabled) is not bool
                or type(strategy_origin_enabled) is not bool
                or type(control_cancel_enabled) is not bool
                or type(account_fact_recovery_enabled) is not bool
                or type(account_event_recovery_enabled) is not bool
                or (strategy_ledger_enabled and not controls_enabled)
                or (account_extensions_enabled and not strategy_ledger_enabled)
                or (parent_authority_enabled and not account_extensions_enabled)
                or (account_facts_financial_enabled and not parent_authority_enabled)
                or (actor_stream_enabled and not account_facts_financial_enabled)
                or (strategy_origin_enabled and not actor_stream_enabled)
                or (control_cancel_enabled and not strategy_origin_enabled)
                or (account_fact_recovery_enabled and not control_cancel_enabled)
                or (account_event_recovery_enabled and not account_fact_recovery_enabled)
                or type(control_release_audit_enabled) is not bool
                or (control_release_audit_enabled and not controls_enabled)):
            raise DirectCommandJournalError("INVALID_INPUT")
        self._schema_version = 19 if account_event_recovery_enabled else 18 if account_fact_recovery_enabled else 17 if control_cancel_enabled else 16 if strategy_origin_enabled else 15 if actor_stream_enabled else 14 if account_facts_financial_enabled else 13 if parent_authority_enabled else 12 if account_extensions_enabled else 11 if strategy_ledger_enabled else 10 if controls_enabled else 9
        # Independent of the schema version (see enable_control_release_audit).
        self._control_release_audit = control_release_audit_enabled
        self._journal_id = _text(expected_journal_id)
        if type(minimum_revision) is not int or minimum_revision < 0:
            raise DirectCommandJournalError("INVALID_REVISION")
        self._minimum_revision = minimum_revision
        try:
            with self._connection() as db, self._transaction_on(db):
                if controls_enabled:
                    # Distinguish an anchored v9 candidate before exact v10 DDL verification.
                    self._assert_anchor(db)
                    # Likewise a journal whose release audit is not what the owner installed.
                    self._assert_release_audit(db)
                self._verify_schema(db, schema_version=self._schema_version)
                self._assert_anchor(db)
                self._verify_v2_upgrade_integrity(db, schema_version=self._schema_version)
                self._verify_v4_identity_integrity(db)
                from .direct_execution_journal import _verify_execution_integrity

                _verify_execution_integrity(db, self._account, self._execution_max_facts)
                from .direct_execution_journal import _verify_consumer_integrity

                _verify_consumer_integrity(db, self._account)
                from .direct_cancel_journal import _verify_cancel_integrity

                _verify_cancel_integrity(db, self._account, self._max_records)
                from .direct_execution_journal import _verify_cancel_error_integrity

                _verify_cancel_error_integrity(db, self._account, self._execution_max_facts)
                from .direct_execution_journal import _verify_place_error_integrity
                from .direct_place_journal import _verify_place_integrity

                _verify_place_integrity(db, self._account, self._max_records)
                _verify_place_error_integrity(db, self, self._execution_max_facts)
                if self._schema_version >= 10:
                    from .direct_control import verify_controls
                    verify_controls(db, self._account, self._max_records)
                if self._schema_version >= 11:
                    from .strategy_position_ledger import _verify_strategy_ledger_integrity
                    _verify_strategy_ledger_integrity(db, self._account)
                if self._schema_version >= 12:
                    from .direct_delegation import verify_delegated_integrity
                    from .external_position_ledger import verify_external_integrity
                    from .account_observer import verify_account_observers
                    verify_delegated_integrity(db, self._account, self._max_records)
                    verify_external_integrity(db, self._account)
                    verify_account_observers(db, self._account)
                if self._schema_version >= 13:
                    from .direct_parent_authority import verify_parent_authority_integrity
                    verify_parent_authority_integrity(db, self._account, self._max_records)
                if self._schema_version >= 14:
                    from .account_observation_journal import verify_account_fact_stream
                    from .strategy_financial_ledger import verify_strategy_financial_integrity
                    verify_account_fact_stream(db, self._account, self._journal_id)
                    verify_strategy_financial_integrity(db, self._account)
                if self._schema_version >= 15:
                    from .delegate_actor_stream import verify_actor_stream
                    verify_actor_stream(db, self._account, self._journal_id, self._max_records)
                if self._schema_version >= 16:
                    from .direct_strategy_origin import verify_strategy_origins
                    verify_strategy_origins(db, self._account, self._journal_id)
                if self._schema_version >= 17:
                    from .direct_control_cancel import verify_control_cancel_integrity
                    verify_control_cancel_integrity(db, self._account, self._journal_id, self._max_records)
                if self._schema_version >= 18:
                    from .account_fact_consumer_ownership import verify_account_fact_consumer_owners
                    from .account_fact_compaction import verify_account_fact_compaction
                    verify_account_fact_consumer_owners(db, self._account)
                    verify_account_fact_compaction(db, self._account, self._journal_id)
                if self._schema_version >= 19:
                    from .account_event_consumer_ownership import verify_account_event_consumer_owners
                    verify_account_event_consumer_owners(db, self._account)
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
                from .direct_execution_journal import _create_trade_date_table

                _create_trade_date_table(db)
                from .direct_execution_journal import _create_consumer_table

                _create_consumer_table(db)
                from .direct_cancel_journal import _create_cancel_tables

                _create_cancel_tables(db)
                from .direct_execution_journal import _create_cancel_error_table

                _create_cancel_error_table(db)
                from .direct_place_journal import _create_place_tables

                _create_place_tables(db)
                db.execute(
                    "INSERT INTO direct_journal_meta VALUES (?, 9, ?, ?, 0)",
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
        self._schema_version = 9
        self._control_release_audit = False
        self._execution_max_facts = execution_max_facts
        self._clock = clock
        self._timeout = timeout_seconds
        self._identity = SQLiteFileIdentity(Path(database_path))
        self._monitor_gate = None
        self._monitor_guard = None
        self._strategy_ledger_ports = None
        self._strategy_external_verifier = None
        self._account_comparison_ports = None
        self._strategy_financial_port = None
        self._strategy_financial_guard = None
        self._unknown_capacity_ports = None
        self._unknown_capacity_guard = None
        self._strategy_ledger_guard = None
        self._dispatch_change_port = None
        self._dispatch_change_guard = None
        self._dispatch_port_lock = threading.Lock()
        self._dispatch_active_transactions = 0

    @property
    def journal_id(self) -> str:
        return self._journal_id

    @property
    def account_scope(self) -> str:
        return self._account

    @property
    def generation(self) -> str:
        return self._generation

    def install_dispatch_change_port(self, *, guard: LocalAccountSessionGuard, port: object) -> None:
        """Install the trusted owner's process-local dispatch invalidation port.

        This port observes this journal's cooperating connections only; it is
        not evidence that external sources or other database writers are fenced.
        """
        self._assert_account_guard(guard)
        if (not all(callable(getattr(port, name, None)) for name in
                    ('matches_owner', 'begin_change', 'finish_change', 'poison', 'poison_domain'))
                or port.matches_owner(self._account, self._generation) is not True):
            raise DirectCommandJournalError('DISPATCH_CHANGE_PORT_UNAVAILABLE')
        with self._dispatch_port_lock:
            if self._dispatch_change_port is not None:
                if self._dispatch_change_port is not port or self._dispatch_change_guard is not guard:
                    raise DirectCommandJournalError('DISPATCH_CHANGE_PORT_ALREADY_BOUND')
                return
            if self._dispatch_active_transactions:
                raise DirectCommandJournalError('DISPATCH_CHANGE_PORT_BUSY')
            self._dispatch_change_port, self._dispatch_change_guard = port, guard

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
        """Explicitly upgrade an anchored v2 journal to v9 under the account guard."""
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
        """Explicitly upgrade an anchored v3 journal to v9 under the account guard."""
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
    def upgrade_v7(
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
        """Upgrade an anchored v7 database with existing fact associations intact."""
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
            old_version=7,
        )

    @classmethod
    def upgrade_from_v8(
        cls,
        database_path: str | Path,
        account_scope: str,
        *,
        generation: str,
        guard: LocalAccountSessionGuard,
        expected_journal_id: str,
        minimum_revision: int,
        max_records: int = 100000,
        execution_max_facts: int = 100000,
        clock: Callable[[], float] = time.monotonic,
        timeout_seconds: float = 5.0,
    ) -> GatewayDirectCommandJournal:
        """Explicitly upgrade an anchored and audited v8 journal to v9."""
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
            old_version=8,
        )

    upgrade_v8 = upgrade_from_v8

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
                from .direct_cancel_journal import _create_cancel_tables, _verify_cancel_integrity
                from .direct_execution_journal import (
                    _create_cancel_error_table,
                    _create_consumer_table,
                    _create_execution_tables,
                    _create_trade_date_table,
                    _verify_cancel_error_integrity,
                    _verify_consumer_integrity,
                    _verify_execution_integrity,
                )
                from .direct_place_journal import _create_place_tables

                if old_version >= 4:
                    self._verify_v4_identity_integrity(db)
                    _verify_execution_integrity(
                        db,
                        self._account,
                        self._execution_max_facts,
                        max_fact_version=(3 if old_version >= 8 else 2 if old_version >= 7 else 1),
                    )
                    if old_version >= 5:
                        _verify_consumer_integrity(db, self._account)
                    if old_version >= 6:
                        _verify_cancel_integrity(db, self._account, self._max_records)
                    if old_version >= 7:
                        _verify_cancel_error_integrity(db, self._account, self._execution_max_facts)
                else:
                    if old_version == 2:
                        self._create_settlement_table(db)
                    _create_execution_tables(db, self._account, self._execution_max_facts)
                if old_version < 5:
                    _create_consumer_table(db)
                if old_version < 6:
                    _create_cancel_tables(db)
                if old_version < 7:
                    _create_cancel_error_table(db)
                if old_version >= 8:
                    from .direct_execution_journal import _verify_place_error_integrity
                    from .direct_place_journal import _verify_place_integrity

                    _verify_place_integrity(db, self._account, self._max_records)
                    _verify_place_error_integrity(db, self, self._execution_max_facts)
                else:
                    _create_place_tables(db)
                _create_trade_date_table(db)
                db.execute(
                    "UPDATE direct_journal_meta SET schema_version=9, revision=revision+1 WHERE account=?",
                    (self._account,),
                )
                owned()
        except sqlite3.DatabaseError as exc:
            raise DirectCommandJournalError("INVALID_DATABASE") from exc
        return self

    @staticmethod
    def _verify_exact_ddl(db: sqlite3.Connection, schema_version: int, release_audit: bool = False) -> None:
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
        if schema_version >= 8:
            from .direct_place_journal import _PLACE_DDL

            expected.update(_PLACE_DDL)
            automatic.update(
                {
                    "sqlite_autoindex_direct_place_preparations_1",
                    "sqlite_autoindex_direct_place_keys_1",
                    "sqlite_autoindex_direct_place_error_attribution_1",
                }
            )
        if schema_version >= 9:
            from .direct_execution_journal import _TRADE_DATE_DDL

            expected["direct_execution_trade_dates"] = _TRADE_DATE_DDL
            automatic.add("sqlite_autoindex_direct_execution_trade_dates_1")
        if schema_version >= 10:
            from .direct_control import _CONTROL_DDL
            expected.update(_CONTROL_DDL)
            automatic.update({"sqlite_autoindex_direct_control_causes_1", "sqlite_autoindex_direct_control_targets_1", "sqlite_autoindex_direct_control_blocked_1"})
        if schema_version >= 11:
            from .strategy_position_ledger import _STRATEGY_LEDGER_DDL
            expected.update(_STRATEGY_LEDGER_DDL)
            automatic.update({"sqlite_autoindex_strategy_position_baseline_1",
                              "sqlite_autoindex_strategy_external_baseline_1"})
        if schema_version >= 12:
            from .direct_delegation import _DELEGATION_DDL
            from .external_position_ledger import _EXTERNAL_LEDGER_DDL
            from .account_observer import _ACCOUNT_OBSERVER_DDL
            expected.update(_DELEGATION_DDL)
            expected.update(_EXTERNAL_LEDGER_DDL)
            expected.update(_ACCOUNT_OBSERVER_DDL)
            automatic.update({"sqlite_autoindex_direct_delegated_commands_1",
                              "sqlite_autoindex_direct_delegated_commands_2",
                              "sqlite_autoindex_direct_account_observer_consumers_1",
                              "sqlite_autoindex_external_position_events_1",
                              "sqlite_autoindex_external_position_trades_1"})
        if schema_version >= 13:
            from .direct_parent_authority import _PARENT_AUTHORITY_DDL
            expected.update(_PARENT_AUTHORITY_DDL)
            automatic.update({"sqlite_autoindex_direct_execution_parents_1",
                              "sqlite_autoindex_direct_execution_parents_2",
                              "sqlite_autoindex_direct_execution_parent_operations_1",
                              "sqlite_autoindex_direct_execution_rollover_evidence_1",
                              "sqlite_autoindex_direct_execution_parent_cancel_targets_1"})
        if schema_version >= 14:
            from .account_observation_journal import _ACCOUNT_FACT_DDL
            from .strategy_financial_ledger import _STRATEGY_FINANCIAL_DDL
            expected.update(_ACCOUNT_FACT_DDL)
            expected.update(_STRATEGY_FINANCIAL_DDL)
            automatic.update({'sqlite_autoindex_account_fact_stream_meta_1',
                              'sqlite_autoindex_account_fact_stream_consumers_1',
                              'sqlite_autoindex_strategy_financial_snapshots_1'})
        if schema_version >= 15:
            from .delegate_actor_stream import _ACTOR_STREAM_DDL
            expected.update(_ACTOR_STREAM_DDL)
            automatic.add('sqlite_autoindex_direct_actor_stream_consumers_1')
        if schema_version >= 16:
            from .direct_strategy_origin import _STRATEGY_ORIGIN_DDL
            expected.update(_STRATEGY_ORIGIN_DDL)
            automatic.update({'sqlite_autoindex_direct_strategy_origins_1', 'sqlite_autoindex_direct_strategy_origins_2'})
        if schema_version >= 17:
            from .direct_control_cancel import _CONTROL_CANCEL_DDL
            expected.update(_CONTROL_CANCEL_DDL)
            automatic.update({'sqlite_autoindex_direct_control_cancel_proofs_1', 'sqlite_autoindex_direct_control_cancel_proofs_2'})
        if schema_version >= 18:
            from .account_fact_consumer_ownership import ACCOUNT_FACT_OWNER_DDL
            from .account_fact_compaction import ACCOUNT_FACT_COMPACTION_DDL
            expected.update(ACCOUNT_FACT_OWNER_DDL)
            expected.update(ACCOUNT_FACT_COMPACTION_DDL)
            automatic.update({'sqlite_autoindex_account_fact_consumer_owners_1',
                              'sqlite_autoindex_account_fact_compaction_meta_1',
                              'sqlite_autoindex_account_fact_compaction_items_1',
                              'sqlite_autoindex_account_fact_compaction_items_2',
                              'sqlite_autoindex_account_fact_snapshot_offers_1'})
        if schema_version >= 19:
            from .account_event_consumer_ownership import ACCOUNT_EVENT_OWNER_DDL
            expected.update(ACCOUNT_EVENT_OWNER_DDL)
            automatic.add('sqlite_autoindex_account_event_consumer_owners_1')
        if release_audit:
            if schema_version < 10:
                raise DirectCommandJournalError("INVALID_DATABASE")
            from .direct_control import _CONTROL_RELEASE_DDL
            expected.update(_CONTROL_RELEASE_DDL)
            automatic.add('sqlite_autoindex_direct_control_releases_1')
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
        self._verify_exact_ddl(db, schema_version, self._control_release_audit)
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

    def _verify_schema(self, db: sqlite3.Connection, *, schema_version: int = 9) -> None:
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
            self._verify_exact_ddl(db, schema_version, self._control_release_audit)
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

    def _assert_release_audit(self, db: sqlite3.Connection) -> None:
        """Name a release audit that differs from the owner's installed option before DDL checks."""
        present = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                             "AND name='direct_control_releases'").fetchone() is not None
        if present != self._control_release_audit:
            raise DirectCommandJournalError("CONTROL_RELEASE_AUDIT_UPGRADE_REQUIRED" if self._control_release_audit
                                            else "CONTROL_RELEASE_AUDIT_MISMATCH")

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

    def settlement_abandon_unsent(
        self, observation: SettlementObservation, marker_id: str,
    ) -> None:
        """Remove one ATTEMPTING marker whose confirmation was never sent.

        Only for the owner that wrote the marker and then failed its final
        claim on the same thread before any provider call: the attempt is
        definitely not in flight, so a later tick may make a new attempt. An
        UNKNOWN or CONFIRMED row, or any identity mismatch, is never removed.
        """
        self._settlement_input(observation, SettlementStatus.UNCONFIRMED)
        marker_id = _text(marker_id)
        with self._transaction() as db:
            row = self._settlement_existing(
                db, observation.exchange_name, observation.trading_day, observation.account_binding
            )
            if (
                row is None
                or row["status"] != "ATTEMPTING"
                or row["marker_id"] != marker_id
                or row["initial_observation_id"] != observation.observation_id
                or row["initial_session_generation"] != observation.session_generation
                or row["owner_generation"] != self._generation
            ):
                raise DirectCommandJournalError("SETTLEMENT_ATTEMPT_MISMATCH")
            db.execute(
                "DELETE FROM direct_journal_settlement WHERE account=? AND exchange_name=? "
                "AND trading_day=? AND status='ATTEMPTING' AND marker_id=?",
                (self._account, observation.exchange_name, observation.trading_day, marker_id),
            )
            self._bump(db)

    def settlement_account_frozen(self) -> bool:
        """Read-only: whether an active account-scope FREEZE control exists."""
        if self._schema_version < 10:
            return False
        with self._connection() as db:
            db.execute("BEGIN")
            try:
                row = db.execute(
                    "SELECT 1 FROM direct_control_causes WHERE account=? AND active=1 "
                    "AND scope_kind='account' AND mode='FREEZE' LIMIT 1",
                    (self._account,),
                ).fetchone()
                return row is not None
            finally:
                if db.in_transaction:
                    db.execute("ROLLBACK")

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
        delegation_permit: object | None = None,
        strategy_origin_permit: object | None = None,
        origin_trading_fence: Callable[[], ContextManager[None]] | None = None,
        before_reservation_commit: Callable[[], None] | None = None,
    ) -> DirectCommandRecord:
        """Create a reservation; repeated keys never renew its original TTL.

        TTL is a first-creation lifecycle option, not part of the payload digest.
        The optional trusted local fence stays held through the SQLite commit;
        it must not perform native or network I/O. Existing keys bypass it.
        The optional owner-provided admission recheck runs inside the same
        transaction after a new insert, and exceptions roll back that insert.
        ``origin_trading_fence`` is the owner's trading fence of a new reservation,
        for the strategy's own (with ``strategy_origin_permit``) or a delegate's
        on its behalf (with ``delegation_permit``); it is entered inside the
        transaction, after an existing key was ruled out.
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
        delegated = None
        if delegation_permit is not None:
            from .direct_delegation import GatewayDelegationPermit
            if type(delegation_permit) is not GatewayDelegationPermit or self._schema_version < 12:
                raise DirectCommandJournalError("DELEGATION_UNAVAILABLE")
            delegated = delegation_permit.command
            if (delegation_permit.operation != "direct.reserve"
                    or delegated.account_scope != self._account
                    or delegated.strategy_scope != strategy or delegated.request_key != request_key
                    or delegated.actor_principal != principal or delegated.payload_digest != digest):
                raise DirectCommandJournalError("DELEGATION_MISMATCH")
        if reservation_fence is not None and not callable(reservation_fence):
            raise DirectCommandJournalError("INVALID_INPUT")
        if before_reservation_commit is not None and not callable(before_reservation_commit):
            raise DirectCommandJournalError("INVALID_INPUT")
        if strategy_origin_permit is not None:
            from .direct_strategy_origin import GatewayStrategyOriginPermit
            if (self._schema_version < 16 or type(strategy_origin_permit) is not GatewayStrategyOriginPermit
                    or delegation_permit is not None or not callable(reservation_fence)):
                raise DirectCommandJournalError('STRATEGY_ORIGIN_UNAVAILABLE')
            origin = strategy_origin_permit.binding
            if (origin.account != self._account or origin.journal_id != self._journal_id
                    or origin.generation != self._generation or origin.strategy != strategy
                    or origin.request_key != request_key or origin.principal != principal or origin.payload_digest != digest):
                raise DirectCommandJournalError('STRATEGY_ORIGIN_MISMATCH')
        # The trading fence of a new reservation: the strategy's own (with its origin permit)
        # or a delegate's on its behalf (G64-09), entered at the same point for both.
        if origin_trading_fence is not None and (
                (strategy_origin_permit is None and delegation_permit is None)
                or not callable(origin_trading_fence)):
            raise DirectCommandJournalError('STRATEGY_ORIGIN_UNAVAILABLE')
        if delegated is not None and reservation_fence is None:
            # The Registry-issued admission must remain held through commit,
            # including an idempotent re-observation of an existing key.
            raise DirectCommandJournalError("DELEGATION_FENCE_REQUIRED")
        needs_capacity_fence = self._unknown_capacity_needed(strategy, payload, existing_key=request_key)
        with ExitStack() as fence_stack, ExitStack() as transaction_stack:
            if delegation_permit is not None or strategy_origin_permit is not None:
                manager = reservation_fence()
                enter, exit_ = type(manager).__enter__, type(manager).__exit__
                enter(manager)
                fence_stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            if needs_capacity_fence:
                self._assert_account_guard(self._unknown_capacity_guard)
                manager = self._unknown_capacity_ports[0]()
                enter, exit_ = type(manager).__enter__, type(manager).__exit__
                enter(manager)
                fence_stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            db = transaction_stack.enter_context(self._transaction())
            if delegation_permit is not None:
                delegation_permit.recheck(db)
            if strategy_origin_permit is not None:
                strategy_origin_permit.recheck(db)
            row = self._find(db, strategy, request_key)
            if row is not None:
                if (
                    row["principal"] != principal
                    or row["digest"] != digest
                    or row["payload_json"] != encoded
                ):
                    raise DirectCommandJournalError("REQUEST_CONFLICT")
                if self._schema_version >= 12:
                    prior = db.execute(
                        "SELECT envelope_json,envelope_digest FROM direct_delegated_commands "
                        "WHERE account=? AND strategy=? AND request_key=?",
                        (self._account, strategy, request_key),
                    ).fetchone()
                    if ((delegated is None) != (prior is None)
                            or (delegated is not None and
                                (prior["envelope_json"] != delegated.canonical_json
                                 or prior["envelope_digest"] != delegated.digest))):
                        raise DirectCommandJournalError("REQUEST_CONFLICT")
                if delegation_permit is not None:
                    delegation_permit.recheck(db)
                if strategy_origin_permit is not None:
                    strategy_origin_permit.recheck(db)
                return self._record(row)
            if self._schema_version >= 16 and delegated is None and strategy_origin_permit is None:
                raise DirectCommandJournalError('STRATEGY_ORIGIN_UNAVAILABLE')
            if origin_trading_fence is not None:
                manager = origin_trading_fence()
                enter, exit_ = type(manager).__enter__, type(manager).__exit__
                enter(manager)
                fence_stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            if self._schema_version >= 10:
                from .direct_control import check_controls
                check_controls(db, self._account, strategy, payload,
                               allow_verified_close=lambda: self._allow_verified_close(db, strategy, payload))
            if reservation_fence is not None and delegated is None and strategy_origin_permit is None:
                manager = reservation_fence()
                # Ignore a context manager's suppression result: a failed
                # transaction must never be reported as a successful reserve.
                enter, exit_ = type(manager).__enter__, type(manager).__exit__
                enter(manager)
                fence_stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            self._check_unknown_scope(db, strategy, payload, capacity_fenced=needs_capacity_fence)
            self._check_strategy_capacity(db, strategy, payload)
            self._assert_monitor_gate(db, strategy, payload)
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
            reservation_id = str(uuid.uuid4())
            db.execute(
                "INSERT INTO direct_journal_commands VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', 1, NULL, NULL)",
                (
                    self._account,
                    strategy,
                    request_key,
                    reservation_id,
                    principal,
                    digest,
                    encoded,
                    self._generation,
                    now + ttl_seconds,
                ),
            )
            if delegated is not None:
                db.execute(
                    "INSERT INTO direct_delegated_commands VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (self._account, strategy, request_key, reservation_id, principal,
                     delegated.canonical_json, delegated.digest),
                )
            if strategy_origin_permit is not None:
                from .direct_strategy_origin import append_strategy_origin
                append_strategy_origin(db, strategy_origin_permit, reservation_id)
            self._bump(db)
            self._check_unknown_scope(db, strategy, payload, exclude_reservation_id=reservation_id, capacity_fenced=needs_capacity_fence)
            self._check_strategy_capacity(db, strategy, payload, exclude_reservation_id=reservation_id)
            if self._schema_version >= 10:
                check_controls(db, self._account, strategy, payload,
                               allow_verified_close=lambda: self._allow_verified_close(
                                   db, strategy, payload, exclude_reservation_id=reservation_id))
            self._assert_monitor_gate(db, strategy, payload, exclude_reservation_id=reservation_id)
            if delegation_permit is not None:
                delegation_permit.recheck(db)
            if strategy_origin_permit is not None:
                strategy_origin_permit.recheck(db)
            result = self._record(self._require(db, strategy, request_key, principal))
            if before_reservation_commit is not None:
                before_reservation_commit()
            return result

    def enable_controls(self, guard: LocalAccountSessionGuard):
        """Explicitly upgrade an audited v9 journal under its live account guard."""
        from .direct_control import _CONTROL_DDL, GatewayDirectControl
        if self._schema_version != 9 or type(guard) is not LocalAccountSessionGuard:
            raise DirectCommandJournalError("CONTROL_UPGRADE_REQUIRED")
        guard.assert_owned()
        if (guard.account_key_digest != hashlib.sha256(self._account.encode("utf-8")).hexdigest()
                or guard.acquire() != self._generation):
            raise DirectCommandJournalError("GUARD_BINDING_MISMATCH")
        with self._transaction() as db:
            self._verify_v2_upgrade_integrity(db, schema_version=9)
            self._verify_v4_identity_integrity(db)
            from .direct_execution_journal import _verify_execution_integrity, _verify_consumer_integrity, _verify_cancel_error_integrity, _verify_place_error_integrity
            from .direct_cancel_journal import _verify_cancel_integrity
            from .direct_place_journal import _verify_place_integrity
            _verify_execution_integrity(db, self._account, self._execution_max_facts)
            _verify_consumer_integrity(db, self._account)
            _verify_cancel_integrity(db, self._account, self._max_records)
            _verify_cancel_error_integrity(db, self._account, self._execution_max_facts)
            _verify_place_integrity(db, self._account, self._max_records)
            _verify_place_error_integrity(db, self, self._execution_max_facts)
            for ddl in _CONTROL_DDL.values():
                db.execute(ddl)
            db.execute("UPDATE direct_journal_meta SET schema_version=10,revision=revision+1 WHERE account=?", (self._account,))
            guard.assert_owned()
        self._schema_version = 10
        return GatewayDirectControl(self, guard)

    def _assert_account_guard(self, guard: LocalAccountSessionGuard) -> None:
        if type(guard) is not LocalAccountSessionGuard:
            raise DirectCommandJournalError("INVALID_GUARD")
        guard.assert_owned()
        if (guard.account_key_digest != hashlib.sha256(self._account.encode("utf-8")).hexdigest()
                or guard.acquire() != self._generation):
            raise DirectCommandJournalError("GUARD_BINDING_MISMATCH")

    def enable_strategy_ledger(self, guard: LocalAccountSessionGuard) -> None:
        """Explicitly add the empty v11 baseline table under the account guard.

        This does not assert an empty account or initialize its baseline.
        The existing v10 journal, including every control row, is fully audited
        inside the upgrade transaction before any DDL is changed.
        """
        if self._schema_version != 10:
            raise DirectCommandJournalError("STRATEGY_LEDGER_UPGRADE_REQUIRED")
        self._assert_account_guard(guard)
        with self._transaction() as db:
            self._verify_v2_upgrade_integrity(db, schema_version=10)
            self._verify_v4_identity_integrity(db)
            from .direct_execution_journal import (
                _verify_cancel_error_integrity, _verify_consumer_integrity,
                _verify_execution_integrity, _verify_place_error_integrity,
            )
            from .direct_cancel_journal import _verify_cancel_integrity
            from .direct_place_journal import _verify_place_integrity
            from .direct_control import verify_controls
            from .strategy_position_ledger import _create_strategy_ledger_tables

            _verify_execution_integrity(db, self._account, self._execution_max_facts)
            _verify_consumer_integrity(db, self._account)
            _verify_cancel_integrity(db, self._account, self._max_records)
            _verify_cancel_error_integrity(db, self._account, self._execution_max_facts)
            _verify_place_integrity(db, self._account, self._max_records)
            _verify_place_error_integrity(db, self, self._execution_max_facts)
            verify_controls(db, self._account, self._max_records)
            self._assert_account_guard(guard)
            _create_strategy_ledger_tables(db)
            db.execute("UPDATE direct_journal_meta SET schema_version=11,revision=revision+1 WHERE account=?", (self._account,))
            self._assert_account_guard(guard)
        self._schema_version = 11

    def enable_account_extensions(self, guard: LocalAccountSessionGuard) -> None:
        """Explicitly upgrade an audited v11 journal; no grant or baseline is created."""
        if self._schema_version != 11:
            raise DirectCommandJournalError("ACCOUNT_EXTENSIONS_UPGRADE_REQUIRED")
        self._assert_account_guard(guard)
        with self._transaction() as db:
            self._verify_v2_upgrade_integrity(db, schema_version=11)
            self._verify_v4_identity_integrity(db)
            from .direct_execution_journal import (
                _verify_cancel_error_integrity, _verify_consumer_integrity,
                _verify_execution_integrity, _verify_place_error_integrity,
            )
            from .direct_cancel_journal import _verify_cancel_integrity
            from .direct_place_journal import _verify_place_integrity
            from .direct_control import verify_controls
            from .strategy_position_ledger import _verify_strategy_ledger_integrity
            from .direct_delegation import _DELEGATION_DDL
            from .external_position_ledger import _EXTERNAL_LEDGER_DDL
            from .account_observer import _ACCOUNT_OBSERVER_DDL

            _verify_execution_integrity(db, self._account, self._execution_max_facts)
            _verify_consumer_integrity(db, self._account)
            _verify_cancel_integrity(db, self._account, self._max_records)
            _verify_cancel_error_integrity(db, self._account, self._execution_max_facts)
            _verify_place_integrity(db, self._account, self._max_records)
            _verify_place_error_integrity(db, self, self._execution_max_facts)
            verify_controls(db, self._account, self._max_records)
            _verify_strategy_ledger_integrity(db, self._account)
            self._assert_account_guard(guard)
            for ddl in (*_DELEGATION_DDL.values(), *_EXTERNAL_LEDGER_DDL.values(), *_ACCOUNT_OBSERVER_DDL.values()):
                db.execute(ddl)
            db.execute("UPDATE direct_journal_meta SET schema_version=12,revision=revision+1 WHERE account=?", (self._account,))
            self._assert_account_guard(guard)
        self._schema_version = 12

    def enable_parent_authority(self, guard: LocalAccountSessionGuard) -> None:
        """Explicitly upgrade an audited v12 journal to an empty parent authority."""
        if self._schema_version != 12:
            raise DirectCommandJournalError("PARENT_AUTHORITY_UPGRADE_REQUIRED")
        self._assert_account_guard(guard)
        with self._transaction() as db:
            self._verify_v2_upgrade_integrity(db, schema_version=12)
            self._verify_v4_identity_integrity(db)
            from .direct_execution_journal import (
                _verify_cancel_error_integrity, _verify_consumer_integrity,
                _verify_execution_integrity, _verify_place_error_integrity,
            )
            from .direct_cancel_journal import _verify_cancel_integrity
            from .direct_place_journal import _verify_place_integrity
            from .direct_control import verify_controls
            from .strategy_position_ledger import _verify_strategy_ledger_integrity
            from .direct_parent_authority import _PARENT_AUTHORITY_DDL

            _verify_execution_integrity(db, self._account, self._execution_max_facts)
            _verify_consumer_integrity(db, self._account)
            _verify_cancel_integrity(db, self._account, self._max_records)
            _verify_cancel_error_integrity(db, self._account, self._execution_max_facts)
            _verify_place_integrity(db, self._account, self._max_records)
            _verify_place_error_integrity(db, self, self._execution_max_facts)
            verify_controls(db, self._account, self._max_records)
            _verify_strategy_ledger_integrity(db, self._account)
            self._assert_account_guard(guard)
            for ddl in _PARENT_AUTHORITY_DDL.values():
                db.execute(ddl)
            db.execute("UPDATE direct_journal_meta SET schema_version=13,revision=revision+1 WHERE account=?", (self._account,))
            self._assert_account_guard(guard)
        self._schema_version = 13

    def enable_account_facts_financial(self, guard: LocalAccountSessionGuard) -> None:
        """Explicit v13 upgrade; bootstrap current facts, never fabricate prior history."""
        if self._schema_version != 13:
            raise DirectCommandJournalError('ACCOUNT_FACTS_FINANCIAL_UPGRADE_REQUIRED')
        self._assert_account_guard(guard)
        with self._transaction() as db:
            self._verify_v2_upgrade_integrity(db, schema_version=13)
            self._verify_v4_identity_integrity(db)
            from .direct_execution_journal import (_verify_cancel_error_integrity, _verify_consumer_integrity,
                _verify_execution_integrity, _verify_place_error_integrity)
            from .direct_cancel_journal import _verify_cancel_integrity
            from .direct_place_journal import _verify_place_integrity
            from .direct_control import verify_controls
            from .strategy_position_ledger import _verify_strategy_ledger_integrity
            from .account_observation_journal import initialize_account_fact_stream
            from .strategy_financial_ledger import _create_strategy_financial_tables
            _verify_execution_integrity(db, self._account, self._execution_max_facts)
            _verify_consumer_integrity(db, self._account)
            _verify_cancel_integrity(db, self._account, self._max_records)
            _verify_cancel_error_integrity(db, self._account, self._execution_max_facts)
            _verify_place_integrity(db, self._account, self._max_records)
            _verify_place_error_integrity(db, self, self._execution_max_facts)
            verify_controls(db, self._account, self._max_records)
            _verify_strategy_ledger_integrity(db, self._account)
            self._assert_account_guard(guard)
            initialize_account_fact_stream(db, self._account, self._journal_id)
            _create_strategy_financial_tables(db)
            db.execute('UPDATE direct_journal_meta SET schema_version=14,revision=revision+1 WHERE account=?', (self._account,))
            self._assert_account_guard(guard)
        self._schema_version = 14

    def enable_actor_stream(self, guard: LocalAccountSessionGuard) -> None:
        """Explicit v14 upgrade; actor cursors are independent of all existing streams."""
        if self._schema_version != 14:
            raise DirectCommandJournalError('ACTOR_STREAM_UPGRADE_REQUIRED')
        self._assert_account_guard(guard)
        with self._transaction() as db:
            self._verify_v2_upgrade_integrity(db, schema_version=14)
            self._verify_v4_identity_integrity(db)
            from .direct_execution_journal import (_verify_cancel_error_integrity, _verify_consumer_integrity,
                _verify_execution_integrity, _verify_place_error_integrity)
            from .direct_cancel_journal import _verify_cancel_integrity
            from .direct_place_journal import _verify_place_integrity
            from .delegate_actor_stream import _ACTOR_STREAM_DDL
            _verify_execution_integrity(db, self._account, self._execution_max_facts)
            _verify_consumer_integrity(db, self._account)
            _verify_cancel_integrity(db, self._account, self._max_records)
            _verify_cancel_error_integrity(db, self._account, self._execution_max_facts)
            _verify_place_integrity(db, self._account, self._max_records)
            _verify_place_error_integrity(db, self, self._execution_max_facts)
            self._assert_account_guard(guard)
            for ddl in _ACTOR_STREAM_DDL.values():
                db.execute(ddl)
            db.execute('UPDATE direct_journal_meta SET schema_version=15,revision=revision+1 WHERE account=?', (self._account,))
            self._assert_account_guard(guard)
        self._schema_version = 15

    def enable_strategy_origin(self, guard: LocalAccountSessionGuard) -> None:
        """Explicit v15 upgrade; historical strategy identities remain unproven."""
        if self._schema_version != 15:
            raise DirectCommandJournalError('STRATEGY_ORIGIN_UPGRADE_REQUIRED')
        self._assert_account_guard(guard)
        with self._transaction() as db:
            self._verify_v2_upgrade_integrity(db, schema_version=15)
            self._verify_v4_identity_integrity(db)
            from .direct_execution_journal import (_verify_cancel_error_integrity, _verify_consumer_integrity,
                _verify_execution_integrity, _verify_place_error_integrity)
            from .direct_cancel_journal import _verify_cancel_integrity
            from .direct_place_journal import _verify_place_integrity
            from .direct_strategy_origin import _STRATEGY_ORIGIN_DDL
            _verify_execution_integrity(db, self._account, self._execution_max_facts)
            _verify_consumer_integrity(db, self._account)
            _verify_cancel_integrity(db, self._account, self._max_records)
            _verify_cancel_error_integrity(db, self._account, self._execution_max_facts)
            _verify_place_integrity(db, self._account, self._max_records)
            _verify_place_error_integrity(db, self, self._execution_max_facts)
            self._assert_account_guard(guard)
            for ddl in _STRATEGY_ORIGIN_DDL.values():
                db.execute(ddl)
            db.execute('UPDATE direct_journal_meta SET schema_version=16,revision=revision+1 WHERE account=?', (self._account,))
            self._assert_account_guard(guard)
        self._schema_version = 16

    def enable_control_cancel(self, guard: LocalAccountSessionGuard) -> None:
        """Explicit v16 upgrade; existing UNKNOWN claims are not retried."""
        if self._schema_version != 16:
            raise DirectCommandJournalError('CONTROL_CANCEL_UPGRADE_REQUIRED')
        self._assert_account_guard(guard)
        with self._transaction() as db:
            self._verify_v2_upgrade_integrity(db, schema_version=16)
            self._verify_v4_identity_integrity(db)
            from .direct_execution_journal import (_verify_cancel_error_integrity, _verify_consumer_integrity,
                _verify_execution_integrity, _verify_place_error_integrity)
            from .direct_cancel_journal import _verify_cancel_integrity
            from .direct_place_journal import _verify_place_integrity
            from .direct_control_cancel import _CONTROL_CANCEL_DDL
            _verify_execution_integrity(db, self._account, self._execution_max_facts)
            _verify_consumer_integrity(db, self._account)
            _verify_cancel_integrity(db, self._account, self._max_records)
            _verify_cancel_error_integrity(db, self._account, self._execution_max_facts)
            _verify_place_integrity(db, self._account, self._max_records)
            _verify_place_error_integrity(db, self, self._execution_max_facts)
            self._assert_account_guard(guard)
            for ddl in _CONTROL_CANCEL_DDL.values():
                db.execute(ddl)
            db.execute('UPDATE direct_journal_meta SET schema_version=17,revision=revision+1 WHERE account=?', (self._account,))
            self._assert_account_guard(guard)
        self._schema_version = 17

    def enable_account_fact_recovery(self, guard: LocalAccountSessionGuard) -> None:
        """Explicit v17 upgrade; retain all existing observations and ACKs."""
        if self._schema_version != 17:
            raise DirectCommandJournalError('ACCOUNT_FACT_RECOVERY_UPGRADE_REQUIRED')
        self._assert_account_guard(guard)
        with self._transaction() as db:
            self._verify_v2_upgrade_integrity(db, schema_version=17)
            self._verify_v4_identity_integrity(db)
            from .direct_execution_journal import (_verify_cancel_error_integrity, _verify_consumer_integrity,
                _verify_execution_integrity, _verify_place_error_integrity)
            from .direct_cancel_journal import _verify_cancel_integrity
            from .direct_place_journal import _verify_place_integrity
            from .account_fact_consumer_ownership import ACCOUNT_FACT_OWNER_DDL
            from .account_fact_compaction import initialize_account_fact_compaction
            _verify_execution_integrity(db, self._account, self._execution_max_facts)
            _verify_consumer_integrity(db, self._account)
            _verify_cancel_integrity(db, self._account, self._max_records)
            _verify_cancel_error_integrity(db, self._account, self._execution_max_facts)
            _verify_place_integrity(db, self._account, self._max_records)
            _verify_place_error_integrity(db, self, self._execution_max_facts)
            self._assert_account_guard(guard)
            initialize_account_fact_compaction(db, self._account, self._journal_id)
            for ddl in ACCOUNT_FACT_OWNER_DDL.values():
                db.execute(ddl)
            db.execute('UPDATE direct_journal_meta SET schema_version=18,revision=revision+1 WHERE account=?', (self._account,))
            self._assert_account_guard(guard)
        self._schema_version = 18

    def enable_account_event_recovery(self, guard: LocalAccountSessionGuard) -> None:
        """Explicit v18 upgrade; preserve prior event offers and durable ACKs."""
        if self._schema_version != 18:
            raise DirectCommandJournalError('ACCOUNT_EVENT_RECOVERY_UPGRADE_REQUIRED')
        self._assert_account_guard(guard)
        with self._transaction() as db:
            self._verify_v2_upgrade_integrity(db, schema_version=18)
            self._verify_v4_identity_integrity(db)
            from .direct_execution_journal import (_verify_cancel_error_integrity, _verify_consumer_integrity,
                _verify_execution_integrity, _verify_place_error_integrity)
            from .direct_cancel_journal import _verify_cancel_integrity
            from .direct_place_journal import _verify_place_integrity
            from .account_event_consumer_ownership import ACCOUNT_EVENT_OWNER_DDL
            _verify_execution_integrity(db, self._account, self._execution_max_facts)
            _verify_consumer_integrity(db, self._account)
            _verify_cancel_integrity(db, self._account, self._max_records)
            _verify_cancel_error_integrity(db, self._account, self._execution_max_facts)
            _verify_place_integrity(db, self._account, self._max_records)
            _verify_place_error_integrity(db, self, self._execution_max_facts)
            self._assert_account_guard(guard)
            for ddl in ACCOUNT_EVENT_OWNER_DDL.values():
                db.execute(ddl)
            db.execute('UPDATE direct_journal_meta SET schema_version=19,revision=revision+1 WHERE account=?', (self._account,))
            self._assert_account_guard(guard)
        self._schema_version = 19

    def enable_control_release_audit(self, guard: LocalAccountSessionGuard) -> None:
        """Explicit one-way upgrade: store who releases each control cause (schema 10 or later).

        The audit does not depend on the features of the schemas after 10, so it
        does not move the schema version and turns none of them on: a journal at
        any version from 10 on takes it as it is. Opening the journal afterwards
        requires ``control_release_audit_enabled=True``; it cannot be removed.

        A cause released before this upgrade gets its release record without a
        releaser: who released it was not stored then and is not invented now.
        The whole journal is verified inside the upgrade transaction first.
        """
        if self._schema_version < 10:
            raise DirectCommandJournalError("CONTROL_UPGRADE_REQUIRED")
        if self._control_release_audit:
            raise DirectCommandJournalError("CONTROL_RELEASE_AUDIT_ALREADY_ENABLED")
        self._assert_account_guard(guard)
        with self._transaction() as db:
            self._verify_v2_upgrade_integrity(db, schema_version=self._schema_version)
            self._verify_v4_identity_integrity(db)
            from .direct_cancel_journal import _verify_cancel_integrity
            from .direct_control import _CONTROL_RELEASE_DDL, verify_controls
            from .direct_execution_journal import (
                _verify_cancel_error_integrity,
                _verify_consumer_integrity,
                _verify_execution_integrity,
                _verify_place_error_integrity,
            )
            from .direct_place_journal import _verify_place_integrity
            _verify_execution_integrity(db, self._account, self._execution_max_facts)
            _verify_consumer_integrity(db, self._account)
            _verify_cancel_integrity(db, self._account, self._max_records)
            _verify_cancel_error_integrity(db, self._account, self._execution_max_facts)
            _verify_place_integrity(db, self._account, self._max_records)
            _verify_place_error_integrity(db, self, self._execution_max_facts)
            self._verify_history(db)
            self._assert_account_guard(guard)
            for ddl in _CONTROL_RELEASE_DDL.values():
                db.execute(ddl)
            db.execute("INSERT INTO direct_control_releases SELECT account,cause_id,resume_id,NULL "
                       "FROM direct_control_causes WHERE account=? AND active=0", (self._account,))
            verify_controls(db, self._account, self._max_records)
            self._bump(db)
            self._assert_account_guard(guard)
        self._control_release_audit = True

    def install_monitor_gate(self, gate: Callable[[], bool], *, guard: LocalAccountSessionGuard) -> None:
        """Install the required-monitor owner's local, nonblocking write gate.

        Never pass a wire request callback here. Once installed, the same
        callable cannot be replaced to silently bypass a failed required gate.
        """
        self._assert_account_guard(guard)
        if not callable(gate):
            raise DirectCommandJournalError("INVALID_INPUT")
        if self._monitor_gate is not None:
            if self._monitor_gate is not gate or self._monitor_guard is not guard:
                raise DirectCommandJournalError("MONITOR_GATE_ALREADY_BOUND")
            return
        self._monitor_gate, self._monitor_guard = gate, guard

    def _assert_monitor_gate(self, db: sqlite3.Connection, strategy: str, payload: object,
                             *, exclude_reservation_id: str | None = None) -> None:
        if self._monitor_gate is None:
            return
        self._assert_account_guard(self._monitor_guard)
        try:
            allowed = self._monitor_gate()
        except Exception:
            allowed = False
        if allowed is not True and not self._allow_verified_close(
                db, strategy, payload, exclude_reservation_id=exclude_reservation_id):
            raise DirectCommandJournalError("CONTROL_STOP_NEW")

    def install_strategy_ledger_ports(
        self, *, guard: LocalAccountSessionGuard, resolve_binding: Callable,
        current_trading_day: Callable, verify_day_transition: Callable,
        verify_current_continuity: Callable, verify_external_current: Callable | None = None,
    ) -> None:
        """Bind trusted local contract/day authorities to this account owner.

        These callbacks must be nonblocking local checks; they may not perform
        network or provider I/O while the SQLite write transaction is held.
        """
        if self._schema_version < 11:
            raise DirectCommandJournalError("STRATEGY_LEDGER_UPGRADE_REQUIRED")
        if verify_external_current is not None and self._schema_version < 12:
            raise DirectCommandJournalError("ACCOUNT_EXTENSIONS_UPGRADE_REQUIRED")
        self._assert_account_guard(guard)
        ports = (resolve_binding, current_trading_day, verify_day_transition, verify_current_continuity)
        if (not all(callable(port) for port in ports)
                or (verify_external_current is not None and not callable(verify_external_current))):
            raise DirectCommandJournalError("INVALID_INPUT")
        if self._strategy_ledger_ports is not None:
            if (any(old is not new for old, new in zip(self._strategy_ledger_ports, ports))
                    or self._strategy_ledger_guard is not guard
                    or self._strategy_external_verifier is not verify_external_current):
                raise DirectCommandJournalError("STRATEGY_LEDGER_ALREADY_BOUND")
            return
        self._strategy_ledger_ports, self._strategy_ledger_guard = ports, guard
        self._strategy_external_verifier = verify_external_current

    def initialize_empty_strategy_ledger(
        self, evidence: object, *, guard: LocalAccountSessionGuard,
        baseline_fence: Callable[[], ContextManager[None]], verify_current_empty: Callable,
    ) -> None:
        """Initialize once under a trusted same-cut provider fence held to commit.

        A verified empty result must cover the entire account's positions and
        open orders. No installed provider verifier currently supplies that
        proof; clients and configuration cannot supply this authority.
        """
        if self._schema_version < 11 or not callable(baseline_fence):
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
        self._assert_account_guard(guard)
        from .strategy_position_ledger import StrategyBaselineEvidence, initialize_empty_strategy_baseline
        if (type(evidence) is not StrategyBaselineEvidence or evidence.account_scope != self._account
                or evidence.journal_id != self._journal_id or evidence.owner_generation != self._generation):
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
        with ExitStack() as fence_stack, self._transaction() as db:
            manager = baseline_fence()
            enter, exit_ = type(manager).__enter__, type(manager).__exit__
            enter(manager)
            fence_stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            before = db.execute("SELECT 1 FROM strategy_position_baseline WHERE account=?", (self._account,)).fetchone()
            initialize_empty_strategy_baseline(db, evidence, verify_current_empty=verify_current_empty)
            if before is None:
                self._bump(db)
            self._assert_account_guard(guard)

    def initialize_external_strategy_ledger(
        self, evidence: object, *, guard: LocalAccountSessionGuard,
        baseline_fence: Callable[[], ContextManager[None]], verify_authorized_snapshot: Callable,
    ) -> None:
        """Install operator-authorized external holdings under the owner fence.

        The installed verifier must authenticate the operator and the complete
        provider snapshot at one comparable cut, held until transaction commit.
        """
        if self._schema_version < 11 or not callable(baseline_fence):
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
        self._assert_account_guard(guard)
        from .strategy_position_ledger import StrategyBaselineEvidence, initialize_external_strategy_baseline
        if (type(evidence) is not StrategyBaselineEvidence or evidence.account_scope != self._account
                or evidence.journal_id != self._journal_id or evidence.owner_generation != self._generation):
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
        with ExitStack() as fence_stack, self._transaction() as db:
            manager = baseline_fence()
            enter, exit_ = type(manager).__enter__, type(manager).__exit__
            enter(manager)
            fence_stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            before = db.execute("SELECT 1 FROM strategy_position_baseline WHERE account=?", (self._account,)).fetchone()
            initialize_external_strategy_baseline(db, evidence, verify_authorized_snapshot=verify_authorized_snapshot)
            if before is None:
                self._bump(db)
            self._assert_account_guard(guard)

    def initialize_replayed_strategy_ledger(
        self, evidence: object, *, guard: LocalAccountSessionGuard,
        baseline_fence: Callable[[], ContextManager[None]], verify_current_snapshot: Callable,
    ) -> None:
        """Adopt this journal's own settled history as the ledger origin (I63-E111).

        Requires the installed ledger ports. The trusted verifier attests the
        provider's complete position and empty open-order snapshot at one
        comparable cut, held until transaction commit; the replay comparison
        itself is done by the ledger on this transaction.
        """
        if (self._schema_version < 11 or not callable(baseline_fence)
                or self._strategy_ledger_ports is None or guard is not self._strategy_ledger_guard):
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
        self._assert_account_guard(guard)
        from .strategy_position_ledger import StrategyBaselineEvidence, initialize_replayed_strategy_baseline
        if (type(evidence) is not StrategyBaselineEvidence or evidence.account_scope != self._account
                or evidence.journal_id != self._journal_id or evidence.owner_generation != self._generation):
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
        resolve_binding, _, verify_transition, verify_continuity = self._strategy_ledger_ports
        with ExitStack() as fence_stack, self._transaction() as db:
            manager = baseline_fence()
            enter, exit_ = type(manager).__enter__, type(manager).__exit__
            enter(manager)
            fence_stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            before = db.execute("SELECT 1 FROM strategy_position_baseline WHERE account=?", (self._account,)).fetchone()
            initialize_replayed_strategy_baseline(
                db, evidence, resolve_binding=resolve_binding, verify_day_transition=verify_transition,
                verify_current_continuity=verify_continuity, verify_current_snapshot=verify_current_snapshot)
            if before is None:
                self._bump(db)
            self._assert_account_guard(guard)

    def read_strategy_ledger_state(self, *, guard: LocalAccountSessionGuard) -> dict:
        """Report whether a baseline exists and whether the journal has history.

        Owner-local and read-only; the result is a description, not a proof.
        ``earliest_trade_day`` is the first trading day of an applied trade.
        """
        if self._schema_version < 11:
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
        self._assert_account_guard(guard)
        from .strategy_position_ledger import _decode_fact
        with self._transaction() as db:
            baseline = db.execute(
                "SELECT evidence_json FROM strategy_position_baseline WHERE account=?", (self._account,)).fetchone()
            history = any(
                db.execute(f"SELECT 1 FROM {table} WHERE account=? LIMIT 1", (self._account,)).fetchone() is not None
                for table in ("direct_journal_commands", "direct_execution_facts"))
            earliest = None
            if baseline is None and history:
                for raw, in db.execute(
                        "SELECT fact_json FROM direct_execution_facts WHERE account=? AND applied=1", (self._account,)):
                    day = _decode_fact(raw).trading_day
                    if earliest is None or day < earliest:
                        earliest = day
            return {"baseline": None if baseline is None else json.loads(baseline[0]),
                    "history_present": history, "earliest_trade_day": earliest}

    def install_unknown_close_capacity(self, *, guard: LocalAccountSessionGuard, source_fence: Callable,
                                       verify_other_close_capacity: Callable):
        """Install owner-only same-cut proof; an absent proof conservatively blocks."""
        if not callable(source_fence) or not callable(verify_other_close_capacity):
            raise DirectCommandJournalError('UNKNOWN_SCOPE_UNAVAILABLE')
        self._assert_account_guard(guard)
        ports = (source_fence, verify_other_close_capacity)
        if self._unknown_capacity_ports is not None:
            if self._unknown_capacity_ports != ports or self._unknown_capacity_guard is not guard:
                raise DirectCommandJournalError('UNKNOWN_SCOPE_ALREADY_BOUND')
            return
        self._unknown_capacity_ports, self._unknown_capacity_guard = ports, guard

    def _unknown_capacity_needed(self, strategy, payload, *, existing_key=None, exclude_reservation_id=None):
        if (self._unknown_capacity_ports is None or type(payload) is not dict
                or payload.get('offset') not in {'close', 'close_today', 'close_yesterday'}):
            return False
        with self._transaction() as db:
            if existing_key is not None and self._find(db, strategy, existing_key) is not None:
                return False
            try:
                self._check_unknown_scope(db, strategy, payload, exclude_reservation_id=exclude_reservation_id)
            except DirectCommandJournalError as exc:
                if exc.code == 'SYSTEM_ORDER_UNKNOWN':
                    return True
                raise
        return False

    def _check_unknown_scope(self, db, strategy, payload, *, exclude_reservation_id=None, capacity_fenced=False):
        from .unknown_order_scope import check_unknown_order_scope
        resolver = None if self._strategy_ledger_ports is None else self._strategy_ledger_ports[0]
        verifier = None
        if capacity_fenced:
            self._assert_account_guard(self._unknown_capacity_guard)
            verifier = self._unknown_capacity_ports[1]
        check_unknown_order_scope(db, self._account, strategy, payload, resolve_binding=resolver,
                                  exclude_reservation_id=exclude_reservation_id,
                                  verify_other_close_capacity=verifier)

    def _check_strategy_capacity(self, db: sqlite3.Connection, strategy: str, payload: object,
                                 *, exclude_reservation_id: str | None = None) -> None:
        if self._schema_version < 11:
            return
        if type(payload) is not dict:
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
        offset = payload.get("offset")
        if offset == "open":
            return
        if offset not in {"close", "close_today", "close_yesterday"} or self._strategy_ledger_ports is None:
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
        self._assert_account_guard(self._strategy_ledger_guard)
        resolve_binding, current_day, verify_transition, verify_continuity = self._strategy_ledger_ports
        try:
            binding = resolve_binding(payload)
            day = current_day()
        except Exception as exc:
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc
        from .strategy_position_ledger import check_strategy_close
        check_strategy_close(db, self._account, strategy, payload, trading_day=day,
                             instrument_binding=binding, resolve_binding=resolve_binding,
                             verify_day_transition=verify_transition,
                             verify_current_continuity=verify_continuity,
                             verify_external_current=self._strategy_external_verifier,
                             exclude_reservation_id=exclude_reservation_id)

    def _allow_verified_close(self, db: sqlite3.Connection, strategy: str, payload: object,
                              *, exclude_reservation_id: str | None = None) -> bool:
        """A request label alone cannot qualify for a STOP_NEW exception."""
        if (self._schema_version < 11 or self._strategy_ledger_ports is None
                or type(payload) is not dict
                or payload.get("offset") not in {"close", "close_today", "close_yesterday"}):
            return False
        self._check_strategy_capacity(db, strategy, payload,
                                      exclude_reservation_id=exclude_reservation_id)
        return True

    def record_verified_external_fact(
        self, fact_digest: str, evidence: object, *, guard: LocalAccountSessionGuard,
        source_fence: Callable[[], ContextManager[None]], verify_source_and_exclusion: Callable,
    ) -> bool:
        """Record a classified external fact under an installed owner's source fence.

        Never expose the callbacks or evidence authority to an RPC peer.
        """
        from .external_position_ledger import ExternalFactEvidence, record_external_fact
        if (self._schema_version < 12 or type(evidence) is not ExternalFactEvidence
                or evidence.account_scope != self._account or evidence.journal_id != self._journal_id
                or evidence.owner_generation != self._generation or not callable(source_fence)
                or not callable(verify_source_and_exclusion)):
            raise DirectCommandJournalError("EXTERNAL_LEDGER_UNAVAILABLE")
        self._assert_account_guard(guard)
        with ExitStack() as stack:
            manager = source_fence()
            enter, exit_ = type(manager).__enter__, type(manager).__exit__
            enter(manager)
            stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            db = stack.enter_context(self._transaction())
            changed = record_external_fact(db, self._account, fact_digest, evidence,
                                           verify_source_and_exclusion=verify_source_and_exclusion)
            if changed:
                if self._schema_version >= 14:
                    from .account_observation_journal import append_account_fact
                    append_account_fact(db, self._account, fact_digest)
                self._bump(db)
            self._assert_account_guard(guard)
            return changed

    def install_account_comparison_ports(
        self, *, guard: LocalAccountSessionGuard, source_fence: Callable,
        read_account_cut: Callable, verify_account_cut: Callable,
        verify_external_current: Callable, verify_external_cut_current: Callable,
    ) -> None:
        """Install nonblocking trusted owner ports; this grants no network ACL."""
        if self._schema_version < 12:
            raise DirectCommandJournalError("ACCOUNT_EXTENSIONS_UPGRADE_REQUIRED")
        self._assert_account_guard(guard)
        ports = (source_fence, read_account_cut, verify_account_cut,
                 verify_external_current, verify_external_cut_current)
        if not all(callable(port) for port in ports):
            raise DirectCommandJournalError("INVALID_INPUT")
        if self._account_comparison_ports is not None:
            if (any(old is not new for old, new in zip(self._account_comparison_ports, ports))
                    or self._account_comparison_guard is not guard):
                raise DirectCommandJournalError("ACCOUNT_COMPARISON_ALREADY_BOUND")
            return
        self._account_comparison_ports, self._account_comparison_guard = ports, guard

    def install_strategy_financial_port(self, *, guard: LocalAccountSessionGuard, source_fence: Callable) -> None:
        """Install a trusted same-cut source fence; remote values are not authority."""
        if self._schema_version < 14 or not callable(source_fence):
            raise DirectCommandJournalError('STRATEGY_FINANCIAL_UNAVAILABLE')
        self._assert_account_guard(guard)
        if self._strategy_financial_port is not None:
            if self._strategy_financial_port is not source_fence or self._strategy_financial_guard is not guard:
                raise DirectCommandJournalError('STRATEGY_FINANCIAL_ALREADY_BOUND')
            return
        self._strategy_financial_port, self._strategy_financial_guard = source_fence, guard

    def append_strategy_financial(self, snapshot, *, guard: LocalAccountSessionGuard) -> bool:
        from .strategy_financial_ledger import StrategyFinancialSnapshot, append_financial_snapshot
        if (self._schema_version < 14 or self._strategy_financial_port is None
                or guard is not self._strategy_financial_guard or type(snapshot) is not StrategyFinancialSnapshot
                or snapshot.account != self._account or snapshot.journal_id != self._journal_id
                or snapshot.owner_generation != self._generation):
            raise DirectCommandJournalError('STRATEGY_FINANCIAL_UNAVAILABLE')
        self._assert_account_guard(guard)
        with ExitStack() as stack:
            manager = self._strategy_financial_port(self._account, snapshot.strategy, snapshot.currency)
            check = type(manager).__enter__(manager)
            exit_ = type(manager).__exit__
            stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            if not callable(check):
                raise DirectCommandJournalError('STRATEGY_FINANCIAL_UNAVAILABLE')
            db = stack.enter_context(self._transaction())
            changed = append_financial_snapshot(db, snapshot, verify_current=check)
            if check(db, snapshot) is not True:
                raise DirectCommandJournalError('STRATEGY_FINANCIAL_UNAVAILABLE')
            if changed:
                self._bump(db)
            self._assert_account_guard(guard)
            return changed

    def read_strategy_financial(self, strategy: str, currency: str, *, admission_fence: Callable):
        from .strategy_financial_ledger import read_financial_snapshot
        strategy, currency = _text(strategy), _text(currency)
        if self._schema_version < 14 or self._strategy_financial_port is None or not callable(admission_fence):
            raise DirectCommandJournalError('STRATEGY_FINANCIAL_UNAVAILABLE')
        self._assert_account_guard(self._strategy_financial_guard)
        with ExitStack() as stack:
            authority = admission_fence()
            auth_check = type(authority).__enter__(authority)
            auth_exit = type(authority).__exit__
            stack.push(lambda *exc: (auth_exit(authority, *exc), False)[1])
            source = self._strategy_financial_port(self._account, strategy, currency)
            check = type(source).__enter__(source)
            source_exit = type(source).__exit__
            stack.push(lambda *exc: (source_exit(source, *exc), False)[1])
            if not callable(auth_check) or not callable(check):
                raise DirectCommandJournalError('STRATEGY_FINANCIAL_UNAVAILABLE')
            db = stack.enter_context(self._transaction())
            auth_check()
            result = read_financial_snapshot(db, self._account, strategy, currency, verify_current=check)
            if result.owner_generation != self._generation or check(db, result) is not True:
                raise DirectCommandJournalError('STRATEGY_FINANCIAL_UNAVAILABLE')
            auth_check()
            self._assert_account_guard(self._strategy_financial_guard)
            return result

    def read_account_net_comparison(self, instrument: object):
        """Compare one instrument at a provable current cut, otherwise UNAVAILABLE.

        The installed local port, never a wire request, supplies account quantity
        and cut. A service must separately authorize this account-wide view.
        """
        from decimal import Decimal
        from bt_api_base.market_protocol import MarketInstrumentKey
        from .external_position_ledger import external_net
        from .strategy_position_ledger import StrategyInstrumentBinding, StrategyNetComparison, compare_account_net

        unavailable = StrategyNetComparison("UNAVAILABLE", None, None, None, None, None)
        if (type(instrument) is not MarketInstrumentKey or self._schema_version < 12
                or self._strategy_ledger_ports is None or self._account_comparison_ports is None):
            return unavailable
        fence, read_cut, verify_account, verify_external, verify_external_cut = self._account_comparison_ports
        resolve_binding, _, verify_transition, verify_continuity = self._strategy_ledger_ports
        try:
            self._assert_account_guard(self._account_comparison_guard)
            with ExitStack() as stack:
                manager = fence()
                enter, exit_ = type(manager).__enter__, type(manager).__exit__
                enter(manager)
                stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
                db = stack.enter_context(self._transaction())
                current = read_cut(db, self._account, instrument)
                if type(current) is not tuple or len(current) != 4:
                    return unavailable
                binding, day, cut, account_net = current
                if type(binding) is not StrategyInstrumentBinding or binding.instrument != instrument:
                    return unavailable
                external = external_net(db, self._account, instrument, trading_day=day, cut=cut,
                                        verify_current=verify_external_cut)

                def verify_external_value(db_, account_, binding_, day_, cut_, expected_):
                    actual = external_net(db_, account_, binding_.instrument, trading_day=day_, cut=cut_,
                                          verify_current=verify_external_cut)
                    return actual == Decimal(expected_)

                result = compare_account_net(db, self._account, binding, trading_day=day,
                    account_net=account_net, external_net=format(external, "f"), cut=cut,
                    resolve_binding=resolve_binding, verify_day_transition=verify_transition,
                    verify_current_continuity=verify_continuity, verify_account_cut=verify_account,
                    verify_external_cut=verify_external_value, verify_external_current=verify_external)
                if read_cut(db, self._account, instrument) != current:
                    return unavailable
                self._assert_account_guard(self._account_comparison_guard)
                return result
        except Exception:
            return unavailable

    def read_external_net(self, instrument: object):
        """The ``external`` book of one instrument at a provable current cut (G64-06).

        Returns ``(trading_day, cut, net quantity)`` read with the installed account
        comparison ports, as ``read_account_net_comparison`` reads it, or raises
        ``STRATEGY_LEDGER_UNAVAILABLE``. A service must separately authorize this
        account-wide view; this method grants no ACL.
        """
        from bt_api_base.market_protocol import MarketInstrumentKey

        from .external_position_ledger import external_net
        from .strategy_position_ledger import StrategyInstrumentBinding

        if (type(instrument) is not MarketInstrumentKey or self._schema_version < 12
                or self._strategy_ledger_ports is None or self._account_comparison_ports is None):
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
        fence, read_cut, _, _, verify_external_cut = self._account_comparison_ports
        try:
            self._assert_account_guard(self._account_comparison_guard)
            with ExitStack() as stack:
                manager = fence()
                enter, exit_ = type(manager).__enter__, type(manager).__exit__
                enter(manager)
                stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
                db = stack.enter_context(self._transaction())
                current = read_cut(db, self._account, instrument)
                if type(current) is not tuple or len(current) != 4:
                    raise ValueError("CUT_UNAVAILABLE")
                binding, day, cut, _ = current
                if type(binding) is not StrategyInstrumentBinding or binding.instrument != instrument:
                    raise ValueError("CUT_UNAVAILABLE")
                quantity = external_net(db, self._account, instrument, trading_day=day, cut=cut,
                                        verify_current=verify_external_cut)
                if read_cut(db, self._account, instrument) != current:
                    raise ValueError("CUT_CHANGED")
                self._assert_account_guard(self._account_comparison_guard)
                return day, cut, quantity
        except Exception as exc:
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc

    def read_strategy_position(self, strategy: str, payload: dict, *, expected_instrument: object):
        """Read an owner-resolved strategy position; this method grants no ACL.

        The service caller must derive ``strategy`` from its authenticated
        principal and verify visibility before invoking it.  The trusted local
        resolver, rather than payload labels, identifies the full instrument.
        """
        from bt_api_base.market_protocol import MarketInstrumentKey
        from .strategy_position_ledger import StrategyInstrumentBinding
        if (self._schema_version < 11 or self._strategy_ledger_ports is None
                or type(payload) is not dict or type(expected_instrument) is not MarketInstrumentKey):
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
        strategy = _text(strategy)
        self._assert_account_guard(self._strategy_ledger_guard)
        resolve_binding, current_day, verify_transition, verify_continuity = self._strategy_ledger_ports
        try:
            binding = resolve_binding(payload)
            day = current_day()
        except Exception as exc:
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc
        if type(binding) is not StrategyInstrumentBinding or binding.instrument != expected_instrument:
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
        from .strategy_position_ledger import _resolve, strategy_position
        with self._transaction() as db:
            if not _resolve(payload, binding, resolve_binding):
                raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
            result = strategy_position(db, self._account, strategy, binding, trading_day=day,
                                       resolve_binding=resolve_binding,
                                       verify_day_transition=verify_transition,
                                       verify_current_continuity=verify_continuity,
                                       verify_external_current=self._strategy_external_verifier)
            try:
                unchanged = (current_day() == day and resolve_binding(payload) == binding
                             and binding.instrument == expected_instrument)
            except Exception as exc:
                raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc
            if not unchanged:
                raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
            self._assert_account_guard(self._strategy_ledger_guard)
            return result

    def read_strategy_close_capacity(self, strategy: str, payload: dict, *, expected_instrument: object):
        """Read own-strategy close capacity without reserving it or granting ACL."""
        from bt_api_base.market_protocol import MarketInstrumentKey
        from .strategy_position_ledger import StrategyInstrumentBinding
        if (self._schema_version < 11 or self._strategy_ledger_ports is None
                or type(payload) is not dict or type(expected_instrument) is not MarketInstrumentKey):
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
        strategy = _text(strategy)
        self._assert_account_guard(self._strategy_ledger_guard)
        resolve_binding, current_day, verify_transition, verify_continuity = self._strategy_ledger_ports
        try:
            binding = resolve_binding(payload)
            day = current_day()
        except Exception as exc:
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc
        if type(binding) is not StrategyInstrumentBinding or binding.instrument != expected_instrument:
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
        from .strategy_position_ledger import strategy_close_capacity
        with self._transaction() as db:
            result = strategy_close_capacity(db, self._account, strategy, payload,
                                             trading_day=day, instrument_binding=binding,
                                             resolve_binding=resolve_binding,
                                             verify_day_transition=verify_transition,
                                             verify_current_continuity=verify_continuity,
                                             verify_external_current=self._strategy_external_verifier)
            try:
                unchanged = (current_day() == day and resolve_binding(payload) == binding
                             and binding.instrument == expected_instrument)
            except Exception as exc:
                raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc
            if not unchanged:
                raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE")
            self._assert_account_guard(self._strategy_ledger_guard)
            return result

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

    def read_delegated_strategy_command(
        self, strategy: str, request_key: str, *, admission_fence: Callable
    ) -> DirectCommandRecord:
        """Read a delegated command using an installed strategy-bound admission.

        The trusted caller must bind the authenticated strategy, account, run,
        action and complete request arguments to its Registry-issued fence.
        This owner-local method must never accept a fence supplied over RPC.
        The record retains the original actor principal.
        """
        strategy, request_key = map(_text, (strategy, request_key))
        if self._schema_version < 12 or not callable(admission_fence):
            raise DirectCommandJournalError("DELEGATION_UNAVAILABLE")
        with ExitStack() as stack:
            manager = admission_fence()
            check = type(manager).__enter__(manager)
            exit_ = type(manager).__exit__
            stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            if not callable(check):
                raise DirectCommandJournalError("INVALID_ADMISSION")
            db = stack.enter_context(self._transaction())
            check()
            delegated = db.execute(
                "SELECT 1 FROM direct_delegated_commands WHERE account=? AND strategy=? AND request_key=?",
                (self._account, strategy, request_key),
            ).fetchone()
            if delegated is None:
                raise DirectCommandJournalError("NOT_FOUND")
            row = self._find(db, strategy, request_key)
            if row is None:
                raise DirectCommandJournalError("INVALID_DATABASE")
            check()
            return self._record(row)

    def read_delegate_command(self, *, delegation_permit, admission_fence) -> DirectCommandRecord:
        """Read the authenticated actor's exact immutable delegated command."""
        from .direct_delegation import GatewayDelegationPermit
        if (self._schema_version < 12 or type(delegation_permit) is not GatewayDelegationPermit
                or delegation_permit.operation not in {'direct.command_status', 'direct.cancel', 'direct.cancel_status', 'direct.release'}
                or not callable(admission_fence)):
            raise DirectCommandJournalError('DELEGATION_UNAVAILABLE')
        command = delegation_permit.command
        with ExitStack() as stack:
            manager = admission_fence()
            enter, exit_ = type(manager).__enter__, type(manager).__exit__
            enter(manager)
            stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            db = stack.enter_context(self._transaction())
            delegation_permit.recheck(db)
            row = self._require(db, command.strategy_scope, command.request_key, command.actor_principal)
            saved = db.execute('SELECT envelope_json,envelope_digest FROM direct_delegated_commands '
                'WHERE account=? AND strategy=? AND request_key=?',
                (self._account, command.strategy_scope, command.request_key)).fetchone()
            if (command.account_scope != self._account or row['digest'] != command.payload_digest
                    or saved is None or saved['envelope_json'] != command.canonical_json
                    or saved['envelope_digest'] != command.digest):
                raise DirectCommandJournalError('DELEGATION_MISMATCH')
            delegation_permit.recheck(db)
            return self._record(row)

    def read_delegate_release(self, operation_id: str, *, delegation_permit, admission_fence):
        """Find the exact persisted release operation, not merely an order state."""
        from .direct_delegation import GatewayDelegationPermit
        operation_id = _text(operation_id)
        if (self._schema_version < 12 or type(delegation_permit) is not GatewayDelegationPermit
                or delegation_permit.operation != 'direct.command_status' or not callable(admission_fence)):
            raise DirectCommandJournalError('DELEGATION_UNAVAILABLE')
        command = delegation_permit.command
        with ExitStack() as stack:
            manager = admission_fence()
            enter, exit_ = type(manager).__enter__, type(manager).__exit__
            enter(manager)
            stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            db = stack.enter_context(self._transaction())
            delegation_permit.recheck(db)
            row = self._require(db, command.strategy_scope, command.request_key, command.actor_principal)
            saved = db.execute('SELECT envelope_json,envelope_digest FROM direct_delegated_commands '
                'WHERE account=? AND strategy=? AND request_key=?',
                (self._account, command.strategy_scope, command.request_key)).fetchone()
            release = db.execute('SELECT * FROM direct_journal_releases WHERE account=? AND operation_id=?',
                                 (self._account, operation_id)).fetchone()
            if (command.account_scope != self._account or saved is None or saved['envelope_json'] != command.canonical_json
                    or saved['envelope_digest'] != command.digest or row['digest'] != command.payload_digest
                    or release is None or release['strategy'] != command.strategy_scope
                    or release['request_key'] != command.request_key or release['reservation_id'] != row['reservation_id']
                    or release['digest'] != command.payload_digest or release['principal'] != command.actor_principal
                    or row['status'] not in {'RELEASED', 'EXPIRED'}):
                raise DirectCommandJournalError('RELEASE_NOT_FOUND')
            delegation_permit.recheck(db)
            return self._record(row), release['expected_version']

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
        *,
        delegation_permit: object | None = None,
        delegation_fence: Callable | None = None,
        release_target_recheck: Callable | None = None,
    ) -> DirectCommandRecord:
        strategy, request_key, reservation_id, digest, principal, operation_id = map(
            _text, (strategy, request_key, reservation_id, digest, principal, operation_id)
        )
        self._version(expected_version)
        if delegation_permit is not None:
            from .direct_delegation import GatewayDelegationPermit
            if (self._schema_version < 12 or type(delegation_permit) is not GatewayDelegationPermit
                    or delegation_permit.operation != 'direct.release' or not callable(delegation_fence)):
                raise DirectCommandJournalError('DELEGATION_UNAVAILABLE')
        elif delegation_fence is not None or release_target_recheck is not None:
            raise DirectCommandJournalError('DELEGATION_UNAVAILABLE')
        with ExitStack() as stack:
            if delegation_permit is not None:
                manager = delegation_fence()
                enter, exit_ = type(manager).__enter__, type(manager).__exit__
                enter(manager)
                stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            db = stack.enter_context(self._transaction())
            args = (strategy, request_key, reservation_id, digest, principal, expected_version)
            old = db.execute(
                "SELECT strategy, request_key, reservation_id, digest, principal, expected_version FROM direct_journal_releases WHERE account=? AND operation_id=?",
                (self._account, operation_id),
            ).fetchone()
            if old is not None and tuple(old) != args:
                raise DirectCommandJournalError("OPERATION_CONFLICT")
            row = self._bound(db, strategy, request_key, reservation_id, digest, principal)
            delegated = None
            if self._schema_version >= 12:
                delegated = db.execute('SELECT envelope_json,envelope_digest FROM direct_delegated_commands '
                    'WHERE account=? AND strategy=? AND request_key=?', (self._account, strategy, request_key)).fetchone()
            if (delegated is None) != (delegation_permit is None):
                raise DirectCommandJournalError('DELEGATION_MISMATCH')
            def check_delegate():
                if delegation_permit is None:
                    return
                command = delegation_permit.command
                if (command.account_scope != self._account or command.strategy_scope != strategy
                        or command.request_key != request_key or command.actor_principal != principal
                        or command.payload_digest != digest or command.canonical_json != delegated['envelope_json']
                        or command.digest != delegated['envelope_digest']):
                    raise DirectCommandJournalError('DELEGATION_MISMATCH')
                delegation_permit.recheck(db)
                if command.parent_ref is not None and (not callable(release_target_recheck)
                        or release_target_recheck(db, command, operation_id, reservation_id, digest) is not True):
                    raise DirectCommandJournalError('PARENT_RELEASE_DENIED')
            check_delegate()
            if old is not None:
                check_delegate()
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
            check_delegate()
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
        before_commit: Callable[[], None] | None = None,
        prepared_place: object | None = None,
        delegation_permit: object | None = None,
        delegation_fence: Callable[[], ContextManager[None]] | None = None,
    ) -> DispatchStart:
        """Begin dispatch under the write transaction and an optional local recheck.

        The trusted recheck runs with SQLite's write lock held; it must not do
        provider I/O, enter another journal transaction, or reenter its fence.
        """
        if ((before_dispatch is not None and not callable(before_dispatch))
                or (before_commit is not None and not callable(before_commit))):
            raise DirectCommandJournalError("INVALID_INPUT")
        strategy, request_key, reservation_id, digest, principal = map(
            _text, (strategy, request_key, reservation_id, digest, principal)
        )
        self._version(expected_version)
        identity = _json(native_identity, scalar_map=True)
        keys = _strong_keys(strong_identity_keys)
        keys_json = _json(list(keys))
        with self._transaction() as preflight:
            preflight_row = self._bound(preflight, strategy, request_key, reservation_id, digest, principal)
            preflight_payload = json.loads(preflight_row['payload_json'])
        needs_capacity_fence = (preflight_row['status'] == 'RESERVED' and self._unknown_capacity_needed(
            strategy, preflight_payload, exclude_reservation_id=reservation_id))
        if delegation_permit is not None:
            from .direct_delegation import GatewayDelegationPermit
            if (type(delegation_permit) is not GatewayDelegationPermit or self._schema_version < 12
                    or delegation_permit.operation != "direct.dispatch"
                    or not callable(delegation_fence)):
                raise DirectCommandJournalError("DELEGATION_UNAVAILABLE")
        elif delegation_fence is not None:
            raise DirectCommandJournalError("DELEGATION_UNAVAILABLE")
        with ExitStack() as fence_stack:
            if delegation_permit is not None:
                manager = delegation_fence()
                enter, exit_ = type(manager).__enter__, type(manager).__exit__
                enter(manager)
                fence_stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            if needs_capacity_fence:
                self._assert_account_guard(self._unknown_capacity_guard)
                manager = self._unknown_capacity_ports[0]()
                enter, exit_ = type(manager).__enter__, type(manager).__exit__
                enter(manager)
                fence_stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
            db = fence_stack.enter_context(self._transaction())
            row = self._bound(db, strategy, request_key, reservation_id, digest, principal)
            delegated_row = None
            if self._schema_version >= 12:
                delegated_row = db.execute(
                    "SELECT envelope_json,envelope_digest FROM direct_delegated_commands "
                    "WHERE account=? AND strategy=? AND request_key=?",
                    (self._account, strategy, request_key),
                ).fetchone()
            if (delegated_row is None) != (delegation_permit is None):
                raise DirectCommandJournalError("DELEGATION_MISMATCH")
            if delegated_row is not None:
                command = delegation_permit.command
                if (command.account_scope != self._account or command.strategy_scope != strategy
                        or command.request_key != request_key or command.actor_principal != principal
                        or command.payload_digest != digest
                        or command.canonical_json != delegated_row["envelope_json"]
                        or command.digest != delegated_row["envelope_digest"]):
                    raise DirectCommandJournalError("DELEGATION_MISMATCH")
                delegation_permit.recheck(db)
            if row["status"] in ("DISPATCHING", "SENT", "NOT_SENT", "UNKNOWN"):
                if prepared_place is not None:
                    from .direct_place_journal import _get_prepared, _validate_prepared

                    old_prepared = _get_prepared(db, self._account, reservation_id)
                    raw_prepared, digest_prepared = _validate_prepared(prepared_place, row)
                    if (
                        old_prepared is None
                        or _json(old_prepared.to_mapping()) != raw_prepared
                        or old_prepared.digest() != digest_prepared
                    ):
                        raise DirectCommandJournalError("PLACE_PREPARATION_CONFLICT")
                if row["native_identity_json"] != identity or row["strong_keys_json"] != keys_json:
                    raise DirectCommandJournalError("IDENTITY_CONFLICT")
                prior_version = row["version"] - (1 if row["status"] == "DISPATCHING" else 2)
                if expected_version != prior_version:
                    raise DirectCommandJournalError("VERSION_CONFLICT")
                if delegation_permit is not None:
                    delegation_permit.recheck(db)
                return DispatchStart(self._record(row), False)
            if row["status"] != "RESERVED":
                raise DirectCommandJournalError("STATE_CONFLICT")
            if row["version"] != expected_version:
                raise DirectCommandJournalError("VERSION_CONFLICT")
            if row["generation"] != self._generation or self._now() >= row["expires_at"]:
                if delegation_permit is not None:
                    delegation_permit.recheck(db)
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
            if self._schema_version >= 12:
                from .external_position_ledger import external_identity_collision
                if external_identity_collision(db, self._account, keys):
                    raise DirectCommandJournalError("EXTERNAL_IDENTITY_CONFLICT")
            for key in keys:
                if (
                    db.execute(
                        "SELECT 1 FROM direct_journal_strong_keys WHERE account=? AND strong_key=?",
                        (self._account, key),
                    ).fetchone()
                    is not None
                ):
                    raise DirectCommandJournalError("IDENTITY_CONFLICT")
            if self._schema_version >= 10:
                from .direct_control import check_controls
                blocked = db.execute(
                    "SELECT cause.mode FROM direct_control_blocked blocked "
                    "JOIN direct_control_causes cause ON cause.account=blocked.account AND cause.cause_id=blocked.cause_id "
                    "WHERE blocked.account=? AND blocked.reservation_id=?", (self._account, row["reservation_id"]),
                ).fetchall()
                if blocked and (any(item[0] != "STOP_NEW" for item in blocked)
                                or not self._allow_verified_close(db, strategy, json.loads(row["payload_json"]),
                                                                  exclude_reservation_id=reservation_id)):
                    raise DirectCommandJournalError("CONTROL_PREVIOUSLY_BLOCKED")
                check_controls(db, self._account, strategy, json.loads(row["payload_json"]),
                               allow_verified_close=lambda: self._allow_verified_close(
                                   db, strategy, json.loads(row["payload_json"]),
                                   exclude_reservation_id=reservation_id))
            self._check_unknown_scope(db, strategy, json.loads(row["payload_json"]), exclude_reservation_id=reservation_id, capacity_fenced=needs_capacity_fence)
            self._check_strategy_capacity(db, strategy, json.loads(row["payload_json"]),
                                          exclude_reservation_id=reservation_id)
            self._assert_monitor_gate(db, strategy, json.loads(row["payload_json"]),
                                      exclude_reservation_id=reservation_id)
            if before_dispatch is not None:
                before_dispatch()
            if self._now() >= row["expires_at"]:
                if delegation_permit is not None:
                    delegation_permit.recheck(db)
                db.execute(
                    "UPDATE direct_journal_commands SET status='EXPIRED', version=version+1 WHERE account=? AND strategy=? AND request_key=?",
                    (self._account, strategy, request_key),
                )
                self._bump(db)
                return DispatchStart(
                    self._record(self._require(db, strategy, request_key, principal)), False
                )
            prepared_raw = prepared_digest = None
            if prepared_place is not None:
                from .direct_place_journal import _validate_prepared

                candidate = dict(row)
                candidate["native_identity_json"] = identity
                prepared_raw, prepared_digest = _validate_prepared(prepared_place, candidate)
                for key in prepared_place.request_keys:
                    if (
                        db.execute(
                            "SELECT 1 FROM direct_place_keys WHERE account=? AND strong_key=?",
                            (self._account, key),
                        ).fetchone()
                        is not None
                    ):
                        raise DirectCommandJournalError("PLACE_KEY_CONFLICT")
            db.execute(
                "UPDATE direct_journal_commands SET status='DISPATCHING', version=version+1, native_identity_json=?, strong_keys_json=? WHERE account=? AND strategy=? AND request_key=?",
                (identity, keys_json, self._account, strategy, request_key),
            )
            for key in keys:
                db.execute(
                    "INSERT INTO direct_journal_strong_keys VALUES (?, ?, ?)",
                    (self._account, key, reservation_id),
                )
            if prepared_place is not None:
                db.execute(
                    "INSERT INTO direct_place_preparations VALUES (?, ?, ?, ?)",
                    (self._account, reservation_id, prepared_raw, prepared_digest),
                )
                for key in prepared_place.request_keys:
                    db.execute(
                        "INSERT INTO direct_place_keys VALUES (?, ?, ?)",
                        (self._account, key, reservation_id),
                    )
            self._bump(db)
            self._check_unknown_scope(db, strategy, json.loads(row["payload_json"]), exclude_reservation_id=reservation_id, capacity_fenced=needs_capacity_fence)
            self._check_strategy_capacity(db, strategy, json.loads(row["payload_json"]),
                                          exclude_reservation_id=reservation_id)
            if self._schema_version >= 10:
                check_controls(db, self._account, strategy, json.loads(row["payload_json"]),
                               allow_verified_close=lambda: self._allow_verified_close(
                                   db, strategy, json.loads(row["payload_json"]),
                                   exclude_reservation_id=reservation_id))
            self._assert_monitor_gate(db, strategy, json.loads(row["payload_json"]),
                                      exclude_reservation_id=reservation_id)
            if delegation_permit is not None:
                delegation_permit.recheck(db)
            if before_commit is not None:
                before_commit()
            return DispatchStart(
                self._record(self._require(db, strategy, request_key, principal)), True
            )

    def recheck_dispatch_controls(
        self, strategy: str, request_key: str, principal: str, reservation_id: str, digest: str,
    ) -> None:
        """Read-only control and monitor recheck for a still RESERVED command.

        Used for the decision-B final validation immediately before the claim
        (which precedes the durable marker): an emergency control or a lost
        required monitor committed before this read refuses the claim. The
        marker transaction rechecks controls and capacity again. No row is
        written.
        """
        strategy, request_key, principal, reservation_id, digest = map(
            _text, (strategy, request_key, principal, reservation_id, digest))
        with self._connection() as db:
            db.execute("BEGIN")
            try:
                self._assert_anchor(db)
                row = self._bound(db, strategy, request_key, reservation_id, digest, principal)
                if row["status"] != "RESERVED":
                    raise DirectCommandJournalError("NOT_RESERVED")
                payload = json.loads(row["payload_json"])
                if self._schema_version >= 10:
                    from .direct_control import check_controls
                    blocked = db.execute(
                        "SELECT cause.mode FROM direct_control_blocked blocked "
                        "JOIN direct_control_causes cause ON cause.account=blocked.account "
                        "AND cause.cause_id=blocked.cause_id "
                        "WHERE blocked.account=? AND blocked.reservation_id=?",
                        (self._account, reservation_id),
                    ).fetchall()
                    if blocked and (any(item[0] != "STOP_NEW" for item in blocked)
                                    or not self._allow_verified_close(
                                        db, strategy, payload,
                                        exclude_reservation_id=reservation_id)):
                        raise DirectCommandJournalError("CONTROL_PREVIOUSLY_BLOCKED")
                    check_controls(db, self._account, strategy, payload,
                                   allow_verified_close=lambda: self._allow_verified_close(
                                       db, strategy, payload,
                                       exclude_reservation_id=reservation_id))
                self._assert_monitor_gate(db, strategy, payload,
                                          exclude_reservation_id=reservation_id)
            finally:
                if db.in_transaction:
                    db.execute("ROLLBACK")

    def get_prepared_place(self, reservation_id: str):
        """Read the prepared value bound to one exact original reservation."""
        from .direct_place_journal import _get_prepared

        reservation_id = _text(reservation_id)
        with self._transaction() as db:
            return _get_prepared(db, self._account, reservation_id)

    def find_place_by_request_key(self, key: str):
        """Resolve only the typed place-key namespace; no authentication is implied."""
        from .direct_place_journal import _find_place_by_key

        key = _text(key)
        with self._transaction() as db:
            return _find_place_by_key(db, self, key)

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

    # -- throttled history checks (I63-E135) ------------------------------
    #
    # ``_transaction`` verifies the anchor and the exact DDL every time. The
    # remaining checks walk whole tables; at schema 14 the account fact stream
    # alone cost 105 ms on a journal with 256 facts, in every transaction.
    # By default nothing changes: they run in every transaction. A trusted
    # owner may set an interval. Then they run when the journal is opened,
    # whenever the database files differ from what this object left behind
    # (another connection or process wrote), and at least once per interval;
    # in between, transactions of this object rely on the last full check.
    # A fault introduced by this object's own writes is therefore reported at
    # the next full check, not at the next transaction.
    _deep_interval = 0.0
    _deep_trusted: tuple | None = None
    _deep_next_at = 0.0
    _deep_clock = staticmethod(time.monotonic)

    def set_deep_verification_interval(self, seconds: float) -> None:
        """Run the whole-table integrity checks at most this often (0: every transaction)."""
        if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 <= seconds <= 3600:
            raise DirectCommandJournalError("INVALID_INPUT")
        self._deep_interval = float(seconds)
        self._deep_trusted = None  # the next transaction checks in full

    def _storage_fingerprint(self) -> tuple:
        result = []
        path = self._identity.path
        for candidate in (path, path.with_name(path.name + "-wal")):
            try:
                info = os.stat(candidate)
                result.append((info.st_ino, info.st_size, info.st_mtime_ns))
            except FileNotFoundError:
                result.append(None)
        return tuple(result)

    def _deep_state_stack(self) -> list:
        local = self.__dict__.get("_deep_local")
        if local is None:
            local = self.__dict__.setdefault("_deep_local", threading.local())
        if not hasattr(local, "stack"):
            local.stack = []
        return local.stack

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self._identity.verify()
        throttled = self._deep_interval > 0
        state = {"before": self._storage_fingerprint() if throttled else None, "verified": False}
        try:
            db = sqlite3.connect(
                self._identity.path.as_uri() + "?mode=rw",
                uri=True,
                timeout=self._timeout,
                isolation_level=None,
            )
        except sqlite3.OperationalError as exc:
            raise DirectCommandJournalError("DATABASE_UNAVAILABLE") from exc
        stack = self._deep_state_stack()
        stack.append(state)
        try:
            db.row_factory = sqlite3.Row
            self._identity.verify()
            db.execute("PRAGMA synchronous = FULL")
            self._identity.verify()
            yield db
        finally:
            db.close()
            stack.remove(state)
            if throttled:
                # Only a connection that started from a checked state leaves a
                # trusted one; its own writes and the checkpoint on close are
                # part of what it leaves behind.
                self._deep_trusted = self._storage_fingerprint() if state["verified"] else None

    @staticmethod
    def _commit(db: sqlite3.Connection) -> None:
        db.execute("COMMIT")

    @contextmanager
    def _transaction_on(self, db: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
        # Bind the observer before entering SQLite. Installation fails rather
        # than missing a transaction that started without the observer.
        with self._dispatch_port_lock:
            self._dispatch_active_transactions += 1
            port = self._dispatch_change_port
        try:
            with self._transaction_with_change_port(db, port):
                yield db
        finally:
            with self._dispatch_port_lock:
                self._dispatch_active_transactions -= 1

    @contextmanager
    def _transaction_with_change_port(self, db: sqlite3.Connection, port: object) -> Iterator[sqlite3.Connection]:
        db.execute("BEGIN IMMEDIATE")
        token = None
        denied = False
        if port is not None:
            def authorize(action, _table, _column, database, _trigger):
                nonlocal token, denied
                # A connection is created per transaction, so the authorizer
                # is installed before any application statement can be cached.
                # TEMP staging and read-only statements do not modify the
                # durable account database. Conservatively fence every main
                # table write, including cursors and journal metadata.
                if database == 'main' and action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE):
                    if token is None and not denied:
                        try:
                            token = port.begin_change('parent_facts')
                            if token is None:
                                raise RuntimeError('empty change token')
                        except Exception:
                            denied = True
                    if denied:
                        return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            db.set_authorizer(authorize)
        try:
            yield db
            self._identity.verify()
            self._commit(db)
        except BaseException:
            try:
                if db.in_transaction:
                    db.execute("ROLLBACK")
            finally:
                if port is not None:
                    try:
                        if token is not None:
                            port.poison(token)
                        elif denied:
                            port.poison_domain('parent_facts')
                    except Exception:
                        port.poison_domain('parent_facts')
            raise
        else:
            if token is not None:
                try:
                    # The journal is not a proof of all selected sources.
                    port.finish_change(token, 'UNAVAILABLE')
                except BaseException:
                    port.poison_domain('parent_facts')
                    raise
        finally:
            if port is not None:
                db.set_authorizer(None)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as db, self._transaction_on(db):
            self._assert_anchor(db)
            if self._schema_version >= 4:
                self._verify_exact_ddl(db, self._schema_version, self._control_release_audit)
            self._verify_history_if_due(db)
            yield db

    def _verify_history_if_due(self, db: sqlite3.Connection) -> None:
        stack = self._deep_state_stack()
        state = stack[-1] if stack else None
        throttled = self._deep_interval > 0 and state is not None and state["before"] is not None
        if (throttled and self._deep_trusted is not None and state["before"] == self._deep_trusted
                and self._deep_clock() < self._deep_next_at):
            state["verified"] = True
            return
        started = self._deep_clock()
        self._verify_history(db)
        if throttled:
            finished = self._deep_clock()
            # On a long history one full check is slow: never spend more than
            # about a twentieth of the owner's time on them.
            self._deep_next_at = finished + max(self._deep_interval, 20.0 * (finished - started))
            state["verified"] = True

    def _verify_history(self, db: sqlite3.Connection) -> None:
        """The whole-table checks of one transaction, by schema version."""
        if self._schema_version >= 10:
            from .direct_control import verify_controls
            verify_controls(db, self._account, self._max_records)
        if self._schema_version >= 11:
            from .strategy_position_ledger import _verify_strategy_ledger_integrity
            _verify_strategy_ledger_integrity(db, self._account)
        if self._schema_version >= 12:
            from .direct_delegation import verify_delegated_integrity
            from .external_position_ledger import verify_external_integrity
            from .account_observer import verify_account_observers
            verify_delegated_integrity(db, self._account, self._max_records)
            verify_external_integrity(db, self._account)
            verify_account_observers(db, self._account)
        if self._schema_version >= 13:
            from .direct_parent_authority import verify_parent_authority_integrity
            verify_parent_authority_integrity(db, self._account, self._max_records)
        if self._schema_version >= 14:
            from .account_observation_journal import verify_account_fact_stream
            from .strategy_financial_ledger import verify_strategy_financial_integrity
            verify_account_fact_stream(db, self._account, self._journal_id)
            verify_strategy_financial_integrity(db, self._account)
        if self._schema_version >= 15:
            from .delegate_actor_stream import verify_actor_stream
            verify_actor_stream(db, self._account, self._journal_id, self._max_records)
        if self._schema_version >= 16:
            from .direct_strategy_origin import verify_strategy_origins
            verify_strategy_origins(db, self._account, self._journal_id)
        if self._schema_version >= 17:
            from .direct_control_cancel import verify_control_cancel_integrity
            verify_control_cancel_integrity(db, self._account, self._journal_id, self._max_records)
        if self._schema_version >= 18:
            from .account_fact_consumer_ownership import verify_account_fact_consumer_owners
            from .account_fact_compaction import verify_account_fact_compaction
            verify_account_fact_consumer_owners(db, self._account)
            verify_account_fact_compaction(db, self._account, self._journal_id)
        if self._schema_version >= 19:
            from .account_event_consumer_ownership import verify_account_event_consumer_owners
            verify_account_event_consumer_owners(db, self._account)

_RECONCILIATION_BLOCKING_STATUSES = (
    ("commands", "direct_journal_commands", ("DISPATCHING", "UNKNOWN")),
    ("cancels", "direct_cancel_attempts", ("DISPATCHING", "UNKNOWN")),
    ("settlements", "direct_journal_settlement", ("ATTEMPTING", "UNKNOWN")),
)


def inspect_unresolved_dispatch(
    path: str | Path, account: str, *, timeout_seconds: float = 5.0
) -> dict[str, int]:
    """Count journal rows whose venue outcome an abandoned owner left open.

    Read-only and meant for operator session reconciliation while the account
    session lock is held, so no Gateway owner is writing. A command or cancel
    still ``DISPATCHING`` or ``UNKNOWN`` may have reached the venue, and an
    ``ATTEMPTING``/``UNKNOWN`` settlement confirmation may have been sent; each
    count must be zero before the session record may be closed. The journal
    must already exist and belong to ``account``.
    """

    account = _text(account)
    if (
        type(timeout_seconds) not in (int, float)
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= 60
    ):
        raise DirectCommandJournalError("INVALID_INPUT")
    journal = Path(path)
    try:
        info = journal.lstat()
    except FileNotFoundError:
        raise DirectCommandJournalError("DATABASE_UNAVAILABLE") from None
    except OSError as exc:
        raise DirectCommandJournalError("DATABASE_UNAVAILABLE") from exc
    if not stat.S_ISREG(info.st_mode):
        raise DirectCommandJournalError("DATABASE_UNAVAILABLE")
    try:
        db = sqlite3.connect(
            journal.absolute().as_uri() + "?mode=ro",
            uri=True,
            timeout=float(timeout_seconds),
            isolation_level=None,
        )
    except sqlite3.Error as exc:
        raise DirectCommandJournalError("DATABASE_UNAVAILABLE") from exc
    try:
        db.execute("BEGIN")
        tables = {
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "direct_journal_meta" not in tables or "direct_journal_commands" not in tables:
            raise DirectCommandJournalError("DATABASE_INVALID")
        owner = db.execute(
            "SELECT COUNT(*) FROM direct_journal_meta WHERE account=?", (account,)
        ).fetchone()[0]
        if owner != 1:
            raise DirectCommandJournalError("ACCOUNT_MISMATCH")
        counts: dict[str, int] = {}
        for label, table, statuses in _RECONCILIATION_BLOCKING_STATUSES:
            for status in statuses:
                key = f"{label}_{status.lower()}"
                if table not in tables:
                    counts[key] = 0
                    continue
                counts[key] = int(
                    db.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE account=? AND status=?",  # noqa: S608
                        (account, status),
                    ).fetchone()[0]
                )
        db.execute("COMMIT")
        return counts
    except sqlite3.Error as exc:
        raise DirectCommandJournalError("DATABASE_UNAVAILABLE") from exc
    finally:
        db.close()
