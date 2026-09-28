"""Local durable writer epochs and single-use action claims.

The authority coordinates processes that use the same SQLite database file.
It is a local fencing contract only: it cannot exclude another host or a
provider session that does not consult this database.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import sqlite3
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Any, Callable, Optional, Union

from .database_identity import SQLiteFileIdentity
from .router import GatewayCommandKind, GatewayCommandStatus, _canonical_json, _validate_redacted

if TYPE_CHECKING:
    from .router import GatewayCommand, GatewayPrincipal


class GatewayWriterAuthorityError(RuntimeError):
    """A local writer lease or action claim failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class GatewayActionStatus(str, Enum):
    """Durable local action state; owner return is not provider acknowledgement."""

    CLAIMED = "claimed"
    DISPATCHING = "dispatching"
    RETURNED_UNVERIFIED = "returned_unverified"
    UNKNOWN = "unknown"
    REJECTED = "rejected"


@dataclass(frozen=True)
class GatewayWriterLease:
    """Opaque in-process lease handle; its token is never persisted in SQLite."""

    account_scope: str
    owner_id: str
    lease_id: str
    epoch: int
    expires_at: float
    _token: str = field(repr=False, compare=False)


@dataclass(frozen=True)
class GatewayActionClaim:
    """Durable identity of one command under one writer epoch."""

    account_scope: str
    strategy_scope: str
    action_id: str
    principal_id: str
    command_fingerprint: str
    owner_id: str
    lease_id: str
    epoch: int
    expires_at: float


@dataclass(frozen=True)
class GatewayActionRecord:
    """Redacted action journal view for local audit and recovery checks."""

    claim: GatewayActionClaim
    status: GatewayActionStatus
    created_at: float
    updated_at: float
    outcome_digest: Optional[str]  # noqa: UP045 -- Python 3.9 is supported.
    rejection_code: Optional[str]  # noqa: UP045 -- Python 3.9 is supported.


class GatewayAccountWriterAuthority:
    """SQLite account writer lease, monotonic epoch, and one-shot action ledger.

    An expired or revoked lease can be replaced only if the prior epoch has no
    unresolved action. A new process starts with no in-memory lease handle and
    must acquire a new epoch after expiry; it cannot recover or replay old
    claims. Owner-returned and unknown actions remain unresolved because an
    executor return is not provider acknowledgement or account reconciliation.
    """

    UNRESOLVED_ACTIONS = (
        GatewayActionStatus.CLAIMED.value,
        GatewayActionStatus.DISPATCHING.value,
        GatewayActionStatus.RETURNED_UNVERIFIED.value,
        GatewayActionStatus.UNKNOWN.value,
    )

    def __init__(
        self,
        database_path: Union[Path, str],  # noqa: UP007 -- Python 3.9 is supported.
        clock: Optional[Callable[[], float]] = None,  # noqa: UP045 -- Python 3.9 is supported.
        max_lease_seconds: float = 60.0,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not _finite_number(max_lease_seconds) or max_lease_seconds <= 0:
            raise ValueError("max_lease_seconds must be finite and positive")
        if not _finite_number(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be finite and positive")
        self._database_identity = SQLiteFileIdentity(Path(database_path).absolute())
        self._database_path = self._database_identity.path
        self._clock = clock or time.time
        self._max_lease_seconds = float(max_lease_seconds)
        self._timeout_seconds = float(timeout_seconds)
        self._leases: dict[str, GatewayWriterLease] = {}
        self._leases_lock = RLock()
        self._initialize_schema()

    @property
    def database_path(self) -> Path:
        """Resolved local database path for Router same-file enforcement."""
        return self._database_path

    def acquire_writer(
        self, account_scope: str, owner_id: str, lease_seconds: float = 30.0
    ) -> GatewayWriterLease:
        """Acquire a new monotonic account epoch if no prior action is unresolved."""
        _require_text(account_scope, "account_scope")
        _require_text(owner_id, "owner_id")
        duration = self._lease_duration(lease_seconds)
        now = self._now()
        token = secrets.token_urlsafe(32)
        lease_id = uuid.uuid4().hex
        expires_at = now + duration
        with self._transaction() as connection:
            current = connection.execute(
                "SELECT * FROM gateway_writer_epochs WHERE account_scope = ?",
                (account_scope,),
            ).fetchone()
            if current is not None:
                active = current["revoked_at"] is None and float(current["expires_at"]) > now
                if active:
                    raise GatewayWriterAuthorityError(
                        "WRITER_LEASE_HELD", "account already has an active writer lease"
                    )
                unresolved = connection.execute(
                    """
                    SELECT action_id FROM gateway_action_claims
                    WHERE account_scope = ? AND status IN (?, ?, ?, ?) LIMIT 1
                    """,
                    (account_scope, *self.UNRESOLVED_ACTIONS),
                ).fetchone()
                if unresolved is not None:
                    raise GatewayWriterAuthorityError(
                        "WRITER_ACTIONS_UNRESOLVED",
                        "prior writer epoch has an unresolved action",
                    )
                epoch = int(current["epoch"]) + 1
            else:
                epoch = 1
            connection.execute(
                """
                INSERT INTO gateway_writer_epochs (
                    account_scope, owner_id, lease_id, token_digest, epoch,
                    acquired_at, expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(account_scope) DO UPDATE SET
                    owner_id = excluded.owner_id,
                    lease_id = excluded.lease_id,
                    token_digest = excluded.token_digest,
                    epoch = excluded.epoch,
                    acquired_at = excluded.acquired_at,
                    expires_at = excluded.expires_at,
                    revoked_at = NULL
                """,
                (
                    account_scope,
                    owner_id,
                    lease_id,
                    _token_digest(token),
                    epoch,
                    now,
                    expires_at,
                ),
            )
        lease = GatewayWriterLease(account_scope, owner_id, lease_id, epoch, expires_at, token)
        with self._leases_lock:
            self._leases[account_scope] = lease
        return lease

    def lease_for(self, account_scope: str) -> GatewayWriterLease:
        """Return this process's acquired lease; never discovers another owner's token."""
        with self._leases_lock:
            lease = self._leases.get(account_scope)
        if lease is None:
            raise GatewayWriterAuthorityError(
                "WRITER_AUTHORITY_UNAVAILABLE", "this process has no account writer lease"
            )
        return lease

    def renew_writer(
        self, lease: GatewayWriterLease, lease_seconds: float = 30.0
    ) -> GatewayWriterLease:
        """Renew the exact current lease without changing its epoch or token."""
        duration = self._lease_duration(lease_seconds)
        now = self._now()
        expires_at = now + duration
        with self._transaction() as connection:
            current = self._require_active_lease(connection, lease, now)
            connection.execute(
                "UPDATE gateway_writer_epochs SET expires_at = ? WHERE account_scope = ?",
                (expires_at, lease.account_scope),
            )
        renewed = GatewayWriterLease(
            lease.account_scope,
            lease.owner_id,
            lease.lease_id,
            lease.epoch,
            expires_at,
            lease._token,
        )
        with self._leases_lock:
            # Do not replace a newer lease handle installed concurrently.
            held = self._leases.get(lease.account_scope)
            if (
                held is not None
                and held.epoch == current["epoch"]
                and held.lease_id == lease.lease_id
            ):
                self._leases[lease.account_scope] = renewed
        return renewed

    def revoke_writer(self, lease: GatewayWriterLease) -> None:
        """Revoke the exact live lease; unresolved actions still block takeover."""
        now = self._now()
        with self._transaction() as connection:
            self._require_active_lease(connection, lease, now)
            in_flight = connection.execute(
                """
                SELECT action_id FROM gateway_action_claims
                WHERE account_scope = ? AND lease_id = ? AND epoch = ? AND status = ?
                LIMIT 1
                """,
                (
                    lease.account_scope,
                    lease.lease_id,
                    lease.epoch,
                    GatewayActionStatus.DISPATCHING.value,
                ),
            ).fetchone()
            if in_flight is not None:
                raise GatewayWriterAuthorityError(
                    "WRITER_ACTION_DISPATCHING",
                    "writer cannot be revoked while an owner call is in flight",
                )
            connection.execute(
                "UPDATE gateway_writer_epochs SET revoked_at = ? WHERE account_scope = ?",
                (now, lease.account_scope),
            )
        with self._leases_lock:
            held = self._leases.get(lease.account_scope)
            if held is not None and held.lease_id == lease.lease_id:
                self._leases.pop(lease.account_scope, None)

    def claim_action(
        self,
        lease: GatewayWriterLease,
        principal: GatewayPrincipal,
        command: GatewayCommand,
    ) -> GatewayActionClaim:
        """Persist one command claim under the current account epoch."""
        if command.account_scope != lease.account_scope:
            raise GatewayWriterAuthorityError(
                "ACTION_ACCOUNT_MISMATCH", "command and lease account scopes differ"
            )
        if (
            command.account_scope not in principal.account_scopes
            or command.strategy_scope not in principal.strategy_scopes
            or command.kind not in principal.allowed_kinds
        ):
            raise GatewayWriterAuthorityError(
                "ACTION_PRINCIPAL_SCOPE_MISMATCH", "principal scope does not cover command"
            )
        if command.kind is GatewayCommandKind.READ:
            raise GatewayWriterAuthorityError(
                "ACTION_READ_NOT_CLAIMABLE", "read commands do not use writer action claims"
            )
        now = self._now()
        with self._transaction() as connection:
            current = self._require_active_lease(connection, lease, now)
            if command.expires_at <= now:
                raise GatewayWriterAuthorityError("ACTION_EXPIRED", "command has expired")
            if command.issued_at > now:
                raise GatewayWriterAuthorityError(
                    "ACTION_NOT_YET_VALID", "command is not yet valid"
                )
            if float(command.expires_at) > float(current["expires_at"]):
                raise GatewayWriterAuthorityError(
                    "ACTION_OUTLIVES_LEASE", "command expiry exceeds writer lease"
                )
            existing = connection.execute(
                """
                SELECT * FROM gateway_action_claims
                WHERE account_scope = ? AND action_id = ?
                """,
                (command.account_scope, command.command_id),
            ).fetchone()
            if existing is not None:
                same_action = (
                    str(existing["strategy_scope"]) == command.strategy_scope
                    and str(existing["principal_id"]) == principal.principal_id
                    and str(existing["command_fingerprint"]) == command.fingerprint
                )
                code = "ACTION_ALREADY_CLAIMED" if same_action else "ACTION_ID_REUSED"
                raise GatewayWriterAuthorityError(
                    code, "action identity already exists in the durable account journal"
                )
            unresolved = connection.execute(
                """
                SELECT action_id FROM gateway_action_claims
                WHERE account_scope = ? AND status IN (?, ?, ?, ?) LIMIT 1
                """,
                (command.account_scope, *self.UNRESOLVED_ACTIONS),
            ).fetchone()
            if unresolved is not None:
                raise GatewayWriterAuthorityError(
                    "WRITER_ACTIONS_UNRESOLVED",
                    "account has a prior action requiring reconciliation",
                )
            claim = GatewayActionClaim(
                account_scope=command.account_scope,
                strategy_scope=command.strategy_scope,
                action_id=command.command_id,
                principal_id=principal.principal_id,
                command_fingerprint=command.fingerprint,
                owner_id=lease.owner_id,
                lease_id=lease.lease_id,
                epoch=lease.epoch,
                expires_at=float(command.expires_at),
            )
            connection.execute(
                """
                INSERT INTO gateway_action_claims (
                    account_scope, action_id, strategy_scope, principal_id,
                    command_fingerprint, owner_id, lease_id, epoch, expires_at,
                    status, created_at, dispatch_started_at, updated_at,
                    outcome_digest, rejection_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL, NULL)
                """,
                (
                    claim.account_scope,
                    claim.action_id,
                    claim.strategy_scope,
                    claim.principal_id,
                    claim.command_fingerprint,
                    claim.owner_id,
                    claim.lease_id,
                    claim.epoch,
                    claim.expires_at,
                    GatewayActionStatus.CLAIMED.value,
                    now,
                    now,
                ),
            )
        return claim

    def begin_action_dispatch(
        self,
        lease: GatewayWriterLease,
        principal: GatewayPrincipal,
        command: GatewayCommand,
        claim: GatewayActionClaim,
    ) -> None:
        """Final epoch/expiry/revocation check immediately before owner dispatch."""
        now = self._now()
        with self._transaction() as connection:
            current_lease = self._require_active_lease(connection, lease, now)
            if (
                command.expires_at <= now
                or command.expires_at > claim.expires_at
                or command.expires_at > float(current_lease["expires_at"])
                or command.fingerprint != claim.command_fingerprint
                or command.command_id != claim.action_id
                or command.account_scope != claim.account_scope
                or command.strategy_scope != claim.strategy_scope
                or principal.principal_id != claim.principal_id
                or command.account_scope not in principal.account_scopes
                or command.strategy_scope not in principal.strategy_scopes
                or command.kind not in principal.allowed_kinds
                or lease.epoch != claim.epoch
                or lease.owner_id != claim.owner_id
                or lease.lease_id != claim.lease_id
            ):
                raise GatewayWriterAuthorityError(
                    "ACTION_BINDING_MISMATCH", "final action binding check failed"
                )
            row = connection.execute(
                """
                SELECT * FROM gateway_action_claims
                WHERE account_scope = ? AND action_id = ?
                """,
                (claim.account_scope, claim.action_id),
            ).fetchone()
            if row is None or not _row_matches_claim(row, claim):
                raise GatewayWriterAuthorityError(
                    "ACTION_CLAIM_BINDING_MISMATCH",
                    "action claim does not match its durable account journal row",
                )
            if row["status"] != GatewayActionStatus.CLAIMED.value:
                raise GatewayWriterAuthorityError(
                    "ACTION_NOT_CLAIMED", "action claim is missing or no longer dispatchable"
                )
            _verify_command_journal_row(connection, principal, command)
            connection.execute(
                """
                UPDATE gateway_action_claims
                SET status = ?, dispatch_started_at = ?, updated_at = ?
                WHERE account_scope = ? AND action_id = ?
                """,
                (
                    GatewayActionStatus.DISPATCHING.value,
                    now,
                    now,
                    claim.account_scope,
                    claim.action_id,
                ),
            )

    def reject_unstarted_action(self, claim: GatewayActionClaim, reason_code: str) -> None:
        """Mark only a never-dispatched CLAIMED action rejected after final-check failure."""
        _require_text(reason_code, "reason_code")
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE gateway_action_claims
                SET status = ?, rejection_code = ?, updated_at = ?
                WHERE account_scope = ? AND action_id = ? AND epoch = ?
                    AND strategy_scope = ? AND principal_id = ? AND owner_id = ?
                    AND lease_id = ? AND command_fingerprint = ? AND expires_at = ?
                    AND status = ?
                """,
                (
                    GatewayActionStatus.REJECTED.value,
                    reason_code,
                    self._now(),
                    claim.account_scope,
                    claim.action_id,
                    claim.epoch,
                    claim.strategy_scope,
                    claim.principal_id,
                    claim.owner_id,
                    claim.lease_id,
                    claim.command_fingerprint,
                    claim.expires_at,
                    GatewayActionStatus.CLAIMED.value,
                ),
            )
            if connection.execute("SELECT changes()").fetchone()[0] != 1:
                raise GatewayWriterAuthorityError(
                    "ACTION_CLAIM_BINDING_MISMATCH",
                    "unstarted action claim no longer matches its durable row",
                )

    def mark_owner_returned_unverified(
        self, claim: GatewayActionClaim, outcome: Mapping[str, Any]
    ) -> None:
        """Record local executor return without treating it as provider ACK."""
        _validate_redacted(outcome)
        digest = hashlib.sha256(_canonical_json(outcome).encode("utf-8")).hexdigest()
        self._transition_action(
            claim,
            GatewayActionStatus.DISPATCHING,
            GatewayActionStatus.RETURNED_UNVERIFIED,
            outcome_digest=digest,
        )

    def mark_unknown(self, claim: GatewayActionClaim, error_type: str) -> None:
        """Keep the account fenced after an uncertain account-owner call."""
        _require_text(error_type, "error_type")
        digest = hashlib.sha256(error_type.encode("utf-8")).hexdigest()
        self._transition_action(
            claim,
            GatewayActionStatus.DISPATCHING,
            GatewayActionStatus.UNKNOWN,
            outcome_digest=digest,
        )

    def get_action(self, account_scope: str, action_id: str) -> Optional[GatewayActionRecord]:  # noqa: UP045 -- Python 3.9 is supported.
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT * FROM gateway_action_claims
                WHERE account_scope = ? AND action_id = ?
                """,
                (account_scope, action_id),
            ).fetchone()
        return self._record_from_row(row) if row is not None else None

    def _transition_action(
        self,
        claim: GatewayActionClaim,
        expected: GatewayActionStatus,
        target: GatewayActionStatus,
        outcome_digest: str,
    ) -> None:
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT * FROM gateway_action_claims
                WHERE account_scope = ? AND action_id = ?
                """,
                (claim.account_scope, claim.action_id),
            ).fetchone()
            if row is None or row["status"] != expected.value or not _row_matches_claim(row, claim):
                raise GatewayWriterAuthorityError(
                    "ACTION_STATE_CONFLICT", "action state changed before finalization"
                )
            connection.execute(
                """
                UPDATE gateway_action_claims
                SET status = ?, outcome_digest = ?, updated_at = ?
                WHERE account_scope = ? AND action_id = ? AND strategy_scope = ?
                    AND principal_id = ? AND owner_id = ? AND lease_id = ?
                    AND epoch = ? AND command_fingerprint = ? AND expires_at = ?
                """,
                (
                    target.value,
                    outcome_digest,
                    self._now(),
                    claim.account_scope,
                    claim.action_id,
                    claim.strategy_scope,
                    claim.principal_id,
                    claim.owner_id,
                    claim.lease_id,
                    claim.epoch,
                    claim.command_fingerprint,
                    claim.expires_at,
                ),
            )
            if connection.execute("SELECT changes()").fetchone()[0] != 1:
                raise GatewayWriterAuthorityError(
                    "ACTION_STATE_CONFLICT", "action binding changed before finalization"
                )

    def _record_from_row(self, row: sqlite3.Row) -> GatewayActionRecord:
        claim = GatewayActionClaim(
            account_scope=str(row["account_scope"]),
            strategy_scope=str(row["strategy_scope"]),
            action_id=str(row["action_id"]),
            principal_id=str(row["principal_id"]),
            command_fingerprint=str(row["command_fingerprint"]),
            owner_id=str(row["owner_id"]),
            lease_id=str(row["lease_id"]),
            epoch=int(row["epoch"]),
            expires_at=float(row["expires_at"]),
        )
        return GatewayActionRecord(
            claim=claim,
            status=GatewayActionStatus(str(row["status"])),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            outcome_digest=(str(row["outcome_digest"]) if row["outcome_digest"] else None),
            rejection_code=(str(row["rejection_code"]) if row["rejection_code"] else None),
        )

    def _require_active_lease(
        self, connection: sqlite3.Connection, lease: GatewayWriterLease, now: float
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM gateway_writer_epochs WHERE account_scope = ?",
            (lease.account_scope,),
        ).fetchone()
        if row is None:
            raise GatewayWriterAuthorityError(
                "WRITER_LEASE_MISSING", "account has no acquired writer lease"
            )
        if (
            str(row["owner_id"]) != lease.owner_id
            or str(row["lease_id"]) != lease.lease_id
            or int(row["epoch"]) != lease.epoch
            or not hmac.compare_digest(str(row["token_digest"]), _token_digest(lease._token))
        ):
            raise GatewayWriterAuthorityError(
                "WRITER_LEASE_STALE", "writer lease does not match current account epoch"
            )
        if row["revoked_at"] is not None:
            raise GatewayWriterAuthorityError(
                "WRITER_LEASE_REVOKED", "writer lease has been revoked"
            )
        if float(row["expires_at"]) <= now:
            raise GatewayWriterAuthorityError("WRITER_LEASE_EXPIRED", "writer lease has expired")
        return row

    def _lease_duration(self, value: float) -> float:
        if not _finite_number(value) or value <= 0 or value > self._max_lease_seconds:
            raise ValueError("lease duration must be positive and within the configured maximum")
        return float(value)

    def _now(self) -> float:
        value = self._clock()
        if not _finite_number(value):
            raise GatewayWriterAuthorityError("CLOCK_INVALID", "authority clock is invalid")
        return float(value)

    def _initialize_schema(self) -> None:
        deadline = time.monotonic() + self._timeout_seconds
        delay_seconds = 0.005
        while True:
            try:
                with self._connection() as connection:
                    connection.execute("PRAGMA journal_mode = WAL")
                    self._database_identity.verify()
                    connection.executescript(
                        """
                CREATE TABLE IF NOT EXISTS gateway_writer_epochs (
                    account_scope TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    token_digest TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    acquired_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked_at REAL
                );
                CREATE TABLE IF NOT EXISTS gateway_action_claims (
                    account_scope TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    strategy_scope TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    command_fingerprint TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    expires_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    dispatch_started_at REAL,
                    updated_at REAL NOT NULL,
                    outcome_digest TEXT,
                    rejection_code TEXT,
                    PRIMARY KEY (account_scope, action_id)
                );
                CREATE INDEX IF NOT EXISTS idx_gateway_action_claims_account_status
                    ON gateway_action_claims(account_scope, status, epoch);
                """
                    )
                    self._database_identity.verify()
                return
            except sqlite3.OperationalError as exc:
                if not _is_retryable_sqlite_lock(exc):
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise GatewayWriterAuthorityError(
                        "WRITER_DATABASE_INITIALIZATION_BUSY",
                        "SQLite database remained locked during writer schema initialization",
                    ) from exc
                time.sleep(min(delay_seconds, remaining))
                delay_seconds = min(delay_seconds * 2.0, 0.1)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self._database_identity.verify()
        connection = sqlite3.connect(
            str(self._database_path), timeout=self._timeout_seconds, isolation_level=None
        )
        try:
            connection.row_factory = sqlite3.Row
            self._database_identity.verify()
            connection.execute("PRAGMA synchronous = FULL")
            self._database_identity.verify()
            yield connection
        finally:
            connection.close()

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


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(name + " must be a non-empty trimmed string")


def _finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(float(value))
    except OverflowError:
        return False


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _is_retryable_sqlite_lock(error: sqlite3.OperationalError) -> bool:
    """Retry only the SQLite BUSY/LOCKED result families during initialization."""
    code = getattr(error, "sqlite_errorcode", None)
    if code is not None:
        base_code = int(code) & 0xFF
        return base_code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}
    return str(error).strip().lower() in {
        "database is locked",
        "database table is locked",
        "database schema is locked",
    }


def _row_matches_claim(row: sqlite3.Row, claim: GatewayActionClaim) -> bool:
    """Compare every action binding field before any state transition."""
    return (
        str(row["account_scope"]) == claim.account_scope
        and str(row["action_id"]) == claim.action_id
        and str(row["strategy_scope"]) == claim.strategy_scope
        and str(row["principal_id"]) == claim.principal_id
        and str(row["owner_id"]) == claim.owner_id
        and str(row["lease_id"]) == claim.lease_id
        and int(row["epoch"]) == claim.epoch
        and str(row["command_fingerprint"]) == claim.command_fingerprint
        and float(row["expires_at"]) == claim.expires_at
    )


def _verify_command_journal_row(
    connection: sqlite3.Connection,
    principal: GatewayPrincipal,
    command: GatewayCommand,
) -> None:
    """Atomically bind a writer claim to the router's persisted command row."""
    try:
        row = connection.execute(
            "SELECT * FROM gateway_commands WHERE command_id = ?",
            (command.command_id,),
        ).fetchone()
    except sqlite3.OperationalError as exc:
        if str(exc).strip().lower() == "no such table: gateway_commands":
            raise GatewayWriterAuthorityError(
                "COMMAND_JOURNAL_UNAVAILABLE",
                "router command journal is unavailable in the authority database",
            ) from exc
        raise
    if row is None:
        raise GatewayWriterAuthorityError(
            "COMMAND_JOURNAL_MISSING", "router command row is missing for action claim"
        )
    expected = (
        ("command_id", command.command_id),
        ("fingerprint", command.fingerprint),
        ("account_scope", command.account_scope),
        ("strategy_scope", command.strategy_scope),
        ("kind", command.kind.value),
        ("payload_json", command.payload_json),
        ("receipt_digest", command.receipt_digest),
        ("issued_at", command.issued_at),
        ("expires_at", command.expires_at),
        ("manual_resume_authorized", int(command.manual_resume_authorized)),
        ("principal_id", principal.principal_id),
    )
    for column, value in expected:
        actual = row[column]
        if column in {"issued_at", "expires_at"}:
            matches = float(actual) == float(value)
        elif column == "manual_resume_authorized":
            matches = int(actual) == int(value)
        else:
            matches = str(actual) == str(value)
        if not matches:
            raise GatewayWriterAuthorityError(
                "COMMAND_JOURNAL_MISMATCH",
                "router command row does not match the action claim",
            )
    if row["status"] != GatewayCommandStatus.DISPATCHING.value:
        raise GatewayWriterAuthorityError(
            "COMMAND_JOURNAL_NOT_DISPATCHING",
            "router command must be durably dispatching before owner invocation",
        )
