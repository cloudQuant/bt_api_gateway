"""Durable, scoped command routing without transport or provider dependencies.

`GatewayCommandRouter` is intentionally a server-side component.  It accepts
an already authenticated principal, checks account and strategy scope before
calling the one injected account-owner executor, and leaves transport and
provider protocol ownership outside this package.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import sqlite3
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Callable, Optional, Protocol, Union

from .database_identity import SQLiteFileIdentity

if TYPE_CHECKING:
    from .writer_authority import GatewayAccountWriterAuthority, GatewayActionClaim


class GatewayRoutingError(RuntimeError):
    """A command did not satisfy the gateway's server-side safety contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class GatewayDispatchError(RuntimeError):
    """The injected account owner raised while handling a persisted command."""


class GatewayCommandKind(str, Enum):
    """Commands accepted by the generic routing boundary."""

    READ = "read"
    SUBMIT = "submit"
    CANCEL = "cancel"
    FREEZE = "freeze"
    DRAIN = "drain"
    RESUME = "resume"


class GatewayCommandStatus(str, Enum):
    """Durable gateway state; returned_unverified is not provider acknowledgement."""

    PENDING = "pending"
    DISPATCHING = "dispatching"
    SUCCEEDED = "succeeded"
    RETURNED_UNVERIFIED = "returned_unverified"
    FAILED = "failed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class GatewayPrincipal:
    """Server-derived identity and immutable scope/command permissions.

    A transport must construct this only after authenticating a client.  Client
    payloads are never allowed to self-report these capabilities.
    """

    principal_id: str
    account_scopes: frozenset[str]
    strategy_scopes: frozenset[str]
    allowed_kinds: frozenset[GatewayCommandKind]

    def __post_init__(self) -> None:
        if not self.principal_id.strip():
            raise ValueError("principal_id is required")
        if not self.account_scopes or not self.strategy_scopes or not self.allowed_kinds:
            raise ValueError(
                "a principal needs non-empty account, strategy, and command permissions"
            )
        if any(not isinstance(kind, GatewayCommandKind) for kind in self.allowed_kinds):
            raise ValueError("allowed_kinds must contain GatewayCommandKind values")
        for name in ("account_scopes", "strategy_scopes", "allowed_kinds"):
            object.__setattr__(self, name, frozenset(getattr(self, name)))


@dataclass(frozen=True)
class GatewayCommand:
    """A redacted strategy-scoped command ready for server-side dispatch."""

    command_id: str
    account_scope: str
    strategy_scope: str
    kind: GatewayCommandKind
    payload: Mapping[str, Any]
    receipt_digest: str
    issued_at: float
    expires_at: float
    manual_resume_authorized: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.kind, GatewayCommandKind):
            raise ValueError("kind must be a GatewayCommandKind")
        if type(self.manual_resume_authorized) is not bool:
            raise ValueError("manual_resume_authorized must be a boolean")
        for name in ("command_id", "account_scope", "strategy_scope", "receipt_digest"):
            if not str(getattr(self, name)).strip():
                raise ValueError(name + " is required")
        if any(
            isinstance(value, bool) or not math.isfinite(value)
            for value in (self.issued_at, self.expires_at)
        ):
            raise ValueError("command timestamps must be finite")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if self.kind is GatewayCommandKind.RESUME and not self.manual_resume_authorized:
            raise ValueError("resume requires explicit manual authorization")
        if not isinstance(self.payload, Mapping):
            raise ValueError("payload must be a mapping")
        _validate_redacted(self.payload)
        object.__setattr__(self, "payload", _freeze_json(json.loads(_canonical_json(self.payload))))

    @property
    def payload_json(self) -> str:
        return _canonical_json(self.payload)

    @property
    def fingerprint(self) -> str:
        return _sha256(
            _canonical_json(
                {
                    "account_scope": self.account_scope,
                    "expires_at": self.expires_at,
                    "issued_at": self.issued_at,
                    "kind": self.kind.value,
                    "manual_resume_authorized": self.manual_resume_authorized,
                    "payload": json.loads(self.payload_json),
                    "receipt_digest": self.receipt_digest,
                    "strategy_scope": self.strategy_scope,
                }
            )
        )


class GatewayAdmission(Protocol):
    """Server-owned, read-only admission check for non-read commands.

    Implementations must revalidate the command's current account/session,
    execution and risk authority.  They must not perform provider I/O or
    reserve/dispatch work; the router invokes the account owner only after an
    exact ``True`` result.
    """

    def __call__(self, principal: GatewayPrincipal, command: GatewayCommand) -> bool:
        """Return the literal boolean ``True`` only for currently admitted work."""


@dataclass(frozen=True)
class GatewayDispatchResult:
    """A persisted result, including an unknown state that must not be retried."""

    command: GatewayCommand
    status: GatewayCommandStatus
    principal_id: str
    outcome: Mapping[str, Any]

    def __post_init__(self) -> None:
        _validate_redacted(self.outcome)
        object.__setattr__(self, "outcome", _freeze_json(json.loads(_canonical_json(self.outcome))))


class GatewayExecutor(Protocol):
    """Server-side account owner invoked only after the command is journaled."""

    def __call__(self, command: GatewayCommand) -> Mapping[str, Any]:
        """Execute a command and return a redacted outcome mapping."""


class GatewayCommandRouter:
    """Persist-before-dispatch command router with no automatic fallback/retry."""

    def __init__(
        self,
        database_path: Union[Path, str],  # noqa: UP007 -- Python 3.9 is supported.
        executor: GatewayExecutor,
        clock: Optional[Callable[[], float]] = None,  # noqa: UP045 -- Python 3.9 is supported.
        timeout_seconds: float = 5.0,
        admission: Optional[GatewayAdmission] = None,  # noqa: UP045 -- Python 3.9 is supported.
        writer_authority: Optional[GatewayAccountWriterAuthority] = None,  # noqa: UP045 -- Python 3.9 is supported.
    ) -> None:
        self._database_identity = SQLiteFileIdentity(Path(database_path).absolute())
        self._database_path = self._database_identity.path
        self._executor = executor
        self._clock = clock or time.time
        self._timeout_seconds = timeout_seconds
        if admission is not None and not callable(admission):
            raise TypeError("admission must be callable")
        if (
            writer_authority is not None
            and writer_authority.database_path != Path(database_path).resolve()
        ):
            raise ValueError("writer_authority and router must use the same SQLite database")
        self._admission = admission
        self._writer_authority = writer_authority
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    def dispatch(
        self, principal: GatewayPrincipal, command: GatewayCommand
    ) -> GatewayDispatchResult:
        """Validate, atomically journal, then invoke the single owner executor once."""
        self._authorize(principal, command)
        with self._transaction() as connection:
            now = self._clock()
            self._expire_unfinished(connection, now)
            existing = connection.execute(
                "SELECT * FROM gateway_commands WHERE command_id = ?", (command.command_id,)
            ).fetchone()
            if existing is not None:
                if str(existing["principal_id"]) != principal.principal_id:
                    raise GatewayRoutingError(
                        "COMMAND_PRINCIPAL_MISMATCH", "command belongs to another principal"
                    )
                if str(existing["fingerprint"]) != command.fingerprint:
                    raise GatewayRoutingError(
                        "COMMAND_ID_REUSED", "command id was reused with different content"
                    )
                return self._result_from_row(existing)
            if command.expires_at <= now:
                raise GatewayRoutingError("COMMAND_EXPIRED", "command expired before dispatch")
            if command.issued_at > now:
                raise GatewayRoutingError(
                    "COMMAND_NOT_YET_VALID", "command issued_at is in the future"
                )
            connection.execute(
                """
                INSERT INTO gateway_commands (
                    command_id, fingerprint, account_scope, strategy_scope, kind, payload_json,
                    receipt_digest, issued_at, expires_at, manual_resume_authorized, principal_id,
                    status, outcome_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    command.command_id,
                    command.fingerprint,
                    command.account_scope,
                    command.strategy_scope,
                    command.kind.value,
                    command.payload_json,
                    command.receipt_digest,
                    command.issued_at,
                    command.expires_at,
                    int(command.manual_resume_authorized),
                    principal.principal_id,
                    GatewayCommandStatus.PENDING.value,
                    now,
                    now,
                ),
            )

        # The SQLite writer lock may have consumed the command's remaining TTL.
        # Expiry before the owner is called proves that no side effect occurred.
        if command.expires_at <= self._clock():
            self._finish(
                command.command_id,
                GatewayCommandStatus.EXPIRED,
                {"reason": "expired_before_dispatch"},
            )
            raise GatewayRoutingError("COMMAND_EXPIRED", "command expired before dispatch")

        # READ is the only command that does not change account or control
        # state. A client-side digest and principal ACL are not substitutes for
        # current server-side execution/risk/session admission.
        action_claim: Optional[GatewayActionClaim] = None  # noqa: UP045 -- Python 3.9 is supported.
        writer_lease: Any = None
        if command.kind is not GatewayCommandKind.READ:
            try:
                admitted = (
                    self._admission is not None and self._admission(principal, command) is True
                )
            except Exception as exc:
                terminal = self._reject_pending(
                    command.command_id,
                    {
                        "error_type": type(exc).__name__,
                        "reason": "server_admission_rejected",
                    },
                )
                if terminal.status is GatewayCommandStatus.EXPIRED:
                    raise GatewayRoutingError(
                        "COMMAND_EXPIRED", "command expired before dispatch"
                    ) from None
                if terminal.status is not GatewayCommandStatus.REJECTED:
                    return terminal
                raise GatewayRoutingError(
                    "SERVER_ADMISSION_REJECTED", "server admission did not approve command"
                ) from None
            if not admitted:
                reason = (
                    "server_admission_unavailable"
                    if self._admission is None
                    else "server_admission_rejected"
                )
                terminal = self._reject_pending(
                    command.command_id,
                    {"reason": reason},
                )
                if terminal.status is GatewayCommandStatus.EXPIRED:
                    raise GatewayRoutingError("COMMAND_EXPIRED", "command expired before dispatch")
                if terminal.status is not GatewayCommandStatus.REJECTED:
                    return terminal
                code = (
                    "SERVER_ADMISSION_UNAVAILABLE"
                    if self._admission is None
                    else "SERVER_ADMISSION_REJECTED"
                )
                raise GatewayRoutingError(code, "server admission did not approve command")

            if self._writer_authority is None:
                terminal = self._reject_pending(
                    command.command_id,
                    {"reason": "writer_authority_unavailable"},
                )
                if terminal.status is GatewayCommandStatus.EXPIRED:
                    raise GatewayRoutingError("COMMAND_EXPIRED", "command expired before dispatch")
                if terminal.status is not GatewayCommandStatus.REJECTED:
                    return terminal
                raise GatewayRoutingError(
                    "WRITER_AUTHORITY_UNAVAILABLE",
                    "non-read command has no server-owned account writer authority",
                )
            try:
                writer_lease = self._writer_authority.lease_for(command.account_scope)
                action_claim = self._writer_authority.claim_action(writer_lease, principal, command)
            except Exception as exc:
                terminal = self._reject_pending(
                    command.command_id,
                    {
                        "error_type": type(exc).__name__,
                        "reason": "writer_action_claim_rejected",
                    },
                )
                if terminal.status is GatewayCommandStatus.EXPIRED:
                    raise GatewayRoutingError(
                        "COMMAND_EXPIRED", "command expired before dispatch"
                    ) from None
                if terminal.status is not GatewayCommandStatus.REJECTED:
                    return terminal
                raise GatewayRoutingError(
                    "WRITER_ACTION_CLAIM_REJECTED",
                    "server writer authority did not claim command",
                ) from None

        # Admission can block on local authority reads. Claim the dispatch
        # transition only after it returns, so expiry/recovery can distinguish
        # an unadmitted command (known not sent) from an owner call in flight.
        recovered = self._begin_dispatch(command.command_id)
        if recovered is not None:
            if action_claim is not None and recovered.status is GatewayCommandStatus.EXPIRED:
                self._writer_authority.reject_unstarted_action(
                    action_claim, "command_expired_before_dispatch"
                )
            if recovered.status is GatewayCommandStatus.EXPIRED:
                raise GatewayRoutingError("COMMAND_EXPIRED", "command expired before dispatch")
            return recovered

        if action_claim is not None:
            try:
                # This commits the current epoch, lease expiry/revocation, action
                # binding, and single-use claim check immediately before owner call.
                self._writer_authority.begin_action_dispatch(
                    writer_lease, principal, command, action_claim
                )
            except Exception as exc:
                self._writer_authority.reject_unstarted_action(action_claim, type(exc).__name__)
                status = (
                    GatewayCommandStatus.EXPIRED
                    if command.expires_at <= self._clock()
                    else GatewayCommandStatus.REJECTED
                )
                self._finish(
                    command.command_id,
                    status,
                    {"reason": "writer_final_check_rejected"},
                )
                raise GatewayRoutingError(
                    "WRITER_FINAL_CHECK_REJECTED",
                    "writer epoch or action claim failed immediately before dispatch",
                ) from None

        try:
            outcome = dict(self._executor(command))
            _validate_redacted(outcome)
        except Exception as exc:
            # An executor can fail after a provider accepted its request. The
            # exception is not evidence of rejection, and must not free capacity.
            safe_outcome = {
                "error_type": type(exc).__name__,
                "reason": "dispatch_reconciliation_required",
            }
            if action_claim is not None:
                with contextlib.suppress(Exception):
                    self._writer_authority.mark_unknown(action_claim, type(exc).__name__)
                    # The durable DISPATCHING claim itself remains unresolved and
                    # fences takeover if a crash or storage error interrupts us.
            self._finish(command.command_id, GatewayCommandStatus.UNKNOWN, safe_outcome)
            raise GatewayDispatchError("account owner execution failed") from exc

        if action_claim is not None:
            # A local executor return says nothing about provider acceptance.
            self._writer_authority.mark_owner_returned_unverified(action_claim, outcome)
        self._finish(
            command.command_id,
            (
                GatewayCommandStatus.RETURNED_UNVERIFIED
                if action_claim is not None
                else GatewayCommandStatus.SUCCEEDED
            ),
            outcome,
        )
        return GatewayDispatchResult(
            command=command,
            status=(
                GatewayCommandStatus.RETURNED_UNVERIFIED
                if action_claim is not None
                else GatewayCommandStatus.SUCCEEDED
            ),
            principal_id=principal.principal_id,
            outcome=outcome,
        )

    def get(self, command_id: str) -> Optional[GatewayDispatchResult]:  # noqa: UP045 -- Python 3.9 is supported.
        """Read a command state without creating a new dispatch opportunity."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM gateway_commands WHERE command_id = ?", (command_id,)
            ).fetchone()
        return self._result_from_row(row) if row is not None else None

    def _authorize(self, principal: GatewayPrincipal, command: GatewayCommand) -> None:
        if command.account_scope not in principal.account_scopes:
            raise GatewayRoutingError(
                "ACCOUNT_SCOPE_DENIED", "principal is not authorized for account"
            )
        if command.strategy_scope not in principal.strategy_scopes:
            raise GatewayRoutingError(
                "STRATEGY_SCOPE_DENIED", "principal is not authorized for strategy"
            )
        if command.kind not in principal.allowed_kinds:
            raise GatewayRoutingError(
                "COMMAND_KIND_DENIED", "principal is not authorized for command kind"
            )

    def _finish(
        self, command_id: str, status: GatewayCommandStatus, outcome: Mapping[str, Any]
    ) -> None:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT status FROM gateway_commands WHERE command_id = ?", (command_id,)
            ).fetchone()
            if row is None:
                raise GatewayRoutingError(
                    "COMMAND_UNKNOWN", "journal entry disappeared before completion"
                )
            if row["status"] not in (
                GatewayCommandStatus.PENDING.value,
                GatewayCommandStatus.DISPATCHING.value,
                GatewayCommandStatus.UNKNOWN.value,
            ):
                raise GatewayRoutingError(
                    "COMMAND_NOT_DISPATCHING", "command cannot change terminal state"
                )
            connection.execute(
                """
                UPDATE gateway_commands SET status = ?, outcome_json = ?, updated_at = ?
                WHERE command_id = ?
                """,
                (status.value, _canonical_json(outcome), self._clock(), command_id),
            )

    def _begin_dispatch(self, command_id: str) -> Optional[GatewayDispatchResult]:  # noqa: UP045 -- Python 3.9 is supported.
        """Atomically move an admitted, unexpired command to owner dispatch."""
        with self._transaction() as connection:
            now = self._clock()
            self._expire_unfinished(connection, now)
            row = connection.execute(
                "SELECT * FROM gateway_commands WHERE command_id = ?", (command_id,)
            ).fetchone()
            if row is None:
                raise GatewayRoutingError(
                    "COMMAND_UNKNOWN", "journal entry disappeared before dispatch"
                )
            if row["status"] != GatewayCommandStatus.PENDING.value:
                return self._result_from_row(row)
            if float(row["expires_at"]) <= now:
                connection.execute(
                    """
                    UPDATE gateway_commands SET status = ?, outcome_json = ?, updated_at = ?
                    WHERE command_id = ?
                    """,
                    (
                        GatewayCommandStatus.EXPIRED.value,
                        _canonical_json({"reason": "expired_before_dispatch"}),
                        now,
                        command_id,
                    ),
                )
                return self._result_from_row(
                    connection.execute(
                        "SELECT * FROM gateway_commands WHERE command_id = ?", (command_id,)
                    ).fetchone()
                )
            connection.execute(
                "UPDATE gateway_commands SET status = ?, updated_at = ? WHERE command_id = ?",
                (GatewayCommandStatus.DISPATCHING.value, now, command_id),
            )
        return None

    def _reject_pending(self, command_id: str, outcome: Mapping[str, Any]) -> GatewayDispatchResult:
        """Reject pre-dispatch work without racing an expiry transition."""
        with self._transaction() as connection:
            now = self._clock()
            self._expire_unfinished(connection, now)
            row = connection.execute(
                "SELECT * FROM gateway_commands WHERE command_id = ?", (command_id,)
            ).fetchone()
            if row is None:
                raise GatewayRoutingError(
                    "COMMAND_UNKNOWN", "journal entry disappeared before admission"
                )
            if row["status"] != GatewayCommandStatus.PENDING.value:
                return self._result_from_row(row)
            connection.execute(
                """
                UPDATE gateway_commands SET status = ?, outcome_json = ?, updated_at = ?
                WHERE command_id = ?
                """,
                (
                    GatewayCommandStatus.REJECTED.value,
                    _canonical_json(outcome),
                    now,
                    command_id,
                ),
            )
            row = connection.execute(
                "SELECT * FROM gateway_commands WHERE command_id = ?", (command_id,)
            ).fetchone()
            return self._result_from_row(row)

    def _expire_unfinished(self, connection: sqlite3.Connection, now: float) -> None:
        connection.execute(
            """
            UPDATE gateway_commands SET status = ?, outcome_json = ?, updated_at = ?
            WHERE status = ? AND expires_at <= ?
            """,
            (
                GatewayCommandStatus.EXPIRED.value,
                _canonical_json({"reason": "expired_before_dispatch"}),
                now,
                GatewayCommandStatus.PENDING.value,
                now,
            ),
        )
        connection.execute(
            """
            UPDATE gateway_commands SET status = ?, outcome_json = ?, updated_at = ?
            WHERE status = ? AND expires_at <= ?
            """,
            (
                GatewayCommandStatus.UNKNOWN.value,
                _canonical_json({"reason": "dispatch_reconciliation_required"}),
                now,
                GatewayCommandStatus.DISPATCHING.value,
                now,
            ),
        )

    def _result_from_row(self, row: sqlite3.Row) -> GatewayDispatchResult:
        command = GatewayCommand(
            command_id=str(row["command_id"]),
            account_scope=str(row["account_scope"]),
            strategy_scope=str(row["strategy_scope"]),
            kind=GatewayCommandKind(str(row["kind"])),
            payload=json.loads(str(row["payload_json"])),
            receipt_digest=str(row["receipt_digest"]),
            issued_at=float(row["issued_at"]),
            expires_at=float(row["expires_at"]),
            manual_resume_authorized=bool(row["manual_resume_authorized"]),
        )
        outcome = json.loads(str(row["outcome_json"])) if row["outcome_json"] else {}
        return GatewayDispatchResult(
            command=command,
            status=GatewayCommandStatus(str(row["status"])),
            principal_id=str(row["principal_id"]),
            outcome=outcome,
        )

    def _initialize_schema(self) -> None:
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS gateway_commands (
                    command_id TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    account_scope TEXT NOT NULL,
                    strategy_scope TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    receipt_digest TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    manual_resume_authorized INTEGER NOT NULL,
                    principal_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    outcome_json TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_gateway_commands_scope_status
                    ON gateway_commands(account_scope, strategy_scope, status, issued_at);
                """
            )

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


_SENSITIVE_KEY_PARTS = ("password", "secret", "token", "credential", "private_key", "api_key")


def _validate_redacted(value: Any) -> None:
    def visit(item: Any, path: str = "") -> None:
        if isinstance(item, Mapping):
            for key, nested in item.items():
                normalized = str(key).lower()
                if any(part in normalized for part in _SENSITIVE_KEY_PARTS):
                    raise ValueError("gateway payload/outcome must be redacted: " + path + str(key))
                visit(nested, path + str(key) + ".")
        elif isinstance(item, (list, tuple)):
            for nested in item:
                visit(nested, path)

    visit(value)
    try:
        _canonical_json(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("gateway payload/outcome must be JSON serializable") from exc


def _canonical_json(value: object) -> str:
    return json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _json_value(nested) for key, nested in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(nested) for nested in value]
    return value


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(nested) for key, nested in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(nested) for nested in value)
    return value


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
