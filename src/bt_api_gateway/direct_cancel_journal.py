"""Same-database cancel attempts. These trusted labels do not authorize trading."""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from contextlib import ExitStack
from dataclasses import dataclass

from bt_api_base.direct_cancel_protocol import PreparedCancelRequest
from bt_api_base.direct_write_protocol import NativeOrderIdentity

from .direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
    _json,
    _text,
)
from .direct_dispatch import _identity, _request

_CANCEL_DDL = {
    "direct_cancel_attempts": "CREATE TABLE direct_cancel_attempts (account TEXT NOT NULL, strategy TEXT NOT NULL, operation_id TEXT NOT NULL, principal TEXT NOT NULL, target_principal TEXT NOT NULL, request_key TEXT NOT NULL, target_reservation_id TEXT NOT NULL, target_digest TEXT NOT NULL, target_identity_json TEXT NOT NULL, symbol TEXT NOT NULL, generation TEXT NOT NULL, target_version INTEGER NOT NULL, attempt_id TEXT NOT NULL UNIQUE, status TEXT NOT NULL, version INTEGER NOT NULL, prepared_json TEXT, prepared_digest TEXT, marker_id TEXT, error_code TEXT, PRIMARY KEY(account, strategy, operation_id))",
    "direct_cancel_keys": "CREATE TABLE direct_cancel_keys (account TEXT NOT NULL, strong_key TEXT NOT NULL, attempt_id TEXT NOT NULL, PRIMARY KEY(account, strong_key))",
    "direct_cancel_keys_attempt": "CREATE INDEX direct_cancel_keys_attempt ON direct_cancel_keys(account, attempt_id)",
}


def _create_cancel_tables(db: sqlite3.Connection) -> None:
    for sql in _CANCEL_DDL.values():
        db.execute(sql)


def _error(value):
    if value is not None and (
        type(value) is not str
        or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", value, re.ASCII) is None
    ):
        raise DirectCommandJournalError("INVALID_INPUT")
    return value


def _target_json(identity: NativeOrderIdentity) -> str:
    if type(identity) is not NativeOrderIdentity:
        raise DirectCommandJournalError("INVALID_INPUT")
    try:
        return _json(_identity(identity, identity.exchange_name))
    except Exception as exc:
        raise DirectCommandJournalError("INVALID_INPUT") from exc


@dataclass(frozen=True)
class CancelRecord:
    account_scope: str
    strategy_scope: str
    operation_id: str
    principal: str
    target_principal: str
    request_key: str
    target_reservation_id: str
    target_digest: str
    target_identity: NativeOrderIdentity
    symbol: str
    generation: str
    target_version: int
    attempt_id: str
    status: str
    version: int
    prepared_cancel: PreparedCancelRequest | None
    prepared_digest: str | None
    marker_id: str | None
    error_code: str | None


@dataclass(frozen=True)
class CancelDispatchStart:
    record: CancelRecord
    newly_started: bool


def _native(raw: str) -> NativeOrderIdentity:
    value = json.loads(raw)
    if type(value) is not dict or set(value) != {
        "exchange_name",
        "client_order_id",
        "session_generation",
        "fields_json",
    }:
        raise ValueError("identity")
    identity = NativeOrderIdentity(
        value["exchange_name"],
        value["client_order_id"],
        json.loads(value["fields_json"]),
        value["session_generation"],
    )
    if _target_json(identity) != raw:
        raise ValueError("identity")
    return identity


def _record(row: sqlite3.Row) -> CancelRecord:
    prepared = (
        None
        if row["prepared_json"] is None
        else PreparedCancelRequest.from_mapping(json.loads(row["prepared_json"]))
    )
    return CancelRecord(
        row["account"],
        row["strategy"],
        row["operation_id"],
        row["principal"],
        row["target_principal"],
        row["request_key"],
        row["target_reservation_id"],
        row["target_digest"],
        _native(row["target_identity_json"]),
        row["symbol"],
        row["generation"],
        row["target_version"],
        row["attempt_id"],
        row["status"],
        row["version"],
        prepared,
        row["prepared_digest"],
        row["marker_id"],
        row["error_code"],
    )


def _target(db, account, strategy, request_key, reservation, digest, principal):
    row = db.execute(
        "SELECT * FROM direct_journal_commands WHERE account=? AND strategy=? AND request_key=?",
        (account, strategy, request_key),
    ).fetchone()
    if row is None:
        raise DirectCommandJournalError("NOT_FOUND")
    if (
        row["principal"] != principal
        or row["reservation_id"] != reservation
        or row["digest"] != digest
    ):
        raise DirectCommandJournalError("REQUEST_CONFLICT")
    return row


def _delegated_cancel_target(db, account, strategy, request_key, reservation, target_principal):
    """Check the historical actor without substituting the current requester."""
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='direct_delegated_commands'").fetchone() is None:
        return False
    return db.execute(
        "SELECT 1 FROM direct_delegated_commands WHERE account=? AND strategy=? "
        "AND request_key=? AND reservation_id=? AND actor_principal=?",
        (account, strategy, request_key, reservation, target_principal),
    ).fetchone() is not None


def _control_cancel_target(db, account, attempt):
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='direct_control_cancel_proofs'").fetchone() is None:
        return False
    return db.execute('SELECT 1 FROM direct_control_cancel_proofs WHERE account=? AND strategy=? AND operation_id=? AND attempt_id=?',
                      (account, attempt.strategy_scope, attempt.operation_id, attempt.attempt_id)).fetchone() is not None


def _verify_cancel_integrity(db: sqlite3.Connection, account: str, capacity: int) -> None:
    try:
        rows = db.execute(
            "SELECT * FROM direct_cancel_attempts LIMIT ?", (capacity + 1,)
        ).fetchall()
        if len(rows) > capacity:
            raise ValueError("capacity")
        expected_keys = set()
        for row in rows:
            item = _record(row)
            for name in (
                "account_scope",
                "strategy_scope",
                "operation_id",
                "principal",
                "target_principal",
                "request_key",
                "target_reservation_id",
                "target_digest",
                "symbol",
                "generation",
                "attempt_id",
            ):
                _text(getattr(item, name))
            parsed_attempt = uuid.UUID(item.attempt_id)
            if (
                str(parsed_attempt) != item.attempt_id
                or parsed_attempt.version != 4
                or item.account_scope != account
                or (item.principal != item.target_principal and not _control_cancel_target(db, account, item) and not _delegated_cancel_target(
                    db, account, item.strategy_scope, item.request_key,
                    item.target_reservation_id, item.target_principal))
                or type(item.target_version) is not int
                or item.target_version < 2
            ):
                raise ValueError("attempt fields")
            command = _target(
                db,
                account,
                item.strategy_scope,
                item.request_key,
                item.target_reservation_id,
                item.target_digest,
                item.target_principal,
            )
            if (
                command["native_identity_json"] != row["target_identity_json"]
                or _request(command["payload_json"])["symbol"] != item.symbol
                or command["version"] < item.target_version
            ):
                raise ValueError("target")
            _error(item.error_code)
            versions = {"REQUESTED": 1, "DISPATCHING": 2, "SENT": 3, "NOT_SENT": 3, "UNKNOWN": 3}
            if versions.get(item.status) != item.version:
                raise ValueError("status")
            if item.status == "REQUESTED":
                if any(
                    x is not None
                    for x in (
                        item.prepared_cancel,
                        item.prepared_digest,
                        item.marker_id,
                        item.error_code,
                    )
                ):
                    raise ValueError("requested fields")
            else:
                prepared = item.prepared_cancel
                if (
                    prepared is None
                    or _json(prepared.to_mapping()) != row["prepared_json"]
                    or prepared.digest() != item.prepared_digest
                    or item.marker_id != item.attempt_id
                    or _target_json(prepared.target_identity) != row["target_identity_json"]
                    or prepared.symbol != item.symbol
                    or (item.status == "DISPATCHING" and item.error_code is not None)
                ):
                    raise ValueError("prepared")
                expected_keys.update(
                    (account, key, item.attempt_id) for key in prepared.request_keys
                )
        actual_keys = {
            tuple(row)
            for row in db.execute(
                "SELECT account,strong_key,attempt_id FROM direct_cancel_keys LIMIT ?",
                (capacity * 16 + 1,),
            )
        }
        if expected_keys != actual_keys:
            raise ValueError("attempt keys")
    except Exception as exc:
        raise DirectCommandJournalError("INVALID_DATABASE") from exc


class GatewayDirectCancelJournal:
    """Trusted local attempts in exactly the original command database."""

    def __init__(self, journal: GatewayDirectCommandJournal) -> None:
        if type(journal) is not GatewayDirectCommandJournal:
            raise DirectCommandJournalError("INVALID_INPUT")
        self._journal = journal

    @property
    def journal(self) -> GatewayDirectCommandJournal:
        return self._journal

    def _require(self, db, strategy, operation_id, principal):
        row = db.execute(
            "SELECT * FROM direct_cancel_attempts WHERE account=? AND strategy=? AND operation_id=?",
            (self.journal.account_scope, strategy, operation_id),
        ).fetchone()
        if row is None:
            raise DirectCommandJournalError("NOT_FOUND")
        if row["principal"] != principal:
            raise DirectCommandJournalError("REQUEST_CONFLICT")
        return row

    def request(
        self,
        strategy,
        operation_id,
        principal,
        request_key,
        reservation_id,
        digest,
        *,
        target_identity,
        symbol,
        before_commit=None,
        target_principal=None,
        strategy_admission_fence=None,
        parent_command=None,
        parent_cancel_recheck=None,
        control_cancel_permit=None,
    ):
        if before_commit is not None and not callable(before_commit):
            raise DirectCommandJournalError("INVALID_INPUT")
        strategy, operation_id, principal, request_key, reservation_id, digest, symbol = map(
            _text, (strategy, operation_id, principal, request_key, reservation_id, digest, symbol)
        )
        target_principal = principal if target_principal is None else _text(target_principal)
        delegated = principal != target_principal
        control = control_cancel_permit is not None
        if control:
            from .direct_control_cancel import GatewayControlCancelPermit
            if (self.journal._schema_version < 17 or type(control_cancel_permit) is not GatewayControlCancelPermit
                    or not callable(strategy_admission_fence) or parent_command is not None or parent_cancel_recheck is not None):
                raise DirectCommandJournalError('CONTROL_CANCEL_DENIED')
        if delegated and (self.journal._schema_version < 12 or not callable(strategy_admission_fence)):
            raise DirectCommandJournalError("DELEGATION_UNAVAILABLE")
        if not delegated and not control and strategy_admission_fence is not None:
            raise DirectCommandJournalError("INVALID_INPUT")
        identity = _target_json(target_identity)
        with ExitStack() as stack:
            check = None
            if delegated or control:
                manager = strategy_admission_fence()
                check = type(manager).__enter__(manager)
                exit_ = type(manager).__exit__
                stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
                if not callable(check):
                    raise DirectCommandJournalError("INVALID_ADMISSION")
            db = stack.enter_context(self.journal._transaction())
            if delegated or control:
                check()
                if delegated and not control and not _delegated_cancel_target(db, self.journal.account_scope, strategy,
                                                request_key, reservation_id, target_principal):
                    raise DirectCommandJournalError("DELEGATION_MISMATCH")
            if control:
                b = control_cancel_permit.binding
                if (b['account'], b['strategy'], b['operation_id'], b['requester'], b['target_principal'],
                    b['request_key'], b['reservation_id'], b['digest'], b['native_identity_json'], b['symbol']) != (
                    self.journal.account_scope, strategy, operation_id, principal, target_principal,
                    request_key, reservation_id, digest, identity, symbol):
                    raise DirectCommandJournalError('CONTROL_CANCEL_DENIED')
                control_cancel_permit.recheck(db)
            if not control and self.journal._schema_version >= 12 and principal == target_principal:
                from bt_api_base.gateway_delegation_protocol import GatewayDelegatedCommand
                saved = db.execute('SELECT envelope_json FROM direct_delegated_commands WHERE account=? AND strategy=? AND request_key=?',
                    (self.journal.account_scope, strategy, request_key)).fetchone()
                cmd = None if saved is None else GatewayDelegatedCommand.from_mapping(json.loads(saved['envelope_json']))
                if cmd is not None and cmd.parent_ref is not None:
                    if type(parent_command) is not GatewayDelegatedCommand or parent_command != cmd or not callable(parent_cancel_recheck):
                        raise DirectCommandJournalError('PARENT_CANCEL_DENIED')
                elif parent_command is not None or parent_cancel_recheck is not None:
                    raise DirectCommandJournalError('PARENT_CANCEL_DENIED')
            else:
                cmd = None
            def check_parent():
                if cmd is not None and cmd.parent_ref is not None and parent_cancel_recheck(
                        db, cmd, operation_id, reservation_id, digest) is not True:
                    raise DirectCommandJournalError('PARENT_CANCEL_DENIED')
            check_parent()
            old = db.execute(
                "SELECT * FROM direct_cancel_attempts WHERE account=? AND strategy=? AND operation_id=?",
                (self.journal.account_scope, strategy, operation_id),
            ).fetchone()
            if old is not None:
                if (
                    old["principal"],
                    old["target_principal"],
                    old["request_key"],
                    old["target_reservation_id"],
                    old["target_digest"],
                    old["target_identity_json"],
                    old["symbol"],
                ) != (principal, target_principal, request_key, reservation_id, digest, identity, symbol):
                    raise DirectCommandJournalError("REQUEST_CONFLICT")
                if before_commit is not None:
                    before_commit()
                if check is not None:
                    check()
                check_parent()
                if control:
                    proof = db.execute('SELECT attempt_id,proof_json FROM direct_control_cancel_proofs WHERE account=? AND strategy=? AND operation_id=?',
                                       (self.journal.account_scope, strategy, operation_id)).fetchone()
                    if proof is None or (proof['attempt_id'], proof['proof_json']) != (old['attempt_id'], control_cancel_permit.binding_json):
                        raise DirectCommandJournalError('CONTROL_CANCEL_DENIED')
                    control_cancel_permit.recheck(db)
                return _record(old)
            command = _target(
                db,
                self.journal.account_scope,
                strategy,
                request_key,
                reservation_id,
                digest,
                target_principal,
            )
            if (
                command["status"] not in {"DISPATCHING", "SENT", "UNKNOWN"}
                or command["native_identity_json"] != identity
                or _request(command["payload_json"])["symbol"] != symbol
            ):
                raise DirectCommandJournalError("INVALID_TARGET")
            if (
                db.execute(
                    "SELECT count(*) FROM direct_cancel_attempts WHERE account=?",
                    (self.journal.account_scope,),
                ).fetchone()[0]
                >= self.journal._max_records
            ):
                raise DirectCommandJournalError("CANCEL_CAPACITY_EXCEEDED")
            attempt = str(uuid.uuid4())
            db.execute(
                "INSERT INTO direct_cancel_attempts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'REQUESTED', 1, NULL, NULL, NULL, NULL)",
                (
                    self.journal.account_scope,
                    strategy,
                    operation_id,
                    principal,
                    target_principal,
                    request_key,
                    reservation_id,
                    digest,
                    identity,
                    symbol,
                    self.journal.generation,
                    command["version"],
                    attempt,
                ),
            )
            if control:
                control_cancel_permit.append(db, attempt)
            self.journal._bump(db)
            result = _record(self._require(db, strategy, operation_id, principal))
            if before_commit is not None:
                before_commit()
            if check is not None:
                check()
            check_parent()
            if control:
                control_cancel_permit.recheck(db)
            return result

    def get(self, strategy, operation_id, principal):
        strategy, operation_id, principal = map(_text, (strategy, operation_id, principal))
        with self.journal._transaction() as db:
            return _record(self._require(db, strategy, operation_id, principal))

    def find_by_request_key(self, cancel_key: str) -> CancelRecord | None:
        """Read the cancel-key namespace only; no authority or freshness implied."""
        cancel_key = _text(cancel_key)
        with self.journal._transaction() as db:
            return _find_cancel_by_request_key(db, self.journal.account_scope, cancel_key)

    def begin_dispatch(
        self,
        strategy,
        operation_id,
        principal,
        expected_version,
        prepared_cancel,
        *,
        before_dispatch=None,
        strategy_admission_fence=None,
        parent_command=None,
        parent_cancel_recheck=None,
        control_cancel_permit=None,
    ):
        strategy, operation_id, principal = map(_text, (strategy, operation_id, principal))
        if (
            type(expected_version) is not int
            or type(prepared_cancel) is not PreparedCancelRequest
            or (before_dispatch is not None and not callable(before_dispatch))
        ):
            raise DirectCommandJournalError("INVALID_INPUT")
        try:
            mapping = prepared_cancel.to_mapping()
            prepared_json = _json(mapping)
            digest = prepared_cancel.digest()
        except Exception as exc:
            raise DirectCommandJournalError("INVALID_INPUT") from exc
        with ExitStack() as stack:
            check = None
            if strategy_admission_fence is not None:
                if not callable(strategy_admission_fence):
                    raise DirectCommandJournalError("INVALID_ADMISSION")
                manager = strategy_admission_fence()
                check = type(manager).__enter__(manager)
                exit_ = type(manager).__exit__
                stack.push(lambda *exc: (exit_(manager, *exc), False)[1])
                if not callable(check):
                    raise DirectCommandJournalError("INVALID_ADMISSION")
            db = stack.enter_context(self.journal._transaction())
            row = self._require(db, strategy, operation_id, principal)
            control = control_cancel_permit is not None
            if self.journal._schema_version >= 17 and not control and db.execute(
                    'SELECT 1 FROM direct_control_cancel_proofs WHERE account=? AND strategy=? AND operation_id=?',
                    (self.journal.account_scope, strategy, operation_id)).fetchone() is not None:
                raise DirectCommandJournalError('CONTROL_CANCEL_DENIED')
            if control:
                from .direct_control_cancel import GatewayControlCancelPermit
                if (self.journal._schema_version < 17 or type(control_cancel_permit) is not GatewayControlCancelPermit
                        or check is None or parent_command is not None or parent_cancel_recheck is not None):
                    raise DirectCommandJournalError('CONTROL_CANCEL_DENIED')
                proof = db.execute('SELECT attempt_id,proof_json FROM direct_control_cancel_proofs WHERE account=? AND strategy=? AND operation_id=?',
                                   (self.journal.account_scope, strategy, operation_id)).fetchone()
                if proof is None or (proof['attempt_id'], proof['proof_json']) != (row['attempt_id'], control_cancel_permit.binding_json):
                    raise DirectCommandJournalError('CONTROL_CANCEL_DENIED')
                control_cancel_permit.recheck(db)
            parent = None
            if not control and self.journal._schema_version >= 12 and row['principal'] == row['target_principal']:
                from bt_api_base.gateway_delegation_protocol import GatewayDelegatedCommand
                saved = db.execute('SELECT envelope_json FROM direct_delegated_commands WHERE account=? AND strategy=? AND request_key=?',
                    (self.journal.account_scope, strategy, row['request_key'])).fetchone()
                parent = None if saved is None else GatewayDelegatedCommand.from_mapping(json.loads(saved['envelope_json']))
                if parent is not None and parent.parent_ref is not None:
                    if type(parent_command) is not GatewayDelegatedCommand or parent_command != parent or not callable(parent_cancel_recheck):
                        raise DirectCommandJournalError('PARENT_CANCEL_DENIED')
                elif parent_command is not None or parent_cancel_recheck is not None:
                    raise DirectCommandJournalError('PARENT_CANCEL_DENIED')
            def check_parent():
                if parent is not None and parent.parent_ref is not None and parent_cancel_recheck(
                        db, parent, operation_id, row['target_reservation_id'], row['target_digest']) is not True:
                    raise DirectCommandJournalError('PARENT_CANCEL_DENIED')
            check_parent()
            if row["principal"] != row["target_principal"]:
                if self.journal._schema_version < 12 or check is None:
                    raise DirectCommandJournalError("DELEGATION_UNAVAILABLE")
                check()
                if not control and not _delegated_cancel_target(db, self.journal.account_scope, strategy,
                        row["request_key"], row["target_reservation_id"], row["target_principal"]):
                    raise DirectCommandJournalError("DELEGATION_MISMATCH")
            elif strategy_admission_fence is not None and not control:
                raise DirectCommandJournalError("INVALID_INPUT")
            if row["status"] != "REQUESTED":
                if row["prepared_json"] != prepared_json or row["prepared_digest"] != digest:
                    raise DirectCommandJournalError("REQUEST_CONFLICT")
                if check is not None:
                    check()
                check_parent()
                if control:
                    control_cancel_permit.recheck(db)
                return CancelDispatchStart(_record(row), False)
            if row["version"] != expected_version:
                raise DirectCommandJournalError("VERSION_CONFLICT")
            if row["generation"] != self.journal.generation:
                raise DirectCommandJournalError("GENERATION_MISMATCH")
            command = _target(
                db,
                self.journal.account_scope,
                strategy,
                row["request_key"],
                row["target_reservation_id"],
                row["target_digest"],
                row["target_principal"],
            )
            if (
                command["status"] not in {"DISPATCHING", "SENT", "UNKNOWN"}
                or command["native_identity_json"] != row["target_identity_json"]
                or _target_json(prepared_cancel.target_identity) != row["target_identity_json"]
                or prepared_cancel.symbol != row["symbol"]
            ):
                raise DirectCommandJournalError("INVALID_TARGET")
            if before_dispatch is not None:
                before_dispatch()
            try:
                for key in prepared_cancel.request_keys:
                    db.execute(
                        "INSERT INTO direct_cancel_keys VALUES (?, ?, ?)",
                        (self.journal.account_scope, key, row["attempt_id"]),
                    )
            except sqlite3.IntegrityError as exc:
                raise DirectCommandJournalError("ATTEMPT_KEY_CONFLICT") from exc
            db.execute(
                "UPDATE direct_cancel_attempts SET status='DISPATCHING',version=2,prepared_json=?,prepared_digest=?,marker_id=attempt_id WHERE account=? AND strategy=? AND operation_id=?",
                (prepared_json, digest, self.journal.account_scope, strategy, operation_id),
            )
            self.journal._bump(db)
            if check is not None:
                check()
            check_parent()
            if control:
                control_cancel_permit.recheck(db)
            return CancelDispatchStart(
                _record(self._require(db, strategy, operation_id, principal)), True
            )

    def finish(
        self,
        strategy,
        operation_id,
        principal,
        expected_version,
        marker_id,
        prepared_digest,
        generation,
        sent,
        *,
        error_code=None,
    ):
        strategy, operation_id, principal, marker_id, prepared_digest, generation = map(
            _text, (strategy, operation_id, principal, marker_id, prepared_digest, generation)
        )
        if type(expected_version) is not int or (sent is not None and type(sent) is not bool):
            raise DirectCommandJournalError("INVALID_INPUT")
        _error(error_code)
        status = "UNKNOWN" if sent is None else ("SENT" if sent else "NOT_SENT")
        with self.journal._transaction() as db:
            row = self._require(db, strategy, operation_id, principal)
            if (
                row["marker_id"] != marker_id
                or row["prepared_digest"] != prepared_digest
                or row["generation"] != generation
                or generation != self.journal.generation
            ):
                raise DirectCommandJournalError("REQUEST_CONFLICT")
            if row["status"] != "DISPATCHING":
                if (
                    row["status"] == status
                    and row["error_code"] == error_code
                    and expected_version == 2
                ):
                    return _record(row)
                raise DirectCommandJournalError("REQUEST_CONFLICT")
            if row["version"] != expected_version:
                raise DirectCommandJournalError("VERSION_CONFLICT")
            db.execute(
                "UPDATE direct_cancel_attempts SET status=?,version=3,error_code=? WHERE account=? AND strategy=? AND operation_id=?",
                (status, error_code, self.journal.account_scope, strategy, operation_id),
            )
            self.journal._bump(db)
            return _record(self._require(db, strategy, operation_id, principal))


def _find_cancel_by_request_key(db, account, cancel_key):
    """Validate a cancel-key association inside the caller's transaction."""
    from .direct_command_journal import payload_digest

    key_row = db.execute(
        "SELECT attempt_id FROM direct_cancel_keys WHERE account=? AND strong_key=?",
        (account, cancel_key),
    ).fetchone()
    if key_row is None:
        return None
    rows = db.execute(
        "SELECT * FROM direct_cancel_attempts WHERE account=? AND attempt_id=?",
        (account, key_row["attempt_id"]),
    ).fetchall()
    try:
        if len(rows) != 1:
            raise ValueError("cancel key orphan")
        raw = rows[0]
        attempt = _record(raw)
        for value in (
            attempt.strategy_scope,
            attempt.operation_id,
            attempt.principal,
            attempt.target_principal,
            attempt.request_key,
            attempt.target_reservation_id,
            attempt.target_digest,
            attempt.symbol,
            attempt.generation,
        ):
            _text(value)
        _error(attempt.error_code)
        parsed = uuid.UUID(attempt.attempt_id)
        if (
            str(parsed) != attempt.attempt_id
            or parsed.version != 4
            or attempt.account_scope != account
            or (attempt.principal != attempt.target_principal and not _control_cancel_target(db, account, attempt) and not _delegated_cancel_target(
                db, account, attempt.strategy_scope, attempt.request_key,
                attempt.target_reservation_id, attempt.target_principal))
            or type(attempt.target_version) is not int
            or attempt.target_version < 2
            or (attempt.status == "DISPATCHING" and attempt.error_code is not None)
            or attempt.status not in {"DISPATCHING", "SENT", "UNKNOWN", "NOT_SENT"}
            or attempt.version != (2 if attempt.status == "DISPATCHING" else 3)
            or attempt.marker_id != attempt.attempt_id
            or attempt.prepared_cancel is None
            or attempt.prepared_cancel.digest() != attempt.prepared_digest
            or _json(attempt.prepared_cancel.to_mapping()) != raw["prepared_json"]
            or cancel_key not in attempt.prepared_cancel.request_keys
            or _target_json(attempt.prepared_cancel.target_identity) != raw["target_identity_json"]
            or attempt.prepared_cancel.symbol != attempt.symbol
        ):
            raise ValueError("cancel attempt")
        command = _target(
            db,
            account,
            attempt.strategy_scope,
            attempt.request_key,
            attempt.target_reservation_id,
            attempt.target_digest,
            attempt.target_principal,
        )
        if (
            command["native_identity_json"] != raw["target_identity_json"]
            or command["version"] < attempt.target_version
            or _request(command["payload_json"])["symbol"] != attempt.symbol
            or payload_digest(json.loads(command["payload_json"])) != attempt.target_digest
        ):
            raise ValueError("cancel command")
        stored = {
            r[0]
            for r in db.execute(
                "SELECT strong_key FROM direct_cancel_keys WHERE account=? AND attempt_id=? LIMIT 17",
                (account, attempt.attempt_id),
            )
        }
        if stored != set(attempt.prepared_cancel.request_keys):
            raise ValueError("cancel keys")
        return attempt
    except Exception as exc:
        raise DirectCommandJournalError("INVALID_DATABASE") from exc
