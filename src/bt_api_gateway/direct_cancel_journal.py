"""Same-database cancel attempts. These trusted labels do not authorize trading."""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
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
                or item.principal != item.target_principal
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
    ):
        strategy, operation_id, principal, request_key, reservation_id, digest, symbol = map(
            _text, (strategy, operation_id, principal, request_key, reservation_id, digest, symbol)
        )
        identity = _target_json(target_identity)
        with self.journal._transaction() as db:
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
                ) != (principal, principal, request_key, reservation_id, digest, identity, symbol):
                    raise DirectCommandJournalError("REQUEST_CONFLICT")
                return _record(old)
            command = _target(
                db,
                self.journal.account_scope,
                strategy,
                request_key,
                reservation_id,
                digest,
                principal,
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
                    principal,
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
            self.journal._bump(db)
            return _record(self._require(db, strategy, operation_id, principal))

    def get(self, strategy, operation_id, principal):
        strategy, operation_id, principal = map(_text, (strategy, operation_id, principal))
        with self.journal._transaction() as db:
            return _record(self._require(db, strategy, operation_id, principal))

    def begin_dispatch(
        self,
        strategy,
        operation_id,
        principal,
        expected_version,
        prepared_cancel,
        *,
        before_dispatch=None,
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
        with self.journal._transaction() as db:
            row = self._require(db, strategy, operation_id, principal)
            if row["status"] != "REQUESTED":
                if row["prepared_json"] != prepared_json or row["prepared_digest"] != digest:
                    raise DirectCommandJournalError("REQUEST_CONFLICT")
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
                principal,
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
