"""Same-database prepared PLACE storage; source labels do not grant authority."""

from __future__ import annotations

import json
import sqlite3

from .direct_command_journal import DirectCommandJournalError, _json

_PLACE_DDL = {
    "direct_place_preparations": "CREATE TABLE direct_place_preparations (account TEXT NOT NULL, reservation_id TEXT NOT NULL, prepared_json TEXT NOT NULL, prepared_digest TEXT NOT NULL, PRIMARY KEY(account, reservation_id))",
    "direct_place_keys": "CREATE TABLE direct_place_keys (account TEXT NOT NULL, strong_key TEXT NOT NULL, reservation_id TEXT NOT NULL, PRIMARY KEY(account, strong_key))",
    "direct_place_keys_reservation": "CREATE INDEX direct_place_keys_reservation ON direct_place_keys(account, reservation_id)",
    "direct_place_error_attribution": "CREATE TABLE direct_place_error_attribution (account TEXT NOT NULL, fact_digest TEXT NOT NULL, reservation_id TEXT NOT NULL, prepared_digest TEXT NOT NULL, place_key TEXT NOT NULL, source_binding_json TEXT NOT NULL, PRIMARY KEY(account, fact_digest))",
}


def _create_place_tables(db: sqlite3.Connection) -> None:
    for sql in _PLACE_DDL.values():
        db.execute(sql)


def _identity_json(identity) -> str:
    return _json(
        {
            "exchange_name": identity.exchange_name,
            "client_order_id": identity.client_order_id,
            "session_generation": identity.session_generation,
            "fields_json": _json(dict(identity.fields)),
        },
        scalar_map=True,
    )


def _validate_prepared(prepared, command):
    from bt_api_base.direct_place_protocol import PreparedPlaceRequest

    if type(prepared) is not PreparedPlaceRequest:
        raise DirectCommandJournalError("INVALID_INPUT")
    try:
        mapping = prepared.to_mapping()
        raw = _json(mapping)
        digest = prepared.digest()
        payload = json.loads(command["payload_json"])
        if (
            type(payload) is not dict
            or payload.get("symbol") != prepared.symbol
            or _identity_json(prepared.identity) != command["native_identity_json"]
        ):
            raise ValueError("prepared place target")
        return raw, digest
    except Exception as exc:
        raise DirectCommandJournalError("PLACE_PREPARATION_CONFLICT") from exc


def _get_prepared(db, account, reservation_id):
    from bt_api_base.direct_place_protocol import PreparedPlaceRequest
    from .direct_command_journal import payload_digest

    row = db.execute(
        "SELECT * FROM direct_place_preparations WHERE account=? AND reservation_id=?",
        (account, reservation_id),
    ).fetchone()
    if row is None:
        if (
            db.execute(
                "SELECT 1 FROM direct_place_keys WHERE account=? AND reservation_id=? LIMIT 1",
                (account, reservation_id),
            ).fetchone()
            is not None
        ):
            raise DirectCommandJournalError("INVALID_DATABASE")
        return None
    try:
        commands = db.execute(
            "SELECT * FROM direct_journal_commands WHERE account=? AND reservation_id=?",
            (account, reservation_id),
        ).fetchall()
        if len(commands) != 1:
            raise ValueError("orphan preparation")
        command = commands[0]
        if command["status"] not in {"DISPATCHING", "SENT", "NOT_SENT", "UNKNOWN"}:
            raise ValueError("command status")
        prepared = PreparedPlaceRequest.from_mapping(json.loads(row["prepared_json"]))
        raw, digest = _validate_prepared(prepared, command)
        if (
            raw != row["prepared_json"]
            or digest != row["prepared_digest"]
            or _json(json.loads(command["payload_json"])) != command["payload_json"]
            or payload_digest(json.loads(command["payload_json"])) != command["digest"]
        ):
            raise ValueError("preparation digest")
        stored = {
            r[0]
            for r in db.execute(
                "SELECT strong_key FROM direct_place_keys WHERE account=? AND reservation_id=? LIMIT 17",
                (account, reservation_id),
            )
        }
        if stored != set(prepared.request_keys):
            raise ValueError("place keys")
        return prepared
    except Exception as exc:
        raise DirectCommandJournalError("INVALID_DATABASE") from exc


def _find_place_by_key(db, journal, key):
    account = journal.account_scope
    row = db.execute(
        "SELECT reservation_id FROM direct_place_keys WHERE account=? AND strong_key=?",
        (account, key),
    ).fetchone()
    if row is None:
        return None
    prepared = _get_prepared(db, account, row["reservation_id"])
    if prepared is None or key not in prepared.request_keys:
        raise DirectCommandJournalError("INVALID_DATABASE")
    command = db.execute(
        "SELECT strategy,request_key FROM direct_journal_commands WHERE account=? AND reservation_id=?",
        (account, row["reservation_id"]),
    ).fetchone()
    if command is None:
        raise DirectCommandJournalError("INVALID_DATABASE")
    return journal._record(journal._find(db, command["strategy"], command["request_key"]))


def _verify_place_integrity(db, account, capacity):
    try:
        rows = db.execute(
            "SELECT account,reservation_id FROM direct_place_preparations LIMIT ?", (capacity + 1,)
        ).fetchall()
        if len(rows) > capacity:
            raise ValueError("place preparation capacity")
        expected = set()
        for row in rows:
            if row["account"] != account:
                raise ValueError("place account")
            prepared = _get_prepared(db, account, row["reservation_id"])
            if prepared is None:
                raise ValueError("place preparation")
            expected.update((account, key, row["reservation_id"]) for key in prepared.request_keys)
        actual = {
            tuple(r)
            for r in db.execute(
                "SELECT account,strong_key,reservation_id FROM direct_place_keys LIMIT ?",
                (capacity * 16 + 1,),
            )
        }
        if expected != actual:
            raise ValueError("place keys orphan")
    except Exception as exc:
        raise DirectCommandJournalError("INVALID_DATABASE") from exc
