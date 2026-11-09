"""Synthetic owner transaction: no external services or account operations."""
import hashlib
import sqlite3
from dataclasses import replace
from types import SimpleNamespace
from contextlib import contextmanager

import pytest
from bt_api_base.gateway_direct_protocol import gateway_payload_digest
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope
from bt_api_gateway.direct_command_journal import DirectCommandJournalError, _json
from bt_api_gateway.direct_strategy_origin import (
    _STRATEGY_ORIGIN_DDL, append_strategy_origin, authorize_strategy_origin,
    read_verified_self_origin, verify_strategy_origins,
)
from test_iter63_direct_execution_journal import INSTRUMENT, fact


@pytest.fixture
def owner(tmp_path):
    db = sqlite3.connect(tmp_path / "account.db")
    db.execute("CREATE TABLE direct_journal_meta(account TEXT, journal_id TEXT)")
    db.execute("CREATE TABLE direct_journal_commands(account TEXT, strategy TEXT, request_key TEXT, reservation_id TEXT, principal TEXT, digest TEXT, payload_json TEXT, generation TEXT)")
    db.execute("CREATE TABLE direct_delegated_commands(account TEXT, reservation_id TEXT)")
    db.execute("CREATE TABLE direct_execution_facts(account TEXT, fact_digest TEXT, fact_json TEXT, disposition TEXT, reservation_id TEXT)")
    db.execute(_STRATEGY_ORIGIN_DDL["direct_strategy_origins"])
    db.execute("INSERT INTO direct_journal_meta VALUES ('acct','jid')")
    payload = {"symbol": "rb2601", "exchange_id": "SHFE", "idempotency_key": "req1"}
    db.execute("INSERT INTO direct_journal_commands VALUES (?,?,?,?,?,?,?,?)", (
        "acct", "s1", "req1", "reservation", "principal", gateway_payload_digest(payload), _json(payload), "generation"))
    event = fact()
    db.execute("INSERT INTO direct_execution_facts VALUES (?,?,?,?,?)", (
        "acct", event.fact_digest(), _json(event.to_mapping()), "ATTRIBUTED", "reservation"))
    db.commit()
    yield db, payload, event
    db.close()


def context():
    identity = WireIdentity(WireRole.STRATEGY_CLIENT, "principal", "s1")
    scope = WireScope("domain", account_ref="acct", strategy_ref="s1", run_id="run")
    return SimpleNamespace(identity=identity, scope=scope, registration_id="registration", principal_ref="principal")


def permit(payload, ctx=None, *, registry_recheck=lambda _: True, instrument_recheck=lambda _: True):
    return authorize_strategy_origin(ctx or context(), INSTRUMENT, payload, account="acct", journal_id="jid",
        generation="generation", service_epoch="epoch", registry_recheck=registry_recheck,
        instrument_recheck=instrument_recheck)


def test_verified_self_and_history_remains_unknown(owner):
    db, payload, event = owner
    assert not read_verified_self_origin(db, "acct", "reservation", "s1", event)
    with db:
        db.execute("BEGIN")
        append_strategy_origin(db, permit(payload), "reservation")
    verify_strategy_origins(db, "acct", "jid")
    assert read_verified_self_origin(db, "acct", "reservation", "s1", event)
    assert not read_verified_self_origin(db, "acct", "legacy", "s1", event)


def test_admission_revocation_rolls_back_original_transaction(owner):
    db, payload, _ = owner
    current = [True]
    p = permit(payload, registry_recheck=lambda _: current[0])
    current[0] = False
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_ORIGIN_UNAVAILABLE"):
        with db:
            db.execute("UPDATE direct_journal_commands SET principal=principal")
            append_strategy_origin(db, p, "reservation")
    assert db.execute("SELECT count(*) FROM direct_strategy_origins").fetchone()[0] == 0


def test_revocation_after_insert_rolls_back_and_restart_verifies(owner):
    db, payload, event = owner
    checks = [0]
    def registry(_):
        checks[0] += 1
        return checks[0] < 3
    p = permit(payload, registry_recheck=registry)
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_ORIGIN_UNAVAILABLE"):
        with db:
            db.execute("BEGIN")
            append_strategy_origin(db, p, "reservation")
    assert db.execute("SELECT count(*) FROM direct_strategy_origins").fetchone()[0] == 0
    with db:
        db.execute("BEGIN")
        append_strategy_origin(db, permit(payload), "reservation")
    path = db.execute("PRAGMA database_list").fetchone()[2]
    with sqlite3.connect(path) as reopened:
        verify_strategy_origins(reopened, "acct", "jid")
        assert read_verified_self_origin(reopened, "acct", "reservation", "s1", event)


def test_reject_wrong_role_scope_and_instrument(owner):
    _, payload, _ = owner
    ctx = context()
    ctx.identity = WireIdentity(WireRole.SERVICE, "principal", "s1")
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_ORIGIN_UNAVAILABLE"):
        permit(payload, ctx)
    ctx = context()
    ctx.scope = replace(ctx.scope, strategy_ref="other")
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_ORIGIN_UNAVAILABLE"):
        permit(payload, ctx)
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_ORIGIN_UNAVAILABLE"):
        permit(payload, instrument_recheck=lambda _: False)
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_ORIGIN_UNAVAILABLE"):
        permit({**payload, "account_id": "other"})
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_ORIGIN_UNAVAILABLE"):
        permit({**payload, "instrument": replace(INSTRUMENT, environment="live").to_dict()})


def test_tamper_cannot_be_relabelled_with_new_digest(owner):
    db, payload, event = owner
    with db:
        db.execute("BEGIN")
        append_strategy_origin(db, permit(payload), "reservation")
    raw = db.execute("SELECT proof_json FROM direct_strategy_origins").fetchone()[0]
    forged = raw.replace('"principal":"principal"', '"principal":"other"')
    with db:
        db.execute("UPDATE direct_strategy_origins SET proof_json=?,proof_digest=?", (
            forged, hashlib.sha256(forged.encode("ascii")).hexdigest()))
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        verify_strategy_origins(db, "acct", "jid")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        read_verified_self_origin(db, "acct", "reservation", "s1", event)


def test_evidence_requires_same_fact_instrument_and_account(owner):
    db, payload, event = owner
    with db:
        db.execute("BEGIN")
        append_strategy_origin(db, permit(payload), "reservation")
    for wrong in (replace(event, account_scope="other"), replace(event, instrument=replace(INSTRUMENT, environment="live"))):
        with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
            read_verified_self_origin(db, "acct", "reservation", "s1", wrong)


def test_real_journal_new_reserve_revoked_admission_rolls_back(tmp_path):
    from bt_api_gateway.direct_command_journal import GatewayDirectCommandJournal
    from bt_api_gateway.session_guard import LocalAccountSessionGuard

    guard_dir = tmp_path / "guards"
    guard_dir.mkdir()
    guard = LocalAccountSessionGuard(guard_dir, "acct", "owner")
    generation = guard.acquire()
    try:
        journal = GatewayDirectCommandJournal.create(tmp_path / "journal.db", "acct", generation=generation)
        journal.enable_controls(guard)
        journal.enable_strategy_ledger(guard)
        journal.enable_account_extensions(guard)
        journal.enable_parent_authority(guard)
        journal.enable_account_facts_financial(guard)
        journal.enable_actor_stream(guard)
        journal.enable_strategy_origin(guard)
        payload = {"symbol": "rb2601", "exchange_id": "SHFE", "idempotency_key": "req1",
                   "side": "buy", "offset": "open", "quantity": "1"}
        calls = [0]
        def registry(_):
            calls[0] += 1
            return calls[0] < 4
        origin = authorize_strategy_origin(context(), INSTRUMENT, payload,
            account="acct", journal_id=journal.journal_id, generation=generation,
            service_epoch="epoch", registry_recheck=registry, instrument_recheck=lambda _: True)
        @contextmanager
        def fence():
            yield
        with pytest.raises(DirectCommandJournalError, match="STRATEGY_ORIGIN_UNAVAILABLE"):
            journal.reserve("s1", "req1", "principal", payload, reservation_fence=fence,
                            strategy_origin_permit=origin)
        with pytest.raises(DirectCommandJournalError, match="NOT_FOUND"):
            journal.get("s1", "req1", "principal")
        with journal._transaction() as db:
            assert db.execute("SELECT count(*) FROM direct_strategy_origins").fetchone()[0] == 0
    finally:
        guard.release()
