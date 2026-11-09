"""Same-journal evidence for newly admitted strategy-origin commands.

This component never authenticates network claims.  The SDK must issue the
context, resolve the instrument on the owner and hold the Registry admission
scope across the journal transaction.  Its callbacks are trusted local code,
not serializable request arguments.  Existing commands receive no evidence.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass

from bt_api_base.gateway_direct_protocol import gateway_payload_digest
from bt_api_base.gateway_execution_protocol import GatewayReturnFact
from bt_api_base.market_protocol import MarketInstrumentKey
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope

from .direct_command_journal import DirectCommandJournalError, _json, _text

_STRATEGY_ORIGIN_DDL = {
    "direct_strategy_origins": "CREATE TABLE direct_strategy_origins (account TEXT NOT NULL, strategy TEXT NOT NULL, request_key TEXT NOT NULL, reservation_id TEXT NOT NULL UNIQUE, proof_json TEXT NOT NULL, proof_digest TEXT NOT NULL, PRIMARY KEY(account, strategy, request_key))",
}


def _deny() -> None:
    raise DirectCommandJournalError("STRATEGY_ORIGIN_UNAVAILABLE")


def _integrity() -> None:
    raise DirectCommandJournalError("INVALID_DATABASE")


@dataclass(frozen=True, slots=True)
class _OriginBinding:
    account: str
    journal_id: str
    generation: str
    strategy: str
    request_key: str
    principal: str
    actor: str
    registration_id: str
    service_epoch: str
    execution_domain: str
    run_id: str
    payload_digest: str
    instrument: MarketInstrumentKey

    def mapping(self, reservation_id: str) -> dict:
        return {
            "schema_version": 1, "account": self.account, "journal_id": self.journal_id,
            "generation": self.generation, "strategy": self.strategy, "request_key": self.request_key,
            "reservation_id": reservation_id, "principal": self.principal, "actor": self.actor,
            "registration_id": self.registration_id, "service_epoch": self.service_epoch,
            "execution_domain": self.execution_domain, "run_id": self.run_id,
            "payload_digest": self.payload_digest, "instrument": self.instrument.to_dict(),
        }


class GatewayStrategyOriginPermit:
    """Owner-local binding, not a replacement for Registry admission."""

    __slots__ = ("_binding", "_context", "_registry_recheck", "_instrument_recheck")

    def __init__(self, binding, context, registry_recheck, instrument_recheck):
        self._binding, self._context = binding, context
        self._registry_recheck, self._instrument_recheck = registry_recheck, instrument_recheck

    @property
    def binding(self):
        """Immutable owner-local identity; not a network authority."""
        return self._binding

    def recheck(self, db: sqlite3.Connection | None = None) -> None:
        b, ctx = self._binding, self._context
        try:
            identity, scope = ctx.identity, ctx.scope
            if (type(identity) is not WireIdentity or identity.role is not WireRole.STRATEGY_CLIENT
                    or identity.delegate_ref is not None or identity.principal_ref != b.principal
                    or identity.actor_ref != b.actor or identity.actor_ref != b.strategy
                    or ctx.principal_ref != b.principal
                    or ctx.registration_id != b.registration_id or type(scope) is not WireScope
                    or scope.account_ref != b.account or scope.strategy_ref != b.strategy
                    or scope.run_id != b.run_id or scope.execution_domain_ref != b.execution_domain
                    or scope.account_refs or scope.manual_book_ref is not None
                    or scope.portfolio_ref is not None or scope.group_id is not None or scope.leg_id is not None
                    or self._registry_recheck(ctx) is not True
                    or self._instrument_recheck(b.instrument) is not True):
                _deny()
            if db is not None:
                if not db.in_transaction:
                    _deny()
                meta = db.execute("SELECT journal_id FROM direct_journal_meta WHERE account=?", (b.account,)).fetchall()
                if len(meta) != 1 or meta[0][0] != b.journal_id:
                    _deny()
        except DirectCommandJournalError:
            raise
        except Exception:
            _deny()


def authorize_strategy_origin(context, instrument: MarketInstrumentKey, payload: dict, *,
                              account: str, journal_id: str, generation: str,
                              service_epoch: str, registry_recheck: Callable,
                              instrument_recheck: Callable) -> GatewayStrategyOriginPermit:
    """Bind an authenticated Registry context and owner-resolved instrument.

    The SDK must supply the exact live admission recheck and hold its scope
    until commit; neither the epoch nor instrument may come from the wire.
    """
    try:
        if (type(instrument) is not MarketInstrumentKey or type(payload) is not dict
                or not callable(registry_recheck) or not callable(instrument_recheck)
                or payload.get("symbol") != instrument.native_symbol
                or (payload.get("account_id") is not None and payload["account_id"] != account)
                or (payload.get("instrument") is not None
                    and MarketInstrumentKey.from_dict(payload["instrument"]) != instrument)
                or (payload.get("exchange_id") is not None and payload["exchange_id"] != instrument.venue)):
            _deny()
        identity, scope = context.identity, context.scope
        binding = _OriginBinding(*map(_text, (
            account, journal_id, generation, scope.strategy_ref, payload.get("idempotency_key"),
            context.principal_ref, identity.actor_ref, context.registration_id, service_epoch,
            scope.execution_domain_ref, scope.run_id, gateway_payload_digest(payload))), instrument)
        permit = GatewayStrategyOriginPermit(binding, context, registry_recheck, instrument_recheck)
        permit.recheck()
        return permit
    except DirectCommandJournalError:
        raise
    except Exception:
        _deny()


def _validate_record(db: sqlite3.Connection, row, account: str, journal_id: str) -> dict:
    try:
        proof = json.loads(row[4])
        fields = {"schema_version", "account", "journal_id", "generation", "strategy", "request_key",
                  "reservation_id", "principal", "actor", "registration_id", "service_epoch",
                  "execution_domain", "run_id", "payload_digest", "instrument"}
        if (type(proof) is not dict or set(proof) != fields or type(proof["schema_version"]) is not int
                or proof["schema_version"] != 1 or proof["account"] != account
                or proof["journal_id"] != journal_id or tuple(row[:4]) !=
                (account, proof["strategy"], proof["request_key"], proof["reservation_id"])
                or _json(proof) != row[4] or hashlib.sha256(row[4].encode("ascii")).hexdigest() != row[5]):
            _integrity()
        for name in fields - {"schema_version", "instrument"}:
            _text(proof[name])
        if proof["actor"] != proof["strategy"]:
            _integrity()
        instrument = MarketInstrumentKey.from_dict(proof["instrument"])
        cmd = db.execute("SELECT principal,digest,payload_json,generation FROM direct_journal_commands "
                         "WHERE account=? AND strategy=? AND request_key=? AND reservation_id=?",
                         (account, proof["strategy"], proof["request_key"], proof["reservation_id"])).fetchone()
        delegated = db.execute("SELECT 1 FROM direct_delegated_commands WHERE account=? AND reservation_id=?",
                               (account, proof["reservation_id"])).fetchone()
        if cmd is None or delegated is not None:
            _integrity()
        payload = json.loads(cmd[2])
        if (cmd[0] != proof["principal"] or cmd[1] != proof["payload_digest"]
                or cmd[3] != proof["generation"] or _json(payload) != cmd[2]
                or gateway_payload_digest(payload) != cmd[1]
                or payload.get("idempotency_key") != proof["request_key"]
                or payload.get("symbol") != instrument.native_symbol
                or (payload.get("account_id") is not None and payload["account_id"] != account)
                or (payload.get("instrument") is not None
                    and MarketInstrumentKey.from_dict(payload["instrument"]) != instrument)
                or (payload.get("exchange_id") is not None and payload["exchange_id"] != instrument.venue)):
            _integrity()
        return proof
    except DirectCommandJournalError:
        raise
    except Exception:
        _integrity()


def append_strategy_origin(db: sqlite3.Connection, permit: GatewayStrategyOriginPermit,
                           reservation_id: str) -> None:
    """Append after command insert, in the same owner transaction and admission scope."""
    if not db.in_transaction or type(permit) is not GatewayStrategyOriginPermit:
        _deny()
    reservation_id = _text(reservation_id)
    permit.recheck(db)
    binding = permit._binding
    proof = binding.mapping(reservation_id)
    raw = _json(proof)
    row = (binding.account, binding.strategy, binding.request_key, reservation_id,
           raw, hashlib.sha256(raw.encode("ascii")).hexdigest())
    _validate_record(db, row, binding.account, binding.journal_id)
    db.execute("INSERT INTO direct_strategy_origins VALUES (?,?,?,?,?,?)", row)
    permit.recheck(db)


def verify_strategy_origins(db: sqlite3.Connection, account: str, journal_id: str) -> None:
    """Validate all stored evidence on owner restart, without inventing history."""
    try:
        meta = db.execute("SELECT journal_id FROM direct_journal_meta WHERE account=?", (account,)).fetchall()
        if len(meta) != 1 or meta[0][0] != journal_id:
            _integrity()
        for row in db.execute("SELECT account,strategy,request_key,reservation_id,proof_json,proof_digest "
                              "FROM direct_strategy_origins ORDER BY account,strategy,request_key"):
            _validate_record(db, row, account, journal_id)
    except DirectCommandJournalError:
        raise
    except Exception:
        _integrity()


def read_verified_self_origin(db: sqlite3.Connection, account: str, reservation_id: str,
                              strategy: str, fact: GatewayReturnFact) -> bool:
    """Read new evidence only for the same attributed fact and complete instrument."""
    row = db.execute("SELECT account,strategy,request_key,reservation_id,proof_json,proof_digest "
                     "FROM direct_strategy_origins WHERE account=? AND reservation_id=?",
                     (account, reservation_id)).fetchone()
    if row is None:
        return False
    try:
        meta = db.execute("SELECT journal_id FROM direct_journal_meta WHERE account=?", (account,)).fetchall()
        if len(meta) != 1:
            _integrity()
        proof = _validate_record(db, row, account, meta[0][0])
        if type(fact) is not GatewayReturnFact or fact.account_scope != account or proof["strategy"] != strategy:
            _integrity()
        stored = db.execute("SELECT fact_json,disposition,reservation_id FROM direct_execution_facts "
                            "WHERE account=? AND fact_digest=?", (account, fact.fact_digest())).fetchone()
        if (stored is None or stored[0] != _json(fact.to_mapping()) or stored[1] != "ATTRIBUTED"
                or stored[2] != reservation_id or MarketInstrumentKey.from_dict(proof["instrument"]) != fact.instrument):
            _integrity()
        return True
    except DirectCommandJournalError:
        raise
    except Exception:
        _integrity()
