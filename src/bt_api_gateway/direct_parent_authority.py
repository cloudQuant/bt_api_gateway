"""Account-owner authority for Execution parents and their child reservations.

All identity, policy, clock and trading-day sources are installed by the service
owner. This module authenticates no wire claims and never performs provider I/O.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import datetime
from decimal import Decimal, localcontext
import hashlib
import json
import re

from bt_api_base.gateway_delegation_protocol import GatewayDelegatedCommand
from bt_api_base.gateway_direct_protocol import canonical_gateway_payload, gateway_payload_digest
from bt_api_base.market_protocol import MarketInstrumentKey

from .direct_command_journal import DirectCommandJournalError
from .session_guard import LocalAccountSessionGuard
from .strategy_position_ledger import _quantity, _remaining_close


class GatewayParentError(ValueError):
    """Finite, value-free owner rejection; NOT_FOUND is local evidence only."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


_PARENT_AUTHORITY_DDL = {
    "direct_execution_parents": "CREATE TABLE direct_execution_parents (account TEXT NOT NULL, strategy TEXT NOT NULL, parent_ref TEXT NOT NULL, registration_operation_id TEXT NOT NULL, spec_json TEXT NOT NULL, spec_digest TEXT NOT NULL, execution_principal TEXT NOT NULL, execution_actor_ref TEXT NOT NULL, state TEXT NOT NULL, version INTEGER NOT NULL, PRIMARY KEY(account, strategy, parent_ref), UNIQUE(account, strategy, registration_operation_id))",
    "direct_execution_parent_operations": "CREATE TABLE direct_execution_parent_operations (account TEXT NOT NULL, strategy TEXT NOT NULL, parent_ref TEXT NOT NULL, operation_id TEXT NOT NULL, kind TEXT NOT NULL, request_digest TEXT NOT NULL, result_json TEXT NOT NULL, PRIMARY KEY(account, strategy, parent_ref, operation_id))",
    "direct_execution_rollover_evidence": "CREATE TABLE direct_execution_rollover_evidence (account TEXT NOT NULL, strategy TEXT NOT NULL, parent_ref TEXT NOT NULL, child_id TEXT NOT NULL, evidence_json TEXT NOT NULL, evidence_digest TEXT NOT NULL, PRIMARY KEY(account, strategy, parent_ref, child_id))",
    "direct_execution_parent_cancel_targets": "CREATE TABLE direct_execution_parent_cancel_targets (account TEXT NOT NULL, strategy TEXT NOT NULL, parent_ref TEXT NOT NULL, child_id TEXT NOT NULL, target_json TEXT NOT NULL, target_digest TEXT NOT NULL, PRIMARY KEY(account, strategy, parent_ref, child_id))",
}

_FIELDS = frozenset({"account_scope", "strategy_scope", "parent_ref", "registration_operation_id",
    "execution_domain_ref", "instrument", "quantity", "quantity_unit", "side", "offset",
    "limit_price", "creation_trading_day", "allowed_trading_days", "expires_at_ns",
    "grant_revision", "target_position_ref", "plan_digest", "plan_version", "time_in_force"})
_ROLLOVER_FIELDS = frozenset({"account_scope", "strategy_scope", "parent_ref", "child_id",
    "target_position_ref", "position_id", "source_trading_day", "trading_day", "source_bucket",
    "target_bucket", "provider_rule_ref", "provider_rule_version", "observation_ref",
    "observation_source_ref", "observation_account_scope", "observation_trading_day",
    "observation_session_ref", "mapping_version", "quantity", "real_close_available",
    "observed_at_ns", "valid_until_ns"})
_CANCEL_TARGET_FIELDS = frozenset({"account_scope", "strategy_scope", "parent_ref", "child_id",
    "request_key", "reservation_id", "payload_digest", "target_principal", "target_version",
    "native_identity", "strong_identity_keys", "phase", "cancel_operation_id"})


def _error(code):
    raise GatewayParentError(code)


def _ref(value):
    try:
        return (type(value) is str and bool(value) and value == value.strip()
                and value.isprintable() and len(value.encode("utf-8", "strict")) <= 256)
    except UnicodeError:
        return False


def _day(value):
    if type(value) is not str or re.fullmatch(r"[0-9]{8}", value) is None:
        return False
    try:
        datetime.date(int(value[:4]), int(value[4:6]), int(value[6:]))
        return True
    except ValueError:
        return False


def _sha(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _spec(value):
    try:
        if type(value) is not dict or set(value) != _FIELDS:
            raise ValueError
        refs = ("account_scope", "strategy_scope", "parent_ref", "registration_operation_id",
                "execution_domain_ref", "quantity_unit", "grant_revision", "plan_version")
        if any(not _ref(value[k]) for k in refs):
            raise ValueError
        key = MarketInstrumentKey.from_dict(value["instrument"])
        if key.to_dict() != value["instrument"]:
            raise ValueError
        _quantity(value["quantity"])
        _quantity(value["limit_price"])
        if (value["side"] not in ("buy", "sell") or value["offset"] not in
                ("open", "close", "close_today", "close_yesterday")
                or (value["offset"] == "open" and value["target_position_ref"] is not None)
                or (value["offset"] != "open" and not _ref(value["target_position_ref"]))
                or re.fullmatch(r"[0-9a-f]{64}", value["plan_digest"]) is None
                or value["time_in_force"] not in ("DAY", "GTD")
                or type(value["expires_at_ns"]) is not int
                or not 0 < value["expires_at_ns"] < 2**63
                or not _day(value["creation_trading_day"])):
            raise ValueError
        days = value["allowed_trading_days"]
        if (type(days) is not list or not 1 <= len(days) <= 366
                or any(not _day(day) for day in days) or days != sorted(set(days))
                or value["creation_trading_day"] != days[0]
                or (value["time_in_force"] == "DAY" and len(days) != 1)):
            raise ValueError
        return json.loads(canonical_gateway_payload(value))
    except Exception:
        _error("INVALID_PARENT")


def _result(row):
    return {"spec": json.loads(row["spec_json"]), "spec_digest": row["spec_digest"],
            "execution_principal": row["execution_principal"],
            "execution_actor_ref": row["execution_actor_ref"],
            "state": row["state"], "version": row["version"]}


def _cancel_targets(db, account, strategy, parent_ref):
    rows = db.execute("SELECT target_json FROM direct_execution_parent_cancel_targets "
        "WHERE account=? AND strategy=? AND parent_ref=? ORDER BY child_id", (account, strategy, parent_ref)).fetchall()
    return [json.loads(row["target_json"]) for row in rows]


def _cancel_operation_id(account, strategy, parent_ref, child_id, parent_cancel_id):
    return "parent-cancel-" + _sha(canonical_gateway_payload(
        [account, strategy, parent_ref, child_id, parent_cancel_id]))


def _freeze_cancel_targets(db, account, strategy, parent_ref, operation_id, capacity):
    """Capture only this parent's original child identities in the caller's transaction."""
    rows = db.execute("SELECT d.envelope_json,c.* FROM direct_delegated_commands d "
        "JOIN direct_journal_commands c ON c.account=d.account AND c.strategy=d.strategy AND c.request_key=d.request_key "
        "WHERE d.account=? AND d.strategy=?", (account, strategy)).fetchall()
    if len(rows) > capacity:
        _error("CAPACITY_EXCEEDED")
    targets = []
    seen = set()
    for row in rows:
        command = GatewayDelegatedCommand.from_mapping(json.loads(row["envelope_json"]))
        if command.parent_ref != parent_ref:
            continue
        if command.child_id in seen:
            _error("AUTHORITY_UNAVAILABLE")
        seen.add(command.child_id)
        if row["status"] in ("RELEASED", "EXPIRED", "NOT_SENT"):
            # Detect contradictory venue facts before treating a local state as unsent.
            _remaining_close(db, account, row["reservation_id"], row["status"],
                             _quantity(json.loads(row["payload_json"])["quantity"]))
            continue
        if row["status"] not in ("RESERVED", "DISPATCHING", "SENT", "UNKNOWN"):
            _error("AUTHORITY_UNAVAILABLE")
        phase = ("RELEASE_PENDING" if row["status"] == "RESERVED" else
                 "WAIT_DISPATCH" if row["status"] == "DISPATCHING" else "CANCEL_PENDING")
        identity = None if row["native_identity_json"] is None else json.loads(row["native_identity_json"])
        keys = None if row["strong_keys_json"] is None else json.loads(row["strong_keys_json"])
        if ((phase == "RELEASE_PENDING" and (identity is not None or keys is not None))
                or (phase != "RELEASE_PENDING" and (identity is None or not keys))):
            _error("AUTHORITY_UNAVAILABLE")
        target = {"account_scope": account, "strategy_scope": strategy, "parent_ref": parent_ref,
            "child_id": command.child_id, "request_key": command.request_key,
            "reservation_id": row["reservation_id"], "payload_digest": row["digest"],
            "target_principal": row["principal"], "target_version": row["version"],
            "native_identity": identity, "strong_identity_keys": keys, "phase": phase,
            "cancel_operation_id": _cancel_operation_id(account, strategy, parent_ref, command.child_id, operation_id)}
        targets.append(target)
    targets.sort(key=lambda item: item["child_id"])
    return targets


def _rollover_evidence(value, spec, command, payload, *, now=None):
    """Check a trusted owner's immutable, source-validated observation binding.

    The installed callback must itself authenticate the provider/rule/session,
    prove the original target mapping, and recheck real available quantity net
    of other outstanding reservations in this same transaction. This schema
    does not manufacture any of those facts from request fields.
    """
    if type(value) is not dict or set(value) != _ROLLOVER_FIELDS:
        raise ValueError
    refs = ("provider_rule_ref", "provider_rule_version", "observation_ref", "observation_source_ref",
            "observation_session_ref", "mapping_version", "position_id")
    if any(not _ref(value[k]) for k in refs):
        raise ValueError
    if (value["account_scope"] != spec["account_scope"] or value["strategy_scope"] != spec["strategy_scope"]
            or value["parent_ref"] != spec["parent_ref"] or value["child_id"] != command.child_id
            or command.account_scope != spec["account_scope"] or command.strategy_scope != spec["strategy_scope"]
            or command.parent_ref != spec["parent_ref"] or command.instrument.to_dict() != spec["instrument"]
            or payload.get("side") != spec["side"] or payload.get("quantity_unit") != spec["quantity_unit"]
            or value["target_position_ref"] != spec["target_position_ref"]
            or value["position_id"] != payload.get("position_id")
            or value["source_trading_day"] != spec["creation_trading_day"]
            or not _day(value["trading_day"]) or value["trading_day"] <= value["source_trading_day"]
            or value["trading_day"] not in spec["allowed_trading_days"]
            or value["source_bucket"] != "today" or value["target_bucket"] != "yesterday"
            or value["observation_account_scope"] != spec["account_scope"]
            or value["observation_trading_day"] != value["trading_day"]
            or spec["offset"] != "close_today" or payload.get("offset") != "close_yesterday"
            or value["quantity"] != payload.get("quantity")
            or _quantity(value["real_close_available"], allow_zero=True) < _quantity(value["quantity"])
            or type(value["observed_at_ns"]) is not int or type(value["valid_until_ns"]) is not int
            or not 0 <= value["observed_at_ns"] < value["valid_until_ns"] <= spec["expires_at_ns"]
            or (now is not None and not value["observed_at_ns"] <= now < value["valid_until_ns"])):
        raise ValueError
    return json.loads(canonical_gateway_payload(value))


def verify_parent_authority_integrity(db, account, capacity):
    """Validate bounded, canonical rows whenever the original journal opens/commits."""
    try:
        parents = db.execute("SELECT * FROM direct_execution_parents").fetchall()
        operations = db.execute("SELECT * FROM direct_execution_parent_operations").fetchall()
        evidence_rows = db.execute("SELECT * FROM direct_execution_rollover_evidence").fetchall()
        target_rows = db.execute("SELECT * FROM direct_execution_parent_cancel_targets").fetchall()
        if len(parents) + len(operations) + len(evidence_rows) + len(target_rows) > capacity:
            raise ValueError
        by_key = {}
        for row in parents:
            spec = _spec(json.loads(row["spec_json"]))
            encoded = canonical_gateway_payload(spec)
            if (row["account"] != account or spec["account_scope"] != account
                    or row["strategy"] != spec["strategy_scope"] or row["parent_ref"] != spec["parent_ref"]
                    or row["registration_operation_id"] != spec["registration_operation_id"]
                    or encoded != row["spec_json"] or _sha(encoded) != row["spec_digest"]
                    or not _ref(row["execution_principal"]) or not _ref(row["execution_actor_ref"])
                    or row["state"] not in ("ACTIVE", "CANCEL_REQUESTED")
                    or type(row["version"]) is not int or row["version"] not in (1, 2)
                    or (row["state"] == "ACTIVE") != (row["version"] == 1)):
                raise ValueError
            by_key[(row["account"], row["strategy"], row["parent_ref"])] = row
        seen = {}
        for row in operations:
            key = (row["account"], row["strategy"], row["parent_ref"])
            parent = by_key[key]
            result = json.loads(row["result_json"])
            expected_result = _result(parent)
            expected_result["state"] = "ACTIVE" if row["kind"] == "REGISTER" else "CANCEL_REQUESTED"
            expected_result["version"] = 1 if row["kind"] == "REGISTER" else 2
            if row["kind"] == "CANCEL":
                expected_result["targets"] = _cancel_targets(db, *key)
            if (not _ref(row["operation_id"]) or row["kind"] not in ("REGISTER", "CANCEL")
                    or canonical_gateway_payload(result) != row["result_json"]
                    or result != expected_result):
                raise ValueError
            expected = (parent["spec_digest"] if row["kind"] == "REGISTER" else
                        _sha(canonical_gateway_payload({"expected_version": 1})))
            if row["request_digest"] != expected:
                raise ValueError
            if row["kind"] == "REGISTER" and row["operation_id"] != parent["registration_operation_id"]:
                raise ValueError
            seen.setdefault(key, []).append(row["kind"])
        for key, row in by_key.items():
            if sorted(seen.get(key, [])) != (["CANCEL", "REGISTER"] if row["state"] == "CANCEL_REQUESTED" else ["REGISTER"]):
                raise ValueError
        cancel_ids = {(row["account"], row["strategy"], row["parent_ref"]): row["operation_id"]
                      for row in operations if row["kind"] == "CANCEL"}
        for saved in target_rows:
            key = (saved["account"], saved["strategy"], saved["parent_ref"])
            parent = by_key[key]
            target = json.loads(saved["target_json"])
            if (type(target) is not dict or set(target) != _CANCEL_TARGET_FIELDS
                    or parent["state"] != "CANCEL_REQUESTED" or key not in cancel_ids
                    or canonical_gateway_payload(target) != saved["target_json"]
                    or _sha(saved["target_json"]) != saved["target_digest"]
                    or target["account_scope"] != key[0] or target["strategy_scope"] != key[1]
                    or target["parent_ref"] != key[2] or target["child_id"] != saved["child_id"]
                    or target["cancel_operation_id"] != _cancel_operation_id(*key, saved["child_id"], cancel_ids[key])
                    or target["phase"] not in ("RELEASE_PENDING", "WAIT_DISPATCH", "CANCEL_PENDING")):
                raise ValueError
            childrow = db.execute("SELECT d.envelope_json,c.* FROM direct_delegated_commands d JOIN direct_journal_commands c "
                "ON c.account=d.account AND c.strategy=d.strategy AND c.request_key=d.request_key "
                "WHERE d.account=? AND d.strategy=? AND d.request_key=?", (key[0], key[1], target["request_key"])).fetchone()
            child = GatewayDelegatedCommand.from_mapping(json.loads(childrow["envelope_json"]))
            if (child.parent_ref != key[2] or child.child_id != saved["child_id"]
                    or childrow["reservation_id"] != target["reservation_id"]
                    or childrow["digest"] != target["payload_digest"] or childrow["principal"] != target["target_principal"]
                    or type(target["target_version"]) is not int or childrow["version"] < target["target_version"]
                    or target["target_version"] != {"RELEASE_PENDING": 1, "WAIT_DISPATCH": 2, "CANCEL_PENDING": 3}[target["phase"]]
                    or (target["phase"] == "RELEASE_PENDING" and (target["native_identity"] is not None or target["strong_identity_keys"] is not None))
                    or (target["phase"] != "RELEASE_PENDING" and
                        (json.loads(childrow["native_identity_json"]) != target["native_identity"]
                         or json.loads(childrow["strong_keys_json"]) != target["strong_identity_keys"]))):
                raise ValueError
        children = {}
        for childrow in db.execute("SELECT d.envelope_json,c.payload_json FROM direct_delegated_commands d "
            "JOIN direct_journal_commands c ON c.account=d.account AND c.strategy=d.strategy AND c.request_key=d.request_key"):
            child = GatewayDelegatedCommand.from_mapping(json.loads(childrow["envelope_json"]))
            parent_key = (child.account_scope, child.strategy_scope, child.parent_ref)
            if parent_key in by_key:
                key = (*parent_key, child.child_id)
                if key in children:
                    raise ValueError
                children[key] = (child, json.loads(childrow["payload_json"]))
        for evidence in evidence_rows:
            key = (evidence["account"], evidence["strategy"], evidence["parent_ref"])
            parent = by_key[key]
            child, payload = children[(*key, evidence["child_id"])]
            value = _rollover_evidence(json.loads(evidence["evidence_json"]), json.loads(parent["spec_json"]), child, payload)
            encoded = canonical_gateway_payload(value)
            if encoded != evidence["evidence_json"] or _sha(encoded) != evidence["evidence_digest"]:
                raise ValueError
        evidence_keys = {(row["account"], row["strategy"], row["parent_ref"], row["child_id"])
                         for row in evidence_rows}
        for key, (child, payload) in children.items():
            parent = by_key[key[:3]]
            if (json.loads(parent["spec_json"])["offset"] == "close_today"
                    and payload.get("offset") == "close_yesterday" and key not in evidence_keys):
                raise ValueError
    except Exception:
        raise DirectCommandJournalError("INVALID_DATABASE") from None


class GatewayParentAuthority:
    """Uses the existing account journal transaction, account guard and ACL fence."""

    def __init__(self, journal, guard, *, now_ns, trading_day, rollover_recheck=None, risk_recheck=None,
                 transfer_completed=None, target_recheck=None):
        if (type(guard) is not LocalAccountSessionGuard or not callable(now_ns)
                or not callable(trading_day) or (rollover_recheck is not None and not callable(rollover_recheck))
                or (risk_recheck is not None and not callable(risk_recheck))
                or (transfer_completed is not None and not callable(transfer_completed))
                or (target_recheck is not None and not callable(target_recheck))):
            _error("INVALID_AUTHORITY")
        self._journal, self._guard = journal, guard
        self._now_ns, self._trading_day = now_ns, trading_day
        self._rollover_recheck, self._risk_recheck = rollover_recheck, risk_recheck
        self._transfer_completed = transfer_completed
        self._target_recheck = target_recheck
        self._guard_check()

    def _guard_check(self):
        try:
            self._guard.assert_owned()
            if (self._journal._schema_version < 13 or
                    self._guard.account_key_digest != hashlib.sha256(self._journal.account_scope.encode("utf-8")).hexdigest()
                    or self._guard.acquire() != self._journal.generation):
                raise ValueError
        except Exception:
            _error("AUTHORITY_UNAVAILABLE")

    @contextmanager
    def _access(self, principal, actor_ref, fence, recheck):
        if not _ref(principal) or not _ref(actor_ref) or not callable(fence) or not callable(recheck):
            _error("AUTHORITY_UNAVAILABLE")
        with ExitStack() as stack:
            manager = fence()
            type(manager).__enter__(manager)
            stack.push(lambda *exc: (type(manager).__exit__(manager, *exc), False)[1])
            db = stack.enter_context(self._journal._transaction())
            self._guard_check()
            if recheck() is not True:
                _error("AUTHORITY_UNAVAILABLE")
            yield db
            self._guard_check()
            if recheck() is not True:
                _error("AUTHORITY_UNAVAILABLE")

    def _row(self, db, account, strategy, parent_ref, registration_operation_id):
        if account != self._journal.account_scope or any(not _ref(x) for x in (strategy, parent_ref, registration_operation_id)):
            _error("INVALID_PARENT")
        row = db.execute("SELECT * FROM direct_execution_parents WHERE account=? AND strategy=? AND parent_ref=?",
                         (account, strategy, parent_ref)).fetchone()
        if row is None:
            _error("NOT_FOUND")
        if row["registration_operation_id"] != registration_operation_id:
            _error("REQUEST_CONFLICT")
        return row

    def _observed(self, row):
        result = _result(row)
        now = self._now_ns()
        if type(now) is not int or now < 0:
            _error("CLOCK_UNAVAILABLE")
        if result["state"] == "ACTIVE" and now >= result["spec"]["expires_at_ns"]:
            result["state"] = "EXPIRED"
        return result

    def register_parent(self, spec, *, principal, actor_ref, fence, recheck):
        spec = _spec(spec)
        if spec["account_scope"] != self._journal.account_scope:
            _error("INVALID_PARENT")
        encoded = canonical_gateway_payload(spec)
        digest = _sha(encoded)
        with self._access(principal, actor_ref, fence, recheck) as db:
            row = db.execute("SELECT * FROM direct_execution_parents WHERE account=? AND strategy=? AND parent_ref=?",
                             (spec["account_scope"], spec["strategy_scope"], spec["parent_ref"])).fetchone()
            if row is not None:
                if (row["spec_json"] != encoded or row["execution_principal"] != principal
                        or row["execution_actor_ref"] != actor_ref):
                    _error("REQUEST_CONFLICT")
                return self._observed(row)
            existing = db.execute("SELECT envelope_json FROM direct_delegated_commands WHERE account=? AND strategy=?",
                                  (spec["account_scope"], spec["strategy_scope"])).fetchall()
            if any(GatewayDelegatedCommand.from_mapping(json.loads(item["envelope_json"])).parent_ref == spec["parent_ref"]
                   for item in existing):
                # A new parent cannot retroactively authorize v12 child claims.
                _error("REQUEST_CONFLICT")
            now, day = self._now_ns(), self._trading_day()
            if type(now) is not int or now < 0 or not _day(day):
                _error("SOURCE_UNAVAILABLE")
            if now >= spec["expires_at_ns"] or day != spec["creation_trading_day"]:
                _error("PARENT_EXPIRED")
            count = db.execute("SELECT (SELECT count(*) FROM direct_execution_parents) + (SELECT count(*) FROM direct_execution_parent_operations) + (SELECT count(*) FROM direct_execution_rollover_evidence) + (SELECT count(*) FROM direct_execution_parent_cancel_targets)").fetchone()[0]
            if count + 2 > self._journal._max_records:
                _error("CAPACITY_EXCEEDED")
            try:
                db.execute("INSERT INTO direct_execution_parents VALUES (?,?,?,?,?,?,?,?,?,?)",
                           (spec["account_scope"], spec["strategy_scope"], spec["parent_ref"], spec["registration_operation_id"], encoded, digest, principal, actor_ref, "ACTIVE", 1))
            except Exception:
                _error("REQUEST_CONFLICT")
            row = self._row(db, spec["account_scope"], spec["strategy_scope"], spec["parent_ref"], spec["registration_operation_id"])
            result = _result(row)
            db.execute("INSERT INTO direct_execution_parent_operations VALUES (?,?,?,?,?,?,?)",
                       (spec["account_scope"], spec["strategy_scope"], spec["parent_ref"], spec["registration_operation_id"], "REGISTER", digest, canonical_gateway_payload(result)))
            self._journal._bump(db)
            return result

    def query_parent(self, account_scope, strategy_scope, parent_ref, registration_operation_id, *, principal, actor_ref, fence, recheck):
        with self._access(principal, actor_ref, fence, recheck) as db:
            return self._observed(self._row(db, account_scope, strategy_scope, parent_ref, registration_operation_id))

    def query_operation(self, account_scope, strategy_scope, parent_ref, operation_id, *, principal, actor_ref, fence, recheck):
        if account_scope != self._journal.account_scope or any(not _ref(x) for x in (strategy_scope, parent_ref, operation_id)):
            _error("INVALID_PARENT")
        with self._access(principal, actor_ref, fence, recheck) as db:
            row = db.execute("SELECT * FROM direct_execution_parent_operations WHERE account=? AND strategy=? AND parent_ref=? AND operation_id=?",
                             (account_scope, strategy_scope, parent_ref, operation_id)).fetchone()
            if row is None:
                _error("NOT_FOUND")
            return {"operation_id": operation_id, "kind": row["kind"], "result": json.loads(row["result_json"])}

    def cancel_parent(self, account_scope, strategy_scope, parent_ref, registration_operation_id, cancel_operation_id, expected_version, *, principal, actor_ref, fence, recheck):
        if not _ref(cancel_operation_id) or type(expected_version) is not int:
            _error("INVALID_PARENT")
        digest = _sha(canonical_gateway_payload({"expected_version": expected_version}))
        with self._access(principal, actor_ref, fence, recheck) as db:
            row = self._row(db, account_scope, strategy_scope, parent_ref, registration_operation_id)
            prior = db.execute("SELECT * FROM direct_execution_parent_operations WHERE account=? AND strategy=? AND parent_ref=? AND operation_id=?",
                               (account_scope, strategy_scope, parent_ref, cancel_operation_id)).fetchone()
            if prior:
                if prior["kind"] != "CANCEL" or prior["request_digest"] != digest:
                    _error("REQUEST_CONFLICT")
                return json.loads(prior["result_json"])
            if row["state"] != "ACTIVE" or row["version"] != expected_version:
                _error("VERSION_CONFLICT")
            targets = _freeze_cancel_targets(db, account_scope, strategy_scope, parent_ref, cancel_operation_id, self._journal._max_records)
            count = db.execute("SELECT (SELECT count(*) FROM direct_execution_parents) + (SELECT count(*) FROM direct_execution_parent_operations) + (SELECT count(*) FROM direct_execution_rollover_evidence) + (SELECT count(*) FROM direct_execution_parent_cancel_targets)").fetchone()[0]
            if count + 1 + len(targets) > self._journal._max_records:
                _error("CAPACITY_EXCEEDED")
            for target in targets:
                encoded = canonical_gateway_payload(target)
                db.execute("INSERT INTO direct_execution_parent_cancel_targets VALUES (?,?,?,?,?,?)",
                           (account_scope, strategy_scope, parent_ref, target["child_id"], encoded, _sha(encoded)))
            db.execute("UPDATE direct_execution_parents SET state='CANCEL_REQUESTED', version=2 WHERE account=? AND strategy=? AND parent_ref=?", (account_scope, strategy_scope, parent_ref))
            row = self._row(db, account_scope, strategy_scope, parent_ref, registration_operation_id)
            result = _result(row)
            result["targets"] = targets
            db.execute("INSERT INTO direct_execution_parent_operations VALUES (?,?,?,?,?,?,?)", (account_scope, strategy_scope, parent_ref, cancel_operation_id, "CANCEL", digest, canonical_gateway_payload(result)))
            self._journal._bump(db)
            return result

    def check_release_target(self, db, command, operation_id, reservation_id, digest):
        """Fence a frozen, definitely-unsubmitted child on journal.release's transaction."""
        try:
            self._guard_check()
            if (not db.in_transaction or type(command) is not GatewayDelegatedCommand
                    or command.parent_ref is None or command.child_id is None):
                return False
            saved = db.execute("SELECT p.state,t.target_json,d.envelope_json,c.* "
                "FROM direct_execution_parent_cancel_targets t JOIN direct_execution_parents p "
                "ON p.account=t.account AND p.strategy=t.strategy AND p.parent_ref=t.parent_ref "
                "JOIN direct_delegated_commands d ON d.account=t.account AND d.strategy=t.strategy "
                "JOIN direct_journal_commands c ON c.account=d.account AND c.strategy=d.strategy AND c.request_key=d.request_key "
                "WHERE t.account=? AND t.strategy=? AND t.parent_ref=? AND t.child_id=? AND d.request_key=?",
                (command.account_scope, command.strategy_scope, command.parent_ref, command.child_id,
                 command.request_key)).fetchone()
            if saved is None or saved["state"] != "CANCEL_REQUESTED" or saved["envelope_json"] != command.canonical_json:
                return False
            target = json.loads(saved["target_json"])
            if (target["phase"] != "RELEASE_PENDING" or target["cancel_operation_id"] != operation_id
                    or target["reservation_id"] != reservation_id or target["payload_digest"] != digest
                    or command.payload_digest != digest or saved["reservation_id"] != reservation_id
                    or saved["principal"] != command.actor_principal or saved["digest"] != digest):
                return False
            if saved["status"] == "RESERVED":
                return saved["version"] == target["target_version"]
            if saved["status"] not in ("RELEASED", "EXPIRED"):
                return False
            release = db.execute("SELECT * FROM direct_journal_releases WHERE account=? AND operation_id=?",
                                 (command.account_scope, operation_id)).fetchone()
            if saved["status"] == "EXPIRED" and release is None:
                return (saved["version"] == target["target_version"] + 1
                        and _remaining_close(db, command.account_scope, reservation_id, "EXPIRED",
                            _quantity(json.loads(saved["payload_json"])["quantity"])) == 0)
            return (release is not None and release["strategy"] == command.strategy_scope
                    and release["request_key"] == command.request_key and release["reservation_id"] == reservation_id
                    and release["digest"] == digest and release["principal"] == command.actor_principal
                    and release["expected_version"] == target["target_version"])
        except Exception:
            return False

    def check_cancel_target(self, db, command, operation_id, reservation_id, digest):
        """Fence a frozen native child against its original same-account command."""
        try:
            self._guard_check()
            if (not db.in_transaction or type(command) is not GatewayDelegatedCommand
                    or command.parent_ref is None or command.child_id is None):
                return False
            saved = db.execute("SELECT p.state,t.target_json,d.envelope_json,c.* "
                "FROM direct_execution_parent_cancel_targets t JOIN direct_execution_parents p "
                "ON p.account=t.account AND p.strategy=t.strategy AND p.parent_ref=t.parent_ref "
                "JOIN direct_delegated_commands d ON d.account=t.account AND d.strategy=t.strategy "
                "JOIN direct_journal_commands c ON c.account=d.account AND c.strategy=d.strategy AND c.request_key=d.request_key "
                "WHERE t.account=? AND t.strategy=? AND t.parent_ref=? AND t.child_id=? AND d.request_key=?",
                (command.account_scope, command.strategy_scope, command.parent_ref, command.child_id,
                 command.request_key)).fetchone()
            if saved is None or saved["state"] != "CANCEL_REQUESTED" or saved["envelope_json"] != command.canonical_json:
                return False
            target = json.loads(saved["target_json"])
            return (target["phase"] in ("CANCEL_PENDING", "WAIT_DISPATCH")
                    and target["cancel_operation_id"] == operation_id
                    and target["reservation_id"] == reservation_id and target["payload_digest"] == digest
                    and command.payload_digest == digest and saved["reservation_id"] == reservation_id
                    and saved["principal"] == command.actor_principal and saved["digest"] == digest
                    and saved["status"] == "SENT"
                    and saved["native_identity_json"] is not None and saved["strong_keys_json"] is not None
                    and json.loads(saved["native_identity_json"]) == target["native_identity"]
                    and json.loads(saved["strong_keys_json"]) == target["strong_identity_keys"])
        except Exception:
            return False

    def recheck_child(self, db, command, payload):
        """Recheck prospective/already persisted child under the caller's write lock."""
        try:
            self._guard_check()
            if (not db.in_transaction or type(command) is not GatewayDelegatedCommand
                    or command.parent_ref is None or command.child_id is None
                    or gateway_payload_digest(dict(payload)) != command.payload_digest):
                return False
            row = db.execute("SELECT * FROM direct_execution_parents WHERE account=? AND strategy=? AND parent_ref=?",
                             (command.account_scope, command.strategy_scope, command.parent_ref)).fetchone()
            if row is None or row["state"] != "ACTIVE":
                return False
            spec = json.loads(row["spec_json"])
            now, day = self._now_ns(), self._trading_day()
            if (type(now) is not int or now < 0 or now >= spec["expires_at_ns"] or not _day(day)
                    or day not in spec["allowed_trading_days"] or command.account_scope != self._journal.account_scope
                    or command.execution_domain_ref != spec["execution_domain_ref"]
                    or command.instrument.to_dict() != spec["instrument"]):
                return False
            if command.actor_kind == "execution":
                if (command.actor_principal != row["execution_principal"] or command.actor_ref != row["execution_actor_ref"]
                        or command.grant_revision != spec["grant_revision"]):
                    return False
            elif command.actor_kind != "risk" or self._risk_recheck is None or self._risk_recheck(db, spec, command) is not True:
                return False
            if (payload.get("side") != spec["side"] or payload.get("quantity_unit") != spec["quantity_unit"]
                    or payload.get("order_type") != "limit"):
                return False
            if spec["offset"] != "open":
                if (self._target_recheck is None
                        or self._target_recheck(db, spec, command, payload, day) is not True):
                    return False
            child_offset = payload.get("offset")
            if child_offset != spec["offset"]:
                if (spec["offset"] != "close_today" or child_offset != "close_yesterday"
                        or day == spec["creation_trading_day"] or self._rollover_recheck is None):
                    return False
                evidence = _rollover_evidence(self._rollover_recheck(db, spec, command, payload, day),
                                              spec, command, payload, now=now)
                if evidence["trading_day"] != day:
                    return False
                encoded = canonical_gateway_payload(evidence)
                prior = db.execute("SELECT evidence_json,evidence_digest FROM direct_execution_rollover_evidence "
                    "WHERE account=? AND strategy=? AND parent_ref=? AND child_id=?",
                    (command.account_scope, command.strategy_scope, command.parent_ref, command.child_id)).fetchone()
                if prior is None:
                    count = db.execute("SELECT (SELECT count(*) FROM direct_execution_parents) + (SELECT count(*) FROM direct_execution_parent_operations) + (SELECT count(*) FROM direct_execution_rollover_evidence) + (SELECT count(*) FROM direct_execution_parent_cancel_targets)").fetchone()[0]
                    if count + 1 > self._journal._max_records:
                        return False
                    db.execute("INSERT INTO direct_execution_rollover_evidence VALUES (?,?,?,?,?,?)",
                        (command.account_scope, command.strategy_scope, command.parent_ref, command.child_id, encoded, _sha(encoded)))
                    self._journal._bump(db)
                elif prior["evidence_json"] != encoded or prior["evidence_digest"] != _sha(encoded):
                    return False
            elif spec["offset"] == "close_today" and day != spec["creation_trading_day"]:
                return False
            price, limit = _quantity(payload.get("price")), _quantity(spec["limit_price"])
            if (spec["side"] == "buy" and price > limit) or (spec["side"] == "sell" and price < limit):
                return False
            prospective = _quantity(payload.get("quantity"))
            if self._transfer_completed is None:
                return False
            transferred = _quantity(self._transfer_completed(db, spec), allow_zero=True)
            rows = db.execute("SELECT d.envelope_json,c.reservation_id,c.status,c.payload_json FROM direct_delegated_commands d JOIN direct_journal_commands c ON c.account=d.account AND c.strategy=d.strategy AND c.request_key=d.request_key WHERE d.account=? AND d.strategy=?", (command.account_scope, command.strategy_scope)).fetchall()
            if len(rows) > self._journal._max_records:
                return False
            child_ids, current = set(), False
            with localcontext() as ctx:
                ctx.prec = 180
                occupied = transferred
                for saved in rows:
                    child = GatewayDelegatedCommand.from_mapping(json.loads(saved["envelope_json"]))
                    if child.parent_ref != command.parent_ref:
                        continue
                    if child.child_id in child_ids:
                        return False
                    child_ids.add(child.child_id)
                    child_payload = json.loads(saved["payload_json"])
                    quantity = _quantity(child_payload.get("quantity"))
                    filled_row = db.execute("SELECT total_quantity FROM direct_execution_totals WHERE account=? AND reservation_id=?", (command.account_scope, saved["reservation_id"])).fetchone()
                    filled = Decimal(0) if filled_row is None else _quantity(filled_row[0], allow_zero=True)
                    occupied += filled + _remaining_close(db, command.account_scope, saved["reservation_id"], saved["status"], quantity)
                    if child.child_id == command.child_id:
                        if child != command or child_payload != dict(payload):
                            return False
                        current = True
                if not current:
                    occupied += prospective
                return occupied <= _quantity(spec["quantity"])
        except Exception:
            return False
