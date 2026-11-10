"""Same-account strategy position replay and close reservation checks.

Only installed account-owner code may invoke these functions, on the journal's
existing write transaction.  No object in this module authenticates a provider,
proves a coherent account snapshot, or owns another SQLite connection.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, localcontext
from typing import Callable

from bt_api_base.direct_write_protocol import DirectExecutionEventKind, DirectOrderStatus
from bt_api_base.gateway_execution_protocol import GatewayReturnFact
from bt_api_base.market_protocol import MarketInstrumentKey

from .direct_command_journal import DirectCommandJournalError, _json

_STRATEGY_LEDGER_DDL = {
    "strategy_position_baseline": "CREATE TABLE strategy_position_baseline (account TEXT PRIMARY KEY, initial_trading_day TEXT NOT NULL, evidence_digest TEXT NOT NULL, evidence_json TEXT NOT NULL)",
    "strategy_external_baseline": "CREATE TABLE strategy_external_baseline (account TEXT NOT NULL, instrument_json TEXT NOT NULL, direction TEXT NOT NULL, today_quantity TEXT NOT NULL, yesterday_quantity TEXT NOT NULL, evidence_digest TEXT NOT NULL, PRIMARY KEY(account, instrument_json, direction))",
}
_MAX_ROWS = 1_000_000


def _error(code: str) -> None:
    raise DirectCommandJournalError(code)


def _text(value: object) -> bool:
    return type(value) is str and bool(value) and value == value.strip() and len(value) <= 512


def _day(value: object) -> bool:
    if type(value) is not str or re.fullmatch(r"[0-9]{8}", value) is None:
        return False
    try:
        datetime.date(int(value[:4]), int(value[4:6]), int(value[6:]))
    except ValueError:
        return False
    return True


def _digest(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _quantity(value: object, *, allow_zero: bool = False) -> Decimal:
    if type(value) is not str or re.fullmatch(r"[0-9]{1,42}(?:\.[0-9]{1,42})?", value) is None:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    try:
        result = Decimal(value)
    except InvalidOperation:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    if result < 0 or (not allow_zero and result == 0):
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    return result


def _create_strategy_ledger_tables(db: sqlite3.Connection) -> None:
    for statement in _STRATEGY_LEDGER_DDL.values():
        db.execute(statement)


@dataclass(frozen=True, slots=True)
class ExternalBaselinePosition:
    """One broker-attested position assigned to external, never a new trade."""

    instrument: MarketInstrumentKey
    direction: str
    today_quantity: str
    yesterday_quantity: str

    def __post_init__(self):
        if type(self.instrument) is not MarketInstrumentKey or self.direction not in {"long", "short"}:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        if not (_quantity(self.today_quantity, allow_zero=True)
                or _quantity(self.yesterday_quantity, allow_zero=True)):
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        # Validate both values even when the first is nonzero.
        _quantity(self.yesterday_quantity, allow_zero=True)

    def to_mapping(self) -> dict:
        return {"instrument": self.instrument.to_dict(), "direction": self.direction,
                "today_quantity": self.today_quantity, "yesterday_quantity": self.yesterday_quantity}

    @classmethod
    def from_mapping(cls, mapping: object) -> "ExternalBaselinePosition":
        if type(mapping) is not dict or set(mapping) != {"instrument", "direction", "today_quantity", "yesterday_quantity"}:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        try:
            instrument = MarketInstrumentKey.from_dict(mapping["instrument"])
        except Exception as exc:
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc
        return cls(instrument, mapping["direction"], mapping["today_quantity"], mapping["yesterday_quantity"])


@dataclass(frozen=True, slots=True)
class StrategyBaselineEvidence:
    """Redacted references to a single full empty-account provider observation.

    These fields are declarations only: constructing this value, or matching
    its digest, never proves provider authority or a comparable cut.
    """

    account_scope: str
    journal_id: str
    trading_day: str
    route: str
    owner_generation: str
    session_generation: int
    source_ref: str
    position_snapshot_ref: str
    open_orders_snapshot_ref: str
    cut_ref: str
    coverage_refs: tuple[str, ...]
    observed_at_ns: int
    valid_until_ns: int
    positions_complete: bool
    open_orders_complete: bool
    positions_empty: bool
    open_orders_empty: bool
    schema_version: int = 1
    external_positions: tuple[ExternalBaselinePosition, ...] = ()
    operator_ref: str | None = None
    operation_id: str | None = None
    # schema_version 2 only (replayed baseline, I63-E111): the journal's own
    # attributed trades, replayed from ``history_start_trading_day``, are
    # declared to explain every row of ``account_positions`` at this cut.
    history_start_trading_day: str | None = None
    account_positions: tuple[ExternalBaselinePosition, ...] = ()

    def __post_init__(self):
        refs = (self.account_scope, self.journal_id, self.route, self.owner_generation, self.source_ref,
                self.position_snapshot_ref, self.open_orders_snapshot_ref, self.cut_ref)
        if type(self.schema_version) is not int or self.schema_version not in (1, 2):
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        if self.schema_version == 1:
            if self.history_start_trading_day is not None or self.account_positions != ():
                _error("STRATEGY_LEDGER_UNAVAILABLE")
            holdings = self.external_positions
        else:
            holdings = self.account_positions
            if (not _day(self.history_start_trading_day) or not _day(self.trading_day)
                    or self.history_start_trading_day > self.trading_day
                    or self.external_positions != () or self.operator_ref is not None
                    or type(holdings) is not tuple or len(holdings) > 4096
                    or any(type(item) is not ExternalBaselinePosition for item in holdings)
                    or len({(_json(item.instrument.to_dict()), item.direction) for item in holdings})
                       != len(holdings)):
                _error("STRATEGY_LEDGER_UNAVAILABLE")
        if (type(holdings) is not tuple
                or any(not _text(item) or not item.isprintable() for item in refs)
                or not _day(self.trading_day)
                or type(self.session_generation) is not int or not 0 < self.session_generation < 2**63
                or type(self.observed_at_ns) is not int or not 0 < self.observed_at_ns < 2**63
                or type(self.valid_until_ns) is not int
                or not self.observed_at_ns < self.valid_until_ns < 2**63
                or type(self.coverage_refs) is not tuple or not 1 <= len(self.coverage_refs) <= 4096
                or any(not _text(item) or not item.isprintable() for item in self.coverage_refs)
                or tuple(sorted(set(self.coverage_refs))) != self.coverage_refs
                or self.positions_complete is not True or self.open_orders_complete is not True
                or type(self.positions_empty) is not bool or self.open_orders_empty is not True
                or type(self.external_positions) is not tuple
                or any(type(item) is not ExternalBaselinePosition for item in self.external_positions)
                or (self.positions_empty != (not holdings))
                or ((self.operator_ref is None) != (self.operation_id is None))
                or (self.operator_ref is not None and (not _text(self.operator_ref)
                    or not self.operator_ref.isprintable() or not _text(self.operation_id)
                    or not self.operation_id.isprintable()))
                or (self.external_positions and self.operator_ref is None)
                or len({(_json(item.instrument.to_dict()), item.direction) for item in self.external_positions})
                   != len(self.external_positions)):
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        try:
            _json(self.to_mapping())
        except DirectCommandJournalError as exc:
            raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc

    @property
    def initial_trading_day(self) -> str:
        """The day the ledger replay starts from (the observation day for v1)."""
        return self.trading_day if self.schema_version == 1 else self.history_start_trading_day

    def to_mapping(self) -> dict:
        mapping = self._v1_mapping()
        if self.schema_version == 2:
            mapping["history_start_trading_day"] = self.history_start_trading_day
            mapping["account_positions"] = [position.to_mapping() for position in self.account_positions]
        return mapping

    def _v1_mapping(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "account_scope": self.account_scope,
            "journal_id": self.journal_id,
            "trading_day": self.trading_day,
            "route": self.route,
            "owner_generation": self.owner_generation,
            "session_generation": self.session_generation,
            "source_ref": self.source_ref,
            "position_snapshot_ref": self.position_snapshot_ref,
            "open_orders_snapshot_ref": self.open_orders_snapshot_ref,
            "cut_ref": self.cut_ref,
            "coverage_refs": list(self.coverage_refs),
            "observed_at_ns": self.observed_at_ns,
            "valid_until_ns": self.valid_until_ns,
            "positions_complete": self.positions_complete,
            "open_orders_complete": self.open_orders_complete,
            "positions_empty": self.positions_empty,
            "open_orders_empty": self.open_orders_empty,
            "external_positions": [position.to_mapping() for position in self.external_positions],
            "operator_ref": self.operator_ref,
            "operation_id": self.operation_id,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_json(self.to_mapping()).encode("ascii")).hexdigest()

    @classmethod
    def from_mapping(cls, mapping: object) -> "StrategyBaselineEvidence":
        fields = {
            "schema_version", "account_scope", "journal_id", "trading_day", "route", "owner_generation",
            "session_generation", "source_ref", "position_snapshot_ref", "open_orders_snapshot_ref",
            "cut_ref", "coverage_refs", "observed_at_ns", "valid_until_ns", "positions_complete",
            "open_orders_complete", "positions_empty", "open_orders_empty", "external_positions",
            "operator_ref", "operation_id",
        }
        replayed = type(mapping) is dict and mapping.get("schema_version") == 2
        if replayed:
            fields |= {"history_start_trading_day", "account_positions"}
        if (type(mapping) is not dict or set(mapping) != fields
                or type(mapping.get("coverage_refs")) is not list
                or type(mapping.get("external_positions")) is not list
                or (replayed and type(mapping.get("account_positions")) is not list)):
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        data = dict(mapping)
        data["coverage_refs"] = tuple(data["coverage_refs"])
        data["external_positions"] = tuple(ExternalBaselinePosition.from_mapping(row) for row in data["external_positions"])
        if replayed:
            data["account_positions"] = tuple(
                ExternalBaselinePosition.from_mapping(row) for row in data["account_positions"])
        return cls(**data)


def _verify_strategy_ledger_integrity(db: sqlite3.Connection, account: str) -> None:
    if not _text(account):
        _error("INVALID_DATABASE")
    try:
        rows = db.execute("SELECT account, initial_trading_day, evidence_digest, evidence_json FROM strategy_position_baseline").fetchall()
        if len(rows) > 1:
            _error("INVALID_DATABASE")
        baseline_rows = db.execute(
            "SELECT account,instrument_json,direction,today_quantity,yesterday_quantity,evidence_digest "
            "FROM strategy_external_baseline"
        ).fetchall()
        if len(baseline_rows) > _MAX_ROWS:
            _error("INVALID_DATABASE")
        if not rows and baseline_rows:
            _error("INVALID_DATABASE")
        for row in rows:
            raw = json.loads(row[3])
            evidence = StrategyBaselineEvidence.from_mapping(raw)
            journal = db.execute("SELECT journal_id FROM direct_journal_meta WHERE account=?", (account,)).fetchone()
            if (journal is None or row[0] != account or evidence.account_scope != account
                    or evidence.journal_id != journal[0]
                    or evidence.initial_trading_day != row[1] or _json(raw) != row[3]
                    or not _digest(row[2]) or evidence.digest != row[2]):
                _error("INVALID_DATABASE")
            expected = {
                (account, _json(item.instrument.to_dict()), item.direction,
                 item.today_quantity, item.yesterday_quantity, evidence.digest)
                for item in evidence.external_positions
            }
            if {tuple(item) for item in baseline_rows} != expected or len(baseline_rows) != len(expected):
                _error("INVALID_DATABASE")
    except DirectCommandJournalError as exc:
        raise DirectCommandJournalError("INVALID_DATABASE") from exc
    except (sqlite3.Error, TypeError, ValueError) as exc:
        raise DirectCommandJournalError("INVALID_DATABASE") from exc


def initialize_empty_strategy_baseline(
    db: sqlite3.Connection,
    evidence: StrategyBaselineEvidence,
    *,
    verify_current_empty: Callable[[StrategyBaselineEvidence], bool],
) -> None:
    """Install an empty baseline once, under the caller's owner fence/transaction.

    The callback is trusted installed owner code, not RPC payload. It verifies
    the exact account/day/session, full positions and open-orders, source
    continuity, comparable cut, and maintains its fence through commit. Neither
    a callback chosen by a client nor this persisted digest is a proof.
    """
    if (not db.in_transaction or type(evidence) is not StrategyBaselineEvidence
            or evidence.schema_version != 1
            or not evidence.positions_empty or not callable(verify_current_empty)):
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    account = evidence.account_scope
    _verify_strategy_ledger_integrity(db, account)
    encoded, digest = _json(evidence.to_mapping()), evidence.digest
    row = db.execute("SELECT initial_trading_day, evidence_digest, evidence_json FROM strategy_position_baseline WHERE account=?", (account,)).fetchone()
    if row is not None:
        if tuple(row) != (evidence.trading_day, digest, encoded):
            _error("STRATEGY_BASELINE_CONFLICT")
        return
    try:
        if any(db.execute(f"SELECT 1 FROM {table} WHERE account=? LIMIT 1", (account,)).fetchone() is not None
               for table in ("direct_journal_commands", "direct_execution_facts")):
            _error("STRATEGY_BASELINE_HISTORY_PRESENT")
        if verify_current_empty(evidence) is not True:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        db.execute("INSERT INTO strategy_position_baseline VALUES (?, ?, ?, ?)",
                   (account, evidence.trading_day, digest, encoded))
    except DirectCommandJournalError:
        raise
    except Exception as exc:
        raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc


def initialize_external_strategy_baseline(
    db: sqlite3.Connection,
    evidence: StrategyBaselineEvidence,
    *,
    verify_authorized_snapshot: Callable[[StrategyBaselineEvidence], bool],
) -> None:
    """Initialize explicit external holdings from one authorized full snapshot.

    The trusted owner verifier must establish operator authority, exact account,
    complete same-cut position/open-order facts and source continuity, including
    every supplied holding, and keep the external fence through commit. Neither
    the rows nor the operator name supplied by a caller constitute that proof.
    """
    if (not db.in_transaction or type(evidence) is not StrategyBaselineEvidence
            or evidence.schema_version != 1
            or evidence.positions_empty or not callable(verify_authorized_snapshot)):
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    account = evidence.account_scope
    _verify_strategy_ledger_integrity(db, account)
    encoded, digest = _json(evidence.to_mapping()), evidence.digest
    row = db.execute("SELECT initial_trading_day,evidence_digest,evidence_json FROM strategy_position_baseline WHERE account=?", (account,)).fetchone()
    if row is not None:
        if tuple(row) != (evidence.trading_day, digest, encoded):
            _error("STRATEGY_BASELINE_CONFLICT")
        return
    try:
        if any(db.execute(f"SELECT 1 FROM {table} WHERE account=? LIMIT 1", (account,)).fetchone() is not None
               for table in ("direct_journal_commands", "direct_execution_facts")):
            _error("STRATEGY_BASELINE_HISTORY_PRESENT")
        if verify_authorized_snapshot(evidence) is not True:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        db.execute("INSERT INTO strategy_position_baseline VALUES (?, ?, ?, ?)",
                   (account, evidence.trading_day, digest, encoded))
        for position in evidence.external_positions:
            db.execute("INSERT INTO strategy_external_baseline VALUES (?, ?, ?, ?, ?, ?)",
                       (account, _json(position.instrument.to_dict()), position.direction,
                        position.today_quantity, position.yesterday_quantity, digest))
        _verify_strategy_ledger_integrity(db, account)
    except DirectCommandJournalError:
        raise
    except Exception as exc:
        raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc


_NEVER_AT_VENUE = frozenset(("RESERVED", "RELEASED", "EXPIRED", "NOT_SENT"))
_POSSIBLY_AT_VENUE = frozenset(("DISPATCHING", "SENT", "UNKNOWN"))


def _command_settled(db: sqlite3.Connection, account: str, reservation_id: str, status: str,
                     quantity: Decimal) -> bool:
    """Whether the journal alone proves nothing more can trade on this command.

    A command that never reached the venue must have no order or trade fact.
    A command that may have reached it needs a newest attributed ORDER fact in
    a terminal state whose cumulative fill equals the applied trades.
    """
    facts = db.execute(
        "SELECT fact_json,disposition,event_sequence FROM direct_execution_facts "
        "WHERE account=? AND reservation_id=? LIMIT ?", (account, reservation_id, _MAX_ROWS + 1),
    ).fetchall()
    if len(facts) > _MAX_ROWS:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    if status in _NEVER_AT_VENUE:
        return not any(_decode_fact(raw).kind in (DirectExecutionEventKind.ORDER, DirectExecutionEventKind.TRADE)
                       for raw, _, _ in facts)
    if status not in _POSSIBLY_AT_VENUE:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    row = db.execute(
        "SELECT total_quantity FROM direct_execution_totals WHERE account=? AND reservation_id=?",
        (account, reservation_id),
    ).fetchone()
    filled = Decimal(0) if row is None else _quantity(row[0], allow_zero=True)
    if filled > quantity:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    ordered = sorted((item for item in facts if item[1] == "ATTRIBUTED" and item[2] is not None),
                     key=lambda item: item[2], reverse=True)
    for raw, _, _ in ordered:
        fact = _decode_fact(raw)
        if fact.kind is not DirectExecutionEventKind.ORDER:
            continue
        # The newest ORDER supersedes older terminal observations.
        return (fact.status in {DirectOrderStatus.CANCELLED, DirectOrderStatus.FILLED, DirectOrderStatus.REJECTED}
                and fact.filled_quantity is not None
                and _quantity(fact.filled_quantity, allow_zero=True) == filled
                and (fact.status is not DirectOrderStatus.FILLED or filled == quantity)
                and (fact.status is not DirectOrderStatus.REJECTED or filled == 0))
    return False


def _native_trading_day(raw: object) -> str | None:
    """The trading day of a command's native identity, or None when unknown."""
    try:
        identity = json.loads(raw) if type(raw) is str else None
        if type(identity) is not dict:
            return None
        fields = identity.get("fields_json")
        fields = json.loads(fields) if type(fields) is str else identity.get("fields")
        day = fields.get("trading_day") if type(fields) is dict else None
    except Exception:
        return None
    return day if _day(day) else None


def prior_day_commands_settled(db: sqlite3.Connection, account: str, binding: "StrategyInstrumentBinding",
                               trading_day: str) -> bool:
    """No command of an earlier trading day on this instrument can still trade.

    A venue query only covers the current trading day, so an order that may
    have reached the venue on an earlier day and has no settled terminal
    evidence in the journal can never be completed by a later query: its fills
    are unknowable and the ledger is not continuous for the instrument. The
    caller holds the owner fence and one SQLite transaction. Commands of the
    current day are not examined; their completeness is the return source's.
    """
    if (not db.in_transaction or not _text(account) or type(binding) is not StrategyInstrumentBinding
            or not _day(trading_day)):
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    try:
        rows = db.execute(
            "SELECT reservation_id,status,payload_json,native_identity_json FROM direct_journal_commands "
            "WHERE account=? AND status IN ('DISPATCHING','SENT','UNKNOWN') LIMIT ?",
            (account, _MAX_ROWS + 1),
        ).fetchall()
        if len(rows) > _MAX_ROWS:
            return False
        for reservation_id, status, raw_payload, raw_identity in rows:
            payload = _decoded_payload(raw_payload)
            if payload.get("symbol") != binding.instrument.native_symbol:
                continue
            if payload.get("exchange_id") not in (None, binding.instrument.venue):
                continue
            if _native_trading_day(raw_identity) == trading_day:
                continue
            if not _command_settled(db, account, reservation_id, status, _quantity(payload.get("quantity"))):
                return False
        return True
    except DirectCommandJournalError:
        return False
    except (sqlite3.Error, KeyError, TypeError, ValueError, ArithmeticError):
        return False


def initialize_replayed_strategy_baseline(
    db: sqlite3.Connection,
    evidence: StrategyBaselineEvidence,
    *,
    resolve_binding: Callable,
    verify_day_transition: Callable[[str, str], bool],
    verify_current_continuity: Callable,
    verify_current_snapshot: Callable[[StrategyBaselineEvidence], bool],
) -> None:
    """Adopt a journal that already has history as the ledger's origin (I63-E111).

    For an account that traded through this journal before its ledger had a
    baseline. Nothing is assigned from the snapshot: the baseline is accepted
    only when the journal's own strongly attributed trades, replayed from
    ``history_start_trading_day`` as if the account had started flat, yield
    exactly the provider's complete position snapshot, every command is
    settled, no fact is unattributed and no order is open. Any residual
    (external or pre-existing holdings, an unresolved order) refuses the
    baseline instead of being booked to a strategy or to external.

    ``verify_current_snapshot`` is trusted installed owner code: it attests
    that ``evidence.account_positions`` and the empty open-order set are the
    provider's complete facts at one comparable cut that is still current, and
    it keeps that fence through commit. The other ports are the owner's
    installed ledger ports.
    """
    if (not db.in_transaction or type(evidence) is not StrategyBaselineEvidence
            or evidence.schema_version != 2
            or not all(callable(port) for port in (resolve_binding, verify_day_transition,
                                                   verify_current_continuity, verify_current_snapshot))):
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    account = evidence.account_scope
    _verify_strategy_ledger_integrity(db, account)
    encoded, digest = _json(evidence.to_mapping()), evidence.digest
    row = db.execute("SELECT initial_trading_day,evidence_digest,evidence_json FROM strategy_position_baseline WHERE account=?", (account,)).fetchone()
    if row is not None:
        if tuple(row) != (evidence.history_start_trading_day, digest, encoded):
            _error("STRATEGY_BASELINE_CONFLICT")
        return
    try:
        commands = db.execute(
            "SELECT reservation_id,strategy,status,payload_json FROM direct_journal_commands WHERE account=? LIMIT ?",
            (account, _MAX_ROWS + 1),
        ).fetchall()
        facts = db.execute(
            "SELECT fact_json,disposition,applied,reservation_id FROM direct_execution_facts WHERE account=? LIMIT ?",
            (account, _MAX_ROWS + 1),
        ).fetchall()
        if len(commands) > _MAX_ROWS or len(facts) > _MAX_ROWS:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        if not commands and not facts:
            # A journal without history takes the empty or the external baseline.
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        known = {item[0] for item in commands}
        instruments: dict[str, MarketInstrumentKey] = {}
        for raw, disposition, applied, reservation_id in facts:
            if disposition != "ATTRIBUTED" or reservation_id not in known:
                _error("STRATEGY_BASELINE_HISTORY_UNRESOLVED")
            fact = _decode_fact(raw)
            if applied and fact.kind is DirectExecutionEventKind.TRADE:
                instruments[_json(fact.instrument.to_dict())] = fact.instrument
        for reservation_id, _, status, raw_payload in commands:
            quantity = _quantity(_decoded_payload(raw_payload).get("quantity"))
            if not _command_settled(db, account, reservation_id, status, quantity):
                _error("STRATEGY_BASELINE_HISTORY_UNRESOLVED")
        if verify_current_snapshot(evidence) is not True:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        db.execute("INSERT INTO strategy_position_baseline VALUES (?, ?, ?, ?)",
                   (account, evidence.history_start_trading_day, digest, encoded))
        names = ("long_today", "long_yesterday", "short_today", "short_yesterday")
        observed: dict[str, dict[str, Decimal]] = {}
        for item in evidence.account_positions:
            key = _json(item.instrument.to_dict())
            instruments[key] = item.instrument
            legs = observed.setdefault(key, {name: Decimal(0) for name in names})
            legs[item.direction + "_today"] = _quantity(item.today_quantity, allow_zero=True)
            legs[item.direction + "_yesterday"] = _quantity(item.yesterday_quantity, allow_zero=True)
        strategies = sorted({item[1] for item in commands})
        if any(not _text(strategy) for strategy in strategies):
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        with localcontext() as context:
            context.prec = 160
            for key in sorted(instruments):
                instrument = instruments[key]
                try:
                    binding = resolve_binding({"symbol": instrument.native_symbol, "exchange_id": instrument.venue})
                except Exception as exc:
                    raise DirectCommandJournalError("STRATEGY_BASELINE_MISMATCH") from exc
                if (type(binding) is not StrategyInstrumentBinding or binding.instrument != instrument
                        or binding.route != evidence.route):
                    _error("STRATEGY_BASELINE_MISMATCH")
                replayed = {name: Decimal(0) for name in names}
                for strategy in strategies:
                    position = strategy_position(
                        db, account, strategy, binding, trading_day=evidence.trading_day,
                        resolve_binding=resolve_binding, verify_day_transition=verify_day_transition,
                        verify_current_continuity=verify_current_continuity)
                    for name in names:
                        replayed[name] += getattr(position, name)
                expected = observed.get(key, {name: Decimal(0) for name in names})
                if binding.split_close_required:
                    matches = all(replayed[name] == expected[name] for name in names)
                else:
                    # The venue chooses the bucket of an ordinary close.
                    matches = all(
                        replayed[side + "_today"] + replayed[side + "_yesterday"]
                        == expected[side + "_today"] + expected[side + "_yesterday"]
                        for side in ("long", "short"))
                if not matches:
                    _error("STRATEGY_BASELINE_MISMATCH")
        if verify_current_snapshot(evidence) is not True:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        _verify_strategy_ledger_integrity(db, account)
    except DirectCommandJournalError:
        raise
    except Exception as exc:
        raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc


@dataclass(frozen=True, slots=True)
class StrategyInstrumentBinding:
    """Installed owner-resolved instrument/unit policy, not a provider receipt."""

    instrument: MarketInstrumentKey
    route: str
    quantity_unit: str
    split_close_required: bool

    def __post_init__(self):
        if (type(self.instrument) is not MarketInstrumentKey or not _text(self.route)
                or self.quantity_unit not in {"base", "contracts", "lots", "native"}
                or type(self.split_close_required) is not bool):
            _error("STRATEGY_LEDGER_UNAVAILABLE")


@dataclass(frozen=True, slots=True)
class StrategyPosition:
    trading_day: str
    long_today: Decimal
    long_yesterday: Decimal
    short_today: Decimal
    short_yesterday: Decimal
    projected_buckets: bool = False

    @property
    def net(self) -> Decimal:
        with localcontext() as context:
            context.prec = 160
            return self.long_today + self.long_yesterday - self.short_today - self.short_yesterday


def _same_binding(value: object, binding: StrategyInstrumentBinding) -> bool:
    return type(value) is StrategyInstrumentBinding and value == binding


def _resolve(payload: dict, binding: StrategyInstrumentBinding, resolve_binding: Callable) -> bool:
    try:
        resolved = resolve_binding(payload)
    except Exception as exc:
        raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc
    if type(resolved) is not StrategyInstrumentBinding:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    if payload.get("symbol") != resolved.instrument.native_symbol:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    if payload.get("exchange_id") not in (None, resolved.instrument.venue):
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    if payload.get("quantity_unit") != resolved.quantity_unit:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    return _same_binding(resolved, binding)


def _advance(old_day: str, new_day: str, legs: dict, verify_day_transition: Callable) -> str:
    if new_day == old_day:
        return old_day
    if not _day(new_day) or new_day < old_day:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    try:
        if verify_day_transition(old_day, new_day) is not True:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
    except DirectCommandJournalError:
        raise
    except Exception as exc:
        raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc
    for direction in ("long", "short"):
        legs[direction + "_yesterday"] += legs[direction + "_today"]
        legs[direction + "_today"] = Decimal(0)
    return new_day


def _transition(legs: dict, direction: str, offset: str, quantity: Decimal, *, split: bool) -> bool:
    today, yesterday = direction + "_today", direction + "_yesterday"
    if offset == "open":
        legs[today] += quantity
        return False
    if offset == "close_today":
        name = today
    elif offset == "close_yesterday":
        name = yesterday
    elif offset == "close" and not split:
        # Projection only: venue allocation may differ for ordinary close.
        if quantity > legs[today] + legs[yesterday]:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        removed = min(quantity, legs[yesterday])
        legs[yesterday] -= removed
        legs[today] -= quantity - removed
        return True
    else:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    if quantity > legs[name]:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    legs[name] -= quantity
    return False


def _direction(side: object, offset: object) -> str:
    if side not in ("buy", "sell") or offset not in ("open", "close", "close_today", "close_yesterday"):
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    return "long" if (side == "buy") == (offset == "open") else "short"


def _decode_fact(raw: str) -> GatewayReturnFact:
    try:
        return GatewayReturnFact.from_mapping(json.loads(raw))
    except Exception as exc:
        raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc


def _decoded_payload(raw: str) -> dict:
    try:
        result = json.loads(raw)
    except Exception as exc:
        raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc
    if type(result) is not dict:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    return result


def strategy_position(
    db: sqlite3.Connection,
    account: str,
    strategy: str,
    binding: StrategyInstrumentBinding,
    *,
    trading_day: str,
    resolve_binding: Callable,
    verify_day_transition: Callable[[str, str], bool],
    verify_current_continuity: Callable,
    verify_external_current: Callable | None = None,
) -> StrategyPosition:
    """Replay only strongly attributed, already quantity-applied real trades.

    The caller must hold the journal account owner fence and one SQLite
    transaction; both resolver and day proof are trusted local owner ports.
    Normal-close bucket allocations are explicitly marked as projections.
    """
    if (not db.in_transaction or not _text(account) or not _text(strategy)
            or type(binding) is not StrategyInstrumentBinding or not _day(trading_day)
            or not callable(resolve_binding) or not callable(verify_day_transition)
            or not callable(verify_current_continuity)):
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    try:
        _verify_strategy_ledger_integrity(db, account)
        row = db.execute("SELECT initial_trading_day, evidence_json FROM strategy_position_baseline WHERE account=?", (account,)).fetchone()
        if row is None or not _day(row[0]):
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        baseline = StrategyBaselineEvidence.from_mapping(json.loads(row[1]))
        if (baseline.route != binding.route
                or verify_current_continuity(db, account, binding, trading_day, baseline) is not True):
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        current = row[0]
        # A conflict or unattributed fact on this instrument may be a delayed
        # strategy trade; never invent ownership or treat it as external.
        columns = "fact_json,fact_digest,disposition" if callable(verify_external_current) else "fact_json"
        unresolved = db.execute(
            "SELECT " + columns + " FROM direct_execution_facts WHERE account=? AND disposition IN ('UNATTRIBUTED','CONFLICT') LIMIT ?",
            (account, _MAX_ROWS + 1),
        ).fetchall()
        if len(unresolved) > _MAX_ROWS:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        verified_external = []
        for item in unresolved:
            fact = _decode_fact(item[0])
            if fact.instrument == binding.instrument and fact.kind is DirectExecutionEventKind.TRADE:
                if callable(verify_external_current) and item[2] == "UNATTRIBUTED":
                    from .external_position_ledger import external_fact_verified
                    if external_fact_verified(db, account, item[1], verify_current=verify_external_current):
                        verified_external.append(item[1])
                        continue
                _error("STRATEGY_LEDGER_UNAVAILABLE")
        if db.execute(
            "SELECT 1 FROM direct_execution_facts f LEFT JOIN direct_journal_commands c "
            "ON c.account=f.account AND c.reservation_id=f.reservation_id "
            "WHERE f.account=? AND f.applied=1 AND c.reservation_id IS NULL LIMIT 1", (account,),
        ).fetchone() is not None:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        rows = db.execute(
            "SELECT f.fact_json, c.payload_json, f.reason FROM direct_execution_facts f "
            "JOIN direct_journal_commands c ON c.account=f.account AND c.reservation_id=f.reservation_id "
            "WHERE f.account=? AND c.strategy=? AND f.disposition='ATTRIBUTED' AND f.applied=1 "
            "ORDER BY f.event_sequence LIMIT ?", (account, strategy, _MAX_ROWS + 1),
        ).fetchall()
        if len(rows) > _MAX_ROWS:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        legs = {name: Decimal(0) for name in ("long_today", "long_yesterday", "short_today", "short_yesterday")}
        estimated = False
        with localcontext() as context:
            context.prec = 160
            for raw_fact, raw_payload, reason in rows:
                fact = _decode_fact(raw_fact)
                if fact.instrument != binding.instrument:
                    continue
                if reason != "MATCHED":
                    _error("STRATEGY_LEDGER_UNAVAILABLE")
                payload = _decoded_payload(raw_payload)
                if (fact.account_scope != account or fact.route != binding.route
                        or fact.kind is not DirectExecutionEventKind.TRADE
                        or not _resolve(payload, binding, resolve_binding)
                        or fact.side != payload.get("side") or fact.offset != payload.get("offset")):
                    _error("STRATEGY_LEDGER_UNAVAILABLE")
                current = _advance(current, fact.trading_day, legs, verify_day_transition)
                direction = _direction(fact.side, fact.offset)
                if payload.get("position_side") not in (None, direction):
                    _error("STRATEGY_LEDGER_UNAVAILABLE")
                estimated |= _transition(legs, direction, fact.offset,
                                         _quantity(fact.trade_quantity), split=binding.split_close_required)
            current = _advance(current, trading_day, legs, verify_day_transition)
            if verify_current_continuity(db, account, binding, trading_day, baseline) is not True:
                _error("STRATEGY_LEDGER_UNAVAILABLE")
            for digest in verified_external:
                if not external_fact_verified(db, account, digest, verify_current=verify_external_current):
                    _error("STRATEGY_LEDGER_UNAVAILABLE")
            return StrategyPosition(current, projected_buckets=estimated, **legs)
    except DirectCommandJournalError:
        raise
    except Exception as exc:
        raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc


def _remaining_close(db: sqlite3.Connection, account: str, reservation_id: str,
                     status: str, quantity: Decimal) -> Decimal:
    row = db.execute(
        "SELECT total_quantity FROM direct_execution_totals WHERE account=? AND reservation_id=?",
        (account, reservation_id),
    ).fetchone()
    filled = Decimal(0) if row is None else _quantity(row[0], allow_zero=True)
    if filled > quantity:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    if status in {"RELEASED", "EXPIRED", "NOT_SENT"}:
        if filled:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        # A contradictory venue order/trade observation prevents a local
        # terminal command state from releasing the reservation.
        observed = db.execute(
            "SELECT fact_json FROM direct_execution_facts WHERE account=? AND reservation_id=? LIMIT ?",
            (account, reservation_id, _MAX_ROWS + 1),
        ).fetchall()
        if len(observed) > _MAX_ROWS or any(
            _decode_fact(raw).kind in (DirectExecutionEventKind.ORDER, DirectExecutionEventKind.TRADE)
            for raw, in observed
        ):
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        return Decimal(0)
    if status not in {"RESERVED", "DISPATCHING", "SENT", "UNKNOWN"}:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    events = db.execute(
        "SELECT fact_json FROM direct_execution_facts WHERE account=? AND reservation_id=? "
        "AND disposition='ATTRIBUTED' AND event_sequence IS NOT NULL ORDER BY event_sequence DESC LIMIT ?",
        (account, reservation_id, _MAX_ROWS + 1),
    ).fetchall()
    if len(events) > _MAX_ROWS:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    for raw, in events:
        fact = _decode_fact(raw)
        if fact.kind is not DirectExecutionEventKind.ORDER:
            continue
        if (fact.status in {DirectOrderStatus.CANCELLED, DirectOrderStatus.FILLED, DirectOrderStatus.REJECTED}
                and fact.filled_quantity is not None
                and _quantity(fact.filled_quantity, allow_zero=True) == filled
                and (fact.status is not DirectOrderStatus.FILLED or filled == quantity)
                and (fact.status is not DirectOrderStatus.REJECTED or filled == 0)):
            return Decimal(0)
        # The newest ORDER supersedes older terminal observations.
        break
    return quantity - filled


@dataclass(frozen=True, slots=True)
class StrategyCloseCapacity:
    position: StrategyPosition
    available: Decimal
    reserved: Decimal


def strategy_close_capacity(
    db: sqlite3.Connection,
    account: str,
    strategy: str,
    payload: dict,
    *,
    trading_day: str,
    instrument_binding: StrategyInstrumentBinding,
    resolve_binding: Callable,
    verify_day_transition: Callable[[str, str], bool],
    verify_current_continuity: Callable,
    verify_external_current: Callable | None = None,
    exclude_reservation_id: str | None = None,
) -> StrategyPosition:
    """Check own strategy's close capacity inside the reservation transaction.

    The owner must perform the following reservation INSERT in the same SQLite
    write transaction. On dispatch recheck, pass the already existing own
    reservation id to avoid double-counting it. ``resolve_binding`` and
    ``verify_day_transition`` must be trusted owner ports; neither is a client
    input. All unresolved or unproved quantities remain occupied.

    This is ownership capacity, not Risk's account-level available-position or
    margin policy. A successful return does not authorize provider dispatch.
    """
    if (not db.in_transaction or not _text(account) or not _text(strategy)
            or type(payload) is not dict or type(instrument_binding) is not StrategyInstrumentBinding
            or not callable(resolve_binding) or not callable(verify_day_transition)
            or (exclude_reservation_id is not None and not _text(exclude_reservation_id))):
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    try:
        offset, side = payload.get("offset"), payload.get("side")
        if offset not in {"close", "close_today", "close_yesterday"}:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        if instrument_binding.split_close_required and offset == "close":
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        if not _resolve(payload, instrument_binding, resolve_binding):
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        direction = _direction(side, offset)
        if payload.get("position_side") not in (None, direction):
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        _quantity(payload.get("quantity"))
        if exclude_reservation_id is not None:
            own = db.execute(
                "SELECT payload_json FROM direct_journal_commands WHERE account=? AND strategy=? AND reservation_id=?",
                (account, strategy, exclude_reservation_id),
            ).fetchone()
            if own is None or _decoded_payload(own[0]) != payload:
                _error("STRATEGY_LEDGER_UNAVAILABLE")
        position = strategy_position(
            db, account, strategy, instrument_binding, trading_day=trading_day,
            resolve_binding=resolve_binding, verify_day_transition=verify_day_transition,
            verify_current_continuity=verify_current_continuity,
            verify_external_current=verify_external_current,
        )
        if position.projected_buckets and offset in {"close_today", "close_yesterday"}:
            # An ordinary venue-selected close cannot establish which of the
            # projected buckets is actually left for an explicit bucket close.
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        pending = {"close": Decimal(0), "close_today": Decimal(0), "close_yesterday": Decimal(0)}
        rows = db.execute(
            "SELECT reservation_id, status, payload_json FROM direct_journal_commands "
            "WHERE account=? AND strategy=? LIMIT ?", (account, strategy, _MAX_ROWS + 1),
        ).fetchall()
        if len(rows) > _MAX_ROWS:
            _error("STRATEGY_LEDGER_UNAVAILABLE")
        with localcontext() as context:
            context.prec = 160
            for reservation_id, status, raw_payload in rows:
                if reservation_id == exclude_reservation_id:
                    continue
                prior = _decoded_payload(raw_payload)
                prior_offset = prior.get("offset")
                if prior.get("symbol") != instrument_binding.instrument.native_symbol:
                    continue
                if prior_offset == "open":
                    continue
                if prior_offset not in pending:
                    _error("STRATEGY_LEDGER_UNAVAILABLE")
                if not _resolve(prior, instrument_binding, resolve_binding):
                    continue
                if _direction(prior.get("side"), prior_offset) != direction:
                    continue
                if prior.get("position_side") not in (None, direction):
                    _error("STRATEGY_LEDGER_UNAVAILABLE")
                if instrument_binding.split_close_required and prior_offset == "close":
                    _error("STRATEGY_LEDGER_UNAVAILABLE")
                pending[prior_offset] += _remaining_close(
                    db, account, reservation_id, status, _quantity(prior.get("quantity"))
                )
            today = getattr(position, direction + "_today")
            yesterday = getattr(position, direction + "_yesterday")
            if offset == "close_today":
                available = today - pending["close_today"] - pending["close"]
            elif offset == "close_yesterday":
                available = yesterday - pending["close_yesterday"] - pending["close"]
            else:
                available = today + yesterday - sum(pending.values(), Decimal(0))
            if available < 0:
                _error("STRATEGY_LEDGER_UNAVAILABLE")
            reserved = sum(pending.values(), Decimal(0))
        return StrategyCloseCapacity(position, available, reserved)
    except DirectCommandJournalError:
        raise
    except (sqlite3.Error, KeyError, TypeError, ValueError, ArithmeticError) as exc:
        raise DirectCommandJournalError("STRATEGY_LEDGER_UNAVAILABLE") from exc


def check_strategy_close(
    db: sqlite3.Connection,
    account: str,
    strategy: str,
    payload: dict,
    *,
    trading_day: str,
    instrument_binding: StrategyInstrumentBinding,
    resolve_binding: Callable,
    verify_day_transition: Callable[[str, str], bool],
    verify_current_continuity: Callable,
    verify_external_current: Callable | None = None,
    exclude_reservation_id: str | None = None,
) -> StrategyPosition:
    capacity = strategy_close_capacity(
        db, account, strategy, payload, trading_day=trading_day,
        instrument_binding=instrument_binding, resolve_binding=resolve_binding,
        verify_day_transition=verify_day_transition, verify_current_continuity=verify_current_continuity,
        verify_external_current=verify_external_current,
        exclude_reservation_id=exclude_reservation_id,
    )
    if capacity.available < _quantity(payload.get("quantity")):
        _error("STRATEGY_CLOSE_EXCEEDS")
    return capacity.position


def _signed_quantity(value: object) -> Decimal:
    if type(value) is not str:
        _error("STRATEGY_LEDGER_UNAVAILABLE")
    if value.startswith("-"):
        return -_quantity(value[1:], allow_zero=True)
    return _quantity(value, allow_zero=True)


@dataclass(frozen=True, slots=True)
class StrategyNetComparison:
    """An owner-attested comparison, not a claim of complete gross positions."""

    status: str
    strategy_net: Decimal | None
    external_net: Decimal | None
    account_net: Decimal | None
    difference: Decimal | None
    cut: str | None


def compare_account_net(
    db: sqlite3.Connection,
    account: str,
    binding: StrategyInstrumentBinding,
    *,
    trading_day: str,
    account_net: str | None,
    external_net: str | None,
    cut: str,
    resolve_binding: Callable,
    verify_day_transition: Callable[[str, str], bool],
    verify_current_continuity: Callable,
    verify_account_cut: Callable[[sqlite3.Connection, str, StrategyInstrumentBinding, str, str, str], bool],
    verify_external_cut: Callable[[sqlite3.Connection, str, StrategyInstrumentBinding, str, str, str], bool],
    verify_external_current: Callable | None = None,
) -> StrategyNetComparison:
    """Compare all historical strategy deltas plus verified external net.

    The caller supplies authenticated provider and external-book values through
    separately trusted owner ports. Both proofs must bind the exact same cut,
    account, instrument and day and remain valid through transaction commit.
    A self-reported value, a timestamp match, or an account-minus-strategies
    residual is not a proof. Missing facts are *never* converted to zero.
    """
    unavailable = StrategyNetComparison("UNAVAILABLE", None, None, None, None, None)
    if (not db.in_transaction or not _text(account) or type(binding) is not StrategyInstrumentBinding
            or not _day(trading_day) or not _text(cut) or account_net is None or external_net is None
            or not callable(verify_account_cut) or not callable(verify_external_cut)):
        return unavailable
    try:
        if (verify_account_cut(db, account, binding, trading_day, cut, account_net) is not True
                or verify_external_cut(db, account, binding, trading_day, cut, external_net) is not True):
            return unavailable
        # Verify the ledger baseline and unresolved-fact scope even when no
        # strategy has ever placed an order.
        strategy_position(
            db, account, "__ledger_comparison_probe__", binding, trading_day=trading_day,
            resolve_binding=resolve_binding, verify_day_transition=verify_day_transition,
            verify_current_continuity=verify_current_continuity,
            verify_external_current=verify_external_current,
        )
        observed = _signed_quantity(account_net)
        external = _signed_quantity(external_net)
        rows = db.execute(
            "SELECT DISTINCT strategy FROM direct_journal_commands WHERE account=? LIMIT ?",
            (account, _MAX_ROWS + 1),
        ).fetchall()
        if len(rows) > _MAX_ROWS or any(not _text(row[0]) for row in rows):
            return unavailable
        total = Decimal(0)
        with localcontext() as context:
            context.prec = 160
            for row in rows:
                total += strategy_position(
                    db, account, row[0], binding, trading_day=trading_day,
                    resolve_binding=resolve_binding, verify_day_transition=verify_day_transition,
                    verify_current_continuity=verify_current_continuity,
                    verify_external_current=verify_external_current,
                ).net
            difference = observed - total - external
        if (verify_account_cut(db, account, binding, trading_day, cut, account_net) is not True
                or verify_external_cut(db, account, binding, trading_day, cut, external_net) is not True):
            return unavailable
        return StrategyNetComparison(
            "MATCH" if difference == 0 else "MISMATCH", total, external, observed, difference, cut
        )
    except Exception:
        return unavailable
