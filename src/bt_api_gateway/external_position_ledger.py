"""External account facts, recorded only by the guarded Gateway owner.

The caller owns the account transaction and source fence.  Neither receipt
references nor hashes authenticate a source or prove a coherent account cut.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from decimal import Decimal, localcontext
from typing import Callable

from bt_api_base.direct_write_protocol import DirectExecutionEventKind
from bt_api_base.gateway_execution_protocol import GatewayReturnFact
from bt_api_base.market_protocol import MarketInstrumentKey

from .direct_command_journal import DirectCommandJournalError, _json
from .strategy_position_ledger import _day, _digest, _quantity, _text, _verify_strategy_ledger_integrity

_EXTERNAL_LEDGER_DDL = {
    "external_position_events": "CREATE TABLE external_position_events (account TEXT NOT NULL, fact_digest TEXT NOT NULL, fact_json TEXT NOT NULL, receipt_digest TEXT NOT NULL, receipt_json TEXT NOT NULL, PRIMARY KEY(account, fact_digest))",
    "external_position_trades": "CREATE TABLE external_position_trades (account TEXT NOT NULL, route TEXT NOT NULL, trade_key_json TEXT NOT NULL, content_digest TEXT NOT NULL, fact_digest TEXT NOT NULL, PRIMARY KEY(account, route, trade_key_json))",
}


def _unavailable():
    raise DirectCommandJournalError("EXTERNAL_LEDGER_UNAVAILABLE")


@dataclass(frozen=True, slots=True)
class ExternalFactEvidence:
    account_scope: str
    journal_id: str
    owner_generation: str
    session_generation: int
    route: str
    trading_day: str
    fact_digest: str
    source_ref: str
    cut_ref: str
    exclusion_ref: str
    schema_version: int = 1

    def __post_init__(self):
        if (type(self.schema_version) is not int or self.schema_version != 1
                or any(not _text(x) or not x.isprintable() for x in
                       (self.account_scope, self.journal_id, self.owner_generation, self.route,
                        self.source_ref, self.cut_ref, self.exclusion_ref))
                or type(self.session_generation) is not int or not 0 < self.session_generation < 2**63
                or not _day(self.trading_day) or not _digest(self.fact_digest)):
            _unavailable()

    def to_mapping(self):
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_mapping(cls, value):
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            _unavailable()
        return cls(**value)

    @property
    def digest(self):
        return hashlib.sha256(_json(self.to_mapping()).encode("ascii")).hexdigest()


def _fact(raw):
    try:
        value = json.loads(raw)
        fact = GatewayReturnFact.from_mapping(value)
        if _json(fact.to_mapping()) != raw:
            _unavailable()
        return fact
    except Exception as exc:
        raise DirectCommandJournalError("EXTERNAL_LEDGER_UNAVAILABLE") from exc


def _validate_record(db, account, fact_digest, fact_json, receipt_digest, receipt_json):
    fact, evidence = _fact(fact_json), ExternalFactEvidence.from_mapping(json.loads(receipt_json))
    journal = db.execute("SELECT journal_id FROM direct_journal_meta WHERE account=?", (account,)).fetchone()
    if (journal is None or evidence.account_scope != account or evidence.journal_id != journal[0]
            or fact.account_scope != account or fact.fact_digest() != fact_digest
            or evidence.fact_digest != fact_digest or evidence.route != fact.route
            or evidence.trading_day != fact.trading_day or evidence.source_ref != fact.source_ref
            or fact.kind not in (DirectExecutionEventKind.ORDER, DirectExecutionEventKind.TRADE)
            or not fact.identity_keys or fact.venue_key is None
            or (fact.session_generation is not None and fact.session_generation != evidence.session_generation)
            or _json(evidence.to_mapping()) != receipt_json or evidence.digest != receipt_digest):
        _unavailable()
    if fact.kind is DirectExecutionEventKind.TRADE:
        if fact.trade_key is None or fact.side not in ("buy", "sell") or fact.trade_quantity is None or fact.trade_price is None:
            _unavailable()
        _quantity(fact.trade_quantity)
    original = db.execute("SELECT fact_json,disposition,reservation_id,applied FROM direct_execution_facts WHERE account=? AND fact_digest=?", (account, fact_digest)).fetchone()
    if original is None or tuple(original) != (fact_json, "UNATTRIBUTED", None, 0):
        _unavailable()
    for key in fact.identity_keys:
        if db.execute("SELECT 1 FROM direct_journal_strong_keys WHERE account=? AND strong_key=?", (account, key)).fetchone() is not None:
            _unavailable()
    if fact.kind is DirectExecutionEventKind.TRADE:
        native = db.execute("SELECT content_digest,fact_digest,applied,reservation_id,conflict FROM direct_execution_trades WHERE account=? AND route=? AND trade_key_json=?", (account, fact.route, _json(list(fact.trade_key)))).fetchone()
        if (native is None or native[0] != fact.trade_content_digest()
                or tuple(native[2:]) != (0, None, 0)):
            _unavailable()
    return fact, evidence


def verify_external_integrity(db: sqlite3.Connection, account: str):
    """Verify stored canonical values/relations; does not authenticate their origin."""
    try:
        rows = db.execute("SELECT account,fact_digest,fact_json,receipt_digest,receipt_json FROM external_position_events LIMIT 1000001").fetchall()
        if len(rows) > 1_000_000:
            _unavailable()
        expected = {}
        fact_keys = {}
        trade_dates = {}
        for row in rows:
            if row[0] != account:
                _unavailable()
            fact, _ = _validate_record(db, *row)
            if fact.kind is DirectExecutionEventKind.TRADE:
                key = (account, fact.route, _json(list(fact.trade_key)))
                current = (fact.trade_content_digest(), row[1])
                if key in expected and expected[key][0] != current[0]:
                    _unavailable()
                if fact.trade_date is not None:
                    if key in trade_dates and trade_dates[key] != fact.trade_date:
                        _unavailable()
                    trade_dates[key] = fact.trade_date
                expected.setdefault(key, current)
                fact_keys[row[1]] = key
        actual = db.execute("SELECT account,route,trade_key_json,content_digest,fact_digest FROM external_position_trades LIMIT 1000001").fetchall()
        if len(actual) != len(expected):
            _unavailable()
        for row in actual:
            key = tuple(row[:3])
            if key not in expected or expected[key][0] != row[3] or fact_keys.get(row[4]) != key:
                _unavailable()
    except Exception as exc:
        raise DirectCommandJournalError("INVALID_DATABASE") from exc


def external_identity_collision(db: sqlite3.Connection, account: str, identity_keys: tuple[str, ...]) -> bool:
    """Detect a later local binding that would contradict an external fact."""
    if not db.in_transaction or not _text(account) or type(identity_keys) is not tuple:
        _unavailable()
    for key in identity_keys:
        if not _text(key):
            _unavailable()
        if db.execute(
            "SELECT 1 FROM external_position_events e, json_each(e.fact_json, '$.identity_keys') k "
            "WHERE e.account=? AND k.value=? LIMIT 1", (account, key),
        ).fetchone() is not None:
            return True
    return False


def external_fact_verified(db: sqlite3.Connection, account: str, fact_digest: str, *, verify_current: Callable) -> bool:
    """Revalidate a specific persisted fact under the installed authority."""
    if not db.in_transaction or not callable(verify_current) or not _digest(fact_digest):
        _unavailable()
    row = db.execute("SELECT fact_json,receipt_digest,receipt_json FROM external_position_events WHERE account=? AND fact_digest=?", (account, fact_digest)).fetchone()
    if row is None:
        return False
    fact, evidence = _validate_record(db, account, fact_digest, *row)
    if fact.kind is DirectExecutionEventKind.TRADE:
        trade = db.execute("SELECT content_digest,fact_digest FROM external_position_trades WHERE account=? AND route=? AND trade_key_json=?", (account, fact.route, _json(list(fact.trade_key)))).fetchone()
        if trade is None or trade[0] != fact.trade_content_digest():
            _unavailable()
    if verify_current(db, fact, evidence) is not True:
        _unavailable()
    return True


def record_external_fact(db: sqlite3.Connection, account: str, fact_digest: str,
                         evidence: ExternalFactEvidence, *, verify_source_and_exclusion: Callable) -> bool:
    """Append one proven external fact, inside the owner write transaction.

    The installed verifier must authenticate account/source/current session and
    establish a comparable cut after the baseline, exclude *all* unresolved
    system orders including late aliases, and hold its external fence to commit.
    It must be called before and after mutation; caller rechecks the owner guard
    before commit. No RPC or client may supply this verifier.
    """
    if (not db.in_transaction or not _text(account) or not _digest(fact_digest)
            or type(evidence) is not ExternalFactEvidence or not callable(verify_source_and_exclusion)):
        _unavailable()
    row = db.execute("SELECT fact_json FROM direct_execution_facts WHERE account=? AND fact_digest=?", (account, fact_digest)).fetchone()
    if row is None:
        _unavailable()
    encoded = _json(evidence.to_mapping())
    fact, _ = _validate_record(db, account, fact_digest, row[0], evidence.digest, encoded)
    baseline = db.execute("SELECT 1 FROM strategy_position_baseline WHERE account=?", (account,)).fetchone()
    if baseline is None or verify_source_and_exclusion(db, fact, evidence) is not True:
        _unavailable()
    old = db.execute("SELECT fact_json,receipt_digest,receipt_json FROM external_position_events WHERE account=? AND fact_digest=?", (account, fact_digest)).fetchone()
    if old is not None:
        if tuple(old) != (row[0], evidence.digest, encoded):
            raise DirectCommandJournalError("EXTERNAL_FACT_CONFLICT")
        return False
    if fact.kind is DirectExecutionEventKind.TRADE:
        key = _json(list(fact.trade_key))
        existing = db.execute("SELECT content_digest,fact_digest FROM external_position_trades WHERE account=? AND route=? AND trade_key_json=?", (account, fact.route, key)).fetchone()
        if existing is not None and existing[0] != fact.trade_content_digest():
            raise DirectCommandJournalError("EXTERNAL_FACT_CONFLICT")
        if existing is not None and fact.trade_date is not None:
            previous = db.execute(
                "SELECT fact_json FROM external_position_events WHERE account=? LIMIT 1000001", (account,),
            ).fetchall()
            if len(previous) > 1_000_000 or any(
                item.kind is DirectExecutionEventKind.TRADE and item.route == fact.route
                and item.trade_key == fact.trade_key and item.trade_date not in (None, fact.trade_date)
                for item in (_fact(row[0]) for row in previous)
            ):
                raise DirectCommandJournalError("EXTERNAL_FACT_CONFLICT")
        native = db.execute("SELECT content_digest,fact_digest,applied,reservation_id,conflict FROM direct_execution_trades WHERE account=? AND route=? AND trade_key_json=?", (account, fact.route, key)).fetchone()
        if (native is None or native[0] != fact.trade_content_digest()
                or tuple(native[2:]) != (0, None, 0)):
            _unavailable()
        if existing is None:
            db.execute("INSERT INTO external_position_trades VALUES (?,?,?,?,?)", (account, fact.route, key, fact.trade_content_digest(), fact_digest))
    db.execute("INSERT INTO external_position_events VALUES (?,?,?,?,?)", (account, fact_digest, row[0], evidence.digest, encoded))
    if verify_source_and_exclusion(db, fact, evidence) is not True:
        _unavailable()
    return True


def external_net(db: sqlite3.Connection, account: str, instrument: MarketInstrumentKey, *,
                 trading_day: str, cut: str, verify_current: Callable) -> Decimal:
    """Sum baseline and real external fills only at a separately verified cut.

    The installed verifier must authenticate every included baseline and event,
    their order relative to the baseline and current cut, complete account
    coverage, session continuity, and the exclusion of all system orders.
    A cut string or matching local sequence alone is not proof.
    """
    if (not db.in_transaction or type(instrument) is not MarketInstrumentKey or not _day(trading_day)
            or not _text(cut) or not callable(verify_current)):
        _unavailable()
    _verify_strategy_ledger_integrity(db, account)
    verify_external_integrity(db, account)
    baseline = db.execute("SELECT evidence_json FROM strategy_position_baseline WHERE account=?", (account,)).fetchone()
    if baseline is None or verify_current(db, account, instrument, trading_day, cut) is not True:
        _unavailable()
    total = Decimal(0)
    with localcontext() as context:
        context.prec = 160
        rows = db.execute("SELECT direction,today_quantity,yesterday_quantity FROM strategy_external_baseline WHERE account=? AND instrument_json=?", (account, _json(instrument.to_dict()))).fetchall()
        for direction, today, yesterday in rows:
            if direction not in ("long", "short"):
                _unavailable()
            total += (_quantity(today, allow_zero=True) + _quantity(yesterday, allow_zero=True)) * (1 if direction == "long" else -1)
        for raw, in db.execute("SELECT e.fact_json FROM external_position_events e JOIN external_position_trades t ON e.account=t.account AND e.fact_digest=t.fact_digest WHERE e.account=?", (account,)):
            fact = _fact(raw)
            if fact.instrument == instrument:
                total += _quantity(fact.trade_quantity) * (1 if fact.side == "buy" else -1)
    if verify_current(db, account, instrument, trading_day, cut) is not True:
        _unavailable()
    return total
