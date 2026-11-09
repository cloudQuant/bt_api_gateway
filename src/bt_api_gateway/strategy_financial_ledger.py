"""Trusted owner financial snapshots in the existing account journal.

A snapshot is an owner-produced projection, not proof of its inputs.  Both
write and read require installed owner code to verify the current source,
coverage and cut while its fence remains held through the transaction.  This
module provides neither authentication nor provider facts, price feeds, fee
reconstruction, capital admission, or a second SQLite connection.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal, localcontext

from .direct_command_journal import DirectCommandJournalError, _json

_STRATEGY_FINANCIAL_DDL = {
    "strategy_financial_snapshots": "CREATE TABLE strategy_financial_snapshots (account TEXT NOT NULL, strategy TEXT NOT NULL, currency TEXT NOT NULL, revision INTEGER NOT NULL, snapshot_digest TEXT NOT NULL, snapshot_json TEXT NOT NULL, PRIMARY KEY(account, strategy, currency, revision))",
}
_MAX_ROWS = 1_000_000
_AMOUNT = re.compile(r"-?(?:0|[1-9][0-9]{0,41})(?:\.[0-9]{1,42})?\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REFERENCES = frozenset(
    {
        "budget",
        "adjustments",
        "realized_pnl",
        "unrealized_pnl",
        "fees",
        "margin",
        "reservations",
        "coverage",
    }
)


def _unavailable() -> None:
    raise DirectCommandJournalError("STRATEGY_FINANCIAL_UNAVAILABLE")


def _text(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 512
        and value == value.strip()
        and value.isprintable()
    )


def _amount(value: object, *, nonnegative: bool = False) -> Decimal:
    if type(value) is not str or _AMOUNT.fullmatch(value) is None:
        _unavailable()
    result = Decimal(value)
    if nonnegative and result < 0:
        _unavailable()
    return result


def _create_strategy_financial_tables(db: sqlite3.Connection) -> None:
    for statement in _STRATEGY_FINANCIAL_DDL.values():
        db.execute(statement)


@dataclass(frozen=True, slots=True)
class StrategyFinancialSnapshot:
    """Immutable complete projection for one strategy, currency and common cut.

    ``source_refs`` covers each input and the no-double-count/continuity cut;
    references only name evidence. The installed owner's verifier must confirm
    completeness, identity, freshness, valuation terms, fee revisions and
    reservation coverage against that evidence before publication or reading.
    An unsupported asset/margin model must not be published as futures.
    """

    account: str
    journal_id: str
    strategy: str
    currency: str
    revision: int
    previous_digest: str | None
    cut_ref: str
    owner_generation: str
    source_refs: tuple[tuple[str, str], ...]
    initial_budget: str
    adjustments: str
    realized_pnl: str
    unrealized_pnl: str
    fees: str
    margin: str
    reservations: str
    model: str = "futures_linear_v1"
    schema_version: int = 1

    def __post_init__(self) -> None:
        if (
            any(
                not _text(value)
                for value in (
                    self.account,
                    self.journal_id,
                    self.strategy,
                    self.currency,
                    self.cut_ref,
                    self.owner_generation,
                )
            )
            or type(self.revision) is not int
            or not 0 < self.revision < 2**63
            or type(self.schema_version) is not int
            or self.schema_version != 1
            or self.model != "futures_linear_v1"
            or (self.revision == 1 and self.previous_digest is not None)
            or (
                self.revision > 1
                and (
                    type(self.previous_digest) is not str
                    or _DIGEST.fullmatch(self.previous_digest) is None
                )
            )
            or type(self.source_refs) is not tuple
            or any(
                type(pair) is not tuple
                or len(pair) != 2
                or not _text(pair[0])
                or not _text(pair[1])
                for pair in self.source_refs
            )
            or tuple(sorted(self.source_refs)) != self.source_refs
            or len(self.source_refs) != len(_REFERENCES)
            or {pair[0] for pair in self.source_refs} != _REFERENCES
        ):
            _unavailable()
        for name in ("initial_budget", "fees", "margin", "reservations"):
            _amount(getattr(self, name), nonnegative=True)
        for name in ("adjustments", "realized_pnl", "unrealized_pnl"):
            _amount(getattr(self, name))
        # Decimal's global context must never silently round a 42+42 digit input.
        with localcontext() as context:
            context.prec = 128
            _ = self.value, self.cash

    @property
    def value(self) -> Decimal:
        with localcontext() as context:
            context.prec = 128
            return (
                Decimal(self.initial_budget)
                + Decimal(self.adjustments)
                + Decimal(self.realized_pnl)
                + Decimal(self.unrealized_pnl)
                - Decimal(self.fees)
            )

    @property
    def cash(self) -> Decimal:
        with localcontext() as context:
            context.prec = 128
            return self.value - Decimal(self.margin) - Decimal(self.reservations)

    def to_mapping(self) -> dict:
        result = {name: getattr(self, name) for name in self.__dataclass_fields__}
        result["source_refs"] = [list(pair) for pair in self.source_refs]
        return result

    @classmethod
    def from_mapping(cls, raw: object) -> StrategyFinancialSnapshot:
        if (
            type(raw) is not dict
            or set(raw) != set(cls.__dataclass_fields__)
            or type(raw["source_refs"]) is not list
            or any(type(pair) is not list or len(pair) != 2 for pair in raw["source_refs"])
        ):
            _unavailable()
        data = dict(raw)
        data["source_refs"] = tuple(tuple(pair) for pair in data["source_refs"])
        return cls(**data)

    @property
    def digest(self) -> str:
        return hashlib.sha256(_json(self.to_mapping()).encode("ascii")).hexdigest()


def _stored(row: tuple, account: str, journal_id: str) -> StrategyFinancialSnapshot:
    try:
        raw = json.loads(row[5])
        snapshot = StrategyFinancialSnapshot.from_mapping(raw)
        if (
            snapshot.account != account
            or snapshot.journal_id != journal_id
            or tuple(row[:4]) != (account, snapshot.strategy, snapshot.currency, snapshot.revision)
            or row[4] != snapshot.digest
            or row[5] != _json(snapshot.to_mapping())
        ):
            _unavailable()
        return snapshot
    except (ValueError, TypeError, KeyError) as exc:
        raise DirectCommandJournalError("STRATEGY_FINANCIAL_UNAVAILABLE") from exc


def _journal_id(db: sqlite3.Connection, account: str) -> str:
    if not _text(account):
        _unavailable()
    rows = db.execute(
        "SELECT journal_id FROM direct_journal_meta WHERE account=?", (account,)
    ).fetchall()
    if len(rows) != 1 or not _text(rows[0][0]):
        _unavailable()
    return rows[0][0]


def verify_strategy_financial_integrity(db: sqlite3.Connection, account: str) -> None:
    """Check canonical content, account and complete per-scope revision chains."""
    try:
        journal_id = _journal_id(db, account)
        rows = db.execute(
            "SELECT account,strategy,currency,revision,snapshot_digest,snapshot_json "
            "FROM strategy_financial_snapshots ORDER BY account,strategy,currency,revision "
            "LIMIT ?",
            (_MAX_ROWS + 1,),
        ).fetchall()
        if len(rows) > _MAX_ROWS:
            _unavailable()
        previous = {}
        for row in rows:
            snapshot = _stored(row, account, journal_id)
            key = (snapshot.strategy, snapshot.currency)
            last = previous.get(key)
            if last is None:
                if snapshot.revision != 1:
                    _unavailable()
            elif (
                snapshot.revision != last.revision + 1
                or snapshot.previous_digest != last.digest
                or snapshot.initial_budget != last.initial_budget
            ):
                _unavailable()
            previous[key] = snapshot
    except (sqlite3.Error, DirectCommandJournalError, TypeError, ValueError) as exc:
        raise DirectCommandJournalError("INVALID_DATABASE") from exc


def append_financial_snapshot(
    db: sqlite3.Connection, snapshot: StrategyFinancialSnapshot, *, verify_current: Callable
) -> bool:
    """Append only under the journal's write transaction and trusted source fence.

    The verifier is installed owner code, not a remote caller-provided claim. It
    checks the exact account, strategy, sources, common cut, no duplicate fee or
    reservation coverage and known current owner generation. The caller must hold
    that fence until commit; stale/missing facts must make the verifier fail.
    """
    if (
        not db.in_transaction
        or type(snapshot) is not StrategyFinancialSnapshot
        or not callable(verify_current)
    ):
        _unavailable()
    if snapshot.journal_id != _journal_id(db, snapshot.account):
        _unavailable()
    row = db.execute(
        "SELECT account,strategy,currency,revision,snapshot_digest,snapshot_json "
        "FROM strategy_financial_snapshots WHERE account=? AND strategy=? AND currency=? "
        "ORDER BY revision DESC LIMIT 1",
        (snapshot.account, snapshot.strategy, snapshot.currency),
    ).fetchone()
    last = None if row is None else _stored(row, snapshot.account, snapshot.journal_id)
    if last is not None and snapshot.revision == last.revision:
        if snapshot.digest != last.digest:
            _unavailable()
        if verify_current(db, snapshot) is not True:
            _unavailable()
        return False
    if (last is None and snapshot.revision != 1) or (
        last is not None
        and (
            snapshot.revision != last.revision + 1
            or snapshot.previous_digest != last.digest
            or snapshot.initial_budget != last.initial_budget
        )
    ):
        _unavailable()
    if db.execute("SELECT COUNT(*) FROM strategy_financial_snapshots").fetchone()[0] >= _MAX_ROWS:
        _unavailable()
    if verify_current(db, snapshot) is not True:
        _unavailable()
    db.execute(
        "INSERT INTO strategy_financial_snapshots VALUES (?,?,?,?,?,?)",
        (
            snapshot.account,
            snapshot.strategy,
            snapshot.currency,
            snapshot.revision,
            snapshot.digest,
            _json(snapshot.to_mapping()),
        ),
    )
    return True


def read_financial_snapshot(
    db: sqlite3.Connection, account: str, strategy: str, currency: str, *, verify_current: Callable
) -> StrategyFinancialSnapshot:
    """Return only the exact scoped latest snapshot if its current cut is valid.

    Authentication and strategy READ authorization must be checked by the
    enclosing service; caller-supplied account/strategy labels are not proof.
    """
    if (
        not db.in_transaction
        or not _text(strategy)
        or not _text(currency)
        or not callable(verify_current)
    ):
        _unavailable()
    journal_id = _journal_id(db, account)
    row = db.execute(
        "SELECT account,strategy,currency,revision,snapshot_digest,snapshot_json "
        "FROM strategy_financial_snapshots WHERE account=? AND strategy=? AND currency=? "
        "ORDER BY revision DESC LIMIT 1",
        (account, strategy, currency),
    ).fetchone()
    if row is None:
        _unavailable()
    snapshot = _stored(row, account, journal_id)
    if verify_current(db, snapshot) is not True:
        _unavailable()
    return snapshot
