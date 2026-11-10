"""Replayed strategy-ledger baseline (I63-E111); synthetic, no provider or account."""
import json
import sqlite3
from contextlib import contextmanager

import pytest
from bt_api_base.direct_write_protocol import (
    DirectExecutionEventKind,
    DirectOrderStatus,
    NativeOrderIdentity,
)
from bt_api_base.gateway_execution_protocol import GatewayReturnFact
from bt_api_base.market_protocol import MarketInstrumentKey

from bt_api_gateway.direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
)
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from bt_api_gateway.session_guard import LocalAccountSessionGuard
from bt_api_gateway.strategy_position_ledger import (
    ExternalBaselinePosition,
    StrategyBaselineEvidence,
    StrategyInstrumentBinding,
    _create_strategy_ledger_tables,
    _verify_strategy_ledger_integrity,
    initialize_empty_strategy_baseline,
    initialize_external_strategy_baseline,
    initialize_replayed_strategy_baseline,
    prior_day_commands_settled,
    strategy_position,
)

RB = MarketInstrumentKey("ctp", "SHFE", "simnow", "future", "rb2601", "rb2601")
SA = MarketInstrumentKey("ctp", "CZCE", "simnow", "future", "SA601", "SA601")
BINDINGS = {"rb2601": StrategyInstrumentBinding(RB, "CTP", "contracts", True),
            "SA601": StrategyInstrumentBinding(SA, "CTP", "contracts", False)}
D0, D1 = "20300101", "20300102"


def resolve(spec):
    return BINDINGS[spec["symbol"]]


def transition(old, new):
    return old < new <= D1


PORTS = dict(resolve_binding=resolve, verify_day_transition=transition,
             verify_current_continuity=lambda *_: True)


@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.executescript("""
        CREATE TABLE direct_journal_meta (account TEXT, journal_id TEXT);
        INSERT INTO direct_journal_meta VALUES ('acct', 'journal');
        CREATE TABLE direct_journal_commands (account TEXT, strategy TEXT, reservation_id TEXT,
            status TEXT, payload_json TEXT, native_identity_json TEXT);
        CREATE TABLE direct_execution_facts (account TEXT, fact_json TEXT, reservation_id TEXT,
            disposition TEXT, applied INTEGER, event_sequence INTEGER, reason TEXT);
        CREATE TABLE direct_execution_totals (account TEXT, reservation_id TEXT, total_quantity TEXT);
    """)
    conn.execute("BEGIN IMMEDIATE")
    _create_strategy_ledger_tables(conn)
    yield conn
    conn.close()


def spec(side="buy", offset="open", quantity="1", symbol="rb2601"):
    return {"symbol": symbol, "side": side, "offset": offset, "quantity": quantity,
            "quantity_unit": "contracts", "exchange_id": BINDINGS[symbol].instrument.venue}


def command(conn, key, order, *, strategy="s1", status="SENT", day=D0):
    native = None if day is None else json.dumps(
        {"exchange_name": "CTP", "fields_json": json.dumps({"trading_day": day})})
    conn.execute("INSERT INTO direct_journal_commands VALUES (?, ?, ?, ?, ?, ?)",
                 ("acct", strategy, key, status, json.dumps(order), native))


SEQUENCE = iter(range(1, 10_000))


def fact(conn, key, order, *, kind=DirectExecutionEventKind.TRADE, status=None, filled=None, quantity=None,
         day=D0, disposition="ATTRIBUTED"):
    instrument = BINDINGS[order["symbol"]].instrument
    trade = kind is DirectExecutionEventKind.TRADE
    sequence = next(SEQUENCE)
    record = GatewayReturnFact(
        "acct", "CTP", instrument, day, kind, "source", identity=NativeOrderIdentity("CTP", "ref", {}, 1),
        identity_keys=("identity", "venue"), binding_keys=("identity",), venue_key="venue",
        trade_key=("X", "trade-" + str(sequence)) if trade else None, status=status,
        side=order["side"], offset=order["offset"],
        trade_quantity=(quantity or order["quantity"]) if trade else None,
        trade_price="10" if trade else None, filled_quantity=filled)
    conn.execute("INSERT INTO direct_execution_facts VALUES (?, ?, ?, ?, ?, ?, ?)",
                 ("acct", json.dumps(record.to_mapping()), key, disposition,
                  int(trade and disposition == "ATTRIBUTED"), sequence, "MATCHED"))


def filled_order(conn, key, order, *, strategy="s1", day=D0):
    command(conn, key, order, strategy=strategy, day=day)
    fact(conn, key, order, day=day)
    fact(conn, key, order, kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.FILLED,
         filled=order["quantity"], day=day)
    conn.execute("INSERT INTO direct_execution_totals VALUES ('acct', ?, ?)", (key, order["quantity"]))


def cancelled_order(conn, key, order, *, strategy="s1", day=D0):
    command(conn, key, order, strategy=strategy, day=day)
    fact(conn, key, order, kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.CANCELLED,
         filled="0", day=day)


def position(instrument, direction, today, yesterday):
    return ExternalBaselinePosition(instrument, direction, today, yesterday)


def evidence(*positions, day=D1, start=D0, generation="generation"):
    return StrategyBaselineEvidence(
        "acct", "journal", day, "CTP", generation, 1, "source", "position-snapshot", "orders-snapshot",
        "cut", ("open_orders", "positions"), 100, 200, True, True, not positions, True,
        schema_version=2, history_start_trading_day=start, account_positions=tuple(positions))


def replay(conn, item, verify=lambda _: True):
    initialize_replayed_strategy_baseline(conn, item, verify_current_snapshot=verify, **PORTS)


def test_history_that_reproduces_the_account_becomes_the_ledger_origin(db):
    filled_order(db, "open-b", spec(), strategy="b")
    cancelled_order(db, "cancel-a", spec(), strategy="a")
    command(db, "released", spec(), strategy="a", status="RELEASED", day=None)
    command(db, "reserved", spec(), strategy="c", status="RESERVED", day=None)
    item = evidence(position(RB, "long", "0", "1"))
    replay(db, item)
    row = db.execute("SELECT initial_trading_day, evidence_digest FROM strategy_position_baseline").fetchone()
    assert tuple(row) == (D0, item.digest)
    _verify_strategy_ledger_integrity(db, "acct")
    owned = strategy_position(db, "acct", "b", BINDINGS["rb2601"], trading_day=D1, **PORTS)
    assert (owned.long_today, owned.long_yesterday) == (0, 1)
    assert strategy_position(db, "acct", "a", BINDINGS["rb2601"], trading_day=D1, **PORTS).net == 0
    # The same evidence is idempotent; any other evidence conflicts.
    replay(db, item)
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_BASELINE_CONFLICT"):
        replay(db, evidence(position(RB, "long", "0", "1"), generation="other"))


def test_flat_history_takes_an_empty_account(db):
    filled_order(db, "open", spec())
    filled_order(db, "close", spec("sell", "close_today"))
    replay(db, evidence(day=D0))
    assert strategy_position(db, "acct", "s1", BINDINGS["rb2601"], trading_day=D0, **PORTS).net == 0


@pytest.mark.parametrize("positions", [
    (),                                             # the journal's lot is missing from the account
    (position(RB, "long", "0", "2"),),              # one more lot than the journal explains
    (position(RB, "long", "1", "0"),),              # right total, wrong SHFE bucket
    (position(RB, "long", "0", "1"), position(RB, "short", "0", "1")),
    (position(RB, "long", "0", "1"), position(SA, "long", "0", "1")),   # holding without history
])
def test_any_residual_refuses_the_baseline(db, positions):
    filled_order(db, "open", spec())
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_BASELINE_MISMATCH"):
        replay(db, evidence(*positions))


def test_position_on_an_unresolvable_instrument_is_a_mismatch(db):
    filled_order(db, "open", spec())
    other = MarketInstrumentKey("ctp", "DCE", "simnow", "future", "m2601", "m2601")
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_BASELINE_MISMATCH"):
        replay(db, evidence(position(RB, "long", "0", "1"), position(other, "long", "0", "1")))


def test_ordinary_close_venue_compares_totals_not_buckets(db):
    filled_order(db, "open", spec(symbol="SA601", quantity="2"))
    replay(db, evidence(position(SA, "long", "2", "0")))  # replay says yesterday 2, venue row says today 2
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_BASELINE_CONFLICT"):
        replay(db, evidence(position(SA, "long", "0", "2")))


@pytest.mark.parametrize("case", ["sent", "dispatching", "unknown", "partial", "unattributed", "never_sent_fact",
                                  "orphan"])
def test_unresolved_history_refuses_the_baseline(db, case):
    filled_order(db, "open", spec())
    if case in ("sent", "dispatching", "unknown"):
        command(db, "live", spec(), status=case.upper())
    elif case == "partial":
        command(db, "live", spec(quantity="2"))
        fact(db, "live", spec(quantity="2"), kind=DirectExecutionEventKind.ORDER,
             status=DirectOrderStatus.CANCELLED, filled="1")
    elif case == "unattributed":
        command(db, "live", spec(), status="RELEASED")
        fact(db, None, spec(), disposition="UNATTRIBUTED")
    elif case == "never_sent_fact":
        command(db, "live", spec(), status="EXPIRED")
        fact(db, "live", spec(), kind=DirectExecutionEventKind.ORDER, status=DirectOrderStatus.ACCEPTED)
    else:
        fact(db, "missing", spec())
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_BASELINE_HISTORY_UNRESOLVED"):
        replay(db, evidence(position(RB, "long", "0", "1")))
    assert db.execute("SELECT count(*) FROM strategy_position_baseline").fetchone()[0] == 0


def test_snapshot_must_be_current_before_and_after_the_comparison(db):
    filled_order(db, "open", spec())
    item = evidence(position(RB, "long", "0", "1"))
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_BASELINE_SNAPSHOT_NOT_CURRENT"):
        replay(db, item, verify=lambda _: False)
    calls = []

    def once(actual):
        calls.append(actual)
        return len(calls) == 1

    with pytest.raises(DirectCommandJournalError, match="STRATEGY_BASELINE_SNAPSHOT_NOT_CURRENT"):
        replay(db, item, verify=once)
    assert calls == [item, item]


def test_journal_without_history_is_not_a_replayed_baseline(db):
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        replay(db, evidence(day=D0))


def test_earlier_trade_than_the_declared_start_is_refused(db):
    filled_order(db, "open", spec())
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_BASELINE_REPLAY_UNAVAILABLE"):
        replay(db, evidence(position(RB, "long", "1", "0"), start=D1))


@pytest.mark.parametrize("port", ["verify_current_continuity", "verify_day_transition"])
def test_history_that_cannot_be_replayed_to_the_observation_day_names_that(db, port):
    # The owner cannot vouch for continuity, or for the day change.
    filled_order(db, "open", spec())
    item = evidence(position(RB, "long", "0", "1"))
    ports = dict(PORTS, **{port: lambda *_: False})
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_BASELINE_REPLAY_UNAVAILABLE"):
        initialize_replayed_strategy_baseline(db, item, verify_current_snapshot=lambda _: True, **ports)


def test_evidence_versions_do_not_mix(db):
    replayed = evidence(day=D0)
    assert replayed.initial_trading_day == D0 and StrategyBaselineEvidence.from_mapping(
        json.loads(json.dumps(replayed.to_mapping()))) == replayed
    for initializer, name in ((initialize_empty_strategy_baseline, "verify_current_empty"),
                              (initialize_external_strategy_baseline, "verify_authorized_snapshot")):
        with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
            initializer(db, replayed, **{name: lambda _: True})
    plain = StrategyBaselineEvidence("acct", "journal", D0, "CTP", "generation", 1, "source",
        "position-snapshot", "orders-snapshot", "cut", ("resource",), 100, 200, True, True, True, True)
    # Version 1 stays byte-identical: no new key reaches its digest.
    assert "account_positions" not in plain.to_mapping() and plain.initial_trading_day == D0
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        initialize_replayed_strategy_baseline(db, plain, verify_current_snapshot=lambda _: True, **PORTS)
    for bad in (dict(history_start_trading_day=D0), dict(account_positions=(position(RB, "long", "1", "0"),))):
        with pytest.raises(DirectCommandJournalError):
            StrategyBaselineEvidence("acct", "journal", D0, "CTP", "generation", 1, "source", "p", "o", "cut",
                                     ("resource",), 100, 200, True, True, True, True, **bad)
    with pytest.raises(DirectCommandJournalError):
        evidence(day=D0, start=D1)  # the history cannot start after the observation


@pytest.mark.parametrize("case,expected", [
    ("settled", True), ("cancelled", True), ("unsettled", False), ("same_day", True),
    ("other_instrument", True), ("unknown_day", False), ("dispatching", False)])
def test_prior_day_commands_settled(db, case, expected):
    binding = BINDINGS["rb2601"]
    if case == "settled":
        filled_order(db, "open", spec())
    elif case == "cancelled":
        cancelled_order(db, "open", spec())
    elif case == "unsettled":
        command(db, "open", spec())
    elif case == "same_day":
        command(db, "open", spec(), day=D1)
    elif case == "other_instrument":
        command(db, "open", spec(symbol="SA601"))
    elif case == "unknown_day":
        command(db, "open", spec(), day=None)
    else:
        command(db, "open", spec(), status="DISPATCHING")
    assert prior_day_commands_settled(db, "acct", binding, D1) is expected


# ---------------------------------------------------------------------------
# through the real journal and its owner fence
# ---------------------------------------------------------------------------
KEY = MarketInstrumentKey("ctp", "SHFE", "simnow", "future", "rb2601", "rb2601")
BINDING = StrategyInstrumentBinding(KEY, "CTP", "contracts", True)


@pytest.fixture
def owner(tmp_path):
    directory = tmp_path / "guard"
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, "acct", "owner")
    generation = guard.acquire()
    journal = GatewayDirectCommandJournal.create(tmp_path / "db", "acct", generation=generation)
    journal.enable_controls(guard)
    yield journal, guard, tmp_path / "db"
    guard.release()


def traded(journal, guard):
    """An open that filled before the journal had a strategy ledger."""
    order = {"symbol": "rb2601", "side": "buy", "offset": "open", "quantity": "1",
             "quantity_unit": "contracts", "exchange_id": "SHFE"}
    record = journal.reserve("b", "open", "p", order)
    native = {"exchange_name": "CTP", "client_order_id": "open", "session_generation": 1,
              "fields_json": json.dumps({"trading_day": D0})}
    journal.begin_dispatch("b", "open", record.reservation_id, record.digest, "p", 1, native, ("anchor",))
    journal.finish("b", "open", record.reservation_id, record.digest, "p", 2, native, ("anchor",), "SENT")
    ledger = GatewayDirectExecutionLedger(journal, guard)
    common = dict(identity=NativeOrderIdentity("CTP", "ref", {"trading_day": D0}, 1),
                  identity_keys=("anchor",), binding_keys=("anchor",), venue_key="anchor",
                  side="buy", offset="open")
    assert ledger.ingest(GatewayReturnFact("acct", "CTP", KEY, D0, DirectExecutionEventKind.TRADE, "source",
        trade_key=("SHFE", "trade"), trade_quantity="1", trade_price="10", **common)).applied
    ledger.ingest(GatewayReturnFact("acct", "CTP", KEY, D0, DirectExecutionEventKind.ORDER, "source",
        status=DirectOrderStatus.FILLED, order_quantity="1", filled_quantity="1", remaining_quantity="0",
        **common))


def journal_evidence(journal, *positions):
    return StrategyBaselineEvidence(
        "acct", journal.journal_id, D1, "CTP", journal.generation, 1, "source", "position-snapshot",
        "orders-snapshot", "cut", ("open_orders", "positions"), 100, 200, True, True, not positions, True,
        schema_version=2, history_start_trading_day=D0, account_positions=tuple(positions))


def test_journal_adopts_pre_ledger_history_and_serves_the_close(owner):
    journal, guard, path = owner
    traded(journal, guard)
    journal.enable_strategy_ledger(guard)
    state = journal.read_strategy_ledger_state(guard=guard)
    assert state == {"baseline": None, "history_present": True, "earliest_trade_day": D0}
    active = []

    @contextmanager
    def fence():
        active.append(True)
        try:
            yield
        finally:
            active.pop()

    def verify(_):
        return bool(active)

    item = journal_evidence(journal, position(KEY, "long", "0", "1"))
    # Without the installed owner ports there is nothing to replay with.
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        journal.initialize_replayed_strategy_ledger(item, guard=guard, baseline_fence=fence,
                                                    verify_current_snapshot=verify)
    journal.install_strategy_ledger_ports(guard=guard, resolve_binding=lambda _: BINDING,
        current_trading_day=lambda: D1, verify_day_transition=transition,
        verify_current_continuity=lambda *_: True)
    with journal._transaction() as db:
        revision = journal._assert_anchor(db)
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_BASELINE_MISMATCH"):
        journal.initialize_replayed_strategy_ledger(journal_evidence(journal), guard=guard,
            baseline_fence=fence, verify_current_snapshot=verify)
    # The refused attempt left neither a baseline nor a revision behind.
    with journal._transaction() as db:
        assert journal._assert_anchor(db) == revision
    assert journal.read_strategy_ledger_state(guard=guard)["baseline"] is None
    journal.initialize_replayed_strategy_ledger(item, guard=guard, baseline_fence=fence,
                                                verify_current_snapshot=verify)
    assert not active
    assert journal.read_strategy_ledger_state(guard=guard)["baseline"] == item.to_mapping()
    close = {"symbol": "rb2601", "side": "sell", "offset": "close_yesterday", "quantity": "1",
             "quantity_unit": "contracts", "exchange_id": "SHFE"}
    assert journal.read_strategy_close_capacity("b", close, expected_instrument=KEY).available == 1
    journal.reserve("b", "close", "p", close)
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_CLOSE_EXCEEDS"):
        journal.reserve("b", "close-again", "p", close)
    # Another strategy owns nothing of that lot.
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_CLOSE_EXCEEDS"):
        journal.reserve("a", "close", "p", close)
    # A reopened journal accepts the persisted version-2 evidence.
    with journal._transaction() as db:
        revision = journal._assert_anchor(db)
    GatewayDirectCommandJournal(path, "acct", generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=revision,
        controls_enabled=True, strategy_ledger_enabled=True)
