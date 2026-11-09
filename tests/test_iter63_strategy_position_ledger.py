"""Synthetic same-transaction strategy position ownership checks."""
import json
import sqlite3

import pytest
from bt_api_base.direct_write_protocol import DirectExecutionEventKind, DirectOrderStatus, NativeOrderIdentity
from bt_api_base.gateway_execution_protocol import GatewayReturnFact
from bt_api_base.market_protocol import MarketInstrumentKey

from bt_api_gateway.direct_command_journal import DirectCommandJournalError
from bt_api_gateway.strategy_position_ledger import (
    StrategyBaselineEvidence,
    StrategyInstrumentBinding,
    _create_strategy_ledger_tables,
    _verify_strategy_ledger_integrity,
    check_strategy_close,
    initialize_empty_strategy_baseline,
    strategy_position,
)

KEY = MarketInstrumentKey("ctp", "SHFE", "simnow", "future", "rb2601", "rb2601")
BINDING = StrategyInstrumentBinding(KEY, "CTP", "lots", True)


@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.executescript("""
        CREATE TABLE direct_journal_meta (account TEXT, journal_id TEXT);
        INSERT INTO direct_journal_meta VALUES ('acct', 'journal');
        CREATE TABLE direct_journal_commands (account TEXT, strategy TEXT, reservation_id TEXT,
            status TEXT, payload_json TEXT);
        CREATE TABLE direct_execution_facts (account TEXT, fact_json TEXT, reservation_id TEXT,
            disposition TEXT, applied INTEGER, event_sequence INTEGER, reason TEXT);
        CREATE TABLE direct_execution_totals (account TEXT, reservation_id TEXT, total_quantity TEXT);
    """)
    conn.execute("BEGIN IMMEDIATE")
    _create_strategy_ledger_tables(conn)
    yield conn
    conn.close()


def baseline_evidence(*, generation="generation", day="20300101"):
    return StrategyBaselineEvidence("acct", "journal", day, "CTP", generation, 1, "source", "position-snapshot",
        "orders-snapshot", "cut", ("resource",), 100, 200, True, True, True, True)


def initialize(conn, verify=lambda *_: True):
    initialize_empty_strategy_baseline(conn, baseline_evidence(), verify_current_empty=verify)


def payload(side="buy", offset="open", quantity="2"):
    return {"symbol": "rb2601", "side": side, "offset": offset, "quantity": quantity,
            "quantity_unit": "lots", "exchange_id": "SHFE", "position_side": None}


def insert_command(conn, key, spec, strategy="s1", status="SENT"):
    conn.execute("INSERT INTO direct_journal_commands VALUES (?, ?, ?, ?, ?)",
                 ("acct", strategy, key, status, json.dumps(spec)))


def insert_fact(conn, key, sequence, *, side="buy", offset="open", quantity="2", day="20300101",
                kind=DirectExecutionEventKind.TRADE, status=None, filled=None, disposition="ATTRIBUTED", instrument=KEY):
    record = GatewayReturnFact(
        "acct", "CTP", instrument, day, kind, "source", identity=NativeOrderIdentity("CTP", "ref", {}, 1),
        identity_keys=("identity", "venue"), binding_keys=("identity",), venue_key="venue",
        trade_key=("SHFE", "trade-" + str(sequence)) if kind is DirectExecutionEventKind.TRADE else None,
        status=status, side=side, offset=offset,
        trade_quantity=quantity if kind is DirectExecutionEventKind.TRADE else None,
        trade_price="10" if kind is DirectExecutionEventKind.TRADE else None,
        filled_quantity=filled,
    )
    conn.execute("INSERT INTO direct_execution_facts VALUES (?, ?, ?, ?, ?, ?, ?)",
                 ("acct", json.dumps(record.to_mapping()), key, disposition,
                  int(kind is DirectExecutionEventKind.TRADE and disposition == "ATTRIBUTED"), sequence, "MATCHED"))


def snapshot(conn, strategy="s1", binding=BINDING, day="20300101", transition=lambda *_: False):
    return strategy_position(conn, "acct", strategy, binding, trading_day=day,
                             resolve_binding=lambda _: binding, verify_day_transition=transition,
                             verify_current_continuity=lambda *_: True)


def check(conn, spec, strategy="s1", binding=BINDING, day="20300101", exclude=None):
    return check_strategy_close(conn, "acct", strategy, spec, trading_day=day,
                                instrument_binding=binding, resolve_binding=lambda _: binding,
                                verify_day_transition=lambda *_: False, verify_current_continuity=lambda *_: True,
                                exclude_reservation_id=exclude)


def test_empty_baseline_requires_current_trusted_proof_and_no_history(db):
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        initialize(db, lambda *_: False)
    insert_command(db, "old", payload())
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_BASELINE_HISTORY_PRESENT"):
        initialize(db)
    db.execute("DELETE FROM direct_journal_commands")
    initialize(db)
    initialize(db)
    _verify_strategy_ledger_integrity(db, "acct")
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_BASELINE_CONFLICT"):
        initialize_empty_strategy_baseline(db, baseline_evidence(day="20300102"),
                                           verify_current_empty=lambda *_: True)


def test_attributed_fills_replay_separate_strategies_and_sides(db):
    initialize(db)
    insert_command(db, "a", payload("buy", "open", "2"))
    insert_fact(db, "a", 1)
    insert_command(db, "b", payload("sell", "open", "3"), strategy="s2")
    insert_fact(db, "b", 2, side="sell", quantity="3")
    assert snapshot(db, "s1").long_today == 2
    assert snapshot(db, "s2").short_today == 3
    assert snapshot(db, "s1").net == 2
    assert snapshot(db, "s2").net == -3
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_CLOSE_EXCEEDS"):
        check(db, payload("sell", "close_today", "3"))
    assert check(db, payload("sell", "close_today", "2")).long_today == 2


def test_reserve_and_unknown_occupy_capacity_until_reliable_terminal(db):
    initialize(db)
    insert_command(db, "open", payload(quantity="5"))
    insert_fact(db, "open", 1, quantity="5")
    insert_command(db, "close1", payload("sell", "close_today", "3"), status="UNKNOWN")
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_CLOSE_EXCEEDS"):
        check(db, payload("sell", "close_today", "3"))
    assert check(db, payload("sell", "close_today", "2")).long_today == 5
    assert check(db, payload("sell", "close_today", "3"), exclude="close1").long_today == 5
    insert_fact(db, "close1", 2, kind=DirectExecutionEventKind.ORDER, side="sell", offset="close_today",
                status=DirectOrderStatus.CANCELLED, filled="0")
    assert check(db, payload("sell", "close_today", "5")).long_today == 5


def test_terminal_does_not_release_unmatched_reported_fill(db):
    initialize(db)
    insert_command(db, "open", payload(quantity="5"))
    insert_fact(db, "open", 1, quantity="5")
    insert_command(db, "close1", payload("sell", "close_today", "4"), status="SENT")
    insert_fact(db, "close1", 2, kind=DirectExecutionEventKind.ORDER, side="sell", offset="close_today",
                status=DirectOrderStatus.CANCELLED, filled="2")
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_CLOSE_EXCEEDS"):
        check(db, payload("sell", "close_today", "2"))


def test_day_change_requires_owner_proof_and_late_facts_are_unavailable(db):
    initialize(db)
    insert_command(db, "open", payload())
    insert_fact(db, "open", 1)
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        snapshot(db, day="20300102")
    assert snapshot(db, day="20300102", transition=lambda *_: True).long_yesterday == 2
    insert_command(db, "new", payload())
    insert_fact(db, "new", 2, day="20300102")
    insert_command(db, "late", payload())
    insert_fact(db, "late", 3, day="20300101")
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        snapshot(db, day="20300102", transition=lambda *_: True)


def test_unattributed_trade_same_instrument_blocks_even_other_strategy(db):
    initialize(db)
    insert_command(db, "open", payload())
    insert_fact(db, "open", 1)
    insert_fact(db, "unbound", 2, disposition="UNATTRIBUTED")
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        check(db, payload("sell", "close_today", "1"))


def test_exact_instrument_unit_and_direction_binding_are_required(db):
    initialize(db)
    insert_command(db, "open", payload())
    insert_fact(db, "open", 1)
    bad = payload("sell", "close_today", "1")
    bad["quantity_unit"] = "base"
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        check(db, bad)
    bad = payload("sell", "close_today", "1")
    bad["position_side"] = "short"
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        check(db, bad)
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        check(db, payload("sell", "close", "1"))


def test_comparison_uses_verified_external_and_never_residual_or_missing_as_zero(db):
    from bt_api_gateway.strategy_position_ledger import compare_account_net

    initialize(db)
    insert_command(db, "open", payload(quantity="5"), strategy="s1")
    insert_fact(db, "open", 1, quantity="5")
    kwargs = dict(trading_day="20300101", cut="cut-1", resolve_binding=lambda _: BINDING,
                  verify_day_transition=lambda *_: False, verify_current_continuity=lambda *_: True,
                  verify_account_cut=lambda *_: True,
                  verify_external_cut=lambda *_: True)
    match = compare_account_net(db, "acct", BINDING, account_net="0", external_net="-5", **kwargs)
    assert (match.status, match.strategy_net, match.external_net, match.difference) == ("MATCH", 5, -5, 0)
    mismatch = compare_account_net(db, "acct", BINDING, account_net="0", external_net="-4", **kwargs)
    assert mismatch.status == "MISMATCH" and mismatch.difference == -1
    assert compare_account_net(db, "acct", BINDING, account_net="0", external_net=None, **kwargs).status == "UNAVAILABLE"
    kwargs["verify_external_cut"] = lambda *_: False
    assert compare_account_net(db, "acct", BINDING, account_net="0", external_net="-5", **kwargs).status == "UNAVAILABLE"


def test_comparison_refuses_missing_baseline_and_changed_cut(db):
    from bt_api_gateway.strategy_position_ledger import compare_account_net

    kwargs = dict(trading_day="20300101", cut="cut", resolve_binding=lambda _: BINDING,
                  verify_day_transition=lambda *_: False, verify_current_continuity=lambda *_: True,
                  verify_account_cut=lambda *_: True,
                  verify_external_cut=lambda *_: True)
    assert compare_account_net(db, "acct", BINDING, account_net="0", external_net="0", **kwargs).status == "UNAVAILABLE"
    initialize(db)
    calls = []
    def changed(*_):
        calls.append(1)
        return len(calls) == 1
    kwargs["verify_account_cut"] = changed
    assert compare_account_net(db, "acct", BINDING, account_net="0", external_net="0", **kwargs).status == "UNAVAILABLE"


def test_unproved_exclusion_and_contradictory_terminal_never_release(db):
    initialize(db)
    insert_command(db, "open", payload(quantity="5"))
    insert_fact(db, "open", 1, quantity="5")
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        check(db, payload("sell", "close_today", "2"), exclude="missing")
    insert_command(db, "close1", payload("sell", "close_today", "3"), status="NOT_SENT")
    insert_fact(db, "close1", 2, kind=DirectExecutionEventKind.ORDER, side="sell", offset="close_today",
                status=DirectOrderStatus.ACCEPTED, filled="0")
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        check(db, payload("sell", "close_today", "2"))


def test_contradictory_applied_fact_never_grants_close(db):
    initialize(db)
    insert_command(db, "open", payload())
    insert_fact(db, "open", 1)
    db.execute("UPDATE direct_execution_facts SET reason='OVERFILL'")
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        check(db, payload("sell", "close_today", "1"))


def test_ordinary_close_estimates_bucket_and_cannot_prove_explicit_bucket_close(db):
    initialize(db)
    key = MarketInstrumentKey("ctp", "DCE", "simnow", "future", "rb2601", "rb2601")
    binding = StrategyInstrumentBinding(key, "CTP", "lots", False)
    opening = payload(quantity="5")
    opening["exchange_id"] = "DCE"
    insert_command(db, "open", opening)
    insert_fact(db, "open", 1, quantity="5", instrument=key)
    closing = payload("sell", "close", "2")
    closing["exchange_id"] = "DCE"
    insert_command(db, "close", closing)
    insert_fact(db, "close", 2, side="sell", offset="close", quantity="2", instrument=key)
    db.execute("INSERT INTO direct_execution_totals VALUES (?, ?, ?)", ("acct", "close", "2"))
    position = snapshot(db, binding=binding)
    assert position.long_today == 3 and position.projected_buckets
    closing["quantity"] = "3"
    assert check(db, closing, binding=binding).long_today == 3
    closing["offset"] = "close_today"
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        check(db, closing, binding=binding)


def test_large_decimal_net_is_not_rounded_by_global_context():
    from decimal import Decimal
    from bt_api_gateway.strategy_position_ledger import StrategyPosition

    position = StrategyPosition("20300101", Decimal("123456789012345678901234567890.12"),
                                Decimal("0"), Decimal("0.11"), Decimal("0"))
    assert position.net == Decimal("123456789012345678901234567890.01")
