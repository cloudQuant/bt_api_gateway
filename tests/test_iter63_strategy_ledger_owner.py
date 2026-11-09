"""Owner-level synthetic tests; no provider, account or external network."""
from contextlib import contextmanager

import pytest
from bt_api_base.direct_write_protocol import DirectExecutionEventKind, NativeOrderIdentity
from bt_api_base.gateway_execution_protocol import GatewayReturnFact
from bt_api_base.market_protocol import MarketInstrumentKey

from bt_api_gateway.direct_command_journal import DirectCommandJournalError, GatewayDirectCommandJournal
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from bt_api_gateway.session_guard import LocalAccountSessionGuard
from bt_api_gateway.strategy_position_ledger import ExternalBaselinePosition, StrategyBaselineEvidence, StrategyInstrumentBinding


KEY = MarketInstrumentKey("ctp", "SHFE", "simnow", "future", "rb2601", "rb2601")
BINDING = StrategyInstrumentBinding(KEY, "CTP", "lots", True)


@pytest.fixture
def owner(tmp_path):
    directory = tmp_path / "guard"
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, "acct", "owner")
    generation = guard.acquire()
    journal = GatewayDirectCommandJournal.create(tmp_path / "db", "acct", generation=generation)
    journal.enable_controls(guard)
    journal.enable_strategy_ledger(guard)
    yield journal, guard, tmp_path / "db"
    guard.release()


def order(side, offset, quantity="1"):
    return {"symbol": "rb2601", "side": side, "offset": offset, "quantity": quantity,
            "quantity_unit": "lots", "exchange_id": "SHFE"}


def install(journal, guard):
    journal.install_strategy_ledger_ports(guard=guard, resolve_binding=lambda _: BINDING,
                                          current_trading_day=lambda: "20300101",
                                          verify_day_transition=lambda *_: False,
                                          verify_current_continuity=lambda *_: True)


def baseline(journal, guard, *, approved=True):
    active = []
    @contextmanager
    def fence():
        active.append(True)
        try:
            yield
        finally:
            active.pop()
    evidence = StrategyBaselineEvidence("acct", journal.journal_id, "20300101", "CTP", journal.generation, 1,
        "source", "position-snapshot", "orders-snapshot", "cut", ("resource",),
        100, 200, True, True, True, True)
    def verify(actual):
        assert active and actual == evidence
        return approved
    journal.initialize_empty_strategy_ledger(evidence, guard=guard,
                                           baseline_fence=fence, verify_current_empty=verify)
    assert not active


def open_fill(journal, guard):
    payload = order("buy", "open")
    record = journal.reserve("s1", "open", "p", payload)
    native = {"exchange_name": "CTP", "client_order_id": "open", "session_generation": 1,
              "fields_json": "{}"}
    journal.begin_dispatch("s1", "open", record.reservation_id, record.digest, "p", 1,
                           native, ("anchor",))
    fact = GatewayReturnFact("acct", "CTP", KEY, "20300101", DirectExecutionEventKind.TRADE,
        "source", identity=NativeOrderIdentity("CTP", "ref", {"trading_day":"20300101"}, 1),
        identity_keys=("anchor",), binding_keys=("anchor",), venue_key="anchor",
        trade_key=("SHFE", "trade"), side="buy", offset="open", trade_quantity="1", trade_price="10")
    assert GatewayDirectExecutionLedger(journal, guard).ingest(fact).applied


def test_v11_requires_explicit_upgrade_and_does_not_assert_baseline(owner):
    journal, guard, path = owner
    with journal._transaction() as db:
        assert db.execute("SELECT count(*) FROM strategy_position_baseline").fetchone()[0] == 0
        revision = journal._assert_anchor(db)
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        journal.reserve("s1", "close", "p", order("sell", "close_today"))
    reopened = GatewayDirectCommandJournal(path, "acct", generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=revision,
        controls_enabled=True, strategy_ledger_enabled=True)
    with reopened._transaction() as db:
        assert db.execute("SELECT count(*) FROM strategy_position_baseline").fetchone()[0] == 0
    with pytest.raises(DirectCommandJournalError):
        GatewayDirectCommandJournal(path, "acct", generation=journal.generation,
            expected_journal_id=journal.journal_id, minimum_revision=revision, controls_enabled=True)
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        baseline(journal, guard, approved=False)


def test_one_owner_transaction_applies_fills_and_reserves_only_own_quantity(owner):
    journal, guard, _ = owner
    baseline(journal, guard)
    install(journal, guard)
    open_fill(journal, guard)
    reserved = journal.reserve("s1", "close1", "p", order("sell", "close_today"))
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_CLOSE_EXCEEDS"):
        journal.reserve("s1", "close2", "p", order("sell", "close_today"))
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_CLOSE_EXCEEDS"):
        journal.reserve("s2", "close-other", "p", order("sell", "close_today"))
    native = {"exchange_name": "CTP", "client_order_id": "close1", "session_generation": 1,
              "fields_json": "{}"}
    dispatch = journal.begin_dispatch("s1", "close1", reserved.reservation_id, reserved.digest, "p", 1,
                                      native, ("close-anchor",))
    assert dispatch.newly_started


def test_monitor_gate_rechecks_before_commit_without_losing_old_reservation(owner):
    journal, guard, _ = owner
    calls = []
    def gate():
        calls.append(True)
        return len(calls) == 1
    journal.install_monitor_gate(gate, guard=guard)
    with pytest.raises(DirectCommandJournalError, match="CONTROL_STOP_NEW"):
        journal.reserve("s1", "blocked", "p", order("buy", "open"))
    with journal._transaction() as db:
        assert db.execute("SELECT count(*) FROM direct_journal_commands").fetchone()[0] == 0
    with pytest.raises(DirectCommandJournalError, match="MONITOR_GATE_ALREADY_BOUND"):
        journal.install_monitor_gate(lambda: True, guard=guard)


def test_monitor_failure_rolls_back_dispatch_identity(owner):
    journal, guard, _ = owner
    calls = []
    def gate():
        calls.append(True)
        return len(calls) < 4
    journal.install_monitor_gate(gate, guard=guard)
    reserved = journal.reserve("s1", "open", "p", order("buy", "open"))
    native = {"exchange_name": "CTP", "client_order_id": "open", "session_generation": 1,
              "fields_json": "{}"}
    with pytest.raises(DirectCommandJournalError, match="CONTROL_STOP_NEW"):
        journal.begin_dispatch("s1", "open", reserved.reservation_id, reserved.digest, "p", 1,
                               native, ("anchor",))
    after = journal.get("s1", "open", "p")
    assert after.status == "RESERVED" and after.native_identity_json is None


def test_versioned_baseline_tampering_fails_reopen(owner):
    journal, guard, path = owner
    baseline(journal, guard)
    with journal._transaction() as db:
        revision = journal._assert_anchor(db)
        db.execute("UPDATE strategy_position_baseline SET evidence_json=replace(evidence_json, 'position-snapshot', 'changed-snapshot')")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        GatewayDirectCommandJournal(path, "acct", generation=journal.generation,
            expected_journal_id=journal.journal_id, minimum_revision=revision,
            controls_enabled=True, strategy_ledger_enabled=True)


def test_external_baseline_needs_authenticated_same_cut_and_cannot_be_strategy_position(owner):
    journal, guard, path = owner
    evidence = StrategyBaselineEvidence("acct", journal.journal_id, "20300101", "CTP", journal.generation, 1,
        "source", "position-snapshot", "orders-snapshot", "cut", ("resource",),
        100, 200, True, True, False, True,
        external_positions=(ExternalBaselinePosition(KEY, "long", "2", "3"),),
        operator_ref="operator", operation_id="operation")
    active = []
    @contextmanager
    def fence():
        active.append(True)
        try:
            yield
        finally:
            active.pop()
    def reject(value):
        assert active and value == evidence
        return False
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        journal.initialize_external_strategy_ledger(evidence, guard=guard, baseline_fence=fence,
                                                    verify_authorized_snapshot=reject)
    with journal._transaction() as db:
        assert db.execute("SELECT count(*) FROM strategy_external_baseline").fetchone()[0] == 0
    def accept(value):
        assert active and value == evidence
        return True
    journal.initialize_external_strategy_ledger(evidence, guard=guard, baseline_fence=fence,
                                                verify_authorized_snapshot=accept)
    assert not active
    install(journal, guard)
    assert journal.read_strategy_position("s1", order("sell", "close_today"), expected_instrument=KEY).long_today == 0
    with journal._transaction() as db:
        revision = journal._assert_anchor(db)
    GatewayDirectCommandJournal(path, "acct", generation=journal.generation,
        expected_journal_id=journal.journal_id, minimum_revision=revision,
        controls_enabled=True, strategy_ledger_enabled=True)
    with journal._transaction() as db:
        db.execute("UPDATE strategy_external_baseline SET today_quantity='9'")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        GatewayDirectCommandJournal(path, "acct", generation=journal.generation,
            expected_journal_id=journal.journal_id, minimum_revision=revision,
            controls_enabled=True, strategy_ledger_enabled=True)


def test_position_and_close_read_require_exact_instrument_and_continuity(owner):
    journal, guard, _ = owner
    baseline(journal, guard)
    install(journal, guard)
    open_fill(journal, guard)
    query = order("sell", "close_today")
    assert journal.read_strategy_position("s1", query, expected_instrument=KEY).long_today == 1
    assert journal.read_strategy_close_capacity("s1", query, expected_instrument=KEY).available == 1
    different = MarketInstrumentKey("ctp", "DCE", "simnow", "future", "rb2601", "rb2601")
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        journal.read_strategy_position("s1", query, expected_instrument=different)
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        journal.read_strategy_close_capacity("s1", query, expected_instrument=different)


def test_lost_continuity_during_replay_blocks_close_and_read(owner):
    journal, guard, _ = owner
    baseline(journal, guard)
    calls = []
    def continuity(*_):
        calls.append(True)
        return len(calls) == 1
    journal.install_strategy_ledger_ports(guard=guard, resolve_binding=lambda _: BINDING,
        current_trading_day=lambda: "20300101", verify_day_transition=lambda *_: False,
        verify_current_continuity=continuity)
    open_fill(journal, guard)
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_LEDGER_UNAVAILABLE"):
        journal.reserve("s1", "close", "p", order("sell", "close_today"))
    with journal._transaction() as db:
        assert db.execute("SELECT count(*) FROM direct_journal_commands WHERE request_key='close'").fetchone()[0] == 0


def test_stop_new_allows_only_proved_close_even_for_previously_reserved_order(owner):
    from bt_api_gateway.direct_control import GatewayDirectControl
    journal, guard, _ = owner
    baseline(journal, guard)
    install(journal, guard)
    open_fill(journal, guard)
    close = journal.reserve("s1", "close", "p", order("sell", "close_today"))
    control = GatewayDirectControl(journal, guard)
    control.apply("stop", "STOP_NEW", scope_kind="strategy", scope_value="s1", origin="operator")
    with pytest.raises(DirectCommandJournalError, match="CONTROL_STOP_NEW"):
        journal.reserve("s1", "new-open", "p", order("buy", "open"))
    native = {"exchange_name": "CTP", "client_order_id": "close", "session_generation": 1,
              "fields_json": "{}"}
    assert journal.begin_dispatch("s1", "close", close.reservation_id, close.digest, "p", 1,
                                  native, ("close-anchor",)).newly_started


def test_freeze_cannot_be_bypassed_by_proved_close_even_after_resume(owner):
    from bt_api_gateway.direct_control import GatewayDirectControl
    journal, guard, _ = owner
    baseline(journal, guard)
    install(journal, guard)
    open_fill(journal, guard)
    close = journal.reserve("s1", "close", "p", order("sell", "close_today"))
    control = GatewayDirectControl(journal, guard)
    control.apply("freeze", "FREEZE", scope_kind="strategy", scope_value="s1", origin="operator")
    with pytest.raises(DirectCommandJournalError, match="CONTROL_FREEZE"):
        journal.reserve("s1", "close-new", "p", order("sell", "close_today"))
    control.resume("freeze", expected_version=1, operation_id="unfreeze")
    native = {"exchange_name": "CTP", "client_order_id": "close", "session_generation": 1,
              "fields_json": "{}"}
    with pytest.raises(DirectCommandJournalError, match="CONTROL_PREVIOUSLY_BLOCKED"):
        journal.begin_dispatch("s1", "close", close.reservation_id, close.digest, "p", 1,
                               native, ("close-anchor",))


def test_monitor_stop_new_allows_only_independently_proved_close(owner):
    journal, guard, _ = owner
    baseline(journal, guard)
    install(journal, guard)
    open_fill(journal, guard)
    journal.install_monitor_gate(lambda: False, guard=guard)
    with pytest.raises(DirectCommandJournalError, match="CONTROL_STOP_NEW"):
        journal.reserve("s1", "open-new", "p", order("buy", "open"))
    assert journal.reserve("s1", "close", "p", order("sell", "close_today")).status == "RESERVED"
    with pytest.raises(DirectCommandJournalError, match="STRATEGY_CLOSE_EXCEEDS"):
        journal.reserve("s1", "too-many", "p", order("sell", "close_today"))
