"""Known system UNKNOWN has the documented minimum strategy/instrument scope."""
import pytest
from contextlib import contextmanager
from bt_api_base.market_protocol import MarketInstrumentKey
from bt_api_gateway.direct_command_journal import DirectCommandJournalError
from bt_api_gateway.strategy_position_ledger import StrategyInstrumentBinding
from bt_api_gateway.unknown_order_scope import check_unknown_order_scope
from test_iter63_strategy_ledger_owner import owner, baseline, install, open_fill, order, BINDING  # noqa: F401
from test_iter63_external_position_ledger import external_trade
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger


def test_known_unknown_fences_owner_and_dependent_close_only(owner):  # noqa: F811
    journal, guard, _ = owner
    baseline(journal, guard)
    install(journal, guard)
    open_fill(journal, guard)
    request = order("sell", "close_today")
    command = journal.reserve("s1", "close", "p", request)
    native = {"exchange_name": "CTP", "client_order_id": "close", "session_generation": 1, "fields_json": "{}"}
    dispatch = journal.begin_dispatch("s1", "close", command.reservation_id, command.digest, "p", 1, native, ("close-key",))
    journal.finish("s1", "close", command.reservation_id, command.digest, "p", dispatch.record.version,
                   native, ("close-key",), "UNKNOWN")
    with pytest.raises(DirectCommandJournalError, match="SYSTEM_ORDER_UNKNOWN"):
        journal.reserve("s1", "blocked-open", "p", order("buy", "open"))
    with pytest.raises(DirectCommandJournalError, match="SYSTEM_ORDER_UNKNOWN"):
        journal.reserve("s2", "blocked-close", "p", order("sell", "close_today"))
    assert journal.reserve("s2", "allowed-open", "p", order("buy", "open")).status == "RESERVED"
    # Unmatched outside source does not imply system ownership.
    assert GatewayDirectExecutionLedger(journal, guard).ingest(external_trade()).disposition == "UNATTRIBUTED"
    different = StrategyInstrumentBinding(MarketInstrumentKey("ctp", "DCE", "simnow", "future", "m2601", "m2601"), "CTP", "lots", False)
    resolve = lambda p: BINDING if p.get("symbol") == "rb2601" else different
    with journal._transaction() as db:
        with pytest.raises(DirectCommandJournalError, match="SYSTEM_ORDER_UNKNOWN"):
            check_unknown_order_scope(db, "acct", "s1", order("buy", "open"), resolve_binding=resolve)
        with pytest.raises(DirectCommandJournalError, match="SYSTEM_ORDER_UNKNOWN"):
            check_unknown_order_scope(db, "acct", "s2", order("sell", "close_today"), resolve_binding=resolve)
        proofs = []
        def proven_capacity(*args):
            proofs.append(args[-1])
            return True
        check_unknown_order_scope(db, "acct", "s2", order("sell", "close_today"), resolve_binding=resolve,
                                  verify_other_close_capacity=proven_capacity)
        assert proofs == [(command.reservation_id,)]
        check_unknown_order_scope(db, "acct", "s2", order("sell", "close_yesterday"), resolve_binding=resolve)
        check_unknown_order_scope(db, "acct", "s2", order("buy", "close_today"), resolve_binding=resolve)
        check_unknown_order_scope(db, "acct", "s2", order("buy", "open"), resolve_binding=resolve)
        check_unknown_order_scope(db, "acct", "s1", order("buy", "open") | {"symbol": "m2601"}, resolve_binding=resolve)
        with pytest.raises(DirectCommandJournalError, match="UNKNOWN_SCOPE_UNAVAILABLE"):
            check_unknown_order_scope(db, "acct", "s1", order("buy", "open"), resolve_binding=None)
        check_unknown_order_scope(db, "acct", "s1", order("buy", "open"), resolve_binding=resolve,
                                  exclude_reservation_id=command.reservation_id)


def test_one_unknown_exclusion_cannot_clear_another(owner):  # noqa: F811
    journal, guard, _ = owner
    baseline(journal, guard)
    install(journal, guard)
    pending = []
    for index in (1, 2):
        key = f"open-{index}"
        command = journal.reserve("s1", key, "p", order("buy", "open"))
        native = {"exchange_name": "CTP", "client_order_id": key, "session_generation": 1, "fields_json": "{}"}
        started = journal.begin_dispatch("s1", key, command.reservation_id, command.digest, "p", 1,
                                         native, (key,))
        pending.append((key, command, native, started.record.version))
    for key, command, native, version in pending:
        journal.finish("s1", key, command.reservation_id, command.digest, "p", version, native, (key,), "UNKNOWN")
    with journal._transaction() as db:
        with pytest.raises(DirectCommandJournalError, match="SYSTEM_ORDER_UNKNOWN"):
            check_unknown_order_scope(db, "acct", "s1", order("buy", "open"), resolve_binding=lambda _: BINDING,
                                      exclude_reservation_id=pending[0][1].reservation_id)


def test_unavailable_capacity_proof_does_not_block_unrelated_commands(owner):  # noqa: F811
    journal, guard, _ = owner
    baseline(journal, guard)
    different = StrategyInstrumentBinding(MarketInstrumentKey("ctp", "DCE", "simnow", "future", "m2601", "m2601"), "CTP", "lots", False)
    journal.install_strategy_ledger_ports(guard=guard, resolve_binding=lambda p: BINDING if p["symbol"] == "rb2601" else different,
        current_trading_day=lambda: "20300101", verify_day_transition=lambda *_: False,
        verify_current_continuity=lambda *_: True)
    open_fill(journal, guard)
    close = journal.reserve("s1", "uncertain-close", "p", order("sell", "close_today"))
    identity = {"exchange_name": "CTP", "client_order_id": "uncertain", "session_generation": 1, "fields_json": "{}"}
    started = journal.begin_dispatch("s1", "uncertain-close", close.reservation_id, close.digest, "p", 1,
                                     identity, ("uncertain-key",))
    journal.finish("s1", "uncertain-close", close.reservation_id, close.digest, "p", started.record.version,
                   identity, ("uncertain-key",), "UNKNOWN")
    entered = []
    @contextmanager
    def unavailable():
        entered.append(True)
        raise DirectCommandJournalError("CAPACITY_PROOF_UNAVAILABLE")
        yield
    journal.install_unknown_close_capacity(guard=guard, source_fence=unavailable,
                                          verify_other_close_capacity=lambda *_: True)
    other_strategy = journal.reserve("s2", "other-open", "p", order("buy", "open"))
    other_contract = journal.reserve("s1", "other-contract", "p", order("buy", "open") | {"symbol": "m2601"})
    assert not entered
    for command in (other_strategy, other_contract):
        native = {"exchange_name": "CTP", "client_order_id": command.request_key,
                  "session_generation": 1, "fields_json": "{}"}
        assert journal.begin_dispatch(command.strategy_scope, command.request_key, command.reservation_id,
            command.digest, "p", 1, native, (command.request_key,)).newly_started
    assert not entered
    with pytest.raises(DirectCommandJournalError, match="CAPACITY_PROOF_UNAVAILABLE"):
        journal.reserve("s2", "dependent-close", "p", order("sell", "close_today"))
    assert entered == [True]
