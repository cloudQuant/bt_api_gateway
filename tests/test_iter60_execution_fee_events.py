"""Iteration 60 R3: fill fees on Gateway execution events and strategy-prefix routing.

A trade observation carries the provider fee of the fill (Base execution
event v2). The same fee is a duplicate; a higher fee for the same fill is a new
event (a fee correction for consumers); a lower fee or another currency is
refused in the append transaction and nothing is written. Routes may be built
from strategy refs with the Base client-order prefix that order-entry owners
use. UNIT/FAKE (temp SQLite, no provider).
"""

from __future__ import annotations

import pytest
from bt_api_base.execution_row_observation_protocol import (
    AccountExecutionTradeObservation,
    execution_observation_from_event,
    strategy_client_order_prefix,
)
from test_execution_events_iter60 import EXEC_A, EXEC_B, UNATTRIBUTED, events, order, publisher
from test_execution_events_iter60 import trade as plain_trade

from bt_api_gateway import GatewayEventJournal
from bt_api_gateway.execution_event_publisher import (
    GatewayExecutionEventError,
    GatewayExecutionScopePolicy,
)


def trade(fee=None, currency=None, **kwargs):
    base = plain_trade(**kwargs)
    return AccountExecutionTradeObservation(base.account_key, base.trade, fee, currency)


def test_fill_fee_corrections_append_and_regressions_are_refused(tmp_path):
    journal = GatewayEventJournal(tmp_path / "gw.db")
    pub = publisher(journal)
    pub.publish([order(), trade("0.1", "USDT")])
    assert pub.publish([trade("0.10", "USDT")]).duplicates == 1
    result = pub.publish([trade("0.15", "USDT")])
    assert (result.appended, result.duplicates) == (1, 0)
    stream = events(journal, EXEC_A)
    fees = [
        execution_observation_from_event(e.kind, e.event_id, e.payload).fee
        for e in stream
        if e.kind.startswith("account.execution_trade")
    ]
    assert fees == ["0.1", "0.15"]
    for bad, code in (
        (trade("0.12", "USDT"), "EXECUTION_FEE_REGRESSED"),
        (trade("0.2", "BTC"), "EXECUTION_FEE_CURRENCY_CONFLICT"),
    ):
        with pytest.raises(GatewayExecutionEventError) as refused:
            pub.publish([bad])
        assert refused.value.code == code
    assert len(events(journal, EXEC_A)) == len(stream)
    # A fee-less re-report of a fee'd fill is a distinct (fee-unknown) fact
    # that changes no recorded fee; the next correction still compares to 0.15.
    pub.publish([trade()])
    with pytest.raises(GatewayExecutionEventError):
        pub.publish([trade("0.14", "USDT")])
    # The recorded fee survives a Gateway restart.
    again = publisher(GatewayEventJournal(tmp_path / "gw.db"))
    with pytest.raises(GatewayExecutionEventError):
        again.publish([trade("0.11", "USDT")])
    assert again.publish([trade("0.2", "USDT")]).appended == 1


def test_routes_from_strategy_refs_use_the_base_prefix(tmp_path):
    routes = GatewayExecutionScopePolicy.for_strategies(
        {"strategy-a": EXEC_A, "strategy-b": EXEC_B}, unattributed_scope=UNATTRIBUTED
    )
    prefix_a = strategy_client_order_prefix("strategy-a")
    assert routes.scope_for_client_order(prefix_a + "abc") == EXEC_A
    assert routes.scope_for_client_order("risk-abc") == UNATTRIBUTED
    journal = GatewayEventJournal(tmp_path / "gw.db")
    pub = publisher(journal, routes=routes)
    pub.publish([order("o-1", prefix_a + "123"), trade("0.1", "USDT", order_id="o-1")])
    assert len(events(journal, EXEC_A)) == 2
    assert events(journal, EXEC_B) == ()
    with pytest.raises(GatewayExecutionEventError):
        GatewayExecutionScopePolicy.for_strategies({})
    with pytest.raises(GatewayExecutionEventError):
        GatewayExecutionScopePolicy.for_strategies({" bad": EXEC_A})
