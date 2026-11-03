"""Iteration 60 R2-C: Gateway producer of typed terminal-order and fill events.

Local fake provider only. The account session worker drains the provider's
typed execution observations into per-strategy event streams of the account
journal (fact-id idempotent, durable order routes, confirm after commit) and
the read service serves them with tracked delivery and ACK through
``stream="execution"``.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from bt_api_base.account_protocol import AccountKey
from bt_api_base.execution_query_protocol import ExecutionOrderRecord, ExecutionTradeRecord
from bt_api_base.execution_row_observation_protocol import (
    EXECUTION_ORDER_EVENT_KIND,
    EXECUTION_TRADE_EVENT_KIND,
    AccountExecutionOrderObservation,
    AccountExecutionTradeObservation,
    execution_observation_from_event,
)
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope
from test_account_session_worker import (
    Clocks,
    FakeProvider,
    _identity,
    _instrument,
    _observation,
    _resource,
)

from bt_api_gateway import GatewayCommandKind, GatewayEventJournal, GatewayPrincipal
from bt_api_gateway.account_session_worker import (
    GatewayAccountSessionWorker,
    GatewayAccountSessionWorkerError,
)
from bt_api_gateway.event_journal import GatewayEventJournalError
from bt_api_gateway.execution_event_publisher import (
    GatewayExecutionEventError,
    GatewayExecutionEventPublisher,
    GatewayExecutionScopePolicy,
)
from bt_api_gateway.service_component import (
    GatewayReadService,
    GatewayServiceAccountScope,
    GatewayServiceError,
)
from bt_api_gateway.session_guard import LocalAccountSessionGuard

ACCOUNT_SCOPE = "account:shared"
STATE_SCOPE = "strategy:account-facts"
EXEC_A = "exec:strategy-a"
EXEC_B = "exec:strategy-b"
UNATTRIBUTED = "exec:unattributed"
DOMAIN = "paper:synthetic"
ACCOUNT_REF = "acct-ref"


def order(order_id="o-1", client="sa-1", status="open", filled="0", quantity="3", **changes):
    return AccountExecutionOrderObservation(
        _identity(),
        ExecutionOrderRecord(
            resource=_resource(),
            instrument=_instrument(),
            order_id=order_id,
            client_order_id=client,
            intent_binding="unresolved" if client is None else "verified",
            side="buy",
            position_effect="unavailable",
            position_side=None,
            position_side_status="unavailable",
            order_type="limit",
            status=status,
            quantity=quantity,
            filled_quantity=filled,
            qty_unit="contract",
            limit_price="10",
            price_currency=None,
            price_currency_status="unavailable",
            created_at_utc=None,
            created_at_status="unavailable",
            observed_at_utc=changes.pop("observed_at_utc", "2027-01-15T08:00:00Z"),
            **changes,
        ),
    )


def trade(trade_id="t-1", order_id="o-1", quantity="1", price="10", **changes):
    return AccountExecutionTradeObservation(
        _identity(),
        ExecutionTradeRecord(
            resource=_resource(),
            instrument=_instrument(),
            trade_id=trade_id,
            order_id=order_id,
            order_binding="unresolved" if order_id is None else "provider_order_identity",
            side="buy",
            position_effect="unavailable",
            position_side=None,
            position_side_status="unavailable",
            quantity=quantity,
            qty_unit="contract",
            price=price,
            price_currency=None,
            price_currency_status="unavailable",
            traded_at_utc=None,
            traded_at_status="unavailable",
            observed_at_utc=changes.pop("observed_at_utc", "2027-01-15T08:00:01Z"),
            **changes,
        ),
    )


def policy(unattributed=UNATTRIBUTED):
    return GatewayExecutionScopePolicy(
        client_order_prefixes={"sa-": EXEC_A, "sb-": EXEC_B, "sa-x-": EXEC_B},
        unattributed_scope=unattributed,
    )


def publisher(journal, **kwargs):
    return GatewayExecutionEventPublisher(
        journal,
        account_key=_identity(),
        journal_account_scope=ACCOUNT_SCOPE,
        policy=kwargs.pop("routes", None) or policy(**kwargs),
    )


def principal(*scopes):
    return GatewayPrincipal(
        principal_id="client",
        account_scopes=frozenset({ACCOUNT_SCOPE}),
        strategy_scopes=frozenset(scopes),
        allowed_kinds=frozenset({GatewayCommandKind.READ}),
    )


def events(journal, scope):
    batch = journal.read_after(principal(scope), ACCOUNT_SCOPE, scope, cursor=None, limit=100)
    return batch.events


# -- publisher ------------------------------------------------------------------


def test_routes_by_verified_client_prefix_and_fills_follow_their_order(tmp_path):
    journal = GatewayEventJournal(tmp_path / "gw.db")
    result = publisher(journal).publish(
        [
            trade("t-0", "o-2"),  # reported ahead of its order observation
            order("o-1", "sa-1"),
            order("o-2", "sa-x-2"),  # longest prefix wins
            trade("t-1", "o-1"),
            order("o-3", None),  # no verified binding
            trade("t-9", "unknown-order"),
        ]
    )
    assert (result.appended, result.duplicates, result.unattributed_dropped) == (6, 0, 0)
    a, b, rest = events(journal, EXEC_A), events(journal, EXEC_B), events(journal, UNATTRIBUTED)
    assert [(e.sequence, e.kind) for e in a] == [
        (1, EXECUTION_ORDER_EVENT_KIND),
        (2, EXECUTION_TRADE_EVENT_KIND),
    ]
    assert [e.kind for e in b] == [EXECUTION_TRADE_EVENT_KIND, EXECUTION_ORDER_EVENT_KIND]
    assert len(rest) == 2
    decoded = execution_observation_from_event(a[1].kind, a[1].event_id, a[1].payload)
    assert decoded == trade("t-1", "o-1")
    # The route is durable: a fill after a Gateway restart still reaches A.
    again = publisher(GatewayEventJournal(tmp_path / "gw.db"))
    again.publish([trade("t-2", "o-1")])
    assert len(events(journal, EXEC_A)) == 3


def test_redelivered_facts_are_idempotent_and_conflicts_fail_closed(tmp_path):
    journal = GatewayEventJournal(tmp_path / "gw.db")
    pub = publisher(journal)
    pub.publish([order(), trade()])
    result = pub.publish(
        [
            order(observed_at_utc="2027-01-15T08:00:09Z"),
            trade(observed_at_utc="2027-01-15T08:01:00Z"),
        ]
    )
    assert (result.appended, result.duplicates) == (0, 2)
    assert len(events(journal, EXEC_A)) == 2
    with pytest.raises(GatewayExecutionEventError) as conflict:
        pub.publish([trade(price="11")])
    assert conflict.value.code == "EXECUTION_FACT_CONFLICT"
    # The same provider order id may not move to another strategy stream.
    with pytest.raises(GatewayExecutionEventError) as moved:
        pub.publish([order("o-1", "sb-1", status="partially_filled", filled="1")])
    assert moved.value.code == "EXECUTION_ROUTE_CONFLICT"
    assert len(events(journal, EXEC_A)) == 2 and events(journal, EXEC_B) == ()


def test_without_unattributed_scope_unroutable_observations_are_counted_not_written(tmp_path):
    journal = GatewayEventJournal(tmp_path / "gw.db")
    pub = publisher(journal, unattributed=None)
    result = pub.publish([order("o-7", None), trade("t-7", "o-7"), trade("t-8", None)])
    assert result.unattributed_dropped == 3 and pub.unattributed_dropped == 3
    assert result.appended == 0


def test_publisher_rejects_foreign_accounts_and_untyped_rows(tmp_path):
    journal = GatewayEventJournal(tmp_path / "gw.db")
    pub = publisher(journal)
    other = replace(order(), account_key=AccountKey("synthetic", "paper-exchange", "paper", "b"))
    for bad in ([other], [order().order], [{"kind": "trade"}]):
        with pytest.raises(GatewayExecutionEventError):
            pub.publish(bad)
    assert events(journal, EXEC_A) == ()
    with pytest.raises(GatewayExecutionEventError):
        GatewayExecutionScopePolicy({"sa-": EXEC_A}, unattributed_scope=EXEC_A)


def test_journal_refuses_a_digest_that_does_not_match_the_payload(tmp_path):
    journal = GatewayEventJournal(tmp_path / "gw.db")
    with pytest.raises(GatewayEventJournalError) as error:
        journal.append_execution_fact(
            ACCOUNT_SCOPE, EXEC_A, "xo-1", "k", {"fact_digest": "a"}, fact_digest="b"
        )
    assert error.value.code == "EXECUTION_FACT_INVALID"


# -- account session worker -------------------------------------------------------


class ExecutionProvider(FakeProvider):
    """A local fake provider with a pending execution-event queue."""

    def __init__(self, observations):
        super().__init__(observations)
        self.pending: list[object] = []
        self.confirmed = 0
        self.fail_confirm = False

    def read_execution_observations(self, *, generation, timeout, limit):
        assert generation and timeout > 0 and limit > 0
        return tuple(self.pending[:limit])

    def confirm_execution_observations(self, *, generation, count):
        if self.fail_confirm:
            raise RuntimeError("confirm lost")
        del self.pending[:count]
        self.confirmed += count


def worker(tmp_path: Path, provider, clocks, **kwargs):
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=clocks.utc)
    guards = tmp_path / "guards"
    guards.mkdir(exist_ok=True)
    built = GatewayAccountSessionWorker(
        provider,
        journal,
        account_key=_identity(),
        journal_account_scope=ACCOUNT_SCOPE,
        state_scope=STATE_SCOPE,
        guard=LocalAccountSessionGuard(guards, _identity().account_key_id, "worker-a"),
        required_coverage=(_resource(),),
        clock=clocks.utc,
        monotonic_clock=clocks.mono,
        execution_publisher=kwargs.pop("execution_publisher", None) or publisher(journal),
        **kwargs,
    )
    return built, journal


def test_worker_drains_provider_events_and_confirms_only_after_commit(tmp_path):
    clocks = Clocks()
    provider = ExecutionProvider(
        [_observation(clocks, observation_id=f"obs-{i}") for i in range(4)]
    )
    built, journal = worker(tmp_path, provider, clocks)
    built.start()
    assert built.execution_status == "idle"
    provider.pending.extend([order(), trade(), order(status="filled", filled="1", quantity="1")])
    provider.fail_confirm = True
    built.maintain()  # appended, confirmation lost: the provider keeps them
    assert built.execution_status == "failed:EXECUTION_EVENTS_CONFIRM_FAILED"
    assert len(provider.pending) == 3 and len(events(journal, EXEC_A)) == 3
    provider.fail_confirm = False
    result = built.publish_execution_events()  # idempotent republication
    assert (result.appended, result.duplicates) == (0, 3)
    assert provider.pending == [] and provider.confirmed == 3
    assert built.execution_status == "published"
    assert built.ready  # account state unaffected by the execution drain
    built.close()


def test_worker_keeps_the_events_when_the_journal_refuses_them(tmp_path):
    clocks = Clocks()
    provider = ExecutionProvider([_observation(clocks, observation_id="obs-1")])
    built, journal = worker(tmp_path, provider, clocks)
    built.start()
    publisher(journal).publish([trade()])
    provider.pending.append(trade(price="99"))
    with pytest.raises(GatewayAccountSessionWorkerError) as error:
        built.publish_execution_events()
    assert error.value.code == "EXECUTION_FACT_CONFLICT"
    assert provider.pending and provider.confirmed == 0
    built.close()


def test_worker_validates_the_execution_publisher(tmp_path):
    clocks = Clocks()
    journal = GatewayEventJournal(tmp_path / "other.db")
    with pytest.raises(GatewayAccountSessionWorkerError) as wrong_journal:
        worker(tmp_path, ExecutionProvider([]), clocks, execution_publisher=publisher(journal))
    assert wrong_journal.value.code == "INVALID_EXECUTION_PUBLISHER"
    with pytest.raises(GatewayAccountSessionWorkerError) as no_capability:
        worker(tmp_path / "x", FakeProvider([]), clocks)
    assert no_capability.value.code == "PROVIDER_EXECUTION_EVENTS_UNAVAILABLE"
    state_journal = GatewayEventJournal(tmp_path / "y" / "gateway.db")
    clash = GatewayExecutionEventPublisher(
        state_journal,
        account_key=_identity(),
        journal_account_scope=ACCOUNT_SCOPE,
        policy=GatewayExecutionScopePolicy({"sa-": STATE_SCOPE}),
    )
    with pytest.raises(GatewayAccountSessionWorkerError) as conflict:
        worker(tmp_path / "y", ExecutionProvider([]), clocks, execution_publisher=clash)
    assert conflict.value.code in {"EXECUTION_SCOPE_CONFLICT", "INVALID_EXECUTION_PUBLISHER"}


# -- read service --------------------------------------------------------------------


def _service(journal, *scopes):
    account = GatewayServiceAccountScope(
        account_ref=ACCOUNT_REF,
        execution_domain_ref=DOMAIN,
        journal_account_scope=ACCOUNT_SCOPE,
        account_read_strategy_scope=STATE_SCOPE,
        execution_scope_map={"strategy-a": EXEC_A, "strategy-b": EXEC_B},
    )
    return GatewayReadService(
        journal,
        accounts={ACCOUNT_REF: account},
        principals={"client": principal(*(scopes or (EXEC_A, EXEC_B, STATE_SCOPE)))},
    )


def _call(service, operation, strategy, **arguments):
    return service.handle(
        operation,
        principal_ref="client",
        scope=WireScope(DOMAIN, account_ref=ACCOUNT_REF, strategy_ref=strategy),
        arguments=arguments,
        identity=WireIdentity(WireRole.STRATEGY_CLIENT, "client", strategy or "account"),
    )


def test_read_service_serves_tracked_execution_streams_per_strategy(tmp_path):
    journal = GatewayEventJournal(tmp_path / "gw.db")
    publisher(journal).publish([order(), trade(), order("o-2", "sb-2")])
    service = _service(journal)
    page = _call(
        service,
        "account.read_after",
        "strategy-a",
        stream="execution",
        cursor=None,
        limit=10,
        track_delivery=True,
    )
    assert [e["sequence"] for e in page["events"]] == [1, 2]
    assert "state_status" not in page and page["snapshot"] is None
    progress = page["consumer_progress"]
    assert progress["offered_cursor"] == 2 and progress["acknowledged_cursor"] == 0
    acked = _call(
        service,
        "account.ack",
        "strategy-a",
        stream="execution",
        stream_epoch=progress["stream_epoch"],
        cursor=2,
    )
    assert acked["consumer_progress"]["acknowledged_cursor"] == 2
    assert (
        _call(service, "account.progress", "strategy-a", stream="execution")["consumer_progress"][
            "acknowledged_cursor"
        ]
        == 2
    )
    assert _call(service, "account.head", "strategy-b", stream="execution")["latest_cursor"] == 1
    # The account stream (no ``stream`` argument) is unchanged.
    assert _call(service, "account.head", None)["latest_cursor"] == 0


def test_read_service_execution_stream_negative_matrix(tmp_path):
    journal = GatewayEventJournal(tmp_path / "gw.db")
    publisher(journal).publish([order()])
    with pytest.raises(GatewayServiceError) as unmapped:
        _call(_service(journal), "account.head", "strategy-z", stream="execution")
    assert unmapped.value.code == "EXECUTION_STREAM_NOT_CONFIGURED"
    with pytest.raises(GatewayServiceError) as unknown:
        _call(_service(journal), "account.head", "strategy-a", stream="orders")
    assert unknown.value.code == "UNKNOWN_STREAM"
    with pytest.raises(GatewayEventJournalError) as denied:
        _call(_service(journal, EXEC_B), "account.read_after", "strategy-a", stream="execution")
    assert denied.value.code == "STRATEGY_SCOPE_DENIED"
    with pytest.raises(GatewayServiceError) as snapshot:
        _call(_service(journal), "account.snapshot", None, stream="execution")
    assert snapshot.value.code == "UNKNOWN_ARGUMENT"
    with pytest.raises(GatewayServiceError):
        GatewayServiceAccountScope(
            account_ref=ACCOUNT_REF,
            execution_domain_ref=DOMAIN,
            journal_account_scope=ACCOUNT_SCOPE,
            account_read_strategy_scope=STATE_SCOPE,
            execution_scope_map={"strategy-a": STATE_SCOPE},
        )
