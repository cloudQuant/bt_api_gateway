"""Synthetic lifecycle tests for trusted account-view projections."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from bt_api_base.account_protocol import (
    AccountBalance,
    AccountKey,
    AccountObservation,
    AccountPosition,
    AccountResourceKey,
)
from bt_api_base.market_protocol import MarketInstrumentKey

from bt_api_gateway import GatewayCommandKind, GatewayEventJournal, GatewayPrincipal
from bt_api_gateway.account_session_worker import (
    GatewayAccountSessionWorker,
    GatewayAccountSessionWorkerError,
)
from bt_api_gateway.account_view_projection import GatewayAccountViewPolicy
from bt_api_gateway.session_guard import LocalAccountSessionGuard


class Clocks:
    def __init__(self) -> None:
        self.wall = 1_800_000_000.0
        self.monotonic = 100.0

    def utc(self) -> float:
        return self.wall

    def mono(self) -> float:
        return self.monotonic

    def advance(self, seconds: float) -> None:
        self.wall += seconds
        self.monotonic += seconds

    def timestamp(self) -> str:
        return datetime.fromtimestamp(self.wall, timezone.utc).isoformat().replace("+00:00", "Z")


class FakeProvider:
    def __init__(self, observations: list[AccountObservation]) -> None:
        self.observations = list(observations)
        self.connect_generations: list[str] = []
        self.close_calls = 0

    def connect(self, *, account_key: AccountKey, generation: str, timeout: float) -> None:
        assert type(account_key) is AccountKey
        assert timeout > 0
        self.connect_generations.append(generation)

    def read_account(self, *, generation: str, timeout: float) -> AccountObservation:
        assert generation == self.connect_generations[-1]
        assert timeout > 0
        return self.observations.pop(0)

    def close(self) -> None:
        self.close_calls += 1


def _account_key() -> AccountKey:
    return AccountKey(
        provider="synthetic",
        venue="paper-exchange",
        environment="paper",
        account_id="acct-a",
    )


def _resource() -> AccountResourceKey:
    return AccountResourceKey(product_type="spot", margin_pool="cross")


def _instrument() -> MarketInstrumentKey:
    return MarketInstrumentKey(
        provider="synthetic",
        venue="paper-exchange",
        environment="paper",
        product_type="spot",
        instrument_id="BTC-USD",
        native_symbol="BTCUSD",
    )


def _observation(
    clocks: Clocks,
    *,
    observation_id: str,
    balance_total: str = "100",
    position_quantity: str = "2",
    balances_complete: bool = True,
    positions_complete: bool = True,
) -> AccountObservation:
    timestamp = clocks.timestamp()
    resource = _resource()
    balance = AccountBalance(
        resource=resource,
        currency="USD",
        total=balance_total,
        available=str(float(balance_total) - 10),
        locked="10",
        observed_at_utc=timestamp,
    )
    position = AccountPosition(
        resource=resource,
        instrument=_instrument(),
        side="net",
        quantity=position_quantity,
        qty_unit="contract",
        average_price="10",
        price_currency="USD",
        observed_at_utc=timestamp,
    )
    return AccountObservation(
        account_key=_account_key(),
        observation_id=observation_id,
        coverage=(resource,),
        balances=(balance,),
        positions=(position,),
        valuation=None,
        started_at_utc=timestamp,
        completed_at_utc=timestamp,
        consistency="multi_query",
        balances_complete=balances_complete,
        positions_complete=positions_complete,
    )


def _policies() -> tuple[GatewayAccountViewPolicy, ...]:
    resource = _resource()
    return (
        GatewayAccountViewPolicy(
            view_scope="strategy:account-positions",
            resources=(resource,),
            fact_kinds=frozenset({"positions"}),
        ),
        GatewayAccountViewPolicy(
            view_scope="strategy:account-balances",
            resources=(resource,),
            fact_kinds=frozenset({"balances"}),
        ),
    )


def _worker(
    tmp_path: Path,
    provider: FakeProvider,
    clocks: Clocks,
    *,
    view_policies: tuple[GatewayAccountViewPolicy, ...],
) -> tuple[GatewayAccountSessionWorker, GatewayEventJournal]:
    account_key = _account_key()
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=clocks.utc)
    guard_directory = tmp_path / "session-guards"
    guard_directory.mkdir(exist_ok=True)
    guard = LocalAccountSessionGuard(guard_directory, account_key.account_key_id, "view-worker")
    worker = GatewayAccountSessionWorker(
        provider,
        journal,
        account_key=account_key,
        journal_account_scope="account:shared",
        state_scope="strategy:account-facts",
        guard=guard,
        required_coverage=(_resource(),),
        view_policies=view_policies,
        refresh_interval_seconds=1.0,
        max_staleness_seconds=5.0,
        request_timeout_seconds=2.0,
        clock=clocks.utc,
        monotonic_clock=clocks.mono,
    )
    return worker, journal


def _read_view(journal: GatewayEventJournal, view_scope: str):
    principal = GatewayPrincipal(
        principal_id="view-test",
        account_scopes=frozenset({"account:shared"}),
        strategy_scopes=frozenset({view_scope}),
        allowed_kinds=frozenset({GatewayCommandKind.READ}),
    )
    return journal.read_after(
        principal,
        "account:shared",
        view_scope,
        cursor=None,
        limit=100,
    )


def test_worker_updates_multiple_views_atomically_across_failed_read_and_restart(
    tmp_path: Path,
) -> None:
    clocks = Clocks()
    initial = _observation(clocks, observation_id="initial")
    clocks.advance(1)
    incomplete = _observation(
        clocks,
        observation_id="incomplete",
        balance_total="105",
        balances_complete=False,
    )
    clocks.advance(1)
    recovered = _observation(
        clocks,
        observation_id="recovered",
        balance_total="110",
        position_quantity="3",
    )
    policies = _policies()
    provider = FakeProvider([initial, incomplete, recovered])
    worker, journal = _worker(tmp_path, provider, clocks, view_policies=policies)

    worker.start()

    assert worker.ready is True
    assert len(provider.connect_generations) == 1
    assert worker.view_policies == tuple(sorted(policies, key=lambda item: item.view_scope))
    assert isinstance(worker.view_policies, tuple)
    with pytest.raises(AttributeError):
        worker.view_policies = ()  # type: ignore[misc]

    positions_before = _read_view(journal, "strategy:account-positions")
    balances_before = _read_view(journal, "strategy:account-balances")
    assert positions_before.snapshot is not None
    assert balances_before.snapshot is not None
    assert positions_before.snapshot.cursor == balances_before.snapshot.cursor == 1
    assert positions_before.latest_cursor == balances_before.latest_cursor == 1
    assert positions_before.events == balances_before.events == ()
    assert positions_before.snapshot.payload["positions"][0]["quantity"] == "2"
    assert balances_before.snapshot.payload["balances"][0]["total"] == "100"
    for view in (positions_before.snapshot.payload, balances_before.snapshot.payload):
        assert view["view_scope"] in {
            "strategy:account-positions",
            "strategy:account-balances",
        }
        assert view["consistency"] == "multi_query"
        assert "policy_digest" not in view
        assert "session_generation" not in view
        assert "observation_id" not in view
    for batch in (positions_before, balances_before):
        assert batch.snapshot is not None
        assert "initial" not in batch.snapshot.snapshot_id
        assert all(
            generation not in batch.snapshot.snapshot_id
            for generation in provider.connect_generations
        )
        assert all(policy.digest not in batch.snapshot.snapshot_id for policy in policies)

    clocks.advance(1)
    with pytest.raises(GatewayAccountSessionWorkerError) as failure:
        worker.refresh()
    assert failure.value.code == "OBSERVATION_INCOMPLETE"
    assert worker.ready is False

    positions_after_failure = _read_view(journal, "strategy:account-positions")
    balances_after_failure = _read_view(journal, "strategy:account-balances")
    assert positions_after_failure.snapshot == positions_before.snapshot
    assert balances_after_failure.snapshot == balances_before.snapshot
    assert positions_after_failure.events == balances_after_failure.events == ()
    assert positions_after_failure.latest_cursor == balances_after_failure.latest_cursor == 1

    clocks.advance(1)
    worker.recover()

    assert worker.ready is True
    assert len(provider.connect_generations) == 2
    assert provider.connect_generations[0] != provider.connect_generations[1]
    assert worker.latest_snapshot is not None
    assert worker.latest_snapshot.cursor == 2

    positions_after_recovery = _read_view(journal, "strategy:account-positions")
    balances_after_recovery = _read_view(journal, "strategy:account-balances")
    assert positions_after_recovery.snapshot is not None
    assert balances_after_recovery.snapshot is not None
    assert positions_after_recovery.snapshot.cursor == balances_after_recovery.snapshot.cursor == 1
    assert positions_after_recovery.latest_cursor == balances_after_recovery.latest_cursor == 2
    assert len(positions_after_recovery.events) == len(balances_after_recovery.events) == 1
    assert positions_after_recovery.events[0].sequence == 2
    assert balances_after_recovery.events[0].sequence == 2
    assert positions_after_recovery.events[0].kind == "account.view_delta"
    assert balances_after_recovery.events[0].kind == "account.view_delta"
    assert "policy_digest" not in positions_after_recovery.events[0].payload
    assert "policy_digest" not in balances_after_recovery.events[0].payload
    assert all(
        generation not in event.event_id
        for batch in (positions_after_recovery, balances_after_recovery)
        for event in batch.events
        for generation in provider.connect_generations
    )
    assert (
        positions_after_recovery.events[0].payload["changes"]["positions"]["upsert"][0]["quantity"]
        == "3"
    )
    assert (
        balances_after_recovery.events[0].payload["changes"]["balances"]["upsert"][0]["total"]
        == "110"
    )
    assert (
        journal.account_view_is_current(
            "account:shared",
            "strategy:account-facts",
            "strategy:account-positions",
            policies[0].digest,
            source_cursor=2,
            view_cursor=2,
        )
        is True
    )
    worker.close()
    assert provider.close_calls == 2


def test_worker_rejects_policy_omission_before_provider_connect(tmp_path: Path) -> None:
    clocks = Clocks()
    policies = _policies()
    provider = FakeProvider([_observation(clocks, observation_id="initial")])
    worker, journal = _worker(tmp_path, provider, clocks, view_policies=policies)
    worker.start()
    worker.close()
    assert provider.connect_generations

    guard_directory = tmp_path / "session-guards"
    new_provider = FakeProvider([])
    replacement = GatewayAccountSessionWorker(
        new_provider,
        journal,
        account_key=_account_key(),
        journal_account_scope="account:shared",
        state_scope="strategy:account-facts",
        guard=LocalAccountSessionGuard(
            guard_directory, _account_key().account_key_id, "view-worker"
        ),
        required_coverage=(_resource(),),
        view_policies=(),
        clock=clocks.utc,
        monotonic_clock=clocks.mono,
    )

    with pytest.raises(GatewayAccountSessionWorkerError) as failure:
        replacement.start()
    assert failure.value.code == "VIEW_POLICY_MISMATCH"
    assert new_provider.connect_generations == []
    replacement.close()


def test_worker_rejects_view_scope_collision_and_uncovered_resource(tmp_path: Path) -> None:
    clocks = Clocks()
    provider = FakeProvider([])
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=clocks.utc)
    guard_directory = tmp_path / "session-guards"
    guard_directory.mkdir()

    with pytest.raises(GatewayAccountSessionWorkerError) as collision:
        GatewayAccountSessionWorker(
            provider,
            journal,
            account_key=_account_key(),
            journal_account_scope="account:shared",
            state_scope="strategy:account-facts",
            guard=LocalAccountSessionGuard(guard_directory, _account_key().account_key_id, "a"),
            required_coverage=(_resource(),),
            view_policies=(
                GatewayAccountViewPolicy(
                    view_scope="strategy:account-facts",
                    resources=(_resource(),),
                    fact_kinds=frozenset({"balances"}),
                ),
            ),
        )
    assert collision.value.code == "VIEW_SCOPE_CONFLICT"

    uncovered = AccountResourceKey(product_type="linear_future", margin_pool="cross")
    with pytest.raises(GatewayAccountSessionWorkerError) as coverage:
        GatewayAccountSessionWorker(
            provider,
            journal,
            account_key=_account_key(),
            journal_account_scope="account:shared",
            state_scope="strategy:account-facts",
            guard=LocalAccountSessionGuard(guard_directory, _account_key().account_key_id, "b"),
            required_coverage=(_resource(),),
            view_policies=(
                GatewayAccountViewPolicy(
                    view_scope="strategy:account-uncovered",
                    resources=(uncovered,),
                    fact_kinds=frozenset({"balances"}),
                ),
            ),
        )
    assert coverage.value.code == "VIEW_POLICY_COVERAGE_MISMATCH"


def test_open_order_view_requires_explicit_complete_provider_facts(tmp_path: Path) -> None:
    clocks = Clocks()
    policy = GatewayAccountViewPolicy(
        view_scope="strategy:account-open-orders",
        resources=(_resource(),),
        fact_kinds=frozenset({"open_orders"}),
    )
    provider = FakeProvider([_observation(clocks, observation_id="unknown-orders")])
    worker, journal = _worker(tmp_path, provider, clocks, view_policies=(policy,))

    with pytest.raises(GatewayAccountSessionWorkerError) as failure:
        worker.start()
    assert failure.value.code == "OBSERVATION_OPEN_ORDERS_INCOMPLETE"
    assert worker.ready is False
    assert worker.latest_snapshot is None
    assert provider.connect_generations
    worker.close()
    assert provider.close_calls == 1
    view_batch = _read_view(journal, policy.view_scope)
    assert view_batch.snapshot is None
    assert view_batch.events == ()
    assert view_batch.latest_cursor == 0
