"""Synthetic provider tests for the shared account-session worker."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Optional

import pytest
from bt_api_base.account_protocol import (
    AccountBalance,
    AccountKey,
    AccountObservation,
    AccountOpenOrder,
    AccountPosition,
    AccountResourceKey,
)
from bt_api_base.market_protocol import MarketInstrumentKey
from bt_api_base.service_protocol import WireScope

from bt_api_gateway import GatewayCommandKind, GatewayEventJournal, GatewayPrincipal
from bt_api_gateway.account_session_worker import (
    GatewayAccountSessionWorker,
    GatewayAccountSessionWorkerError,
)
from bt_api_gateway.event_journal import GatewayEventJournalError
from bt_api_gateway.service_component import (
    GatewayReadService,
    GatewayServiceAccountScope,
    GatewayServiceError,
)
from bt_api_gateway.session_guard import (
    LocalAccountSessionGuard,
    LocalAccountSessionGuardError,
)


class Clocks:
    def __init__(self, wall: float = 1_800_000_000.0, monotonic: float = 100.0) -> None:
        self.wall = wall
        self.monotonic = monotonic

    def utc(self) -> float:
        return self.wall

    def mono(self) -> float:
        return self.monotonic

    def advance(self, seconds: float) -> None:
        self.wall += seconds
        self.monotonic += seconds

    def timestamp(self, offset: float = 0.0) -> str:
        value = datetime.fromtimestamp(self.wall + offset, timezone.utc)
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")


class FakeProvider:
    def __init__(self, observations: list[object]) -> None:
        self.observations = list(observations)
        self.connect_generations: list[str] = []
        self.read_generations: list[str] = []
        self.read_calls = 0
        self.close_results: list[object] = []
        self.close_calls = 0
        self.connect_hook = None
        self.read_hook = None

    def connect(self, *, account_key: AccountKey, generation: str, timeout: float) -> None:
        assert type(account_key) is AccountKey
        assert timeout > 0
        self.connect_generations.append(generation)
        if self.connect_hook is not None:
            self.connect_hook()

    def read_account(self, *, generation: str, timeout: float) -> AccountObservation:
        assert timeout > 0
        self.read_calls += 1
        self.read_generations.append(generation)
        if self.read_hook is not None:
            self.read_hook()
        value = self.observations.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value  # type: ignore[return-value]

    def close(self) -> Optional[bool]:  # noqa: UP045 -- Python 3.9 support.
        self.close_calls += 1
        if self.close_results:
            value = self.close_results.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value  # type: ignore[return-value]
        return None


def _identity(account_id: str = "acct-a") -> AccountKey:
    return AccountKey(
        provider="synthetic",
        venue="paper-exchange",
        environment="paper",
        account_id=account_id,
    )


def _resource(product_type: str = "spot") -> AccountResourceKey:
    return AccountResourceKey(product_type=product_type, margin_pool="cross")


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
    account_key: Optional[AccountKey] = None,  # noqa: UP045 -- Python 3.9 support.
    coverage: Optional[tuple[AccountResourceKey, ...]] = None,  # noqa: UP045
    positions: tuple[AccountPosition, ...] = (),
    balances_complete: bool = True,
    positions_complete: bool = True,
    open_orders: Optional[tuple[AccountOpenOrder, ...]] = None,  # noqa: UP045
    open_orders_complete: bool = False,
    row_timestamp: Optional[str] = None,  # noqa: UP045
    started_at_utc: Optional[str] = None,  # noqa: UP045
    completed_at_utc: Optional[str] = None,  # noqa: UP045
) -> AccountObservation:
    identity = account_key or _identity()
    resource = _resource()
    timestamp = row_timestamp or clocks.timestamp()
    balance = AccountBalance(
        resource=resource,
        currency="USD",
        total="100",
        available="90",
        locked="10",
        observed_at_utc=timestamp,
    )
    return AccountObservation(
        account_key=identity,
        observation_id=observation_id,
        coverage=(resource,) if coverage is None else coverage,
        balances=(balance,),
        positions=positions,
        valuation=None,
        started_at_utc=started_at_utc or clocks.timestamp(),
        completed_at_utc=completed_at_utc or clocks.timestamp(),
        consistency="multi_query",
        balances_complete=balances_complete,
        positions_complete=positions_complete,
        open_orders=open_orders,
        open_orders_complete=open_orders_complete,
    )


def _position(clocks: Clocks, quantity: str = "2") -> AccountPosition:
    return AccountPosition(
        resource=_resource(),
        instrument=_instrument(),
        side="net",
        quantity=quantity,
        qty_unit="contract",
        average_price="10",
        price_currency="USD",
        observed_at_utc=clocks.timestamp(),
    )


def _open_order(
    clocks: Clocks,
    *,
    order_id: str = "order-1",
    observed_at_utc: Optional[str] = None,  # noqa: UP045
    created_at_utc: Optional[str] = None,  # noqa: UP045
) -> AccountOpenOrder:
    observed_at = observed_at_utc or clocks.timestamp()
    created_at = created_at_utc or clocks.timestamp(-1.0)
    return AccountOpenOrder(
        resource=_resource(),
        instrument=_instrument(),
        order_id=order_id,
        side="buy",
        position_side="net",
        order_type="limit",
        status="partially_filled",
        quantity="4",
        filled_quantity="1",
        qty_unit="contract",
        created_at_utc=created_at,
        observed_at_utc=observed_at,
        client_order_id="client-order-1",
        limit_price="100",
        stop_price=None,
        price_currency="USD",
        reduce_only=False,
    )


def _worker(
    tmp_path: Path,
    provider: FakeProvider,
    clocks: Clocks,
    *,
    account_key: Optional[AccountKey] = None,  # noqa: UP045
    required_coverage: Optional[tuple[AccountResourceKey, ...]] = None,  # noqa: UP045
    require_open_orders: bool = False,
    max_staleness_seconds: float = 5.0,
    request_timeout_seconds: float = 2.0,
    guard: Optional[LocalAccountSessionGuard] = None,  # noqa: UP045
) -> tuple[GatewayAccountSessionWorker, GatewayEventJournal]:
    identity = account_key or _identity()
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=clocks.utc)
    guard_directory = tmp_path / "session-guards"
    guard_directory.mkdir(exist_ok=True)
    session_guard = guard or LocalAccountSessionGuard(
        guard_directory, identity.account_key_id, "worker-a"
    )
    worker = GatewayAccountSessionWorker(
        provider,
        journal,
        account_key=identity,
        journal_account_scope="account:shared",
        state_scope="strategy:account-facts",
        guard=session_guard,
        required_coverage=required_coverage or (_resource(),),
        require_open_orders=require_open_orders,
        refresh_interval_seconds=1.0,
        max_staleness_seconds=max_staleness_seconds,
        request_timeout_seconds=request_timeout_seconds,
        clock=clocks.utc,
        monotonic_clock=clocks.mono,
    )
    return worker, journal


def _journal_row_counts(journal: GatewayEventJournal) -> tuple[int, int]:
    with sqlite3.connect(journal._database_path) as connection:  # type: ignore[attr-defined]
        events = connection.execute("SELECT COUNT(*) FROM gateway_events").fetchone()[0]
        dedupe = connection.execute("SELECT COUNT(*) FROM gateway_event_dedupe").fetchone()[0]
    return int(events), int(dedupe)


def test_worker_publishes_complete_replacements_without_event_or_dedupe_growth(tmp_path) -> None:
    clocks = Clocks()
    with_position = _observation(
        clocks,
        observation_id="obs-1",
        positions=(_position(clocks),),
    )
    empty_positions = _observation(clocks, observation_id="obs-2", positions=())
    provider = FakeProvider([with_position, empty_positions])
    worker, journal = _worker(tmp_path, provider, clocks)

    worker.start()
    first = worker.latest_snapshot
    assert first is not None
    assert first.cursor == 1
    assert len(first.payload["observation"]["positions"]) == 1  # type: ignore[index]
    assert worker.ready is True

    clocks.advance(1.1)
    worker.maintain()
    second = worker.latest_snapshot
    assert second is not None
    assert second.cursor == 2
    assert second.payload["observation"]["positions"] == ()  # type: ignore[index]
    assert provider.connect_generations == [worker.session_generation]
    assert provider.read_calls == 2
    assert _journal_row_counts(journal) == (0, 0)

    worker.close()
    assert worker.state == "closed"


def test_complete_open_orders_snapshot_replaces_orders_with_complete_empty_state(tmp_path) -> None:
    clocks = Clocks()
    with_order = _observation(
        clocks,
        observation_id="open-order-present",
        open_orders=(_open_order(clocks),),
        open_orders_complete=True,
    )
    empty_orders = _observation(
        clocks,
        observation_id="open-order-empty",
        open_orders=(),
        open_orders_complete=True,
    )
    provider = FakeProvider([with_order, empty_orders])
    worker, _ = _worker(tmp_path, provider, clocks, require_open_orders=True)

    worker.start()
    first = worker.latest_snapshot
    assert first is not None
    assert first.payload["schema_version"] == 2
    assert len(first.payload["observation"]["open_orders"]) == 1  # type: ignore[index]
    assert first.payload["observation"]["open_orders_complete"] is True  # type: ignore[index]
    assert worker.ready is True

    clocks.advance(1.1)
    snapshot = worker.refresh()

    assert snapshot.cursor == 2
    assert snapshot.payload["schema_version"] == 2
    assert snapshot.payload["observation"]["open_orders"] == ()  # type: ignore[index]
    assert snapshot.payload["observation"]["open_orders_complete"] is True  # type: ignore[index]
    assert worker.ready is True
    assert provider.connect_generations == [worker.session_generation]
    assert provider.read_calls == 2
    worker.close()


@pytest.mark.parametrize("include_orders", [False, True])
def test_required_open_orders_rejects_missing_or_incomplete_observation(
    tmp_path, include_orders
) -> None:
    clocks = Clocks()
    observation = _observation(
        clocks,
        observation_id=f"orders-incomplete-{include_orders}",
        open_orders=(_open_order(clocks),) if include_orders else None,
        open_orders_complete=False,
    )
    provider = FakeProvider([observation])
    worker, _ = _worker(tmp_path, provider, clocks, require_open_orders=True)

    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        worker.start()

    assert raised.value.code == "OBSERVATION_OPEN_ORDERS_INCOMPLETE"
    assert worker.ready is False
    assert worker.latest_snapshot is None
    assert provider.connect_generations == [worker.session_generation]
    assert provider.read_calls == 1
    worker.close()


def test_stale_open_order_row_prevents_ready_snapshot(tmp_path) -> None:
    clocks = Clocks()
    stale_order = _open_order(
        clocks,
        observed_at_utc=clocks.timestamp(-10.0),
        created_at_utc=clocks.timestamp(-11.0),
    )
    provider = FakeProvider(
        [
            _observation(
                clocks,
                observation_id="stale-open-order",
                open_orders=(stale_order,),
                open_orders_complete=True,
            )
        ]
    )
    worker, _ = _worker(tmp_path, provider, clocks, require_open_orders=True)

    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        worker.start()

    assert raised.value.code == "OBSERVATION_STALE"
    assert worker.ready is False
    assert worker.latest_snapshot is None
    worker.close()


def test_new_observation_id_does_not_extend_freshness_of_unchanged_open_order(tmp_path) -> None:
    clocks = Clocks()
    old_order = _open_order(clocks)
    first = _observation(
        clocks,
        observation_id="open-order-original-time",
        open_orders=(old_order,),
        open_orders_complete=True,
    )
    repeated_order = _observation(
        clocks,
        observation_id="open-order-new-observation-id",
        open_orders=(old_order,),
        open_orders_complete=True,
    )
    provider = FakeProvider([first, repeated_order])
    worker, _ = _worker(tmp_path, provider, clocks, require_open_orders=True)
    worker.start()

    clocks.advance(4.0)
    worker.refresh()
    status = worker.read_status()
    assert status["ready"] is True
    assert status["fresh_for_seconds"] == pytest.approx(1.0)

    clocks.advance(1.1)
    status = worker.read_status()
    assert status["ready"] is False
    assert status["fresh_for_seconds"] == 0.0
    assert worker.latest_snapshot is not None
    assert worker.latest_snapshot.cursor == 2
    worker.close()


def test_order_row_timestamps_cannot_regress_on_a_new_observation_id(tmp_path) -> None:
    clocks = Clocks()
    first = _observation(
        clocks,
        observation_id="order-row-time-1",
        open_orders=(_open_order(clocks),),
        open_orders_complete=True,
    )
    provider = FakeProvider([first])
    worker, _ = _worker(tmp_path, provider, clocks, require_open_orders=True)
    worker.start()

    clocks.advance(2.0)
    regressed_order = _open_order(
        clocks,
        observed_at_utc=clocks.timestamp(-3.0),
        created_at_utc=clocks.timestamp(-4.0),
    )
    provider.observations.append(
        _observation(
            clocks,
            observation_id="order-row-time-2",
            open_orders=(regressed_order,),
            open_orders_complete=True,
        )
    )
    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        worker.refresh()

    assert raised.value.code == "ROW_OBSERVATION_TIME_REGRESSED"
    assert worker.latest_snapshot is not None
    assert worker.latest_snapshot.cursor == 1
    assert worker.latest_snapshot.payload["schema_version"] == 2
    assert worker.ready is False
    worker.close()


def test_legacy_observation_roundtrips_as_schema_v1_after_restart(tmp_path) -> None:
    clocks = Clocks()
    sample = _observation(clocks, observation_id="legacy-v1")
    assert "open_orders" not in sample.to_dict()
    assert "open_orders_complete" not in sample.to_dict()
    first, _ = _worker(tmp_path, FakeProvider([sample]), clocks)
    first.start()
    old_snapshot = first.latest_snapshot
    assert old_snapshot is not None
    assert old_snapshot.payload["schema_version"] == 1
    first.close()

    second, _ = _worker(tmp_path, FakeProvider([sample]), clocks)
    second.start()
    new_snapshot = second.latest_snapshot
    assert new_snapshot is not None
    assert new_snapshot.cursor == 2
    assert new_snapshot.payload["schema_version"] == 1
    assert "open_orders" not in new_snapshot.payload["observation"]
    assert "open_orders_complete" not in new_snapshot.payload["observation"]
    assert second.ready is True
    second.close()


def test_recovery_reentry_during_provider_connect_is_rejected(tmp_path) -> None:
    clocks = Clocks()
    provider = FakeProvider([_observation(clocks, observation_id="connect-reentry")])
    worker, _ = _worker(tmp_path, provider, clocks)
    provider.connect_hook = worker.recover

    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        worker.start()

    assert raised.value.code == "RECOVERY_DURING_CONNECT"
    assert len(provider.connect_generations) == 1
    assert provider.read_calls == 0
    provider.connect_hook = None
    worker.close()


def test_one_guard_object_cannot_be_bound_to_two_workers(tmp_path) -> None:
    clocks = Clocks()
    first_provider = FakeProvider([_observation(clocks, observation_id="first-owner")])
    first, _ = _worker(tmp_path, first_provider, clocks)
    second_provider = FakeProvider([_observation(clocks, observation_id="second-owner")])

    with pytest.raises(LocalAccountSessionGuardError) as raised:
        _worker(tmp_path, second_provider, clocks, guard=first._guard)

    assert raised.value.code == "SESSION_CONSUMER_CONFLICT"
    assert second_provider.connect_generations == []
    assert first_provider.connect_generations == []
    first.start()
    assert len(first_provider.connect_generations) == 1
    first.close()


def test_worker_rejects_guard_bound_to_another_account_before_connect(tmp_path) -> None:
    clocks = Clocks()
    identity = _identity("acct-a")
    provider = FakeProvider([_observation(clocks, observation_id="wrong-guard-account")])
    guard_directory = tmp_path / "session-guards"
    guard_directory.mkdir()
    wrong_account_guard = LocalAccountSessionGuard(
        guard_directory, _identity("acct-b").account_key_id, "worker-wrong-account"
    )

    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        _worker(tmp_path, provider, clocks, account_key=identity, guard=wrong_account_guard)

    assert raised.value.code == "SESSION_GUARD_ACCOUNT_MISMATCH"
    assert provider.connect_generations == []
    assert provider.read_calls == 0
    assert provider.close_calls == 0


def test_identical_latest_observation_coalesces_without_advancing_cursor(tmp_path) -> None:
    clocks = Clocks()
    sample = _observation(clocks, observation_id="obs-same")
    provider = FakeProvider([sample, sample])
    worker, journal = _worker(tmp_path, provider, clocks)

    worker.start()
    first = worker.latest_snapshot
    clocks.advance(0.1)
    repeated = worker.refresh()

    assert first is repeated
    assert worker.latest_snapshot is not None
    assert worker.latest_snapshot.cursor == 1
    assert provider.read_calls == 2
    assert _journal_row_counts(journal) == (0, 0)
    worker.close()


def test_duplicate_observation_cannot_extend_freshness_after_utc_moves_backwards(
    tmp_path,
) -> None:
    clocks = Clocks()
    sample = _observation(clocks, observation_id="fixed-observation-time")
    provider = FakeProvider([sample, sample])
    worker, _ = _worker(tmp_path, provider, clocks)
    worker.start()

    clocks.advance(4.0)
    clocks.wall -= 3.0
    worker.refresh()
    status = worker.read_status()
    assert status["ready"] is True
    assert status["fresh_for_seconds"] == pytest.approx(1.0)

    clocks.advance(1.1)
    status = worker.read_status()
    assert status["ready"] is False
    assert status["fresh_for_seconds"] == 0.0
    assert worker.latest_snapshot is not None
    assert worker.latest_snapshot.cursor == 1
    worker.close()


def test_new_observation_cannot_rejuvenate_old_provider_times_after_utc_rollback(tmp_path) -> None:
    clocks = Clocks()
    sample = _observation(clocks, observation_id="first-provider-time")
    newer_id_same_times = replace(sample, observation_id="new-id-same-provider-times")
    provider = FakeProvider([sample, newer_id_same_times])
    worker, _ = _worker(tmp_path, provider, clocks)
    worker.start()

    clocks.advance(4.0)
    clocks.wall -= 3.0
    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        worker.refresh()

    assert raised.value.code == "WALL_CLOCK_REGRESSED"
    assert worker.latest_snapshot is not None
    assert worker.latest_snapshot.cursor == 1
    assert worker.ready is False
    worker.close()


def test_reused_latest_observation_id_with_changed_content_is_rejected(tmp_path) -> None:
    clocks = Clocks()
    sample = _observation(clocks, observation_id="obs-reused")
    changed_balance = replace(sample.balances[0], total="101")
    changed = replace(sample, balances=(changed_balance,))
    provider = FakeProvider([sample, changed])
    worker, _ = _worker(tmp_path, provider, clocks)
    worker.start()

    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        worker.refresh()

    assert raised.value.code == "OBSERVATION_ID_REUSED"
    assert worker.latest_snapshot is not None
    assert worker.latest_snapshot.cursor == 1
    assert worker.ready is False
    worker.close()


@pytest.mark.parametrize(
    "observation_factory,expected_code",
    [
        (
            lambda clocks: _observation(
                clocks, observation_id="wrong-account", account_key=_identity("acct-b")
            ),
            "OBSERVATION_ACCOUNT_MISMATCH",
        ),
        (
            lambda clocks: _observation(clocks, observation_id="partial", positions_complete=False),
            "OBSERVATION_INCOMPLETE",
        ),
        (
            lambda clocks: _observation(
                clocks,
                observation_id="stale",
                row_timestamp=clocks.timestamp(-10),
            ),
            "OBSERVATION_STALE",
        ),
        (
            lambda clocks: _observation(
                clocks,
                observation_id="narrow",
                coverage=(_resource(), _resource("linear")),
            ),
            "OBSERVATION_COVERAGE_MISMATCH",
        ),
    ],
)
def test_worker_rejects_wrong_incomplete_stale_or_unrequested_observation(
    tmp_path, observation_factory, expected_code
) -> None:
    clocks = Clocks()
    provider = FakeProvider([observation_factory(clocks)])
    worker, _ = _worker(tmp_path, provider, clocks)

    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        worker.start()
    assert raised.value.code == expected_code
    assert worker.ready is False
    assert worker.latest_snapshot is None
    worker.close()
    assert provider.close_calls == 1


def test_worker_rejects_late_provider_reply_and_preserves_resources_for_close(tmp_path) -> None:
    clocks = Clocks()
    provider = FakeProvider([_observation(clocks, observation_id="late")])
    worker, _ = _worker(tmp_path, provider, clocks, request_timeout_seconds=0.5)
    provider.read_hook = lambda: clocks.advance(0.6)

    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        worker.start()

    assert raised.value.code == "PROVIDER_RESPONSE_LATE"
    assert worker.session_generation is not None
    assert worker.ready is False
    worker.close()
    assert provider.close_calls == 1


def test_restart_uses_new_generation_and_old_persisted_state_is_not_ready(tmp_path) -> None:
    clocks = Clocks()
    first_provider = FakeProvider([_observation(clocks, observation_id="before-restart")])
    first, journal = _worker(tmp_path, first_provider, clocks)
    first.start()
    old_snapshot = first.latest_snapshot
    assert old_snapshot is not None
    old_generation = first.session_generation
    first.close()

    failed_provider = FakeProvider([RuntimeError("private provider detail")])
    second, _ = _worker(tmp_path, failed_provider, clocks)
    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        second.start()

    assert raised.value.code == "PROVIDER_READ_FAILED"
    assert second.session_generation != old_generation
    assert second.latest_snapshot == old_snapshot
    assert second.latest_snapshot is not None
    assert second.latest_snapshot.payload["session_generation"] == old_generation
    assert second.read_status() == {
        "session_generation": second.session_generation,
        "ready": False,
        "fresh_for_seconds": 0.0,
    }
    second.close()
    assert (
        journal.read_after(
            GatewayPrincipal(
                principal_id="test-reader",
                account_scopes=frozenset({"account:shared"}),
                strategy_scopes=frozenset({"strategy:account-facts"}),
                allowed_kinds=frozenset({GatewayCommandKind.READ}),
            ),
            "account:shared",
            "strategy:account-facts",
        ).latest_cursor
        == 1
    )


def test_restart_rejects_older_complete_empty_snapshot_against_persisted_floor(tmp_path) -> None:
    clocks = Clocks()
    initial = replace(
        _observation(
            clocks,
            observation_id="persisted-position",
            positions=(_position(clocks),),
        ),
        balances=(),
    )
    first_provider = FakeProvider([initial])
    first, _ = _worker(tmp_path, first_provider, clocks)
    first.start()
    old_snapshot = first.latest_snapshot
    assert old_snapshot is not None
    first.close()

    clocks.advance(2.0)
    older_empty = replace(
        _observation(
            clocks,
            observation_id="older-empty-after-restart",
            positions=(),
            row_timestamp=clocks.timestamp(-3.0),
            started_at_utc=clocks.timestamp(-4.0),
            completed_at_utc=clocks.timestamp(-3.0),
        ),
        balances=(),
    )
    second_provider = FakeProvider([older_empty])
    second, journal = _worker(tmp_path, second_provider, clocks)

    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        second.start()

    assert raised.value.code == "OBSERVATION_COMPLETION_TIME_REGRESSED"
    assert second.session_generation is not None
    assert second.session_generation != old_snapshot.payload["session_generation"]
    assert second.latest_snapshot == old_snapshot
    assert second.read_status() == {
        "session_generation": second.session_generation,
        "ready": False,
        "fresh_for_seconds": 0.0,
    }
    assert second_provider.connect_generations == [second.session_generation]
    assert second_provider.read_calls == 1
    second.close()

    batch = journal.read_after(
        GatewayPrincipal(
            principal_id="test-reader",
            account_scopes=frozenset({"account:shared"}),
            strategy_scopes=frozenset({"strategy:account-facts"}),
            allowed_kinds=frozenset({GatewayCommandKind.READ}),
        ),
        "account:shared",
        "strategy:account-facts",
    )
    assert batch.latest_cursor == 1
    assert batch.snapshot == old_snapshot
    assert len(batch.snapshot.payload["observation"]["positions"]) == 1  # type: ignore[index]


def test_restart_restores_open_order_row_timestamp_floor(tmp_path) -> None:
    clocks = Clocks()
    initial = replace(
        _observation(
            clocks,
            observation_id="persisted-open-order",
            open_orders=(_open_order(clocks),),
            open_orders_complete=True,
        ),
        balances=(),
        positions=(),
    )
    first, _ = _worker(tmp_path, FakeProvider([initial]), clocks, require_open_orders=True)
    first.start()
    old_snapshot = first.latest_snapshot
    assert old_snapshot is not None
    first.close()

    clocks.advance(2.0)
    regressed_order = _open_order(
        clocks,
        observed_at_utc=clocks.timestamp(-3.0),
        created_at_utc=clocks.timestamp(-4.0),
    )
    newer_completion = replace(
        _observation(
            clocks,
            observation_id="regressed-open-order-after-restart",
            open_orders=(regressed_order,),
            open_orders_complete=True,
        ),
        balances=(),
        positions=(),
    )
    second_provider = FakeProvider([newer_completion])
    second, _ = _worker(tmp_path, second_provider, clocks, require_open_orders=True)

    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        second.start()

    assert raised.value.code == "ROW_OBSERVATION_TIME_REGRESSED"
    assert second.latest_snapshot == old_snapshot
    assert second.latest_snapshot is not None
    assert second.latest_snapshot.payload["schema_version"] == 2
    assert second.ready is False
    second.close()


def test_old_generation_reply_returning_after_explicit_recovery_is_rejected(tmp_path) -> None:
    clocks = Clocks()
    provider = FakeProvider([_observation(clocks, observation_id="initial")])
    worker, _ = _worker(tmp_path, provider, clocks)
    worker.start()
    old_generation = worker.session_generation
    provider.observations.extend(
        [
            _observation(clocks, observation_id="new-generation"),
            _observation(clocks, observation_id="late-old-generation"),
        ]
    )

    def recover_before_old_reply() -> None:
        # Model a connection failure that triggers explicit recovery while the
        # prior provider read is still outstanding. The old call then returns
        # after the new generation has published its baseline.
        provider.read_hook = None
        worker.recover()

    provider.read_hook = recover_before_old_reply

    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        worker.refresh()

    assert raised.value.code == "PROVIDER_RESULT_GENERATION_STALE"
    assert worker.session_generation != old_generation
    assert provider.connect_generations == [old_generation, worker.session_generation]
    assert worker.latest_snapshot is not None
    assert worker.latest_snapshot.cursor == 2
    assert worker.latest_snapshot.payload["session_generation"] == worker.session_generation
    assert worker.ready is True
    provider.read_hook = None
    worker.close()


@pytest.mark.parametrize("failed_assertion", [3, 4])
def test_guard_ownership_is_rechecked_after_provider_and_before_snapshot_write(
    tmp_path, monkeypatch, failed_assertion: int
) -> None:
    clocks = Clocks()
    provider = FakeProvider(
        [
            _observation(clocks, observation_id="guard-before-read"),
            _observation(clocks, observation_id="guard-after-read"),
        ]
    )
    worker, _ = _worker(tmp_path, provider, clocks)
    worker.start()
    guard = worker._guard
    original_assert_owned = guard.assert_owned
    assertion_count = 0

    def assert_owned_then_lose() -> None:
        nonlocal assertion_count
        assertion_count += 1
        if assertion_count == failed_assertion:
            raise LocalAccountSessionGuardError("SESSION_NOT_OWNED", "synthetic loss")
        original_assert_owned()

    monkeypatch.setattr(guard, "assert_owned", assert_owned_then_lose)
    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        worker.refresh()

    assert raised.value.code == "SESSION_OWNERSHIP_LOST"
    assert assertion_count == failed_assertion
    assert worker.latest_snapshot is not None
    assert worker.latest_snapshot.cursor == 1
    assert worker.ready is False
    monkeypatch.setattr(guard, "assert_owned", original_assert_owned)
    worker.close()


def test_failed_close_keeps_guard_until_same_provider_close_retry_succeeds(tmp_path) -> None:
    clocks = Clocks()
    provider = FakeProvider([_observation(clocks, observation_id="close-retry")])
    provider.close_results = [False, None]
    worker, _ = _worker(tmp_path, provider, clocks)
    worker.start()

    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        worker.close()
    assert raised.value.code == "PROVIDER_CLOSE_UNCONFIRMED"
    assert worker.session_generation is not None
    assert worker.ready is False

    other_guard = LocalAccountSessionGuard(
        tmp_path / "session-guards", _identity().account_key_id, "worker-b"
    )
    with pytest.raises(Exception) as denied:
        other_guard.acquire()
    assert getattr(denied.value, "code", None) == "SESSION_ALREADY_OWNED"

    worker.close()
    assert provider.close_calls == 2
    assert worker.session_generation is None
    next_generation = other_guard.acquire()
    assert next_generation
    other_guard.release()


def test_read_service_shares_account_facts_without_provider_queries_and_enforces_acl(
    tmp_path,
) -> None:
    clocks = Clocks()
    provider = FakeProvider([_observation(clocks, observation_id="shared-state")])
    worker, journal = _worker(tmp_path, provider, clocks)
    worker.start()
    principal = GatewayPrincipal(
        principal_id="principal-a",
        account_scopes=frozenset({"account:shared"}),
        strategy_scopes=frozenset({"strategy:account-facts", "strategy:unrelated"}),
        allowed_kinds=frozenset({GatewayCommandKind.READ}),
    )
    limited_principal = GatewayPrincipal(
        principal_id="principal-limited",
        account_scopes=frozenset({"account:shared"}),
        strategy_scopes=frozenset({"strategy:other"}),
        allowed_kinds=frozenset({GatewayCommandKind.READ}),
    )
    shared_refs = {"strategy-a", "strategy-b"}
    account = GatewayServiceAccountScope(
        account_ref="account-a",
        execution_domain_ref="paper-a",
        journal_account_scope="account:shared",
        strategy_scope_map={"strategy-other": "strategy:unrelated"},
        shared_account_facts_scope="strategy:account-facts",
        shared_fact_strategy_refs=shared_refs,
        account_read_strategy_scope="strategy:account-facts",
    )
    shared_refs.add("strategy-c")
    assert account.shared_fact_strategy_refs == frozenset({"strategy-a", "strategy-b"})
    service = GatewayReadService(
        journal,
        accounts={"account-a": account},
        principals={
            "principal-a": principal,
            "principal-limited": limited_principal,
        },
        state_worker=worker,
    )
    provider_reads = provider.read_calls

    first = service.handle(
        "account.snapshot",
        principal_ref="principal-a",
        scope=_wire_scope(strategy_ref="strategy-a"),
        arguments={},
    )
    second = service.handle(
        "account.snapshot",
        principal_ref="principal-a",
        scope=_wire_scope(strategy_ref="strategy-b"),
        arguments={},
    )
    account_wide = service.handle(
        "account.snapshot",
        principal_ref="principal-a",
        scope=_wire_scope(strategy_ref=None),
        arguments={},
    )

    assert first["snapshot"]["snapshot_id"] == second["snapshot"]["snapshot_id"]  # type: ignore[index]
    assert first["snapshot"]["cursor"] == second["snapshot"]["cursor"] == 1  # type: ignore[index]
    assert account_wide["snapshot"]["snapshot_id"] == first["snapshot"]["snapshot_id"]  # type: ignore[index]
    status = first["state_status"]
    assert type(status) is type(MappingProxyType({}))
    assert set(status) == {"session_generation", "ready", "fresh_for_seconds"}  # type: ignore[arg-type]
    assert status["ready"] is True  # type: ignore[index]
    with pytest.raises(TypeError):
        status["ready"] = False  # type: ignore[index]
    unrelated = service.handle(
        "account.snapshot",
        principal_ref="principal-a",
        scope=_wire_scope(strategy_ref="strategy-other"),
        arguments={},
    )
    assert unrelated["snapshot"] is None
    assert unrelated["state_status"]["ready"] is False  # type: ignore[index]
    assert unrelated["state_status"]["fresh_for_seconds"] == 0.0  # type: ignore[index]
    assert provider.read_calls == provider_reads
    with pytest.raises(GatewayEventJournalError) as denied_principal:
        service.handle(
            "account.snapshot",
            principal_ref="principal-limited",
            scope=_wire_scope(strategy_ref="strategy-a"),
            arguments={},
        )
    assert denied_principal.value.code == "STRATEGY_SCOPE_DENIED"
    with pytest.raises(GatewayServiceError) as denied_strategy:
        service.handle(
            "account.snapshot",
            principal_ref="principal-a",
            scope=_wire_scope(strategy_ref="strategy-c"),
            arguments={},
        )
    assert denied_strategy.value.code == "STRATEGY_SCOPE_DENIED"
    with pytest.raises(GatewayServiceError) as denied_account:
        service.handle(
            "account.snapshot",
            principal_ref="principal-a",
            scope=_wire_scope(account_ref="account-b", strategy_ref="strategy-a"),
            arguments={},
        )
    assert denied_account.value.code == "UNKNOWN_ACCOUNT"
    worker.close()


def test_state_worker_binding_requires_exact_single_account_and_stream_scopes(tmp_path) -> None:
    clocks = Clocks()
    provider = FakeProvider([_observation(clocks, observation_id="binding")])
    worker, journal = _worker(tmp_path, provider, clocks)
    principal = GatewayPrincipal(
        principal_id="principal-a",
        account_scopes=frozenset({"account:shared"}),
        strategy_scopes=frozenset({"strategy:account-facts"}),
        allowed_kinds=frozenset({GatewayCommandKind.READ}),
    )
    account = GatewayServiceAccountScope(
        account_ref="account-a",
        execution_domain_ref="paper-a",
        journal_account_scope="account:shared",
        shared_account_facts_scope="strategy:other",
        shared_fact_strategy_refs={"strategy-a"},
    )

    with pytest.raises(GatewayServiceError) as raised:
        GatewayReadService(
            journal,
            accounts={"account-a": account},
            principals={"principal-a": principal},
            state_worker=worker,
        )
    assert raised.value.code == "STATE_WORKER_STATE_SCOPE_MISMATCH"

    correctly_bound = GatewayServiceAccountScope(
        account_ref="account-a",
        execution_domain_ref="paper-a",
        journal_account_scope="account:shared",
        shared_account_facts_scope="strategy:account-facts",
        shared_fact_strategy_refs={"strategy-a"},
    )
    other_journal = GatewayEventJournal(tmp_path / "other-journal.db")
    with pytest.raises(GatewayServiceError) as wrong_journal:
        GatewayReadService(
            other_journal,
            accounts={"account-a": correctly_bound},
            principals={"principal-a": principal},
            state_worker=worker,
        )
    assert wrong_journal.value.code == "STATE_WORKER_JOURNAL_MISMATCH"


def test_same_generation_row_timestamps_cannot_regress(tmp_path) -> None:
    clocks = Clocks()
    first = _observation(
        clocks,
        observation_id="row-time-1",
        positions=(_position(clocks),),
    )
    provider = FakeProvider([first])
    worker, _ = _worker(tmp_path, provider, clocks)
    worker.start()

    clocks.advance(2.0)
    earlier = clocks.timestamp(-3.0)
    provider.observations.append(
        _observation(
            clocks,
            observation_id="row-time-2",
            positions=(_position(clocks, quantity="3"),),
            row_timestamp=earlier,
        )
    )
    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        worker.refresh()
    assert raised.value.code == "ROW_OBSERVATION_TIME_REGRESSED"
    assert worker.latest_snapshot is not None
    assert worker.latest_snapshot.cursor == 1
    assert worker.ready is False
    worker.close()


def test_older_complete_empty_positions_snapshot_cannot_remove_newer_positions(tmp_path) -> None:
    clocks = Clocks()
    first = _observation(
        clocks,
        observation_id="positions-present",
        positions=(_position(clocks),),
        row_timestamp=clocks.timestamp(-2.0),
    )
    provider = FakeProvider([first])
    worker, _ = _worker(tmp_path, provider, clocks)
    worker.start()

    clocks.advance(2.0)
    older_empty = _observation(
        clocks,
        observation_id="older-complete-empty",
        positions=(),
        row_timestamp=clocks.timestamp(-4.0),
        started_at_utc=clocks.timestamp(-3.0),
        completed_at_utc=clocks.timestamp(-3.0),
    )
    provider.observations.append(older_empty)
    with pytest.raises(GatewayAccountSessionWorkerError) as raised:
        worker.refresh()

    assert raised.value.code == "OBSERVATION_COMPLETION_TIME_REGRESSED"
    assert worker.latest_snapshot is not None
    assert worker.latest_snapshot.cursor == 1
    assert len(worker.latest_snapshot.payload["observation"]["positions"]) == 1  # type: ignore[index]
    assert worker.ready is False
    worker.close()


def _wire_scope(
    *,
    account_ref: str = "account-a",
    strategy_ref: Optional[str] = None,  # noqa: UP045
) -> WireScope:
    return WireScope(
        execution_domain_ref="paper-a",
        account_ref=account_ref,
        strategy_ref=strategy_ref,
    )
