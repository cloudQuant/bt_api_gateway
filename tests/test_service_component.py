"""Gateway service options and real journal-backed account reads."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Optional

import pytest
from bt_api_base.account_protocol import (
    AccountBalance,
    AccountKey,
    AccountObservation,
    AccountOpenOrder,
    AccountResourceKey,
)
from bt_api_base.market_protocol import MarketInstrumentKey
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope

from bt_api_gateway import GatewayCommandKind, GatewayEventJournal, GatewayPrincipal
from bt_api_gateway.account_session_worker import GatewayAccountSessionWorker
from bt_api_gateway.event_journal import GatewayAccountSnapshot, GatewayEventJournalError
from bt_api_gateway.service_component import (
    SUPPORTED_OPERATIONS,
    GatewayReadService,
    GatewayServiceAccountScope,
    GatewayServiceError,
    _state_result_matches_worker,
    validate_service_options,
)
from bt_api_gateway.session_guard import LocalAccountSessionGuard


def _principal(
    principal_id: str,
    *,
    accounts: frozenset[str] = frozenset({"account:journal"}),
    strategies: frozenset[str] = frozenset({"strategy:alpha", "strategy:account_read"}),
    allowed_kinds: frozenset[GatewayCommandKind] = frozenset({GatewayCommandKind.READ}),
) -> GatewayPrincipal:
    return GatewayPrincipal(
        principal_id=principal_id,
        account_scopes=accounts,
        strategy_scopes=strategies,
        allowed_kinds=allowed_kinds,
    )


def _scope(
    *,
    account_ref: Optional[str] = "account-a",  # noqa: UP045 -- Python 3.9 support.
    execution_domain_ref: str = "paper-a",
    strategy_ref: Optional[str] = "strategy-a",  # noqa: UP045 -- Python 3.9 support.
    run_id: Optional[str] = None,  # noqa: UP045 -- Python 3.9 support.
) -> WireScope:
    return WireScope(
        execution_domain_ref=execution_domain_ref,
        account_ref=account_ref,
        strategy_ref=strategy_ref,
        run_id=run_id,
    )


def _identity(
    actor_ref: str = "actor-a",
    *,
    principal_ref: str = "principal-a",
    role: WireRole = WireRole.STRATEGY_CLIENT,
    delegate_ref: Optional[str] = None,  # noqa: UP045 -- Python 3.9 support.
) -> WireIdentity:
    return WireIdentity(
        role=role,
        principal_ref=principal_ref,
        actor_ref=actor_ref,
        delegate_ref=delegate_ref,
    )


def _service(journal: GatewayEventJournal) -> GatewayReadService:
    return GatewayReadService(
        journal,
        accounts={
            "account-a": GatewayServiceAccountScope(
                account_ref="account-a",
                execution_domain_ref="paper-a",
                journal_account_scope="account:journal",
                strategy_scope_map={"strategy-a": "strategy:alpha"},
                account_read_strategy_scope="strategy:account_read",
            )
        },
        principals={"principal-a": _principal("principal-a")},
    )


def _shared_view_service(journal: GatewayEventJournal) -> GatewayReadService:
    return GatewayReadService(
        journal,
        accounts={
            "account-a": GatewayServiceAccountScope(
                account_ref="account-a",
                execution_domain_ref="paper-a",
                journal_account_scope="account:journal",
                shared_account_facts_scope="strategy:shared-facts",
                shared_fact_strategy_refs=frozenset({"strategy-a", "strategy-b"}),
                account_read_strategy_scope="strategy:account_read",
            )
        },
        principals={
            "principal-a": _principal(
                "principal-a",
                strategies=frozenset({"strategy:shared-facts", "strategy:account_read"}),
            )
        },
    )


class _StateProvider:
    def __init__(self, observations: tuple[AccountObservation, ...]) -> None:
        self._observations = list(observations)

    def connect(self, *, account_key: AccountKey, generation: str, timeout: float) -> None:
        assert account_key.account_id == "acct-state"
        assert generation
        assert timeout > 0

    def read_account(self, *, generation: str, timeout: float) -> AccountObservation:
        assert generation
        assert timeout > 0
        return self._observations.pop(0)

    def close(self) -> None:
        return None


def _state_observation(
    observation_id: str,
    *,
    open_orders: Optional[tuple[AccountOpenOrder, ...]] = None,  # noqa: UP045
    open_orders_complete: bool = False,
) -> AccountObservation:
    completed_at = "2023-11-14T22:13:20Z"
    resource = AccountResourceKey(product_type="spot", margin_pool="cross")
    account_key = AccountKey(
        provider="synthetic",
        venue="paper-exchange",
        environment="paper",
        account_id="acct-state",
    )
    balance = AccountBalance(
        resource=resource,
        currency="USD",
        total="100",
        available="90",
        locked="10",
        observed_at_utc=completed_at,
    )
    return AccountObservation(
        account_key=account_key,
        observation_id=observation_id,
        coverage=(resource,),
        balances=(balance,),
        positions=(),
        valuation=None,
        started_at_utc=completed_at,
        completed_at_utc=completed_at,
        consistency="provider_atomic",
        balances_complete=True,
        positions_complete=True,
        open_orders=open_orders,
        open_orders_complete=open_orders_complete,
    )


def _state_order() -> AccountOpenOrder:
    resource = AccountResourceKey(product_type="spot", margin_pool="cross")
    instrument = MarketInstrumentKey(
        provider="synthetic",
        venue="paper-exchange",
        environment="paper",
        product_type="spot",
        instrument_id="BTC-USD",
        native_symbol="BTCUSD",
    )
    return AccountOpenOrder(
        resource=resource,
        instrument=instrument,
        order_id="order-1",
        side="buy",
        position_side="net",
        order_type="limit",
        status="open",
        quantity="1",
        filled_quantity="0",
        qty_unit="base",
        created_at_utc="2023-11-14T22:13:19Z",
        observed_at_utc="2023-11-14T22:13:20Z",
    )


def _state_service(tmp_path, observations: tuple[AccountObservation, ...]):
    (tmp_path / "guards").mkdir()
    account_key = AccountKey(
        provider="synthetic",
        venue="paper-exchange",
        environment="paper",
        account_id="acct-state",
    )
    journal = GatewayEventJournal(tmp_path / "state.db", clock=lambda: 1_700_000_000.0)
    worker = GatewayAccountSessionWorker(
        _StateProvider(observations),
        journal,
        account_key=account_key,
        journal_account_scope="account:journal",
        state_scope="strategy:account_read",
        guard=LocalAccountSessionGuard(tmp_path / "guards", account_key.account_key_id, "worker-a"),
        required_coverage=(AccountResourceKey(product_type="spot", margin_pool="cross"),),
        clock=lambda: 1_700_000_000.0,
        monotonic_clock=lambda: 10.0,
    )
    service = GatewayReadService(
        journal,
        accounts={
            "account-a": GatewayServiceAccountScope(
                account_ref="account-a",
                execution_domain_ref="paper-a",
                journal_account_scope="account:journal",
                account_read_strategy_scope="strategy:account_read",
            )
        },
        principals={
            "principal-a": _principal(
                "principal-a", strategies=frozenset({"strategy:account_read"})
            )
        },
        state_worker=worker,
    )
    return worker, service


def test_service_options_match_sdk_gateway_roles_and_return_immutable_mapping() -> None:
    market = validate_service_options({"role": "market_hub"}, ("service.market_source",))
    account = validate_service_options(
        {
            "role": "account_session_worker",
            "account_session_ref": "a01-session",
        },
        ("service.account_read", "service.provider_session"),
    )

    assert market == {"role": "market_hub"}
    assert account == {
        "role": "account_session_worker",
        "account_session_ref": "a01-session",
    }
    assert type(market) is type(account) is type(MappingProxyType({}))
    with pytest.raises(TypeError):
        market["role"] = "account_session_worker"  # type: ignore[index]


def test_market_service_options_preserve_explicit_bounded_replay_opt_in() -> None:
    market = validate_service_options(
        {"role": "market_hub", "bounded_read_after": True},
        ("service.market_source",),
    )

    assert market == {"role": "market_hub", "bounded_read_after": True}


@pytest.mark.parametrize(
    "options,ports,code",
    [
        ({"role": "unknown"}, ("service.account_read",), "UNKNOWN_SERVICE_ROLE"),
        (
            {"role": "market_hub", "account_session_ref": "session-a"},
            ("service.market_source",),
            "UNKNOWN_OPTION",
        ),
        (
            {"role": "market_hub", "bounded_read_after": 1},
            ("service.market_source",),
            "INVALID_BOUNDED_READ_AFTER",
        ),
        (
            {"role": "account_session_worker"},
            ("service.account_read",),
            "MISSING_ACCOUNT_SESSION_REF",
        ),
        (
            {"role": "account_session_worker", "account_session_ref": "bad ref"},
            ("service.account_read",),
            "INVALID_ACCOUNT_SESSION_REF",
        ),
        (
            {"role": "market_hub"},
            ("service.account_read",),
            "ROLE_PORT_MISMATCH",
        ),
        (
            {"role": "account_session_worker", "account_session_ref": "session-a"},
            ("service.account_read", "service.account_read"),
            "INVALID_BIND_PORTS",
        ),
    ],
)
def test_service_options_reject_unknown_or_mismatched_configuration(
    options: Mapping[str, object], ports: tuple[str, ...], code: str
) -> None:
    with pytest.raises(GatewayServiceError) as raised:
        validate_service_options(options, ports)
    assert raised.value.code == code


def test_read_after_uses_real_journal_acl_and_recovers_from_persisted_snapshot(
    tmp_path,
) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=lambda: 1_700_000_000.0)
    journal.append(
        "account:journal",
        "strategy:alpha",
        "event-1",
        "position_update",
        {"symbol": "BTC-USDT", "quantity": "1"},
    )
    persisted = journal.capture_snapshot(
        "account:journal",
        "strategy:alpha",
        "snapshot-1",
        expected_cursor=1,
        payload={"positions": {"BTC-USDT": "1"}},
    )
    journal.append(
        "account:journal",
        "strategy:alpha",
        "event-2",
        "position_update",
        {"symbol": "BTC-USDT", "quantity": "2"},
    )

    result = _service(journal).handle(
        "account.read_after",
        principal_ref="principal-a",
        scope=_scope(),
        arguments={"cursor": 0, "limit": 1},
    )

    assert result["requested_cursor"] == 0
    assert result["snapshot"]["snapshot_id"] == persisted.snapshot_id  # type: ignore[index]
    assert result["snapshot"]["cursor"] == 1  # type: ignore[index]
    assert [event["sequence"] for event in result["events"]] == [2]  # type: ignore[index]
    assert result["next_cursor"] == result["latest_cursor"] == 2
    assert result["recovered_from_snapshot"] is True
    assert "snapshot_source" not in result


def test_account_snapshot_uses_explicit_account_stream_and_labels_persisted_baseline(
    tmp_path,
) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=lambda: 1_700_000_000.0)
    journal.append(
        "account:journal",
        "strategy:account_read",
        "account-event-1",
        "balance_update",
        {"currency": "USD", "balance": "10"},
    )
    journal.capture_snapshot(
        "account:journal",
        "strategy:account_read",
        "account-snapshot-1",
        expected_cursor=1,
        payload={"balances": {"USD": "10"}},
    )

    service = _service(journal)
    snapshot = service.handle(
        "account.snapshot",
        principal_ref="principal-a",
        scope=_scope(strategy_ref=None),
        arguments={},
    )
    head = service.handle(
        "account.head",
        principal_ref="principal-a",
        scope=_scope(strategy_ref=None),
        arguments={},
    )

    assert snapshot["snapshot_source"] == "persisted_journal_baseline"
    assert snapshot["snapshot"]["snapshot_id"] == "account-snapshot-1"  # type: ignore[index]
    assert snapshot["snapshot"]["strategy_scope"] == "strategy:account_read"  # type: ignore[index]
    assert snapshot["events"] == ()
    assert head == {"latest_cursor": 1}
    assert (
        journal.read_after(
            _principal("principal-a"),
            "account:journal",
            "strategy:account_read",
            cursor=1,
        ).latest_cursor
        == 1
    )


def test_account_snapshot_without_persisted_baseline_does_not_claim_one(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")

    result = _service(journal).handle(
        "account.snapshot",
        principal_ref="principal-a",
        scope=_scope(strategy_ref=None),
        arguments={},
    )

    assert result["snapshot"] is None
    assert result["snapshot_source"] is None
    assert result["events"] == ()
    assert result["latest_cursor"] == 0


def test_account_wide_scope_requires_explicit_mapping_and_strategy_scope_is_exact(
    tmp_path,
) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    no_account_stream = GatewayReadService(
        journal,
        accounts={
            "account-a": GatewayServiceAccountScope(
                account_ref="account-a",
                execution_domain_ref="paper-a",
                journal_account_scope="account:journal",
                strategy_scope_map={"strategy-a": "strategy:alpha"},
            )
        },
        principals={"principal-a": _principal("principal-a")},
    )

    with pytest.raises(GatewayServiceError) as no_stream:
        no_account_stream.handle(
            "account.head",
            principal_ref="principal-a",
            scope=_scope(strategy_ref=None),
            arguments={},
        )
    assert no_stream.value.code == "ACCOUNT_WIDE_READ_NOT_CONFIGURED"

    with pytest.raises(GatewayServiceError) as widened:
        _service(journal).handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(strategy_ref="strategy-b", run_id="run-b"),
            arguments={},
        )
    assert widened.value.code == "STRATEGY_SCOPE_DENIED"


def test_strategy_run_scope_reads_the_same_durable_strategy_stream(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    journal.append(
        "account:journal",
        "strategy:alpha",
        "event-1",
        "position_update",
        {"symbol": "BTC-USDT", "quantity": "1"},
    )
    service = _service(journal)

    without_run = service.handle(
        "account.read_after",
        principal_ref="principal-a",
        scope=_scope(),
        arguments={},
    )
    with_run = service.handle(
        "account.read_after",
        principal_ref="principal-a",
        scope=_scope(strategy_ref="strategy-a", run_id="run-a"),
        arguments={},
    )

    assert with_run["events"] == without_run["events"]
    assert with_run["latest_cursor"] == without_run["latest_cursor"] == 1


@pytest.mark.parametrize(
    "scope,principal_ref,arguments,operation,code",
    [
        (
            _scope(account_ref="unknown-account"),
            "principal-a",
            {},
            "account.head",
            "UNKNOWN_ACCOUNT",
        ),
        (
            _scope(execution_domain_ref="other-domain"),
            "principal-a",
            {},
            "account.head",
            "EXECUTION_DOMAIN_DENIED",
        ),
        (_scope(), "unknown-principal", {}, "account.head", "UNKNOWN_PRINCIPAL"),
        (
            _scope(),
            "principal-a",
            {"account_ref": "account-b"},
            "account.read_after",
            "UNKNOWN_ARGUMENT",
        ),
        (
            _scope(),
            "principal-a",
            {"principal_ref": "principal-b"},
            "account.read_after",
            "UNKNOWN_ARGUMENT",
        ),
        (
            _scope(),
            "principal-a",
            {"scope": {"strategy_ref": "strategy-b"}},
            "account.read_after",
            "UNKNOWN_ARGUMENT",
        ),
        (_scope(), "principal-a", {}, "account.unknown", "UNSUPPORTED_OPERATION"),
    ],
)
def test_handle_rejects_untrusted_identity_scope_arguments_and_unsupported_ops(
    tmp_path, scope, principal_ref, arguments, operation, code
) -> None:
    service = _service(GatewayEventJournal(tmp_path / "gateway.db"))
    with pytest.raises(GatewayServiceError) as raised:
        service.handle(
            operation,
            principal_ref=principal_ref,
            scope=scope,
            arguments=arguments,
        )
    assert raised.value.code == code


@pytest.mark.parametrize(
    "principal,code",
    [
        (
            _principal("principal-a", accounts=frozenset({"account:elsewhere"})),
            "ACCOUNT_SCOPE_DENIED",
        ),
        (
            _principal("principal-a", strategies=frozenset({"strategy:elsewhere"})),
            "STRATEGY_SCOPE_DENIED",
        ),
        (
            _principal("principal-a", allowed_kinds=frozenset({GatewayCommandKind.SUBMIT})),
            "COMMAND_KIND_DENIED",
        ),
    ],
)
def test_journal_acl_rejects_account_strategy_or_read_not_authorized(
    tmp_path, principal, code
) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    service = GatewayReadService(
        journal,
        accounts={
            "account-a": GatewayServiceAccountScope(
                account_ref="account-a",
                execution_domain_ref="paper-a",
                journal_account_scope="account:journal",
                strategy_scope_map={"strategy-a": "strategy:alpha"},
            )
        },
        principals={"principal-a": principal},
    )

    with pytest.raises(GatewayEventJournalError) as denied:
        service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={},
        )
    assert denied.value.code == code


def test_read_cursor_and_limit_are_bounded_by_real_journal_contract(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    service = _service(journal)

    with pytest.raises(GatewayEventJournalError) as ahead:
        service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"cursor": 1},
        )
    assert ahead.value.code == "CURSOR_AHEAD"

    with pytest.raises(GatewayEventJournalError) as too_large:
        service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"limit": GatewayEventJournal.MAX_BATCH_SIZE + 1},
        )
    assert too_large.value.code == "BATCH_SIZE_INVALID"


def test_untracked_read_keeps_legacy_shape_and_does_not_open_consumer(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    journal.append("account:journal", "strategy:alpha", "event-1", "balance_update", {"USD": "1"})
    service = _service(journal)

    result = service.handle(
        "account.read_after",
        principal_ref="principal-a",
        scope=_scope(),
        arguments={"cursor": 0, "track_delivery": False},
    )

    assert set(result) == {
        "requested_cursor",
        "snapshot",
        "events",
        "next_cursor",
        "latest_cursor",
        "recovered_from_snapshot",
    }
    assert result["latest_cursor"] == 1
    with pytest.raises(GatewayEventJournalError) as missing:
        service.handle(
            "account.progress",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={},
            identity=_identity(),
        )
    assert missing.value.code == "CONSUMER_NOT_FOUND"
    with pytest.raises(GatewayEventJournalError) as missing_ack:
        service.handle(
            "account.ack",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"stream_epoch": "epoch-a", "cursor": 0},
            identity=_identity(),
        )
    assert missing_ack.value.code == "CONSUMER_NOT_FOUND"

    with pytest.raises(GatewayServiceError) as epoch_without_tracking:
        service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"stream_epoch": "epoch-a"},
        )
    assert epoch_without_tracking.value.code == "UNKNOWN_ARGUMENT"


@pytest.mark.parametrize(
    "operation,arguments",
    [
        ("account.read_after", {"track_delivery": True}),
        ("account.progress", {}),
        ("account.ack", {"stream_epoch": "epoch-a", "cursor": 0}),
    ],
)
def test_consumer_requests_require_identity_bound_to_principal(
    tmp_path, operation, arguments
) -> None:
    service = _service(GatewayEventJournal(tmp_path / "gateway.db"))

    with pytest.raises(GatewayServiceError) as missing:
        service.handle(
            operation,
            principal_ref="principal-a",
            scope=_scope(),
            arguments=arguments,
        )
    assert missing.value.code == "CONSUMER_IDENTITY_REQUIRED"

    with pytest.raises(GatewayServiceError) as mismatch:
        service.handle(
            operation,
            principal_ref="principal-a",
            scope=_scope(),
            arguments=arguments,
            identity=_identity(principal_ref="principal-b"),
        )
    assert mismatch.value.code == "CONSUMER_PRINCIPAL_MISMATCH"


@pytest.mark.parametrize(
    "operation,arguments",
    [
        (
            "account.read_after",
            {"track_delivery": True, "consumer_ref": "client-chosen"},
        ),
        ("account.progress", {"consumer_ref": "client-chosen"}),
        (
            "account.ack",
            {"stream_epoch": "epoch-a", "cursor": 0, "consumer_id": "client-chosen"},
        ),
    ],
)
def test_consumer_reference_cannot_be_supplied_by_client(tmp_path, operation, arguments) -> None:
    service = _service(GatewayEventJournal(tmp_path / "gateway.db"))
    with pytest.raises(GatewayServiceError) as raised:
        service.handle(
            operation,
            principal_ref="principal-a",
            scope=_scope(),
            arguments=arguments,
            identity=_identity(),
        )
    assert raised.value.code == "UNKNOWN_ARGUMENT"


def test_ack_rejects_wrong_epoch_and_unoffered_cursor_without_advancing(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    journal.append("account:journal", "strategy:alpha", "event-1", "balance_update", {"USD": "1"})
    service = _service(journal)
    identity = _identity()
    offered = service.handle(
        "account.read_after",
        principal_ref="principal-a",
        scope=_scope(),
        arguments={"track_delivery": True},
        identity=identity,
    )
    progress = offered["consumer_progress"]
    assert progress["offered_cursor"] == 1  # type: ignore[index]
    assert progress["acknowledged_cursor"] == 0  # type: ignore[index]
    epoch = progress["stream_epoch"]  # type: ignore[index]

    with pytest.raises(GatewayEventJournalError) as wrong_epoch:
        service.handle(
            "account.ack",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"stream_epoch": "wrong-epoch", "cursor": 1},
            identity=identity,
        )
    assert wrong_epoch.value.code == "STREAM_EPOCH_MISMATCH"

    with pytest.raises(GatewayEventJournalError) as resume_epoch:
        service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"track_delivery": True, "cursor": 1, "stream_epoch": "wrong-epoch"},
            identity=identity,
        )
    assert resume_epoch.value.code == "STREAM_EPOCH_MISMATCH"

    with pytest.raises(GatewayEventJournalError) as missing_resume_epoch:
        service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"track_delivery": True, "cursor": 1},
            identity=identity,
        )
    assert missing_resume_epoch.value.code == "STREAM_EPOCH_REQUIRED"

    with pytest.raises(GatewayEventJournalError) as future:
        service.handle(
            "account.ack",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"stream_epoch": epoch, "cursor": 2},
            identity=identity,
        )
    assert future.value.code == "ACK_CURSOR_AHEAD"

    current = service.handle(
        "account.progress",
        principal_ref="principal-a",
        scope=_scope(),
        arguments={},
        identity=identity,
    )
    assert current == {"consumer_progress": progress}


def test_consumer_identity_and_strategy_scope_are_stable_and_isolated(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    journal.append(
        "account:journal", "strategy:shared-facts", "event-1", "balance_update", {"USD": "1"}
    )
    service = _shared_view_service(journal)
    actor = _identity()
    first_scope = _scope(strategy_ref="strategy-a", run_id="run-1")
    first_read = service.handle(
        "account.read_after",
        principal_ref="principal-a",
        scope=first_scope,
        arguments={"track_delivery": True},
        identity=actor,
    )
    first_progress = first_read["consumer_progress"]
    epoch = first_progress["stream_epoch"]  # type: ignore[index]
    assert first_progress["offered_cursor"] == 1  # type: ignore[index]

    acknowledged = service.handle(
        "account.ack",
        principal_ref="principal-a",
        scope=_scope(strategy_ref="strategy-a", run_id="run-2"),
        arguments={"stream_epoch": epoch, "cursor": 1},
        identity=actor,
    )
    assert acknowledged["consumer_progress"]["acknowledged_cursor"] == 1  # type: ignore[index]
    repeated = service.handle(
        "account.ack",
        principal_ref="principal-a",
        scope=_scope(strategy_ref="strategy-a", run_id="run-2"),
        arguments={"stream_epoch": epoch, "cursor": 0},
        identity=actor,
    )
    assert repeated["consumer_progress"]["acknowledged_cursor"] == 1  # type: ignore[index]
    resumed_read = service.handle(
        "account.read_after",
        principal_ref="principal-a",
        scope=_scope(strategy_ref="strategy-a", run_id="run-2"),
        arguments={"track_delivery": True, "cursor": 1, "stream_epoch": epoch},
        identity=actor,
    )
    assert resumed_read["requested_cursor"] == 1
    assert resumed_read["events"] == ()
    assert resumed_read["consumer_progress"]["acknowledged_cursor"] == 1  # type: ignore[index]
    resumed = service.handle(
        "account.progress",
        principal_ref="principal-a",
        scope=_scope(strategy_ref="strategy-a", run_id="run-3"),
        arguments={},
        identity=actor,
    )
    assert resumed["consumer_progress"] == acknowledged["consumer_progress"]
    assert set(resumed) == {"consumer_progress"}

    independent_identities = (
        (_identity(actor_ref="actor-b"), "strategy-a"),
        (_identity(delegate_ref="delegate-a"), "strategy-a"),
        (
            _identity(role=WireRole.APPLICATION_CLIENT),
            "strategy-a",
        ),
        (_identity(), "strategy-b"),
    )
    for distinct_identity, strategy_ref in independent_identities:
        view = service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(strategy_ref=strategy_ref),
            arguments={"track_delivery": True},
            identity=distinct_identity,
        )
        distinct_progress = view["consumer_progress"]
        assert distinct_progress["offered_cursor"] == 1  # type: ignore[index]
        assert distinct_progress["acknowledged_cursor"] == 0  # type: ignore[index]

    actor_progress = service.handle(
        "account.progress",
        principal_ref="principal-a",
        scope=first_scope,
        arguments={},
        identity=actor,
    )
    assert actor_progress["consumer_progress"]["acknowledged_cursor"] == 1  # type: ignore[index]


@pytest.mark.parametrize(
    "operation,arguments",
    [
        ("account.read_after", {"track_delivery": True}),
        ("account.progress", {}),
        ("account.ack", {"stream_epoch": "epoch-a", "cursor": 0}),
    ],
)
def test_consumer_operations_still_enforce_journal_acl(tmp_path, operation, arguments) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    service = GatewayReadService(
        journal,
        accounts={
            "account-a": GatewayServiceAccountScope(
                account_ref="account-a",
                execution_domain_ref="paper-a",
                journal_account_scope="account:journal",
                strategy_scope_map={"strategy-a": "strategy:alpha"},
            )
        },
        principals={
            "principal-a": _principal("principal-a", strategies=frozenset({"strategy:elsewhere"}))
        },
    )

    with pytest.raises(GatewayEventJournalError) as denied:
        service.handle(
            operation,
            principal_ref="principal-a",
            scope=_scope(),
            arguments=arguments,
            identity=_identity(),
        )
    assert denied.value.code == "STRATEGY_SCOPE_DENIED"


def test_supported_operations_are_finite_and_service_borrows_journal(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    service = _service(journal)

    assert (
        frozenset(
            {
                "account.ack",
                "account.configuration",
                "account.head",
                "account.progress",
                "account.read_after",
                "account.server_time_probe",
                "account.snapshot",
            }
        )
        == SUPPORTED_OPERATIONS
    )
    result = service.handle(
        "account.head",
        principal_ref="principal-a",
        scope=_scope(),
        arguments={},
    )
    assert result["latest_cursor"] == 0
    assert (
        journal.read_after(
            _principal("principal-a"), "account:journal", "strategy:alpha"
        ).latest_cursor
        == 0
    )


def test_state_worker_v2_orders_are_read_after_complete_empty_replacement(tmp_path) -> None:
    worker, service = _state_service(
        tmp_path,
        (
            _state_observation(
                "with-order", open_orders=(_state_order(),), open_orders_complete=True
            ),
            _state_observation("without-orders", open_orders=(), open_orders_complete=True),
        ),
    )
    worker.start()
    try:
        with_order = service.handle(
            "account.snapshot",
            principal_ref="principal-a",
            scope=_scope(strategy_ref=None),
            arguments={},
        )
        first_state = with_order["snapshot"]["payload"]  # type: ignore[index]
        assert with_order["state_status"]["ready"] is True  # type: ignore[index]
        assert first_state["schema_version"] == 2
        assert len(first_state["observation"]["open_orders"]) == 1

        tracked = service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(strategy_ref=None),
            arguments={"track_delivery": True},
            identity=_identity(),
        )
        assert tracked["state_status"]["ready"] is True  # type: ignore[index]
        assert tracked["consumer_progress"]["offered_cursor"] == tracked["latest_cursor"]  # type: ignore[index]
        progress = service.handle(
            "account.progress",
            principal_ref="principal-a",
            scope=_scope(strategy_ref=None),
            arguments={},
            identity=_identity(),
        )
        assert set(progress) == {"consumer_progress"}

        worker.refresh()
        empty = service.handle(
            "account.snapshot",
            principal_ref="principal-a",
            scope=_scope(strategy_ref=None),
            arguments={},
        )
        empty_state = empty["snapshot"]["payload"]  # type: ignore[index]
        assert empty["state_status"]["ready"] is True  # type: ignore[index]
        assert empty_state["schema_version"] == 2
        assert empty_state["observation"]["open_orders"] == ()
        assert empty_state["observation"]["open_orders_complete"] is True
    finally:
        worker.close()


def test_state_worker_legacy_observation_keeps_schema_v1_readable(tmp_path) -> None:
    worker, service = _state_service(tmp_path, (_state_observation("legacy"),))
    worker.start()
    try:
        result = service.handle(
            "account.snapshot",
            principal_ref="principal-a",
            scope=_scope(strategy_ref=None),
            arguments={},
        )
        state = result["snapshot"]["payload"]  # type: ignore[index]
        assert result["state_status"]["ready"] is True  # type: ignore[index]
        assert state["schema_version"] == 1
        assert "open_orders" not in state["observation"]
    finally:
        worker.close()


def test_state_worker_rejects_schema_version_inconsistent_with_observation(tmp_path) -> None:
    worker, _service_with_state = _state_service(
        tmp_path,
        (
            _state_observation(
                "with-order", open_orders=(_state_order(),), open_orders_complete=True
            ),
        ),
    )
    worker.start()
    try:
        latest = worker.latest_snapshot
        assert latest is not None
        wrong_payload = dict(latest.payload)
        wrong_payload["schema_version"] = 1
        wrong_snapshot = GatewayAccountSnapshot(
            account_scope=latest.account_scope,
            strategy_scope=latest.strategy_scope,
            snapshot_id=latest.snapshot_id,
            cursor=latest.cursor,
            payload=wrong_payload,
            captured_at=latest.captured_at,
        )
        worker._latest_snapshot = wrong_snapshot

        assert (
            _state_result_matches_worker(
                {"latest_cursor": wrong_snapshot.cursor},
                operation="account.head",
                strategy_scope=worker.state_scope,
                worker=worker,
                generation=worker.session_generation,
            )
            is False
        )
    finally:
        worker.close()
