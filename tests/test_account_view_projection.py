"""Pure tests for authorization-scoped provider account projections."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

import pytest
from bt_api_base.account_protocol import (
    AccountBalance,
    AccountKey,
    AccountObservation,
    AccountOpenOrder,
    AccountPosition,
    AccountResourceKey,
    AccountValuation,
)
from bt_api_base.market_protocol import MarketInstrumentKey

from bt_api_gateway.account_view_projection import (
    ACCOUNT_VIEW_DELTA_SCHEMA_ID,
    ACCOUNT_VIEW_SCHEMA_ID,
    MAX_ACCOUNT_VIEW_POLICIES,
    MAX_ACCOUNT_VIEW_RESOURCES,
    AccountViewProjectionError,
    GatewayAccountViewPolicy,
    project_account_view,
    validate_policy_set,
    view_delta,
)

_OBSERVED_AT = "2026-10-14T10:00:00Z"
_COMPLETED_AT = "2026-10-14T10:00:01Z"


def _resource(product_type: str, margin_pool: str) -> AccountResourceKey:
    return AccountResourceKey(product_type=product_type, margin_pool=margin_pool)


def _instrument(resource: AccountResourceKey, instrument_id: str) -> MarketInstrumentKey:
    return MarketInstrumentKey(
        provider="provider-a",
        venue="venue-a",
        environment="paper",
        product_type=resource.product_type,
        instrument_id=instrument_id,
        native_symbol=instrument_id.upper(),
    )


def _balance(resource: AccountResourceKey, currency: str, total: str) -> AccountBalance:
    return AccountBalance(
        resource=resource,
        currency=currency,
        total=total,
        available=total,
        locked="0",
        observed_at_utc=_OBSERVED_AT,
    )


def _position(resource: AccountResourceKey, instrument_id: str, quantity: str) -> AccountPosition:
    return AccountPosition(
        resource=resource,
        instrument=_instrument(resource, instrument_id),
        side="net",
        quantity=quantity,
        qty_unit="contracts",
        average_price="10",
        price_currency="USD",
        observed_at_utc=_OBSERVED_AT,
    )


def _open_order(
    resource: AccountResourceKey, instrument_id: str, order_id: str
) -> AccountOpenOrder:
    return AccountOpenOrder(
        resource=resource,
        instrument=_instrument(resource, instrument_id),
        order_id=order_id,
        side="buy",
        position_side="net",
        order_type="limit",
        status="open",
        quantity="2",
        filled_quantity="0",
        qty_unit="contracts",
        created_at_utc=_OBSERVED_AT,
        observed_at_utc=_OBSERVED_AT,
        client_order_id=None,
        limit_price="10",
        stop_price=None,
        price_currency="USD",
        reduce_only=False,
    )


def _observation(
    *,
    observation_id: str = "observation-a",
    coverage: tuple[AccountResourceKey, ...] | None = None,
    balances: tuple[AccountBalance, ...] | None = None,
    positions: tuple[AccountPosition, ...] | None = None,
    valuation: AccountValuation | None = None,
    balances_complete: bool = True,
    positions_complete: bool = True,
    open_orders: tuple[AccountOpenOrder, ...] | None = None,
    open_orders_complete: bool = False,
    completed_at_utc: str = _COMPLETED_AT,
    consistency: str = "provider_atomic",
) -> AccountObservation:
    primary = _resource("linear", "pool-a")
    secondary = _resource("spot", "pool-b")
    return AccountObservation(
        account_key=AccountKey(
            provider="provider-a",
            venue="venue-a",
            environment="paper",
            account_id="account-a",
        ),
        observation_id=observation_id,
        coverage=(primary, secondary) if coverage is None else coverage,
        balances=(
            (_balance(primary, "USD", "100"), _balance(secondary, "USD", "200"))
            if balances is None
            else balances
        ),
        positions=(
            (_position(primary, "btc-usd", "1"), _position(secondary, "eth-usd", "2"))
            if positions is None
            else positions
        ),
        valuation=valuation,
        started_at_utc="2026-10-14T09:59:59Z",
        completed_at_utc=completed_at_utc,
        consistency=consistency,
        balances_complete=balances_complete,
        positions_complete=positions_complete,
        open_orders=open_orders,
        open_orders_complete=open_orders_complete,
    )


def _policy(
    *,
    view_scope: str = "view:alpha",
    resources: tuple[AccountResourceKey, ...] | None = None,
    fact_kinds: frozenset[str] = frozenset({"balances", "positions"}),
    include_valuation: bool = False,
) -> GatewayAccountViewPolicy:
    primary = _resource("linear", "pool-a")
    return GatewayAccountViewPolicy(
        view_scope=view_scope,
        resources=(primary,) if resources is None else resources,
        fact_kinds=fact_kinds,
        include_valuation=include_valuation,
    )


def _code(code: str, call: object) -> None:
    with pytest.raises(AccountViewProjectionError) as raised:
        call()  # type: ignore[operator] -- this helper receives test callables.
    assert raised.value.code == code


def test_policy_digest_is_canonical_and_policy_set_is_bounded_and_ordered() -> None:
    primary = _resource("linear", "pool-a")
    secondary = _resource("spot", "pool-b")
    first = _policy(view_scope="view:z", resources=(secondary, primary))
    reordered = _policy(view_scope="view:z", resources=(primary, secondary))
    alpha = _policy(view_scope="view:a")

    assert first.resources == (primary, secondary)
    assert first.canonical_json == reordered.canonical_json
    assert first.digest == reordered.digest
    assert validate_policy_set((first, alpha)) == (alpha, first)
    assert validate_policy_set(()) == ()

    _code("DUPLICATE_VIEW_SCOPE", lambda: validate_policy_set((first, reordered)))
    _code(
        "INVALID_VIEW_POLICY_SET",
        lambda: validate_policy_set((alpha,) * (MAX_ACCOUNT_VIEW_POLICIES + 1)),
    )
    _code(
        "INVALID_VIEW_LIMIT",
        lambda: validate_policy_set((), max_views=MAX_ACCOUNT_VIEW_POLICIES + 1),
    )


def test_policy_rejects_unbounded_or_ambiguous_resource_and_fact_scopes() -> None:
    resources = tuple(
        _resource("product", f"pool-{index}") for index in range(MAX_ACCOUNT_VIEW_RESOURCES + 1)
    )
    _code(
        "INVALID_VIEW_RESOURCES",
        lambda: _policy(resources=resources),
    )
    _code(
        "DUPLICATE_VIEW_RESOURCE",
        lambda: _policy(resources=(_resource("linear", "pool-a"),) * 2),
    )
    _code(
        "INVALID_VIEW_FACT_KINDS",
        lambda: GatewayAccountViewPolicy(
            view_scope="view:invalid",
            resources=(_resource("linear", "pool-a"),),
            fact_kinds=frozenset({"balances", "orders"}),
        ),
    )
    _code(
        "EMPTY_VIEW_POLICY",
        lambda: GatewayAccountViewPolicy("view:empty", (), frozenset()),
    )


def test_projection_filters_resources_and_fact_kinds_and_is_recursively_immutable() -> None:
    primary = _resource("linear", "pool-a")
    policy = _policy(fact_kinds=frozenset({"balances", "positions"}))
    observation = _observation(
        open_orders=(_open_order(primary, "btc-usd", "secret-order"),),
        open_orders_complete=True,
        valuation=AccountValuation("USD", "75", "125", _OBSERVED_AT),
    )

    view = project_account_view(observation, policy)
    assert view["schema_id"] == ACCOUNT_VIEW_SCHEMA_ID
    assert view["schema_version"] == 1
    assert view["view_scope"] == "view:alpha"
    assert view["consistency"] == "multi_query"
    assert tuple(view["fact_kinds"]) == ("balances", "positions")
    assert tuple(view["coverage"]) == (primary.to_dict(),)
    assert len(view["balances"]) == 1
    assert view["balances"][0]["resource"] == primary.to_dict()
    assert len(view["positions"]) == 1
    assert "open_orders" not in view
    assert "valuation" not in view
    assert "account_key" not in view
    assert "observation_id" not in view
    assert "policy_digest" not in view
    assert "started_at_utc" not in view
    assert "completed_at_utc" not in view
    assert "session_generation" not in view
    assert "source_cursor" not in view
    assert "secret-order" not in repr(view)
    assert isinstance(view, Mapping)
    with pytest.raises(TypeError):
        view["view_scope"] = "view:other"  # type: ignore[index]
    with pytest.raises(TypeError):
        view["balances"][0]["total"] = "999"  # type: ignore[index]


def test_projection_order_is_independent_of_provider_row_order() -> None:
    primary = _resource("linear", "pool-a")
    secondary = _resource("spot", "pool-b")
    policy = _policy(
        resources=(secondary, primary),
        fact_kinds=frozenset({"balances", "positions"}),
    )
    first = _observation()
    second = replace(
        first,
        balances=tuple(reversed(first.balances)),
        positions=tuple(reversed(first.positions)),
    )

    assert project_account_view(first, policy) == project_account_view(second, policy)


def test_projection_rejects_uncovered_or_incomplete_requested_facts() -> None:
    primary = _resource("linear", "pool-a")
    policy = _policy(resources=(primary, _resource("spot", "pool-b")))
    observation = _observation(
        coverage=(primary,),
        balances=(_balance(primary, "USD", "100"),),
        positions=(_position(primary, "btc-usd", "1"),),
    )
    _code("VIEW_RESOURCE_NOT_COVERED", lambda: project_account_view(observation, policy))

    balances_policy = _policy(fact_kinds=frozenset({"balances"}))
    _code(
        "VIEW_BALANCES_INCOMPLETE",
        lambda: project_account_view(_observation(balances_complete=False), balances_policy),
    )
    positions_policy = _policy(fact_kinds=frozenset({"positions"}))
    _code(
        "VIEW_POSITIONS_INCOMPLETE",
        lambda: project_account_view(_observation(positions_complete=False), positions_policy),
    )
    orders_policy = _policy(fact_kinds=frozenset({"open_orders"}))
    _code(
        "VIEW_OPEN_ORDERS_INCOMPLETE",
        lambda: project_account_view(_observation(), orders_policy),
    )
    _code(
        "VIEW_OPEN_ORDERS_INCOMPLETE",
        lambda: project_account_view(
            _observation(open_orders=(), open_orders_complete=False), orders_policy
        ),
    )


def test_complete_empty_open_orders_are_distinct_from_unavailable_orders() -> None:
    policy = _policy(fact_kinds=frozenset({"open_orders"}))
    view = project_account_view(_observation(open_orders=(), open_orders_complete=True), policy)

    assert view["open_orders"] == ()


def test_valuation_is_separately_authorized_and_missing_is_rejected() -> None:
    policy = _policy(fact_kinds=frozenset(), include_valuation=True)
    with_value = project_account_view(
        _observation(valuation=AccountValuation("USD", "75", "125", _OBSERVED_AT)),
        policy,
    )

    assert with_value["valuation"]["equity"] == "125"
    assert "policy_digest" not in with_value
    _code(
        "VIEW_VALUATION_INCOMPLETE",
        lambda: project_account_view(_observation(), policy),
    )

    changed = project_account_view(
        _observation(
            valuation=AccountValuation("USD", "76", "126", _OBSERVED_AT),
            observation_id="observation-b",
        ),
        policy,
    )
    delta = view_delta(with_value, changed)
    assert delta is not None
    assert delta["schema_id"] == ACCOUNT_VIEW_DELTA_SCHEMA_ID
    assert delta["valuation"]["set"]["equity"] == "126"
    assert "policy_digest" not in delta


def test_delta_emits_deterministic_upserts_and_identity_only_deletes() -> None:
    primary = _resource("linear", "pool-a")
    policy = _policy(fact_kinds=frozenset({"balances", "positions"}))
    previous_observation = _observation()
    changed_observation = replace(
        previous_observation,
        balances=(_balance(primary, "USD", "101"),),
        positions=(),
    )

    previous = project_account_view(previous_observation, policy)
    current = project_account_view(changed_observation, policy)
    delta = view_delta(previous, current)

    assert delta is not None
    assert delta["schema_id"] == ACCOUNT_VIEW_DELTA_SCHEMA_ID
    assert delta["changes"]["balances"]["upsert"][0]["total"] == "101"
    assert delta["changes"]["balances"]["delete"] == ()
    assert delta["changes"]["positions"]["upsert"] == ()
    assert delta["changes"]["positions"]["delete"] == (
        {
            "resource": primary.to_dict(),
            "instrument": _instrument(primary, "btc-usd").to_dict(),
            "side": "net",
        },
    )
    assert "observation_id" not in delta
    assert "source_cursor" not in delta


def test_hidden_facts_and_observation_metadata_do_not_create_a_view_event() -> None:
    secondary = _resource("spot", "pool-b")
    policy = _policy(fact_kinds=frozenset({"balances"}))
    previous = project_account_view(_observation(), policy)
    hidden_only = replace(
        _observation(observation_id="observation-b", consistency="multi_query"),
        balances=(
            _balance(_resource("linear", "pool-a"), "USD", "100"),
            _balance(secondary, "USD", "999"),
        ),
        completed_at_utc="2026-10-14T10:00:02Z",
    )
    current = project_account_view(hidden_only, policy)

    assert current == previous
    assert view_delta(previous, current) is None


def test_delta_rejects_view_or_policy_rebinding_and_malformed_projection() -> None:
    previous = project_account_view(_observation(), _policy())
    other_scope = project_account_view(_observation(), _policy(view_scope="view:beta"))
    other_policy = project_account_view(_observation(), _policy(fact_kinds=frozenset({"balances"})))

    _code("VIEW_SCOPE_MISMATCH", lambda: view_delta(previous, other_scope))
    _code("VIEW_POLICY_MISMATCH", lambda: view_delta(previous, other_policy))
    malformed = dict(previous)
    malformed["observation_id"] = "must-not-be-accepted"
    _code("VIEW_PROJECTION_INVALID", lambda: view_delta(malformed, previous))


def test_delta_rejects_instrument_product_outside_authorized_resource() -> None:
    previous = dict(project_account_view(_observation(), _policy()))
    positions = [dict(row) for row in previous["positions"]]
    instrument = dict(positions[0]["instrument"])
    instrument["product_type"] = "spot"
    positions[0]["instrument"] = instrument
    previous["positions"] = positions

    valid = project_account_view(_observation(), _policy())
    _code("VIEW_PROJECTION_INVALID", lambda: view_delta(previous, valid))


def test_valuation_only_policy_is_explicit_and_has_no_resource_coverage() -> None:
    policy = GatewayAccountViewPolicy(
        view_scope="view:valuation",
        resources=(),
        fact_kinds=frozenset(),
        include_valuation=True,
    )
    view = project_account_view(
        _observation(valuation=AccountValuation("USD", "75", "125", _OBSERVED_AT)),
        policy,
    )

    assert view["coverage"] == ()
    assert view["fact_kinds"] == ()
    assert view["consistency"] == "multi_query"
    assert view["valuation"]["equity"] == "125"
