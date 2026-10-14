"""Synthetic provider coverage for shared public market subscriptions."""

from __future__ import annotations

from itertools import count
from typing import Any

import pytest
from bt_api_base.market_protocol import MarketInstrumentKey, MarketSubscriptionKey
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope, encode_envelope

from bt_api_gateway.market_hub import (
    MAX_MARKET_EVENT_BYTES,
    MAX_MARKET_KEY_UNIVERSE,
    MAX_MARKET_READ_PAGE_BYTES,
    MAX_TOTAL_MARKET_REPLAY_BYTES,
    GatewayMarketHub,
    GatewayMarketHubError,
    GatewayMarketRegistration,
    GatewayMarketService,
    GatewayMarketServiceError,
)


class CountedProvider:
    def __init__(self) -> None:
        self.subscribed: list[tuple[MarketSubscriptionKey, object]] = []
        self.unsubscribed: list[object] = []
        self.active_handles: set[object] = set()
        self.generations: dict[MarketSubscriptionKey, str] = {}
        self.fail_unsubscribe = 0

    def subscribe(self, key: MarketSubscriptionKey, *, generation: str) -> object:
        handle = object()
        self.subscribed.append((key, handle))
        self.active_handles.add(handle)
        self.generations[key] = generation
        return handle

    def unsubscribe(self, handle: object) -> bool:
        self.unsubscribed.append(handle)
        self.active_handles.discard(handle)
        key = next(key for key, subscribed_handle in self.subscribed if subscribed_handle is handle)
        self.generations.pop(key, None)
        if self.fail_unsubscribe:
            self.fail_unsubscribe -= 1
            return False
        return True


def _key(**changes: Any) -> MarketSubscriptionKey:
    instrument_fields: dict[str, str] = {
        "provider": "synthetic",
        "venue": "test-venue",
        "environment": "paper",
        "product_type": "spot",
        "instrument_id": "instrument-1",
        "native_symbol": "TST-USD",
    }
    instrument_overrides = changes.pop("instrument", {})
    instrument_fields.update(instrument_overrides)
    fields: dict[str, Any] = {
        "source_ref": "source:public",
        "entitlement_ref": "entitlement:public",
        "instrument": MarketInstrumentKey(**instrument_fields),
        "channel": "trades",
        "depth": None,
        "timeframe": None,
    }
    fields.update(changes)
    return MarketSubscriptionKey(**fields)


def _identity() -> WireIdentity:
    return WireIdentity(
        role=WireRole.SERVICE,
        principal_ref="service:market",
        actor_ref="actor:gateway",
    )


def _scope(**changes: Any) -> WireScope:
    values: dict[str, Any] = {"execution_domain_ref": "domain:paper"}
    values.update(changes)
    return WireScope(**values)


def _hub(
    keys: tuple[MarketSubscriptionKey, ...] | None = None,
    principals: tuple[str, ...] = ("principal:a", "principal:b"),
    *,
    max_replay_events: int = 1_000,
    max_replay_bytes: int = 256 * 1024,
    publisher: Any = None,
) -> tuple[GatewayMarketHub, CountedProvider, list[Any]]:
    exported = keys or (_key(),)
    provider = CountedProvider()
    published: list[Any] = []
    epochs = count(1)
    hub = GatewayMarketHub(
        provider,
        key_universe=exported,
        principal_allowed_keys=dict.fromkeys(principals, exported),
        service_identity=_identity(),
        service_scope=_scope(),
        max_replay_events=max_replay_events,
        max_replay_bytes=max_replay_bytes,
        epoch_factory=lambda: f"epoch-{next(epochs)}",
    )
    hub.set_publisher(publisher or published.append)
    return hub, provider, published


def _publish(
    hub: GatewayMarketHub,
    key: MarketSubscriptionKey,
    provider: CountedProvider,
    n: int = 1,
) -> Any:
    return hub.publish(
        key,
        {"price": n, "symbol": key.instrument.native_symbol},
        f"2026-10-14T10:00:{n:02d}Z",
        generation=provider.generations[key],
    )


def test_two_registration_refs_share_one_provider_start_and_last_release() -> None:
    key = _key()
    hub, provider, _ = _hub()

    first = hub.subscribe("principal:a", key, "registration:a")
    repeated = hub.subscribe("principal:a", key, "registration:a")
    second = hub.subscribe("principal:b", key, "registration:b")

    assert first["already_subscribed"] is False
    assert repeated["already_subscribed"] is True
    assert second["already_subscribed"] is False
    assert len(provider.subscribed) == 1
    assert hub.readiness["active_registrations"] == 2

    assert hub.unsubscribe("principal:a", key, "registration:a")["upstream_released"] is False
    assert provider.unsubscribed == []
    assert hub.unsubscribe("principal:b", key, "registration:b")["upstream_released"] is True
    assert len(provider.unsubscribed) == 1
    hub.unsubscribe("principal:b", key, "registration:b")
    assert len(provider.unsubscribed) == 1


def test_full_audience_preflight_and_exact_key_authorization() -> None:
    key = _key()
    other = _key(source_ref="source:other")
    provider = CountedProvider()
    with pytest.raises(GatewayMarketHubError, match="INCOMPLETE_MARKET_AUDIENCE"):
        GatewayMarketHub(
            provider,
            key_universe=(key, other),
            principal_allowed_keys={"principal:a": (key,)},
            service_identity=_identity(),
            service_scope=_scope(),
        )

    hub, _, _ = _hub((key, other))
    hub.validate_audience(("principal:a", "principal:b"), _identity(), _scope())
    with pytest.raises(GatewayMarketHubError, match="MARKET_AUDIENCE_MISMATCH"):
        hub.validate_audience(("principal:a",), _identity(), _scope())
    with pytest.raises(GatewayMarketHubError, match="MARKET_KEY_NOT_EXPORTED"):
        hub.subscribe("principal:a", _key(source_ref="not-exported"), "registration:a")
    with pytest.raises(GatewayMarketHubError, match="UNKNOWN_PRINCIPAL"):
        hub.subscribe("principal:unknown", key, "registration:a")


def test_key_dimensions_do_not_collide_or_share_provider_handles() -> None:
    base = _key()
    variants = (
        _key(source_ref="source:other"),
        _key(entitlement_ref="entitlement:other"),
        _key(channel="quotes"),
        _key(depth=5),
        _key(timeframe="1m"),
        _key(instrument={"instrument_id": "instrument-2"}),
    )
    assert len({base.stream_id, *(key.stream_id for key in variants)}) == 1 + len(variants)

    hub, provider, _ = _hub((base, *variants))
    for index, key in enumerate((base, *variants)):
        hub.subscribe("principal:a", key, f"registration:{index}")
    assert len(provider.subscribed) == 1 + len(variants)


def test_replay_head_snapshot_and_cursor_gap_are_explicit() -> None:
    key = _key()
    hub, provider, _ = _hub(max_replay_events=2)
    hub.subscribe("principal:a", key, "registration:a")
    initial = hub.head(key)
    assert initial["head"] == 0
    assert initial["oldest_sequence"] == 1
    assert initial["latest_observed_at_utc"] is None

    first = _publish(hub, key, provider, 1)
    _publish(hub, key, provider, 2)
    third = _publish(hub, key, provider, 3)
    snapshot = hub.snapshot(key)
    assert snapshot["snapshot_kind"] == "latest_event"
    assert snapshot["complete"] is False
    assert snapshot["event"] is third
    assert third.header.sequence == snapshot["head"]

    gap = hub.read_after(key, epoch=first.header.stream_epoch, after=0, limit=2)
    assert gap["gap"] is True
    assert gap["gap_reason"] == "cursor_too_old"
    assert gap["events"] == ()

    page = hub.read_after(key, epoch=third.header.stream_epoch, after=1, limit=1)
    assert [event.header.sequence for event in page["events"]] == [2]
    assert page["next_after"] == 2
    assert page["has_more"] is True


def test_epoch_reset_is_explicit_and_old_cursor_gets_epoch_gap() -> None:
    key = _key()
    hub, provider, _ = _hub()
    hub.subscribe("principal:a", key, "registration:a")
    old = _publish(hub, key, provider)
    generation = provider.generations[key]
    new_epoch = hub.reset_stream_epoch(key)

    assert new_epoch != old.header.stream_epoch
    assert provider.generations[key] == generation
    assert hub.head(key)["head"] == 0
    assert hub.head(key)["oldest_sequence"] == 1
    result = hub.read_after(key, epoch=old.header.stream_epoch, after=1)
    assert result["gap"] is True
    assert result["gap_reason"] == "epoch_mismatch"
    assert result["events"] == ()
    fresh = _publish(hub, key, provider, 2)
    assert fresh.header.stream_epoch == new_epoch
    assert fresh.header.sequence == 1


def test_failed_stop_is_confirmed_before_new_start_and_new_epoch() -> None:
    key = _key()
    hub, provider, published = _hub()
    provider.fail_unsubscribe = 1
    hub.subscribe("principal:a", key, "registration:a")
    old_generation = provider.generations[key]
    old = _publish(hub, key, provider)

    with pytest.raises(GatewayMarketHubError, match="PROVIDER_UNSUBSCRIBE_FAILED"):
        hub.unsubscribe("principal:a", key, "registration:a")
    assert hub.readiness["pending_releases"] == 1
    assert len(provider.subscribed) == 1
    assert not provider.active_handles

    hub.subscribe("principal:b", key, "registration:b")
    assert len(provider.subscribed) == 2
    assert provider.subscribed[-1][1] in provider.active_handles
    assert provider.subscribed[0][1] not in provider.active_handles
    assert hub.readiness["pending_releases"] == 0
    assert hub.head(key)["epoch"] != old.header.stream_epoch
    assert hub.snapshot(key)["event"] is None
    assert hub.head(key)["head"] == 0
    new_generation = provider.generations[key]
    assert new_generation != old_generation
    before = hub.head(key)
    published_count = len(published)
    with pytest.raises(GatewayMarketHubError, match="STALE_SOURCE_GENERATION"):
        hub.publish(
            key,
            {"price": 99},
            "2026-10-14T10:00:09Z",
            generation=old_generation,
        )
    assert hub.head(key) == before
    assert len(published) == published_count
    assert hub.unsubscribe("principal:b", key, "registration:b")["upstream_released"] is True
    assert len(provider.unsubscribed) == 3
    assert provider.unsubscribed[0] is provider.unsubscribed[1]


def test_publish_failure_keeps_event_in_replay_for_read_after() -> None:
    key = _key()

    def broken_publisher(_: Any) -> None:
        raise RuntimeError("finite fake publisher failure")

    hub, provider, _ = _hub(publisher=broken_publisher)
    hub.subscribe("principal:a", key, "registration:a")
    with pytest.raises(GatewayMarketHubError, match="PUBLISHER_FAILED"):
        _publish(hub, key, provider)

    head = hub.head(key)
    batch = hub.read_after(key, epoch=head["epoch"], after=0)
    assert head["head"] == 1
    assert [event.header.sequence for event in batch["events"]] == [1]


def test_application_registration_has_no_fabricated_strategy_and_scope_is_public() -> None:
    key = _key()
    hub, _, _ = _hub(principals=("application:read-only",))
    service = GatewayMarketService(hub)
    registration = GatewayMarketRegistration(
        principal_ref="application:read-only",
        execution_domain_ref="domain:paper",
    )
    service.register_registration("trusted-registration", registration)
    subscribe = service.handle(
        "market.subscribe",
        principal_ref=registration.principal_ref,
        scope=_scope(),
        arguments={"key": key.to_dict()},
        registration_id="trusted-registration",
    )
    assert subscribe["stream_id"] == key.stream_id

    with pytest.raises(GatewayMarketServiceError, match="PUBLIC_MARKET_SCOPE_REQUIRED"):
        service.handle(
            "market.head",
            principal_ref=registration.principal_ref,
            scope=_scope(account_ref="account:private"),
            arguments={"key": key.to_dict()},
            registration_id="trusted-registration",
        )


def test_registration_binding_is_idempotent_but_cannot_be_rebound() -> None:
    hub, _, _ = _hub()
    service = GatewayMarketService(hub)
    first = GatewayMarketRegistration("principal:a", "domain:paper")
    service.register_registration("trusted-registration", first)
    service.register_registration("trusted-registration", first)
    with pytest.raises(GatewayMarketServiceError, match="REGISTRATION_REBIND_DENIED"):
        service.register_registration(
            "trusted-registration",
            GatewayMarketRegistration("principal:b", "domain:paper"),
        )


def test_service_rejects_extra_arguments_and_requires_active_subscription() -> None:
    key = _key()
    hub, _, _ = _hub(principals=("principal:a",))
    service = GatewayMarketService(
        hub,
        registrations={
            "trusted-registration": GatewayMarketRegistration("principal:a", "domain:paper")
        },
    )
    with pytest.raises(GatewayMarketServiceError, match="INVALID_ARGUMENTS"):
        service.handle(
            "market.subscribe",
            principal_ref="principal:a",
            scope=_scope(),
            arguments={"key": key.to_dict(), "registration_id": "client-controlled"},
            registration_id="trusted-registration",
        )
    with pytest.raises(GatewayMarketServiceError, match="MARKET_SUBSCRIPTION_REQUIRED"):
        service.handle(
            "market.head",
            principal_ref="principal:a",
            scope=_scope(),
            arguments={"key": key.to_dict()},
            registration_id="trusted-registration",
        )


def test_explicit_maintenance_prunes_only_owner_declared_inactive_refs() -> None:
    key = _key()
    hub, provider, _ = _hub()
    hub.subscribe("principal:a", key, "registration:a")
    hub.subscribe("principal:b", key, "registration:b")

    result = hub.maintain({"registration:b"})
    assert result == {
        "pruned_registrations": 1,
        "released_upstreams": 0,
        "pending_releases": 0,
    }
    assert provider.unsubscribed == []
    assert hub.registration_active(key, "registration:b") is True

    result = hub.maintain(set())
    assert result["pruned_registrations"] == 1
    assert result["released_upstreams"] == 1
    assert len(provider.unsubscribed) == 1


def test_replay_event_is_bounded_and_wire_payload_has_only_key_and_data() -> None:
    key = _key()
    hub, provider, published = _hub(max_replay_bytes=MAX_MARKET_EVENT_BYTES)
    hub.subscribe("principal:a", key, "registration:a")
    event = _publish(hub, key, provider)

    assert set(event.payload) == {"key", "data"}
    assert event.header.sent_at_utc == "2026-10-14T10:00:01Z"
    assert published == [event]
    with pytest.raises(GatewayMarketHubError, match="INVALID_EVENT_DATA"):
        hub.publish(
            key,
            {1: "invalid-key"},  # type: ignore[dict-item]
            "2026-10-14T10:00:01Z",
            generation=provider.generations[key],
        )


def test_key_universe_and_configured_total_replay_budget_are_finite() -> None:
    keys = tuple(_key(source_ref=f"source:{index}") for index in range(MAX_MARKET_KEY_UNIVERSE + 1))
    with pytest.raises(GatewayMarketHubError, match="KEY_UNIVERSE_TOO_LARGE"):
        _hub(keys)

    with pytest.raises(GatewayMarketHubError, match="TOTAL_REPLAY_BUDGET_EXCEEDED"):
        _hub(max_replay_bytes=MAX_TOTAL_MARKET_REPLAY_BYTES + 1)


def test_read_after_page_stays_below_sdk_response_budget_and_sets_has_more() -> None:
    key = _key()
    hub, provider, _ = _hub(max_replay_events=10, max_replay_bytes=2 * 1024 * 1024)
    hub.subscribe("principal:a", key, "registration:a")
    blob = "x" * (230 * 1024)
    for sequence in range(1, 6):
        hub.publish(
            key,
            {"blob": blob},
            f"2026-10-14T10:00:{sequence:02d}Z",
            generation=provider.generations[key],
        )

    head = hub.head(key)
    page = hub.read_after(key, epoch=head["epoch"], after=0, limit=10)
    page_bytes = sum(len(encode_envelope(event)) for event in page["events"])
    assert page_bytes <= MAX_MARKET_READ_PAGE_BYTES
    assert page_bytes < 900 * 1024
    assert page["has_more"] is True
    assert page["next_after"] == page["events"][-1].header.sequence
