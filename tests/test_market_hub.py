"""Synthetic provider coverage for shared public market subscriptions."""

from __future__ import annotations

import threading
from itertools import count
from typing import Any

import pytest
from bt_api_base.market_protocol import (
    MarketInstrumentKey,
    MarketProviderEvent,
    MarketSourceDescriptor,
    MarketSubscriptionKey,
)
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
        self.pending_events: dict[object, list[MarketProviderEvent]] = {}
        self.poll_calls: list[tuple[object, int, int]] = []
        self.fail_unsubscribe = 0

    def subscribe(self, key: MarketSubscriptionKey, *, generation: str) -> object:
        handle = object()
        self.subscribed.append((key, handle))
        self.active_handles.add(handle)
        self.generations[key] = generation
        self.pending_events[handle] = []
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

    def poll(self, handle: object, *, limit: int) -> tuple[MarketProviderEvent, ...]:
        self.poll_calls.append((handle, limit, threading.get_ident()))
        events = self.pending_events.setdefault(handle, [])
        batch = tuple(events[:limit])
        del events[:limit]
        return batch

    def enqueue(self, key: MarketSubscriptionKey, event: MarketProviderEvent) -> None:
        handle = next(handle for subscribed_key, handle in self.subscribed if subscribed_key == key)
        self.pending_events[handle].append(event)


class DescribingProvider(CountedProvider):
    def __init__(self) -> None:
        super().__init__()
        self.describe_calls: list[dict[str, object]] = []
        self.descriptor_factory: Any = None

    def describe_source(
        self,
        handle: object,
        *,
        key: MarketSubscriptionKey,
        generation: str,
        stream_id: str,
        epoch: str,
    ) -> MarketSourceDescriptor | None:
        self.describe_calls.append(
            {
                "handle": handle,
                "key": key,
                "generation": generation,
                "stream_id": stream_id,
                "epoch": epoch,
            }
        )
        if self.descriptor_factory is None:
            return None
        return self.descriptor_factory(
            handle=handle,
            key=key,
            generation=generation,
            stream_id=stream_id,
            epoch=epoch,
        )


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
    provider: Any = None,
    max_replay_events: int = 1_000,
    max_replay_bytes: int = 256 * 1024,
    max_provider_events_per_maintain: int = 32,
    publisher: Any = None,
) -> tuple[GatewayMarketHub, CountedProvider, list[Any]]:
    exported = keys or (_key(),)
    if provider is None:
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
        max_provider_events_per_maintain=max_provider_events_per_maintain,
        epoch_factory=lambda: f"epoch-{next(epochs)}",
    )
    hub.set_publisher(publisher or published.append)
    return hub, provider, published


def _source_descriptor(
    key: MarketSubscriptionKey,
    *,
    stream_id: str | None = None,
    epoch: str = "epoch-1",
    provider: str | None = None,
    connection_generation: int = 7,
    source: str = "ctp.native.md",
    clock_domain_id: str = "ctp-md-process:123:monotonic:session-a",
    clock_source_session_id: str = "session-a",
    clock_source: str = "time.monotonic_ns",
) -> MarketSourceDescriptor:
    return MarketSourceDescriptor(
        key=key,
        stream_id=key.stream_id if stream_id is None else stream_id,
        epoch=epoch,
        provider=key.instrument.provider if provider is None else provider,
        source=source,
        connection_generation=connection_generation,
        clock_domain_id=clock_domain_id,
        clock_source_session_id=clock_source_session_id,
        clock_source=clock_source,
    )


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


def test_manual_publish_provider_without_poll_remains_supported() -> None:
    key = _key()

    class ManualPublishProvider:
        def __init__(self) -> None:
            self.generation: str | None = None

        def subscribe(self, _key: MarketSubscriptionKey, *, generation: str) -> object:
            self.generation = generation
            return object()

        def unsubscribe(self, _handle: object) -> bool:
            return True

    provider = ManualPublishProvider()
    published: list[Any] = []
    hub = GatewayMarketHub(
        provider,
        key_universe=(key,),
        principal_allowed_keys={"principal:a": (key,)},
        service_identity=_identity(),
        service_scope=_scope(),
    )
    hub.set_publisher(published.append)
    hub.subscribe("principal:a", key, "registration:a")

    result = hub.maintain({"registration:a"})
    assert result == {
        "pruned_registrations": 0,
        "released_upstreams": 0,
        "pending_releases": 0,
    }
    assert published == []
    assert dict(hub.source_diagnostics) == {
        "provider_poll_calls": 0,
        "provider_events_polled": 0,
        "provider_events_published": 0,
        "stale_generation_events_dropped": 0,
        "provider_poll_failures": 0,
        "provider_invalid_batches": 0,
        "provider_invalid_events": 0,
        "provider_event_rejections": 0,
    }

    assert provider.generation is not None
    hub.publish(
        key,
        {"symbol": key.instrument.native_symbol, "price": 101.5},
        "2026-10-16T10:00:01Z",
        generation=provider.generation,
    )

    (event,) = published
    assert event.payload == {
        "key": key.to_dict(),
        "data": {"symbol": "TST-USD", "price": 101.5},
    }


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


def test_strategy_registration_preserves_account_binding_without_stream_partition() -> None:
    key = _key()
    hub, provider, _ = _hub(principals=("principal:a",))
    registration = GatewayMarketRegistration(
        principal_ref="principal:a",
        execution_domain_ref="domain:paper",
        strategy_ref="strategy:a",
        run_id="run:a",
        account_ref="account:shared",
    )
    service = GatewayMarketService(hub, registrations={"registration:a": registration})

    accepted = service.handle(
        "market.subscribe",
        principal_ref="principal:a",
        scope=_scope(
            account_ref="account:shared",
            strategy_ref="strategy:a",
            run_id="run:a",
        ),
        arguments={"key": key.to_dict()},
        registration_id="registration:a",
    )
    assert accepted["stream_id"] == key.stream_id
    assert [subscribed_key for subscribed_key, _handle in provider.subscribed] == [key]
    assert hub.readiness["active_registrations"] == 1

    # Account association is checked against each strategy registration but
    # does not partition the shared stream or create another provider handle.
    service.register_registration(
        "registration:b",
        GatewayMarketRegistration(
            principal_ref="principal:a",
            execution_domain_ref="domain:paper",
            strategy_ref="strategy:b",
            run_id="run:b",
            account_ref="account:other",
        ),
    )
    second_account = service.handle(
        "market.subscribe",
        principal_ref="principal:a",
        scope=_scope(
            account_ref="account:other",
            strategy_ref="strategy:b",
            run_id="run:b",
        ),
        arguments={"key": key.to_dict()},
        registration_id="registration:b",
    )
    assert second_account["stream_id"] == key.stream_id
    assert [subscribed_key for subscribed_key, _handle in provider.subscribed] == [key]
    assert hub.readiness["active_registrations"] == 2

    with pytest.raises(GatewayMarketServiceError, match="ACCOUNT_SCOPE_DENIED"):
        service.handle(
            "market.subscribe",
            principal_ref="principal:a",
            scope=_scope(
                account_ref="account:other",
                strategy_ref="strategy:a",
                run_id="run:a",
            ),
            arguments={"key": key.to_dict()},
            registration_id="registration:a",
        )
    assert [subscribed_key for subscribed_key, _handle in provider.subscribed] == [key]
    assert hub.readiness["active_registrations"] == 2


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


def test_source_descriptor_is_opt_in_and_bound_to_the_active_provider_handle() -> None:
    key = _key()
    provider = DescribingProvider()
    provider.descriptor_factory = lambda **values: _source_descriptor(
        values["key"], epoch=values["epoch"]
    )
    hub, _, _ = _hub(principals=("principal:a",), provider=provider)
    service = GatewayMarketService(hub)
    registration = GatewayMarketRegistration("principal:a", "domain:paper")
    service.register_registration("registration:a", registration)
    service.register_registration("registration:b", registration)

    legacy = service.handle(
        "market.subscribe",
        principal_ref="principal:a",
        scope=_scope(),
        arguments={"key": key.to_dict()},
        registration_id="registration:a",
    )
    explicit_false = service.handle(
        "market.subscribe",
        principal_ref="principal:a",
        scope=_scope(),
        arguments={"key": key.to_dict(), "require_source_descriptor": False},
        registration_id="registration:b",
    )
    assert set(legacy) == {
        "stream_id",
        "epoch",
        "head",
        "oldest_sequence",
        "already_subscribed",
    }
    assert set(explicit_false) == set(legacy)
    assert legacy["stream_id"] == key.stream_id
    assert legacy["already_subscribed"] is False
    assert explicit_false["already_subscribed"] is False
    assert provider.describe_calls == []


def test_requested_descriptor_uses_current_generation_key_and_epoch() -> None:
    key = _key()
    provider = DescribingProvider()
    provider.descriptor_factory = lambda **values: _source_descriptor(
        values["key"], epoch=values["epoch"]
    )
    hub, _, _ = _hub(principals=("principal:a",), provider=provider)
    service = GatewayMarketService(
        hub,
        registrations={"registration:a": GatewayMarketRegistration("principal:a", "domain:paper")},
    )

    result = service.handle(
        "market.subscribe",
        principal_ref="principal:a",
        scope=_scope(),
        arguments={"key": key.to_dict(), "require_source_descriptor": True},
        registration_id="registration:a",
    )

    assert set(result) == {
        "stream_id",
        "epoch",
        "head",
        "oldest_sequence",
        "already_subscribed",
        "source_descriptor",
    }
    assert result["source_descriptor"] == _source_descriptor(key, epoch=result["epoch"]).to_dict()
    assert len(provider.subscribed) == 1
    handle = provider.subscribed[0][1]
    assert provider.describe_calls == [
        {
            "handle": handle,
            "key": key,
            "generation": provider.generations[key],
            "stream_id": key.stream_id,
            "epoch": result["epoch"],
        }
    ]
    repeated = service.handle(
        "market.subscribe",
        principal_ref="principal:a",
        scope=_scope(),
        arguments={"key": key.to_dict(), "require_source_descriptor": True},
        registration_id="registration:a",
    )
    assert repeated["already_subscribed"] is True
    assert repeated["source_descriptor"] == result["source_descriptor"]
    assert len(provider.describe_calls) == 2


@pytest.mark.parametrize("flag", [0, 1, "true", None])
def test_subscribe_descriptor_flag_requires_exact_bool(flag: object) -> None:
    key = _key()
    hub, provider, _ = _hub(principals=("principal:a",))
    service = GatewayMarketService(
        hub,
        registrations={"registration:a": GatewayMarketRegistration("principal:a", "domain:paper")},
    )

    with pytest.raises(GatewayMarketServiceError, match="INVALID_ARGUMENTS"):
        service.handle(
            "market.subscribe",
            principal_ref="principal:a",
            scope=_scope(),
            arguments={"key": key.to_dict(), "require_source_descriptor": flag},
            registration_id="registration:a",
        )
    assert provider.subscribed == []


@pytest.mark.parametrize("failure", ["missing", "none", "raises", "wrong_key", "wrong_epoch"])
def test_descriptor_failure_is_finite_and_cleans_new_provider_acquisition(failure: str) -> None:
    key = _key()
    provider: CountedProvider
    if failure == "missing":
        provider = CountedProvider()
    else:
        provider = DescribingProvider()
        if failure == "none":
            provider.descriptor_factory = lambda **_values: None
        elif failure == "raises":

            def _raise(**_values: Any) -> None:
                raise RuntimeError("private provider detail")

            provider.descriptor_factory = _raise
        elif failure == "wrong_key":
            other = _key(source_ref="source:other")
            provider.descriptor_factory = lambda **values: _source_descriptor(
                other, epoch=values["epoch"]
            )
        else:
            provider.descriptor_factory = lambda **values: _source_descriptor(
                values["key"], epoch="another-epoch"
            )

    hub, _, _ = _hub(principals=("principal:a",), provider=provider)
    service = GatewayMarketService(
        hub,
        registrations={"registration:a": GatewayMarketRegistration("principal:a", "domain:paper")},
    )

    with pytest.raises(
        GatewayMarketServiceError, match="MARKET_SOURCE_DESCRIPTOR_UNAVAILABLE"
    ) as raised:
        service.handle(
            "market.subscribe",
            principal_ref="principal:a",
            scope=_scope(),
            arguments={"key": key.to_dict(), "require_source_descriptor": True},
            registration_id="registration:a",
        )

    assert str(raised.value) == "MARKET_SOURCE_DESCRIPTOR_UNAVAILABLE"
    assert hub.registration_active(key, "registration:a") is False
    assert hub.readiness["active_registrations"] == 0
    assert provider.active_handles == set()
    assert len(provider.subscribed) == 1
    assert provider.unsubscribed == [provider.subscribed[0][1]]


def test_uncertain_descriptor_cleanup_retains_handle_until_release_retry() -> None:
    key = _key()
    provider = DescribingProvider()
    provider.descriptor_factory = lambda **_values: None
    provider.fail_unsubscribe = 1
    original_unsubscribe = provider.unsubscribe

    def uncertain_unsubscribe(handle: object) -> bool:
        if provider.fail_unsubscribe:
            provider.fail_unsubscribe -= 1
            provider.unsubscribed.append(handle)
            return False
        return original_unsubscribe(handle)

    provider.unsubscribe = uncertain_unsubscribe  # type: ignore[method-assign]
    hub, _, _ = _hub(principals=("principal:a",), provider=provider)
    service = GatewayMarketService(
        hub,
        registrations={"registration:a": GatewayMarketRegistration("principal:a", "domain:paper")},
    )

    with pytest.raises(GatewayMarketServiceError, match="MARKET_SOURCE_DESCRIPTOR_UNAVAILABLE"):
        service.handle(
            "market.subscribe",
            principal_ref="principal:a",
            scope=_scope(),
            arguments={"key": key.to_dict(), "require_source_descriptor": True},
            registration_id="registration:a",
        )

    handle = provider.subscribed[0][1]
    assert hub.readiness["pending_releases"] == 1
    assert hub.registration_active(key, "registration:a") is False
    assert provider.active_handles == {handle}

    provider.descriptor_factory = lambda **values: _source_descriptor(
        values["key"], epoch=values["epoch"]
    )
    result = service.handle(
        "market.subscribe",
        principal_ref="principal:a",
        scope=_scope(),
        arguments={"key": key.to_dict(), "require_source_descriptor": True},
        registration_id="registration:a",
    )
    assert result["source_descriptor"] == _source_descriptor(key, epoch=result["epoch"]).to_dict()
    assert len(provider.subscribed) == 2
    assert provider.unsubscribed[0] is handle
    assert provider.active_handles == {provider.subscribed[1][1]}
    assert hub.readiness["pending_releases"] == 0
    assert hub.readiness["active_upstreams"] == 1


def test_invalid_descriptor_for_new_registration_preserves_existing_shared_stream() -> None:
    key = _key()
    provider = DescribingProvider()
    provider.descriptor_factory = lambda **values: _source_descriptor(
        values["key"], epoch="stale-epoch"
    )
    hub, _, _ = _hub(principals=("principal:a",), provider=provider)
    service = GatewayMarketService(hub)
    registration = GatewayMarketRegistration("principal:a", "domain:paper")
    service.register_registration("registration:a", registration)
    service.register_registration("registration:b", registration)
    legacy = service.handle(
        "market.subscribe",
        principal_ref="principal:a",
        scope=_scope(),
        arguments={"key": key.to_dict()},
        registration_id="registration:a",
    )

    with pytest.raises(GatewayMarketServiceError, match="MARKET_SOURCE_DESCRIPTOR_UNAVAILABLE"):
        service.handle(
            "market.subscribe",
            principal_ref="principal:a",
            scope=_scope(),
            arguments={"key": key.to_dict(), "require_source_descriptor": True},
            registration_id="registration:b",
        )

    assert hub.registration_active(key, "registration:a") is True
    assert hub.registration_active(key, "registration:b") is False
    assert hub.readiness["active_registrations"] == 1
    assert len(provider.subscribed) == 1
    assert provider.unsubscribed == []
    assert legacy["stream_id"] == key.stream_id


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


def test_maintain_publishes_provider_events_on_owner_thread_with_existing_wire_shape() -> None:
    key = _key()
    hub, provider, published = _hub()
    owner_thread = threading.get_ident()
    hub.subscribe("principal:a", key, "registration:a")
    provider.enqueue(
        key,
        MarketProviderEvent(
            generation=provider.generations[key],
            observed_at_utc="2026-10-16T10:00:01Z",
            data={"symbol": "TST-USD", "price": 101.5},
        ),
    )

    result = hub.maintain({"registration:a"})

    event = published[0]
    assert result == {
        "pruned_registrations": 0,
        "released_upstreams": 0,
        "pending_releases": 0,
    }
    assert event.header.schema_id == "sdk.market.event"
    assert event.header.operation == "market.event"
    assert event.payload == {"key": key.to_dict(), "data": {"symbol": "TST-USD", "price": 101.5}}
    assert "generation" not in event.payload
    assert provider.poll_calls == [
        (provider.subscribed[0][1], 1, owner_thread),
        (provider.subscribed[0][1], 1, owner_thread),
    ]
    assert dict(hub.source_diagnostics) == {
        "provider_poll_calls": 2,
        "provider_events_polled": 1,
        "provider_events_published": 1,
        "stale_generation_events_dropped": 0,
        "provider_poll_failures": 0,
        "provider_invalid_batches": 0,
        "provider_invalid_events": 0,
        "provider_event_rejections": 0,
    }


def test_maintain_uses_a_finite_round_robin_provider_poll_budget() -> None:
    first = _key()
    second = _key(source_ref="source:second")
    hub, provider, published = _hub((first, second), max_provider_events_per_maintain=4)
    hub.subscribe("principal:a", first, "registration:a")
    hub.subscribe("principal:a", second, "registration:b")
    for key in (first, second):
        for index in range(10):
            provider.enqueue(
                key,
                MarketProviderEvent(
                    generation=provider.generations[key],
                    observed_at_utc=f"2026-10-16T10:00:{index:02d}Z",
                    data={"price": index + 1},
                ),
            )

    hub.maintain({"registration:a", "registration:b"})

    first_handle = provider.subscribed[0][1]
    second_handle = provider.subscribed[1][1]
    assert len(published) == 4
    assert [handle for handle, limit, _thread in provider.poll_calls] == [
        first_handle,
        second_handle,
        first_handle,
        second_handle,
    ]
    assert all(limit == 1 for _handle, limit, _thread in provider.poll_calls)
    assert dict(hub.source_diagnostics)["provider_events_polled"] == 4


def test_maintain_drops_stale_generation_events_before_replay_or_publication() -> None:
    key = _key()
    hub, provider, published = _hub()
    hub.subscribe("principal:a", key, "registration:a")
    provider.enqueue(
        key,
        MarketProviderEvent(
            generation="previous-acquisition-generation",
            observed_at_utc="2026-10-16T10:00:01Z",
            data={"price": 101.5},
        ),
    )

    hub.maintain({"registration:a"})

    assert published == []
    assert hub.head(key)["head"] == 0
    assert dict(hub.source_diagnostics)["stale_generation_events_dropped"] == 1


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
