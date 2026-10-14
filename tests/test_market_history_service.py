"""Bounded historical-market service coverage using synthetic providers."""

from __future__ import annotations

import math
import time
from typing import Any

import pytest
from bt_api_base.market_history_protocol import (
    MarketBar,
    MarketHistoryPage,
    MarketHistoryRequest,
)
from bt_api_base.market_protocol import MarketInstrumentKey, MarketSubscriptionKey
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope

from bt_api_gateway.market_hub import (
    ALL_MARKET_OPERATIONS,
    MARKET_HISTORY_OPERATION,
    MARKET_OPERATIONS,
    SUPPORTED_OPERATIONS,
    GatewayMarketHub,
    GatewayMarketHubError,
    GatewayMarketRegistration,
    GatewayMarketService,
    GatewayMarketServiceError,
)


class SubscriptionProvider:
    def __init__(self) -> None:
        self.subscribed: list[tuple[MarketSubscriptionKey, object, str]] = []
        self.unsubscribed: list[object] = []

    def subscribe(self, key: MarketSubscriptionKey, *, generation: str) -> object:
        handle = object()
        self.subscribed.append((key, handle, generation))
        return handle

    def unsubscribe(self, handle: object) -> bool:
        self.unsubscribed.append(handle)
        return True


class HistoryProvider:
    def __init__(self, result: object = None, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.calls: list[tuple[MarketHistoryRequest, float]] = []
        self.delay_seconds = 0.0

    def fetch(self, request: MarketHistoryRequest, timeout_seconds: float) -> MarketHistoryPage:
        self.calls.append((request, timeout_seconds))
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        if self.error is not None:
            raise self.error
        return self.result  # type: ignore[return-value] -- malformed-page cases are intentional.


def _key(**changes: Any) -> MarketSubscriptionKey:
    fields: dict[str, Any] = {
        "source_ref": "source:public",
        "entitlement_ref": "entitlement:public",
        "instrument": MarketInstrumentKey(
            provider="synthetic",
            venue="test-venue",
            environment="paper",
            product_type="spot",
            instrument_id="instrument-1",
            native_symbol="TST-USD",
        ),
        "channel": "bar",
        "depth": None,
        "timeframe": "1m",
    }
    fields.update(changes)
    return MarketSubscriptionKey(**fields)


def _request(
    *,
    key: MarketSubscriptionKey | None = None,
    start: str = "2026-01-01T00:00:00Z",
    end: str = "2026-01-01T00:02:00Z",
    limit: int = 100,
) -> MarketHistoryRequest:
    return MarketHistoryRequest(
        key=_key() if key is None else key,
        start_time_utc=start,
        end_time_utc=end,
        limit=limit,
    )


def _page(request: MarketHistoryRequest | None = None) -> MarketHistoryPage:
    actual = _request() if request is None else request
    bar = MarketBar(
        open_time_utc=actual.start_time_utc,
        close_time_utc="2026-01-01T00:01:00Z",
        open="10.0",
        high="11.0",
        low="9.0",
        close="10.5",
        volume="2.0",
    )
    return MarketHistoryPage(
        request=actual,
        bars=(bar,),
        complete=True,
        next_start_time_utc=None,
        observed_at_utc=actual.end_time_utc,
    )


def _runtime(
    *,
    history_provider: object | None = None,
    history_timeout_seconds: float | None = None,
    key: MarketSubscriptionKey | None = None,
) -> tuple[GatewayMarketHub, GatewayMarketService, SubscriptionProvider]:
    exported_key = _key() if key is None else key
    stream_provider = SubscriptionProvider()
    hub = GatewayMarketHub(
        stream_provider,
        key_universe=(exported_key,),
        principal_allowed_keys={"principal:alpha": (exported_key,)},
        service_identity=WireIdentity(
            role=WireRole.SERVICE,
            principal_ref="service:market",
            actor_ref="actor:gateway",
        ),
        service_scope=WireScope(execution_domain_ref="domain:paper"),
        publisher=lambda _event: True,
        history_provider=history_provider,  # type: ignore[arg-type] -- config failures are tested.
        history_timeout_seconds=history_timeout_seconds,
    )
    registration = GatewayMarketRegistration(
        principal_ref="principal:alpha",
        execution_domain_ref="domain:paper",
    )
    service = GatewayMarketService(hub, registrations={"registration:1": registration})
    return hub, service, stream_provider


def _call(
    service: GatewayMarketService,
    request: MarketHistoryRequest,
    *,
    principal_ref: str = "principal:alpha",
    scope: WireScope | None = None,
    registration_id: str = "registration:1",
) -> dict[str, object]:
    return service.handle(
        MARKET_HISTORY_OPERATION,
        principal_ref=principal_ref,
        scope=WireScope(execution_domain_ref="domain:paper") if scope is None else scope,
        arguments=request.to_dict(),
        registration_id=registration_id,
    )  # type: ignore[return-value] -- the RPC contract is a string-keyed mapping.


def test_history_is_advertised_only_when_a_provider_and_timeout_are_configured() -> None:
    _, legacy_service, _ = _runtime()
    assert SUPPORTED_OPERATIONS == MARKET_OPERATIONS
    assert legacy_service.supported_operations == MARKET_OPERATIONS
    assert MARKET_HISTORY_OPERATION not in legacy_service.supported_operations
    with pytest.raises(GatewayMarketServiceError, match="UNSUPPORTED_OPERATION"):
        legacy_service.handle(
            MARKET_HISTORY_OPERATION,
            principal_ref="principal:alpha",
            scope=WireScope(execution_domain_ref="domain:paper"),
            arguments={},
            registration_id="registration:1",
        )

    history = HistoryProvider(_page())
    _, history_service, _ = _runtime(
        history_provider=history,
        history_timeout_seconds=2.5,
    )
    assert history_service.supported_operations == ALL_MARKET_OPERATIONS


@pytest.mark.parametrize(
    ("provider", "timeout", "code"),
    [
        (None, 1.0, "HISTORY_TIMEOUT_WITHOUT_PROVIDER"),
        (HistoryProvider(_page()), None, "HISTORY_TIMEOUT_REQUIRED"),
        (object(), 1.0, "INVALID_HISTORY_PROVIDER"),
        (HistoryProvider(_page()), 0.0, "INVALID_HISTORY_TIMEOUT"),
        (HistoryProvider(_page()), math.inf, "INVALID_HISTORY_TIMEOUT"),
        (HistoryProvider(_page()), math.nan, "INVALID_HISTORY_TIMEOUT"),
        (HistoryProvider(_page()), 301.0, "INVALID_HISTORY_TIMEOUT"),
        (HistoryProvider(_page()), True, "INVALID_HISTORY_TIMEOUT"),
    ],
)
def test_history_provider_requires_an_explicit_valid_timeout(
    provider: object | None, timeout: float | None, code: str
) -> None:
    with pytest.raises(GatewayMarketHubError, match=code):
        _runtime(history_provider=provider, history_timeout_seconds=timeout)


def test_history_fetch_uses_exact_request_without_live_subscription_or_cache() -> None:
    request = _request()
    expected_page = _page(request)
    provider = HistoryProvider(expected_page)
    hub, service, stream_provider = _runtime(
        history_provider=provider,
        history_timeout_seconds=3.0,
    )

    first = _call(service, request)
    second = _call(service, request)

    assert first == expected_page.to_dict()
    assert second == expected_page.to_dict()
    assert provider.calls == [(request, 3.0), (request, 3.0)]
    assert not stream_provider.subscribed
    assert hub.readiness["active_upstreams"] == 0


def test_exact_history_request_fields_are_required_before_provider_call() -> None:
    provider = HistoryProvider(_page())
    _, service, _ = _runtime(history_provider=provider, history_timeout_seconds=1.0)
    arguments = _request().to_dict()
    arguments["extra"] = "rejected"

    with pytest.raises(GatewayMarketServiceError, match="INVALID_ARGUMENTS"):
        service.handle(
            MARKET_HISTORY_OPERATION,
            principal_ref="principal:alpha",
            scope=WireScope(execution_domain_ref="domain:paper"),
            arguments=arguments,
            registration_id="registration:1",
        )
    assert not provider.calls

    malformed = _request().to_dict()
    malformed["limit"] = True
    with pytest.raises(GatewayMarketServiceError, match="INVALID_HISTORY_REQUEST"):
        service.handle(
            MARKET_HISTORY_OPERATION,
            principal_ref="principal:alpha",
            scope=WireScope(execution_domain_ref="domain:paper"),
            arguments=malformed,
            registration_id="registration:1",
        )
    assert not provider.calls


@pytest.mark.parametrize(
    ("principal_ref", "scope", "registration_id", "key", "code"),
    [
        (
            "principal:alpha",
            WireScope(execution_domain_ref="domain:paper", account_ref="account:private"),
            "registration:1",
            _key(),
            "PUBLIC_MARKET_SCOPE_REQUIRED",
        ),
        (
            "principal:other",
            WireScope(execution_domain_ref="domain:paper"),
            "registration:1",
            _key(),
            "UNKNOWN_PRINCIPAL",
        ),
        (
            "principal:alpha",
            WireScope(execution_domain_ref="domain:paper"),
            "registration:1",
            _key(entitlement_ref="entitlement:other"),
            "MARKET_KEY_NOT_EXPORTED",
        ),
    ],
)
def test_registration_scope_principal_and_key_are_checked_before_provider_query(
    principal_ref: str,
    scope: WireScope,
    registration_id: str,
    key: MarketSubscriptionKey,
    code: str,
) -> None:
    provider = HistoryProvider(_page(_request(key=key)))
    _, service, _ = _runtime(history_provider=provider, history_timeout_seconds=1.0)

    with pytest.raises(GatewayMarketServiceError, match=code):
        _call(
            service,
            _request(key=key),
            principal_ref=principal_ref,
            scope=scope,
            registration_id=registration_id,
        )
    assert not provider.calls


def test_history_page_must_be_the_exact_page_type_and_match_the_request() -> None:
    request = _request()
    provider = HistoryProvider({"not": "a history page"})
    _, service, _ = _runtime(history_provider=provider, history_timeout_seconds=1.0)

    with pytest.raises(GatewayMarketServiceError, match="INVALID_HISTORY_PAGE"):
        _call(service, request)
    assert len(provider.calls) == 1

    other_request = _request(end="2026-01-01T00:03:00Z")
    provider.result = _page(other_request)
    with pytest.raises(GatewayMarketServiceError, match="HISTORY_REQUEST_MISMATCH"):
        _call(service, request)
    assert len(provider.calls) == 2


def test_provider_exception_is_finite_and_never_retried() -> None:
    provider = HistoryProvider(error=RuntimeError("private provider detail"))
    _, service, _ = _runtime(history_provider=provider, history_timeout_seconds=1.0)

    with pytest.raises(GatewayMarketServiceError, match="HISTORY_PROVIDER_FAILED") as raised:
        _call(service, _request())
    assert str(raised.value) == "HISTORY_PROVIDER_FAILED"
    assert len(provider.calls) == 1


def test_provider_return_after_configured_timeout_is_rejected_without_retry() -> None:
    provider = HistoryProvider(_page())
    provider.delay_seconds = 0.03
    _, service, _ = _runtime(history_provider=provider, history_timeout_seconds=0.01)

    with pytest.raises(GatewayMarketServiceError, match="HISTORY_PROVIDER_TIMEOUT"):
        _call(service, _request())
    assert len(provider.calls) == 1
    assert provider.calls[0][1] == 0.01


def test_response_byte_limit_is_checked_on_serialized_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = HistoryProvider(_page())
    _, service, _ = _runtime(history_provider=provider, history_timeout_seconds=1.0)
    original_to_dict = MarketHistoryPage.to_dict

    def oversized_to_dict(page: MarketHistoryPage) -> dict[str, object]:
        result = original_to_dict(page)
        result["padding"] = "x" * (512 * 1024)
        return result

    monkeypatch.setattr(MarketHistoryPage, "to_dict", oversized_to_dict)
    with pytest.raises(GatewayMarketServiceError, match="HISTORY_PAGE_TOO_LARGE"):
        _call(service, _request())
    assert len(provider.calls) == 1
