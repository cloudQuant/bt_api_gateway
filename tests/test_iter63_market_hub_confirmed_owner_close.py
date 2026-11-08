"""Only a confirmed whole-provider close can resolve borrowed-handle uncertainty."""

from __future__ import annotations

import threading

import pytest
from test_market_hub import CountedProvider, _identity, _key, _scope

from bt_api_gateway.market_hub import GatewayMarketHub, GatewayMarketHubError


def make_hub(provider, confirmation=None):
    key = _key()
    return GatewayMarketHub(
        provider,
        key_universe=(key,),
        principal_allowed_keys={"principal:a": (key,)},
        service_identity=_identity(),
        service_scope=_scope(),
        publisher=lambda _: None,
        provider_cleanup_confirmed=confirmation,
    )


@pytest.mark.parametrize("bad", [False, 0, "yes", object()])
def test_invalid_confirmation_dependency_is_rejected(bad):
    with pytest.raises(GatewayMarketHubError, match="INVALID_PROVIDER_CLEANUP_CONFIRMATION"):
        make_hub(CountedProvider(), bad)


@pytest.mark.parametrize("failed", ["raise", "none"])
@pytest.mark.parametrize("answer", [False, 1, "true", "raise"])
def test_uncertain_start_retained_until_exact_confirmed_close(failed, answer):
    class UncertainProvider(CountedProvider):
        calls = 0

        def subscribe(self, key, *, generation):
            self.calls += 1
            if failed == "raise":
                raise RuntimeError("synthetic ambiguous native failure")
            return None

    provider = UncertainProvider()
    proof = [answer]

    def confirmed():
        if proof[0] == "raise":
            raise RuntimeError("synthetic unavailable confirmation")
        return proof[0]

    hub = make_hub(provider, confirmed)
    with pytest.raises(GatewayMarketHubError):
        hub.subscribe("principal:a", _key(), "reg:a")
    with pytest.raises(GatewayMarketHubError, match="PROVIDER_SUBSCRIBE_OUTCOME_UNKNOWN"):
        hub.close()
    assert hub._stream(_key()).start_uncertain is True
    assert hub.readiness["closing"] is False
    with pytest.raises(GatewayMarketHubError, match="PROVIDER_SUBSCRIBE_OUTCOME_UNKNOWN"):
        hub.subscribe("principal:a", _key(), "reg:a")
    assert provider.calls == 1 and provider.unsubscribed == []
    proof[0] = True
    hub.close()
    hub.close()
    assert hub.readiness["closing"] is True
    assert hub._stream(_key()).start_uncertain is False
    with pytest.raises(GatewayMarketHubError, match="HUB_CLOSED"):
        hub.subscribe("principal:a", _key(), "reg:a")
    assert provider.calls == 1 and provider.unsubscribed == []


def test_confirmed_provider_close_clears_active_handle_without_unsubscribe():
    provider = CountedProvider()
    proof = [False]
    hub = make_hub(provider, lambda: proof[0])
    hub.subscribe("principal:a", _key(), "reg:a")
    stream = hub._stream(_key())
    handle = stream.handle
    provider.fail_unsubscribe = 1
    with pytest.raises(GatewayMarketHubError, match="PROVIDER_UNSUBSCRIBE_FAILED"):
        hub.close()
    assert stream.handle is handle and stream.pending_release is True
    proof[0] = True
    hub.close()
    hub.close()
    assert provider.unsubscribed == [handle]
    assert stream.handle is None and stream.pending_release is False
    assert stream.generation is None and not stream.registrations
    assert hub._registration_ref_count == 0 and hub._registration_principals == {}
    assert hub.readiness["active_upstreams"] == hub.readiness["pending_releases"] == 0


def test_confirmed_close_clears_active_registrations_without_provider_call():
    provider = CountedProvider()
    hub = make_hub(provider, lambda: True)
    hub.subscribe("principal:a", _key(), "reg:a")
    hub.close()
    assert provider.unsubscribed == []
    assert hub._registration_ref_count == 0 and not hub._registration_principals
    assert hub.readiness["active_registrations"] == hub.readiness["active_upstreams"] == 0


def test_owner_thread_and_in_progress_guards_precede_confirmation():
    calls = []
    hub = make_hub(CountedProvider(), lambda: calls.append(True) or True)
    errors = []

    def wrong_thread():
        try:
            hub.close()
        except GatewayMarketHubError as error:
            errors.append(error.code)

    thread = threading.Thread(target=wrong_thread)
    thread.start()
    thread.join(timeout=2)
    assert not thread.is_alive() and errors == ["OWNER_THREAD_REQUIRED"] and not calls
    stream = hub._stream(_key())
    stream.starting = True
    with pytest.raises(GatewayMarketHubError, match="PROVIDER_START_IN_PROGRESS"):
        hub.close()
    assert not calls
    stream.starting = False
    hub.close()
    assert calls == [True]
