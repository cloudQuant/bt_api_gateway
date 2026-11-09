"""Owner-resolved market clock routing; no live provider or network."""

import pytest

from bt_api_gateway.market_hub import GatewayMarketHubError, GatewayMarketRegistration, GatewayMarketService, GatewayMarketServiceError
from test_market_hub import CountedProvider, _hub, _key, _scope


def test_clock_uses_server_stream_state_and_revalidates_registration():
    class Provider(CountedProvider):
        def read_market_login_clock(self, handle, **kwargs):
            self.observed = (handle, kwargs)
            if self.revoke:
                self.hub.unsubscribe("principal:a", kwargs["key"], "reg:a")
            return {"schema_version": 1}

    provider = Provider()
    provider.revoke = False
    hub, _, _ = _hub(provider=provider)
    provider.hub = hub
    key = _key()
    hub.subscribe("principal:a", key, "reg:a")
    service = GatewayMarketService(hub, registrations={
        "reg:a": GatewayMarketRegistration(principal_ref="principal:a", execution_domain_ref="domain:paper")
    })
    context = {"principal_ref": "principal:a", "scope": _scope(), "registration_id": "reg:a"}
    assert service.handle("market.clock_observation", arguments={"key": key.to_dict()}, **context) == {"schema_version": 1}
    handle, observed = provider.observed
    assert handle is provider.subscribed[0][1]
    assert observed == {"key": key, "generation": provider.generations[key],
                        "stream_id": key.stream_id, "epoch": "epoch-1"}
    with pytest.raises(GatewayMarketServiceError, match="INVALID_ARGUMENTS"):
        service.handle("market.clock_observation", arguments={"key": key.to_dict(), "epoch": "forged"}, **context)
    provider.revoke = True
    with pytest.raises((GatewayMarketHubError, GatewayMarketServiceError), match="MARKET_SOURCE_UNAVAILABLE"):
        service.handle("market.clock_observation", arguments={"key": key.to_dict()}, **context)
