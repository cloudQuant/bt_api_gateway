"""A re-granted consumer cannot bootstrap events published during revocation."""

from test_market_hub import _scope
from test_market_hub_runtime_revocation_iter60 import A, B, _publish, _setup

from bt_api_gateway.market_hub import GatewayMarketRegistration, GatewayMarketService


def test_bootstrap_snapshot_respects_regrant_floor_with_shared_upstream():
    hub, provider, _transport, key, _only_a = _setup()
    service = GatewayMarketService(
        hub,
        registrations={"reg-new": GatewayMarketRegistration(B, "domain:paper")},
    )
    try:
        _publish(hub, provider, key, 1)
        hub.revoke_principal_keys(B)
        _publish(hub, provider, key, 2)
        assert hub.registration_active(key, "reg-a")
        assert hub.snapshot(key, principal_ref=A)["event"].payload["data"]["last"] == 2
        hub.grant_principal_keys(B, {key})
        floor_epoch, floor_sequence = hub.grant_floor(B, key)

        result = service.handle(
            "market.bootstrap_many",
            principal_ref=B,
            scope=_scope(),
            arguments={"subscriptions": [{"key": key.to_dict()}]},
            registration_id="reg-new",
        )
        assert result["status"] == "active"
        assert result["items"][0]["snapshot"]["event"] is None
        assert result["items"][0]["head"]["head"] == floor_sequence
        assert len(provider.subscribed) == 1

        gap = service.handle(
            "market.read_after",
            principal_ref=B,
            scope=_scope(),
            arguments={
                "key": key.to_dict(),
                "epoch": floor_epoch,
                "after": 0,
                "limit": 10,
            },
            registration_id="reg-new",
        )
        assert gap["gap"] is True and gap["gap_reason"] == "authorization_floor"
        assert gap["events"] == ()
        _publish(hub, provider, key, 3)
        later = service.handle(
            "market.read_after",
            principal_ref=B,
            scope=_scope(),
            arguments={
                "key": key.to_dict(),
                "epoch": floor_epoch,
                "after": floor_sequence,
                "limit": 10,
            },
            registration_id="reg-new",
        )
        assert len(later["events"]) == 1
        assert later["events"][0]["payload"]["data"]["last"] == 3
        assert hub.snapshot(key, principal_ref=A)["event"].payload["data"]["last"] == 3
    finally:
        hub.close()
