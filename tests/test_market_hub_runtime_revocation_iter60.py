"""Iteration 60 G2: runtime revocation of an already-subscribed market principal.

Local synthetic provider and an in-process recording publisher; the real
CURVE/XPUB rebuild is covered by the SDK host test
``tests/unit/test_iter60_market_runtime_revocation.py`` (INTEGRATION_SIM).
"""

from __future__ import annotations

import pytest

from bt_api_gateway.market_hub import GatewayMarketHub, GatewayMarketHubError

from test_market_hub import CountedProvider, _identity, _key, _scope

A, B = "principal:a", "principal:b"
STAMP = "2026-11-03T00:00:00Z"


class _Transport:
    """Records publications and the grants it was asked to enforce."""

    def __init__(self):
        self.events = []
        self.grants = []
        self.fail = False

    def publish(self, envelope):
        self.events.append(envelope)
        return True

    def regrant(self, grants):
        if self.fail:
            raise RuntimeError("rebuild failed")
        self.grants.append(dict(grants))
        return True


def _setup(regrant=True):
    provider = CountedProvider()
    shared = _key()
    only_a = _key(source_ref="source:a-only")
    hub = GatewayMarketHub(
        provider,
        key_universe=(shared, only_a),
        principal_allowed_keys={A: {shared, only_a}, B: {shared}},
        service_identity=_identity(),
        service_scope=_scope(),
    )
    transport = _Transport()
    hub.set_partitioned_publisher(
        transport.publish,
        principal_stream_grants={
            A: {shared.stream_id, only_a.stream_id},
            B: {shared.stream_id},
        },
        regrant=transport.regrant if regrant else None,
    )
    hub.subscribe(A, shared, "reg-a")
    hub.subscribe(B, shared, "reg-b")
    return hub, provider, transport, shared, only_a


def _publish(hub, provider, key, value):
    return hub.publish(key, {"last": value}, STAMP, generation=provider.generations[key])


def test_revocation_stops_access_drops_registrations_and_rebuilds_transport():
    hub, provider, transport, shared, _ = _setup()
    _publish(hub, provider, shared, 1)
    generation = hub.authorization_generation
    result = hub.revoke_principal_keys(B)
    assert result["authorization_generation"] == generation + 1
    assert result["revoked_stream_ids"] == (shared.stream_id,)
    assert result["dropped_registrations"] == 1 and result["transport_enforced"] is True
    assert transport.grants[-1][B] == frozenset()
    assert not hub.registration_active(shared, "reg-b")
    assert hub.registration_active(shared, "reg-a")
    for call in (
        lambda: hub.subscribe(B, shared, "reg-b2"),
        lambda: hub._authorize_key(B, shared),
    ):
        with pytest.raises(GatewayMarketHubError) as info:
            call()
        assert info.value.code == "MARKET_KEY_DENIED"
    # The shared upstream stays live for A.
    _publish(hub, provider, shared, 2)
    assert len(transport.events) == 2
    assert hub.authorization_diagnostics["revoked_registrations"] == 1


def test_regrant_requires_resync_from_the_floor_and_hides_revoked_history():
    hub, provider, transport, shared, _ = _setup()
    _publish(hub, provider, shared, 1)
    hub.revoke_principal_keys(B)
    _publish(hub, provider, shared, 2)  # published while B is revoked
    _publish(hub, provider, shared, 3)
    head = hub.head(shared)
    result = hub.grant_principal_keys(B, {shared})
    assert result["granted_stream_ids"] == (shared.stream_id,)
    assert hub.grant_floor(B, shared) == (head["epoch"], head["head"])
    assert shared.stream_id in transport.grants[-1][B]
    # Below the floor: an explicit gap, never the events B was not entitled to.
    page = hub.read_after(shared, epoch=head["epoch"], after=1, principal_ref=B)
    assert page["gap"] is True and page["gap_reason"] == "authorization_floor"
    assert page["events"] == ()
    assert hub.snapshot(shared, principal_ref=B)["event"] is None
    # A is unaffected; from the floor B reads only later events.
    assert len(hub.read_after(shared, epoch=head["epoch"], after=1, principal_ref=A)["events"]) == 2
    _publish(hub, provider, shared, 4)
    page = hub.read_after(shared, epoch=head["epoch"], after=head["head"], principal_ref=B)
    assert [event.header.sequence for event in page["events"]] == [head["head"] + 1]
    assert hub.snapshot(shared, principal_ref=B)["event"] is not None
    assert hub.authorization_generation == 3


def test_failed_transport_rebuild_suspends_all_delivery_until_resumed():
    hub, provider, transport, shared, _ = _setup()
    transport.fail = True
    result = hub.revoke_principal_keys(B)
    assert result["transport_enforced"] is False and hub.delivery_suspended
    with pytest.raises(GatewayMarketHubError) as info:
        _publish(hub, provider, shared, 1)
    assert info.value.code == "DELIVERY_SUSPENDED"
    assert transport.events == []
    assert hub.authorization_diagnostics["publisher_regrant_failures"] == 1
    transport.fail = False
    assert hub.resume_delivery() is True and not hub.delivery_suspended
    _publish(hub, provider, shared, 1)
    assert len(transport.events) == 1


def test_without_a_regrant_callback_revocation_fails_closed():
    hub, provider, _transport, shared, _ = _setup(regrant=False)
    assert hub.revoke_principal_keys(B)["transport_enforced"] is False
    with pytest.raises(GatewayMarketHubError):
        _publish(hub, provider, shared, 1)


def test_revocation_needs_a_partitioned_publisher_and_known_principal():
    provider = CountedProvider()
    key = _key()
    hub = GatewayMarketHub(
        provider,
        key_universe=(key,),
        principal_allowed_keys={A: {key}, B: {key}},
        service_identity=_identity(),
        service_scope=_scope(),
    )
    hub.set_publisher(lambda envelope: True)
    with pytest.raises(GatewayMarketHubError) as info:
        hub.revoke_principal_keys(B)
    assert info.value.code == "REVOCATION_REQUIRES_PARTITIONED_PUBLISHER"
    hub2, *_ = _setup()
    with pytest.raises(GatewayMarketHubError) as info:
        hub2.revoke_principal_keys("principal:unknown")
    assert info.value.code == "UNKNOWN_PRINCIPAL"
    with pytest.raises(GatewayMarketHubError) as info:
        hub2.grant_principal_keys(B, {_key(source_ref="not-exported")})
    assert info.value.code == "INVALID_MARKET_KEY"


def test_sole_holder_revocation_releases_the_upstream():
    hub, provider, _transport, _shared, only_a = _setup()
    hub.subscribe(A, only_a, "reg-a-only")
    assert len(provider.active_handles) == 2
    hub.revoke_principal_keys(A, {only_a})
    assert len(provider.active_handles) == 1
