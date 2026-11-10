"""Synthetic checks for nonblocking, registration-scoped market bootstrap."""

import pytest
from test_market_hub import CountedProvider, _identity, _key, _scope, _source_descriptor

from bt_api_gateway.market_hub import (
    GatewayMarketHub,
    GatewayMarketHubError,
    GatewayMarketRegistration,
    GatewayMarketService,
    GatewayMarketServiceError,
)


class AsyncProvider(CountedProvider):
    def __init__(self):
        super().__init__()
        self.ready = False
        self.descriptor_ready = False
        self.descriptor_bad = False
        self.release_ready = True
        self.poll_count = 0

    def begin_subscribe(self, key, *, generation):
        return super().subscribe(key, generation=generation)

    def subscription_ready(self, handle):
        return self.ready

    def probe_source(self, handle, *, key, generation, stream_id, epoch):
        if self.descriptor_bad:
            raise RuntimeError("failed")
        if not self.descriptor_ready:
            return None
        return _source_descriptor(key, stream_id=stream_id, epoch=epoch)

    def unsubscribe(self, handle):
        if not self.release_ready:
            return False
        return super().unsubscribe(handle)

    def poll(self, handle, *, limit):
        self.poll_count += 1
        return ()


def setup(*, keys=None, principals=("a",), **options):
    keys = keys or (_key(),)
    provider = AsyncProvider()
    hub = GatewayMarketHub(
        provider,
        key_universe=keys,
        principal_allowed_keys=dict.fromkeys(principals, keys),
        service_identity=_identity(),
        service_scope=_scope(),
        **options,
    )
    hub.set_publisher(lambda value: None)
    regs = {
        p: GatewayMarketRegistration(principal_ref=p, execution_domain_ref="domain:paper")
        for p in principals
    }
    return hub, provider, GatewayMarketService(hub, registrations=regs)


def call(service, operation, principal="a", **arguments):
    return service.handle(
        "market." + operation,
        principal_ref=principal,
        scope=_scope(),
        registration_id=principal,
        arguments=arguments,
        result_fits=lambda result: True,
    )


def begin(service, oid, keys, principal="a", descriptor=False, refresh=False):
    return call(
        service,
        "bootstrap_begin",
        principal,
        operation_id=oid,
        refresh_existing=refresh,
        subscriptions=[
            {"key": key.to_dict(), "require_source_descriptor": descriptor} for key in keys
        ],
    )


def status(service, oid, principal="a"):
    return call(service, "bootstrap_status", principal, operation_id=oid)


def advance(service, oid, principal="a", limit=200):
    for _ in range(limit):
        result = status(service, oid, principal)
        if result["status"] not in {"pending", "cancelling"}:
            return result
    return result


def test_pending_idempotency_shared_handle_and_descriptor():
    key = _key()
    hub, provider, service = setup(keys=(key,), principals=("a", "b"))
    a, b = "a" * 32, "b" * 32
    assert begin(service, a, (key,), descriptor=True)["status"] == "pending"
    assert begin(service, b, (key,), "b", True)["status"] == "pending"
    for _ in range(5):
        hub.maintain(("a", "b"))
    assert len(provider.subscribed) == 1
    assert not hub.registration_active(key, "a")
    assert provider.poll_count == 0
    assert begin(service, a, (key,), descriptor=True)["status"] == "pending"
    with pytest.raises(GatewayMarketServiceError, match="OPERATION_ID_CONFLICT"):
        begin(service, a, (key,), descriptor=False)
    provider.ready = True
    hub.maintain(("a", "b"))
    assert status(service, a)["status"] == "pending"
    assert len(provider.subscribed) == 1
    provider.descriptor_ready = True
    hub.maintain(("a", "b"))
    first = advance(service, a)
    second = advance(service, b, "b")
    assert first["status"] == second["status"] == "active"
    assert begin(service, a, (key,), descriptor=True) == first
    assert len(provider.subscribed) == 1


def test_rollback_retain_handle_and_cancel_before_begin():
    first, second = _key(), _key(instrument={"instrument_id": "two", "native_symbol": "TWO"})
    hub, provider, service = setup(keys=(first, second))
    provider.ready = True
    provider.descriptor_ready = True
    oid = "a" * 32
    assert begin(service, oid, (first, second), descriptor=True)["status"] == "pending"
    for _ in range(4):
        status(service, oid)
    provider.descriptor_bad = True
    provider.release_ready = False
    for _ in range(10):
        result = status(service, oid)
        if result["status"] == "cancelling":
            break
    assert result["status"] == "cancelling"
    assert len(provider.subscribed) == 2
    with pytest.raises(GatewayMarketHubError, match="PROVIDER_UNSUBSCRIBE_FAILED"):
        hub.close()
    assert len(provider.unsubscribed) == 0
    provider.release_ready = True
    hub.close()
    assert len(provider.unsubscribed) == 2

    _, _, service = setup()
    oid = "b" * 32
    assert call(service, "bootstrap_cancel", operation_id=oid)["status"] == "cancelled"
    assert begin(service, oid, (first,))["status"] == "cancelled"


def test_expiry_capacity_old_owner_and_reply_budget():
    clock = [0.0]
    key = _key()
    hub, provider, service = setup(
        bootstrap_clock=lambda: clock[0],
        bootstrap_timeout_seconds=5,
        bootstrap_max_jobs_per_registration=2,
    )
    oid = "a" * 32
    begin(service, oid, (key,))
    clock[0] = 6
    assert advance(service, oid)["code"] == "BOOTSTRAP_TIMEOUT"
    provider.ready = True
    newer = "b" * 32
    begin(service, newer, (key,))
    assert advance(service, newer)["status"] == "active"
    assert call(service, "bootstrap_cancel", operation_id=oid)["status"] == "rejected"
    assert hub.registration_active(key, "a")
    with pytest.raises(GatewayMarketServiceError, match="BOOTSTRAP_JOB_CAPACITY"):
        call(service, "bootstrap_cancel", operation_id="c" * 32)
    with pytest.raises(GatewayMarketServiceError, match="REPLY_TOO_LARGE"):
        service.handle(
            "market.bootstrap_status",
            principal_ref="a",
            scope=_scope(),
            registration_id="a",
            arguments={"operation_id": newer},
            result_fits=lambda result: False,
        )
    assert status(service, newer)["status"] == "active"


def test_legacy_rpc_rejected_and_partial_provider_rejected():
    key = _key()
    _, provider, service = setup()
    with pytest.raises(GatewayMarketServiceError, match="ASYNC_BOOTSTRAP_REQUIRED"):
        call(service, "subscribe", key=key.to_dict())
    assert not provider.subscribed
    provider.subscription_ready = None
    with pytest.raises(GatewayMarketHubError, match="INVALID_ASYNC_PROVIDER"):
        GatewayMarketHub(
            provider,
            key_universe=(key,),
            principal_allowed_keys={"a": (key,)},
            service_identity=_identity(),
            service_scope=_scope(),
        )


def test_revocation_cancels_pending_and_regrant_never_replays_old_result():
    key = _key()
    other = _key(instrument={"instrument_id": "other", "native_symbol": "OTHER"})
    provider = AsyncProvider()
    provider.ready = True
    hub = GatewayMarketHub(
        provider,
        key_universe=(key, other),
        principal_allowed_keys={"a": (key,), "b": (key, other)},
        service_identity=_identity(),
        service_scope=_scope(),
    )
    hub.set_partitioned_publisher(
        lambda event: None,
        principal_stream_grants=hub.principal_stream_grants(),
        regrant=lambda grants: True,
    )
    service = GatewayMarketService(
        hub,
        registrations={
            p: GatewayMarketRegistration(principal_ref=p, execution_domain_ref="domain:paper")
            for p in ("a", "b")
        },
    )
    old = "a" * 32
    begin(service, old, (key,))
    assert advance(service, old)["status"] == "active"
    begin(service, "b" * 32, (key,), "b")
    assert advance(service, "b" * 32, "b")["status"] == "active"
    hub.revoke_principal_keys("a", (key,))
    assert status(service, old)["status"] == "unknown"
    hub.grant_principal_keys("a", (key,))
    assert status(service, old)["status"] == "unknown"
    assert hub.registration_active(key, "b")
    assert len(provider.subscribed) == 1


def test_first_reply_budget_and_cache_capacity_roll_back():
    key = _key()
    hub, provider, service = setup()
    provider.ready = True
    oid = "d" * 32
    begin(service, oid, (key,))
    hub.maintain(("a",))
    with pytest.raises(GatewayMarketServiceError, match="REPLY_TOO_LARGE"):
        service.handle(
            "market.bootstrap_status",
            principal_ref="a",
            scope=_scope(),
            registration_id="a",
            arguments={"operation_id": oid},
            result_fits=lambda result: False,
        )
    result = advance(service, oid)
    assert result["status"] == "rejected"
    assert result["code"] == "BATCH_REPLY_TOO_LARGE"
    assert not hub.registration_active(key, "a")
    assert len(provider.unsubscribed) == 1

    hub, provider, service = setup(bootstrap_max_result_bytes=1)
    provider.ready = True
    begin(service, oid, (key,))
    assert advance(service, oid)["code"] == "BOOTSTRAP_RESULT_CAPACITY"
    assert not hub.registration_active(key, "a")
    assert len(provider.unsubscribed) == 1


def test_pending_lease_prune_and_delayed_cleanup_bound_context():
    key = _key()
    hub, provider, service = setup(principals=("a", "b"))
    oid = "e" * 32
    begin(service, oid, (key,))
    provider.release_ready = False
    service.maintain(("b",))
    with pytest.raises(GatewayMarketServiceError, match="REGISTRATION_REBIND_DENIED"):
        service.register_registration(
            "a", GatewayMarketRegistration(principal_ref="b", execution_domain_ref="domain:paper")
        )
    assert len(provider.subscribed) == 1
    provider.release_ready = True
    service.maintain(("b",))
    service.maintain(("b",))
    service.register_registration(
        "a", GatewayMarketRegistration(principal_ref="b", execution_domain_ref="domain:paper")
    )


def test_round_robin_job_progress_is_bounded():
    key = _key()
    principals = tuple(f"p{i}" for i in range(40))
    hub, provider, service = setup(principals=principals)
    for i, principal in enumerate(principals):
        begin(service, f"{i:032x}", (key,), principal)
    provider.ready = True
    hub.maintain(principals)
    # At most 32 key stages were advanced; a later sweep advances other jobs.
    count = sum(hub.registration_active(key, p) for p in principals)
    assert count < len(principals)
    for _ in range(10):
        hub.maintain(principals)
    assert all(hub.registration_active(key, p) for p in principals)
    assert len(provider.subscribed) == 1


def test_uncertain_acquisition_is_retained_and_not_retried():
    key = _key()
    hub, provider, service = setup(principals=("a", "b"))
    calls = []

    def fail_start(key, *, generation):
        calls.append(key)
        raise RuntimeError("outcome unknown")

    provider.begin_subscribe = fail_start
    begin(service, "1" * 32, (key,))
    first = advance(service, "1" * 32, limit=5)
    assert first["status"] == "cancelling"
    second = begin(service, "2" * 32, (key,), "b")
    assert second["status"] == "unknown"
    assert second["uncertain_stream_ids"] == [key.stream_id]
    assert len(calls) == 1
    with pytest.raises(GatewayMarketHubError, match="PROVIDER_SUBSCRIBE_OUTCOME_UNKNOWN"):
        hub.close()


def test_epoch_change_invalidates_cached_response():
    key = _key()
    hub, provider, service = setup()
    provider.ready = True
    oid = "3" * 32
    begin(service, oid, (key,))
    assert advance(service, oid)["status"] == "active"
    hub.reset_stream_epoch(key)
    assert advance(service, oid)["status"] == "unknown"
    assert hub.registration_active(key, "a")


def test_refresh_borrows_exact_owner_and_cancel_never_releases_it():
    first, second = _key(), _key(instrument={"instrument_id": "two", "native_symbol": "TWO"})
    hub, provider, service = setup(keys=(first, second))
    provider.ready = provider.descriptor_ready = True
    old, refresh = "4" * 32, "5" * 32
    begin(service, old, (first, second))
    assert advance(service, old)["status"] == "active"
    previous_count = hub.readiness["active_registrations"]
    begin(service, refresh, (first,), descriptor=True, refresh=True)
    response = advance(service, refresh)
    assert response["status"] == "active"
    assert response["items"][0]["subscription"]["already_subscribed"] is True
    assert "source_descriptor" in response["items"][0]["subscription"]
    assert hub.readiness["active_registrations"] == previous_count
    with pytest.raises(GatewayMarketServiceError, match="OPERATION_ID_CONFLICT"):
        begin(service, refresh, (first,), descriptor=True, refresh=False)
    assert call(service, "bootstrap_cancel", operation_id=refresh)["status"] == "cancelled"
    assert hub.registration_active(first, "a") and hub.registration_active(second, "a")
    assert not provider.unsubscribed
    assert status(service, old)["status"] == "active"


def test_lost_active_reply_member_unsubscribe_preserves_other_member():
    first, second = _key(), _key(instrument={"instrument_id": "two", "native_symbol": "TWO"})
    hub, provider, service = setup(keys=(first, second))
    provider.ready = True
    oid = "6" * 32
    begin(service, oid, (first, second))
    # The offered active result is deliberately discarded as if the network lost it.
    assert advance(service, oid)["status"] == "active"
    call(service, "unsubscribe", key=first.to_dict())
    reply = status(service, oid)
    assert reply["status"] == "unknown" and reply["code"] == "BOOTSTRAP_STALE"
    assert reply["uncertain_stream_ids"] == [second.stream_id]
    assert not hub.registration_active(first, "a")
    assert hub.registration_active(second, "a")
    assert len(provider.unsubscribed) == 1
    assert advance(service, oid)["status"] == "unknown"
    call(service, "bootstrap_cancel", operation_id=oid)
    assert advance(service, oid)["status"] == "cancelled"
    assert not hub.registration_active(second, "a")


def test_refresh_pending_failure_and_stale_owner_do_not_remove_original_or_replacement():
    first, second = _key(), _key(instrument={"instrument_id": "two", "native_symbol": "TWO"})
    hub, provider, service = setup(keys=(first, second))
    provider.ready = True
    original, refresh, replacement = "7" * 32, "8" * 32, "9" * 32
    begin(service, original, (first,))
    assert advance(service, original)["status"] == "active"
    begin(service, refresh, (first, second), descriptor=True, refresh=True)
    provider.descriptor_bad = True
    assert advance(service, refresh)["status"] == "rejected"
    assert hub.registration_active(first, "a")
    assert not hub.registration_active(second, "a")
    provider.descriptor_bad = False
    provider.descriptor_ready = True
    begin(service, replacement, (first,), descriptor=True, refresh=True)
    assert advance(service, replacement)["status"] == "active"
    call(service, "unsubscribe", key=first.to_dict())
    next_id = "a" * 32
    begin(service, next_id, (first,))
    assert advance(service, next_id)["status"] == "active"
    assert status(service, replacement)["status"] == "unknown"
    call(service, "bootstrap_cancel", operation_id=replacement)
    assert advance(service, replacement)["status"] == "cancelled"
    assert hub.registration_active(first, "a")


def test_revoke_one_offered_batch_member_keeps_other_and_refresh_can_reacquire():
    first, second = _key(), _key(instrument={"instrument_id": "two", "native_symbol": "TWO"})
    provider = AsyncProvider()
    provider.ready = True
    hub = GatewayMarketHub(
        provider,
        key_universe=(first, second),
        principal_allowed_keys={"a": (first, second), "b": (first,)},
        service_identity=_identity(),
        service_scope=_scope(),
    )
    hub.set_partitioned_publisher(
        lambda event: None,
        principal_stream_grants=hub.principal_stream_grants(),
        regrant=lambda grants: True,
    )
    service = GatewayMarketService(
        hub,
        registrations={
            p: GatewayMarketRegistration(principal_ref=p, execution_domain_ref="domain:paper")
            for p in ("a", "b")
        },
    )
    oid = "b" * 32
    begin(service, oid, (first, second))
    assert advance(service, oid)["status"] == "active"
    hub.revoke_principal_keys("a", (first,))
    assert not hub.registration_active(first, "a")
    assert hub.registration_active(second, "a")
    hub.grant_principal_keys("a", (first,))
    assert status(service, oid)["status"] == "unknown"
    begin(service, "c" * 32, (first, second), refresh=True)
    assert advance(service, "c" * 32)["status"] == "active"
    assert hub.registration_active(first, "a") and hub.registration_active(second, "a")


def test_pending_only_stream_advances_reset_ack_without_poll():
    key = _key()
    provider = AsyncProvider()
    provider.ready = provider.descriptor_ready = True
    provider.reset_phase = "idle"

    def reset_required(handle):
        if provider.reset_phase == "request":
            return True
        if provider.reset_phase == "ack_pending":
            provider.reset_phase = "done"
        return False

    def acknowledge(handle, *, epoch):
        provider.reset_phase = "ack_pending"
        return False

    original_probe = provider.probe_source

    def probe(handle, **kwargs):
        if provider.reset_phase in {"request", "ack_pending"}:
            return None
        return original_probe(handle, **kwargs)

    provider.source_epoch_reset_required = reset_required
    provider.acknowledge_source_epoch_reset = acknowledge
    provider.probe_source = probe
    hub = GatewayMarketHub(
        provider,
        key_universe=(key,),
        principal_allowed_keys={"a": (key,), "b": (key,)},
        service_identity=_identity(),
        service_scope=_scope(),
    )
    hub.set_publisher(lambda value: None)
    service = GatewayMarketService(
        hub,
        registrations={
            p: GatewayMarketRegistration(principal_ref=p, execution_domain_ref="domain:paper")
            for p in ("a", "b")
        },
    )
    begin(service, "d" * 32, (key,))
    assert advance(service, "d" * 32)["status"] == "active"
    provider.reset_phase = "request"
    begin(service, "e" * 32, (key,), "b", True)
    for _ in range(4):
        status(service, "e" * 32, "b")
    hub.maintain(("a", "b"))
    assert provider.reset_phase == "ack_pending"
    call(service, "unsubscribe", key=key.to_dict())
    before = provider.poll_count
    hub.maintain(("a", "b"))
    assert provider.reset_phase == "done"
    assert provider.poll_count == before
    assert advance(service, "e" * 32, "b")["status"] == "active"
    assert len(provider.subscribed) == 1


def test_market_not_ready_preserves_existing_pending_and_offered_refs():
    first = _key()
    second = _key(instrument={"instrument_id": "two", "native_symbol": "TWO"})
    third = _key(instrument={"instrument_id": "three", "native_symbol": "THREE"})
    provider = AsyncProvider()
    provider.ready = True
    delivery = [True]
    hub = GatewayMarketHub(
        provider,
        key_universe=(first, second, third),
        principal_allowed_keys={"a": (first, second), "b": (first, second, third)},
        service_identity=_identity(),
        service_scope=_scope(),
    )
    hub.set_partitioned_publisher(
        lambda event: None,
        principal_stream_grants=hub.principal_stream_grants(),
        regrant=lambda grants: delivery[0],
    )
    service = GatewayMarketService(
        hub,
        registrations={
            p: GatewayMarketRegistration(principal_ref=p, execution_domain_ref="domain:paper")
            for p in ("a", "b")
        },
    )
    active, pending, fresh = "1" * 32, "2" * 32, "3" * 32
    begin(service, active, (first,))
    assert advance(service, active)["status"] == "active"
    provider.ready = False
    begin(service, pending, (second,), "b")
    assert status(service, pending, "b")["status"] == "pending"
    calls = len(provider.subscribed)
    delivery[0] = False
    hub.revoke_principal_keys("b", (third,))
    assert hub.delivery_suspended
    assert begin(service, fresh, (first,)) == {
        "operation_id": fresh,
        "status": "rejected",
        "code": "MARKET_NOT_READY",
    }
    assert status(service, pending, "b")["status"] == "pending"
    assert begin(service, pending, (second,), "b")["status"] == "pending"
    assert status(service, active)["code"] == "MARKET_NOT_READY"
    hub.maintain(("a", "b"))
    assert len(provider.subscribed) == calls
    assert hub.registration_active(first, "a")
    result = call(service, "bootstrap_cancel", "b", operation_id=pending)
    assert result["status"] in {"cancelling", "cancelled"}
    delivery[0] = True
    assert hub.resume_delivery()
    assert status(service, active)["status"] == "active"
    hub.maintain(("a", "b"))
    assert advance(service, pending, "b")["status"] == "cancelled"
    assert hub.registration_active(first, "a")


def test_deadline_expires_while_not_ready_and_unconfirmed_handle_is_retained():
    key, other = _key(), _key(instrument={"instrument_id": "two", "native_symbol": "TWO"})
    provider = AsyncProvider()
    clock = [0.0]
    hub = GatewayMarketHub(
        provider,
        key_universe=(key, other),
        principal_allowed_keys={"a": (key,), "b": (key, other)},
        service_identity=_identity(),
        service_scope=_scope(),
        bootstrap_clock=lambda: clock[0],
        bootstrap_timeout_seconds=5,
    )
    hub.set_partitioned_publisher(
        lambda event: None,
        principal_stream_grants=hub.principal_stream_grants(),
        regrant=lambda grants: False,
    )
    service = GatewayMarketService(
        hub,
        registrations={
            p: GatewayMarketRegistration(principal_ref=p, execution_domain_ref="domain:paper")
            for p in ("a", "b")
        },
    )
    oid = "a" * 32
    assert begin(service, oid, (key,))["status"] == "pending"
    assert len(provider.subscribed) == 1
    provider.release_ready = False
    hub.revoke_principal_keys("b", (other,))
    assert hub.delivery_suspended
    clock[0] = 6
    result = status(service, oid)
    assert result["status"] == "cancelling" and result["code"] == "BOOTSTRAP_TIMEOUT"
    for _ in range(3):
        hub.maintain(("a", "b"))
    assert status(service, oid)["status"] == "cancelling"
    assert len(provider.subscribed) == 1 and not provider.unsubscribed
    provider.release_ready = True
    hub.maintain(("a", "b"))
    assert advance(service, oid)["status"] == "rejected"
    assert len(provider.unsubscribed) == 1


def test_first_active_requires_complete_reply_checker():
    key = _key()
    hub, provider, service = setup()
    provider.ready = True
    oid = "a" * 32
    begin(service, oid, (key,))
    hub.maintain(("a",))
    with pytest.raises(GatewayMarketServiceError, match="REPLY_BUDGET_REQUIRED"):
        service.handle(
            "market.bootstrap_status",
            principal_ref="a",
            scope=_scope(),
            registration_id="a",
            arguments={"operation_id": oid},
        )
    assert hub.registration_active(key, "a")
    assert status(service, oid)["status"] == "active"


def test_not_ready_rejected_id_is_stable_and_conflicts_after_recovery():
    key = _key()
    provider = AsyncProvider()
    hub = GatewayMarketHub(
        provider,
        key_universe=(key,),
        principal_allowed_keys={"a": (key,)},
        service_identity=_identity(),
        service_scope=_scope(),
    )
    service = GatewayMarketService(
        hub,
        registrations={
            "a": GatewayMarketRegistration(principal_ref="a", execution_domain_ref="domain:paper")
        },
    )
    oid = "f" * 32
    assert begin(service, oid, (key,))["code"] == "MARKET_NOT_READY"
    assert not provider.subscribed
    hub.set_publisher(lambda event: None)
    assert begin(service, oid, (key,))["code"] == "MARKET_NOT_READY"
    with pytest.raises(GatewayMarketServiceError, match="OPERATION_ID_CONFLICT"):
        begin(service, oid, (key,), descriptor=True)
    assert not provider.subscribed


@pytest.mark.parametrize("checker", [None, False])
def test_fresh_begin_requires_callable_reply_budget_before_any_effect(checker):
    key = _key()
    hub, provider, service = setup()
    arguments = {"operation_id": "a" * 32, "subscriptions": [{"key": key.to_dict()}]}
    with pytest.raises(GatewayMarketServiceError, match="REPLY_BUDGET_REQUIRED"):
        service.handle(
            "market.bootstrap_begin",
            principal_ref="a",
            scope=_scope(),
            registration_id="a",
            arguments=arguments,
            result_fits=checker,
        )
    assert not provider.subscribed and not hub.registration_active(key, "a")
    assert status(service, "a" * 32)["status"] == "not_found"
    with pytest.raises(GatewayMarketServiceError, match="REPLY_BUDGET_REQUIRED"):
        service.handle(
            "market.bootstrap_begin",
            principal_ref="a",
            scope=_scope(),
            registration_id="a",
            arguments=arguments,
        )
    assert not provider.subscribed


def test_refresh_cannot_borrow_legacy_active_ref():
    key = _key()
    hub, provider, service = setup()
    hub.subscribe("a", key, "a")
    response = begin(service, "a" * 32, (key,), refresh=True)
    assert response["status"] == "rejected"
    assert response["code"] == "MARKET_ALREADY_SUBSCRIBED"
    assert hub.registration_active(key, "a")
    assert len(provider.subscribed) == 1 and not provider.unsubscribed


def test_refresh_without_descriptor_request_does_not_probe_or_invent_one():
    key = _key()
    hub, provider, service = setup()
    provider.ready = True
    begin(service, "a" * 32, (key,))
    assert advance(service, "a" * 32)["status"] == "active"

    def forbidden_probe(handle, **kwargs):
        raise AssertionError("descriptor was not requested")

    provider.probe_source = forbidden_probe
    begin(service, "b" * 32, (key,), refresh=True)
    reply = advance(service, "b" * 32)
    assert reply["status"] == "active"
    assert "source_descriptor" not in reply["items"][0]["subscription"]
    assert hub.registration_active(key, "a")



def test_unsubscribe_answers_for_the_callers_reference_while_the_upstream_release_is_pending():
    # A provider that releases off-thread (the Gateway's owner bridge) cannot
    # confirm the release inside the unsubscribe call. The caller's reference
    # is gone all the same; only the upstream release is still the Hub's work.
    key = _key()
    hub, provider, service = setup(keys=(key,), principals=("a", "b"))
    provider.ready = provider.descriptor_ready = True
    assert begin(service, "1" * 32, (key,))["status"] == "pending"
    assert advance(service, "1" * 32)["status"] == "active"
    assert begin(service, "2" * 32, (key,), "b")["status"] == "pending"
    assert advance(service, "2" * 32, "b")["status"] == "active"

    # Not the last user: an ordinary reply, the upstream stays.
    reply = call(service, "unsubscribe", "b", key=key.to_dict())
    assert reply["upstream_released"] is False and len(provider.unsubscribed) == 0
    assert hub.ready and hub.registration_active(key, "a")

    provider.release_ready = False
    reply = call(service, "unsubscribe", key=key.to_dict())  # the last user leaves
    assert dict(reply) == {"stream_id": key.stream_id, "epoch": hub.head(key)["epoch"],
                           "head": hub.head(key)["head"], "upstream_released": False}
    assert not hub.registration_active(key, "a")
    assert not hub.ready and hub.readiness["pending_releases"] == 1  # the Hub still owes the release
    # Asking again is idempotent and still truthful.
    assert call(service, "unsubscribe", key=key.to_dict())["upstream_released"] is False
    # The Hub's own interface keeps reporting the unconfirmed release.
    with pytest.raises(GatewayMarketHubError, match="PROVIDER_UNSUBSCRIBE_FAILED"):
        hub.unsubscribe("a", key, "a")

    provider.release_ready = True
    hub.maintain(())
    assert hub.ready and len(provider.unsubscribed) == 1
    assert call(service, "unsubscribe", key=key.to_dict())["upstream_released"] is True


def test_unsubscribe_still_fails_while_the_callers_reference_cannot_be_dropped():
    key = _key()
    hub, provider, service = setup(keys=(key,))
    calls = []

    def fail_start(key, *, generation):
        calls.append(key)
        raise RuntimeError("outcome unknown")

    provider.begin_subscribe = fail_start
    begin(service, "1" * 32, (key,))
    advance(service, "1" * 32, limit=5)
    with pytest.raises(GatewayMarketHubError, match="PROVIDER_SUBSCRIBE_OUTCOME_UNKNOWN"):
        call(service, "unsubscribe", key=key.to_dict())
