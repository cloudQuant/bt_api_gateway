"""Focused service routing and freshness checks for trusted account views."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Optional, Union

import pytest
from bt_api_base.account_protocol import (
    AccountBalance,
    AccountKey,
    AccountObservation,
    AccountResourceKey,
)
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope

from bt_api_gateway import GatewayCommandKind, GatewayEventJournal, GatewayPrincipal
from bt_api_gateway.account_session_worker import (
    GatewayAccountSessionWorker,
    GatewayAccountSessionWorkerError,
)
from bt_api_gateway.account_view_projection import GatewayAccountViewPolicy
from bt_api_gateway.service_component import (
    GatewayReadService,
    GatewayServiceAccountScope,
    GatewayServiceError,
)
from bt_api_gateway.session_guard import LocalAccountSessionGuard

_ACCOUNT_KEY = AccountKey(
    provider="synthetic",
    venue="paper-exchange",
    environment="paper",
    account_id="account-view-test",
)
_RESOURCE_A = AccountResourceKey(product_type="spot", margin_pool="wallet-a")
_RESOURCE_B = AccountResourceKey(product_type="spot", margin_pool="wallet-b")
_RESOURCES = (_RESOURCE_A, _RESOURCE_B)
_OBSERVED_AT = "2023-11-14T22:13:20Z"
_ACCOUNT_SCOPE = "account:view-journal"
_SOURCE_SCOPE = "strategy:source-state"


class _Provider:
    def __init__(
        self,
        observations: tuple[Union[AccountObservation, Exception], ...],  # noqa: UP007
    ) -> None:
        self._observations = list(observations)

    def connect(self, *, account_key: AccountKey, generation: str, timeout: float) -> None:
        assert account_key == _ACCOUNT_KEY
        assert generation
        assert timeout > 0

    def read_account(self, *, generation: str, timeout: float) -> AccountObservation:
        assert generation
        assert timeout > 0
        observation = self._observations.pop(0)
        if isinstance(observation, Exception):
            raise observation
        return observation

    def close(self) -> bool:
        return True


def _observation(
    observation_id: str,
    value_a: int,
    value_b: int,
) -> AccountObservation:
    balances = tuple(
        AccountBalance(
            resource=resource,
            currency="USD",
            total=str(value),
            available=str(value),
            locked="0",
            observed_at_utc=_OBSERVED_AT,
        )
        for resource, value in ((_RESOURCE_A, value_a), (_RESOURCE_B, value_b))
    )
    return AccountObservation(
        account_key=_ACCOUNT_KEY,
        observation_id=observation_id,
        coverage=_RESOURCES,
        balances=balances,
        positions=(),
        valuation=None,
        started_at_utc=_OBSERVED_AT,
        completed_at_utc=_OBSERVED_AT,
        consistency="multi_query",
        balances_complete=True,
        positions_complete=True,
    )


def _policies() -> tuple[GatewayAccountViewPolicy, GatewayAccountViewPolicy]:
    return (
        GatewayAccountViewPolicy(
            view_scope="journal:view-a",
            resources=(_RESOURCE_A,),
            fact_kinds=frozenset({"balances"}),
        ),
        GatewayAccountViewPolicy(
            view_scope="journal:view-b",
            resources=(_RESOURCE_B,),
            fact_kinds=frozenset({"balances"}),
        ),
    )


def _new_worker_service(
    tmp_path,
    observations: tuple[Union[AccountObservation, Exception], ...],  # noqa: UP007
    *,
    view_policies: tuple[GatewayAccountViewPolicy, ...] = _policies(),
    strategy_scope_map: Optional[Mapping[str, str]] = None,  # noqa: UP045
    account_read_strategy_scope: Optional[str] = None,  # noqa: UP045
):
    guard_dir = tmp_path / "guards"
    guard_dir.mkdir(exist_ok=True)
    journal = GatewayEventJournal(tmp_path / "views.db", clock=lambda: 1_700_000_000.0)
    worker = GatewayAccountSessionWorker(
        _Provider(observations),
        journal,
        account_key=_ACCOUNT_KEY,
        journal_account_scope=_ACCOUNT_SCOPE,
        state_scope=_SOURCE_SCOPE,
        guard=LocalAccountSessionGuard(guard_dir, _ACCOUNT_KEY.account_key_id, "view-worker"),
        required_coverage=_RESOURCES,
        view_policies=view_policies,
        clock=lambda: 1_700_000_000.0,
        monotonic_clock=lambda: 10.0,
    )
    if strategy_scope_map is None:
        strategy_scope_map = {
            "strategy-a": "journal:view-a",
            "strategy-b": "journal:view-b",
        }
    account_scope = GatewayServiceAccountScope(
        account_ref="account-a",
        execution_domain_ref="paper-a",
        journal_account_scope=_ACCOUNT_SCOPE,
        strategy_scope_map=strategy_scope_map,
        account_read_strategy_scope=account_read_strategy_scope,
    )
    strategy_refs = frozenset(strategy_scope_map.values())
    if account_read_strategy_scope is not None:
        strategy_refs = strategy_refs | {account_read_strategy_scope}
    principal = GatewayPrincipal(
        principal_id="principal-a",
        account_scopes=frozenset({_ACCOUNT_SCOPE}),
        strategy_scopes=strategy_refs,
        allowed_kinds=frozenset({GatewayCommandKind.READ}),
    )
    service = GatewayReadService(
        journal,
        accounts={"account-a": account_scope},
        principals={"principal-a": principal},
        state_worker=worker,
    )
    return journal, worker, service


def _scope(strategy_ref: Optional[str]) -> WireScope:  # noqa: UP045
    return WireScope(
        execution_domain_ref="paper-a",
        account_ref="account-a",
        strategy_ref=strategy_ref,
    )


def _read(
    service: GatewayReadService,
    operation: str,
    strategy_ref: Optional[str],  # noqa: UP045
    **args,
):
    return service.handle(
        operation,
        principal_ref="principal-a",
        scope=_scope(strategy_ref),
        arguments=args,
    )


def _payload(result):
    snapshot = result["snapshot"]
    assert snapshot is not None
    return snapshot["payload"]


def test_two_views_are_isolated_and_hidden_source_update_keeps_view_fresh(tmp_path) -> None:
    _journal, worker, service = _new_worker_service(
        tmp_path,
        (
            _observation("initial", 100, 200),
            _observation("hidden-b-update", 100, 201),
        ),
        account_read_strategy_scope=_SOURCE_SCOPE,
    )
    worker.start()
    try:
        before_a = _read(service, "account.snapshot", "strategy-a")
        before_b = _read(service, "account.snapshot", "strategy-b")
        canonical = _read(service, "account.snapshot", None)
        view_a = _payload(before_a)
        view_b = _payload(before_b)
        canonical_payload = _payload(canonical)
        assert canonical_payload["schema_id"] == "sdk.account.state"
        assert len(canonical_payload["observation"]["balances"]) == 2
        assert canonical["state_status"]["ready"] is True
        assert view_a["schema_id"] == "sdk.account.view"
        assert view_b["schema_id"] == "sdk.account.view"
        assert view_a["view_scope"] == "journal:view-a"
        assert view_b["view_scope"] == "journal:view-b"
        assert "policy_digest" not in view_a
        assert "policy_digest" not in view_b
        assert view_a["consistency"] == view_b["consistency"] == "multi_query"
        assert tuple(row["resource"] for row in view_a["balances"]) == (_RESOURCE_A.to_dict(),)
        assert tuple(row["resource"] for row in view_b["balances"]) == (_RESOURCE_B.to_dict(),)
        cursor_a = before_a["latest_cursor"]
        cursor_b = before_b["latest_cursor"]

        worker.refresh()
        after_a = _read(service, "account.snapshot", "strategy-a")
        after_b = _read(service, "account.snapshot", "strategy-b")
        head_a = _read(service, "account.head", "strategy-a")
        assert worker.latest_snapshot.cursor == 2
        assert after_a["latest_cursor"] == cursor_a == 1
        assert after_b["latest_cursor"] == cursor_b + 1 == 2
        assert after_a["events"] == ()
        assert len(after_b["events"]) == 1
        delta_b = after_b["events"][0]["payload"]
        assert delta_b["view_scope"] == "journal:view-b"
        assert "policy_digest" not in delta_b
        upsert_b = delta_b["changes"]["balances"]["upsert"]
        assert len(upsert_b) == 1
        assert upsert_b[0]["resource"] == _RESOURCE_B.to_dict()
        assert upsert_b[0]["total"] == "201"
        assert after_a["state_status"]["ready"] is True
        assert after_b["state_status"]["ready"] is True
        assert set(after_a["state_status"]) == {
            "session_generation",
            "ready",
            "fresh_for_seconds",
        }
        assert set(after_b["state_status"]) == set(after_a["state_status"])
        assert head_a["latest_cursor"] == cursor_a
        assert head_a["state_status"]["ready"] is True
    finally:
        worker.close()


def test_partial_view_page_cannot_claim_freshness(tmp_path) -> None:
    _journal, worker, service = _new_worker_service(
        tmp_path,
        (
            _observation("initial", 100, 200),
            _observation("change-one", 101, 200),
            _observation("change-two", 102, 200),
        ),
    )
    worker.start()
    try:
        worker.refresh()
        worker.refresh()
        result = _read(service, "account.snapshot", "strategy-a", limit=1)
        assert result["next_cursor"] < result["latest_cursor"]
        assert result["state_status"]["ready"] is False
        assert result["state_status"]["fresh_for_seconds"] == 0.0
        read_after = service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope("strategy-a"),
            arguments={"cursor": 0, "limit": 1},
        )
        assert read_after["next_cursor"] < read_after["latest_cursor"]
        assert read_after["state_status"]["ready"] is False
        assert read_after["state_status"]["fresh_for_seconds"] == 0.0
    finally:
        worker.close()


def test_stale_worker_does_not_claim_view_freshness(tmp_path) -> None:
    _journal, worker, service = _new_worker_service(
        tmp_path,
        (_observation("initial", 100, 200), RuntimeError("synthetic read failure")),
    )
    worker.start()
    try:
        with pytest.raises(GatewayAccountSessionWorkerError):
            worker.refresh()
        result = _read(service, "account.snapshot", "strategy-a")
        assert result["state_status"]["ready"] is False
        assert result["state_status"]["fresh_for_seconds"] == 0.0
    finally:
        worker.close()


def test_tracked_page_size_checks_use_one_frozen_status_sample(tmp_path, monkeypatch) -> None:
    _journal, worker, service = _new_worker_service(
        tmp_path,
        (
            _observation("initial", 100, 200),
            _observation("change-one", 101, 200),
            _observation("change-two", 102, 200),
        ),
    )
    worker.start()
    try:
        worker.refresh()
        worker.refresh()
        status_calls = 0
        fit_calls = 0
        read_status = worker.read_status

        def counted_status():
            nonlocal status_calls
            status_calls += 1
            return read_status()

        def one_event_fits(result):
            nonlocal fit_calls
            fit_calls += 1
            return len(result["events"]) <= 1

        monkeypatch.setattr(worker, "read_status", counted_status)
        result = service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope("strategy-a"),
            arguments={"track_delivery": True},
            identity=WireIdentity(
                role=WireRole.STRATEGY_CLIENT,
                principal_ref="principal-a",
                actor_ref="actor-a",
            ),
            result_fits=one_event_fits,
        )
        assert fit_calls > 1
        assert status_calls == 1
        assert result["state_status"]["ready"] is False
        assert result["state_status"]["fresh_for_seconds"] == 0.0
    finally:
        worker.close()


def test_view_route_rejects_forged_or_canonical_scope_mapping(tmp_path) -> None:
    observations = (_observation("initial", 100, 200),)
    journal, worker, _service = _new_worker_service(tmp_path, observations)
    try:
        bad_account = GatewayServiceAccountScope(
            account_ref="account-a",
            execution_domain_ref="paper-a",
            journal_account_scope=_ACCOUNT_SCOPE,
            strategy_scope_map={"strategy-a": _SOURCE_SCOPE},
        )
        principal = GatewayPrincipal(
            principal_id="principal-a",
            account_scopes=frozenset({_ACCOUNT_SCOPE}),
            strategy_scopes=frozenset({"journal:view-a", "journal:view-b"}),
            allowed_kinds=frozenset({GatewayCommandKind.READ}),
        )
        with pytest.raises(GatewayServiceError) as invalid_mapping:
            GatewayReadService(
                journal,
                accounts={"account-a": bad_account},
                principals={"principal-a": principal},
                state_worker=worker,
            )
        assert invalid_mapping.value.code == "STATE_VIEW_SCOPE_MAPPING_INVALID"

        canonical_conflict = GatewayServiceAccountScope(
            account_ref="account-a",
            execution_domain_ref="paper-a",
            journal_account_scope=_ACCOUNT_SCOPE,
            account_read_strategy_scope="journal:view-a",
        )
        with pytest.raises(GatewayServiceError) as conflict:
            GatewayReadService(
                journal,
                accounts={"account-a": canonical_conflict},
                principals={"principal-a": principal},
                state_worker=worker,
            )
        assert conflict.value.code == "STATE_VIEW_CANONICAL_SCOPE_CONFLICT"

        service = GatewayReadService(
            journal,
            accounts={
                "account-a": GatewayServiceAccountScope(
                    account_ref="account-a",
                    execution_domain_ref="paper-a",
                    journal_account_scope=_ACCOUNT_SCOPE,
                    strategy_scope_map={"strategy-a": "journal:view-a"},
                )
            },
            principals={"principal-a": principal},
            state_worker=worker,
        )
        for forged_scope in ("strategy-forged", "journal:view-a"):
            with pytest.raises(GatewayServiceError) as forged:
                service.handle(
                    "account.snapshot",
                    principal_ref="principal-a",
                    scope=_scope(forged_scope),
                    arguments={},
                )
            assert forged.value.code == "STRATEGY_SCOPE_DENIED"
    finally:
        worker.close()


def test_no_policy_canonical_route_keeps_full_state_schema(tmp_path) -> None:
    _journal, worker, service = _new_worker_service(
        tmp_path,
        (_observation("canonical", 100, 200),),
        view_policies=(),
        strategy_scope_map={},
        account_read_strategy_scope=_SOURCE_SCOPE,
    )
    worker.start()
    try:
        result = _read(service, "account.snapshot", None)
        payload = _payload(result)
        assert payload["schema_id"] == "sdk.account.state"
        assert payload["schema_version"] == 1
        assert result["state_status"]["ready"] is True
        assert "view_scope" not in payload
    finally:
        worker.close()
