"""Service integration tests for trusted, bounded consumer-read pages."""

from __future__ import annotations

import json
from collections.abc import Mapping
from types import MappingProxyType
from typing import Optional

import pytest
from bt_api_base.account_protocol import AccountKey, AccountResourceKey
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope

from bt_api_gateway import GatewayCommandKind, GatewayEventJournal, GatewayPrincipal
from bt_api_gateway.account_session_worker import GatewayAccountSessionWorker
from bt_api_gateway.event_journal import GatewayEventJournalError
from bt_api_gateway.service_component import (
    GatewayReadService,
    GatewayServiceAccountScope,
    GatewayServiceError,
)
from bt_api_gateway.session_guard import LocalAccountSessionGuard


def _principal(
    *,
    accounts: frozenset[str] = frozenset({"account:journal"}),
) -> GatewayPrincipal:
    return GatewayPrincipal(
        principal_id="principal-a",
        account_scopes=accounts,
        strategy_scopes=frozenset({"strategy:alpha", "strategy:account_read"}),
        allowed_kinds=frozenset({GatewayCommandKind.READ}),
    )


def _scope() -> WireScope:
    return WireScope(
        execution_domain_ref="paper-a",
        account_ref="account-a",
        strategy_ref="strategy-a",
    )


def _identity() -> WireIdentity:
    return WireIdentity(
        role=WireRole.STRATEGY_CLIENT,
        principal_ref="principal-a",
        actor_ref="actor-a",
    )


def _service(
    journal: GatewayEventJournal,
    *,
    principal: Optional[GatewayPrincipal] = None,  # noqa: UP045 -- Python 3.9 support.
    state_worker: Optional[GatewayAccountSessionWorker] = None,  # noqa: UP045
) -> GatewayReadService:
    return GatewayReadService(
        journal,
        accounts={
            "account-a": GatewayServiceAccountScope(
                account_ref="account-a",
                execution_domain_ref="paper-a",
                journal_account_scope="account:journal",
                strategy_scope_map={"strategy-a": "strategy:alpha"},
                account_read_strategy_scope="strategy:account_read",
            )
        },
        principals={"principal-a": principal or _principal()},
        state_worker=state_worker,
    )


class _UnusedProvider:
    def connect(self, *, account_key: AccountKey, generation: str, timeout: float) -> None:
        raise AssertionError("service reads must not connect a provider")

    def read_account(self, *, generation: str, timeout: float):
        raise AssertionError("service reads must not query a provider")

    def close(self) -> None:
        return None


def _state_worker(tmp_path, journal: GatewayEventJournal) -> GatewayAccountSessionWorker:
    guard_dir = tmp_path / "guards"
    guard_dir.mkdir()
    account_key = AccountKey(
        provider="synthetic",
        venue="paper-exchange",
        environment="paper",
        account_id="acct-state",
    )
    return GatewayAccountSessionWorker(
        _UnusedProvider(),
        journal,
        account_key=account_key,
        journal_account_scope="account:journal",
        state_scope="strategy:account_read",
        guard=LocalAccountSessionGuard(guard_dir, account_key.account_key_id, "worker-a"),
        required_coverage=(AccountResourceKey(product_type="spot", margin_pool="cross"),),
        clock=lambda: 1_700_000_000.0,
        monotonic_clock=lambda: 10.0,
    )


def _plain_json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain_json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain_json_value(item) for item in value]
    return value


def _serialized_result(value: Mapping[str, object]) -> bytes:
    normalized = _plain_json_value(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def test_page_fit_sees_full_state_status_result_and_returns_cached_candidate(
    tmp_path, monkeypatch
) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=lambda: 1_700_000_000.0)
    journal.append(
        "account:journal",
        "strategy:alpha",
        "event-1",
        "balance_update",
        {"currency": "USD", "total": "1"},
    )
    worker = _state_worker(tmp_path, journal)
    status_reads = 0

    def read_status() -> Mapping[str, object]:
        nonlocal status_reads
        status_reads += 1
        return MappingProxyType(
            {
                "session_generation": None,
                "ready": False,
                "fresh_for_seconds": float(status_reads),
            }
        )

    monkeypatch.setattr(worker, "read_status", read_status)
    service = _service(journal, state_worker=worker)
    candidates: list[Mapping[str, object]] = []
    serialized_sizes: list[int] = []

    def result_fits(result: Mapping[str, object]) -> bool:
        candidates.append(result)
        serialized_sizes.append(len(_serialized_result(result)))
        return serialized_sizes[-1] <= 100_000

    result = service.handle(
        "account.read_after",
        principal_ref="principal-a",
        scope=_scope(),
        arguments={"track_delivery": True},
        identity=_identity(),
        result_fits=result_fits,
    )

    assert candidates
    assert any(result is candidate for candidate in candidates)
    assert "consumer_progress" in candidates[0]
    assert candidates[0]["consumer_progress"]["offered_cursor"] == 1  # type: ignore[index]
    assert "state_status" in candidates[0]
    assert candidates[0]["state_status"]["fresh_for_seconds"] == 1.0  # type: ignore[index]
    accepted_index = next(
        index for index, candidate in enumerate(candidates) if result is candidate
    )
    assert len(_serialized_result(result)) == serialized_sizes[accepted_index]
    assert all(
        candidate["state_status"] == candidates[0]["state_status"] for candidate in candidates
    )
    assert status_reads == 1


def test_fit_callback_runs_only_after_consumer_identity_and_journal_acl(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    calls: list[Mapping[str, object]] = []
    service = _service(journal)

    with pytest.raises(GatewayServiceError) as missing_identity:
        service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"track_delivery": True},
            result_fits=lambda result: calls.append(result) is None,
        )
    assert missing_identity.value.code == "CONSUMER_IDENTITY_REQUIRED"
    assert calls == []

    denied_service = _service(
        journal,
        principal=_principal(accounts=frozenset({"account:other"})),
    )
    with pytest.raises(GatewayEventJournalError) as denied:
        denied_service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"track_delivery": True},
            identity=_identity(),
            result_fits=lambda result: calls.append(result) is None,
        )
    assert denied.value.code == "ACCOUNT_SCOPE_DENIED"
    assert calls == []


def test_result_fitter_is_trusted_context_and_legacy_untracked_shape_is_unchanged(
    tmp_path,
) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    journal.append("account:journal", "strategy:alpha", "event-1", "balance", {"USD": "1"})
    service = _service(journal)
    calls: list[Mapping[str, object]] = []

    result = service.handle(
        "account.read_after",
        principal_ref="principal-a",
        scope=_scope(),
        arguments={"cursor": 0, "track_delivery": False},
        result_fits=lambda value: calls.append(value) is None,
    )

    assert set(result) == {
        "requested_cursor",
        "snapshot",
        "events",
        "next_cursor",
        "latest_cursor",
        "recovered_from_snapshot",
    }
    assert result["latest_cursor"] == 1
    assert calls == []
    with pytest.raises(GatewayServiceError) as wire_callback:
        service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"track_delivery": True, "result_fits": True},
            identity=_identity(),
        )
    assert wire_callback.value.code == "UNKNOWN_ARGUMENT"
    with pytest.raises(GatewayServiceError) as non_callable:
        service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"track_delivery": True},
            identity=_identity(),
            result_fits=True,  # type: ignore[arg-type]
        )
    assert non_callable.value.code == "INVALID_RESULT_FITNESS_CHECK"


def test_oversized_snapshot_does_not_create_or_advance_consumer_progress(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=lambda: 1_700_000_000.0)
    journal.replace_state_snapshot(
        "account:journal",
        "strategy:alpha",
        "snapshot-1",
        {"facts": "x" * 80_000},
        expected_cursor=0,
        captured_at=1_700_000_000.0,
    )
    service = _service(journal)
    inspected: list[Mapping[str, object]] = []

    with pytest.raises(GatewayEventJournalError) as too_large:
        service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"track_delivery": True},
            identity=_identity(),
            result_fits=lambda result: inspected.append(result) is None and False,
        )
    assert too_large.value.code == "CONSUMER_PAGE_TOO_LARGE"
    assert inspected
    assert inspected[0]["snapshot"]["snapshot_id"] == "snapshot-1"  # type: ignore[index]

    with pytest.raises(GatewayEventJournalError) as no_progress:
        service.handle(
            "account.progress",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={},
            identity=_identity(),
        )
    assert no_progress.value.code == "CONSUMER_NOT_FOUND"
