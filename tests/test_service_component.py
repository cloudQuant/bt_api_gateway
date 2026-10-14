"""Gateway service options and real journal-backed account reads."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Optional

import pytest
from bt_api_base.service_protocol import WireScope

from bt_api_gateway import GatewayCommandKind, GatewayEventJournal, GatewayPrincipal
from bt_api_gateway.event_journal import GatewayEventJournalError
from bt_api_gateway.service_component import (
    SUPPORTED_OPERATIONS,
    GatewayReadService,
    GatewayServiceAccountScope,
    GatewayServiceError,
    validate_service_options,
)


def _principal(
    principal_id: str,
    *,
    accounts: frozenset[str] = frozenset({"account:journal"}),
    strategies: frozenset[str] = frozenset({"strategy:alpha", "strategy:account_read"}),
    allowed_kinds: frozenset[GatewayCommandKind] = frozenset({GatewayCommandKind.READ}),
) -> GatewayPrincipal:
    return GatewayPrincipal(
        principal_id=principal_id,
        account_scopes=accounts,
        strategy_scopes=strategies,
        allowed_kinds=allowed_kinds,
    )


def _scope(
    *,
    account_ref: Optional[str] = "account-a",  # noqa: UP045 -- Python 3.9 support.
    execution_domain_ref: str = "paper-a",
    strategy_ref: Optional[str] = "strategy-a",  # noqa: UP045 -- Python 3.9 support.
    run_id: Optional[str] = None,  # noqa: UP045 -- Python 3.9 support.
) -> WireScope:
    return WireScope(
        execution_domain_ref=execution_domain_ref,
        account_ref=account_ref,
        strategy_ref=strategy_ref,
        run_id=run_id,
    )


def _service(journal: GatewayEventJournal) -> GatewayReadService:
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
        principals={"principal-a": _principal("principal-a")},
    )


def test_service_options_match_sdk_gateway_roles_and_return_immutable_mapping() -> None:
    market = validate_service_options({"role": "market_hub"}, ("service.market_source",))
    account = validate_service_options(
        {
            "role": "account_session_worker",
            "account_session_ref": "a01-session",
        },
        ("service.account_read", "service.provider_session"),
    )

    assert market == {"role": "market_hub"}
    assert account == {
        "role": "account_session_worker",
        "account_session_ref": "a01-session",
    }
    assert type(market) is type(account) is type(MappingProxyType({}))
    with pytest.raises(TypeError):
        market["role"] = "account_session_worker"  # type: ignore[index]


@pytest.mark.parametrize(
    "options,ports,code",
    [
        ({"role": "unknown"}, ("service.account_read",), "UNKNOWN_SERVICE_ROLE"),
        (
            {"role": "market_hub", "account_session_ref": "session-a"},
            ("service.market_source",),
            "UNKNOWN_OPTION",
        ),
        (
            {"role": "account_session_worker"},
            ("service.account_read",),
            "MISSING_ACCOUNT_SESSION_REF",
        ),
        (
            {"role": "account_session_worker", "account_session_ref": "bad ref"},
            ("service.account_read",),
            "INVALID_ACCOUNT_SESSION_REF",
        ),
        (
            {"role": "market_hub"},
            ("service.account_read",),
            "ROLE_PORT_MISMATCH",
        ),
        (
            {"role": "account_session_worker", "account_session_ref": "session-a"},
            ("service.account_read", "service.account_read"),
            "INVALID_BIND_PORTS",
        ),
    ],
)
def test_service_options_reject_unknown_or_mismatched_configuration(
    options: Mapping[str, object], ports: tuple[str, ...], code: str
) -> None:
    with pytest.raises(GatewayServiceError) as raised:
        validate_service_options(options, ports)
    assert raised.value.code == code


def test_read_after_uses_real_journal_acl_and_recovers_from_persisted_snapshot(
    tmp_path,
) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=lambda: 1_700_000_000.0)
    journal.append(
        "account:journal",
        "strategy:alpha",
        "event-1",
        "position_update",
        {"symbol": "BTC-USDT", "quantity": "1"},
    )
    persisted = journal.capture_snapshot(
        "account:journal",
        "strategy:alpha",
        "snapshot-1",
        expected_cursor=1,
        payload={"positions": {"BTC-USDT": "1"}},
    )
    journal.append(
        "account:journal",
        "strategy:alpha",
        "event-2",
        "position_update",
        {"symbol": "BTC-USDT", "quantity": "2"},
    )

    result = _service(journal).handle(
        "account.read_after",
        principal_ref="principal-a",
        scope=_scope(),
        arguments={"cursor": 0, "limit": 1},
    )

    assert result["requested_cursor"] == 0
    assert result["snapshot"]["snapshot_id"] == persisted.snapshot_id  # type: ignore[index]
    assert result["snapshot"]["cursor"] == 1  # type: ignore[index]
    assert [event["sequence"] for event in result["events"]] == [2]  # type: ignore[index]
    assert result["next_cursor"] == result["latest_cursor"] == 2
    assert result["recovered_from_snapshot"] is True
    assert "snapshot_source" not in result


def test_account_snapshot_uses_explicit_account_stream_and_labels_persisted_baseline(
    tmp_path,
) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=lambda: 1_700_000_000.0)
    journal.append(
        "account:journal",
        "strategy:account_read",
        "account-event-1",
        "balance_update",
        {"currency": "USD", "balance": "10"},
    )
    journal.capture_snapshot(
        "account:journal",
        "strategy:account_read",
        "account-snapshot-1",
        expected_cursor=1,
        payload={"balances": {"USD": "10"}},
    )

    service = _service(journal)
    snapshot = service.handle(
        "account.snapshot",
        principal_ref="principal-a",
        scope=_scope(strategy_ref=None),
        arguments={},
    )
    head = service.handle(
        "account.head",
        principal_ref="principal-a",
        scope=_scope(strategy_ref=None),
        arguments={},
    )

    assert snapshot["snapshot_source"] == "persisted_journal_baseline"
    assert snapshot["snapshot"]["snapshot_id"] == "account-snapshot-1"  # type: ignore[index]
    assert snapshot["snapshot"]["strategy_scope"] == "strategy:account_read"  # type: ignore[index]
    assert snapshot["events"] == ()
    assert head == {"latest_cursor": 1}
    assert (
        journal.read_after(
            _principal("principal-a"),
            "account:journal",
            "strategy:account_read",
            cursor=1,
        ).latest_cursor
        == 1
    )


def test_account_snapshot_without_persisted_baseline_does_not_claim_one(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")

    result = _service(journal).handle(
        "account.snapshot",
        principal_ref="principal-a",
        scope=_scope(strategy_ref=None),
        arguments={},
    )

    assert result["snapshot"] is None
    assert result["snapshot_source"] is None
    assert result["events"] == ()
    assert result["latest_cursor"] == 0


def test_account_wide_scope_requires_explicit_mapping_and_strategy_scope_is_exact(
    tmp_path,
) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    no_account_stream = GatewayReadService(
        journal,
        accounts={
            "account-a": GatewayServiceAccountScope(
                account_ref="account-a",
                execution_domain_ref="paper-a",
                journal_account_scope="account:journal",
                strategy_scope_map={"strategy-a": "strategy:alpha"},
            )
        },
        principals={"principal-a": _principal("principal-a")},
    )

    with pytest.raises(GatewayServiceError) as no_stream:
        no_account_stream.handle(
            "account.head",
            principal_ref="principal-a",
            scope=_scope(strategy_ref=None),
            arguments={},
        )
    assert no_stream.value.code == "ACCOUNT_WIDE_READ_NOT_CONFIGURED"

    with pytest.raises(GatewayServiceError) as widened:
        _service(journal).handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(strategy_ref="strategy-b", run_id="run-b"),
            arguments={},
        )
    assert widened.value.code == "STRATEGY_SCOPE_DENIED"


def test_strategy_run_scope_reads_the_same_durable_strategy_stream(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    journal.append(
        "account:journal",
        "strategy:alpha",
        "event-1",
        "position_update",
        {"symbol": "BTC-USDT", "quantity": "1"},
    )
    service = _service(journal)

    without_run = service.handle(
        "account.read_after",
        principal_ref="principal-a",
        scope=_scope(),
        arguments={},
    )
    with_run = service.handle(
        "account.read_after",
        principal_ref="principal-a",
        scope=_scope(strategy_ref="strategy-a", run_id="run-a"),
        arguments={},
    )

    assert with_run["events"] == without_run["events"]
    assert with_run["latest_cursor"] == without_run["latest_cursor"] == 1


@pytest.mark.parametrize(
    "scope,principal_ref,arguments,operation,code",
    [
        (
            _scope(account_ref="unknown-account"),
            "principal-a",
            {},
            "account.head",
            "UNKNOWN_ACCOUNT",
        ),
        (
            _scope(execution_domain_ref="other-domain"),
            "principal-a",
            {},
            "account.head",
            "EXECUTION_DOMAIN_DENIED",
        ),
        (_scope(), "unknown-principal", {}, "account.head", "UNKNOWN_PRINCIPAL"),
        (
            _scope(),
            "principal-a",
            {"account_ref": "account-b"},
            "account.read_after",
            "UNKNOWN_ARGUMENT",
        ),
        (
            _scope(),
            "principal-a",
            {"principal_ref": "principal-b"},
            "account.read_after",
            "UNKNOWN_ARGUMENT",
        ),
        (
            _scope(),
            "principal-a",
            {"scope": {"strategy_ref": "strategy-b"}},
            "account.read_after",
            "UNKNOWN_ARGUMENT",
        ),
        (_scope(), "principal-a", {}, "account.ack", "UNSUPPORTED_OPERATION"),
    ],
)
def test_handle_rejects_untrusted_identity_scope_arguments_and_unsupported_ops(
    tmp_path, scope, principal_ref, arguments, operation, code
) -> None:
    service = _service(GatewayEventJournal(tmp_path / "gateway.db"))
    with pytest.raises(GatewayServiceError) as raised:
        service.handle(
            operation,
            principal_ref=principal_ref,
            scope=scope,
            arguments=arguments,
        )
    assert raised.value.code == code


@pytest.mark.parametrize(
    "principal,code",
    [
        (
            _principal("principal-a", accounts=frozenset({"account:elsewhere"})),
            "ACCOUNT_SCOPE_DENIED",
        ),
        (
            _principal("principal-a", strategies=frozenset({"strategy:elsewhere"})),
            "STRATEGY_SCOPE_DENIED",
        ),
        (
            _principal("principal-a", allowed_kinds=frozenset({GatewayCommandKind.SUBMIT})),
            "COMMAND_KIND_DENIED",
        ),
    ],
)
def test_journal_acl_rejects_account_strategy_or_read_not_authorized(
    tmp_path, principal, code
) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    service = GatewayReadService(
        journal,
        accounts={
            "account-a": GatewayServiceAccountScope(
                account_ref="account-a",
                execution_domain_ref="paper-a",
                journal_account_scope="account:journal",
                strategy_scope_map={"strategy-a": "strategy:alpha"},
            )
        },
        principals={"principal-a": principal},
    )

    with pytest.raises(GatewayEventJournalError) as denied:
        service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={},
        )
    assert denied.value.code == code


def test_read_cursor_and_limit_are_bounded_by_real_journal_contract(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    service = _service(journal)

    with pytest.raises(GatewayEventJournalError) as ahead:
        service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"cursor": 1},
        )
    assert ahead.value.code == "CURSOR_AHEAD"

    with pytest.raises(GatewayEventJournalError) as too_large:
        service.handle(
            "account.read_after",
            principal_ref="principal-a",
            scope=_scope(),
            arguments={"limit": GatewayEventJournal.MAX_BATCH_SIZE + 1},
        )
    assert too_large.value.code == "BATCH_SIZE_INVALID"


def test_supported_operations_are_finite_and_service_borrows_journal(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "gateway.db")
    service = _service(journal)

    assert (
        frozenset({"account.read_after", "account.snapshot", "account.head"})
        == SUPPORTED_OPERATIONS
    )
    result = service.handle(
        "account.head",
        principal_ref="principal-a",
        scope=_scope(),
        arguments={},
    )
    assert result["latest_cursor"] == 0
    assert (
        journal.read_after(
            _principal("principal-a"), "account:journal", "strategy:alpha"
        ).latest_cursor
        == 0
    )
