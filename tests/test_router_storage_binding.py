"""GW04: actual SQLite binding and writer ownership before provider dispatch."""

from __future__ import annotations

import os
import sqlite3

import pytest

from bt_api_gateway import (
    GatewayAccountWriterAuthority,
    GatewayCommand,
    GatewayCommandKind,
    GatewayCommandRouter,
    GatewayCommandStatus,
    GatewayPrincipal,
    GatewayRoutingError,
)


class Clock:
    now = 1_700_000_000.0

    def __call__(self):
        return self.now


def _principal():
    return GatewayPrincipal(
        principal_id="binding-client",
        account_scopes=frozenset({"account:binding"}),
        strategy_scopes=frozenset({"strategy:binding"}),
        allowed_kinds=frozenset({GatewayCommandKind.SUBMIT}),
    )


def _command(clock, command_id):
    return GatewayCommand(
        command_id=command_id,
        account_scope="account:binding",
        strategy_scope="strategy:binding",
        kind=GatewayCommandKind.SUBMIT,
        payload={"symbol": "SYNTHETIC", "quantity": "1"},
        receipt_digest="synthetic-approved-contract",
        issued_at=clock.now,
        expires_at=clock.now + 10,
    )


def _router(path, authority, clock, calls):
    return GatewayCommandRouter(
        path,
        lambda command: calls.append(command.command_id) or {"returned": True},
        clock=clock,
        admission=lambda _principal, _command: True,
        writer_authority=authority,
    )


def test_same_sqlite_file_binding_dispatches_once_and_persists_owner(tmp_path):
    clock = Clock()
    database = tmp_path / "gateway.sqlite"
    authority = GatewayAccountWriterAuthority(database, clock=clock)
    lease = authority.acquire_writer("account:binding", "owner-a", lease_seconds=30)
    calls = []
    router = _router(tmp_path / "." / "gateway.sqlite", authority, clock, calls)
    command = _command(clock, "same-file")

    result = router.dispatch(_principal(), command)
    repeated = router.dispatch(_principal(), command)

    assert os.path.samefile(database, authority.database_path)
    assert result.status is GatewayCommandStatus.RETURNED_UNVERIFIED
    assert repeated.status is result.status
    assert calls == ["same-file"]
    with sqlite3.connect(database) as connection:
        rows = connection.execute("SELECT owner_id, epoch FROM gateway_action_claims").fetchall()
        assert rows == [("owner-a", lease.epoch)]
        assert connection.execute("SELECT count(*) FROM gateway_commands").fetchone() == (1,)


def test_different_sqlite_files_reject_binding_before_provider_or_router_schema(tmp_path):
    clock = Clock()
    authority = GatewayAccountWriterAuthority(tmp_path / "owner.sqlite", clock=clock)
    authority.acquire_writer("account:binding", "owner-a", lease_seconds=30)
    router_path = tmp_path / "router.sqlite"
    with sqlite3.connect(router_path) as connection:
        connection.execute("CREATE TABLE untouched (value INTEGER)")
    calls = []

    with pytest.raises(ValueError, match="must use the same SQLite database"):
        _router(router_path, authority, clock, calls)

    assert not os.path.samefile(router_path, authority.database_path)
    assert calls == []
    with sqlite3.connect(router_path) as connection:
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall() == [("untouched",)]


@pytest.mark.parametrize("binding", ["unowned", "stale-owner"])
def test_same_file_with_wrong_owner_rejects_before_provider(tmp_path, binding):
    clock = Clock()
    database = tmp_path / "gateway.sqlite"
    old_owner = GatewayAccountWriterAuthority(database, clock=clock)
    old_lease = old_owner.acquire_writer("account:binding", "owner-a", lease_seconds=1)
    second_authority = GatewayAccountWriterAuthority(database, clock=clock)
    if binding == "stale-owner":
        clock.now += 2
        new_lease = second_authority.acquire_writer("account:binding", "owner-b", lease_seconds=30)
        assert new_lease.epoch == old_lease.epoch + 1
        rejected_authority = old_owner
        expected_owner = "owner-b"
    else:
        rejected_authority = second_authority
        expected_owner = "owner-a"
    calls = []
    router = _router(database, rejected_authority, clock, calls)

    with pytest.raises(GatewayRoutingError) as rejected:
        router.dispatch(_principal(), _command(clock, binding))

    assert rejected.value.code == "WRITER_ACTION_CLAIM_REJECTED"
    assert calls == []
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT owner_id FROM gateway_writer_epochs").fetchall() == [
            (expected_owner,)
        ]
        assert connection.execute("SELECT count(*) FROM gateway_action_claims").fetchone() == (0,)
        assert connection.execute("SELECT status FROM gateway_commands").fetchone() == (
            GatewayCommandStatus.REJECTED.value,
        )
