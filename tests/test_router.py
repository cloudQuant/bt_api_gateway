"""Provider-free contract tests for the shared account gateway router."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from bt_api_gateway import (
    GatewayAccountWriterAuthority,
    GatewayActionStatus,
    GatewayCommand,
    GatewayCommandKind,
    GatewayCommandRouter,
    GatewayCommandStatus,
    GatewayDispatchError,
    GatewayPrincipal,
    GatewayRoutingError,
)


class MutableClock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class RecordingExecutor:
    def __init__(self) -> None:
        self.commands = []
        self.fail = False

    def __call__(self, command: GatewayCommand):
        self.commands.append(command)
        if self.fail:
            raise RuntimeError("provider session failure")
        return {"command_id": command.command_id, "accepted": True}


def approve_offline_fixture(_principal: GatewayPrincipal, _command: GatewayCommand) -> bool:
    """Explicit test-only admission; production integrations must inject a verifier."""
    return True


def make_writer_authority(database, clock):
    authority = GatewayAccountWriterAuthority(database, clock=clock)
    authority.acquire_writer("account:demo", "offline-test-owner", lease_seconds=30)
    return authority


@pytest.fixture
def principal() -> GatewayPrincipal:
    return GatewayPrincipal(
        principal_id="client-a",
        account_scopes=frozenset({"account:demo"}),
        strategy_scopes=frozenset({"strategy:one"}),
        allowed_kinds=frozenset(
            {GatewayCommandKind.READ, GatewayCommandKind.SUBMIT, GatewayCommandKind.FREEZE}
        ),
    )


def make_command(
    command_id: str,
    kind: GatewayCommandKind = GatewayCommandKind.SUBMIT,
    payload=None,
    expires_at: float = 1_700_000_010.0,
    manual_resume_authorized: bool = False,
) -> GatewayCommand:
    return GatewayCommand(
        command_id=command_id,
        account_scope="account:demo",
        strategy_scope="strategy:one",
        kind=kind,
        payload=payload if payload is not None else {"symbol": "BTC-USDT", "quantity": "1"},
        receipt_digest="approved-contract-digest",
        issued_at=1_700_000_000.0,
        expires_at=expires_at,
        manual_resume_authorized=manual_resume_authorized,
    )


def test_dispatch_is_idempotent_and_persists_result(tmp_path, principal: GatewayPrincipal) -> None:
    clock = MutableClock()
    executor = RecordingExecutor()
    router = GatewayCommandRouter(
        tmp_path / "gateway.db",
        executor,
        clock=clock,
        admission=approve_offline_fixture,
        writer_authority=make_writer_authority(tmp_path / "gateway.db", clock),
    )
    command = make_command("cmd-1")

    first = router.dispatch(principal, command)
    duplicate = router.dispatch(principal, command)
    assert first.status is GatewayCommandStatus.RETURNED_UNVERIFIED
    assert duplicate.outcome == first.outcome
    assert len(executor.commands) == 1


def test_scope_privilege_and_secret_rejections_happen_before_executor(
    tmp_path, principal: GatewayPrincipal
) -> None:
    executor = RecordingExecutor()
    router = GatewayCommandRouter(
        tmp_path / "gateway.db",
        executor,
        clock=MutableClock(),
        admission=approve_offline_fixture,
        writer_authority=make_writer_authority(tmp_path / "gateway.db", MutableClock()),
    )
    wrong_scope = GatewayCommand(
        command_id="wrong-scope",
        account_scope="account:other",
        strategy_scope="strategy:one",
        kind=GatewayCommandKind.SUBMIT,
        payload={},
        receipt_digest="digest",
        issued_at=1_700_000_000.0,
        expires_at=1_700_000_010.0,
    )
    with pytest.raises(GatewayRoutingError) as scope_error:
        router.dispatch(principal, wrong_scope)
    assert scope_error.value.code == "ACCOUNT_SCOPE_DENIED"
    with pytest.raises(GatewayRoutingError) as kind_error:
        router.dispatch(principal, make_command("drain", GatewayCommandKind.DRAIN))
    assert kind_error.value.code == "COMMAND_KIND_DENIED"
    with pytest.raises(ValueError, match="redacted"):
        make_command("secret", payload={"api_token": "never-forward"})
    assert executor.commands == []


def test_failed_dispatch_is_durable_and_never_retried_implicitly(
    tmp_path, principal: GatewayPrincipal
) -> None:
    executor = RecordingExecutor()
    executor.fail = True
    router = GatewayCommandRouter(
        tmp_path / "gateway.db",
        executor,
        clock=MutableClock(),
        admission=approve_offline_fixture,
        writer_authority=make_writer_authority(tmp_path / "gateway.db", MutableClock()),
    )
    command = make_command("failing")
    with pytest.raises(GatewayDispatchError):
        router.dispatch(principal, command)
    assert len(executor.commands) == 1
    repeated = router.dispatch(principal, command)
    assert repeated.status is GatewayCommandStatus.UNKNOWN
    assert len(executor.commands) == 1


def test_expired_and_resume_commands_fail_closed(tmp_path, principal: GatewayPrincipal) -> None:
    clock = MutableClock(1_700_000_011.0)
    executor = RecordingExecutor()
    router = GatewayCommandRouter(tmp_path / "gateway.db", executor, clock=clock)
    with pytest.raises(GatewayRoutingError) as expired_error:
        router.dispatch(principal, make_command("expired"))
    assert expired_error.value.code == "COMMAND_EXPIRED"
    with pytest.raises(ValueError, match="manual authorization"):
        make_command("resume", GatewayCommandKind.RESUME)
    assert executor.commands == []


def test_command_captures_immutable_nested_payload_before_dispatch(tmp_path, principal):
    payload = {"legs": [{"quantity": "1"}]}
    command = make_command("immutable", payload=payload)
    original_fingerprint = command.fingerprint
    payload["legs"][0]["quantity"] = "999"
    payload["api_key"] = "must-not-enter-command"
    with pytest.raises(TypeError):
        command.payload["legs"][0]["quantity"] = "888"
    assert command.fingerprint == original_fingerprint
    executor = RecordingExecutor()
    router = GatewayCommandRouter(
        tmp_path / "gateway.db",
        executor,
        clock=MutableClock(),
        admission=approve_offline_fixture,
        writer_authority=make_writer_authority(tmp_path / "gateway.db", MutableClock()),
    )
    router.dispatch(principal, command)
    assert executor.commands[0].payload["legs"][0]["quantity"] == "1"
    assert "api_key" not in router.get("immutable").command.payload


@pytest.mark.parametrize("value", [float("nan"), float("inf"), True])
def test_command_deadline_is_finite(value):
    with pytest.raises(ValueError):
        make_command("invalid-time", expires_at=value)


def test_future_command_cannot_dispatch(tmp_path, principal):
    executor = RecordingExecutor()
    router = GatewayCommandRouter(tmp_path / "gateway.db", executor, clock=MutableClock(0))
    with pytest.raises(GatewayRoutingError) as rejected:
        router.dispatch(principal, make_command("future"))
    assert rejected.value.code == "COMMAND_NOT_YET_VALID"
    assert executor.commands == []


def test_non_read_command_without_server_admission_is_durably_rejected(
    tmp_path, principal: GatewayPrincipal
) -> None:
    executor = RecordingExecutor()
    router = GatewayCommandRouter(tmp_path / "gateway.db", executor, clock=MutableClock())
    command = make_command("no-admission")

    with pytest.raises(GatewayRoutingError) as rejected:
        router.dispatch(principal, command)

    assert rejected.value.code == "SERVER_ADMISSION_UNAVAILABLE"
    saved = router.get(command.command_id)
    assert saved.status is GatewayCommandStatus.REJECTED
    assert saved.outcome == {"reason": "server_admission_unavailable"}
    assert executor.commands == []


def test_non_read_command_without_account_writer_authority_is_durably_rejected(
    tmp_path, principal: GatewayPrincipal
) -> None:
    executor = RecordingExecutor()
    router = GatewayCommandRouter(
        tmp_path / "gateway.db",
        executor,
        clock=MutableClock(),
        admission=approve_offline_fixture,
    )
    command = make_command("no-writer-authority")

    with pytest.raises(GatewayRoutingError) as rejected:
        router.dispatch(principal, command)

    assert rejected.value.code == "WRITER_AUTHORITY_UNAVAILABLE"
    saved = router.get(command.command_id)
    assert saved.status is GatewayCommandStatus.REJECTED
    assert saved.outcome == {"reason": "writer_authority_unavailable"}
    assert executor.commands == []


def test_final_writer_check_rejects_revoked_lease_before_executor(tmp_path, principal) -> None:
    database = tmp_path / "gateway.db"
    clock = MutableClock()
    authority = make_writer_authority(database, clock)
    lease = authority.lease_for("account:demo")
    begin = authority.begin_action_dispatch

    def revoke_then_check(current_lease, current_principal, current_command, claim):
        authority.revoke_writer(current_lease)
        begin(current_lease, current_principal, current_command, claim)

    authority.begin_action_dispatch = revoke_then_check
    executor = RecordingExecutor()
    router = GatewayCommandRouter(
        database,
        executor,
        clock=clock,
        admission=approve_offline_fixture,
        writer_authority=authority,
    )

    with pytest.raises(GatewayRoutingError) as rejected:
        router.dispatch(principal, make_command("revoked-before-dispatch"))

    assert rejected.value.code == "WRITER_FINAL_CHECK_REJECTED"
    assert router.get("revoked-before-dispatch").status is GatewayCommandStatus.REJECTED
    assert executor.commands == []
    assert lease.epoch == 1


def test_reused_command_id_with_changed_payload_is_rejected_before_executor(
    tmp_path, principal
) -> None:
    database = tmp_path / "gateway.db"
    clock = MutableClock()
    executor = RecordingExecutor()
    router = GatewayCommandRouter(
        database,
        executor,
        clock=clock,
        admission=approve_offline_fixture,
        writer_authority=make_writer_authority(database, clock),
    )
    original = make_command("same-action-id")
    result = router.dispatch(principal, original)
    changed = make_command("same-action-id", payload={"symbol": "BTC-USDT", "quantity": "2"})

    assert result.status is GatewayCommandStatus.RETURNED_UNVERIFIED
    with pytest.raises(GatewayRoutingError) as reused:
        router.dispatch(principal, changed)

    assert reused.value.code == "COMMAND_ID_REUSED"
    assert len(executor.commands) == 1


@pytest.mark.parametrize(
    ("column", "replacement"),
    [
        ("fingerprint", "0" * 64),
        ("account_scope", "account:other"),
        ("strategy_scope", "strategy:other"),
        ("principal_id", "other-principal"),
        ("payload_json", '{"quantity":"2","symbol":"BTC-USDT"}'),
        ("status", "pending"),
    ],
)
def test_final_authority_check_cross_binds_command_journal_before_executor(
    tmp_path, principal, column: str, replacement: str
) -> None:
    database = tmp_path / (column + ".sqlite")
    clock = MutableClock()
    authority = make_writer_authority(database, clock)
    begin = authority.begin_action_dispatch

    def corrupt_journal_then_check(lease, current_principal, current_command, claim):
        update_sql = {
            "fingerprint": "UPDATE gateway_commands SET fingerprint = ? WHERE command_id = ?",
            "account_scope": "UPDATE gateway_commands SET account_scope = ? WHERE command_id = ?",
            "strategy_scope": "UPDATE gateway_commands SET strategy_scope = ? WHERE command_id = ?",
            "principal_id": "UPDATE gateway_commands SET principal_id = ? WHERE command_id = ?",
            "payload_json": "UPDATE gateway_commands SET payload_json = ? WHERE command_id = ?",
            "status": "UPDATE gateway_commands SET status = ? WHERE command_id = ?",
        }[column]
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                update_sql,
                (replacement, current_command.command_id),
            )
            connection.commit()
        finally:
            connection.close()
        begin(lease, current_principal, current_command, claim)

    authority.begin_action_dispatch = corrupt_journal_then_check
    executor = RecordingExecutor()
    router = GatewayCommandRouter(
        database,
        executor,
        clock=clock,
        admission=approve_offline_fixture,
        writer_authority=authority,
    )
    current = make_command("cross-bind-" + column)

    with pytest.raises(GatewayRoutingError) as rejected:
        router.dispatch(principal, current)

    assert rejected.value.code == "WRITER_FINAL_CHECK_REJECTED"
    assert router.get(current.command_id).status is GatewayCommandStatus.REJECTED
    assert (
        authority.get_action("account:demo", current.command_id).status
        is GatewayActionStatus.REJECTED
    )
    assert executor.commands == []


def test_missing_command_journal_row_blocks_final_dispatch(tmp_path, principal) -> None:
    database = tmp_path / "gateway.db"
    clock = MutableClock()
    authority = make_writer_authority(database, clock)
    begin = authority.begin_action_dispatch

    def delete_journal_then_check(lease, current_principal, current_command, claim):
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                "DELETE FROM gateway_commands WHERE command_id = ?",
                (current_command.command_id,),
            )
            connection.commit()
        finally:
            connection.close()
        begin(lease, current_principal, current_command, claim)

    authority.begin_action_dispatch = delete_journal_then_check
    executor = RecordingExecutor()
    router = GatewayCommandRouter(
        database,
        executor,
        clock=clock,
        admission=approve_offline_fixture,
        writer_authority=authority,
    )
    current = make_command("missing-command-row")

    with pytest.raises(GatewayRoutingError):
        router.dispatch(principal, current)

    assert (
        authority.get_action("account:demo", current.command_id).status
        is GatewayActionStatus.REJECTED
    )
    assert executor.commands == []


@pytest.mark.parametrize("decision", [False, "yes", 1])
def test_server_admission_requires_literal_true(tmp_path, principal, decision) -> None:
    executor = RecordingExecutor()
    router = GatewayCommandRouter(
        tmp_path / "gateway.db",
        executor,
        clock=MutableClock(),
        admission=lambda _principal, _command: decision,
    )
    command = make_command("bad-admission")

    with pytest.raises(GatewayRoutingError) as rejected:
        router.dispatch(principal, command)

    assert rejected.value.code == "SERVER_ADMISSION_REJECTED"
    assert router.get(command.command_id).status is GatewayCommandStatus.REJECTED
    assert executor.commands == []


def test_server_admission_exception_is_redacted_and_prevents_dispatch(tmp_path, principal) -> None:
    executor = RecordingExecutor()
    raw_message = "admission exception containing opaque credential"

    def failing_admission(_principal, _command):
        raise RuntimeError(raw_message)

    database = tmp_path / "gateway.db"
    router = GatewayCommandRouter(
        database, executor, clock=MutableClock(), admission=failing_admission
    )
    command = make_command("admission-error")

    with pytest.raises(GatewayRoutingError) as rejected:
        router.dispatch(principal, command)

    assert rejected.value.code == "SERVER_ADMISSION_REJECTED"
    saved = router.get(command.command_id)
    assert saved.status is GatewayCommandStatus.REJECTED
    assert saved.outcome == {
        "error_type": "RuntimeError",
        "reason": "server_admission_rejected",
    }
    assert raw_message.encode() not in database.read_bytes()
    assert executor.commands == []


def test_read_command_can_run_without_write_admission(tmp_path, principal) -> None:
    executor = RecordingExecutor()
    router = GatewayCommandRouter(tmp_path / "gateway.db", executor, clock=MutableClock())

    result = router.dispatch(principal, make_command("read-only", GatewayCommandKind.READ))

    assert result.status is GatewayCommandStatus.SUCCEEDED
    assert len(executor.commands) == 1


def test_command_expiring_during_admission_never_reaches_owner(tmp_path, principal) -> None:
    admission_entered, finish_admission = Event(), Event()
    clock = MutableClock()
    executor = RecordingExecutor()

    def delayed_admission(_principal, _command):
        admission_entered.set()
        assert finish_admission.wait(timeout=10)
        return True

    database = tmp_path / "gateway.db"
    owner = GatewayCommandRouter(
        database,
        executor,
        clock=clock,
        admission=delayed_admission,
        writer_authority=make_writer_authority(database, clock),
    )
    observer = GatewayCommandRouter(database, executor, clock=clock)
    command = make_command("expires-during-admission")

    with ThreadPoolExecutor(max_workers=1) as pool:
        dispatch = pool.submit(owner.dispatch, principal, command)
        try:
            assert admission_entered.wait(timeout=10)
            clock.value += 11
            expired = observer.dispatch(principal, command)
            assert expired.status is GatewayCommandStatus.EXPIRED
        finally:
            finish_admission.set()
        with pytest.raises(GatewayRoutingError) as rejected:
            dispatch.result(timeout=10)

    assert rejected.value.code == "COMMAND_EXPIRED"
    assert executor.commands == []


def test_concurrent_duplicate_and_expired_retry_do_not_repeat_side_effect(tmp_path, principal):
    entered, release = Event(), Event()
    calls = []

    def executor(command):
        calls.append(command.command_id)
        entered.set()
        assert release.wait(timeout=10)
        return {"provider_ack": "accepted"}

    database = tmp_path / "gateway.db"
    clock = MutableClock()
    owner = GatewayCommandRouter(
        database,
        executor,
        clock=clock,
        admission=approve_offline_fixture,
        writer_authority=make_writer_authority(database, clock),
    )
    other = GatewayCommandRouter(database, executor, clock=clock, admission=approve_offline_fixture)
    command = make_command("concurrent")
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(owner.dispatch, principal, command)
        try:
            assert entered.wait(timeout=10)
            duplicate = other.dispatch(principal, command)
            assert duplicate.status is GatewayCommandStatus.DISPATCHING
            clock.value += 11
            unknown = other.dispatch(principal, command)
            assert unknown.status is GatewayCommandStatus.UNKNOWN
        finally:
            release.set()
        assert first.result(timeout=10).status is GatewayCommandStatus.RETURNED_UNVERIFIED
    # A late local return is visible as unverified; retries after the envelope
    # TTL return it without another owner call or implying a provider ACK.
    reopened = GatewayCommandRouter(
        database, executor, clock=clock, admission=approve_offline_fixture
    )
    assert reopened.dispatch(principal, command).status is GatewayCommandStatus.RETURNED_UNVERIFIED
    assert calls == ["concurrent"]


def test_executor_exception_is_unknown_and_does_not_persist_raw_message(tmp_path, principal):
    calls = []
    raw_message = "opaque-auth-material-should-never-be-journaled"

    def uncertain(command):
        calls.append(command.command_id)
        raise TimeoutError(raw_message)

    database = tmp_path / "gateway.db"
    router = GatewayCommandRouter(
        database,
        uncertain,
        clock=MutableClock(),
        admission=approve_offline_fixture,
        writer_authority=make_writer_authority(database, MutableClock()),
    )
    command = make_command("unknown")
    with pytest.raises(GatewayDispatchError):
        router.dispatch(principal, command)
    reopened = GatewayCommandRouter(
        database,
        uncertain,
        clock=MutableClock(),
        admission=approve_offline_fixture,
    )
    result = reopened.dispatch(principal, command)
    assert result.status is GatewayCommandStatus.UNKNOWN
    assert result.outcome["reason"] == "dispatch_reconciliation_required"
    assert raw_message.encode() not in database.read_bytes()
    assert calls == ["unknown"]


def test_duplicate_command_remains_bound_to_original_principal(tmp_path, principal):
    executor = RecordingExecutor()
    router = GatewayCommandRouter(
        tmp_path / "gateway.db",
        executor,
        clock=MutableClock(),
        admission=approve_offline_fixture,
        writer_authority=make_writer_authority(tmp_path / "gateway.db", MutableClock()),
    )
    command = make_command("bound")
    router.dispatch(principal, command)
    other = GatewayPrincipal(
        "other", principal.account_scopes, principal.strategy_scopes, principal.allowed_kinds
    )
    with pytest.raises(GatewayRoutingError) as rejected:
        router.dispatch(other, command)
    assert rejected.value.code == "COMMAND_PRINCIPAL_MISMATCH"
    assert len(executor.commands) == 1


def test_process_exit_after_durable_dispatch_never_retries_owner(tmp_path, principal):
    database = tmp_path / "gateway.db"
    program = """
import os
import socket
import sys
def no_network(*args, **kwargs):
    raise AssertionError('gateway worker attempted external I/O')
socket.create_connection = no_network
socket.socket.connect = no_network
from bt_api_gateway import GatewayAccountWriterAuthority, GatewayCommand, GatewayCommandKind, GatewayCommandRouter, GatewayPrincipal
principal = GatewayPrincipal('client-a', frozenset({'account:demo'}), frozenset({'strategy:one'}), frozenset({GatewayCommandKind.SUBMIT}))
command = GatewayCommand('crashed', 'account:demo', 'strategy:one', GatewayCommandKind.SUBMIT, {'symbol': 'BTC-USDT', 'quantity': '1'}, 'approved-contract-digest', 1700000000.0, 1700000010.0)
def crash_after_claim(command):
    os._exit(7)
authority = GatewayAccountWriterAuthority(sys.argv[1], clock=lambda: 1700000000.0)
authority.acquire_writer('account:demo', 'crash-test-owner', lease_seconds=30)
router = GatewayCommandRouter(sys.argv[1], crash_after_claim, clock=lambda: 1700000000.0, admission=lambda principal, command: True, writer_authority=authority)
router.dispatch(principal, command)
"""
    result = subprocess.run(  # noqa: S603 -- fixed crash worker with no provider or shell.
        [sys.executable, "-c", program, str(database)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 7, result.stderr
    executor = RecordingExecutor()
    router = GatewayCommandRouter(
        database,
        executor,
        clock=MutableClock(1_700_000_011.0),
        admission=approve_offline_fixture,
    )
    assert router.get("crashed").status is GatewayCommandStatus.DISPATCHING
    recovered = router.dispatch(principal, make_command("crashed"))
    assert recovered.status is GatewayCommandStatus.UNKNOWN
    assert executor.commands == []


def test_nonfinite_payload_is_not_a_canonical_command():
    with pytest.raises(ValueError, match="serializable"):
        make_command("not-json", payload={"price": float("nan")})
