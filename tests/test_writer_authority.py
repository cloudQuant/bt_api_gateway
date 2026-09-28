"""Local SQLite writer-fence contract tests with abrupt process exits."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import time
from dataclasses import replace

import pytest

from bt_api_gateway import (
    GatewayAccountWriterAuthority,
    GatewayActionStatus,
    GatewayCommand,
    GatewayCommandKind,
    GatewayCommandRouter,
    GatewayCommandStatus,
    GatewayPrincipal,
    GatewayWriterAuthorityError,
)
from bt_api_gateway.database_identity import GatewayDatabaseIdentityError


class MutableClock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def principal() -> GatewayPrincipal:
    return GatewayPrincipal(
        "server-fixture-client",
        frozenset({"acct:test"}),
        frozenset({"strategy:test"}),
        frozenset({GatewayCommandKind.SUBMIT, GatewayCommandKind.CANCEL}),
    )


def command(command_id: str = "action-1", expires_at: float = 1_700_000_010.0) -> GatewayCommand:
    return GatewayCommand(
        command_id=command_id,
        account_scope="acct:test",
        strategy_scope="strategy:test",
        kind=GatewayCommandKind.SUBMIT,
        payload={"symbol": "TEST", "quantity": "1"},
        receipt_digest="fixture-only",
        issued_at=1_700_000_000.0,
        expires_at=expires_at,
    )


def seed_dispatching_command_journal(database, current, current_principal, clock) -> None:
    """Create an exact Router journal row for direct authority unit tests."""
    router = GatewayCommandRouter(database, lambda _command: {}, clock=clock)
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            """
            INSERT INTO gateway_commands (
                command_id, fingerprint, account_scope, strategy_scope, kind, payload_json,
                receipt_digest, issued_at, expires_at, manual_resume_authorized, principal_id,
                status, outcome_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
            """,
            (
                current.command_id,
                current.fingerprint,
                current.account_scope,
                current.strategy_scope,
                current.kind.value,
                current.payload_json,
                current.receipt_digest,
                current.issued_at,
                current.expires_at,
                int(current.manual_resume_authorized),
                current_principal.principal_id,
                "pending",
                clock(),
                clock(),
            ),
        )
        connection.commit()
    finally:
        connection.close()
    assert router._begin_dispatch(current.command_id) is None


def test_independent_authority_process_cannot_steal_active_epoch(tmp_path) -> None:
    database = tmp_path / "shared.sqlite"
    parent = GatewayAccountWriterAuthority(database, clock=lambda: 1_700_000_000.0)
    lease = parent.acquire_writer("acct:test", "owner-a", lease_seconds=30)
    program = """
import sys
from bt_api_gateway import GatewayAccountWriterAuthority, GatewayWriterAuthorityError
authority = GatewayAccountWriterAuthority(sys.argv[1], clock=lambda: 1700000000.0)
try:
    authority.acquire_writer('acct:test', 'owner-b', lease_seconds=30)
except GatewayWriterAuthorityError as exc:
    print(exc.code)
else:
    raise SystemExit('second process unexpectedly acquired account lease')
"""
    result = subprocess.run(  # noqa: S603 -- fixed local lease-competition fixture.
        [sys.executable, "-c", program, str(database)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "WRITER_LEASE_HELD"
    assert parent.lease_for("acct:test") == lease


def test_expired_owner_is_stale_after_new_epoch_and_cannot_claim(tmp_path) -> None:
    database = tmp_path / "shared.sqlite"
    clock = MutableClock()
    old_authority = GatewayAccountWriterAuthority(database, clock=clock)
    old_lease = old_authority.acquire_writer("acct:test", "owner-a", lease_seconds=2)
    clock.value += 3
    new_authority = GatewayAccountWriterAuthority(database, clock=clock)
    new_lease = new_authority.acquire_writer("acct:test", "owner-b", lease_seconds=10)
    assert new_lease.epoch == old_lease.epoch + 1

    with pytest.raises(GatewayWriterAuthorityError) as stale:
        old_authority.claim_action(old_lease, principal(), command())
    assert stale.value.code == "WRITER_LEASE_STALE"


def test_revoked_epoch_fails_closed_and_allows_clean_takeover(tmp_path) -> None:
    database = tmp_path / "shared.sqlite"
    clock = MutableClock()
    old_authority = GatewayAccountWriterAuthority(database, clock=clock)
    old_lease = old_authority.acquire_writer("acct:test", "owner-a", lease_seconds=10)
    old_authority.revoke_writer(old_lease)

    with pytest.raises(GatewayWriterAuthorityError) as revoked:
        old_authority.claim_action(old_lease, principal(), command())
    assert revoked.value.code == "WRITER_LEASE_REVOKED"

    new_authority = GatewayAccountWriterAuthority(database, clock=clock)
    lease = new_authority.acquire_writer("acct:test", "owner-b", lease_seconds=10)
    assert lease.epoch == old_lease.epoch + 1


def test_duplicate_action_id_and_command_identity_cannot_be_reclaimed(tmp_path) -> None:
    database = tmp_path / "shared.sqlite"
    clock = MutableClock()
    authority = GatewayAccountWriterAuthority(database, clock=clock)
    lease = authority.acquire_writer("acct:test", "owner-a", lease_seconds=30)
    first = command()
    claim = authority.claim_action(lease, principal(), first)
    assert claim.action_id == first.command_id
    with pytest.raises(GatewayWriterAuthorityError) as duplicate:
        authority.claim_action(lease, principal(), first)
    assert duplicate.value.code == "ACTION_ALREADY_CLAIMED"

    changed = GatewayCommand(
        command_id=first.command_id,
        account_scope=first.account_scope,
        strategy_scope=first.strategy_scope,
        kind=first.kind,
        payload={"symbol": "TEST", "quantity": "2"},
        receipt_digest=first.receipt_digest,
        issued_at=first.issued_at,
        expires_at=first.expires_at,
    )
    with pytest.raises(GatewayWriterAuthorityError) as reused:
        authority.claim_action(lease, principal(), changed)
    assert reused.value.code == "ACTION_ID_REUSED"


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("account_scope", "acct:other"),
        ("action_id", "action-other"),
        ("strategy_scope", "strategy:other"),
        ("principal_id", "client-other"),
        ("owner_id", "owner-other"),
        ("lease_id", "lease-other"),
        ("epoch", 99),
        ("command_fingerprint", "0" * 64),
        ("expires_at", 1_700_000_009.0),
    ],
)
def test_claim_state_transitions_require_exact_durable_row_binding(
    tmp_path, field: str, forged_value
) -> None:
    database = tmp_path / (field + ".sqlite")
    clock = MutableClock()
    authority = GatewayAccountWriterAuthority(database, clock=clock)
    lease = authority.acquire_writer("acct:test", "owner-a", lease_seconds=30)
    current = command()
    seed_dispatching_command_journal(database, current, principal(), clock)
    claim = authority.claim_action(lease, principal(), current)
    forged_claim = replace(claim, **{field: forged_value})

    with pytest.raises(GatewayWriterAuthorityError) as rejected:
        authority.reject_unstarted_action(forged_claim, "forged")
    assert rejected.value.code == "ACTION_CLAIM_BINDING_MISMATCH"
    assert authority.get_action("acct:test", claim.action_id).status is GatewayActionStatus.CLAIMED

    with pytest.raises(GatewayWriterAuthorityError) as final_check:
        authority.begin_action_dispatch(lease, principal(), current, forged_claim)
    assert final_check.value.code in {
        "ACTION_BINDING_MISMATCH",
        "ACTION_CLAIM_BINDING_MISMATCH",
    }
    assert authority.get_action("acct:test", claim.action_id).status is GatewayActionStatus.CLAIMED

    authority.begin_action_dispatch(lease, principal(), current, claim)
    with pytest.raises(GatewayWriterAuthorityError) as transition:
        authority.mark_owner_returned_unverified(forged_claim, {"local": "returned"})
    assert transition.value.code == "ACTION_STATE_CONFLICT"
    assert (
        authority.get_action("acct:test", claim.action_id).status is GatewayActionStatus.DISPATCHING
    )


def test_returned_unverified_action_blocks_later_action_under_same_epoch(tmp_path) -> None:
    database = tmp_path / "shared.sqlite"
    clock = MutableClock()
    authority = GatewayAccountWriterAuthority(database, clock=clock)
    lease = authority.acquire_writer("acct:test", "owner-a", lease_seconds=30)
    first_command = command("first")
    seed_dispatching_command_journal(database, first_command, principal(), clock)
    first_claim = authority.claim_action(lease, principal(), first_command)
    authority.begin_action_dispatch(lease, principal(), first_command, first_claim)
    authority.mark_owner_returned_unverified(first_claim, {"local": "returned"})

    with pytest.raises(GatewayWriterAuthorityError) as blocked:
        authority.claim_action(lease, principal(), command("second"))
    assert blocked.value.code == "WRITER_ACTIONS_UNRESOLVED"


def test_unresolved_claim_prevents_new_epoch_after_disconnect_or_restart(tmp_path) -> None:
    database = tmp_path / "shared.sqlite"
    clock = MutableClock()
    first_process = GatewayAccountWriterAuthority(database, clock=clock)
    lease = first_process.acquire_writer("acct:test", "owner-a", lease_seconds=2)
    claim = first_process.claim_action(lease, principal(), command(expires_at=1_700_000_001.5))
    assert (
        first_process.get_action("acct:test", claim.action_id).status is GatewayActionStatus.CLAIMED
    )

    # A reopened authority has no token and cannot clear the prior claim.
    clock.value += 3
    reopened = GatewayAccountWriterAuthority(database, clock=clock)
    with pytest.raises(GatewayWriterAuthorityError) as fenced:
        reopened.acquire_writer("acct:test", "owner-b", lease_seconds=10)
    assert fenced.value.code == "WRITER_ACTIONS_UNRESOLVED"
    assert reopened.get_action("acct:test", claim.action_id).status is GatewayActionStatus.CLAIMED


def test_revocation_cannot_race_after_final_action_dispatch_check(tmp_path) -> None:
    database = tmp_path / "shared.sqlite"
    clock = MutableClock()
    authority = GatewayAccountWriterAuthority(database, clock=clock)
    lease = authority.acquire_writer("acct:test", "owner-a", lease_seconds=30)
    current = command()
    seed_dispatching_command_journal(database, current, principal(), clock)
    claim = authority.claim_action(lease, principal(), current)
    authority.begin_action_dispatch(lease, principal(), current, claim)

    with pytest.raises(GatewayWriterAuthorityError) as blocked:
        authority.revoke_writer(lease)
    assert blocked.value.code == "WRITER_ACTION_DISPATCHING"
    assert (
        authority.get_action("acct:test", claim.action_id).status is GatewayActionStatus.DISPATCHING
    )


@pytest.mark.parametrize(
    ("crash_point", "expected_action_status", "expected_command_status"),
    [
        ("after_claim", "claimed", "pending"),
        ("before_final_check", "claimed", "dispatching"),
        ("before_executor", "dispatching", "dispatching"),
        ("after_executor_return", "returned_unverified", "dispatching"),
    ],
)
def test_crash_points_leave_durable_unresolved_fence(
    tmp_path, crash_point: str, expected_action_status: str, expected_command_status: str
) -> None:
    database = tmp_path / (crash_point + ".sqlite")
    program = r"""
import os
import socket
import sys

def no_network(*args, **kwargs):
    raise AssertionError('unexpected external network access')
socket.create_connection = no_network
socket.socket.connect = no_network
from bt_api_gateway import GatewayAccountWriterAuthority, GatewayCommand, GatewayCommandKind, GatewayCommandRouter, GatewayPrincipal

point = sys.argv[2]
principal = GatewayPrincipal('fixture', frozenset({'acct:test'}), frozenset({'strategy:test'}), frozenset({GatewayCommandKind.SUBMIT}))
command = GatewayCommand('crash-' + point, 'acct:test', 'strategy:test', GatewayCommandKind.SUBMIT, {'symbol': 'TEST', 'quantity': '1'}, 'fixture-only', 1700000000.0, 1700000010.0)
authority = GatewayAccountWriterAuthority(sys.argv[1], clock=lambda: 1700000000.0)
authority.acquire_writer('acct:test', 'owner-a', lease_seconds=30)

def executor(command):
    if point == 'before_executor':
        os._exit(17)
    return {'owner_return': 'local-only'}

if point == 'before_final_check':
    authority.begin_action_dispatch = lambda *args, **kwargs: os._exit(17)
elif point == 'after_executor_return':
    original = authority.mark_owner_returned_unverified
    def mark_then_crash(claim, outcome):
        original(claim, outcome)
        os._exit(17)
    authority.mark_owner_returned_unverified = mark_then_crash

router = GatewayCommandRouter(sys.argv[1], executor, clock=lambda: 1700000000.0, admission=lambda p, c: True, writer_authority=authority)
if point == 'after_claim':
    router._begin_dispatch = lambda *args, **kwargs: os._exit(17)
router.dispatch(principal, command)
raise SystemExit('crash hook was not reached')
"""
    result = subprocess.run(  # noqa: S603 -- fixed local crash-point fixture.
        [sys.executable, "-c", program, str(database), crash_point],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 17, result.stderr

    clock = MutableClock(1_700_000_040.0)
    recovered = GatewayAccountWriterAuthority(database, clock=clock)
    record = recovered.get_action("acct:test", "crash-" + crash_point)
    assert record is not None
    assert record.status.value == expected_action_status
    replay_calls = []
    recovered_router = GatewayCommandRouter(
        database,
        lambda current: replay_calls.append(current) or {"unexpected": True},
        clock=clock,
    )
    command_record = recovered_router.get("crash-" + crash_point)
    assert command_record is not None
    assert command_record.status.value == expected_command_status
    replay_principal = GatewayPrincipal(
        "fixture",
        frozenset({"acct:test"}),
        frozenset({"strategy:test"}),
        frozenset({GatewayCommandKind.SUBMIT}),
    )
    replayed = recovered_router.dispatch(
        replay_principal,
        command("crash-" + crash_point),
    )
    expected_replay_status = (
        GatewayCommandStatus.EXPIRED
        if expected_command_status == "pending"
        else GatewayCommandStatus.UNKNOWN
    )
    assert replayed.status is expected_replay_status
    assert replay_calls == []
    with pytest.raises(GatewayWriterAuthorityError) as fenced:
        recovered.acquire_writer("acct:test", "owner-after-crash", lease_seconds=10)
    assert fenced.value.code == "WRITER_ACTIONS_UNRESOLVED"


def test_two_processes_racing_for_one_account_epoch_have_one_winner(tmp_path) -> None:
    database = tmp_path / "shared.sqlite"
    trigger = tmp_path / "start"
    program = """
import pathlib
import sys
import time
from bt_api_gateway import GatewayAccountWriterAuthority, GatewayWriterAuthorityError
database, trigger, ready, owner = map(pathlib.Path, sys.argv[1:5])
ready.touch()
while not trigger.exists():
    time.sleep(0.005)
try:
    authority = GatewayAccountWriterAuthority(database, clock=lambda: 1700000000.0)
    authority.acquire_writer('acct:test', str(owner), lease_seconds=30)
except GatewayWriterAuthorityError as exc:
    print(exc.code)
else:
    print('ACQUIRED')
"""
    workers = []
    for name in ("owner-a", "owner-b"):
        ready = tmp_path / (name + ".ready")
        workers.append(
            (
                ready,
                subprocess.Popen(  # noqa: S603 -- fixed local SQLite contention fixture.
                    [sys.executable, "-c", program, str(database), str(trigger), str(ready), name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                ),
            )
        )
    try:
        for ready, _process in workers:
            deadline = time.monotonic() + 10
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.005)
            assert ready.exists(), "writer worker did not reach the shared start barrier"
        trigger.touch()
        results = [process.communicate(timeout=30) for _ready, process in workers]
    finally:
        trigger.touch()
        for _ready, process in workers:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)

    outputs = [stdout.strip() for stdout, _stderr in results]
    errors = [stderr for _stdout, stderr in results]
    assert all(not error for error in errors), errors
    assert outputs.count("ACQUIRED") == 1
    failures = [output for output in outputs if output != "ACQUIRED"]
    assert len(failures) == 1
    assert failures[0] in {
        "WRITER_LEASE_HELD",
        "WRITER_DATABASE_INITIALIZATION_BUSY",
    }


class _FailingWalConnection:
    def __init__(self, connection, failure):
        self._connection = connection
        self._failure = failure

    def __getattr__(self, name):
        return getattr(self._connection, name)

    def __setattr__(self, name, value):
        if name in {"_connection", "_failure"}:
            object.__setattr__(self, name, value)
        else:
            setattr(self._connection, name, value)

    def execute(self, statement, *args):
        failure = self._failure(statement)
        if failure is not None:
            raise sqlite3.OperationalError(failure)
        return self._connection.execute(statement, *args)


def test_schema_initialization_retries_only_sqlite_busy_lock(monkeypatch, tmp_path) -> None:
    from bt_api_gateway import writer_authority as writer_authority_module

    real_connect = sqlite3.connect
    wal_attempts = 0

    def failure(statement):
        nonlocal wal_attempts
        if statement == "PRAGMA journal_mode = WAL" and wal_attempts < 2:
            wal_attempts += 1
            return "database is locked"
        return None

    def connect(*args, **kwargs):
        return _FailingWalConnection(real_connect(*args, **kwargs), failure)

    monkeypatch.setattr(writer_authority_module.sqlite3, "connect", connect)
    authority = GatewayAccountWriterAuthority(tmp_path / "retry.sqlite")

    assert wal_attempts == 2
    lease = authority.acquire_writer("acct:test", "owner", lease_seconds=5)
    assert lease.epoch == 1


def test_schema_initialization_lock_retry_is_bounded_and_translated(monkeypatch, tmp_path) -> None:
    from bt_api_gateway import writer_authority as writer_authority_module

    real_connect = sqlite3.connect
    wal_attempts = 0

    def failure(statement):
        nonlocal wal_attempts
        if statement == "PRAGMA journal_mode = WAL":
            wal_attempts += 1
            return "database is locked"
        return None

    def connect(*args, **kwargs):
        return _FailingWalConnection(real_connect(*args, **kwargs), failure)

    monkeypatch.setattr(writer_authority_module.sqlite3, "connect", connect)
    with pytest.raises(GatewayWriterAuthorityError) as busy:
        GatewayAccountWriterAuthority(tmp_path / "busy.sqlite", timeout_seconds=0.03)

    assert busy.value.code == "WRITER_DATABASE_INITIALIZATION_BUSY"
    assert wal_attempts > 1


def test_schema_initialization_does_not_swallow_non_lock_sqlite_error(
    monkeypatch, tmp_path
) -> None:
    from bt_api_gateway import writer_authority as writer_authority_module

    real_connect = sqlite3.connect

    def connect(*args, **kwargs):
        return _FailingWalConnection(
            real_connect(*args, **kwargs),
            lambda statement: (
                "disk I/O error" if statement == "PRAGMA journal_mode = WAL" else None
            ),
        )

    monkeypatch.setattr(writer_authority_module.sqlite3, "connect", connect)
    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        GatewayAccountWriterAuthority(tmp_path / "io-error.sqlite")


def test_authority_and_router_fail_closed_after_database_file_replacement(tmp_path) -> None:
    database = tmp_path / "gateway.sqlite"
    replacement = tmp_path / "replacement.sqlite"
    clock = MutableClock()
    authority = GatewayAccountWriterAuthority(database, clock=clock)
    lease = authority.acquire_writer("acct:test", "owner-a", lease_seconds=30)
    executor_calls = []
    router = GatewayCommandRouter(
        database,
        lambda current: executor_calls.append(current) or {"returned": True},
        clock=clock,
        admission=lambda _principal, _command: True,
        writer_authority=authority,
    )
    replacement_connection = sqlite3.connect(replacement)
    try:
        connection = replacement_connection
        connection.execute("CREATE TABLE unrelated (value TEXT)")
    finally:
        replacement_connection.close()

    database.unlink()
    replacement.replace(database)

    with pytest.raises(GatewayDatabaseIdentityError) as authority_error:
        authority.renew_writer(lease, lease_seconds=10)
    assert authority_error.value.code == "WRITER_DATABASE_IDENTITY_CHANGED"
    with pytest.raises(GatewayDatabaseIdentityError) as router_error:
        router.dispatch(principal(), command("after-db-replacement"))
    assert router_error.value.code == "WRITER_DATABASE_IDENTITY_CHANGED"
    assert executor_calls == []
