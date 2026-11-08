import os
import threading

import pytest
from bt_api_base.direct_write_protocol import NativeOrderIdentity, PreDispatchRecord, WriteOperation

from bt_api_gateway.direct_command_journal import GatewayDirectCommandJournal
from bt_api_gateway.direct_dispatch import (
    DirectDispatchError,
    GatewayDirectDispatcher,
    NativeDispatchOutcome,
)
from bt_api_gateway.session_guard import LocalAccountSessionGuard, LocalAccountSessionGuardError


@pytest.fixture
def setup(tmp_path):
    directory = tmp_path / "guards"
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, "synthetic-account", "synthetic-owner")
    generation = guard.acquire()
    journal = GatewayDirectCommandJournal.create(
        tmp_path / "db", "synthetic-account", generation=generation, clock=lambda: 100.0
    )
    yield journal, guard
    # This fixture has no actual native session.
    guard.release()


def reserve(journal, key="one", strategy="s", payload=None):
    return journal.reserve(
        strategy, key, "principal", {"symbol": "X", "qty": "1"} if payload is None else payload
    )


def invoke(dispatcher, row):
    return dispatcher.dispatch(
        row.strategy_scope,
        row.request_key,
        row.principal,
        row.reservation_id,
        row.digest,
        row.version,
    )


def identity(ref="r"):
    return NativeOrderIdentity("TEST", ref, {"trading_day": "20300101", "front_id": 1}, 1)


def keys(value):
    return (f"TEST:20300101:{value.client_order_id}",)


def marker_record(payload, scope, value=None, **changes):
    native_id = value or identity()
    values = {
        "operation": WriteOperation.PLACE,
        "host_scope": scope,
        "exchange_name": "TEST",
        "symbol": "X",
        "identity": native_id,
        "target_identity": None,
        "request_summary": payload,
        "trading_day": "20300101",
        "session_generation": 1,
        "created_at_utc": "synthetic",
    }
    values.update(changes)
    return PreDispatchRecord(**values)


def build(journal, guard, native, gate=lambda row: None):
    return GatewayDirectDispatcher(journal, "TEST", guard, native, keys, gate)


def test_commit_precedes_native_and_replay_never_reallocates(setup):
    journal, guard = setup
    first = reserve(journal, "one")
    second = reserve(journal, "two")
    calls = []

    # Reverse reservation dispatch order.
    second = journal.release(
        second.strategy_scope,
        second.request_key,
        second.reservation_id,
        second.digest,
        second.principal,
        "release",
        second.version,
    )
    third = reserve(journal, "three", payload={"symbol": "X", "qty": "2"})

    def corrected(payload, port, scope):
        key = "three" if payload["qty"] == "2" else "one"
        value = identity("ref-" + payload["qty"])
        marker = port.commit(marker_record(payload, scope, value))
        assert journal.get("s", key, "principal").status == "DISPATCHING"
        calls.append(("commit", key))
        calls.append(("send", key))
        payload["qty"] = "changed"
        return NativeDispatchOutcome(True, value, marker)

    dispatcher = build(journal, guard, corrected)
    assert invoke(dispatcher, third).status == "SENT"
    assert invoke(dispatcher, first).status == "SENT"
    assert invoke(dispatcher, third).status == "SENT"
    assert invoke(dispatcher, second).status == "RELEASED"
    assert calls == [("commit", "three"), ("send", "three"), ("commit", "one"), ("send", "one")]
    assert '"qty":"2"' in journal.get("s", "three", "principal").payload_json


@pytest.mark.parametrize("result,status", [(True, "SENT"), (False, "NOT_SENT"), (None, "UNKNOWN")])
def test_valid_native_outcomes(setup, result, status):
    journal, guard = setup
    row = reserve(journal)

    def native(payload, port, scope):
        value = identity()
        marker = port.commit(marker_record(payload, scope, value))
        return NativeDispatchOutcome(result, value, marker)

    assert invoke(build(journal, guard, native), row).status == status


@pytest.mark.parametrize(
    "mode",
    ["raise", "invalid_type", "wrong_marker", "wrong_identity", "missing_identity", "truthy"],
)
def test_invalid_or_lost_reply_after_commit_is_unknown(setup, mode):
    journal, guard = setup
    row = reserve(journal)
    calls = []

    def native(payload, port, scope):
        value = identity()
        marker = port.commit(marker_record(payload, scope, value))
        calls.append("send")
        if mode == "raise":
            raise OSError("lost reply")
        if mode == "invalid_type":
            return object()
        if mode == "wrong_marker":
            return NativeDispatchOutcome(True, value, "other")
        if mode == "wrong_identity":
            return NativeDispatchOutcome(True, identity("different"), marker)
        if mode == "missing_identity":
            return NativeDispatchOutcome(True, None, marker)
        return NativeDispatchOutcome(1, value, marker)

    dispatcher = build(journal, guard, native)
    assert invoke(dispatcher, row).status == "UNKNOWN"
    assert invoke(dispatcher, row).status == "UNKNOWN"
    assert calls == ["send"]


@pytest.mark.parametrize(
    "kind", ["operation", "route", "scope", "summary", "identity", "generation", "target", "symbol"]
)
def test_invalid_commit_records_refuse_before_send(setup, kind):
    journal, guard = setup
    row = reserve(journal)
    sent = []

    def native(payload, port, scope):
        value = identity()
        changes = {
            "operation": {"operation": WriteOperation.CANCEL},
            "route": {"exchange_name": "OTHER"},
            "scope": {"host_scope": "other"},
            "summary": {"request_summary": {"qty": "changed"}},
            "identity": {"identity": None},
            "generation": {"session_generation": 2},
            "target": {"target_identity": value},
            "symbol": {"symbol": "OTHER"},
        }[kind]
        marker = port.commit(marker_record(payload, scope, value, **changes))
        if marker:
            sent.append(marker)
        return NativeDispatchOutcome(True, value, marker)

    with pytest.raises(DirectDispatchError, match="PRE_DISPATCH_FAILED"):
        invoke(build(journal, guard, native), row)
    assert sent == [] and journal.get("s", "one", "principal").status == "RESERVED"


@pytest.mark.parametrize("payload", [{}, [1], {"x": [1]}, {"x": {"y": "1"}}])
def test_nonscalar_payload_rejected_before_native(setup, payload):
    journal, guard = setup
    row = reserve(journal, payload=payload)
    calls = []
    dispatcher = build(journal, guard, lambda *args: calls.append("native"))
    with pytest.raises(DirectDispatchError, match="PAYLOAD_UNSUPPORTED"):
        invoke(dispatcher, row)
    assert calls == [] and journal.get("s", "one", "principal").status == "RESERVED"


def test_both_admission_checks_fail_closed(setup):
    journal, guard = setup
    row = reserve(journal)
    calls = []

    def gate(_):
        calls.append("gate")
        if len(calls) == 2:
            raise ValueError("blocked")

    def native(payload, port, scope):
        port.commit(marker_record(payload, scope))
        calls.append("send")

    with pytest.raises(DirectDispatchError, match="PRE_DISPATCH_FAILED"):
        invoke(build(journal, guard, native, gate), row)
    assert calls == ["gate", "gate"]
    assert journal.get("s", "one", "principal").status == "RESERVED"


def test_identity_collision_no_send_and_guard_is_bound(setup):
    journal, guard = setup
    first, second = reserve(journal, "one"), reserve(journal, "two")
    sends = []

    def native(payload, port, scope):
        value = identity()
        marker = port.commit(marker_record(payload, scope, value))
        if marker:
            sends.append(marker)
        return NativeDispatchOutcome(True, value, marker)

    dispatcher = build(journal, guard, native)
    assert invoke(dispatcher, first).status == "SENT"
    with pytest.raises(DirectDispatchError, match="PRE_DISPATCH_FAILED"):
        invoke(dispatcher, second)
    assert sends == [first.reservation_id]
    with pytest.raises(LocalAccountSessionGuardError, match="different local consumer"):
        build(journal, guard, native)


def test_release_expiry_and_input_binding_never_invoke_native(setup):
    journal, guard = setup
    released, expired = reserve(journal, "release"), reserve(journal, "expire")
    journal.release(
        released.strategy_scope,
        released.request_key,
        released.reservation_id,
        released.digest,
        released.principal,
        "op",
        released.version,
    )
    expired_result = journal.begin_dispatch(
        expired.strategy_scope,
        expired.request_key,
        expired.reservation_id,
        expired.digest,
        expired.principal,
        expired.version,
        {"ref": "x"},
        ("x",),
    )
    journal.finish(
        expired.strategy_scope,
        expired.request_key,
        expired.reservation_id,
        expired.digest,
        expired.principal,
        expired_result.record.version,
        {"ref": "x"},
        ("x",),
        "UNKNOWN",
    )
    calls = []
    dispatcher = build(journal, guard, lambda *args: calls.append(1))
    assert invoke(dispatcher, released).status == "RELEASED"
    assert invoke(dispatcher, expired).status == "UNKNOWN"
    fresh = reserve(journal, "new")
    with pytest.raises(DirectDispatchError, match="REQUEST_CONFLICT"):
        dispatcher.dispatch("s", "new", "principal", fresh.reservation_id, "wrong", fresh.version)
    with pytest.raises(DirectDispatchError, match="VERSION_CONFLICT"):
        dispatcher.dispatch("s", "new", "principal", fresh.reservation_id, fresh.digest, 9)
    assert calls == []


@pytest.mark.parametrize("after_commit", [False, True])
def test_commit_exception_never_sends_and_reconciles_durable_begin(setup, after_commit):
    journal, guard = setup
    row = reserve(journal)
    original = journal._commit
    sent = []

    def native(payload, port, scope):
        value = identity()

        def fail(db):
            state = db.execute("SELECT status FROM direct_journal_commands").fetchone()[0]
            if state == "DISPATCHING":
                if after_commit:
                    original(db)
                raise OSError("synthetic commit failure")
            original(db)

        journal._commit = fail
        try:
            marker = port.commit(marker_record(payload, scope, value))
            sent.append(marker)
        except OSError:
            pass
        finally:
            journal._commit = original
        return NativeDispatchOutcome(False, value, None)

    dispatcher = build(journal, guard, native)
    if after_commit:
        assert invoke(dispatcher, row).status == "UNKNOWN"
        assert invoke(dispatcher, row).status == "UNKNOWN"
    else:
        with pytest.raises(DirectDispatchError, match="PRE_DISPATCH_FAILED"):
            invoke(dispatcher, row)
        assert journal.get("s", "one", "principal").status == "RESERVED"
    assert sent == []


@pytest.mark.parametrize("after_commit", [False, True])
def test_finish_failure_keeps_record_and_replay_never_sends(setup, after_commit):
    journal, guard = setup
    row = reserve(journal)
    original = journal._commit
    calls = []

    def native(payload, port, scope):
        value = identity()
        marker = port.commit(marker_record(payload, scope, value))
        calls.append("send")

        def fail(db):
            if db.execute("SELECT status FROM direct_journal_commands").fetchone()[0] == "SENT":
                if after_commit:
                    original(db)
                raise OSError("before finish commit")
            original(db)

        journal._commit = fail
        return NativeDispatchOutcome(True, value, marker)

    dispatcher = build(journal, guard, native)
    with pytest.raises(DirectDispatchError, match="FINISH_FAILED"):
        invoke(dispatcher, row)
    journal._commit = original
    assert invoke(dispatcher, row).status == ("SENT" if after_commit else "DISPATCHING")
    assert calls == ["send"]


def test_wrong_thread_and_deferred_port_refused(setup):
    journal, guard = setup
    row = reserve(journal)
    ports = []

    def native(payload, port, scope):
        ports.append((port, marker_record(payload, scope)))
        return NativeDispatchOutcome(False, None, None)

    dispatcher = build(journal, guard, native)
    errors = []

    def run():
        try:
            invoke(dispatcher, row)
        except LocalAccountSessionGuardError as exc:
            errors.append(exc.code)

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    assert errors == ["SESSION_WRONG_OWNER"]
    with pytest.raises(DirectDispatchError, match="PRE_DISPATCH_FAILED"):
        invoke(dispatcher, row)
    with pytest.raises(DirectDispatchError, match="COMMIT_CLOSED"):
        ports[0][0].commit(ports[0][1])
    assert journal.get("s", "one", "principal").status == "RESERVED"


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork")
def test_fork_child_cannot_use_parent_guard(setup):
    journal, guard = setup
    row = reserve(journal)
    dispatcher = build(journal, guard, lambda *args: None)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            invoke(dispatcher, row)
            result = "unexpected success"
        except LocalAccountSessionGuardError as exc:
            result = exc.code
        os.write(write_fd, result.encode())
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    result = os.read(read_fd, 128).decode()
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    assert status == 0 and result == "SESSION_WRONG_OWNER"
    assert journal.get("s", "one", "principal").status == "RESERVED"


def test_real_ttl_expiry_and_wrong_scope_fail_without_native(setup, tmp_path):
    journal, guard = setup
    row = reserve(journal)
    journal._clock = lambda: 110.0
    calls = []
    dispatcher = build(journal, guard, lambda *args: calls.append(1))
    assert invoke(dispatcher, row).status == "EXPIRED"
    assert calls == []
    other_dir = tmp_path / "other-guards"
    other_dir.mkdir()
    other = LocalAccountSessionGuard(other_dir, "other-account", "other")
    other.acquire()
    try:
        with pytest.raises(DirectDispatchError, match="ACCOUNT_SCOPE_MISMATCH"):
            build(journal, other, lambda *args: None)
    finally:
        other.release()


def test_reacquired_guard_generation_does_not_authorize_dispatch(setup):
    journal, guard = setup
    row = reserve(journal)
    calls = []
    dispatcher = build(journal, guard, lambda *args: calls.append(1))
    guard.release()
    guard.acquire()
    with pytest.raises(DirectDispatchError, match="GUARD_GENERATION_CHANGED"):
        invoke(dispatcher, row)
    assert calls == [] and journal.get("s", "one", "principal").status == "RESERVED"


def test_gate_reentrancy_rejected_before_native_call(setup):
    journal, guard = setup
    row = reserve(journal)
    errors = []

    def gate(_):
        try:
            invoke(dispatcher, row)
        except DirectDispatchError as exc:
            errors.append(exc.code)
        raise ValueError("gate denies")

    dispatcher = build(journal, guard, lambda *args: pytest.fail("native reached"), gate)
    with pytest.raises(DirectDispatchError, match="ADMISSION_DENIED"):
        invoke(dispatcher, row)
    assert errors == ["DISPATCH_REENTRANT"]
    assert journal.get("s", "one", "principal").status == "RESERVED"


def test_mutated_payload_is_not_accepted_as_summary(setup):
    journal, guard = setup
    row = reserve(journal)
    calls = []

    def native(payload, port, scope):
        payload["qty"] = "999"
        marker = port.commit(marker_record(payload, scope))
        calls.append(marker)

    with pytest.raises(DirectDispatchError, match="PRE_DISPATCH_FAILED"):
        invoke(build(journal, guard, native), row)
    assert calls == []
    assert journal.get("s", "one", "principal").payload_json == row.payload_json


@pytest.mark.parametrize("result", [False, 0, "", "yes", [], object()])
def test_admission_requires_none_or_exact_true(setup, result):
    journal, guard = setup
    row = reserve(journal)
    dispatcher = build(
        journal, guard, lambda *args: pytest.fail("native reached"), lambda _: result
    )
    with pytest.raises(DirectDispatchError, match="ADMISSION_DENIED"):
        invoke(dispatcher, row)
    assert journal.get("s", "one", "principal").status == "RESERVED"


def test_guard_and_journal_generation_must_match(setup, tmp_path):
    _, guard = setup
    old = GatewayDirectCommandJournal.create(
        tmp_path / "old-db", "synthetic-account", generation="old", clock=lambda: 100.0
    )
    row = reserve(old)
    with pytest.raises(DirectDispatchError, match="GENERATION_MISMATCH"):
        build(old, guard, lambda *args: pytest.fail("native reached"))
    assert old.get("s", "one", "principal") == row


@pytest.mark.parametrize("payload", [{"qty": 1}, {"symbol": ""}, {"symbol": " X "}, {"symbol": 1}])
def test_missing_or_invalid_symbol_rejected_before_native(setup, payload):
    journal, guard = setup
    row = reserve(journal, payload=payload)
    with pytest.raises(DirectDispatchError, match="PAYLOAD_UNSUPPORTED"):
        invoke(build(journal, guard, lambda *args: pytest.fail("native reached")), row)


def test_release_between_gate_and_commit_cannot_get_marker(setup):
    journal, guard = setup
    row = reserve(journal)
    sent = []

    def native(payload, port, scope):
        journal.release(
            row.strategy_scope,
            row.request_key,
            row.reservation_id,
            row.digest,
            row.principal,
            "op",
            row.version,
        )
        marker = port.commit(marker_record(payload, scope))
        if marker:
            sent.append(marker)

    dispatcher = build(journal, guard, native)
    with pytest.raises(DirectDispatchError, match="PRE_DISPATCH_FAILED"):
        invoke(dispatcher, row)
    assert invoke(dispatcher, row).status == "RELEASED"
    assert sent == []


def test_expiry_inside_commit_cannot_get_marker(setup):
    journal, guard = setup
    row = reserve(journal)
    sent = []

    def native(payload, port, scope):
        journal._clock = lambda: 110.0
        marker = port.commit(marker_record(payload, scope))
        if marker:
            sent.append(marker)
        return NativeDispatchOutcome(False, identity(), marker)

    dispatcher = build(journal, guard, native)
    with pytest.raises(DirectDispatchError, match="PRE_DISPATCH_FAILED"):
        invoke(dispatcher, row)
    assert invoke(dispatcher, row).status == "EXPIRED"
    assert sent == []
