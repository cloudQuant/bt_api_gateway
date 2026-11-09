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


def invoke(dispatcher, row, **kwargs):
    return dispatcher.dispatch(
        row.strategy_scope,
        row.request_key,
        row.principal,
        row.reservation_id,
        row.digest,
        row.version,
        **kwargs,
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


def build(journal, guard, native, gate=lambda row: True):
    from iter63_claim_support import SyntheticClaimPort, claiming

    return GatewayDirectDispatcher(journal, "TEST", guard, claiming(native), keys, gate,
                                   claim_port=SyntheticClaimPort())


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
    if type(payload) is not dict:
        # A non-mapping payload is now refused at reservation already.
        from bt_api_gateway.direct_command_journal import DirectCommandJournalError

        with pytest.raises(DirectCommandJournalError):
            reserve(journal, payload=payload)
        return
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
        return True

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
    # Reserve before the system UNKNOWN exists: afterwards the unknown-order
    # scope fence (no binding resolver here) refuses new reservations.
    fresh = reserve(journal, "new")
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
    dispatcher.assert_owned()
    errors = []

    def run():
        try:
            dispatcher.assert_owned()
        except LocalAccountSessionGuardError as exc:
            errors.append(exc.code)
        try:
            invoke(dispatcher, row)
        except LocalAccountSessionGuardError as exc:
            errors.append(exc.code)

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    assert errors == ["SESSION_WRONG_OWNER", "SESSION_WRONG_OWNER"]
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


@pytest.mark.parametrize("result", [None, False, 0, "", "yes", [], object()])
def test_admission_requires_exact_true(setup, result):
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


def test_request_fence_covers_admission_and_commit_but_not_native(setup, monkeypatch):
    from contextlib import contextmanager

    journal, guard = setup
    first = reserve(journal, "one")
    second = reserve(journal, "two", payload={"symbol": "X", "qty": "2"})
    events = []
    inside = []
    original_begin = journal.begin_dispatch

    def begin(*args, **kwargs):
        assert inside == [args[1]]
        events.append(("begin", args[1]))
        return original_begin(*args, **kwargs)

    monkeypatch.setattr(journal, "begin_dispatch", begin)

    def fence_for(expected):
        @contextmanager
        def fence(row):
            assert row.request_key == expected and not inside
            inside.append(expected)
            events.append(("enter", expected))
            try:
                yield
            finally:
                events.append(("exit", expected))
                inside.pop()

        return fence

    def gate(row):
        assert inside == [row.request_key]
        events.append(("admit", row.request_key))
        return True

    def native(payload, port, scope):
        assert not inside
        key = "one" if payload["qty"] == "1" else "two"
        events.append(("native", key))
        value = identity("ref-" + payload["qty"])
        marker = port.commit(marker_record(payload, scope, value))
        assert not inside and marker
        events.append(("send", key))
        return NativeDispatchOutcome(True, value, marker)

    dispatcher = build(journal, guard, native, gate)
    assert dispatcher.journal is journal
    with pytest.raises(AttributeError):
        dispatcher.journal = object()
    for row in (first, second):
        assert invoke(dispatcher, row, request_fence=fence_for(row.request_key)).status == "SENT"
        assert (
            invoke(dispatcher, row, request_fence=lambda _: pytest.fail("replay fenced")).status
            == "SENT"
        )
    for key in ("one", "two"):
        matching = [event for event in events if event[1] == key]
        assert [event[0] for event in matching] == [
            "enter",
            "admit",
            "exit",
            "native",
            "enter",
            "admit",
            "begin",
            "admit",  # before_dispatch, under the journal write lock
            "admit",  # before_commit, immediately before COMMIT
            "exit",
            # Decision B: final authority recheck for the claim, released
            # before the (synthetic) native send.
            "enter",
            "admit",
            "exit",
            "send",
        ]


def test_request_fence_revocation_between_initial_check_and_commit(setup):
    from contextlib import contextmanager

    journal, guard = setup
    row = reserve(journal)
    attempts, sends = [], []
    allowed = [True]

    @contextmanager
    def fence(record):
        attempts.append(record.reservation_id)
        if not allowed[0]:
            raise PermissionError("revoked")
        yield

    def native(payload, port, scope):
        allowed[0] = False
        marker = port.commit(marker_record(payload, scope))
        if marker:
            sends.append(marker)
        return NativeDispatchOutcome(False, identity(), marker)

    dispatcher = build(journal, guard, native)
    with pytest.raises(DirectDispatchError, match="PRE_DISPATCH_FAILED"):
        invoke(dispatcher, row, request_fence=fence)
    assert attempts == [row.reservation_id, row.reservation_id]
    assert sends == [] and journal.get("s", "one", "principal").status == "RESERVED"


def test_fence_cannot_suppress_admission_denial(setup):
    from contextlib import contextmanager, suppress

    journal, guard = setup
    row = reserve(journal)

    @contextmanager
    def suppressing(_):
        with suppress(Exception):
            yield

    dispatcher = build(journal, guard, lambda *args: pytest.fail("native reached"), lambda _: None)
    with pytest.raises(DirectDispatchError, match="ADMISSION_DENIED"):
        invoke(dispatcher, row, request_fence=suppressing)
    assert journal.get("s", "one", "principal").status == "RESERVED"


def test_fence_exit_failure_after_commit_marks_unknown_and_replay_does_not_send(setup):
    from contextlib import contextmanager

    journal, guard = setup
    row = reserve(journal)
    entries, sends = [], []

    @contextmanager
    def fence(_):
        entries.append(1)
        yield
        if len(entries) == 2:
            raise OSError("lost commit scope")

    def native(payload, port, scope):
        try:
            marker = port.commit(marker_record(payload, scope))
        except OSError:
            marker = None
        if marker:
            sends.append(marker)
        return NativeDispatchOutcome(False, identity(), marker)

    dispatcher = build(journal, guard, native)
    assert invoke(dispatcher, row, request_fence=fence).status == "UNKNOWN"
    assert invoke(dispatcher, row, request_fence=fence).status == "UNKNOWN"
    assert len(entries) == 2 and sends == []


def test_admission_exception_always_reports_denied(setup):
    journal, guard = setup
    row = reserve(journal)

    def gate(_):
        raise DirectDispatchError("other-error")

    dispatcher = build(journal, guard, lambda *args: pytest.fail("native reached"), gate)
    with pytest.raises(DirectDispatchError, match="ADMISSION_DENIED"):
        invoke(dispatcher, row)
    assert journal.get("s", "one", "principal").status == "RESERVED"


def test_fence_exit_failure_after_duplicate_never_finishes_other_attempt(setup, monkeypatch):
    from contextlib import contextmanager

    from bt_api_gateway.direct_command_journal import DispatchStart

    journal, guard = setup
    row = reserve(journal)
    original = journal.begin_dispatch
    entries = []

    def duplicate(*args, **kwargs):
        started_by_other = original(*args, **kwargs)
        return DispatchStart(started_by_other.record, False)

    monkeypatch.setattr(journal, "begin_dispatch", duplicate)

    @contextmanager
    def fence(_):
        entries.append(1)
        yield
        if len(entries) == 2:
            raise OSError("lost exit")

    def native(payload, port, scope):
        marker = port.commit(marker_record(payload, scope))
        return NativeDispatchOutcome(True, identity(), marker)

    dispatcher = build(journal, guard, native)
    with pytest.raises(DirectDispatchError, match="PRE_DISPATCH_FAILED"):
        invoke(dispatcher, row, request_fence=fence)
    assert journal.get("s", "one", "principal").status == "DISPATCHING"
    assert invoke(dispatcher, row, request_fence=fence).status == "DISPATCHING"
    assert len(entries) == 2


def test_lease_recheck_after_waiting_for_sqlite_lock_blocks_marker(setup, monkeypatch):
    import sqlite3
    from contextlib import contextmanager

    journal, guard = setup
    row = reserve(journal)
    auth_now = [0]
    entered_commit = threading.Event()
    waiting_for_lock = threading.Event()
    checks = []
    sent = []
    original_transaction = journal._transaction

    @contextmanager
    def traced_transaction():
        if entered_commit.is_set():
            waiting_for_lock.set()
        with original_transaction() as db:
            yield db

    monkeypatch.setattr(journal, "_transaction", traced_transaction)
    scopes = []

    @contextmanager
    def fence(_):
        assert auth_now[0] < 1
        scopes.append(1)
        if len(scopes) == 2:
            entered_commit.set()

        def recheck():
            checks.append(auth_now[0])
            if auth_now[0] >= 1:
                raise PermissionError("lease expired")

        yield recheck

    def native(payload, port, scope):
        lock = sqlite3.connect(
            journal._identity.path, isolation_level=None, check_same_thread=False
        )
        lock.execute("BEGIN IMMEDIATE")

        def expire_and_unlock():
            assert waiting_for_lock.wait(2)
            threading.Event().wait(0.05)
            auth_now[0] = 1
            lock.execute("COMMIT")

        thread = threading.Thread(target=expire_and_unlock)
        thread.start()
        try:
            marker = port.commit(marker_record(payload, scope))
            if marker:
                sent.append(marker)
            return NativeDispatchOutcome(False, identity(), marker)
        finally:
            thread.join(2)
            assert not thread.is_alive()
            lock.close()

    dispatcher = build(journal, guard, native)
    with pytest.raises(DirectDispatchError, match="PRE_DISPATCH_FAILED"):
        invoke(dispatcher, row, request_fence=fence)
    assert scopes == [1, 1] and checks == [1]
    assert sent == [] and journal.get("s", "one", "principal").status == "RESERVED"


@pytest.mark.parametrize(
    "bad_field",
    [
        {"api_key": "synthetic"},
        {"API-Key": "synthetic"},
        {"apiKey": "synthetic"},
        {"extra": "x" * 257},
        {"extra": "\ud800"},
        {"extra": 1.25},
        {"extra": {"nested": 1}},
        {str(i): "x" for i in range(129)},
    ],
)
def test_unrepresentable_extra_identity_field_rejects_before_commit_and_send(setup, bad_field):
    journal, guard = setup
    row = reserve(journal)
    sent = []
    # The identity has usable strong session fields; a separate malformed
    # extra field must still fail before the durable marker is written.
    value = NativeOrderIdentity(
        "TEST", "ref", {"trading_day": "20300101", "front_id": 1, "session_id": 7}, 1
    )
    object.__setattr__(value, "fields", {**value.fields, **bad_field})

    def native(payload, port, scope):
        marker = port.commit(marker_record(payload, scope, value))
        if marker:
            sent.append(marker)
        return NativeDispatchOutcome(True, value, marker)

    with pytest.raises(DirectDispatchError, match="PRE_DISPATCH_FAILED"):
        invoke(build(journal, guard, native), row)
    observed = journal.get("s", "one", "principal")
    assert observed.status == "RESERVED" and observed.native_identity_json is None
    assert observed.strong_identity_keys == () and sent == []
