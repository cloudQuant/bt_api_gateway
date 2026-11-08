"""Synthetic same-owner cancel dispatch, without native calls."""

import threading

import pytest
from bt_api_base.direct_write_protocol import PreDispatchRecord, WriteOperation

from bt_api_gateway.direct_cancel_dispatch import GatewayDirectCancelDispatcher
from bt_api_gateway.direct_cancel_journal import GatewayDirectCancelJournal
from bt_api_gateway.direct_dispatch import (
    DirectDispatchError,
    GatewayDirectDispatcher,
    NativeDispatchOutcome,
)
import test_iter63_direct_cancel_journal as fixtures
from test_iter63_direct_cancel_journal import make_order, prepared, request

setup = fixtures.setup


def build(journal, guard, native, admission=lambda _: True):
    owner = GatewayDirectDispatcher(
        journal, "TEST", guard, lambda *_: None, lambda _: ("unused",), lambda _: True
    )
    cancel = GatewayDirectCancelJournal(journal)
    dispatcher = GatewayDirectCancelDispatcher(cancel, owner, guard, "TEST", native, admission)
    return dispatcher, cancel, owner


def record(target, symbol, scope, prep):
    return PreDispatchRecord(
        WriteOperation.CANCEL,
        scope,
        "TEST",
        symbol,
        None,
        target,
        {},
        prep.trading_day,
        prep.session_generation,
        "synthetic",
        prep,
    )


@pytest.mark.parametrize("sent,status", [(True, "SENT"), (False, "NOT_SENT"), (None, "UNKNOWN")])
def test_commit_before_send_repeated_attempt_no_resend(setup, sent, status):
    journal, _, guard, path = setup
    order, identity = make_order(journal)
    calls = []

    def native(target, symbol, port, scope):
        prep = prepared(target)
        calls.append("prepare")
        marker = port.commit(record(target, symbol, scope, prep))
        assert dispatcher.journal.get("s", "cancel", "p").status == "DISPATCHING"
        calls.append("send")
        return NativeDispatchOutcome(
            sent, target, marker, "cancel_unknown" if sent is None else None
        )

    dispatcher, cancel, owner = build(journal, guard, native)
    attempt = request(cancel, order, identity)
    finished = dispatcher.dispatch("s", "cancel", "p", expected_version=attempt.version)
    assert finished.status == status and journal.get("s", "order", "p") == order
    assert dispatcher.dispatch("s", "cancel", "p", expected_version=attempt.version) == finished
    assert calls == ["prepare", "send"]


def test_commit_denial_never_calls_send_and_leaves_requested(setup):
    journal, _, guard, path = setup
    order, identity = make_order(journal)
    attempts, sends = [], []

    def admission(row):
        attempts.append(row.status)
        return len(attempts) == 1

    def native(target, symbol, port, scope):
        marker = port.commit(record(target, symbol, scope, prepared(target)))
        sends.append(marker)
        return NativeDispatchOutcome(True, target, marker)

    dispatcher, cancel, owner = build(journal, guard, native, admission)
    row = request(cancel, order, identity)
    with pytest.raises(DirectDispatchError, match="PRE_DISPATCH_FAILED"):
        dispatcher.dispatch("s", "cancel", "p", expected_version=row.version)
    assert cancel.get("s", "cancel", "p").status == "REQUESTED" and not sends


@pytest.mark.parametrize(
    "mode", ["raise_after_commit", "wrong_marker", "wrong_identity", "bad_error"]
)
def test_postcommit_ambiguous_result_is_unknown(setup, mode):
    journal, _, guard, path = setup
    order, identity = make_order(journal)

    def native(target, symbol, port, scope):
        marker = port.commit(record(target, symbol, scope, prepared(target)))
        if mode == "raise_after_commit":
            raise RuntimeError("lost")
        if mode == "wrong_marker":
            return NativeDispatchOutcome(True, target, "wrong")
        if mode == "wrong_identity":
            return NativeDispatchOutcome(True, None, marker)
        return NativeDispatchOutcome(True, target, marker, "invalid error spaces")

    dispatcher, cancel, owner = build(journal, guard, native)
    row = request(cancel, order, identity)
    result = dispatcher.dispatch("s", "cancel", "p", expected_version=row.version)
    assert result.status == "UNKNOWN" and result.error_code == "OUTCOME_UNCERTAIN"
    assert journal.get("s", "order", "p") == order


def test_finish_failure_preserves_dispatching_without_resend(setup, monkeypatch):
    journal, _, guard, path = setup
    order, identity = make_order(journal)
    calls = []

    def native(target, symbol, port, scope):
        marker = port.commit(record(target, symbol, scope, prepared(target)))
        calls.append(marker)
        return NativeDispatchOutcome(True, target, marker)

    dispatcher, cancel, owner = build(journal, guard, native)
    row = request(cancel, order, identity)

    def fail(*args, **kwargs):
        raise RuntimeError("storage fail")

    monkeypatch.setattr(cancel, "finish", fail)
    with pytest.raises(DirectDispatchError, match="FINISH_FAILED"):
        dispatcher.dispatch("s", "cancel", "p", expected_version=row.version)
    assert cancel.get("s", "cancel", "p").status == "DISPATCHING"
    assert (
        dispatcher.dispatch("s", "cancel", "p", expected_version=row.version).status
        == "DISPATCHING"
    )
    assert len(calls) == 1


def test_exact_owner_binding_thread_and_wrong_pid(setup, monkeypatch):
    from bt_api_gateway import direct_cancel_dispatch as module

    journal, _, guard, path = setup
    dispatcher, cancel, owner = build(journal, guard, lambda *_: None)
    assert owner.is_bound_to(journal, guard, "TEST")
    assert not owner.is_bound_to(journal, guard, "OTHER")
    values = []
    t = threading.Thread(target=lambda: values.append(dispatcher.is_bound_to(owner)))
    t.start()
    t.join()
    assert values == [True] and not dispatcher.is_bound_to(object())
    with monkeypatch.context() as patch:
        patch.setattr(module.os, "getpid", lambda: dispatcher._pid + 1)
        with pytest.raises(DirectDispatchError, match="WRONG_OWNER"):
            dispatcher.is_bound_to(owner)
