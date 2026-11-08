from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Event, Lock

import pytest

from bt_api_gateway.direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
)


def make_journal(tmp_path, clock=lambda: 100.0):
    return GatewayDirectCommandJournal.create(
        tmp_path / "journal.db", "account", generation="g1", clock=clock
    )


def revision(journal):
    return journal.recovery_page(limit=10).revision


def test_denial_and_idempotent_retry_do_not_mutate_or_extend_ttl(tmp_path):
    now = [100.0]
    journal = make_journal(tmp_path, clock=lambda: now[0])
    calls = []

    @contextmanager
    def denied():
        calls.append(1)
        raise ValueError("denied")
        yield

    with pytest.raises(ValueError, match="denied"):
        journal.reserve("strategy", "key", "principal", {"symbol": "a"}, reservation_fence=denied)
    assert revision(journal) == 0
    with pytest.raises(DirectCommandJournalError, match="NOT_FOUND"):
        journal.get("strategy", "key", "principal")
    first = journal.reserve("strategy", "key", "principal", {"symbol": "a"}, ttl_seconds=10)
    now[0] = 105.0
    second = journal.reserve(
        "strategy", "key", "principal", {"symbol": "a"}, ttl_seconds=30, reservation_fence=denied
    )
    assert second == first and second.expires_at == 110.0
    assert calls == [1] and revision(journal) == 1
    assert journal.get("strategy", "key", "principal") == first
    released = journal.release(
        "strategy", "key", first.reservation_id, first.digest, "principal", "operation", 1
    )
    assert released.status == "RELEASED"


def test_gate_stays_locked_until_after_commit(tmp_path, monkeypatch):
    journal = make_journal(tmp_path)
    gate, entered, proceed, committed, acquired = Lock(), Event(), Event(), Event(), Event()
    original = journal._commit

    @contextmanager
    def fence():
        with gate:
            entered.set()
            yield

    def commit(db):
        assert entered.is_set() and not acquired.is_set()
        assert proceed.wait(5)
        original(db)
        committed.set()

    monkeypatch.setattr(journal, "_commit", commit)

    def change_gate():
        with gate:
            assert committed.is_set()
            acquired.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        reserve = pool.submit(
            journal.reserve,
            "strategy",
            "key",
            "principal",
            {"symbol": "a"},
            reservation_fence=fence,
        )
        assert entered.wait(5)
        change = pool.submit(change_gate)
        assert not acquired.wait(0.1)
        proceed.set()
        assert reserve.result(timeout=5).status == "RESERVED"
        change.result(timeout=5)
    assert acquired.is_set()


def test_existing_key_does_not_wait_for_locked_gate(tmp_path):
    now = [100.0]
    journal = make_journal(tmp_path, clock=lambda: now[0])
    first = journal.reserve("strategy", "key", "principal", {"symbol": "a"})
    gate = Lock()

    @contextmanager
    def fence():
        with gate:
            yield

    now[0] = 105.0
    gate.acquire()
    with ThreadPoolExecutor(max_workers=1) as pool:
        repeated = pool.submit(
            journal.reserve,
            "strategy",
            "key",
            "principal",
            {"symbol": "a"},
            ttl_seconds=30,
            reservation_fence=fence,
        )
        try:
            assert repeated.result(timeout=2) == first
        finally:
            gate.release()
    assert first.expires_at == 110.0 and revision(journal) == 1


def test_failed_commit_rolls_back_and_exit_cannot_suppress(tmp_path, monkeypatch):
    journal = make_journal(tmp_path)

    @contextmanager
    def suppressing():
        try:
            yield
        except RuntimeError:
            pass

    def bad_commit(db):
        raise RuntimeError("commit failed")

    monkeypatch.setattr(journal, "_commit", bad_commit)
    with pytest.raises(RuntimeError, match="commit failed"):
        journal.reserve(
            "strategy", "key", "principal", {"symbol": "a"}, reservation_fence=suppressing
        )
    monkeypatch.undo()
    assert revision(journal) == 0
    with pytest.raises(DirectCommandJournalError, match="NOT_FOUND"):
        journal.get("strategy", "key", "principal")


def test_exit_error_is_propagated_after_committed_row(tmp_path):
    journal = make_journal(tmp_path)

    @contextmanager
    def bad_exit():
        yield
        raise RuntimeError("exit failed")

    with pytest.raises(RuntimeError, match="exit failed"):
        journal.reserve("strategy", "key", "principal", {"symbol": "a"}, reservation_fence=bad_exit)
    assert journal.get("strategy", "key", "principal").status == "RESERVED"
    assert revision(journal) == 1
