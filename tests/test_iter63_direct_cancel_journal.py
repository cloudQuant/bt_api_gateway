"""Synthetic cancel journal tests: no account or provider I/O."""

import sqlite3

import pytest
from bt_api_base.direct_cancel_protocol import PreparedCancelRequest
from bt_api_base.direct_write_protocol import NativeOrderIdentity

from bt_api_gateway.direct_cancel_journal import GatewayDirectCancelJournal
from bt_api_gateway.direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
)
from bt_api_gateway.direct_dispatch import _identity
from bt_api_gateway.session_guard import LocalAccountSessionGuard


@pytest.fixture
def setup(tmp_path):
    directory = tmp_path / "guard"
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, "acct", "owner")
    generation = guard.acquire()
    journal = GatewayDirectCommandJournal.create(
        tmp_path / "db", "acct", generation=generation, max_records=10, execution_max_facts=20
    )
    yield journal, GatewayDirectCancelJournal(journal), guard, tmp_path / "db"
    guard.release()


def make_order(journal, *, key="order", strategy="s", principal="p", ref="ref"):
    row = journal.reserve(strategy, key, principal, {"symbol": "X", "side": "buy", "quantity": "1"})
    identity = NativeOrderIdentity("TEST", ref, {"trading_day": "20300101", "front_id": 1}, 1)
    native = _identity(identity, "TEST")
    result = journal.begin_dispatch(
        strategy, key, row.reservation_id, row.digest, principal, 1, native, ("order-key-" + ref,)
    )
    return result.record, identity


def request(cancel, order, identity, operation="cancel"):
    return cancel.request(
        order.strategy_scope,
        operation,
        order.principal,
        order.request_key,
        order.reservation_id,
        order.digest,
        target_identity=identity,
        symbol="X",
    )


def prepared(identity, key="cancel-key-1", reservation="provider-reservation"):
    return PreparedCancelRequest(
        reservation, identity, "X", "20300102", 2, {"request_id": 12}, (key,)
    )


def reopen(journal, path):
    return GatewayDirectCommandJournal(
        path,
        "acct",
        generation=journal.generation,
        expected_journal_id=journal.journal_id,
        minimum_revision=0,
        max_records=10,
        execution_max_facts=20,
    )


def test_attempts_are_independent_idempotent_and_do_not_change_order(setup):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    first = request(cancel, order, identity, "one")
    second = request(cancel, order, identity, "two")
    assert first.attempt_id != second.attempt_id
    assert first.principal == first.target_principal == "p" and first.target_version == 2
    assert request(cancel, order, identity, "one") == first
    with pytest.raises(DirectCommandJournalError, match="REQUEST_CONFLICT"):
        cancel.request(
            "s",
            "one",
            "p",
            order.request_key,
            order.reservation_id,
            order.digest,
            target_identity=identity,
            symbol="Y",
        )
    p1, p2 = prepared(identity), prepared(identity, "cancel-key-2", "p2")
    started = cancel.begin_dispatch("s", "one", "p", 1, p1)
    assert started.newly_started and started.record.marker_id == first.attempt_id
    assert not cancel.begin_dispatch("s", "one", "p", 1, p1).newly_started
    with pytest.raises(DirectCommandJournalError, match="REQUEST_CONFLICT"):
        cancel.begin_dispatch("s", "one", "p", 1, p2)
    with pytest.raises(DirectCommandJournalError, match="ATTEMPT_KEY_CONFLICT"):
        cancel.begin_dispatch("s", "two", "p", 1, p1)
    assert cancel.get("s", "two", "p").status == "REQUESTED"
    other = cancel.begin_dispatch("s", "two", "p", 1, p2).record
    done = cancel.finish(
        "s",
        "one",
        "p",
        2,
        first.attempt_id,
        p1.digest(),
        journal.generation,
        False,
        error_code="cancel_rejected",
    )
    assert done.status == "NOT_SENT" and done.error_code == "cancel_rejected"
    assert (
        cancel.finish(
            "s",
            "one",
            "p",
            2,
            first.attempt_id,
            p1.digest(),
            journal.generation,
            False,
            error_code="cancel_rejected",
        )
        == done
    )
    assert cancel.get("s", "two", "p") == other
    assert journal.get("s", order.request_key, "p") == order
    assert GatewayDirectCancelJournal(reopen(journal, path)).get("s", "one", "p") == done


def test_scope_target_generation_and_order_key_denied(setup):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    with pytest.raises(DirectCommandJournalError):
        cancel.request(
            "other",
            "one",
            "p",
            order.request_key,
            order.reservation_id,
            order.digest,
            target_identity=identity,
            symbol="X",
        )
    with pytest.raises(DirectCommandJournalError):
        cancel.request(
            "s",
            "one",
            "other",
            order.request_key,
            order.reservation_id,
            order.digest,
            target_identity=identity,
            symbol="X",
        )
    request(cancel, order, identity)
    started = cancel.begin_dispatch("s", "cancel", "p", 1, prepared(identity, "order-key-ref"))
    assert started.newly_started
    request(cancel, order, identity, "generation-check")
    journal._generation = "new-owner-generation"
    with pytest.raises(DirectCommandJournalError, match="GENERATION_MISMATCH"):
        cancel.begin_dispatch("s", "generation-check", "p", 1, prepared(identity))


def test_v5_upgrade_is_explicit_guarded_atomic_and_preserves_order(setup, monkeypatch):
    from bt_api_gateway import direct_cancel_journal as module

    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    with journal._transaction() as db:
        before = journal._assert_anchor(db)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE direct_execution_trade_dates")
        db.execute("DROP TABLE direct_place_error_attribution")
        db.execute("DROP TABLE direct_place_keys")
        db.execute("DROP TABLE direct_place_preparations")
        db.execute("DROP TABLE direct_cancel_error_attribution")
        db.execute("DROP TABLE direct_cancel_keys")
        db.execute("DROP TABLE direct_cancel_attempts")
        db.execute("UPDATE direct_journal_meta SET schema_version=5")
    options = dict(
        generation=journal.generation,
        expected_journal_id=journal.journal_id,
        minimum_revision=before,
        max_records=10,
        execution_max_facts=20,
    )
    with pytest.raises(DirectCommandJournalError):
        GatewayDirectCommandJournal(path, "acct", **options)
    original = module._create_cancel_tables

    def fail(db):
        original(db)
        raise RuntimeError("after ddl")

    monkeypatch.setattr(module, "_create_cancel_tables", fail)
    with pytest.raises(RuntimeError, match="after ddl"):
        GatewayDirectCommandJournal.upgrade_v5(path, "acct", guard=guard, **options)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone() == (
            5,
            before,
        )
        assert (
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='direct_cancel_attempts'"
            ).fetchone()[0]
            == 0
        )
    monkeypatch.setattr(module, "_create_cancel_tables", original)
    upgraded = GatewayDirectCommandJournal.upgrade_v5(path, "acct", guard=guard, **options)
    assert upgraded.get("s", "order", "p") == order
    with upgraded._transaction() as db:
        assert upgraded._assert_anchor(db) == before + 1


@pytest.mark.parametrize("mutation", ["key", "target", "marker", "prepared", "extra_table"])
def test_reopen_rejects_corrupt_cancel_state(setup, mutation):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    row = request(cancel, order, identity)
    cancel.begin_dispatch("s", "cancel", "p", row.version, prepared(identity))
    with sqlite3.connect(path) as db:
        if mutation == "key":
            db.execute("UPDATE direct_cancel_keys SET strong_key='different'")
        elif mutation == "target":
            db.execute("UPDATE direct_cancel_attempts SET target_principal='other'")
        elif mutation == "marker":
            db.execute("UPDATE direct_cancel_attempts SET marker_id='different'")
        elif mutation == "prepared":
            db.execute("UPDATE direct_cancel_attempts SET prepared_digest=?", ("0" * 64,))
        else:
            db.execute("CREATE TABLE extra (value TEXT)")
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        reopen(journal, path)


def test_original_version_can_advance_without_invalidating_cancel(setup):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    row = request(cancel, order, identity)
    native = _identity(identity, "TEST")
    finished = journal.finish(
        "s", "order", order.reservation_id, order.digest, "p", 2, native, ("order-key-ref",), "SENT"
    )
    assert finished.version == 3 and row.target_version == 2
    started = cancel.begin_dispatch("s", "cancel", "p", 1, prepared(identity))
    assert started.newly_started
    assert (
        GatewayDirectCancelJournal(reopen(journal, path)).get("s", "cancel", "p").status
        == "DISPATCHING"
    )


def test_crash_reopen_preserves_dispatching_and_no_new_marker(setup):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    row = request(cancel, order, identity)
    prep = prepared(identity)
    started = cancel.begin_dispatch("s", "cancel", "p", row.version, prep)
    recovered = GatewayDirectCancelJournal(reopen(journal, path))
    stored = recovered.get("s", "cancel", "p")
    assert stored.status == "DISPATCHING" and stored.marker_id == started.record.marker_id
    assert not recovered.begin_dispatch("s", "cancel", "p", 1, prep).newly_started
    with pytest.raises(DirectCommandJournalError, match="REQUEST_CONFLICT"):
        recovered.finish("s", "cancel", "p", 2, "other", prep.digest(), journal.generation, True)


def test_upgrade_v5_rejects_corrupt_consumer_without_schema_writes(setup):
    journal, cancel, guard, path = setup
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE direct_execution_trade_dates")
        db.execute("DROP TABLE direct_place_error_attribution")
        db.execute("DROP TABLE direct_place_keys")
        db.execute("DROP TABLE direct_place_preparations")
        db.execute("DROP TABLE direct_cancel_error_attribution")
        db.execute("DROP TABLE direct_cancel_keys")
        db.execute("DROP TABLE direct_cancel_attempts")
        db.execute("UPDATE direct_journal_meta SET schema_version=5")
        db.execute("INSERT INTO direct_execution_consumers VALUES ('acct','p','c','s',8,0)")
        before = db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        GatewayDirectCommandJournal.upgrade_v5(
            path,
            "acct",
            guard=guard,
            generation=journal.generation,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=10,
            execution_max_facts=20,
        )
    with sqlite3.connect(path) as db:
        assert (
            db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
            == before
        )
        assert (
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='direct_cancel_attempts'"
            ).fetchone()[0]
            == 0
        )


def test_order_and_cancel_key_namespaces_allow_both_insertion_orders(setup):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    request(cancel, order, identity, "same-as-existing")
    assert cancel.begin_dispatch(
        "s", "same-as-existing", "p", 1, prepared(identity, "order-key-ref")
    ).newly_started
    request(cancel, order, identity, "same-as-future")
    assert cancel.begin_dispatch(
        "s", "same-as-future", "p", 1, prepared(identity, "order-key-ref2", "provider-two")
    ).newly_started
    second, _ = make_order(journal, key="order-two", ref="ref2")
    assert second.status == "DISPATCHING"
    request(cancel, order, identity, "same-cancel-key")
    with pytest.raises(DirectCommandJournalError, match="ATTEMPT_KEY_CONFLICT"):
        cancel.begin_dispatch(
            "s", "same-cancel-key", "p", 1, prepared(identity, "order-key-ref2", "provider-three")
        )
    reopened = GatewayDirectCancelJournal(reopen(journal, path))
    assert reopened.get("s", "same-as-existing", "p").status == "DISPATCHING"
    assert reopened.get("s", "same-as-future", "p").status == "DISPATCHING"
    assert reopened.get("s", "same-cancel-key", "p").status == "REQUESTED"


def test_order_learned_alias_may_share_cancel_key_and_reopen(setup):
    from bt_api_base.direct_write_protocol import DirectExecutionEventKind, DirectOrderStatus
    from bt_api_base.gateway_execution_protocol import GatewayReturnFact
    from bt_api_base.market_protocol import MarketInstrumentKey
    from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger

    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    row = request(cancel, order, identity)
    assert cancel.begin_dispatch(
        "s", "cancel", "p", row.version, prepared(identity, "shared-venue-key")
    ).newly_started
    fact = GatewayReturnFact(
        "acct",
        "TEST",
        MarketInstrumentKey("test", "EX", "sim", "future", "X", "X"),
        "20300101",
        DirectExecutionEventKind.ORDER,
        "source",
        identity=identity,
        identity_keys=("order-key-ref", "shared-venue-key"),
        binding_keys=("order-key-ref",),
        venue_key="shared-venue-key",
        status=DirectOrderStatus.ACCEPTED,
    )
    result = GatewayDirectExecutionLedger(journal, guard).ingest(fact)
    assert result.disposition == "ATTRIBUTED"
    reopened = reopen(journal, path)
    assert GatewayDirectCancelJournal(reopened).get("s", "cancel", "p").status == "DISPATCHING"
    assert len(GatewayDirectExecutionLedger(reopened, guard).read_events("s")) == 1


def test_cancel_capacity_is_separate_and_bounded(tmp_path):
    directory = tmp_path / "guards"
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, "acct", "owner")
    generation = guard.acquire()
    try:
        journal = GatewayDirectCommandJournal.create(
            tmp_path / "db", "acct", generation=generation, max_records=1
        )
        cancel = GatewayDirectCancelJournal(journal)
        order, identity = make_order(journal)
        first = request(cancel, order, identity, "one")
        with pytest.raises(DirectCommandJournalError, match="CANCEL_CAPACITY_EXCEEDED"):
            request(cancel, order, identity, "two")
        assert request(cancel, order, identity, "one") == first
        assert journal.get("s", "order", "p") == order
    finally:
        guard.release()


def test_request_before_commit_checks_new_and_duplicate_under_sqlite_lock(setup):
    journal, cancel, guard, path = setup
    order, identity = make_order(journal)
    observed = []

    def deny():
        with sqlite3.connect(path, timeout=0) as db:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                db.execute("BEGIN IMMEDIATE")
        observed.append("checked")
        raise RuntimeError("revoked")

    args = ("s", "cancel", "p", order.request_key, order.reservation_id, order.digest)
    with pytest.raises(RuntimeError, match="revoked"):
        cancel.request(*args, target_identity=identity, symbol="X", before_commit=deny)
    with pytest.raises(DirectCommandJournalError, match="NOT_FOUND"):
        cancel.get("s", "cancel", "p")
    row = cancel.request(
        *args,
        target_identity=identity,
        symbol="X",
        before_commit=lambda: observed.append("allowed"),
    )
    with pytest.raises(RuntimeError, match="revoked"):
        cancel.request(*args, target_identity=identity, symbol="X", before_commit=deny)
    assert cancel.get("s", "cancel", "p") == row
    assert observed == ["checked", "allowed", "checked"]
    with pytest.raises(DirectCommandJournalError, match="INVALID_INPUT"):
        cancel.request(*args, target_identity=identity, symbol="X", before_commit=1)
