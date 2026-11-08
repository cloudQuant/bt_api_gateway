import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from threading import Barrier

import pytest

from bt_api_gateway.database_identity import GatewayDatabaseIdentityError
from bt_api_gateway.direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
    payload_digest,
)

_journal_ids = {}


def journal(path, clock=lambda: 100.0, generation="process-1", **kwargs):
    if path not in _journal_ids:
        result = GatewayDirectCommandJournal.create(
            path, "account", generation=generation, clock=clock, **kwargs
        )
        _journal_ids[path] = result.journal_id
        return result
    return GatewayDirectCommandJournal(
        path,
        "account",
        generation=generation,
        expected_journal_id=_journal_ids[path],
        minimum_revision=0,
        clock=clock,
        **kwargs,
    )


def dispatch(j, *items):
    identity = items[-1]
    key = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return j.begin_dispatch(*items, (key,))


def finish(j, *items):
    identity = items[-2]
    key = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return j.finish(*items[:-1], (key,), items[-1])


def reserve(j, strategy="s", key="k", payload=None):
    return j.reserve(strategy, key, "owner", {"qty": "1"} if payload is None else payload)


def args(row):
    return (row.strategy_scope, row.request_key, row.reservation_id, row.digest, row.principal)


def error(code, call):
    with pytest.raises(DirectCommandJournalError) as exc:
        call()
    assert exc.value.code == code


def test_reserve_is_bounded_idempotent_and_immutable(tmp_path):
    now = [100.0]
    j = journal(tmp_path / "db", clock=lambda: now[0], max_records=2)
    payload = {"qty": "1", "meta": [True, None]}
    row = reserve(j, payload=payload)
    payload["meta"].append("changed")
    now[0] += 3
    again = reserve(j, payload={"meta": [True, None], "qty": "1"})
    assert row == again and again.expires_at == 110
    assert row.digest == payload_digest({"qty": "1", "meta": [True, None]})
    with pytest.raises(FrozenInstanceError):
        row.status = "SENT"
    error("REQUEST_CONFLICT", lambda: reserve(j, payload=payload))
    error(
        "REQUEST_CONFLICT", lambda: j.reserve("s", "k", "other", {"qty": "1", "meta": [True, None]})
    )
    assert reserve(j, strategy="other").reservation_id != row.reservation_id
    error("CAPACITY_EXCEEDED", lambda: reserve(j, key="third"))
    error("SCHEMA_OR_CAPACITY_MISMATCH", lambda: journal(tmp_path / "db", max_records=3))


@pytest.mark.parametrize(
    "payload",
    [
        1.2,
        float("nan"),
        {"secret_key": "x"},
        {"api_key": "x"},
        {1: "x"},
        {"x": object()},
        [0] * 4097,
        {"x": "a" * 17000},
    ],
)
def test_bad_payload_fails_closed(tmp_path, payload):
    j = journal(tmp_path / "db")
    error("INVALID_PAYLOAD", lambda: reserve(j, payload=payload))


def test_release_and_expiry_are_tombstones_and_operation_id_is_bound(tmp_path):
    now = [100.0]
    path = tmp_path / "db"
    j = journal(path, clock=lambda: now[0])
    a = reserve(j)
    released = j.release(*args(a), "op", a.version)
    assert released.status == "RELEASED"
    assert j.release(*args(a), "op", a.version) == released
    error("OPERATION_CONFLICT", lambda: j.release(*args(a), "op", 2))
    assert reserve(j) == released
    error("STATE_CONFLICT", lambda: dispatch(j, *args(a), a.version, {"ref": "a"}))
    b = reserve(j, key="other")
    now[0] = 110.0
    expired = j.expire("s", "other", "owner")
    assert expired.status == "EXPIRED"
    expired = j.release(*args(b), "op2", b.version)
    assert expired.status == "EXPIRED" and expired.release_operation_id == "op2"
    assert j.release(*args(b), "op2", b.version) == expired
    reopened = journal(path, generation="process-2")
    assert reopened.get("s", "k", "owner") == released
    assert reopened.get("s", "other", "owner") == expired
    error("NOT_FOUND", lambda: reopened.get("s", "missing", "owner"))


def test_dispatch_finish_recovery_and_identity(tmp_path):
    path = tmp_path / "db"
    j = journal(path)
    a = reserve(j)
    started = dispatch(j, *args(a), a.version, {"ref": "one", "front": 1})
    assert started.newly_started and started.record.status == "DISPATCHING"
    assert not dispatch(j, *args(a), a.version, {"front": 1, "ref": "one"}).newly_started
    error("IDENTITY_CONFLICT", lambda: dispatch(j, *args(a), a.version, {"ref": "two"}))
    error("STATE_CONFLICT", lambda: j.release(*args(a), "op", a.version))
    reopened = journal(path, generation="process-2")
    assert reopened.get("s", "k", "owner").status == "DISPATCHING"
    unknown = finish(
        reopened, *args(a), started.record.version, {"ref": "one", "front": 1}, "UNKNOWN"
    )
    assert (
        finish(reopened, *args(a), started.record.version, {"ref": "one", "front": 1}, "UNKNOWN")
        == unknown
    )
    error(
        "STATE_CONFLICT",
        lambda: finish(reopened, *args(a), unknown.version, {"ref": "one", "front": 1}, "NOT_SENT"),
    )
    assert not dispatch(reopened, *args(a), a.version, {"ref": "one", "front": 1}).newly_started
    error("STATE_CONFLICT", lambda: reopened.release(*args(a), "op", a.version))
    b = reserve(reopened, key="b")
    s = dispatch(reopened, *args(b), b.version, {"ref": "b"})
    sent = finish(reopened, *args(b), s.record.version, {"ref": "b"}, "SENT")
    assert sent.status == "SENT"
    error(
        "STATE_CONFLICT",
        lambda: finish(reopened, *args(b), s.record.version, {"ref": "b"}, "UNKNOWN"),
    )


def test_old_generation_cannot_dispatch_and_expire_is_explicit(tmp_path):
    path = tmp_path / "db"
    old = journal(path)
    row = reserve(old)
    reopened = journal(path, generation="process-2")
    result = dispatch(reopened, *args(row), row.version, {"ref": "x"})
    assert result.record.status == "EXPIRED" and not result.newly_started
    assert reopened.expire("s", "k", "owner") == result.record


@pytest.mark.parametrize("expiry", [False, True])
def test_release_dispatch_expire_compete_in_sqlite(tmp_path, expiry):
    now = [100.0]
    path = tmp_path / "db"
    initial = journal(path, clock=lambda: now[0])
    row = reserve(initial)
    instances = [journal(path, clock=lambda: now[0]) for _ in range(3)]
    if expiry:
        now[0] = 110.0
    barrier = Barrier(3)

    def run(index):
        barrier.wait()
        try:
            if index == 0:
                return instances[index].release(*args(row), "release-op", row.version)
            if index == 1:
                return dispatch(instances[index], *args(row), row.version, {"ref": "r"})
            return instances[index].expire("s", "k", "owner")
        except DirectCommandJournalError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(run, range(3)))
    started = sum(getattr(result, "newly_started", False) for result in results)
    final = initial.get("s", "k", "owner")
    assert final.status in ({"EXPIRED", "RELEASED"} if expiry else {"DISPATCHING", "RELEASED"})
    assert started == (final.status == "DISPATCHING")


def test_commit_failure_before_and_after_commit(tmp_path, monkeypatch):
    j = journal(tmp_path / "db")
    original = j._commit

    def before(db):
        raise OSError("before commit")

    monkeypatch.setattr(j, "_commit", before)
    with pytest.raises(OSError):
        reserve(j)
    error("NOT_FOUND", lambda: j.get("s", "k", "owner"))

    def after(db):
        original(db)
        raise OSError("after commit")

    monkeypatch.setattr(j, "_commit", after)
    with pytest.raises(OSError):
        reserve(j)
    monkeypatch.setattr(j, "_commit", original)
    row = reserve(j)
    assert row.status == "RESERVED"
    assert j.get("s", "k", "owner") == row


def test_database_replacement_is_rejected(tmp_path):
    path = tmp_path / "db"
    j = journal(path)
    reserve(j)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"")
    replacement.replace(path)
    with pytest.raises(GatewayDatabaseIdentityError):
        j.get("s", "k", "owner")


@pytest.mark.parametrize("operation", ["release", "expire", "dispatch", "finish"])
@pytest.mark.parametrize("after_commit", [False, True])
def test_each_mutation_commit_failure(tmp_path, monkeypatch, operation, after_commit):
    now = [100.0]
    j = journal(tmp_path / "db", clock=lambda: now[0])
    row = reserve(j)
    if operation == "finish":
        start = dispatch(j, *args(row), row.version, {"ref": "r"})
    if operation == "expire":
        now[0] = 110
    prior_revision = j.recovery_page(limit=10).revision
    original = j._commit

    def fail(db):
        if after_commit:
            original(db)
        raise OSError("injected commit failure")

    monkeypatch.setattr(j, "_commit", fail)
    with pytest.raises(OSError):
        if operation == "release":
            j.release(*args(row), "op", row.version)
        elif operation == "expire":
            j.expire("s", "k", "owner")
        elif operation == "dispatch":
            dispatch(j, *args(row), row.version, {"ref": "r"})
        else:
            finish(j, *args(row), start.record.version, {"ref": "r"}, "SENT")
    monkeypatch.setattr(j, "_commit", original)
    actual = j.get("s", "k", "owner").status
    before = "DISPATCHING" if operation == "finish" else "RESERVED"
    after = {
        "release": "RELEASED",
        "expire": "EXPIRED",
        "dispatch": "DISPATCHING",
        "finish": "SENT",
    }[operation]
    assert actual == (after if after_commit else before)
    assert j.recovery_page(limit=10).revision == prior_revision + int(after_commit)
    if operation == "dispatch" and after_commit:
        assert not dispatch(j, *args(row), row.version, {"ref": "r"}).newly_started


def test_account_and_release_operation_capacity_are_bounded(tmp_path):
    path = tmp_path / "db"
    j = journal(path)
    row = reserve(j)
    j.release(*args(row), "op", row.version)
    error("OPERATION_CONFLICT", lambda: j.release(*args(row), "other", row.version))
    error(
        "ACCOUNT_MISMATCH",
        lambda: GatewayDirectCommandJournal(
            path, "other", generation="g", expected_journal_id=j.journal_id, minimum_revision=0
        ),
    )


def test_expiry_at_release_and_versioned_dispatch_retry(tmp_path):
    now = [100.0]
    j = journal(tmp_path / "db", clock=lambda: now[0])
    row = reserve(j)
    now[0] = 110.0
    assert j.release(*args(row), "op", row.version).status == "EXPIRED"
    now[0] = 120.0
    other = reserve(j, key="other")
    start = dispatch(j, *args(other), other.version, {"ref": "r"})
    assert start.newly_started
    error("VERSION_CONFLICT", lambda: dispatch(j, *args(other), 2, {"ref": "r"}))
    error("INVALID_PAYLOAD", lambda: dispatch(j, *args(other), 1, {"ref": 1.1}))


def test_explicit_create_and_anchored_reopen(tmp_path):
    import sqlite3

    path = tmp_path / "db"
    error(
        "DATABASE_UNAVAILABLE",
        lambda: GatewayDirectCommandJournal(
            path, "account", generation="g", expected_journal_id="missing", minimum_revision=0
        ),
    )
    assert not path.exists()
    j = GatewayDirectCommandJournal.create(path, "account", generation="g")
    initial = j.recovery_page(limit=1)
    assert initial.revision == 0 and initial.journal_id == j.journal_id
    error(
        "DATABASE_EXISTS",
        lambda: GatewayDirectCommandJournal.create(path, "account", generation="g"),
    )
    error(
        "JOURNAL_ID_MISMATCH",
        lambda: GatewayDirectCommandJournal(
            path, "account", generation="g", expected_journal_id="wrong", minimum_revision=0
        ),
    )
    backup = tmp_path / "earlier"
    with sqlite3.connect(path) as source, sqlite3.connect(backup) as target:
        source.backup(target)
    row = reserve(j)
    anchor = j.recovery_page(limit=1).revision
    assert anchor == 1
    reopened = GatewayDirectCommandJournal(
        path, "account", generation="new", expected_journal_id=j.journal_id, minimum_revision=anchor
    )
    assert reopened.get("s", "k", "owner") == row
    error(
        "REVISION_ROLLBACK",
        lambda: GatewayDirectCommandJournal(
            backup,
            "account",
            generation="g",
            expected_journal_id=j.journal_id,
            minimum_revision=anchor,
        ),
    )
    empty = tmp_path / "empty"
    empty.touch()
    error(
        "INVALID_DATABASE",
        lambda: GatewayDirectCommandJournal(
            empty, "account", generation="g", expected_journal_id=j.journal_id, minimum_revision=0
        ),
    )


def test_recovery_pagination_and_mutation_revision(tmp_path):
    j = journal(tmp_path / "db")
    a = reserve(j, strategy="a", key="one")
    b = reserve(j, strategy="b", key="two")
    c = reserve(j, strategy="c", key="three")
    d = reserve(j, strategy="d", key="four")
    sent = dispatch(j, *args(b), b.version, {"ref": "b"})
    unknown = dispatch(j, *args(c), c.version, {"ref": "c"})
    finish(j, *args(c), unknown.record.version, {"ref": "c"}, "UNKNOWN")
    released = j.release(*args(d), "release-d", d.version)
    page1 = j.recovery_page(limit=2)
    assert [(r.strategy_scope, r.status) for r in page1.records] == [
        ("a", "RESERVED"),
        ("b", "DISPATCHING"),
    ]
    page2 = j.recovery_page(limit=2, cursor=page1.next_cursor)
    assert [(r.strategy_scope, r.status) for r in page2.records] == [
        ("c", "UNKNOWN"),
        ("d", "RELEASED"),
    ]
    assert page2.records[-1].release_operation_id == "release-d" and page2.records[-1] == released
    assert page1.revision == page2.revision and page2.next_cursor is None
    assert reserve(j, strategy="a", key="one") == a
    assert j.get("a", "one", "owner") == a
    assert dispatch(j, *args(b), b.version, {"ref": "b"}).newly_started is False
    assert j.recovery_page(limit=2, cursor=page1.next_cursor).revision == page1.revision
    finish(j, *args(b), sent.record.version, {"ref": "b"}, "SENT")
    error("RESTART_REQUIRED", lambda: j.recovery_page(limit=2, cursor=page1.next_cursor))
    assert j.recovery_page(limit=2).revision == page1.revision + 1


def test_lost_reserve_reply_discoverable_by_new_owner(tmp_path, monkeypatch):
    path = tmp_path / "db"
    j = journal(path)
    original = j._commit

    def lost_reply(db):
        original(db)
        raise OSError("response lost")

    monkeypatch.setattr(j, "_commit", lost_reply)
    with pytest.raises(OSError):
        reserve(j, strategy="strategy-b", key="client-not-saved")
    restored = GatewayDirectCommandJournal(
        path, "account", generation="new", expected_journal_id=j.journal_id, minimum_revision=0
    )
    page = restored.recovery_page(limit=1)
    assert page.records[0].request_key == "client-not-saved"
    assert page.records[0].status == "RESERVED" and page.records[0].reservation_id


def test_strong_identity_collision_across_strategies_and_reopen(tmp_path):
    path = tmp_path / "db"
    j = journal(path)
    a = reserve(j, strategy="a")
    b = reserve(j, strategy="b")
    first = j.begin_dispatch(
        *args(a), a.version, {"raw": "one"}, ("day/account/strong", "secondary")
    )
    assert first.newly_started
    error(
        "IDENTITY_CONFLICT",
        lambda: j.begin_dispatch(
            *args(b), b.version, {"raw": "different"}, ("day/account/strong",)
        ),
    )
    error(
        "IDENTITY_CONFLICT",
        lambda: j.begin_dispatch(*args(b), b.version, {"raw": "one"}, ("other-key",)),
    )
    error(
        "IDENTITY_CONFLICT",
        lambda: j.begin_dispatch(*args(a), a.version, {"raw": "one"}, ("secondary",)),
    )
    error(
        "IDENTITY_CONFLICT",
        lambda: j.finish(*args(a), first.record.version, {"raw": "one"}, ("secondary",), "UNKNOWN"),
    )
    reopened = GatewayDirectCommandJournal(
        path,
        "account",
        generation="process-1",
        expected_journal_id=j.journal_id,
        minimum_revision=3,
        clock=lambda: 100.0,
    )
    error(
        "IDENTITY_CONFLICT",
        lambda: reopened.begin_dispatch(
            *args(b), b.version, {"raw": "another"}, ("day/account/strong",)
        ),
    )
    assert reopened.get("b", "k", "owner").status == "RESERVED"
    assert reopened.recovery_page(limit=10).records[0].strong_identity_keys == (
        "day/account/strong",
        "secondary",
    )


def test_concurrent_strong_key_claim_has_one_winner(tmp_path):
    path = tmp_path / "db"
    j = journal(path)
    a = reserve(j, strategy="a")
    b = reserve(j, strategy="b")
    peers = [journal(path), journal(path)]
    barrier = Barrier(2)

    def run(pair):
        peer, row = pair
        barrier.wait()
        try:
            return peer.begin_dispatch(
                *args(row), row.version, {"raw": row.strategy_scope}, ("same-strong-identity",)
            )
        except DirectCommandJournalError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, zip(peers, (a, b), strict=True)))
    assert sum(getattr(item, "newly_started", False) for item in results) == 1
    assert results.count("IDENTITY_CONFLICT") == 1
    assert sorted(r.status for r in j.recovery_page(limit=10).records) == [
        "DISPATCHING",
        "RESERVED",
    ]


def test_missing_and_recreated_database_never_resets_known_journal(tmp_path):
    path = tmp_path / "db"
    j = journal(path)
    reserve(j)
    old_id = j.journal_id
    path.unlink()
    error(
        "DATABASE_UNAVAILABLE",
        lambda: GatewayDirectCommandJournal(
            path, "account", generation="new", expected_journal_id=old_id, minimum_revision=1
        ),
    )
    replacement = GatewayDirectCommandJournal.create(path, "account", generation="new")
    assert replacement.journal_id != old_id
    error(
        "JOURNAL_ID_MISMATCH",
        lambda: GatewayDirectCommandJournal(
            path, "account", generation="new", expected_journal_id=old_id, minimum_revision=1
        ),
    )


def test_strong_keys_required_canonical_and_retry_stable(tmp_path):
    j = journal(tmp_path / "db")
    row = reserve(j)
    for keys in ((), ("b", "a"), ("a", "a"), ("x",) * 17):
        error(
            "INVALID_IDENTITY_KEYS",
            lambda keys=keys: j.begin_dispatch(*args(row), row.version, {"ref": "x"}, keys),
        )
    assert j.get("s", "k", "owner").status == "RESERVED"
    started = j.begin_dispatch(*args(row), row.version, {"ref": "x"}, ("a", "b"))
    assert not j.begin_dispatch(*args(row), row.version, {"ref": "x"}, ("a", "b")).newly_started
    finished = j.finish(*args(row), started.record.version, {"ref": "x"}, ("a", "b"), "SENT")
    assert (
        j.finish(*args(row), started.record.version, {"ref": "x"}, ("a", "b"), "SENT") == finished
    )


def test_reopen_rejects_damaged_identity_constraint(tmp_path):
    import sqlite3

    path = tmp_path / "db"
    j = journal(path)
    with sqlite3.connect(path) as db:
        db.execute("DROP INDEX direct_journal_native_identity")
        db.execute(
            "CREATE INDEX direct_journal_native_identity ON direct_journal_commands(account, native_identity_json)"
        )
    error(
        "INVALID_DATABASE",
        lambda: GatewayDirectCommandJournal(
            path, "account", generation="g", expected_journal_id=j.journal_id, minimum_revision=0
        ),
    )


def test_observation_tracks_remaining_ttl_without_mutation_or_renewal(tmp_path):
    now = [100.0]
    j = journal(tmp_path / "db", clock=lambda: now[0])
    row = j.reserve("s", "k", "owner", {"qty": "1"}, ttl_seconds=10)
    revision = j.recovery_page(limit=1).revision
    observation = j.observe("s", "k", "owner")
    assert observation.record == row and observation.generation_current
    assert observation.remaining_ttl_seconds == 10.0
    with pytest.raises(FrozenInstanceError):
        observation.remaining_ttl_seconds = 100
    now[0] = 103.0
    repeated = j.reserve("s", "k", "owner", {"qty": "1"}, ttl_seconds=30)
    assert repeated == row
    assert j.observe("s", "k", "owner").remaining_ttl_seconds == 7.0
    now[0] = 110.0
    at_boundary = j.observe("s", "k", "owner")
    assert at_boundary.remaining_ttl_seconds == 0.0 and at_boundary.record.status == "RESERVED"
    now[0] = 111.0
    after = j.observe("s", "k", "owner")
    assert after.remaining_ttl_seconds == 0.0 and after.record.status == "RESERVED"
    assert j.recovery_page(limit=1).revision == revision
    assert j.get("s", "k", "owner") == row
    expired = j.expire("s", "k", "owner")
    assert expired.status == "EXPIRED"
    terminal = j.observe("s", "k", "owner")
    assert terminal.generation_current and terminal.remaining_ttl_seconds is None


def test_observation_of_old_generation_is_zero_and_read_only(tmp_path):
    path = tmp_path / "db"
    old = journal(path, clock=lambda: 100.0)
    row = reserve(old)
    current = journal(path, generation="process-2", clock=lambda: 1.0)
    revision = current.recovery_page(limit=1).revision
    observed = current.observe("s", "k", "owner")
    assert not observed.generation_current and observed.remaining_ttl_seconds == 0.0
    assert observed.record == row and observed.record.status == "RESERVED"
    assert current.recovery_page(limit=1).revision == revision
    released = current.release(*args(row), "op", row.version)
    assert released.status == "EXPIRED"
    observed = current.observe("s", "k", "owner")
    assert not observed.generation_current and observed.remaining_ttl_seconds is None


@pytest.mark.parametrize("bad_clock", [float("nan"), float("inf"), -1, True, "1"])
def test_observation_rejects_invalid_clock_without_writing(tmp_path, bad_clock):
    now = [100.0]
    j = journal(tmp_path / "db", clock=lambda: now[0])
    row = reserve(j)
    revision = j.recovery_page(limit=1).revision
    now[0] = bad_clock
    error("CLOCK_INVALID", lambda: j.observe("s", "k", "owner"))
    assert j.get("s", "k", "owner") == row
    assert j.recovery_page(limit=1).revision == revision
