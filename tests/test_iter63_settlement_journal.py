"""SQLite-only settlement journal behavior using synthetic identities."""

import sqlite3

import pytest
from bt_api_base.direct_write_protocol import SettlementObservation, SettlementStatus

from bt_api_gateway.direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
)
from bt_api_gateway.session_guard import LocalAccountSessionGuard


def obs(
    day="20300101", status=SettlementStatus.UNCONFIRMED, session=1, oid="obs-1", account="native-a"
):
    return SettlementObservation("TEST", account, day, session, status, oid)


@pytest.fixture
def owned(tmp_path):
    directory = tmp_path / "guards"
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, "acct", "owner")
    generation = guard.acquire()
    journal = GatewayDirectCommandJournal.create(
        tmp_path / "journal.sqlite", "acct", generation=generation, max_records=3
    )
    yield journal, guard, tmp_path / "journal.sqlite"
    guard.release()


def _drop_v4_for_v2(db):
    for name in (
        "direct_cancel_keys",
        "direct_cancel_attempts",
        "direct_execution_consumers",
        "direct_execution_meta",
        "direct_execution_facts",
        "direct_execution_aliases",
        "direct_execution_trades",
        "direct_execution_positions",
        "direct_execution_totals",
        "direct_execution_events",
        "direct_execution_conflicts",
    ):
        db.execute(f"DROP TABLE {name}")
    db.execute("DROP TABLE direct_journal_settlement")


def begin(journal, item=None, marker="marker-1", **kwargs):
    return journal.settlement_begin(
        item or obs(),
        marker,
        before_begin=kwargs.get("before_begin", lambda: None),
        before_commit=kwargs.get("before_commit", lambda: None),
    )


def test_attempt_readback_same_day_and_new_day(owned):
    journal, guard, _ = owned
    created = begin(journal)
    assert created.newly_started and created.record.status == "ATTEMPTING"
    replay = begin(journal, obs(session=2, oid="obs-2"), marker="another")
    assert not replay.newly_started and replay.record.marker_id == "marker-1"
    unknown = journal.settlement_mark_unknown(obs(), "marker-1")
    assert unknown.status == "UNKNOWN" and unknown.version == 2
    final = journal.settlement_confirm(
        obs(status=SettlementStatus.CONFIRMED, session=2, oid="readback")
    )
    assert (
        final.status == "CONFIRMED"
        and final.version == 3
        and final.confirmation_observation_id == "readback"
    )
    assert not begin(journal, obs(session=3, oid="later"), marker="never").newly_started
    assert begin(journal, obs(day="20300102", oid="next")).newly_started
    with pytest.raises(DirectCommandJournalError, match="SETTLEMENT_ACCOUNT_MISMATCH"):
        begin(journal, obs(day="20300103", account="wrong"))
    assert journal.settlement_get("TEST", "20300101") == final
    assert journal.settlement_get("TEST", "20300102").status == "ATTEMPTING"


def test_shared_capacity_no_removal_and_fenced_rollback(owned):
    journal, _, _ = owned
    journal.reserve("s", "one", "p", {"symbol": "rb"})
    before = journal.get("s", "one", "p")

    def fail():
        raise RuntimeError("fence")

    with pytest.raises(RuntimeError, match="fence"):
        begin(journal, before_commit=fail)
    assert journal.settlement_get("TEST", "20300101") is None
    begin(journal)
    begin(journal, obs(day="20300102", oid="next"))
    with pytest.raises(DirectCommandJournalError, match="CAPACITY_EXCEEDED"):
        begin(journal, obs(day="20300103", oid="third"))
    with pytest.raises(DirectCommandJournalError, match="CAPACITY_EXCEEDED"):
        journal.reserve("s", "two", "p", {"symbol": "rb"})
    assert journal.get("s", "one", "p") == before


def test_v2_upgrade_is_explicit_guarded_atomic_and_preserves_records(owned):
    journal, guard, path = owned
    order = journal.reserve("s", "one", "p", {"symbol": "rb"})
    with sqlite3.connect(path) as db:
        _drop_v4_for_v2(db)
        db.execute("UPDATE direct_journal_meta SET schema_version=2")
    journal._schema_version = 2  # model an already-open v2 object
    assert journal.get("s", "one", "p") == order
    with sqlite3.connect(path) as db:
        before = db.execute("SELECT revision FROM direct_journal_meta").fetchone()[0]
    with pytest.raises(DirectCommandJournalError, match="JOURNAL_ID_MISMATCH"):
        GatewayDirectCommandJournal.upgrade_v2(
            path,
            "acct",
            generation=journal.generation,
            guard=guard,
            expected_journal_id="wrong",
            minimum_revision=before,
            max_records=3,
        )
    with sqlite3.connect(path) as db:
        assert db.execute(
            "SELECT schema_version, revision FROM direct_journal_meta"
        ).fetchone() == (2, before)
        assert (
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='direct_journal_settlement'"
            ).fetchone()[0]
            == 0
        )
    upgraded = GatewayDirectCommandJournal.upgrade_v2(
        path,
        "acct",
        generation=journal.generation,
        guard=guard,
        expected_journal_id=journal.journal_id,
        minimum_revision=before,
        max_records=3,
    )
    assert upgraded.get("s", "one", "p") == order
    with sqlite3.connect(path) as db:
        assert db.execute(
            "SELECT schema_version, revision FROM direct_journal_meta"
        ).fetchone() == (6, before + 1)
    with pytest.raises(DirectCommandJournalError, match="SCHEMA_OR_CAPACITY_MISMATCH"):
        journal.get("s", "one", "p")
    assert begin(upgraded).newly_started


def test_existing_db_without_migration_is_never_accepted_or_recreated(owned):
    journal, _, path = owned
    with sqlite3.connect(path) as db:
        _drop_v4_for_v2(db)
        db.execute("UPDATE direct_journal_meta SET schema_version=2")
    with pytest.raises(DirectCommandJournalError):
        GatewayDirectCommandJournal(
            path,
            "acct",
            generation=journal.generation,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=3,
        )
    assert path.exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "partial_index",
        "missing_unique",
        "nullable",
        "orphan_key",
        "orphan_release",
        "over_capacity",
        "delete_trigger",
    ],
)
def test_upgrade_rejects_mutated_v2_schema_or_data_without_writes(owned, mutation):
    journal, guard, path = owned
    journal.reserve("s", "one", "p", {"symbol": "rb"})
    with sqlite3.connect(path) as db:
        _drop_v4_for_v2(db)
        db.execute("UPDATE direct_journal_meta SET schema_version=2")
        if mutation == "partial_index":
            db.execute("DROP INDEX direct_journal_native_identity")
            db.execute(
                "CREATE UNIQUE INDEX direct_journal_native_identity ON direct_journal_commands(account, native_identity_json) WHERE native_identity_json IS NULL"
            )
        elif mutation in ("missing_unique", "nullable"):
            (ddl,) = db.execute(
                "SELECT sql FROM sqlite_master WHERE name='direct_journal_commands'"
            ).fetchone()
            ddl = ddl.replace(
                "reservation_id TEXT NOT NULL UNIQUE",
                "reservation_id TEXT NOT NULL"
                if mutation == "missing_unique"
                else "reservation_id TEXT UNIQUE",
            )
            db.execute("DROP INDEX direct_journal_native_identity")
            db.execute("ALTER TABLE direct_journal_commands RENAME TO old_commands")
            db.execute(ddl)
            db.execute("INSERT INTO direct_journal_commands SELECT * FROM old_commands")
            db.execute("DROP TABLE old_commands")
            db.execute(
                "CREATE UNIQUE INDEX direct_journal_native_identity ON direct_journal_commands(account, native_identity_json) WHERE native_identity_json IS NOT NULL"
            )
        elif mutation == "orphan_key":
            db.execute("INSERT INTO direct_journal_strong_keys VALUES ('acct','orphan','missing')")
        elif mutation == "orphan_release":
            db.execute(
                "INSERT INTO direct_journal_releases VALUES ('acct','op','s','none','missing','digest','p',1)"
            )
        elif mutation == "delete_trigger":
            db.execute(
                "CREATE TRIGGER erase_orders AFTER UPDATE OF schema_version ON direct_journal_meta BEGIN DELETE FROM direct_journal_commands; END"
            )
        else:
            for index in range(3):
                db.execute(
                    "INSERT INTO direct_journal_commands SELECT account,strategy,?, ?,principal,digest,payload_json,generation,expires_at,status,version,native_identity_json,strong_keys_json FROM direct_journal_commands WHERE request_key='one'",
                    (f"k{index}", f"r{index}"),
                )
        baseline = db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
        count = db.execute("SELECT count(*) FROM direct_journal_commands").fetchone()[0]
    with pytest.raises(DirectCommandJournalError, match="INVALID_DATABASE"):
        GatewayDirectCommandJournal.upgrade_v2(
            path,
            "acct",
            generation=journal.generation,
            guard=guard,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=3,
        )
    with sqlite3.connect(path) as db:
        assert (
            db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
            == baseline
        )
        assert db.execute("SELECT count(*) FROM direct_journal_commands").fetchone()[0] == count
        assert (
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='direct_journal_settlement'"
            ).fetchone()[0]
            == 0
        )


def test_upgrade_failure_after_ddl_rolls_back_schema_and_revision(owned, monkeypatch):
    journal, guard, path = owned
    with sqlite3.connect(path) as db:
        _drop_v4_for_v2(db)
        db.execute("UPDATE direct_journal_meta SET schema_version=2")
        baseline = db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
    original = GatewayDirectCommandJournal._create_settlement_table

    def fail_after_ddl(db):
        original(db)
        raise RuntimeError("synthetic migration fault")

    monkeypatch.setattr(
        GatewayDirectCommandJournal, "_create_settlement_table", staticmethod(fail_after_ddl)
    )
    with pytest.raises(RuntimeError, match="synthetic migration fault"):
        GatewayDirectCommandJournal.upgrade_v2(
            path,
            "acct",
            generation=journal.generation,
            guard=guard,
            expected_journal_id=journal.journal_id,
            minimum_revision=0,
            max_records=3,
        )
    with sqlite3.connect(path) as db:
        assert (
            db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
            == baseline
        )
        assert (
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='direct_journal_settlement'"
            ).fetchone()[0]
            == 0
        )


def test_upgrade_rejects_wrong_account_guard_and_generation(owned, tmp_path):
    journal, guard, path = owned
    with sqlite3.connect(path) as db:
        _drop_v4_for_v2(db)
        db.execute("UPDATE direct_journal_meta SET schema_version=2")
        baseline = db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
    other_dir = tmp_path / "other-guards"
    other_dir.mkdir()
    other = LocalAccountSessionGuard(other_dir, "other-account", "other-owner")
    other.acquire()
    try:
        for owner, generation in ((other, journal.generation), (guard, "wrong-generation")):
            with pytest.raises(DirectCommandJournalError, match="GUARD_BINDING_MISMATCH"):
                GatewayDirectCommandJournal.upgrade_v2(
                    path,
                    "acct",
                    generation=generation,
                    guard=owner,
                    expected_journal_id=journal.journal_id,
                    minimum_revision=0,
                    max_records=3,
                )
    finally:
        other.release()
    with sqlite3.connect(path) as db:
        assert (
            db.execute("SELECT schema_version,revision FROM direct_journal_meta").fetchone()
            == baseline
        )


def test_upgrade_preserves_unknown_identity_strong_keys_and_release(owned):
    journal, guard, path = owned
    first = journal.reserve("s", "unknown", "p", {"symbol": "rb"})
    native = {
        "exchange_name": "TEST",
        "client_order_id": "ref",
        "session_generation": 1,
        "fields_json": "{}",
    }
    started = journal.begin_dispatch(
        "s", "unknown", first.reservation_id, first.digest, "p", 1, native, ("strong-1",)
    )
    unknown = journal.finish(
        "s",
        "unknown",
        first.reservation_id,
        first.digest,
        "p",
        started.record.version,
        native,
        ("strong-1",),
        "UNKNOWN",
    )
    second = journal.reserve("s", "released", "p", {"symbol": "rb"})
    released = journal.release(
        "s", "released", second.reservation_id, second.digest, "p", "release-op", 1
    )
    with sqlite3.connect(path) as db:
        _drop_v4_for_v2(db)
        db.execute("UPDATE direct_journal_meta SET schema_version=2")
        before_keys = db.execute("SELECT * FROM direct_journal_strong_keys").fetchall()
        before_releases = db.execute("SELECT * FROM direct_journal_releases").fetchall()
        revision = db.execute("SELECT revision FROM direct_journal_meta").fetchone()[0]
    upgraded = GatewayDirectCommandJournal.upgrade_v2(
        path,
        "acct",
        generation=journal.generation,
        guard=guard,
        expected_journal_id=journal.journal_id,
        minimum_revision=revision,
        max_records=3,
    )
    assert upgraded.get("s", "unknown", "p") == unknown
    assert upgraded.get("s", "released", "p") == released
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT * FROM direct_journal_strong_keys").fetchall() == before_keys
        assert db.execute("SELECT * FROM direct_journal_releases").fetchall() == before_releases
        assert db.execute("SELECT revision FROM direct_journal_meta").fetchone()[0] == revision + 1
