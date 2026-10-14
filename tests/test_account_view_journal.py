"""Atomic account-state projection and bounded journal view contracts."""

from __future__ import annotations

import sqlite3

import pytest
from bt_api_base.account_protocol import (
    AccountBalance,
    AccountKey,
    AccountObservation,
    AccountResourceKey,
)

from bt_api_gateway import (
    GatewayCommandKind,
    GatewayEventJournal,
    GatewayEventJournalError,
    GatewayPrincipal,
)
from bt_api_gateway.account_view_projection import GatewayAccountViewPolicy

ACCOUNT_SCOPE = "account:synthetic"
SOURCE_SCOPE = "state:canonical"
CAPTURED_AT = 1_800_000_000.0
TIMESTAMP = "2027-01-15T00:00:00Z"
SPOT = AccountResourceKey("spot", "cash")
LINEAR = AccountResourceKey("linear", "cross")
POLICIES = (
    GatewayAccountViewPolicy("view:linear", (LINEAR,), frozenset({"balances"})),
    GatewayAccountViewPolicy("view:spot", (SPOT,), frozenset({"balances"})),
)


def _observation(
    observation_id: str,
    *,
    spot_total: str | None = "10",
    linear_total: str | None = "20",
    account_id: str = "synthetic-account",
) -> AccountObservation:
    balances = tuple(
        balance
        for resource, currency, total in (
            (SPOT, "USD", spot_total),
            (LINEAR, "USDT", linear_total),
        )
        if total is not None
        for balance in (AccountBalance(resource, currency, total, total, "0", TIMESTAMP),)
    )
    return AccountObservation(
        account_key=AccountKey("synthetic", "local", "paper", account_id),
        observation_id=observation_id,
        coverage=(SPOT, LINEAR),
        balances=balances,
        positions=(),
        valuation=None,
        started_at_utc=TIMESTAMP,
        completed_at_utc=TIMESTAMP,
        consistency="multi_query",
        balances_complete=True,
        positions_complete=True,
    )


def _state_payload(observation: AccountObservation, *, generation: str = "a" * 32):
    return {
        "schema_id": "sdk.account.state",
        "schema_version": 1,
        "session_generation": generation,
        "observation": observation.to_dict(),
    }


def _replace(
    journal: GatewayEventJournal,
    observation: AccountObservation,
    expected_cursor: int,
    *,
    view_policies=POLICIES,
    snapshot_id: str | None = None,
):
    return journal.replace_state_snapshot(
        ACCOUNT_SCOPE,
        SOURCE_SCOPE,
        snapshot_id or "source:" + observation.observation_id,
        _state_payload(observation),
        expected_cursor=expected_cursor,
        captured_at=CAPTURED_AT + expected_cursor + 1,
        view_policies=view_policies,
    )


def _reader(scope: str) -> GatewayPrincipal:
    return GatewayPrincipal(
        principal_id="reader:" + scope,
        account_scopes=frozenset({ACCOUNT_SCOPE}),
        strategy_scopes=frozenset({scope}),
        allowed_kinds=frozenset({GatewayCommandKind.READ}),
    )


def test_two_views_filter_facts_and_hidden_updates_keep_contiguous_cursors(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "views.db")
    first = _replace(journal, _observation("obs-1"), 0)

    spot = journal.read_after(_reader("view:spot"), ACCOUNT_SCOPE, "view:spot")
    linear = journal.read_after(_reader("view:linear"), ACCOUNT_SCOPE, "view:linear")
    assert first.cursor == 1
    assert spot.snapshot.cursor == linear.snapshot.cursor == 1
    assert spot.snapshot.payload["balances"][0]["currency"] == "USD"
    assert linear.snapshot.payload["balances"][0]["currency"] == "USDT"
    assert "account_key" not in spot.snapshot.payload
    assert "policy_digest" not in spot.snapshot.payload
    assert "started_at_utc" not in spot.snapshot.payload
    assert "completed_at_utc" not in spot.snapshot.payload
    assert spot.snapshot.payload["consistency"] == "multi_query"
    spot_baseline_id = spot.snapshot.snapshot_id
    spot_baseline_captured_at = spot.snapshot.captured_at

    # Only the linear fact changes. The spot view follows the new private
    # source cursor without manufacturing a public event or sequence gap.
    _replace(journal, _observation("obs-2", linear_total="21"), 1)
    spot_after_hidden = journal.read_after(
        _reader("view:spot"), ACCOUNT_SCOPE, "view:spot", cursor=1
    )
    spot_after_hidden_baseline = journal.read_after(
        _reader("view:spot"), ACCOUNT_SCOPE, "view:spot", cursor=None
    )
    linear_after_change = journal.read_after(
        _reader("view:linear"), ACCOUNT_SCOPE, "view:linear", cursor=1
    )
    assert spot_after_hidden.events == ()
    assert spot_after_hidden.next_cursor == spot_after_hidden.latest_cursor == 1
    assert spot_after_hidden.snapshot is None
    assert [event.sequence for event in linear_after_change.events] == [2]
    linear_event_observed_at = linear_after_change.events[0].observed_at
    assert spot_after_hidden_baseline.snapshot.snapshot_id == spot_baseline_id
    assert spot_after_hidden_baseline.snapshot.captured_at == spot_baseline_captured_at
    assert journal.account_view_is_current(
        ACCOUNT_SCOPE, SOURCE_SCOPE, "view:spot", POLICIES[1].digest, 2, 1
    )
    assert journal.account_view_is_current(
        ACCOUNT_SCOPE, SOURCE_SCOPE, "view:linear", POLICIES[0].digest, 2, 2
    )

    _replace(journal, _observation("obs-3", spot_total="11", linear_total="21"), 2)
    spot_changed = journal.read_after(_reader("view:spot"), ACCOUNT_SCOPE, "view:spot", cursor=1)
    linear_unchanged = journal.read_after(
        _reader("view:linear"), ACCOUNT_SCOPE, "view:linear", cursor=2
    )
    linear_replayed = journal.read_after(
        _reader("view:linear"), ACCOUNT_SCOPE, "view:linear", cursor=1
    )
    assert [event.sequence for event in spot_changed.events] == [2]
    assert spot_changed.events[0].payload["changes"]["balances"]["upsert"][0]["total"] == "11"
    assert "started_at_utc" not in spot_changed.events[0].payload
    assert "completed_at_utc" not in spot_changed.events[0].payload
    assert linear_unchanged.events == ()
    assert linear_unchanged.next_cursor == linear_unchanged.latest_cursor == 2
    assert linear_replayed.events[0].observed_at == linear_event_observed_at
    assert journal.account_view_is_current(
        ACCOUNT_SCOPE, SOURCE_SCOPE, "view:spot", POLICIES[1].digest, 3, 2
    )


def test_complete_empty_projection_deletes_rows_and_incomplete_view_rolls_back(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "deletions.db")
    _replace(journal, _observation("obs-1"), 0)
    with pytest.raises(GatewayEventJournalError) as incomplete:
        journal.replace_state_snapshot(
            ACCOUNT_SCOPE,
            SOURCE_SCOPE,
            "source:incomplete",
            {
                **_state_payload(_observation("obs-incomplete")),
                "observation": {
                    **_observation("obs-incomplete").to_dict(),
                    "balances_complete": False,
                },
            },
            expected_cursor=1,
            captured_at=CAPTURED_AT + 2,
            view_policies=POLICIES,
        )
    assert incomplete.value.code == "VIEW_BALANCES_INCOMPLETE"
    assert journal.read_after(_reader("view:spot"), ACCOUNT_SCOPE, "view:spot").latest_cursor == 1

    _replace(journal, _observation("obs-2", spot_total=None), 1)
    deleted = journal.read_after(_reader("view:spot"), ACCOUNT_SCOPE, "view:spot", cursor=1).events[
        0
    ]
    assert deleted.sequence == 2
    assert deleted.payload["changes"]["balances"]["upsert"] == ()
    assert deleted.payload["changes"]["balances"]["delete"] == (
        {"resource": SPOT.to_dict(), "currency": "USD"},
    )


def test_all_views_and_canonical_snapshot_rollback_if_later_view_write_fails(tmp_path) -> None:
    database = tmp_path / "atomic.db"
    journal = GatewayEventJournal(database)
    _replace(journal, _observation("obs-1"), 0)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_second_view BEFORE INSERT ON gateway_events
            WHEN NEW.strategy_scope = 'view:spot'
            BEGIN SELECT RAISE(ABORT, 'synthetic view failure'); END
            """
        )

    with pytest.raises(sqlite3.IntegrityError):
        _replace(journal, _observation("obs-2", spot_total="11", linear_total="21"), 1)

    canonical = journal.read_after(_reader(SOURCE_SCOPE), ACCOUNT_SCOPE, SOURCE_SCOPE, cursor=1)
    linear = journal.read_after(_reader("view:linear"), ACCOUNT_SCOPE, "view:linear", cursor=1)
    spot = journal.read_after(_reader("view:spot"), ACCOUNT_SCOPE, "view:spot", cursor=1)
    assert canonical.latest_cursor == 1
    assert linear.latest_cursor == spot.latest_cursor == 1
    assert linear.events == spot.events == ()
    assert not journal.account_view_is_current(
        ACCOUNT_SCOPE, SOURCE_SCOPE, "view:spot", POLICIES[1].digest, 2, 1
    )

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER reject_second_view")
    _replace(journal, _observation("obs-2", spot_total="11", linear_total="21"), 1)
    assert journal.read_after(_reader(SOURCE_SCOPE), ACCOUNT_SCOPE, SOURCE_SCOPE).latest_cursor == 2


def test_view_compaction_is_bounded_and_restart_preserves_replay_and_currentness(tmp_path) -> None:
    database = tmp_path / "compact.db"
    journal = GatewayEventJournal(database)
    journal.MAX_ACCOUNT_VIEW_EVENTS = 2
    _replace(journal, _observation("obs-1"), 0, view_policies=(POLICIES[1],))
    for index in range(2, 6):
        _replace(
            journal,
            _observation(f"obs-{index}", spot_total=str(10 + index)),
            index - 1,
            view_policies=(POLICIES[1],),
        )

    restarted = GatewayEventJournal(database)
    restarted.validate_state_view_policies(ACCOUNT_SCOPE, SOURCE_SCOPE, (POLICIES[1],))
    replay = restarted.read_after(_reader("view:spot"), ACCOUNT_SCOPE, "view:spot", cursor=0)
    assert replay.snapshot is not None and replay.snapshot.cursor == 3
    assert [event.sequence for event in replay.events] == [4, 5]
    assert replay.next_cursor == replay.latest_cursor == 5
    assert replay.snapshot.payload["balances"][0]["total"] == "13"
    assert journal.account_view_is_current(
        ACCOUNT_SCOPE, SOURCE_SCOPE, "view:spot", POLICIES[1].digest, 5, 5
    )
    with sqlite3.connect(database) as connection:
        event_count = connection.execute(
            "SELECT COUNT(*) FROM gateway_events WHERE account_scope=? AND strategy_scope=?",
            (ACCOUNT_SCOPE, "view:spot"),
        ).fetchone()[0]
        dedupe_count = connection.execute(
            "SELECT COUNT(*) FROM gateway_event_dedupe WHERE account_scope=? AND strategy_scope=?",
            (ACCOUNT_SCOPE, "view:spot"),
        ).fetchone()[0]
        event_bytes = connection.execute(
            """
            SELECT COALESCE(SUM(length(CAST(payload_json AS BLOB))), 0)
            FROM gateway_events WHERE account_scope=? AND strategy_scope=?
            """,
            (ACCOUNT_SCOPE, "view:spot"),
        ).fetchone()[0]
    assert event_count == dedupe_count == 2
    assert event_bytes <= GatewayEventJournal.MAX_ACCOUNT_VIEW_EVENT_BYTES


def test_policy_binding_account_identity_and_manual_view_writes_are_enforced(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "binding.db")
    legacy = journal.replace_state_snapshot(
        ACCOUNT_SCOPE,
        "state:legacy",
        "legacy:1",
        {"cash": "1"},
        expected_cursor=0,
        captured_at=CAPTURED_AT,
    )
    assert legacy.cursor == 1
    with pytest.raises(GatewayEventJournalError) as too_late:
        journal.validate_state_view_policies(ACCOUNT_SCOPE, "state:legacy", POLICIES)
    assert too_late.value.code == "VIEW_POLICY_SET_REQUIRED"

    _replace(journal, _observation("obs-1"), 0)
    with pytest.raises(GatewayEventJournalError) as omitted:
        journal.validate_state_view_policies(ACCOUNT_SCOPE, SOURCE_SCOPE, ())
    assert omitted.value.code == "VIEW_POLICY_MISMATCH"
    changed_policy = (
        GatewayAccountViewPolicy("view:spot", (SPOT,), frozenset({"positions"})),
        GatewayAccountViewPolicy("view:linear", (LINEAR,), frozenset({"balances"})),
    )
    with pytest.raises(GatewayEventJournalError) as changed:
        journal.validate_state_view_policies(ACCOUNT_SCOPE, SOURCE_SCOPE, changed_policy)
    assert changed.value.code == "VIEW_POLICY_MISMATCH"

    with pytest.raises(GatewayEventJournalError) as append_denied:
        journal.append(ACCOUNT_SCOPE, "view:spot", "manual:1", "fact", {"value": 1})
    with pytest.raises(GatewayEventJournalError) as snapshot_denied:
        journal.capture_snapshot(
            ACCOUNT_SCOPE, "view:spot", "manual:1", 1, {"value": 1}, CAPTURED_AT
        )
    with pytest.raises(GatewayEventJournalError) as replace_denied:
        journal.replace_state_snapshot(
            ACCOUNT_SCOPE,
            "view:spot",
            "manual:1",
            {"value": 1},
            expected_cursor=1,
            captured_at=CAPTURED_AT,
        )
    assert append_denied.value.code == "MANAGED_VIEW_WRITE_DENIED"
    assert snapshot_denied.value.code == "MANAGED_VIEW_WRITE_DENIED"
    assert replace_denied.value.code == "MANAGED_VIEW_WRITE_DENIED"

    with pytest.raises(GatewayEventJournalError) as account_changed:
        _replace(journal, _observation("obs-2", account_id="other-account"), 1)
    assert account_changed.value.code == "VIEW_ACCOUNT_MISMATCH"
    source = journal.read_after(_reader(SOURCE_SCOPE), ACCOUNT_SCOPE, SOURCE_SCOPE)
    assert source.latest_cursor == 1


def test_view_schema_generation_and_sequence_overflow_are_rejected(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "validation.db")
    malformed = _state_payload(_observation("obs-1"), generation="not-a-generation")
    with pytest.raises(GatewayEventJournalError) as generation:
        journal.replace_state_snapshot(
            ACCOUNT_SCOPE,
            SOURCE_SCOPE,
            "source:bad-generation",
            malformed,
            expected_cursor=0,
            captured_at=CAPTURED_AT,
            view_policies=POLICIES,
        )
    assert generation.value.code == "VIEW_SOURCE_SCHEMA_INVALID"

    mismatch = _state_payload(_observation("obs-1"))
    mismatch["schema_version"] = 2
    with pytest.raises(GatewayEventJournalError) as version:
        journal.replace_state_snapshot(
            ACCOUNT_SCOPE,
            SOURCE_SCOPE,
            "source:bad-version",
            mismatch,
            expected_cursor=0,
            captured_at=CAPTURED_AT,
            view_policies=POLICIES,
        )
    assert version.value.code == "VIEW_SOURCE_SCHEMA_INVALID"

    with pytest.raises(GatewayEventJournalError) as overflow:
        journal.replace_state_snapshot(
            ACCOUNT_SCOPE,
            SOURCE_SCOPE,
            "source:overflow",
            _state_payload(_observation("obs-ok")),
            expected_cursor=GatewayEventJournal.MAX_SQLITE_INTEGER,
            captured_at=CAPTURED_AT,
            view_policies=POLICIES,
        )
    assert overflow.value.code == "SEQUENCE_OVERFLOW"


def test_restart_preflight_rejects_corrupt_view_baseline_and_missing_delta(tmp_path) -> None:
    baseline_database = tmp_path / "corrupt-baseline.db"
    baseline_journal = GatewayEventJournal(baseline_database)
    _replace(baseline_journal, _observation("obs-1"), 0, view_policies=(POLICIES[1],))
    with sqlite3.connect(baseline_database) as connection:
        connection.execute(
            """
            UPDATE gateway_event_snapshots SET fingerprint = ?
            WHERE account_scope = ? AND strategy_scope = ?
            """,
            ("0" * 64, ACCOUNT_SCOPE, "view:spot"),
        )
    with pytest.raises(GatewayEventJournalError) as baseline_read:
        baseline_journal.read_after(_reader("view:spot"), ACCOUNT_SCOPE, "view:spot")
    assert baseline_read.value.code == "VIEW_BINDING_CORRUPT"
    with pytest.raises(GatewayEventJournalError) as baseline_corrupt:
        GatewayEventJournal(baseline_database).validate_state_view_policies(
            ACCOUNT_SCOPE, SOURCE_SCOPE, (POLICIES[1],)
        )
    assert baseline_corrupt.value.code == "VIEW_BINDING_CORRUPT"

    sequence_database = tmp_path / "missing-delta.db"
    sequence_journal = GatewayEventJournal(sequence_database)
    _replace(sequence_journal, _observation("obs-1"), 0, view_policies=(POLICIES[1],))
    for index in range(2, 5):
        _replace(
            sequence_journal,
            _observation(f"obs-{index}", spot_total=str(10 + index)),
            index - 1,
            view_policies=(POLICIES[1],),
        )
    with sqlite3.connect(sequence_database) as connection:
        connection.execute(
            """
            DELETE FROM gateway_events
            WHERE account_scope = ? AND strategy_scope = ? AND sequence = 3
            """,
            (ACCOUNT_SCOPE, "view:spot"),
        )
    with pytest.raises(GatewayEventJournalError) as gap_read:
        sequence_journal.read_after(_reader("view:spot"), ACCOUNT_SCOPE, "view:spot")
    assert gap_read.value.code == "VIEW_BINDING_CORRUPT"
    with pytest.raises(GatewayEventJournalError) as gap:
        GatewayEventJournal(sequence_database).validate_state_view_policies(
            ACCOUNT_SCOPE, SOURCE_SCOPE, (POLICIES[1],)
        )
    assert gap.value.code == "VIEW_BINDING_CORRUPT"


def test_view_read_rejects_missing_private_membership_metadata(tmp_path) -> None:
    database = tmp_path / "missing-view-metadata.db"
    journal = GatewayEventJournal(database)
    _replace(journal, _observation("obs-1"), 0, view_policies=(POLICIES[1],))
    _replace(
        journal,
        _observation("obs-2", spot_total="11"),
        1,
        view_policies=(POLICIES[1],),
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            UPDATE gateway_event_snapshots SET payload_json = ?
            WHERE account_scope = ? AND strategy_scope = ?
            """,
            (
                '{"schema_id":"sdk.account.view","schema_version":99}',
                ACCOUNT_SCOPE,
                "view:spot",
            ),
        )
        connection.execute(
            "DELETE FROM gateway_account_views WHERE account_scope = ? AND view_scope = ?",
            (ACCOUNT_SCOPE, "view:spot"),
        )
        connection.execute(
            "DELETE FROM gateway_state_view_sources WHERE account_scope = ? AND source_scope = ?",
            (ACCOUNT_SCOPE, SOURCE_SCOPE),
        )

    with pytest.raises(GatewayEventJournalError) as missing_metadata:
        journal.read_after(_reader("view:spot"), ACCOUNT_SCOPE, "view:spot")
    assert missing_metadata.value.code == "VIEW_BINDING_CORRUPT"
    with pytest.raises(GatewayEventJournalError) as tracked_read:
        journal.read_for_consumer(
            _reader("view:spot"),
            ACCOUNT_SCOPE,
            "view:spot",
            "consumer:lost-view-metadata",
            cursor=None,
        )
    assert tracked_read.value.code == "VIEW_BINDING_CORRUPT"
    with sqlite3.connect(database) as connection:
        consumer_streams = connection.execute(
            """
            SELECT COUNT(*) FROM gateway_consumer_streams
            WHERE account_scope = ? AND strategy_scope = ?
            """,
            (ACCOUNT_SCOPE, "view:spot"),
        ).fetchone()[0]
        consumer_progress = connection.execute(
            """
            SELECT COUNT(*) FROM gateway_consumer_progress
            WHERE account_scope = ? AND strategy_scope = ?
            """,
            (ACCOUNT_SCOPE, "view:spot"),
        ).fetchone()[0]
    assert consumer_streams == consumer_progress == 0


def test_oversized_policy_set_preflight_does_not_bind_or_create_source_rows(tmp_path) -> None:
    journal = GatewayEventJournal(tmp_path / "policy-size.db")
    policies = tuple(
        GatewayAccountViewPolicy(
            f"view:{view_index:02d}",
            tuple(
                AccountResourceKey(
                    f"product-{view_index:02d}-{resource_index:02d}-" + "p" * 220,
                    f"margin-{view_index:02d}-{resource_index:02d}-" + "m" * 220,
                )
                for resource_index in range(64)
            ),
            frozenset({"balances"}),
        )
        for view_index in range(64)
    )
    with pytest.raises(GatewayEventJournalError) as too_large:
        journal.validate_state_view_policies(ACCOUNT_SCOPE, SOURCE_SCOPE, policies)
    assert too_large.value.code == "VIEW_POLICY_SET_TOO_LARGE"
    with sqlite3.connect(tmp_path / "policy-size.db") as connection:
        source_bindings = connection.execute(
            "SELECT COUNT(*) FROM gateway_state_view_sources"
        ).fetchone()[0]
        source_snapshots = connection.execute(
            "SELECT COUNT(*) FROM gateway_event_snapshots WHERE strategy_scope = ?",
            (SOURCE_SCOPE,),
        ).fetchone()[0]
    assert source_bindings == source_snapshots == 0
