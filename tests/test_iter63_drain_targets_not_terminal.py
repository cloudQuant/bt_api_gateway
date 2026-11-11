"""A DRAIN freezes only orders that may still be working (I63-E131).

Every order ever sent used to become a target of every DRAIN in its scope. On SimNow on
2026-11-11 four DRAINs added 203 target rows of which 202 were orders that had ended long
before. The table has a fixed capacity, so on an account with months of history an emergency
DRAIN, a lease-expiry DRAIN or a cancel-only start would be refused for lack of room.
"""
from dataclasses import replace

import pytest
from bt_api_base.direct_write_protocol import DirectExecutionEventKind, DirectOrderStatus
from test_iter63_direct_execution_journal import command, fact

from bt_api_gateway.direct_command_journal import (
    DirectCommandJournalError,
    GatewayDirectCommandJournal,
)
from bt_api_gateway.direct_control import GatewayDirectControl
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from bt_api_gateway.session_guard import LocalAccountSessionGuard


@pytest.fixture
def setup(tmp_path):
    directory = tmp_path / "guards"
    directory.mkdir()
    guard = LocalAccountSessionGuard(directory, "acct", "owner")
    journal = GatewayDirectCommandJournal.create(tmp_path / "db", "acct", generation=guard.acquire(),
                                                 max_records=12, clock=lambda: 100.0)
    control = journal.enable_controls(guard)
    yield journal, control, GatewayDirectExecutionLedger(journal, guard), guard, tmp_path / "db"
    guard.release()


def _order(journal, key, *, strategy="s1", status="SENT"):
    row, _ = command(journal, strategy=strategy, key=key, anchor=key + "-anchor", status=status)
    return row


def _returned(ledger, key, status, *, filled="0", ref=None):
    result = ledger.ingest(replace(
        fact(kind=DirectExecutionEventKind.ORDER, status=status, keys=(key + "-anchor", "venue-" + key),
             binding=(key + "-anchor",), venue="venue-" + key, ref=ref or f"{key}-{status.value}-{filled}"),
        order_quantity="2", filled_quantity=filled))
    assert result.disposition == "ATTRIBUTED", result


def _targets(control, cause):
    return {row["request_key"]: row["state"] for row in control.targets(cause)}


def test_orders_the_journal_saw_end_are_not_frozen(setup):
    journal, control, ledger, _, _ = setup
    for key in ("cancelled", "filled", "rejected", "working", "part-filled", "no-return"):
        _order(journal, key)
    _order(journal, "dispatching", status=None)
    _order(journal, "unknown", status="UNKNOWN")
    _returned(ledger, "cancelled", DirectOrderStatus.ACCEPTED)
    _returned(ledger, "cancelled", DirectOrderStatus.CANCELLED, filled="1")
    _returned(ledger, "filled", DirectOrderStatus.FILLED, filled="2")
    _returned(ledger, "rejected", DirectOrderStatus.REJECTED)
    _returned(ledger, "working", DirectOrderStatus.ACCEPTED)
    _returned(ledger, "part-filled", DirectOrderStatus.PARTIALLY_FILLED, filled="1")
    control.apply("drain", "DRAIN", scope_kind="strategy", scope_value="s1", origin="operator")
    # Only what may still be at the venue is a target; the three ended orders are not.
    assert _targets(control, "drain") == dict.fromkeys(
        ("working", "part-filled", "no-return", "dispatching", "unknown"), "PENDING")
    # A target that ends later is tracked as before.
    _returned(ledger, "working", DirectOrderStatus.CANCELLED)
    assert control.reconcile_targets("drain") is True
    assert _targets(control, "drain")["working"] == "OBSERVED_TERMINAL"


def test_an_end_the_journal_cannot_trust_keeps_the_order_as_a_target(setup):
    journal, control, ledger, _, _ = setup
    for key in ("filled-short", "rejected-with-fill", "ended-then-working"):
        _order(journal, key)
    _returned(ledger, "filled-short", DirectOrderStatus.FILLED, filled="1")            # says filled, 1 of 2
    _returned(ledger, "rejected-with-fill", DirectOrderStatus.REJECTED, filled="1")    # says rejected, yet 1 filled
    _returned(ledger, "ended-then-working", DirectOrderStatus.CANCELLED)
    _returned(ledger, "ended-then-working", DirectOrderStatus.ACCEPTED, ref="later")   # the latest return is not an end
    control.apply("drain", "DRAIN", scope_kind="account", origin="operator")
    assert _targets(control, "drain") == {
        "filled-short": "PENDING", "rejected-with-fill": "PENDING", "ended-then-working": "PENDING"}


def test_repeated_drains_do_not_fill_the_table_with_history(setup):
    journal, control, ledger, guard, path = setup
    for index in range(5):                       # five orders that all ended; capacity of the table is 12
        _order(journal, f"old-{index}")
        _returned(ledger, f"old-{index}", DirectOrderStatus.CANCELLED)
    _order(journal, "working")
    _returned(ledger, "working", DirectOrderStatus.ACCEPTED)
    for round_ in range(6):                      # 6 x 6 = 36 rows before this change: the third was refused
        cause = f"drain-{round_}"
        control.apply(cause, "DRAIN", scope_kind="account", origin="operator")
        assert _targets(control, cause) == {"working": "PENDING"}
        control.resume(cause, expected_version=1, operation_id="resume-" + cause)
    with journal._transaction() as db:
        assert db.execute("SELECT count(*) FROM direct_control_targets").fetchone()[0] == 6
    # The stored state is consistent for a restarted owner.
    reopened = GatewayDirectCommandJournal(path, "acct", generation=journal.generation,
                                           expected_journal_id=journal.journal_id, minimum_revision=0,
                                           max_records=12, clock=lambda: 100.0, controls_enabled=True)
    GatewayDirectControl(reopened, guard)


def test_a_drain_that_does_not_fit_is_still_refused(setup):
    journal, control, _, _, _ = setup
    for index in range(7):                       # seven orders without any return: all are targets
        _order(journal, f"open-{index}")
    control.apply("first", "DRAIN", scope_kind="account", origin="operator")
    with pytest.raises(DirectCommandJournalError, match="^CONTROL_CAPACITY_EXCEEDED$"):
        control.apply("second", "DRAIN", scope_kind="account", origin="operator")
