"""Account fact labels come from the real persisted Execution parent command."""
from contextlib import contextmanager

from bt_api_base.direct_write_protocol import DirectExecutionEventKind, DirectOrderStatus
from bt_api_gateway.direct_execution_journal import GatewayDirectExecutionLedger
from test_iter63_direct_execution_journal import fact
from test_iter63_direct_parent_authority import owner, spec, kwargs, reserve, delegated, fence  # noqa: F401


def test_account_fact_uses_real_execution_parent_and_child(owner):  # noqa: F811
    journal, guard, authority, _ = owner
    authority.register_parent(spec(), **kwargs())
    journal.enable_account_facts_financial(guard)
    command = reserve(journal, authority, "child-a", "1")
    _, permit = delegated(authority, "child-a", "1", operation="direct.dispatch")
    native = {"exchange_name": "CTP", "client_order_id": "child-a", "session_generation": 1, "fields_json": "{}"}
    journal.begin_dispatch("strategy", "child-a", command.reservation_id, command.digest, "exec", command.version,
        native, ("exec-key",), delegation_permit=permit, delegation_fence=fence)
    ledger = GatewayDirectExecutionLedger(journal, guard)
    order = fact(kind=DirectExecutionEventKind.ORDER, keys=("exec-key", "venue-a"), binding=("exec-key",),
                 day="20261109", status=DirectOrderStatus.ACCEPTED)
    assert ledger.ingest(order).disposition == "ATTRIBUTED"
    trade = fact(keys=("venue-a",), binding=(), day="20261109")
    assert ledger.ingest(trade).disposition == "ATTRIBUTED"
    @contextmanager
    def admission():
        yield lambda: None
    page = ledger.read_account_facts(principal_id="observer", consumer_ref="risk", admission_fence=admission,
                                     result_fits=lambda _: True)
    assert len(page.events) == 2
    for event in page.events:
        assert (event.reservation_id, event.origin, event.parent_ref, event.child_id) == (
            command.reservation_id, "execution:exec", "parent", "child-a")
