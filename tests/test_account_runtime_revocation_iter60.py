"""Iteration 60 G2: runtime revocation of a running account-read principal.

Local temp SQLite journal and fake reconciliation assembly (UNIT/FAKE).
"""

from __future__ import annotations

import pytest
from test_reconciliation_authority import assembly  # noqa: F401  (fixture)
from test_service_component import _scope, _service

from bt_api_gateway import GatewayEventJournal
from bt_api_gateway.reconciliation_authority import GatewayReconciliationInspectionError
from bt_api_gateway.service_component import GatewayServiceError


def test_revoked_principal_reads_are_refused_and_generation_increases(tmp_path):
    journal = GatewayEventJournal(tmp_path / "gateway.db", clock=lambda: 1_700_000_000.0)
    journal.append(
        "account:journal", "strategy:alpha", "event-1", "position_update", {"quantity": "1"}
    )
    service = _service(journal)
    read = lambda: service.handle(  # noqa: E731
        "account.read_after",
        principal_ref="principal-a",
        scope=_scope(),
        arguments={"cursor": 0, "limit": 1},
    )
    assert read()["latest_cursor"] == 1
    generation = service.authorization_generation
    assert service.revoke_principal("principal-a") == generation + 1
    with pytest.raises(GatewayServiceError) as info:
        read()
    assert info.value.code == "UNKNOWN_PRINCIPAL"
    with pytest.raises(GatewayServiceError):
        service.revoke_principal("principal-a")


def test_inspector_revocation_invalidates_issued_handles(assembly):  # noqa: F811
    candidate = assembly.inspector.inspect(assembly.principal)
    candidate.assert_current()
    assembly.inspector.revoke_principal(assembly.principal.principal_id)
    with pytest.raises(GatewayReconciliationInspectionError, match="INSPECTION_UNKNOWN"):
        candidate.assert_current()
    with pytest.raises(GatewayReconciliationInspectionError, match="PRINCIPAL_DENIED"):
        assembly.inspector.inspect(assembly.principal)
    with pytest.raises(GatewayReconciliationInspectionError, match="PRINCIPAL_DENIED"):
        assembly.inspector.revoke_principal(assembly.principal.principal_id)
