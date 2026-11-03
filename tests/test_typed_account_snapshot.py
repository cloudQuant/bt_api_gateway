"""Gateway typed account snapshot retains journal and source boundaries."""
from dataclasses import replace
import importlib.util
from pathlib import Path

import pytest

from bt_api_gateway.service_component import GatewayReadService, GatewayServiceError
from bt_api_gateway.event_journal import GatewayEventJournalError
from bt_api_base.wire_codec_v1 import account_observation_from_typed_map

_spec = importlib.util.spec_from_file_location(
    "gateway_component_fixture", Path(__file__).with_name("test_service_component.py")
)
_fixtures = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixtures)
_principal = _fixtures._principal
_scope = _fixtures._scope
_state_observation = _fixtures._state_observation
_state_service = _fixtures._state_service


def test_typed_snapshot_requires_canonical_source_and_existing_acl(tmp_path):
    observation = _state_observation('one')
    worker, service = _state_service(tmp_path, (observation,))
    try:
        worker.start()
        scope = _scope(strategy_ref=None)
        generic = service.handle('account.snapshot', principal_ref='principal-a', scope=scope, arguments={'limit': 1})
        typed = service.handle('account.snapshot.typed', principal_ref='principal-a', scope=scope, arguments={'limit': 1})
        assert generic['snapshot']['cursor'] == typed['snapshot']['cursor'] == 1
        assert account_observation_from_typed_map(typed['snapshot']['payload']['observation']).to_dict() == observation.to_dict()
        with pytest.raises(GatewayServiceError):
            service.handle('account.snapshot.typed', principal_ref='principal-a', scope=_scope(strategy_ref='strategy-a'), arguments={})
        service._principals = {'principal-a': _principal('principal-a', strategies=frozenset({'other'}))}
        with pytest.raises(GatewayEventJournalError):
            service.handle('account.snapshot.typed', principal_ref='principal-a', scope=scope, arguments={})
    finally:
        worker.close()


def test_typed_rejects_noncanonical_without_generic_fallback(tmp_path):
    original = _state_observation('one')
    noncanonical = replace(original, balances=(replace(original.balances[0], total='100.00'),))
    worker, service = _state_service(tmp_path, (noncanonical,))
    try:
        worker.start()
        scope = _scope(strategy_ref=None)
        generic = service.handle('account.snapshot', principal_ref='principal-a', scope=scope, arguments={})
        assert generic['snapshot']['payload']['observation']['balances'][0]['total'] == '100.00'
        with pytest.raises(GatewayServiceError, match='ACCOUNT_TYPED_OBSERVATION_INVALID'):
            service.handle('account.snapshot.typed', principal_ref='principal-a', scope=scope, arguments={})
    finally:
        worker.close()
