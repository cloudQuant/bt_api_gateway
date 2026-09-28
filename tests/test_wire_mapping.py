"""Strict transport projection tests for durable gateway commands."""

from __future__ import annotations

import copy

import pytest

from bt_api_gateway import (
    GATEWAY_COMMAND_WIRE_SCHEMA,
    GatewayCommand,
    GatewayCommandKind,
    GatewayWireMappingError,
    gateway_command_from_wire_payload,
    gateway_command_to_wire_payload,
)


def _command() -> GatewayCommand:
    return GatewayCommand(
        command_id="iteration41.command.1",
        account_scope="account:fixture",
        strategy_scope="scope:fixture",
        kind=GatewayCommandKind.SUBMIT,
        payload={"intent_id": "intent.1", "nested": {"quantity": "1"}},
        receipt_digest="a" * 64,
        issued_at=1_700_000_000.0,
        expires_at=1_700_000_030.0,
    )


def test_gateway_wire_projection_round_trips_exact_command_without_principal_claim() -> None:
    command = _command()

    payload = gateway_command_to_wire_payload(command)
    restored = gateway_command_from_wire_payload(payload)

    assert payload["schema"] == GATEWAY_COMMAND_WIRE_SCHEMA
    assert "principal" not in payload
    assert restored == command
    assert restored.fingerprint == command.fingerprint


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.update({"principal": "client-supplied"}),
        lambda payload: payload["command"].update({"principal_id": "client-supplied"}),
        lambda payload: payload["command"].update({"command_id": 41}),
        lambda payload: payload["command"].update({"issued_at": True}),
        lambda payload: payload.update({"command_fingerprint": "b" * 64}),
    ),
)
def test_gateway_wire_projection_rejects_extra_or_mutated_identity(mutate) -> None:
    payload = copy.deepcopy(gateway_command_to_wire_payload(_command()))
    mutate(payload)

    with pytest.raises(GatewayWireMappingError):
        gateway_command_from_wire_payload(payload)
