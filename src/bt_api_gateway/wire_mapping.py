"""Strict gateway-command JSON mapping for an external transport envelope.

The gateway package deliberately does not depend on a transport implementation.
This module supplies the one canonical command projection that a transport may
place inside its own versioned envelope.  In particular, identity and scope
come from :class:`GatewayCommand`; no client principal or authorization claim
has a place in this projection.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from typing import Any

from .router import GatewayCommand, GatewayCommandKind

GATEWAY_COMMAND_WIRE_SCHEMA = "bt_api_gateway.command.v1"


class GatewayWireMappingError(ValueError):
    """A transport payload cannot be mapped to one exact gateway command."""


def gateway_command_to_wire_payload(command: GatewayCommand) -> dict[str, Any]:
    """Return the only permitted transport projection of ``command``.

    The explicit fingerprint makes any mutation visible before the command
    reaches the durable router.  ``payload_json`` is parsed back to ordinary
    JSON values so an immutable mapping proxy never leaks into a serializer.
    """

    if not isinstance(command, GatewayCommand):
        raise TypeError("GatewayCommand is required")
    _validate_command_text_fields(
        {
            "account_scope": command.account_scope,
            "command_id": command.command_id,
            "receipt_digest": command.receipt_digest,
            "strategy_scope": command.strategy_scope,
        }
    )
    return {
        "command": {
            "account_scope": command.account_scope,
            "command_id": command.command_id,
            "expires_at": command.expires_at,
            "issued_at": command.issued_at,
            "kind": command.kind.value,
            "manual_resume_authorized": command.manual_resume_authorized,
            "payload": json.loads(command.payload_json),
            "receipt_digest": command.receipt_digest,
            "strategy_scope": command.strategy_scope,
        },
        "command_fingerprint": command.fingerprint,
        "schema": GATEWAY_COMMAND_WIRE_SCHEMA,
    }


def gateway_command_from_wire_payload(value: Mapping[str, Any]) -> GatewayCommand:
    """Parse a strict transport projection without accepting extra fields.

    A caller still has to authenticate the peer and pass the resulting
    server-derived principal to :class:`GatewayCommandRouter`.  This decoder
    intentionally has no principal parameter or principal-shaped field.
    """

    if not isinstance(value, Mapping):
        raise GatewayWireMappingError("gateway wire payload must be an object")
    _require_exact_fields(value, {"command", "command_fingerprint", "schema"}, "envelope")
    if value["schema"] != GATEWAY_COMMAND_WIRE_SCHEMA:
        raise GatewayWireMappingError("unsupported gateway command schema")
    raw_command = value["command"]
    if not isinstance(raw_command, Mapping):
        raise GatewayWireMappingError("gateway command must be an object")
    _require_exact_fields(
        raw_command,
        {
            "account_scope",
            "command_id",
            "expires_at",
            "issued_at",
            "kind",
            "manual_resume_authorized",
            "payload",
            "receipt_digest",
            "strategy_scope",
        },
        "command",
    )
    fingerprint = value["command_fingerprint"]
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(character not in "0123456789abcdef" for character in fingerprint)
    ):
        raise GatewayWireMappingError("invalid gateway command fingerprint")
    _validate_number(raw_command["issued_at"], "issued_at")
    _validate_number(raw_command["expires_at"], "expires_at")
    if not isinstance(raw_command["manual_resume_authorized"], bool):
        raise GatewayWireMappingError("manual_resume_authorized must be a boolean")
    if not isinstance(raw_command["payload"], Mapping):
        raise GatewayWireMappingError("gateway command payload must be an object")
    _validate_command_text_fields(raw_command)
    try:
        command = GatewayCommand(
            command_id=raw_command["command_id"],
            account_scope=raw_command["account_scope"],
            strategy_scope=raw_command["strategy_scope"],
            kind=GatewayCommandKind(raw_command["kind"]),
            payload=raw_command["payload"],
            receipt_digest=raw_command["receipt_digest"],
            issued_at=float(raw_command["issued_at"]),
            expires_at=float(raw_command["expires_at"]),
            manual_resume_authorized=raw_command["manual_resume_authorized"],
        )
    except (TypeError, ValueError) as error:
        raise GatewayWireMappingError("invalid gateway command") from error
    if command.fingerprint != fingerprint:
        raise GatewayWireMappingError("gateway command fingerprint mismatch")
    return command


def _require_exact_fields(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    supplied = set(value)
    if supplied != expected:
        unexpected = ",".join(sorted(str(item) for item in supplied - expected))
        missing = ",".join(sorted(expected - supplied))
        detail = "unknown=" + unexpected if unexpected else "missing=" + missing
        raise GatewayWireMappingError("invalid " + name + " fields: " + detail)


def _validate_number(value: Any, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GatewayWireMappingError(name + " must be a finite number")
    if not math.isfinite(float(value)):
        raise GatewayWireMappingError(name + " must be a finite number")


def _validate_command_text_fields(value: Mapping[str, Any]) -> None:
    for name in ("account_scope", "command_id", "receipt_digest", "strategy_scope"):
        field = value[name]
        if not isinstance(field, str) or not field.strip() or field != field.strip():
            raise GatewayWireMappingError(name + " must be a non-empty trimmed string")
