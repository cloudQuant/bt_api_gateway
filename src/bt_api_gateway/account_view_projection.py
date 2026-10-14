"""Pure, bounded projections of provider account facts for authorized views.

Resource permission controls which provider facts a reader may see. It does
not assign strategy ownership, allocate positions, or imply virtual holdings.
Those facts remain with Execution or another qualified order-management
system.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Optional

from bt_api_base.account_protocol import (
    MAX_ACCOUNT_ROWS,
    AccountBalance,
    AccountObservation,
    AccountOpenOrder,
    AccountPosition,
    AccountResourceKey,
    AccountValuation,
)
from bt_api_base.service_protocol import MAX_REFERENCE_BYTES

ACCOUNT_VIEW_SCHEMA_ID = "sdk.account.view"
ACCOUNT_VIEW_SCHEMA_VERSION = 1
ACCOUNT_VIEW_DELTA_SCHEMA_ID = "sdk.account.view.delta"
ACCOUNT_VIEW_DELTA_SCHEMA_VERSION = 1
MAX_ACCOUNT_VIEW_POLICIES = 64
MAX_ACCOUNT_VIEW_RESOURCES = 64
ACCOUNT_VIEW_FACT_KINDS = frozenset({"balances", "positions", "open_orders"})

_POLICY_SCHEMA_ID = "gateway.account.view_policy"
_POLICY_SCHEMA_VERSION = 1
_PROJECTION_FIELDS = frozenset(
    {
        "schema_id",
        "schema_version",
        "view_scope",
        "consistency",
        "coverage",
        "fact_kinds",
    }
)


class AccountViewProjectionError(ValueError):
    """A policy or projection cannot be used as a complete authorized view."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class GatewayAccountViewPolicy:
    """Trusted server policy for one account view.

    The policy is supplied by trusted Gateway configuration, never by a wire
    request. ``resources`` limits resource-keyed facts. Provider valuation is
    an account-level fact and is included only by its separate explicit flag.
    A valuation-only policy may use an empty resource tuple.
    """

    view_scope: str
    resources: tuple[AccountResourceKey, ...]
    fact_kinds: frozenset[str]
    include_valuation: bool = False

    def __post_init__(self) -> None:
        _require_scope(self.view_scope)
        if type(self.resources) is not tuple or len(self.resources) > MAX_ACCOUNT_VIEW_RESOURCES:
            raise AccountViewProjectionError("INVALID_VIEW_RESOURCES")
        if any(type(resource) is not AccountResourceKey for resource in self.resources):
            raise AccountViewProjectionError("INVALID_VIEW_RESOURCES")
        if len(set(self.resources)) != len(self.resources):
            raise AccountViewProjectionError("DUPLICATE_VIEW_RESOURCE")
        if type(self.fact_kinds) is not frozenset or any(
            type(kind) is not str or kind not in ACCOUNT_VIEW_FACT_KINDS for kind in self.fact_kinds
        ):
            raise AccountViewProjectionError("INVALID_VIEW_FACT_KINDS")
        if type(self.include_valuation) is not bool:
            raise AccountViewProjectionError("INVALID_VIEW_VALUATION_PERMISSION")
        if self.fact_kinds and not self.resources:
            raise AccountViewProjectionError("VIEW_RESOURCES_REQUIRED")
        if not self.fact_kinds and not self.include_valuation:
            raise AccountViewProjectionError("EMPTY_VIEW_POLICY")

        canonical_resources = tuple(sorted(self.resources, key=_resource_sort_key))
        object.__setattr__(self, "resources", canonical_resources)

    def to_dict(self) -> dict[str, Any]:
        """Return the canonical JSON-ready policy representation."""
        return {
            "schema_id": _POLICY_SCHEMA_ID,
            "schema_version": _POLICY_SCHEMA_VERSION,
            "view_scope": self.view_scope,
            "resources": [resource.to_dict() for resource in self.resources],
            "fact_kinds": sorted(self.fact_kinds),
            "include_valuation": self.include_valuation,
        }

    @property
    def canonical_json(self) -> str:
        """Return stable compact JSON for policy binding and audit digests."""
        return _canonical_json(self.to_dict())

    @property
    def digest(self) -> str:
        """Return a stable lowercase SHA-256 digest of the complete policy."""
        return hashlib.sha256(self.canonical_json.encode("utf-8")).hexdigest()


def validate_policy_set(
    view_policies: tuple[GatewayAccountViewPolicy, ...],
    *,
    max_views: int = MAX_ACCOUNT_VIEW_POLICIES,
) -> tuple[GatewayAccountViewPolicy, ...]:
    """Validate and canonically order trusted view policies by ``view_scope``."""
    if type(max_views) is not int or not 1 <= max_views <= MAX_ACCOUNT_VIEW_POLICIES:
        raise AccountViewProjectionError("INVALID_VIEW_LIMIT")
    if type(view_policies) is not tuple or len(view_policies) > max_views:
        raise AccountViewProjectionError("INVALID_VIEW_POLICY_SET")
    if any(type(policy) is not GatewayAccountViewPolicy for policy in view_policies):
        raise AccountViewProjectionError("INVALID_VIEW_POLICY_SET")
    scopes = [policy.view_scope for policy in view_policies]
    if len(set(scopes)) != len(scopes):
        raise AccountViewProjectionError("DUPLICATE_VIEW_SCOPE")
    return tuple(sorted(view_policies, key=lambda policy: policy.view_scope))


def project_account_view(
    observation: AccountObservation, policy: GatewayAccountViewPolicy
) -> Mapping[str, Any]:
    """Build one complete immutable JSON view from validated provider facts.

    A missing or incomplete requested fact set is rejected rather than treated
    as empty. The source account identity, observation identity, observation
    times, consistency metadata, and any producer cursor are omitted. Row
    observation timestamps remain part of the visible facts.
    """
    if type(observation) is not AccountObservation:
        raise AccountViewProjectionError("OBSERVATION_TYPE_INVALID")
    if type(policy) is not GatewayAccountViewPolicy:
        raise AccountViewProjectionError("VIEW_POLICY_INVALID")

    covered_resources = set(observation.coverage)
    if not set(policy.resources).issubset(covered_resources):
        raise AccountViewProjectionError("VIEW_RESOURCE_NOT_COVERED")
    if "balances" in policy.fact_kinds and not observation.balances_complete:
        raise AccountViewProjectionError("VIEW_BALANCES_INCOMPLETE")
    if "positions" in policy.fact_kinds and not observation.positions_complete:
        raise AccountViewProjectionError("VIEW_POSITIONS_INCOMPLETE")
    if "open_orders" in policy.fact_kinds and (
        observation.open_orders is None or not observation.open_orders_complete
    ):
        raise AccountViewProjectionError("VIEW_OPEN_ORDERS_INCOMPLETE")
    if policy.include_valuation and observation.valuation is None:
        raise AccountViewProjectionError("VIEW_VALUATION_INCOMPLETE")

    allowed_resources = set(policy.resources)
    result: dict[str, Any] = {
        "schema_id": ACCOUNT_VIEW_SCHEMA_ID,
        "schema_version": ACCOUNT_VIEW_SCHEMA_VERSION,
        "view_scope": policy.view_scope,
        "consistency": "multi_query",
        "coverage": tuple(resource.to_dict() for resource in policy.resources),
        "fact_kinds": tuple(sorted(policy.fact_kinds)),
    }
    if "balances" in policy.fact_kinds:
        rows = [row.to_dict() for row in observation.balances if row.resource in allowed_resources]
        result["balances"] = _ordered_rows("balances", rows)
    if "positions" in policy.fact_kinds:
        rows = [row.to_dict() for row in observation.positions if row.resource in allowed_resources]
        result["positions"] = _ordered_rows("positions", rows)
    if "open_orders" in policy.fact_kinds:
        rows = [
            row.to_dict()
            for row in observation.open_orders or ()
            if row.resource in allowed_resources
        ]
        result["open_orders"] = _ordered_rows("open_orders", rows)
    if policy.include_valuation:
        # The completeness check above makes the authorized valuation present.
        result["valuation"] = observation.valuation.to_dict()
    return _freeze_json(result)


def view_delta(
    previous: Mapping[str, Any], current: Mapping[str, Any]
) -> Optional[Mapping[str, Any]]:  # noqa: UP045 -- Python 3.9 support.
    """Return a complete, immutable visible change or ``None`` if unchanged.

    Changes contain row upserts and identity-only deletes. Observation-level
    metadata and facts excluded by the view policy cannot create events.
    Policy changes require a replacement snapshot and cannot be represented as
    a delta across different view bindings.
    """
    previous_view = _parse_projection(previous)
    current_view = _parse_projection(current)
    if previous_view["view_scope"] != current_view["view_scope"]:
        raise AccountViewProjectionError("VIEW_SCOPE_MISMATCH")
    if previous_view["policy_digest"] != current_view["policy_digest"]:
        raise AccountViewProjectionError("VIEW_POLICY_MISMATCH")
    for field in ("coverage", "fact_kinds", "valuation_authorized"):
        if previous_view[field] != current_view[field]:
            raise AccountViewProjectionError("VIEW_SHAPE_MISMATCH")

    changes: dict[str, Any] = {}
    for kind in current_view["fact_kinds"]:
        before = previous_view["rows"][kind]
        after = current_view["rows"][kind]
        upserts = [
            after[key]["row"]
            for key in sorted(after)
            if key not in before or before[key] != after[key]
        ]
        deletes = [before[key]["identity"] for key in sorted(before) if key not in after]
        changes[kind] = {"upsert": tuple(upserts), "delete": tuple(deletes)}

    valuation_changed = previous_view["valuation"] != current_view["valuation"]
    has_row_change = any(change["upsert"] or change["delete"] for change in changes.values())
    if not has_row_change and not valuation_changed:
        return None

    result: dict[str, Any] = {
        "schema_id": ACCOUNT_VIEW_DELTA_SCHEMA_ID,
        "schema_version": ACCOUNT_VIEW_DELTA_SCHEMA_VERSION,
        "view_scope": current_view["view_scope"],
        "changes": changes,
    }
    if current_view["valuation_authorized"] and valuation_changed:
        result["valuation"] = {"set": current_view["valuation"]}
    return _freeze_json(result)


def _parse_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")
    if value.get("schema_id") != ACCOUNT_VIEW_SCHEMA_ID:
        raise AccountViewProjectionError("VIEW_SCHEMA_INVALID")
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise AccountViewProjectionError("VIEW_SCHEMA_INVALID")
    if value.get("consistency") != "multi_query":
        raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")
    view_scope = value.get("view_scope")
    try:
        _require_scope(view_scope)
    except AccountViewProjectionError:
        raise AccountViewProjectionError("VIEW_PROJECTION_INVALID") from None
    coverage_value = value.get("coverage")
    if (
        not isinstance(coverage_value, (list, tuple))
        or len(coverage_value) > MAX_ACCOUNT_VIEW_RESOURCES
    ):
        raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")
    resources: list[AccountResourceKey] = []
    for item in coverage_value:
        if not isinstance(item, Mapping):
            raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")
        try:
            resources.append(AccountResourceKey.from_dict(item))
        except (KeyError, TypeError, ValueError):
            raise AccountViewProjectionError("VIEW_PROJECTION_INVALID") from None
    if len(set(resources)) != len(resources) or tuple(resources) != tuple(
        sorted(resources, key=_resource_sort_key)
    ):
        raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")

    kinds_value = value.get("fact_kinds")
    if not isinstance(kinds_value, (list, tuple)):
        raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")
    fact_kinds = tuple(kinds_value)
    if (
        any(type(kind) is not str or kind not in ACCOUNT_VIEW_FACT_KINDS for kind in fact_kinds)
        or len(set(fact_kinds)) != len(fact_kinds)
        or fact_kinds != tuple(sorted(fact_kinds))
    ):
        raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")
    valuation_authorized = "valuation" in value
    if not fact_kinds and not valuation_authorized:
        raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")
    expected_fields = set(_PROJECTION_FIELDS) | set(fact_kinds)
    if valuation_authorized:
        expected_fields.add("valuation")
    if set(value) != expected_fields:
        raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")

    resource_set = set(resources)
    rows_by_kind: dict[str, dict[str, dict[str, Any]]] = {}
    for kind in fact_kinds:
        rows_value = value[kind]
        if not isinstance(rows_value, (list, tuple)) or len(rows_value) > MAX_ACCOUNT_ROWS:
            raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")
        rows: dict[str, dict[str, Any]] = {}
        ordered_keys: list[str] = []
        for raw_row in rows_value:
            if not isinstance(raw_row, Mapping):
                raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")
            row = _parse_row(kind, raw_row)
            resource = AccountResourceKey.from_dict(row["resource"])
            if resource not in resource_set:
                raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")
            identity = _row_identity(kind, row)
            key = _canonical_json(identity)
            if key in rows:
                raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")
            rows[key] = {"identity": identity, "row": row}
            ordered_keys.append(key)
        if ordered_keys != sorted(ordered_keys):
            raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")
        rows_by_kind[kind] = rows

    valuation: Any = None
    if valuation_authorized:
        valuation_value = value["valuation"]
        if not isinstance(valuation_value, Mapping):
            raise AccountViewProjectionError("VIEW_PROJECTION_INVALID")
        try:
            valuation = _freeze_json(AccountValuation.from_dict(valuation_value).to_dict())
        except (KeyError, TypeError, ValueError):
            raise AccountViewProjectionError("VIEW_PROJECTION_INVALID") from None

    policy_digest = _projection_policy_digest(
        view_scope,
        resources,
        fact_kinds,
        valuation_authorized,
    )

    return {
        "view_scope": view_scope,
        "policy_digest": policy_digest,
        "coverage": tuple(resources),
        "fact_kinds": fact_kinds,
        "valuation_authorized": valuation_authorized,
        "valuation": valuation,
        "rows": rows_by_kind,
    }


def _parse_row(kind: str, value: Mapping[str, Any]) -> dict[str, Any]:
    row_type = {
        "balances": AccountBalance,
        "positions": AccountPosition,
        "open_orders": AccountOpenOrder,
    }[kind]
    try:
        row = row_type.from_dict(value).to_dict()
        if kind in {"positions", "open_orders"}:
            resource = AccountResourceKey.from_dict(row["resource"])
            instrument = row["instrument"]
            if instrument["product_type"] != resource.product_type:
                raise ValueError("instrument product type does not match resource")
        return _freeze_json(row)
    except (KeyError, TypeError, ValueError):
        raise AccountViewProjectionError("VIEW_PROJECTION_INVALID") from None


def _ordered_rows(kind: str, rows: list[dict[str, Any]]) -> tuple[Mapping[str, Any], ...]:
    identities = [(_canonical_json(_row_identity(kind, row)), row) for row in rows]
    identities.sort(key=lambda item: item[0])
    return tuple(_freeze_json(row) for _, row in identities)


def _row_identity(kind: str, row: Mapping[str, Any]) -> dict[str, Any]:
    if kind == "balances":
        return {"resource": row["resource"], "currency": row["currency"]}
    if kind == "positions":
        return {
            "resource": row["resource"],
            "instrument": row["instrument"],
            "side": row["side"],
        }
    return {
        "resource": row["resource"],
        "instrument": row["instrument"],
        "order_id": row["order_id"],
    }


def _resource_sort_key(resource: AccountResourceKey) -> tuple[str, str]:
    return resource.product_type, resource.margin_pool


def _projection_policy_digest(
    view_scope: str,
    resources: list[AccountResourceKey],
    fact_kinds: tuple[str, ...],
    include_valuation: bool,
) -> str:
    policy = {
        "schema_id": _POLICY_SCHEMA_ID,
        "schema_version": _POLICY_SCHEMA_VERSION,
        "view_scope": view_scope,
        "resources": [resource.to_dict() for resource in resources],
        "fact_kinds": list(fact_kinds),
        "include_valuation": include_valuation,
    }
    return hashlib.sha256(_canonical_json(policy).encode("utf-8")).hexdigest()


def _require_scope(value: object) -> None:
    if type(value) is not str:
        raise AccountViewProjectionError("INVALID_VIEW_SCOPE")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise AccountViewProjectionError("INVALID_VIEW_SCOPE") from None
    if (
        not encoded
        or len(encoded) > MAX_REFERENCE_BYTES
        or value != value.strip()
        or any(ord(char) < 32 or 0x7F <= ord(char) <= 0x9F for char in value)
    ):
        raise AccountViewProjectionError("INVALID_VIEW_SCOPE")


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(nested) for key, nested in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(nested) for nested in value)
    return value


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _json_value(nested) for key, nested in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(nested) for nested in value]
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


__all__ = [
    "ACCOUNT_VIEW_DELTA_SCHEMA_ID",
    "ACCOUNT_VIEW_DELTA_SCHEMA_VERSION",
    "ACCOUNT_VIEW_FACT_KINDS",
    "ACCOUNT_VIEW_SCHEMA_ID",
    "ACCOUNT_VIEW_SCHEMA_VERSION",
    "MAX_ACCOUNT_VIEW_POLICIES",
    "MAX_ACCOUNT_VIEW_RESOURCES",
    "AccountViewProjectionError",
    "GatewayAccountViewPolicy",
    "project_account_view",
    "validate_policy_set",
    "view_delta",
]
