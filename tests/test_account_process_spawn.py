"""Synthetic spawn-only smoke node; invoke only when a Root slot is approved."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from bt_api_base.account_protocol import (
    AccountBalance,
    AccountKey,
    AccountObservation,
    AccountResourceKey,
)

from bt_api_gateway.account_process import (
    GatewayAccountSessionProcessBinding,
    GatewayAccountSessionProcessProvider,
    GatewayAccountSessionProfileUnavailableError,
    serve_account_session_child,
)

_PROFILE_REF = "synthetic.gateway.read-only.v1"
_GENERATION = "0123456789abcdef0123456789abcdef"
_KEY = AccountKey(
    provider="synthetic",
    venue="localhost",
    environment="unit",
    account_id="synthetic-account",
)


class _SyntheticProvider:
    native_owner_created = False
    native_connection_generation = None

    def connect(self, *, account_key: AccountKey, generation: str, timeout: float) -> None:
        if account_key != _KEY or generation != _GENERATION or timeout <= 0:
            raise RuntimeError("synthetic bind mismatch")

    def read_account(self, *, generation: str, timeout: float) -> AccountObservation:
        if generation != _GENERATION or timeout <= 0:
            raise RuntimeError("synthetic generation mismatch")
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        resource = AccountResourceKey(product_type="spot", margin_pool="cross")
        balance = AccountBalance(
            resource=resource,
            currency="USD",
            total="125",
            available="125",
            locked="0",
            observed_at_utc=now,
        )
        return AccountObservation(
            account_key=_KEY,
            observation_id="synthetic-spawn-observation",
            coverage=(resource,),
            balances=(balance,),
            positions=(),
            valuation=None,
            started_at_utc=now,
            completed_at_utc=now,
            consistency="provider_atomic",
            balances_complete=True,
            positions_complete=True,
        )

    def close(self) -> bool:
        return True


def _synthetic_profile_factory(profile_ref: str) -> GatewayAccountSessionProcessBinding:
    if profile_ref != _PROFILE_REF:
        raise GatewayAccountSessionProfileUnavailableError()
    return GatewayAccountSessionProcessBinding(_KEY, _SyntheticProvider())


def _synthetic_child_entry(connection: Any) -> None:
    serve_account_session_child(
        connection,
        provider_factory=_synthetic_profile_factory,
    )


def test_synthetic_spawn_account_process_roundtrip() -> None:
    """Exercises one local synthetic child; no venue SDK or credentials."""

    provider = GatewayAccountSessionProcessProvider(
        account_key=_KEY,
        profile_ref=_PROFILE_REF,
        child_target=_synthetic_child_entry,
        close_timeout_seconds=2.0,
    )
    primary: BaseException | None = None
    try:
        assert provider.connect(account_key=_KEY, generation=_GENERATION, timeout=5.0) is None
        observation = provider.read_account(generation=_GENERATION, timeout=2.0)
        assert type(observation) is AccountObservation
        assert observation.account_key == _KEY
        assert observation.observation_id == "synthetic-spawn-observation"
        assert observation.balances[0].total == "125"
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if not provider.close():
            if primary is None:
                pytest.fail("synthetic child did not provide bounded normal-close evidence")
            primary.add_note("synthetic account child cleanup remained uncertain")
