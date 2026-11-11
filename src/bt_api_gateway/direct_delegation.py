"""Trusted-owner checks for optional risk/execution delegation.

This module never authenticates a network peer.  The calling SDK service must
provide the Registry-issued context and a live Registry recheck; the returned
permit is only usable while its owner holds the original transaction fence.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
from types import MappingProxyType

from bt_api_base.gateway_delegation_protocol import GatewayDelegatedCommand
from bt_api_base.gateway_direct_protocol import canonical_gateway_payload, gateway_payload_digest
from bt_api_base.market_protocol import MarketInstrumentKey
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope


class GatewayDelegationDenied(ValueError):
    """Finite, value-free rejection; not proof that any prior command was unsent."""


_OPERATIONS = frozenset({"direct.reserve", "direct.dispatch", "direct.release",
                         "direct.command_status", "direct.cancel", "direct.cancel_status"})
_DELEGATION_DDL = {
    "direct_delegated_commands": "CREATE TABLE direct_delegated_commands (account TEXT NOT NULL, strategy TEXT NOT NULL, request_key TEXT NOT NULL, reservation_id TEXT NOT NULL UNIQUE, actor_principal TEXT NOT NULL, envelope_json TEXT NOT NULL, envelope_digest TEXT NOT NULL, PRIMARY KEY(account, strategy, request_key))",
}


@dataclass(frozen=True, slots=True)
class GatewayDelegateGrant:
    """Installed operator grant; declaration alone does not authenticate a caller."""

    identity: WireIdentity
    account_scope: str
    strategy_scope: str
    execution_domain_ref: str
    actor_kind: str
    revision: str
    instruments: frozenset[MarketInstrumentKey]
    operations: frozenset[str]

    def __post_init__(self) -> None:
        values = (self.account_scope, self.strategy_scope, self.execution_domain_ref, self.revision)
        try:
            valid_values = all(type(v) is str and v and v == v.strip() and v.isprintable()
                               and len(v.encode("utf-8", errors="strict")) <= 256 for v in values)
        except UnicodeError:
            valid_values = False
        if (type(self.identity) is not WireIdentity
                or self.identity.role not in (WireRole.SERVICE, WireRole.APPLICATION_CLIENT)
                or type(self.actor_kind) is not str or self.actor_kind not in ("risk", "execution")
                or not valid_values
                or type(self.instruments) is not frozenset or not self.instruments
                or any(type(v) is not MarketInstrumentKey for v in self.instruments)
                or type(self.operations) is not frozenset or not self.operations
                or not self.operations <= _OPERATIONS):
            raise GatewayDelegationDenied("INVALID_GRANT")


def _rejected():
    raise GatewayDelegationDenied("DELEGATION_DENIED")


def _claims_match(ctx, grant, cmd, operation) -> bool:
    """Compare the envelope with the authenticated context and the installed grant only."""
    identity, scope = ctx.identity, ctx.scope
    return not (type(grant) is not GatewayDelegateGrant or type(cmd) is not GatewayDelegatedCommand
                or type(identity) is not WireIdentity or type(scope) is not WireScope
                or identity != grant.identity or ctx.principal_ref != identity.principal_ref
                or type(ctx.registration_id) is not str or not ctx.registration_id
                or identity.principal_ref != cmd.actor_principal or identity.actor_ref != cmd.actor_ref
                or scope.execution_domain_ref != cmd.execution_domain_ref
                or scope.account_ref != cmd.account_scope or scope.strategy_ref != cmd.strategy_scope
                or scope.run_id != cmd.run_id or scope.account_refs or scope.manual_book_ref is not None
                or scope.portfolio_ref is not None or scope.group_id is not None or scope.leg_id is not None
                or grant.account_scope != cmd.account_scope or grant.strategy_scope != cmd.strategy_scope
                or grant.execution_domain_ref != cmd.execution_domain_ref
                or grant.actor_kind != cmd.actor_kind or grant.revision != cmd.grant_revision
                or cmd.instrument not in grant.instruments or operation not in grant.operations)


def _payload_matches(cmd, payload) -> bool:
    return (type(payload) is dict and payload.get("idempotency_key") == cmd.request_key
            and payload.get("symbol") == cmd.instrument.native_symbol
            and (payload.get("exchange_id") is None or payload["exchange_id"] == cmd.instrument.venue))


def delegated_request_matches(context, grant, command, operation: str, payload) -> bool:
    """Static check of one request against the authenticated context and installed grant.

    It reads no journal or Registry state and never authorizes anything: the
    owner still rechecks the Registry, the grant and the instrument under its
    transaction fence. ``False`` is a definite refusal of this request (another
    strategy or account, another actor, an instrument outside the grant, an
    operation the grant lacks, or a payload naming another instrument); it says
    nothing about any earlier command.
    """
    try:
        return _payload_matches(command, payload) and _claims_match(context, grant, command, operation)
    except Exception:
        return False


class GatewayDelegationPermit:
    """Recheckable owner-local binding; it does not replace Registry admission."""

    __slots__ = ("_context", "_command", "_operation", "_grant", "_payload_digest", "_payload_json",
                 "_registry_recheck", "_current_grant", "_instrument_recheck", "_parent_recheck")

    def __init__(self, context, command, operation, grant, payload_digest, payload_json, registry_recheck,
                 current_grant, instrument_recheck, parent_recheck):
        self._context, self._command, self._operation = context, command, operation
        self._grant, self._payload_digest = grant, payload_digest
        self._payload_json = payload_json
        self._registry_recheck, self._current_grant = registry_recheck, current_grant
        self._instrument_recheck, self._parent_recheck = instrument_recheck, parent_recheck

    @property
    def command(self):
        return self._command

    @property
    def operation(self):
        return self._operation

    def recheck(self, db=None) -> None:
        """Recheck in the owner transaction; parent authority must use its connection."""
        self._check(db, verify_parent=True)

    def _check(self, db, *, verify_parent):
        cmd, grant, ctx = self._command, self._grant, self._context
        try:
            if (not _claims_match(ctx, grant, cmd, self._operation)
                    or self._payload_digest != cmd.payload_digest
                    or self._current_grant() != grant or self._registry_recheck(ctx) is not True
                    or self._instrument_recheck(cmd.instrument) is not True):
                _rejected()
            if cmd.parent_ref is not None and self._operation in {"direct.reserve", "direct.dispatch"} and verify_parent:
                if (db is None or self._parent_recheck is None
                        or gateway_payload_digest(json.loads(self._payload_json)) != cmd.payload_digest
                        or self._parent_recheck(db, cmd, MappingProxyType(json.loads(self._payload_json))) is not True):
                    _rejected()
        except GatewayDelegationDenied:
            raise
        except Exception:
            _rejected()


def authorize_delegated_command(context, grant: GatewayDelegateGrant, command: GatewayDelegatedCommand,
                                operation: str, payload: dict, *, registry_recheck: Callable,
                                current_grant: Callable, instrument_recheck: Callable,
                                parent_recheck: Callable | None = None) -> GatewayDelegationPermit:
    """Validate request claims; owner must call permit.recheck under its commit fence.

    ``context`` and callbacks must come from trusted installed service code, not
    from a request body. Parent authority must be verified by the owner against
    the already-registered parent inside the same transaction as child admission.
    """
    try:
        if (type(grant) is not GatewayDelegateGrant or type(command) is not GatewayDelegatedCommand
                or operation not in _OPERATIONS or not _payload_matches(command, payload)
                or not all(callable(fn) for fn in (registry_recheck, current_grant, instrument_recheck))
                or (parent_recheck is not None and not callable(parent_recheck))):
            _rejected()
        digest = gateway_payload_digest(payload)
        permit = GatewayDelegationPermit(context, command, operation, grant, digest, canonical_gateway_payload(payload),
            registry_recheck, current_grant, instrument_recheck, parent_recheck)
        # A registered parent is checked only on the actual owner connection;
        # this initial field/Registry check is not parent authorization.
        permit._check(None, verify_parent=False)
        return permit
    except GatewayDelegationDenied:
        raise
    except Exception:
        _rejected()


def verify_delegated_integrity(db, account: str, max_records: int) -> None:
    """Revalidate stored declarations against their unchanged original command."""
    import hashlib
    import json

    from .direct_command_journal import DirectCommandJournalError, _json

    try:
        rows = db.execute(
            "SELECT d.*, c.principal, c.digest, c.payload_json, c.reservation_id AS command_reservation "
            "FROM direct_delegated_commands d LEFT JOIN direct_journal_commands c "
            "ON c.account=d.account AND c.strategy=d.strategy AND c.request_key=d.request_key"
        ).fetchall()
        if len(rows) > max_records:
            raise ValueError
        for row in rows:
            raw = json.loads(row["envelope_json"])
            command = GatewayDelegatedCommand.from_mapping(raw)
            payload = json.loads(row["payload_json"])
            if (row["account"] != account or command.canonical_json != row["envelope_json"]
                    or command.digest != row["envelope_digest"]
                    or hashlib.sha256(row["envelope_json"].encode("ascii")).hexdigest() != row["envelope_digest"]
                    or command.account_scope != account or command.strategy_scope != row["strategy"]
                    or command.request_key != row["request_key"]
                    or command.actor_principal != row["actor_principal"]
                    or row["principal"] != command.actor_principal
                    or row["reservation_id"] != row["command_reservation"]
                    or command.payload_digest != row["digest"]
                    or _json(payload) != row["payload_json"]
                    or gateway_payload_digest(payload) != command.payload_digest
                    or payload.get("idempotency_key") != command.request_key
                    or payload.get("symbol") != command.instrument.native_symbol
                    or (payload.get("exchange_id") is not None
                        and payload["exchange_id"] != command.instrument.venue)):
                raise ValueError
    except Exception:
        raise DirectCommandJournalError("INVALID_DATABASE") from None
