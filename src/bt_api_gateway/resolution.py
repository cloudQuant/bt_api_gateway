"""Provider-query resolution contracts, with no default trusted verifier.

These types are local contracts, not authentication credentials. Only a
constructor-injected server capability may verify a proof reference. A typed
proof, source label or digest supplied by a client is never sufficient.
Resolution clears command uncertainty in the current writer epoch only; it
does not release order exposure, risk reservations, or the takeover fence.
"""

from __future__ import annotations

import hashlib
import json
import math
import secrets
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any, Optional

from .router import GatewayCommand, GatewayCommandKind, _canonical_json


def _text(value: str) -> None:
    if type(value) is not str or not value or value != value.strip() or len(value) > 512:
        raise ValueError("bounded non-empty trimmed text required")


def _number(value: float) -> None:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("finite timestamp required")


@dataclass(frozen=True)
class GatewayProviderBinding:
    """Provider correlation persisted before the provider call by its owner."""

    source_id: str
    provider_account_id: Optional[str]  # noqa: UP045 -- Python 3.9 support.
    provider_session_id: Optional[str]  # noqa: UP045 -- Python 3.9 support.
    request_reference: str
    operation: str
    target_order_id: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.
    authentication_profile: str = "provider_session"
    credential_binding_ref: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.
    local_capture_scope: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.
    internal_account_scope: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.
    request_reference_kind: str = "client_order_id"
    schema: str = "bt_api_gateway.provider_binding.v2"

    def __post_init__(self) -> None:
        for value in (self.source_id, self.request_reference):
            _text(value)
        if self.schema != "bt_api_gateway.provider_binding.v2":
            raise ValueError("unsupported provider binding schema")
        if self.request_reference_kind not in {
            "client_order_id",
            "provider_request_id",
            "local_action_id",
        }:
            raise ValueError("request reference semantics must be explicit")
        if self.authentication_profile in {"provider_session", "offline_fake"}:
            _text(self.provider_account_id)
            _text(self.provider_session_id)
            if any(
                value is not None
                for value in (
                    self.credential_binding_ref,
                    self.local_capture_scope,
                    self.internal_account_scope,
                )
            ):
                raise ValueError("session/fake profile cannot claim REST credential identity")
        elif self.authentication_profile == "signed_rest":
            if self.provider_session_id is not None:
                raise ValueError("signed REST has no provider session identity")
            if self.provider_account_id is not None:
                _text(self.provider_account_id)
            _text(self.credential_binding_ref)
            if (
                not self.credential_binding_ref.startswith("sha256:")
                or len(self.credential_binding_ref) != 71
                or any(c not in "0123456789abcdef" for c in self.credential_binding_ref[7:])
            ):
                raise ValueError(
                    "signed REST requires a key fingerprint reference, not a provider UID"
                )
            _text(self.local_capture_scope)
            _text(self.internal_account_scope)
            if self.request_reference_kind == "local_action_id":
                raise ValueError(
                    "signed REST must correlate a provider-observable request reference"
                )
        else:
            raise ValueError("unsupported authentication profile")
        if self.operation not in {"submit", "cancel"}:
            raise ValueError("only submit and cancel have query resolution")
        if self.operation == "cancel":
            _text(self.target_order_id)
        elif self.target_order_id is not None:
            raise ValueError("submit has no cancellation target")

    @property
    def correlation_digest(self) -> str:
        """Duplicate-operation key; local aliases do not create a new identity."""
        value = asdict(self)
        for field in ("local_capture_scope", "internal_account_scope", "target_order_id"):
            value.pop(field)
        return hashlib.sha256(_canonical_json(value).encode()).hexdigest()

    @property
    def source_frame_digest(self) -> str:
        value = asdict(self)
        for field in (
            "request_reference",
            "request_reference_kind",
            "operation",
            "target_order_id",
        ):
            value.pop(field)
        return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


@dataclass(frozen=True)
class GatewayResolutionRequest:
    """Fresh challenge bound to an exact immutable durable source snapshot."""

    snapshot_json: str
    challenge: str
    requested_at: float
    proof_reference: str

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical_json(asdict(self)).encode()).hexdigest()


@dataclass(frozen=True)
class GatewayProviderQueryProof:
    """Immutable query attestation returned only by the configured verifier.

    A known working submit may clear uncertainty while retaining its exposure.
    A cancel needs both its terminal query result and a terminal target order.
    """

    request_digest: str
    proof_reference: str
    verifier_id: str
    source_id: str
    source_generation: int
    source_sequence: int
    query_digest_sha256: str
    binding: GatewayProviderBinding
    provider_order_id: str
    order_state: str
    cancel_state: Optional[str]  # noqa: UP045 -- Python 3.9 support.
    query_started_at: float
    observed_at: float
    verified_at: float
    expires_at: float

    def __post_init__(self) -> None:
        for value in (
            self.proof_reference,
            self.verifier_id,
            self.source_id,
            self.provider_order_id,
        ):
            _text(value)
        for value in (self.request_digest, self.query_digest_sha256):
            if (
                type(value) is not str
                or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)
            ):
                raise ValueError("SHA-256 digest required")
        if type(self.binding) is not GatewayProviderBinding:
            raise ValueError("exact provider binding required")
        for value in (self.source_generation, self.source_sequence):
            if type(value) is not int or value < 1:
                raise ValueError("positive source frame required")
        terminal = {"filled", "cancelled", "rejected", "expired"}
        if self.order_state not in terminal | {"working", "partially_filled"}:
            raise ValueError("unsupported queried order state")
        if self.binding.operation == "cancel":
            if self.order_state not in terminal or self.cancel_state not in {
                "cancelled",
                "rejected",
            }:
                raise ValueError("cancel requires terminal action and target-order query")
            if self.provider_order_id != self.binding.target_order_id:
                raise ValueError("cancel target differs from queried order")
        elif self.cancel_state is not None:
            raise ValueError("submit query cannot contain cancel state")
        for value in (self.query_started_at, self.observed_at, self.verified_at, self.expires_at):
            _number(value)
        if not self.query_started_at <= self.observed_at <= self.verified_at < self.expires_at:
            raise ValueError("invalid query evidence chronology")


class GatewayQueryVerifier(ABC):
    """Server-owned independent query source; no implementation is shipped."""

    @abstractmethod
    def verify_query(self, request: GatewayResolutionRequest) -> GatewayProviderQueryProof:
        """Read immutable source evidence without mutating the gateway journal."""


@dataclass(frozen=True)
class GatewayResolutionCapability:
    """Explicit server injection, never a client payload or proof authority.

    Labels and Python object identity enforce configuration consistency only;
    deployments must independently trust the configured verifier's source.
    """

    verifier: GatewayQueryVerifier
    verifier_id: str
    source_id: str
    source_generation: int
    max_evidence_age: float = 10.0

    def __post_init__(self) -> None:
        if not isinstance(self.verifier, GatewayQueryVerifier):
            raise TypeError("a server-owned GatewayQueryVerifier is required")
        _text(self.verifier_id)
        _text(self.source_id)
        if type(self.source_generation) is not int or self.source_generation < 1:
            raise ValueError("positive configured source generation required")
        _number(self.max_evidence_age)
        if not 0 < self.max_evidence_age <= 300:
            raise ValueError("evidence age must be between zero and 300 seconds")


@dataclass(frozen=True)
class GatewayActionResolution:
    """Separate durable query conclusion; original action/router history remains."""

    account_scope: str
    action_id: str
    proof_reference: str
    source_id: str
    verifier_id: str
    provider_order_id: str
    order_state: str
    cancel_state: Optional[str]  # noqa: UP045 -- Python 3.9 support.
    resolved_at: float
    duplicate: bool


class GatewayResolutionMixin:
    """Public resolution methods used by the local writer authority."""

    def _resolution_error(self, code: str, message: str) -> Exception:
        from .writer_authority import GatewayWriterAuthorityError

        return GatewayWriterAuthorityError(code, message)

    def _capability_snapshot(self) -> tuple:
        capability = self._resolution_capability
        if type(capability) is not GatewayResolutionCapability:
            raise self._resolution_error(
                "RESOLUTION_VERIFIER_UNAVAILABLE", "no configured verifier"
            )
        # Capture every policy field and the bound implementation identity.
        # Frozen dataclasses alone do not prevent deliberate object mutation.
        capability.__post_init__()
        method = capability.verifier.verify_query
        return (
            capability,
            capability.verifier,
            getattr(method, "__func__", method),
            capability.verifier_id,
            capability.source_id,
            capability.source_generation,
            capability.max_evidence_age,
        )

    def _same_capability(self, snapshot: tuple) -> None:
        current = self._capability_snapshot()
        if any(current[i] is not snapshot[i] for i in (0, 1, 2)) or current[3:] != snapshot[3:]:
            raise self._resolution_error("RESOLUTION_POLICY_CHANGED", "verifier policy changed")

    def _resolution_snapshot(self, connection: Any, lease: Any, action_id: str) -> dict:
        self._require_active_lease(connection, lease, self._now())
        row = connection.execute(
            "SELECT * FROM gateway_action_claims WHERE account_scope=? AND action_id=?",
            (lease.account_scope, action_id),
        ).fetchone()
        if row is None or row["status"] not in {"returned_unverified", "unknown"}:
            raise self._resolution_error(
                "ACTION_NOT_RESOLVABLE", "action is not an unresolved result"
            )
        if (row["owner_id"], row["lease_id"], row["epoch"]) != (
            lease.owner_id,
            lease.lease_id,
            lease.epoch,
        ):
            raise self._resolution_error(
                "RESOLUTION_OWNER_MISMATCH", "original current writer required"
            )
        command_row = connection.execute(
            "SELECT * FROM gateway_commands WHERE command_id=?", (action_id,)
        ).fetchone()
        if command_row is None:
            raise self._resolution_error(
                "RESOLUTION_COMMAND_MISSING", "exact router command required"
            )
        raw = dict(command_row)
        command = GatewayCommand(
            command_id=raw["command_id"],
            account_scope=raw["account_scope"],
            strategy_scope=raw["strategy_scope"],
            kind=GatewayCommandKind(raw["kind"]),
            payload=json.loads(raw["payload_json"]),
            receipt_digest=raw["receipt_digest"],
            issued_at=raw["issued_at"],
            expires_at=raw["expires_at"],
            manual_resume_authorized=bool(raw["manual_resume_authorized"]),
        )
        if (
            command.fingerprint != raw["fingerprint"]
            or (
                command.account_scope,
                command.strategy_scope,
                command.fingerprint,
                raw["principal_id"],
                command.expires_at,
            )
            != (
                row["account_scope"],
                row["strategy_scope"],
                row["command_fingerprint"],
                row["principal_id"],
                row["expires_at"],
            )
            or raw["status"] != row["status"]
        ):
            raise self._resolution_error(
                "RESOLUTION_COMMAND_MISMATCH", "claim and command disagree"
            )
        binding_row = connection.execute(
            "SELECT binding_json FROM gateway_provider_bindings WHERE account_scope=? AND action_id=?",
            (lease.account_scope, action_id),
        ).fetchone()
        if binding_row is None:
            raise self._resolution_error(
                "RESOLUTION_BINDING_MISSING", "pre-dispatch provider binding required"
            )
        binding = GatewayProviderBinding(**json.loads(binding_row[0]))
        if binding.operation != command.kind.value:
            raise self._resolution_error(
                "RESOLUTION_OPERATION_MISMATCH", "provider operation differs"
            )
        if (
            binding.authentication_profile == "signed_rest"
            and binding.internal_account_scope != command.account_scope
        ):
            raise self._resolution_error(
                "RESOLUTION_ACCOUNT_MISMATCH", "REST local account binding differs"
            )
        return {"claim": dict(row), "command": raw, "binding": asdict(binding)}

    def bind_provider_action(self, lease: Any, claim: Any, binding: GatewayProviderBinding) -> None:
        """Owner records correlation after begin-dispatch and before provider I/O.

        This is not a provider call or permission to write. Only the router's
        dispatched claim with its active original lease can obtain a binding.
        """
        from .writer_authority import _row_matches_claim

        policy = self._capability_snapshot()
        if type(binding) is not GatewayProviderBinding or binding.source_id != policy[4]:
            raise self._resolution_error(
                "PROVIDER_BINDING_INVALID", "configured provider binding required"
            )
        binding.__post_init__()
        if (
            binding.authentication_profile == "signed_rest"
            and binding.internal_account_scope != claim.account_scope
        ):
            raise self._resolution_error(
                "PROVIDER_BINDING_ACCOUNT_MISMATCH", "REST local account binding differs"
            )
        serialized = _canonical_json(asdict(binding))
        with self._transaction() as connection:
            self._same_capability(policy)
            self._require_active_lease(connection, lease, self._now())
            row = connection.execute(
                "SELECT * FROM gateway_action_claims WHERE account_scope=? AND action_id=?",
                (claim.account_scope, claim.action_id),
            ).fetchone()
            if (
                row is None
                or row["status"] != "dispatching"
                or not _row_matches_claim(row, claim)
                or (claim.account_scope, claim.owner_id, claim.lease_id, claim.epoch)
                != (lease.account_scope, lease.owner_id, lease.lease_id, lease.epoch)
            ):
                raise self._resolution_error(
                    "PROVIDER_BINDING_CLAIM_MISMATCH", "exact active dispatch required"
                )
            raw = connection.execute(
                "SELECT * FROM gateway_commands WHERE command_id=?", (claim.action_id,)
            ).fetchone()
            if (
                raw is None
                or raw["kind"] != binding.operation
                or raw["status"] != "dispatching"
                or raw["fingerprint"] != claim.command_fingerprint
            ):
                raise self._resolution_error(
                    "PROVIDER_BINDING_COMMAND_MISMATCH", "exact operation required"
                )
            existing = connection.execute(
                "SELECT binding_json FROM gateway_provider_bindings WHERE account_scope=? AND action_id=?",
                (claim.account_scope, claim.action_id),
            ).fetchone()
            if existing is not None:
                if existing[0] != serialized:
                    raise self._resolution_error(
                        "PROVIDER_BINDING_CONFLICT", "binding is immutable"
                    )
                return
            connection.execute(
                "INSERT INTO gateway_provider_bindings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    claim.account_scope,
                    claim.action_id,
                    binding.source_id,
                    binding.provider_account_id,
                    binding.provider_session_id,
                    binding.request_reference,
                    binding.operation,
                    serialized,
                    binding.correlation_digest,
                ),
            )

    def resolve_action(
        self, lease: Any, action_id: str, proof_reference: str
    ) -> GatewayActionResolution:
        """Resolve current-epoch uncertainty using the constructor-owned verifier.

        No proof object, verifier, callback or desired status is accepted here.
        The external verification runs with every SQLite connection closed.
        """
        _text(action_id)
        _text(proof_reference)
        policy = self._capability_snapshot()
        with self._connection() as connection:
            staged = self._resolution_snapshot(connection, lease, action_id)
            existing = connection.execute(
                "SELECT * FROM gateway_action_resolutions WHERE account_scope=? AND action_id=?",
                (lease.account_scope, action_id),
            ).fetchone()
        snapshot_json = _canonical_json(staged)
        if existing is not None:
            if (
                existing["proof_reference"] != proof_reference
                or existing["snapshot_json"] != snapshot_json
            ):
                raise self._resolution_error("RESOLUTION_CONFLICT", "resolution is immutable")
            self._same_capability(policy)
            return self._resolution_record(existing, True)
        request = GatewayResolutionRequest(
            snapshot_json, secrets.token_hex(32), self._now(), proof_reference
        )
        try:
            proof = policy[1].verify_query(request)
        except Exception as exc:
            raise self._resolution_error(
                "RESOLUTION_VERIFICATION_FAILED", "query verification failed"
            ) from exc
        self._same_capability(policy)
        if type(proof) is not GatewayProviderQueryProof:
            raise self._resolution_error(
                "RESOLUTION_PROOF_INVALID", "typed configured-verifier proof required"
            )
        # Snapshot once after callback; no mutable evidence fields are retained.
        proof_json = _canonical_json(asdict(proof))
        proof = GatewayProviderQueryProof(
            **{
                **json.loads(proof_json),
                "binding": GatewayProviderBinding(**json.loads(proof_json)["binding"]),
            }
        )
        expected_binding = GatewayProviderBinding(**staged["binding"])
        if (
            proof.request_digest != request.digest
            or proof.proof_reference != proof_reference
            or (proof.verifier_id, proof.source_id, proof.source_generation)
            != (policy[3], policy[4], policy[5])
            or proof.binding != expected_binding
        ):
            raise self._resolution_error(
                "RESOLUTION_PROOF_MISMATCH", "query proof does not bind exact request"
            )
        with self._transaction() as connection:
            self._same_capability(policy)
            current = self._resolution_snapshot(connection, lease, action_id)
            if _canonical_json(current) != snapshot_json:
                raise self._resolution_error(
                    "RESOLUTION_SOURCE_CHANGED", "claim or command changed during verification"
                )
            now = self._now()
            dispatch_started = staged["claim"]["dispatch_started_at"]
            if (
                dispatch_started is None
                or proof.query_started_at < dispatch_started
                or proof.verified_at < request.requested_at
                or proof.verified_at > now
                or proof.expires_at <= now
                or now - proof.query_started_at > policy[6]
                or proof.expires_at - proof.verified_at > policy[6]
            ):
                raise self._resolution_error(
                    "RESOLUTION_PROOF_STALE", "query chronology or freshness invalid"
                )
            existing = connection.execute(
                "SELECT * FROM gateway_action_resolutions WHERE account_scope=? AND action_id=?",
                (lease.account_scope, action_id),
            ).fetchone()
            if existing is not None:
                if (
                    existing["proof_reference"] == proof_reference
                    and existing["snapshot_json"] == snapshot_json
                ):
                    return self._resolution_record(existing, True)
                raise self._resolution_error("RESOLUTION_CONFLICT", "another resolution committed")
            reused = connection.execute(
                "SELECT action_id FROM gateway_action_resolutions WHERE source_id=? AND proof_reference=?",
                (proof.source_id, proof_reference),
            ).fetchone()
            if reused is not None:
                raise self._resolution_error(
                    "RESOLUTION_PROOF_REUSED", "proof already belongs to an action"
                )
            frame = connection.execute(
                "SELECT source_generation, source_sequence FROM gateway_action_resolutions WHERE source_id=? AND source_frame_key=? ORDER BY source_generation DESC, source_sequence DESC LIMIT 1",
                (
                    proof.source_id,
                    proof.binding.source_frame_digest,
                ),
            ).fetchone()
            if frame is not None and (proof.source_generation, proof.source_sequence) <= (
                frame[0],
                frame[1],
            ):
                raise self._resolution_error(
                    "RESOLUTION_FRAME_STALE", "query source frame did not advance"
                )
            self._same_capability(policy)
            now = self._now()
            self._require_active_lease(connection, lease, now)
            if proof.expires_at <= now or now - proof.query_started_at > policy[6]:
                raise self._resolution_error(
                    "RESOLUTION_PROOF_STALE", "query expired before append"
                )
            connection.execute(
                "INSERT INTO gateway_action_resolutions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    lease.account_scope,
                    action_id,
                    proof_reference,
                    proof.source_id,
                    proof.verifier_id,
                    proof.source_generation,
                    proof.source_sequence,
                    proof.binding.provider_account_id,
                    proof.binding.provider_session_id,
                    snapshot_json,
                    proof_json,
                    proof.provider_order_id,
                    proof.order_state,
                    proof.cancel_state,
                    now,
                    proof.binding.source_frame_digest,
                ),
            )
            row = connection.execute(
                "SELECT * FROM gateway_action_resolutions WHERE account_scope=? AND action_id=?",
                (lease.account_scope, action_id),
            ).fetchone()
            return self._resolution_record(row, False)

    @staticmethod
    def _resolution_record(row: Any, duplicate: bool) -> GatewayActionResolution:
        return GatewayActionResolution(
            row["account_scope"],
            row["action_id"],
            row["proof_reference"],
            row["source_id"],
            row["verifier_id"],
            row["provider_order_id"],
            row["order_state"],
            row["cancel_state"],
            row["resolved_at"],
            duplicate,
        )
