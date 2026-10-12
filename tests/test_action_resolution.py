"""Fake query-source falsification tests; never provider acceptance."""

import json
import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import pytest

from bt_api_gateway import (
    GatewayAccountWriterAuthority,
    GatewayCommand,
    GatewayCommandKind,
    GatewayCommandRouter,
    GatewayDispatchError,
    GatewayPrincipal,
    GatewayProviderBinding,
    GatewayProviderQueryProof,
    GatewayQueryVerifier,
    GatewayResolutionCapability,
    GatewayRoutingError,
    GatewayWriterAuthorityError,
)


class Clock:
    def __init__(self):
        self.value = 1700000000.0

    def __call__(self):
        return self.value


class FakeSource(GatewayQueryVerifier):
    """Explicit fake issuer with injected faults, never a deployed authority."""

    def __init__(self, clock):
        self.clock = clock
        self.sequence = 0
        self.before = None
        self.transform = lambda proof: proof
        self.calls = 0
        self.binding_transform = lambda binding: binding

    def verify_query(self, request):
        self.calls += 1
        if self.before:
            self.before()
        snapshot = json.loads(request.snapshot_json)
        binding = GatewayProviderBinding(**snapshot["binding"])
        self.sequence += 1
        proof = GatewayProviderQueryProof(
            request.digest,
            request.proof_reference,
            "fake-verifier",
            "fake-source",
            1,
            self.sequence,
            "a" * 64,
            binding,
            binding.target_order_id or "provider-" + snapshot["claim"]["action_id"],
            "cancelled" if binding.operation == "cancel" else "working",
            "cancelled" if binding.operation == "cancel" else None,
            self.clock(),
            self.clock(),
            self.clock(),
            self.clock() + 5,
        )
        return self.transform(proof)


@pytest.fixture
def rig(tmp_path):
    clock = Clock()
    source = FakeSource(clock)
    policy = GatewayResolutionCapability(source, "fake-verifier", "fake-source", 1)
    database = tmp_path / "gateway.sqlite"
    authority = GatewayAccountWriterAuthority(database, clock=clock, resolution_capability=policy)
    lease = authority.acquire_writer("account", "owner", 30)
    principal = GatewayPrincipal(
        "principal",
        frozenset({"account"}),
        frozenset({"strategy"}),
        frozenset({GatewayCommandKind.SUBMIT, GatewayCommandKind.CANCEL}),
    )
    calls = []

    def executor(command):
        claim = authority.get_action("account", command.command_id).claim
        binding = GatewayProviderBinding(
            "fake-source",
            "provider-account",
            "session-1",
            command.command_id,
            command.kind.value,
            command.payload.get("target_order_id"),
            authentication_profile="offline_fake",
        )
        binding = source.binding_transform(binding)
        authority.bind_provider_action(lease, claim, binding)
        calls.append(command.command_id)
        return {"fake_return": True}

    router = GatewayCommandRouter(
        database, executor, clock=clock, admission=lambda p, c: True, writer_authority=authority
    )

    def dispatch(cid="first", kind=GatewayCommandKind.SUBMIT):
        payload = (
            {"target_order_id": "provider-first"}
            if kind is GatewayCommandKind.CANCEL
            else {"quantity": "1"}
        )
        command = GatewayCommand(
            cid, "account", "strategy", kind, payload, "fake-only", clock(), clock() + 10
        )
        return router.dispatch(principal, command)

    return SimpleNamespace(
        clock=clock,
        source=source,
        policy=policy,
        db=database,
        authority=authority,
        lease=lease,
        router=router,
        calls=calls,
        dispatch=dispatch,
    )


def test_known_working_submit_allows_cancel_without_rewriting_history(rig):
    rig.dispatch()
    resolved = rig.authority.resolve_action(rig.lease, "first", "proof-first")
    assert resolved.order_state == "working" and resolved.duplicate is False
    assert rig.authority.get_action("account", "first").status.value == "returned_unverified"
    assert rig.router.get("first").status.value == "returned_unverified"
    rig.dispatch("cancel", GatewayCommandKind.CANCEL)
    second = rig.authority.resolve_action(rig.lease, "cancel", "proof-cancel")
    assert second.order_state == second.cancel_state == "cancelled"
    assert rig.calls == ["first", "cancel"]


def test_no_verifier_or_arbitrary_callback_cannot_resolve(rig):
    rig.dispatch()
    unconfigured = GatewayAccountWriterAuthority(rig.db, clock=rig.clock)
    with pytest.raises(GatewayWriterAuthorityError, match="no configured verifier"):
        unconfigured.resolve_action(rig.lease, "first", "proof")
    with pytest.raises(TypeError):
        GatewayAccountWriterAuthority(rig.db, resolution_capability=lambda: True)
    with pytest.raises(TypeError):
        GatewayResolutionCapability(lambda request: True, "fake-verifier", "fake-source", 1)
    with pytest.raises(TypeError):
        rig.authority.resolve_action(rig.lease, "first", "proof", verifier=rig.source)


def test_exact_resolution_idempotent_and_other_reference_conflicts(rig):
    rig.dispatch()
    rig.authority.resolve_action(rig.lease, "first", "proof")
    assert rig.authority.resolve_action(rig.lease, "first", "proof").duplicate
    assert rig.source.calls == 1
    with pytest.raises(GatewayWriterAuthorityError) as error:
        rig.authority.resolve_action(rig.lease, "first", "other-proof")
    assert error.value.code == "RESOLUTION_CONFLICT"


def test_proof_reference_cannot_resolve_a_different_claim(rig):
    rig.dispatch()
    rig.authority.resolve_action(rig.lease, "first", "same-proof")
    rig.dispatch("second")
    with pytest.raises(GatewayWriterAuthorityError) as error:
        rig.authority.resolve_action(rig.lease, "second", "same-proof")
    assert error.value.code == "RESOLUTION_PROOF_REUSED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_digest", "b" * 64),
        ("source_id", "wrong-source"),
        ("verifier_id", "wrong-verifier"),
        ("source_generation", 2),
        ("proof_reference", "wrong-reference"),
    ],
)
def test_mismatched_query_proof_rejected(rig, field, value):
    rig.dispatch()
    rig.source.transform = lambda proof: replace(proof, **{field: value})
    with pytest.raises(GatewayWriterAuthorityError) as error:
        rig.authority.resolve_action(rig.lease, "first", "proof")
    assert error.value.code == "RESOLUTION_PROOF_MISMATCH"


@pytest.mark.parametrize(
    "field,value",
    [
        ("provider_account_id", "wrong-account"),
        ("provider_session_id", "wrong-session"),
        ("request_reference", "wrong-action"),
    ],
)
def test_provider_correlation_mismatch_rejected(rig, field, value):
    rig.dispatch()
    rig.source.transform = lambda proof: replace(
        proof, binding=replace(proof.binding, **{field: value})
    )
    with pytest.raises(GatewayWriterAuthorityError) as error:
        rig.authority.resolve_action(rig.lease, "first", "proof")
    assert error.value.code == "RESOLUTION_PROOF_MISMATCH"


@pytest.mark.parametrize("fault", ["future", "expired", "before_dispatch", "too_long"])
def test_evidence_chronology_rejected(rig, fault):
    rig.dispatch()

    def transform(proof):
        if fault == "future":
            return replace(proof, verified_at=rig.clock() + 1)
        if fault == "expired":
            rig.clock.value += 6
            return proof
        if fault == "before_dispatch":
            return replace(proof, query_started_at=rig.clock() - 1)
        return replace(proof, expires_at=rig.clock() + 100)

    rig.source.transform = transform
    with pytest.raises(GatewayWriterAuthorityError) as error:
        rig.authority.resolve_action(rig.lease, "first", "proof")
    assert error.value.code == "RESOLUTION_PROOF_STALE"


def test_non_monotonic_source_frame_rejected(rig):
    rig.dispatch()
    rig.authority.resolve_action(rig.lease, "first", "proof-1")
    rig.dispatch("second")
    rig.source.sequence = 0
    with pytest.raises(GatewayWriterAuthorityError) as error:
        rig.authority.resolve_action(rig.lease, "second", "proof-2")
    assert error.value.code == "RESOLUTION_FRAME_STALE"


@pytest.mark.parametrize(
    "fault", ["replace_capability", "mutate_generation", "replace_verifier", "replace_method"]
)
def test_verifier_policy_rechecked_after_external_verification(rig, fault):
    rig.dispatch()

    def change():
        if fault == "replace_capability":
            rig.authority._resolution_capability = replace(rig.policy)
        elif fault == "mutate_generation":
            object.__setattr__(rig.policy, "source_generation", 2)
        elif fault == "replace_verifier":
            object.__setattr__(rig.policy, "verifier", FakeSource(rig.clock))
        else:
            rig.source.verify_query = lambda request: None

    rig.source.before = change
    with pytest.raises(GatewayWriterAuthorityError) as error:
        rig.authority.resolve_action(rig.lease, "first", "proof")
    assert error.value.code == "RESOLUTION_POLICY_CHANGED"


def test_verifier_runs_outside_transaction_and_changed_command_fails(rig):
    rig.dispatch()

    def mutate():
        with sqlite3.connect(rig.db, timeout=0) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE gateway_commands SET receipt_digest='changed' WHERE command_id='first'"
            )

    rig.source.before = mutate
    with pytest.raises(GatewayWriterAuthorityError) as error:
        rig.authority.resolve_action(rig.lease, "first", "proof")
    assert error.value.code == "RESOLUTION_COMMAND_MISMATCH"


@pytest.mark.parametrize(
    "field,value", [("principal_id", "other"), ("owner_id", "other"), ("epoch", 2)]
)
def test_changed_claim_during_verification_fails(rig, field, value):
    rig.dispatch()

    def mutate():
        statements = {
            "principal_id": "UPDATE gateway_action_claims SET principal_id=? WHERE action_id='first'",
            "owner_id": "UPDATE gateway_action_claims SET owner_id=? WHERE action_id='first'",
            "epoch": "UPDATE gateway_action_claims SET epoch=? WHERE action_id='first'",
        }
        with sqlite3.connect(rig.db) as connection:
            connection.execute(statements[field], (value,))

    rig.source.before = mutate
    with pytest.raises(GatewayWriterAuthorityError):
        rig.authority.resolve_action(rig.lease, "first", "proof")


@pytest.mark.parametrize("fault", ["expire", "revoke"])
def test_current_lease_required_at_commit(rig, fault):
    rig.dispatch()

    def invalidate():
        if fault == "expire":
            rig.clock.value += 31
        else:
            rig.authority.revoke_writer(rig.lease)

    rig.source.before = invalidate
    with pytest.raises(GatewayWriterAuthorityError) as error:
        rig.authority.resolve_action(rig.lease, "first", "proof")
    assert error.value.code in {"WRITER_LEASE_EXPIRED", "WRITER_LEASE_REVOKED"}


def test_takeover_stays_closed_even_with_resolution(rig):
    rig.dispatch()
    rig.authority.resolve_action(rig.lease, "first", "proof")
    rig.clock.value += 31
    reopened = GatewayAccountWriterAuthority(
        rig.db, clock=rig.clock, resolution_capability=rig.policy
    )
    with pytest.raises(GatewayWriterAuthorityError) as error:
        reopened.acquire_writer("account", "new-owner", 30)
    assert error.value.code == "WRITER_ACTIONS_UNRESOLVED"


def test_cancel_requires_terminal_queried_action_and_target(rig):
    rig.dispatch()
    rig.authority.resolve_action(rig.lease, "first", "proof-1")
    rig.dispatch("cancel", GatewayCommandKind.CANCEL)
    rig.source.transform = lambda proof: replace(proof, order_state="working")
    with pytest.raises(GatewayWriterAuthorityError) as error:
        rig.authority.resolve_action(rig.lease, "cancel", "proof-2")
    assert error.value.code == "RESOLUTION_VERIFICATION_FAILED"


def test_resolution_append_only_and_transaction_abort_keeps_fence(rig):
    rig.dispatch()
    with sqlite3.connect(rig.db) as connection:
        connection.execute(
            "CREATE TRIGGER injected_abort BEFORE INSERT ON gateway_action_resolutions BEGIN SELECT RAISE(ABORT, 'fake interruption'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        rig.authority.resolve_action(rig.lease, "first", "proof")
    with pytest.raises(GatewayRoutingError):
        rig.dispatch("second")
    with sqlite3.connect(rig.db) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM gateway_action_resolutions").fetchone()[0] == 0
        )
        connection.execute("DROP TRIGGER injected_abort")
    rig.authority.resolve_action(rig.lease, "first", "proof")
    with sqlite3.connect(rig.db) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM gateway_action_resolutions")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE gateway_action_resolutions SET proof_reference='forged'")


def test_unknown_history_can_resolve_without_resubmission(rig):
    original = rig.router._executor

    def uncertain(command):
        original(command)
        raise TimeoutError("fake result lost after provider call")

    rig.router._executor = uncertain
    with pytest.raises(GatewayDispatchError):
        rig.dispatch()
    assert rig.authority.get_action("account", "first").status.value == "unknown"
    rig.authority.resolve_action(rig.lease, "first", "proof")
    assert rig.router.get("first").status.value == "unknown"
    assert rig.calls == ["first"]


def test_untyped_proof_and_forged_lease_cannot_resolve(rig):
    rig.dispatch()
    rig.source.transform = lambda proof: {"typed_looking_proof": proof}
    with pytest.raises(GatewayWriterAuthorityError) as error:
        rig.authority.resolve_action(rig.lease, "first", "proof")
    assert error.value.code == "RESOLUTION_PROOF_INVALID"
    with pytest.raises(GatewayWriterAuthorityError) as error:
        rig.authority.resolve_action(replace(rig.lease, _token="wrong"), "first", "proof")
    assert error.value.code == "WRITER_LEASE_STALE"


def test_source_generation_cannot_regress_across_resolutions(rig):
    rig.dispatch()
    rig.authority._resolution_capability = replace(rig.policy, source_generation=2)
    rig.source.transform = lambda proof: replace(proof, source_generation=2)
    rig.authority.resolve_action(rig.lease, "first", "proof-first")
    rig.dispatch("second")
    rig.authority._resolution_capability = rig.policy
    rig.source.transform = lambda proof: proof
    with pytest.raises(GatewayWriterAuthorityError) as error:
        rig.authority.resolve_action(rig.lease, "second", "proof-second")
    assert error.value.code == "RESOLUTION_FRAME_STALE"


@pytest.mark.parametrize("provider_uid", [None, "actual-query-uid"])
def test_signed_rest_nullable_identity_and_local_credential_binding(rig, provider_uid):
    rig.source.binding_transform = lambda binding: replace(
        binding,
        authentication_profile="signed_rest",
        provider_account_id=provider_uid,
        provider_session_id=None,
        credential_binding_ref="sha256:" + "c" * 64,
        local_capture_scope="local-capture-1",
        internal_account_scope="account",
        request_reference_kind="client_order_id",
    )
    rig.dispatch()
    result = rig.authority.resolve_action(rig.lease, "first", "proof")
    assert result.order_state == "working"


@pytest.mark.parametrize(
    "changes",
    [
        {"authentication_profile": "provider_session", "provider_account_id": None},
        {"authentication_profile": "provider_session", "provider_session_id": None},
        {
            "authentication_profile": "provider_session",
            "credential_binding_ref": "sha256:" + "c" * 64,
        },
        {"authentication_profile": "signed_rest"},
        {
            "authentication_profile": "signed_rest",
            "provider_account_id": None,
            "provider_session_id": None,
        },
        {"authentication_profile": "invented_profile"},
        {"request_reference_kind": "unspecified"},
    ],
)
def test_contradictory_or_incomplete_binding_profiles_rejected(changes):
    base = GatewayProviderBinding("source", "uid", "session", "request", "submit")
    with pytest.raises(ValueError):
        replace(base, **changes)


@pytest.mark.parametrize(
    "field,value",
    [
        ("provider_session_id", "invented-session"),
        ("credential_binding_ref", "uid-is-not-a-key-fingerprint"),
        ("internal_account_scope", None),
        ("local_capture_scope", None),
        ("request_reference_kind", "local_action_id"),
    ],
)
def test_signed_rest_profile_rejects_identity_substitution(field, value):
    base = GatewayProviderBinding(
        "source",
        None,
        None,
        "client-id",
        "submit",
        authentication_profile="signed_rest",
        credential_binding_ref="sha256:" + "c" * 64,
        local_capture_scope="local-capture",
        internal_account_scope="account",
    )
    with pytest.raises(ValueError):
        replace(base, **{field: value})


def test_signed_rest_local_account_must_match_claim(rig):
    rig.source.binding_transform = lambda binding: replace(
        binding,
        authentication_profile="signed_rest",
        provider_account_id=None,
        provider_session_id=None,
        credential_binding_ref="sha256:" + "c" * 64,
        local_capture_scope="local-capture",
        internal_account_scope="other-account",
    )
    with pytest.raises(GatewayDispatchError):
        rig.dispatch()
    assert rig.calls == []


def test_proof_cannot_switch_authentication_profile(rig):
    rig.dispatch()
    rig.source.transform = lambda proof: replace(
        proof, binding=replace(proof.binding, authentication_profile="provider_session")
    )
    with pytest.raises(GatewayWriterAuthorityError) as error:
        rig.authority.resolve_action(rig.lease, "first", "proof")
    assert error.value.code == "RESOLUTION_PROOF_MISMATCH"
