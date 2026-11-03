"""Synthetic owner/journal checks; never evidence of a real provider."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import pytest
from bt_api_base.position_bootstrap_protocol import (
    PositionStreamBinding,
    PositionStreamEvent,
    PositionStreamSnapshot,
)
from test_account_session_worker import Clocks, _observation, _position, _resource, _worker

from bt_api_gateway import GatewayCommandKind, GatewayPrincipal
from bt_api_gateway.account_position_snapshot import (
    GatewayFullPositionSnapshot,
    position_rows_sha256,
    resource_coverage_sha256,
)
from bt_api_gateway.event_journal import GatewayEventJournalError
from bt_api_gateway.reconciliation_authority import (
    GatewayReconciliationCandidate,
    GatewayReconciliationInspectionError,
    GatewayReconciliationInspector,
)

bootstrap_module = pytest.importorskip("bt_api_py.position_stream_bootstrap")


class FullProvider:
    def __init__(self, clocks, observation):
        self.clocks = clocks
        self.observation = observation
        self.current_source = None

    def connect(self, *, account_key, generation, timeout):
        return None

    def read_account(self, *, generation, timeout):
        observation = self.observation
        self.current_source = GatewayFullPositionSnapshot(
            observation=observation,
            account_key_id=observation.account_key.account_key_id,
            session_generation=generation,
            query_scope="ALL_ACCOUNT_POSITIONS",
            filters=(),
            permission_scope="ACCOUNT_FULL",
            permission_revision="fake-permission-1",
            pagination_exhausted=True,
            page_count=1,
            account_revision=1,
            source_schema_version="fake-schema-1",
            snapshot_version="fake-cut-1",
            positions_sha256=position_rows_sha256(observation),
            resource_coverage_sha256=resource_coverage_sha256(observation),
            valid_until_utc=self.clocks.timestamp(60),
        )
        return self.current_source

    def close(self):
        return None


class FakeVerifier:
    """Explicit fake assertion; this does not authenticate any real source."""

    def verify_binding(self, binding):
        return True

    def verify_snapshot(self, binding, snapshot):
        return True

    def verify_event(self, binding, event):
        return True

    def verify_live(self, binding, now_ns):
        return True


class FakePort:
    def __init__(self, bootstrap, provider):
        self.bootstrap = bootstrap
        self.provider = provider
        self.allowed = True

    def projection(self):
        return self.bootstrap.projection()

    def assert_receipt_binding(self, receipt, projection):
        return self.allowed and receipt._source is self.provider.current_source


class FakeGrants:
    def __init__(self, expires):
        self.value = ("fake-grant-revision-1", expires)

    def current_grant(self, principal, account_ref, now_ns):
        return self.value


class FakeAccountBindings:
    def __init__(self, worker, expires):
        self.expected = (
            "local-account",
            worker.account_key,
            worker.journal_account_scope,
            worker.state_scope,
        )
        self.value = ("fake-binding-revision-1", expires)

    def current_binding(self, account_ref, account_key, journal_scope, state_scope, now_ns):
        if (account_ref, account_key, journal_scope, state_scope) != self.expected:
            return None
        return self.value


@pytest.fixture(params=(False, True), ids=("empty", "one-position"))
def assembly(tmp_path, request):
    clocks = Clocks()
    positions = (_position(clocks),) if request.param else ()
    observation = _observation(clocks, observation_id="fake-observation", positions=positions)
    provider = FullProvider(clocks, observation)
    worker, journal = _worker(tmp_path, provider, clocks)
    worker.start()
    now_ns = int(clocks.utc() * 1_000_000_000)
    binding = PositionStreamBinding(
        account_key=observation.account_key,
        account_ref="local-account",
        route_ref="synthetic-route",
        session_ref=worker.session_generation,
        connection_epoch=1,
        subscription_epoch=1,
        subscription_ready_ref="fake-ready",
        valid_until_ns=now_ns + 60_000_000_000,
    )
    bootstrap = bootstrap_module.PositionStreamBootstrap(
        binding, FakeVerifier(), clock_ns=lambda: int(clocks.utc() * 1_000_000_000)
    )
    bootstrap.install_snapshot(
        PositionStreamSnapshot(
            binding=binding,
            cut_sequence=7,
            observed_ns=now_ns,
            snapshot_receipt_ref="fake-cut-1",
            positions=positions,
        )
    )
    port = FakePort(bootstrap, provider)
    grants = FakeGrants(now_ns + 50_000_000_000)
    account_bindings = FakeAccountBindings(worker, now_ns + 50_000_000_000)
    principal = GatewayPrincipal(
        "fake-reconciler",
        frozenset({worker.journal_account_scope}),
        frozenset({worker.state_scope}),
        frozenset({GatewayCommandKind.READ}),
    )
    consumer_ref = "server-bound-consumer"
    batch, progress = journal.read_for_consumer(
        principal, worker.journal_account_scope, worker.state_scope, consumer_ref
    )
    journal.acknowledge(
        principal,
        worker.journal_account_scope,
        worker.state_scope,
        consumer_ref,
        stream_epoch=progress.stream_epoch,
        cursor=batch.next_cursor,
    )
    inspector = GatewayReconciliationInspector(
        worker,
        port,
        grants,
        account_ref="local-account",
        required_resources=(_resource(),),
        principals={principal.principal_id: (principal, consumer_ref)},
        account_bindings=account_bindings,
        clock_ns=lambda: int(clocks.utc() * 1_000_000_000),
    )
    try:
        yield SimpleNamespace(
            worker=worker,
            journal=journal,
            inspector=inspector,
            principal=principal,
            consumer_ref=consumer_ref,
            bootstrap=bootstrap,
            port=port,
            grants=grants,
            account_bindings=account_bindings,
            clocks=clocks,
            binding=binding,
        )
    finally:
        worker.close()


def test_local_inspection_rechecks_source_and_keeps_journal_progress_unchanged(assembly):
    before = assembly.journal.consumer_progress(
        assembly.principal,
        assembly.worker.journal_account_scope,
        assembly.worker.state_scope,
        assembly.consumer_ref,
    )
    candidate = assembly.inspector.inspect(assembly.principal)
    assert type(candidate) is GatewayReconciliationCandidate
    candidate.assert_current()
    after = assembly.journal.consumer_progress(
        assembly.principal,
        assembly.worker.journal_account_scope,
        assembly.worker.state_scope,
        assembly.consumer_ref,
    )
    assert before == after
    assert not hasattr(candidate, "complete")
    assert not hasattr(candidate, "positions")
    assert not hasattr(candidate, "to_dict")


def test_distinct_but_equal_principal_and_forged_candidate_are_refused(assembly):
    equal_principal = replace(assembly.principal)
    assert equal_principal == assembly.principal
    with pytest.raises(GatewayReconciliationInspectionError, match="PRINCIPAL_DENIED"):
        assembly.inspector.inspect(equal_principal)
    with pytest.raises(GatewayReconciliationInspectionError, match="INSPECTION_UNKNOWN"):
        GatewayReconciliationCandidate(assembly.inspector).assert_current()


def test_grant_revocation_and_source_disconnect_invalidate_existing_handle(assembly):
    candidate = assembly.inspector.inspect(assembly.principal)
    assembly.grants.value = ("fake-grant-revision-2", assembly.grants.value[1])
    with pytest.raises(GatewayReconciliationInspectionError, match="INSPECTION_CHANGED"):
        candidate.assert_current()
    assembly.grants.value = ("fake-grant-revision-1", assembly.grants.value[1])
    with pytest.raises(GatewayReconciliationInspectionError, match="INSPECTION_UNKNOWN"):
        candidate.assert_current()
    candidate = assembly.inspector.inspect(assembly.principal)
    assembly.bootstrap.interrupt()
    with pytest.raises(GatewayReconciliationInspectionError, match="SOURCE_UNAVAILABLE"):
        candidate.assert_current()


def test_unauthenticated_source_binding_and_expiration_are_refused(assembly):
    assembly.port.allowed = False
    with pytest.raises(GatewayReconciliationInspectionError, match="SOURCE_UNAVAILABLE"):
        assembly.inspector.inspect(assembly.principal)
    assembly.port.allowed = True
    candidate = assembly.inspector.inspect(assembly.principal)
    assembly.clocks.advance(6)
    with pytest.raises(GatewayReconciliationInspectionError, match="SOURCE_UNAVAILABLE"):
        candidate.assert_current()


def test_post_snapshot_event_is_not_promoted_to_same_journal_cut(assembly):
    candidate = assembly.inspector.inspect(assembly.principal)
    assembly.bootstrap.push(
        PositionStreamEvent(
            binding=assembly.binding,
            sequence=8,
            observed_ns=int(assembly.clocks.utc() * 1_000_000_000),
            event_receipt_ref="fake-event-8",
            position=_position(assembly.clocks),
        )
    )
    with pytest.raises(GatewayReconciliationInspectionError, match="SOURCE_BINDING_MISMATCH"):
        candidate.assert_current()


def test_event_during_journal_read_prevents_candidate_issuance(assembly, monkeypatch):
    original = assembly.journal.inspect_reconciliation_cut

    def interrupted(*args):
        result = original(*args)
        assembly.bootstrap.push(
            PositionStreamEvent(
                binding=assembly.binding,
                sequence=8,
                observed_ns=int(assembly.clocks.utc() * 1_000_000_000),
                event_receipt_ref="fake-event-8",
                position=_position(assembly.clocks),
            )
        )
        return result

    monkeypatch.setattr(assembly.journal, "inspect_reconciliation_cut", interrupted)
    with pytest.raises(GatewayReconciliationInspectionError, match="JOURNAL_OR_GRANT_UNAVAILABLE"):
        assembly.inspector.inspect(assembly.principal)


def test_missing_ack_and_wrong_account_acl_fail_without_creating_progress(assembly):
    principal = GatewayPrincipal(
        "new-fake-principal",
        frozenset({assembly.worker.journal_account_scope}),
        frozenset({assembly.worker.state_scope}),
        frozenset({GatewayCommandKind.READ}),
    )
    with pytest.raises(GatewayEventJournalError) as missing:
        assembly.journal.inspect_reconciliation_cut(
            principal,
            assembly.worker.journal_account_scope,
            assembly.worker.state_scope,
            "unseen-consumer",
        )
    assert missing.value.code == "CONSUMER_NOT_FOUND"
    with pytest.raises(GatewayEventJournalError) as denied:
        assembly.journal.inspect_reconciliation_cut(
            principal, "wrong-account", assembly.worker.state_scope, assembly.consumer_ref
        )
    assert denied.value.code == "ACCOUNT_SCOPE_DENIED"
    with pytest.raises(GatewayEventJournalError) as still_missing:
        assembly.journal.consumer_progress(
            principal,
            assembly.worker.journal_account_scope,
            assembly.worker.state_scope,
            "unseen-consumer",
        )
    assert still_missing.value.code == "CONSUMER_NOT_FOUND"


@pytest.mark.parametrize("replacement", (False, True), ids=("missing", "replaced"))
def test_reconciliation_read_rejects_missing_or_replaced_database(assembly, replacement):
    path = assembly.journal._database_path
    saved = path.with_suffix(".saved")
    path.rename(saved)
    if replacement:
        path.write_bytes(b"not the account database")
    try:
        with pytest.raises(GatewayEventJournalError) as failed:
            assembly.journal.inspect_reconciliation_cut(
                assembly.principal,
                assembly.worker.journal_account_scope,
                assembly.worker.state_scope,
                assembly.consumer_ref,
            )
        assert failed.value.code == "RECONCILIATION_JOURNAL_UNAVAILABLE"
        if replacement:
            assert path.read_bytes() == b"not the account database"
        else:
            assert not path.exists()
        with pytest.raises(GatewayEventJournalError) as denied:
            assembly.journal.inspect_reconciliation_cut(
                assembly.principal, "wrong-account", assembly.worker.state_scope, assembly.consumer_ref
            )
        assert denied.value.code == "ACCOUNT_SCOPE_DENIED"
    finally:
        if replacement:
            path.unlink()
        saved.rename(path)


def test_reconciliation_read_escapes_uri_path_and_reads_live_wal(assembly):
    path = assembly.journal._database_path
    renamed = path.with_name("gateway #read?%.db")
    path.rename(renamed)
    assembly.journal._database_path = renamed
    try:
        # Keep the WAL open while the read-only connection reads its contents.
        with sqlite3.connect(renamed) as writer:
            writer.execute("BEGIN IMMEDIATE")
            writer.execute("UPDATE gateway_consumer_progress SET offered_cursor = offered_cursor + 1")
            writer.commit()
            assert renamed.with_name(renamed.name + "-wal").exists()
            batch, progress = assembly.journal.inspect_reconciliation_cut(
                assembly.principal,
                assembly.worker.journal_account_scope,
                assembly.worker.state_scope,
                assembly.consumer_ref,
            )
            assert batch.next_cursor == progress.acknowledged_cursor
            assert progress.offered_cursor == progress.acknowledged_cursor + 1
    finally:
        assembly.journal._database_path = path
        renamed.rename(path)


def test_reconciliation_read_wraps_inaccessible_database(assembly, monkeypatch):
    path = assembly.journal._database_path
    original = path.read_bytes()

    def inaccessible(*args, **kwargs):
        raise sqlite3.OperationalError("private filesystem details")

    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, "connect", inaccessible)
        with pytest.raises(GatewayEventJournalError) as failed:
            assembly.journal.inspect_reconciliation_cut(
                assembly.principal,
                assembly.worker.journal_account_scope,
                assembly.worker.state_scope,
                assembly.consumer_ref,
            )
    assert failed.value.code == "RECONCILIATION_JOURNAL_UNAVAILABLE"
    assert "private" not in str(failed.value)
    assert path.read_bytes() == original


def test_unacknowledged_consumer_cannot_issue_handle(assembly):
    principal = GatewayPrincipal(
        "unacknowledged",
        frozenset({assembly.worker.journal_account_scope}),
        frozenset({assembly.worker.state_scope}),
        frozenset({GatewayCommandKind.READ}),
    )
    consumer = "unacknowledged-consumer"
    batch, progress = assembly.journal.read_for_consumer(
        principal, assembly.worker.journal_account_scope, assembly.worker.state_scope, consumer
    )
    assert batch.next_cursor > progress.acknowledged_cursor
    inspector = GatewayReconciliationInspector(
        assembly.worker,
        assembly.port,
        assembly.grants,
        account_ref="local-account",
        required_resources=(_resource(),),
        principals={principal.principal_id: (principal, consumer)},
        account_bindings=assembly.account_bindings,
        clock_ns=lambda: int(assembly.clocks.utc() * 1_000_000_000),
    )
    with pytest.raises(GatewayReconciliationInspectionError, match="JOURNAL_OR_GRANT_UNAVAILABLE"):
        inspector.inspect(principal)
    assert (
        assembly.journal.consumer_progress(
            principal, assembly.worker.journal_account_scope, assembly.worker.state_scope, consumer
        )
        == progress
    )


def test_matching_unregistered_account_alias_is_rejected(assembly, monkeypatch):
    projection = assembly.port.projection()
    changed = replace(projection, binding=replace(projection.binding, account_ref="wrong-alias"))
    monkeypatch.setattr(assembly.port, "projection", lambda: changed)
    inspector = GatewayReconciliationInspector(
        assembly.worker,
        assembly.port,
        assembly.grants,
        account_ref="wrong-alias",
        required_resources=(_resource(),),
        principals={assembly.principal.principal_id: (assembly.principal, assembly.consumer_ref)},
        account_bindings=assembly.account_bindings,
        clock_ns=lambda: int(assembly.clocks.utc() * 1_000_000_000),
    )
    with pytest.raises(GatewayReconciliationInspectionError, match="ACCOUNT_BINDING_UNAVAILABLE"):
        inspector.inspect(assembly.principal)


@pytest.mark.parametrize("field", ("account_key", "journal_scope", "state_scope"))
def test_registered_account_binding_must_match_each_identity_dimension(assembly, field):
    account_ref, key, journal_scope, state_scope = assembly.account_bindings.expected
    if field == "account_key":
        key = replace(key, account_id="another-account")
    elif field == "journal_scope":
        journal_scope = "another-account-scope"
    else:
        state_scope = "another-state-scope"
    assembly.account_bindings.expected = (account_ref, key, journal_scope, state_scope)
    with pytest.raises(GatewayReconciliationInspectionError, match="ACCOUNT_BINDING_UNAVAILABLE"):
        assembly.inspector.inspect(assembly.principal)


def test_missing_or_revoked_account_registration_fails_closed(assembly):
    with pytest.raises(GatewayReconciliationInspectionError, match="ACCOUNT_BINDING_PORT_INVALID"):
        GatewayReconciliationInspector(
            assembly.worker,
            assembly.port,
            assembly.grants,
            account_ref="local-account",
            required_resources=(_resource(),),
            principals={assembly.principal.principal_id: (assembly.principal, assembly.consumer_ref)},
        )
    candidate = assembly.inspector.inspect(assembly.principal)
    original = assembly.account_bindings.value
    assembly.account_bindings.value = None
    with pytest.raises(GatewayReconciliationInspectionError, match="ACCOUNT_BINDING_UNAVAILABLE"):
        candidate.assert_current()
    assembly.account_bindings.value = original
    with pytest.raises(GatewayReconciliationInspectionError, match="INSPECTION_UNKNOWN"):
        candidate.assert_current()


@pytest.mark.parametrize("change", ["account", "session", "snapshot", "cut", "time", "rows"])
def test_mismatched_source_snapshot_claims_are_rejected(assembly, monkeypatch, change):
    projection = assembly.port.projection()
    changes = {
        "account": {"binding": replace(projection.binding, account_ref="different")},
        "session": {"binding": replace(projection.binding, session_ref="different")},
        "snapshot": {"snapshot_receipt_ref": "different"},
        "cut": {"snapshot_cut_sequence": projection.sequence + 1},
        "time": {"observed_ns": projection.observed_ns - 1},
        "rows": {"positions": () if projection.positions else (_position(assembly.clocks),)},
    }
    tampered = replace(projection, **changes[change])
    monkeypatch.setattr(assembly.port, "projection", lambda: tampered)
    with pytest.raises(GatewayReconciliationInspectionError, match="SOURCE_BINDING_MISMATCH"):
        assembly.inspector.inspect(assembly.principal)


def test_resource_universe_and_wrong_stream_scope_are_rejected(assembly):
    with pytest.raises(GatewayReconciliationInspectionError, match="RESOURCE_UNIVERSE_INVALID"):
        GatewayReconciliationInspector(
            assembly.worker,
            assembly.port,
            assembly.grants,
            account_ref="local-account",
            required_resources=(_resource("linear"),),
            principals={
                assembly.principal.principal_id: (assembly.principal, assembly.consumer_ref)
            },
            account_bindings=assembly.account_bindings,
        )
    unauthorized = GatewayPrincipal(
        "wrong-stream",
        frozenset({assembly.worker.journal_account_scope}),
        frozenset({"some-other-view"}),
        frozenset({GatewayCommandKind.READ}),
    )
    with pytest.raises(GatewayReconciliationInspectionError, match="PRINCIPALS_INVALID"):
        GatewayReconciliationInspector(
            assembly.worker,
            assembly.port,
            assembly.grants,
            account_ref="local-account",
            required_resources=(_resource(),),
            principals={unauthorized.principal_id: (unauthorized, "wrong-consumer")},
            account_bindings=assembly.account_bindings,
        )
