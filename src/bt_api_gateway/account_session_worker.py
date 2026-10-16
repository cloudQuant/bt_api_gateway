"""One owner-thread, read-only provider session that publishes full account state.

The worker is deliberately not a provider SDK adapter. It accepts a trusted
provider object with only connect, read_account, and close operations, and
persists complete replacements through GatewayEventJournal's state-only
stream. It never writes account commands or strategy-attributed positions.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Callable, Optional, Protocol

from bt_api_base.account_certification_protocol import (
    AccountConfigurationObservation,
    ExchangeServerTimeObservation,
)
from bt_api_base.account_protocol import (
    MAX_ACCOUNT_ROWS,
    AccountKey,
    AccountObservation,
    AccountResourceKey,
)

from .account_certification import (
    GatewayCertificationFactsError,
    collect_account_configuration,
    collect_exchange_server_time,
)
from .account_view_projection import (
    AccountViewProjectionError,
    GatewayAccountViewPolicy,
    project_account_view,
    validate_policy_set,
)
from .account_position_snapshot import (
    GatewayFullPositionSnapshot,
    GatewayFullPositionSnapshotReceipt,
    GatewayPositionSnapshotError,
    position_rows_sha256,
    resource_coverage_sha256,
    utc_timestamp_ns,
)
from .event_journal import (
    GatewayAccountSnapshot,
    GatewayEventJournal,
    GatewayEventJournalError,
)
from .router import GatewayCommandKind, GatewayPrincipal
from .session_guard import LocalAccountSessionGuard, LocalAccountSessionGuardError

_STATE_SCHEMA_ID = "sdk.account.state"
_STATE_SCHEMA_VERSION_LEGACY = 1
_STATE_SCHEMA_VERSION_OPEN_ORDERS = 2
_MAX_TRACKED_ROWS = 3 * MAX_ACCOUNT_ROWS + 1
_STATE_METADATA_RESERVE_BYTES = 4096


class GatewayAccountSessionWorkerError(RuntimeError):
    """A finite, value-free account-session worker failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class GatewayAccountSessionProvider(Protocol):
    """Trusted provider boundary exposing account reads and lifecycle only."""

    def connect(self, *, account_key: AccountKey, generation: str, timeout: float) -> None:
        """Open the selected account read session within the adapter timeout."""

    def read_account(
        self, *, generation: str, timeout: float
    ) -> AccountObservation | GatewayFullPositionSnapshot:
        """Return an observation, optionally with trusted full-position coverage."""

    def close(self) -> Optional[bool]:  # noqa: UP045 -- Python 3.9 support.
        """Close idempotently; only None or literal True confirms success."""


class GatewayAccountSessionWorker:
    """Share one read-only provider session and publish replaceable account facts.

    Construction is pure. The owning ServiceHost calls start after it has
    registered the resource's retryable close callback. All lifecycle and
    provider calls belong to the creating thread. Refresh is synchronous and
    occurs only on explicit refresh or a later maintain call; client reads do
    not trigger provider queries. ``clock_resolution_seconds`` may specify
    ``(wall, monotonic)`` resolutions for injected clocks; omitted injected
    clocks use a zero comparison allowance.
    """

    def __init__(
        self,
        provider: GatewayAccountSessionProvider,
        journal: GatewayEventJournal,
        *,
        account_key: AccountKey,
        journal_account_scope: str,
        state_scope: str,
        guard: LocalAccountSessionGuard,
        required_coverage: tuple[AccountResourceKey, ...],
        view_policies: tuple[GatewayAccountViewPolicy, ...] = (),
        require_open_orders: bool = False,
        refresh_interval_seconds: float = 1.0,
        max_staleness_seconds: float = 5.0,
        request_timeout_seconds: float = 2.0,
        clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
        clock_resolution_seconds: Optional[tuple[float, float]] = None,  # noqa: UP045
    ) -> None:
        if type(account_key) is not AccountKey:
            raise GatewayAccountSessionWorkerError("INVALID_ACCOUNT_KEY")
        if type(journal) is not GatewayEventJournal:
            raise GatewayAccountSessionWorkerError("INVALID_JOURNAL")
        if type(guard) is not LocalAccountSessionGuard:
            raise GatewayAccountSessionWorkerError("INVALID_SESSION_GUARD")
        if (
            not callable(getattr(provider, "connect", None))
            or not callable(getattr(provider, "read_account", None))
            or not callable(getattr(provider, "close", None))
        ):
            raise GatewayAccountSessionWorkerError("INVALID_PROVIDER")
        _require_scope_text(journal_account_scope, "INVALID_JOURNAL_SCOPE")
        _require_scope_text(state_scope, "INVALID_STATE_SCOPE")
        if type(required_coverage) is not tuple or not required_coverage:
            raise GatewayAccountSessionWorkerError("INVALID_REQUIRED_COVERAGE")
        if any(type(item) is not AccountResourceKey for item in required_coverage):
            raise GatewayAccountSessionWorkerError("INVALID_REQUIRED_COVERAGE")
        if len(set(required_coverage)) != len(required_coverage):
            raise GatewayAccountSessionWorkerError("INVALID_REQUIRED_COVERAGE")
        if type(view_policies) is not tuple:
            raise GatewayAccountSessionWorkerError("INVALID_VIEW_POLICIES")
        try:
            canonical_view_policies = validate_policy_set(view_policies)
        except Exception:
            raise GatewayAccountSessionWorkerError("INVALID_VIEW_POLICIES") from None
        required_resources = frozenset(required_coverage)
        for policy in canonical_view_policies:
            if policy.view_scope == state_scope:
                raise GatewayAccountSessionWorkerError("VIEW_SCOPE_CONFLICT")
            if not frozenset(policy.resources) <= required_resources:
                raise GatewayAccountSessionWorkerError("VIEW_POLICY_COVERAGE_MISMATCH")
        if type(require_open_orders) is not bool:
            raise GatewayAccountSessionWorkerError("INVALID_OPEN_ORDERS_REQUIREMENT")
        if not callable(clock) or not callable(monotonic_clock):
            raise GatewayAccountSessionWorkerError("INVALID_CLOCK")
        wall_resolution, monotonic_resolution = _clock_resolutions(
            clock, monotonic_clock, clock_resolution_seconds
        )
        self._refresh_interval = _positive_seconds(refresh_interval_seconds)
        self._max_staleness = _positive_seconds(max_staleness_seconds)
        self._request_timeout = _positive_seconds(request_timeout_seconds)

        self._owner_thread_id = threading.get_ident()
        self._provider = provider
        self._journal = journal
        self._account_key = account_key
        self._journal_account_scope = journal_account_scope
        self._state_scope = state_scope
        self._guard = guard
        self._required_coverage = tuple(required_coverage)
        self._view_policies = canonical_view_policies
        self._require_open_orders = require_open_orders
        self._clock = clock
        self._monotonic_clock = monotonic_clock
        # A delta uses two readings from each clock. Allow only their combined,
        # reported quantization error when comparing wall time with monotonic
        # elapsed time; this budget never extends provider freshness.
        self._wall_clock_regression_budget = 2.0 * (wall_resolution + monotonic_resolution)
        principal_digest = hashlib.sha256(account_key.account_key_id.encode("ascii")).hexdigest()
        self._journal_principal = GatewayPrincipal(
            principal_id="gateway-account-session-" + principal_digest,
            account_scopes=frozenset({journal_account_scope}),
            strategy_scopes=frozenset({state_scope}),
            allowed_kinds=frozenset({GatewayCommandKind.READ}),
        )
        if guard.account_key_digest != principal_digest:
            raise GatewayAccountSessionWorkerError("SESSION_GUARD_ACCOUNT_MISMATCH")

        self._state = "new"
        self._generation: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.
        self._cursor = 0
        self._latest_snapshot: Optional[GatewayAccountSnapshot] = None  # noqa: UP045
        self._latest_observation: Optional[AccountObservation] = None  # noqa: UP045
        self._latest_position_source: Optional[GatewayFullPositionSnapshot] = None  # noqa: UP045
        self._last_observation_id: Optional[str] = None  # noqa: UP045
        self._last_observation_digest: Optional[str] = None  # noqa: UP045
        self._last_completed_at: Optional[datetime] = None  # noqa: UP045
        self._last_row_times: dict[str, datetime] = {}
        self._last_captured_at: Optional[float] = None  # noqa: UP045
        self._wall_monotonic_anchor: Optional[tuple[float, float]] = None  # noqa: UP045
        self._snapshot_counter = 0
        self._last_success_monotonic: Optional[float] = None  # noqa: UP045
        self._provider_expiry_monotonic: Optional[float] = None  # noqa: UP045
        self._next_refresh_monotonic: Optional[float] = None  # noqa: UP045
        self._freshness_invalidated = True
        self._guard_attempted = False
        self._guard_acquired = False
        self._connect_attempted = False
        self._provider_connect_active = False
        self._provider_close_confirmed = False
        self._guard.bind_consumer(self)

    @property
    def journal(self) -> GatewayEventJournal:
        """Return the borrowed journal this worker publishes into."""

        return self._journal

    @property
    def account_key(self) -> AccountKey:
        return self._account_key

    @property
    def journal_account_scope(self) -> str:
        return self._journal_account_scope

    @property
    def state_scope(self) -> str:
        return self._state_scope

    @property
    def required_coverage(self) -> tuple[AccountResourceKey, ...]:
        return self._required_coverage

    @property
    def view_policies(self) -> tuple[GatewayAccountViewPolicy, ...]:
        """Canonical trusted projections published with each full snapshot."""

        return self._view_policies

    @property
    def state(self) -> str:
        if self._state == "ready" and not self.ready:
            return "stale"
        return self._state

    @property
    def session_generation(self) -> Optional[str]:  # noqa: UP045 -- Python 3.9 support.
        return self._generation

    @property
    def latest_snapshot(self) -> Optional[GatewayAccountSnapshot]:  # noqa: UP045
        """Return the latest persisted state, including an older diagnostic generation."""

        return self._latest_snapshot

    @property
    def ready(self) -> bool:
        return bool(self.read_status()["ready"])

    def read_status(self) -> Mapping[str, object]:
        """Return provider-generation readiness and conservative freshness only."""

        generation = self._generation
        fresh_for = 0.0
        if (
            generation is not None
            and self._guard_acquired
            and not self._freshness_invalidated
            and self._latest_snapshot is not None
            and self._latest_observation is not None
            and self._last_success_monotonic is not None
        ):
            try:
                self._guard.assert_owned()
                if (
                    self._latest_snapshot.account_scope == self._journal_account_scope
                    and self._latest_snapshot.strategy_scope == self._state_scope
                    and self._latest_snapshot.cursor == self._cursor
                    and self._latest_snapshot.payload.get("schema_id") == _STATE_SCHEMA_ID
                    and self._latest_snapshot.payload.get("schema_version")
                    == _observation_schema_version(self._latest_observation)
                    and _snapshot_generation(self._latest_snapshot) == generation
                    and _canonical_json(
                        _plain_json(self._latest_snapshot.payload.get("observation"))
                    )
                    == _canonical_json(self._latest_observation.to_dict())
                ):
                    fresh_for = self._freshness_seconds(
                        self._latest_observation, self._last_success_monotonic
                    )
            except (LocalAccountSessionGuardError, GatewayAccountSessionWorkerError):
                fresh_for = 0.0
        is_ready = self._state == "ready" and fresh_for > 0.0
        return MappingProxyType(
            {
                "session_generation": generation,
                "ready": is_ready,
                "fresh_for_seconds": max(0.0, float(fresh_for)),
            }
        )

    def start(self) -> None:
        """Acquire one local owner, connect once, and require a first full baseline."""

        self._check_owner()
        if self._state != "new":
            raise GatewayAccountSessionWorkerError("WORKER_ALREADY_STARTED")
        self._state = "starting"
        generation: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.
        try:
            self._guard_attempted = True
            generation = self._guard.acquire()
            if type(generation) is not str or not generation:
                raise GatewayAccountSessionWorkerError("INVALID_SESSION_GENERATION")
            self._generation = generation
            self._guard_acquired = True
            self._assert_current_generation_owned(generation)
            self._load_existing_state()
            self._connect_attempted = True
            self._provider_connect_active = True
            try:
                result = self._provider.connect(
                    account_key=self._account_key,
                    generation=generation,
                    timeout=self._request_timeout,
                )
            finally:
                self._provider_connect_active = False
            self._assert_current_generation_owned(generation)
            if result is not None:
                raise GatewayAccountSessionWorkerError("PROVIDER_CONNECT_RESULT_INVALID")
            self._provider_close_confirmed = False
            self._state = "connected"
            self._refresh_impl()
        except BaseException as exc:
            if self._generation == generation and self._state not in {
                "refresh_failed",
                "failed",
                "ownership_lost",
            }:
                self._state = "failed"
            if isinstance(exc, GatewayAccountSessionWorkerError):
                raise
            if isinstance(exc, LocalAccountSessionGuardError):
                code = (
                    exc.code
                    if exc.code
                    in {"SESSION_ALREADY_OWNED", "SESSION_RECONCILIATION_REQUIRED"}
                    else "SESSION_OWNERSHIP_UNAVAILABLE"
                )
                raise GatewayAccountSessionWorkerError(code) from None
            code = "PROVIDER_CONNECT_FAILED" if self._connect_attempted else "START_FAILED"
            if isinstance(exc, Exception):
                raise GatewayAccountSessionWorkerError(code) from None
            raise

    def refresh(self) -> GatewayAccountSnapshot:
        """Perform one shared full account read and atomically replace its state."""

        self._check_owner()
        if self._state not in {"connected", "ready", "refresh_failed"}:
            raise GatewayAccountSessionWorkerError("SESSION_NOT_ACTIVE")
        try:
            self._guard.assert_owned()
        except LocalAccountSessionGuardError:
            self._freshness_invalidated = True
            self._state = "ownership_lost"
            raise GatewayAccountSessionWorkerError("SESSION_OWNERSHIP_LOST") from None
        return self._refresh_impl()

    def maintain(self) -> None:
        """Refresh once when due; this is the sole periodic query path."""

        self._check_owner()
        if self._state not in {"connected", "ready", "refresh_failed"}:
            return
        now = self._monotonic_now()
        due = self._next_refresh_monotonic
        if due is None or now >= due:
            self.refresh()

    def recover(self) -> None:
        """Explicitly close and release before connecting under a fresh generation."""

        self._check_owner()
        if self._state == "new":
            self.start()
            return
        if self._provider_connect_active:
            raise GatewayAccountSessionWorkerError("RECOVERY_DURING_CONNECT")
        self.close()
        self._reset_for_restart()
        self.start()

    def close(self) -> None:
        """Retry provider close and guard release without dropping uncertain ownership."""

        self._check_owner()
        if self._state == "closed":
            return
        if self._provider_connect_active:
            raise GatewayAccountSessionWorkerError("CLOSE_DURING_CONNECT")
        self._state = "closing"
        if self._connect_attempted and not self._provider_close_confirmed:
            try:
                result = self._provider.close()
            except BaseException as exc:
                self._state = "close_failed"
                if isinstance(exc, Exception):
                    raise GatewayAccountSessionWorkerError("PROVIDER_CLOSE_FAILED") from None
                raise
            if result is not None and result is not True:
                self._state = "close_failed"
                raise GatewayAccountSessionWorkerError("PROVIDER_CLOSE_UNCONFIRMED")
            self._provider_close_confirmed = True
        if self._guard_attempted:
            try:
                self._guard.release()
            except BaseException as exc:
                self._state = "close_failed"
                if isinstance(exc, Exception):
                    raise GatewayAccountSessionWorkerError("SESSION_GUARD_RELEASE_FAILED") from None
                raise
        self._guard_acquired = False
        self._generation = None
        self._freshness_invalidated = True
        self._state = "closed"

    def read_account_configuration(self) -> AccountConfigurationObservation:
        """Collect one current, typed configuration fact from the active session."""

        generation = self._active_fact_generation()
        try:
            return collect_account_configuration(
                self._provider,
                account_key_id=self._account_key.account_key_id,
                generation=generation,
                timeout=self._request_timeout,
                assert_owned=lambda: self._assert_current_generation_owned(generation),
                monotonic_clock=self._monotonic_clock,
                wall_clock=self._clock,
            )
        except GatewayCertificationFactsError as exc:
            raise GatewayAccountSessionWorkerError(exc.code) from None

    def read_exchange_server_time(self) -> ExchangeServerTimeObservation:
        """Collect provider server time without substituting a local clock sample."""

        generation = self._active_fact_generation()
        try:
            return collect_exchange_server_time(
                self._provider,
                account_key_id=self._account_key.account_key_id,
                generation=generation,
                timeout=self._request_timeout,
                assert_owned=lambda: self._assert_current_generation_owned(generation),
                monotonic_clock=self._monotonic_clock,
                wall_clock=self._clock,
            )
        except GatewayCertificationFactsError as exc:
            raise GatewayAccountSessionWorkerError(exc.code) from None

    def read_full_position_snapshot_receipt(self) -> GatewayFullPositionSnapshotReceipt:
        """Issue a non-wire receipt for this owner's current full position snapshot.

        A bare serialized account.snapshot, including its completeness flags,
        cannot be converted into this receipt. The provider must have returned
        the trusted full-query result for the same current session generation.
        """

        generation = self._active_fact_generation()
        source = self._latest_position_source
        observation = self._latest_observation
        snapshot = self._latest_snapshot
        if source is None or observation is None or snapshot is None:
            raise GatewayAccountSessionWorkerError("POSITION_SNAPSHOT_PROOF_UNAVAILABLE")
        self._validate_full_position_source(source, observation, generation)
        observed_at_ns = source.observed_at_ns
        valid_until_ns = min(
            source.valid_until_ns,
            observed_at_ns + int(self._max_staleness * 1_000_000_000),
        )
        if valid_until_ns <= int(self._wall_clock() * 1_000_000_000):
            raise GatewayAccountSessionWorkerError("POSITION_SNAPSHOT_PROOF_STALE")
        receipt = GatewayFullPositionSnapshotReceipt(
            _issuer=self,
            _snapshot=snapshot,
            _source=source,
            account_key=self._account_key,
            observation=observation,
            session_generation=generation,
            snapshot_cursor=snapshot.cursor,
            valid_until_ns=valid_until_ns,
        )
        self._assert_current_position_snapshot_receipt(receipt)
        return receipt

    def _assert_current_position_snapshot_receipt(
        self, receipt: GatewayFullPositionSnapshotReceipt
    ) -> None:
        self._check_owner()
        if (
            type(receipt) is not GatewayFullPositionSnapshotReceipt
            or receipt._issuer is not self
            or receipt._snapshot is not self._latest_snapshot
            or receipt._source is not self._latest_position_source
            or receipt.observation is not self._latest_observation
            or receipt.account_key is not self._account_key
        ):
            raise GatewayAccountSessionWorkerError("POSITION_SNAPSHOT_RECEIPT_STALE")
        generation = self._active_fact_generation()
        if (
            receipt.session_generation != generation
            or self._latest_snapshot is None
            or receipt.snapshot_cursor != self._latest_snapshot.cursor
        ):
            raise GatewayAccountSessionWorkerError("POSITION_SNAPSHOT_RECEIPT_STALE")
        self._validate_full_position_source(
            receipt._source, receipt.observation, generation
        )
        if receipt.valid_until_ns <= int(self._wall_clock() * 1_000_000_000):
            raise GatewayAccountSessionWorkerError("POSITION_SNAPSHOT_RECEIPT_STALE")

    def _validate_full_position_source(
        self,
        source: GatewayFullPositionSnapshot,
        observation: AccountObservation,
        generation: str,
    ) -> None:
        try:
            valid = (
                type(source) is GatewayFullPositionSnapshot
                and source.observation is observation
                and source.account_key_id == self._account_key.account_key_id
                and source.session_generation == generation
                and source.observation.account_key == self._account_key
                and source.observation.positions_complete is True
                and source.query_scope == "ALL_ACCOUNT_POSITIONS"
                and source.filters == ()
                and source.permission_scope == "ACCOUNT_FULL"
                and source.pagination_exhausted is True
                and source.positions_sha256 == position_rows_sha256(observation)
                and source.resource_coverage_sha256 == resource_coverage_sha256(observation)
                and source.observed_at_ns
                == utc_timestamp_ns(observation.completed_at_utc)
                and source.valid_until_ns > source.observed_at_ns
            )
        except GatewayPositionSnapshotError:
            valid = False
        if not valid:
            raise GatewayAccountSessionWorkerError("POSITION_SNAPSHOT_SOURCE_INVALID")

    def _active_fact_generation(self) -> str:
        self._check_owner()
        generation = self._generation
        if (
            self._state != "ready"
            or generation is None
            or not self._connect_attempted
            or self.read_status().get("ready") is not True
        ):
            raise GatewayAccountSessionWorkerError("SESSION_NOT_READY")
        self._assert_current_generation_owned(generation)
        return generation

    def _refresh_impl(self) -> GatewayAccountSnapshot:
        self._freshness_invalidated = True
        self._state = "refreshing"
        phase = "provider_read"
        start_monotonic = self._monotonic_now()
        generation = self._generation
        try:
            if generation is None or not self._connect_attempted:
                raise GatewayAccountSessionWorkerError("SESSION_NOT_ACTIVE")
            self._assert_current_generation_owned(generation)
            provider_result = self._provider.read_account(
                generation=generation,
                timeout=self._request_timeout,
            )
            if type(provider_result) is GatewayFullPositionSnapshot:
                position_source: Optional[GatewayFullPositionSnapshot] = provider_result
                observation = provider_result.observation
            else:
                position_source = None
                observation = provider_result
            end_monotonic = self._monotonic_now()
            self._assert_current_generation_owned(generation)
            if end_monotonic < start_monotonic:
                raise GatewayAccountSessionWorkerError("MONOTONIC_CLOCK_REGRESSED")
            if end_monotonic - start_monotonic > self._request_timeout:
                raise GatewayAccountSessionWorkerError("PROVIDER_RESPONSE_LATE")
            captured_at, wall_after, logical_wall, projected_floor = self._capture_wall_sample()
            if wall_after < end_monotonic:
                raise GatewayAccountSessionWorkerError("MONOTONIC_CLOCK_REGRESSED")
            phase = "observation_validation"
            row_times, completed_at = self._validate_observation(observation, now=logical_wall)
            if position_source is not None:
                self._validate_full_position_source(position_source, observation, generation)
            if any("open_orders" in policy.fact_kinds for policy in self._view_policies) and (
                observation.open_orders is None or not observation.open_orders_complete
            ):
                raise GatewayAccountSessionWorkerError("OBSERVATION_OPEN_ORDERS_INCOMPLETE")
            for policy in self._view_policies:
                try:
                    project_account_view(observation, policy)
                except AccountViewProjectionError as exc:
                    raise GatewayAccountSessionWorkerError(exc.code) from None
            serialized_observation = _canonical_json(observation.to_dict())
            digest = hashlib.sha256(serialized_observation.encode("utf-8")).hexdigest()
            if observation.observation_id == self._last_observation_id:
                if digest != self._last_observation_digest:
                    raise GatewayAccountSessionWorkerError("OBSERVATION_ID_REUSED")
                previous_source_digest = (
                    None
                    if self._latest_position_source is None
                    else _canonical_json(self._latest_position_source.source_payload())
                )
                current_source_digest = (
                    None
                    if position_source is None
                    else _canonical_json(position_source.source_payload())
                )
                if previous_source_digest != current_source_digest:
                    raise GatewayAccountSessionWorkerError("POSITION_SOURCE_ID_REUSED")
                if self._latest_snapshot is None:
                    raise GatewayAccountSessionWorkerError("CURRENT_BASELINE_MISSING")
                self._next_refresh_monotonic = end_monotonic + self._refresh_interval
                self._freshness_invalidated = False
                self._state = "ready"
                return self._latest_snapshot

            phase = "journal_replace"
            self._snapshot_counter += 1
            snapshot_id = f"{generation}:{self._snapshot_counter}"
            payload = {
                "schema_id": _STATE_SCHEMA_ID,
                "schema_version": _observation_schema_version(observation),
                "session_generation": generation,
                "observation": observation.to_dict(),
            }
            if len(_canonical_json(payload).encode("utf-8")) > (
                self._journal.MAX_STATE_SNAPSHOT_BYTES - _STATE_METADATA_RESERVE_BYTES
            ):
                self._snapshot_counter -= 1
                raise GatewayAccountSessionWorkerError("STATE_SNAPSHOT_TOO_LARGE")
            if self._last_captured_at is not None and captured_at < self._last_captured_at:
                raise GatewayAccountSessionWorkerError("WALL_CLOCK_REGRESSED")
            if projected_floor is not None:
                floating_rounding = 2.0 * max(math.ulp(captured_at), math.ulp(projected_floor))
                if (
                    captured_at + self._wall_clock_regression_budget + floating_rounding
                    < projected_floor
                ):
                    raise GatewayAccountSessionWorkerError("WALL_CLOCK_REGRESSED")
            oldest_provider_time = min(
                timestamp.timestamp() for timestamp in _observation_times(observation)
            )
            provider_age = max(0.0, logical_wall - oldest_provider_time)
            provider_remaining = max(0.0, self._max_staleness - provider_age)
            self._assert_current_generation_owned(generation)
            snapshot = self._journal.replace_state_snapshot(
                self._journal_account_scope,
                self._state_scope,
                snapshot_id,
                payload,
                expected_cursor=self._cursor,
                captured_at=captured_at,
                view_policies=self._view_policies,
            )
            self._cursor = snapshot.cursor
            self._latest_snapshot = snapshot
            self._latest_observation = observation
            self._latest_position_source = position_source
            self._last_observation_id = observation.observation_id
            self._last_observation_digest = digest
            self._last_completed_at = completed_at
            self._last_row_times = row_times
            self._last_captured_at = captured_at
            self._wall_monotonic_anchor = (logical_wall, wall_after)
            self._last_success_monotonic = wall_after
            self._provider_expiry_monotonic = wall_after + provider_remaining
            self._next_refresh_monotonic = self._last_success_monotonic + self._refresh_interval
            self._freshness_invalidated = False
            self._state = "ready"
            return snapshot
        except GatewayAccountSessionWorkerError as exc:
            if exc.code == "SESSION_OWNERSHIP_LOST":
                raise
            if not (
                exc.code == "PROVIDER_RESULT_GENERATION_STALE" and self._generation != generation
            ):
                self._record_refresh_failure()
            raise
        except GatewayEventJournalError:
            self._record_refresh_failure()
            raise GatewayAccountSessionWorkerError("STATE_WRITE_FAILED") from None
        except BaseException as exc:
            self._record_refresh_failure()
            if isinstance(exc, Exception):
                code = "PROVIDER_READ_FAILED" if phase == "provider_read" else "OBSERVATION_INVALID"
                if phase == "journal_replace":
                    code = "STATE_WRITE_FAILED"
                raise GatewayAccountSessionWorkerError(code) from None
            raise

    def _load_existing_state(self) -> None:
        try:
            self._journal.validate_state_view_policies(
                self._journal_account_scope,
                self._state_scope,
                self._view_policies,
            )
        except GatewayEventJournalError as exc:
            raise GatewayAccountSessionWorkerError(exc.code) from None
        batch = self._journal.read_after(
            self._journal_principal,
            self._journal_account_scope,
            self._state_scope,
            cursor=None,
            limit=GatewayEventJournal.MAX_BATCH_SIZE,
        )
        if batch.events:
            raise GatewayAccountSessionWorkerError("STATE_STREAM_HAS_EVENTS")
        snapshot = batch.snapshot
        if snapshot is not None and snapshot.payload.get("schema_id") != _STATE_SCHEMA_ID:
            raise GatewayAccountSessionWorkerError("STATE_STREAM_SCHEMA_MISMATCH")
        if snapshot is not None and (
            type(snapshot.payload.get("schema_version")) is not int
            or snapshot.payload.get("schema_version")
            not in {_STATE_SCHEMA_VERSION_LEGACY, _STATE_SCHEMA_VERSION_OPEN_ORDERS}
        ):
            raise GatewayAccountSessionWorkerError("STATE_STREAM_SCHEMA_MISMATCH")
        persisted_observation: Optional[AccountObservation] = None  # noqa: UP045
        if snapshot is not None:
            payload = _plain_json(snapshot.payload)
            expected_fields = {
                "schema_id",
                "schema_version",
                "session_generation",
                "observation",
            }
            if (
                type(payload) is not dict
                or set(payload) != expected_fields
                or type(payload.get("session_generation")) is not str
                or not payload["session_generation"]
            ):
                raise GatewayAccountSessionWorkerError("STATE_STREAM_PAYLOAD_INVALID")
            try:
                persisted_observation = AccountObservation.from_dict(payload["observation"])
            except (KeyError, TypeError, ValueError):
                raise GatewayAccountSessionWorkerError("STATE_STREAM_OBSERVATION_INVALID") from None
            if persisted_observation.account_key != self._account_key:
                raise GatewayAccountSessionWorkerError("STATE_STREAM_ACCOUNT_MISMATCH")
            if len(persisted_observation.coverage) != len(self._required_coverage) or set(
                persisted_observation.coverage
            ) != set(self._required_coverage):
                raise GatewayAccountSessionWorkerError("STATE_STREAM_COVERAGE_MISMATCH")
            if (
                not persisted_observation.balances_complete
                or not persisted_observation.positions_complete
            ):
                raise GatewayAccountSessionWorkerError("STATE_STREAM_OBSERVATION_INCOMPLETE")
            if payload["schema_version"] != _observation_schema_version(persisted_observation):
                raise GatewayAccountSessionWorkerError("STATE_STREAM_SCHEMA_MISMATCH")
        self._cursor = batch.latest_cursor
        self._latest_snapshot = snapshot
        if persisted_observation is not None and snapshot is not None:
            # The persisted state remains diagnostic after restart. Its provider
            # timestamps only prevent a later generation from replacing known
            # facts with chronologically older data; they never make this worker
            # ready or count as a current-generation observation.
            self._last_completed_at = _parse_utc(persisted_observation.completed_at_utc)
            self._last_row_times = _row_times(persisted_observation)
            self._last_captured_at = snapshot.captured_at
            current_wall, sample_after, logical_wall, _ = self._capture_wall_sample()
            if current_wall < snapshot.captured_at:
                raise GatewayAccountSessionWorkerError("WALL_CLOCK_REGRESSED")
            self._wall_monotonic_anchor = (logical_wall, sample_after)

    def _validate_observation(
        self, observation: object, *, now: float
    ) -> tuple[dict[str, datetime], datetime]:
        if type(observation) is not AccountObservation:
            raise GatewayAccountSessionWorkerError("OBSERVATION_TYPE_INVALID")
        if observation.account_key != self._account_key:
            raise GatewayAccountSessionWorkerError("OBSERVATION_ACCOUNT_MISMATCH")
        if len(observation.coverage) != len(self._required_coverage) or set(
            observation.coverage
        ) != set(self._required_coverage):
            raise GatewayAccountSessionWorkerError("OBSERVATION_COVERAGE_MISMATCH")
        if not observation.balances_complete or not observation.positions_complete:
            raise GatewayAccountSessionWorkerError("OBSERVATION_INCOMPLETE")
        if self._require_open_orders and (
            observation.open_orders is None or not observation.open_orders_complete
        ):
            raise GatewayAccountSessionWorkerError("OBSERVATION_OPEN_ORDERS_INCOMPLETE")

        completed_at = _parse_utc(observation.completed_at_utc)
        if self._last_completed_at is not None and completed_at < self._last_completed_at:
            raise GatewayAccountSessionWorkerError("OBSERVATION_COMPLETION_TIME_REGRESSED")
        provider_times = _observation_times(observation)
        if any(timestamp.timestamp() > now + self._request_timeout for timestamp in provider_times):
            raise GatewayAccountSessionWorkerError("OBSERVATION_FROM_FUTURE")
        if any(now - timestamp.timestamp() > self._max_staleness for timestamp in provider_times):
            raise GatewayAccountSessionWorkerError("OBSERVATION_STALE")
        row_times = _row_times(observation)
        combined = dict(self._last_row_times)
        for key, timestamp in row_times.items():
            previous = combined.get(key)
            if previous is not None and timestamp < previous:
                raise GatewayAccountSessionWorkerError("ROW_OBSERVATION_TIME_REGRESSED")
            combined[key] = timestamp
        if len(combined) > _MAX_TRACKED_ROWS:
            raise GatewayAccountSessionWorkerError("ROW_TIME_TRACKING_LIMIT")
        return combined, completed_at

    def _freshness_seconds(
        self, observation: AccountObservation, last_success_monotonic: float
    ) -> float:
        wall_before = self._monotonic_now()
        now_wall = self._wall_clock()
        now_mono = self._monotonic_now()
        expiry = self._provider_expiry_monotonic
        if now_mono < wall_before or now_mono < last_success_monotonic or expiry is None:
            return 0.0
        # Place the wall reading at the end of its monotonic bracket, then keep
        # the provider-age clock at least as far forward as the last accepted
        # monotonic projection. A wall-clock rollback can therefore shorten
        # freshness but can never renew it.
        now_wall += now_mono - wall_before
        if self._wall_monotonic_anchor is not None:
            anchor_wall, anchor_monotonic = self._wall_monotonic_anchor
            if now_mono < anchor_monotonic:
                return 0.0
            now_wall = max(now_wall, anchor_wall + (now_mono - anchor_monotonic))
        oldest_provider_time = min(
            timestamp.timestamp() for timestamp in _observation_times(observation)
        )
        provider_wall_remaining = self._max_staleness - max(0.0, now_wall - oldest_provider_time)
        provider_monotonic_remaining = expiry - now_mono
        local_remaining = self._max_staleness - (now_mono - last_success_monotonic)
        return max(
            0.0,
            min(
                self._max_staleness,
                provider_wall_remaining,
                provider_monotonic_remaining,
                local_remaining,
            ),
        )

    def _record_refresh_failure(self) -> None:
        self._freshness_invalidated = True
        self._state = "refresh_failed"
        try:
            self._next_refresh_monotonic = self._monotonic_now() + self._refresh_interval
        except GatewayAccountSessionWorkerError:
            self._next_refresh_monotonic = None

    def _assert_current_generation_owned(self, generation: str) -> None:
        try:
            self._guard.assert_owned()
        except LocalAccountSessionGuardError:
            self._freshness_invalidated = True
            self._state = "ownership_lost"
            raise GatewayAccountSessionWorkerError("SESSION_OWNERSHIP_LOST") from None
        if self._generation != generation:
            raise GatewayAccountSessionWorkerError("PROVIDER_RESULT_GENERATION_STALE")

    def _reset_for_restart(self) -> None:
        self._state = "new"
        self._generation = None
        self._cursor = 0
        self._latest_observation = None
        self._latest_position_source = None
        self._last_observation_id = None
        self._last_observation_digest = None
        self._last_completed_at = None
        self._last_row_times.clear()
        self._last_captured_at = None
        self._wall_monotonic_anchor = None
        self._snapshot_counter = 0
        self._last_success_monotonic = None
        self._provider_expiry_monotonic = None
        self._next_refresh_monotonic = None
        self._freshness_invalidated = True
        self._guard_attempted = False
        self._guard_acquired = False
        self._connect_attempted = False
        self._provider_connect_active = False
        self._provider_close_confirmed = False

    def _wall_clock(self) -> float:
        return _clock_value(self._clock)

    def _capture_wall_sample(
        self,
    ) -> tuple[float, float, float, Optional[float]]:  # noqa: UP045
        monotonic_before = self._monotonic_now()
        captured_at = self._wall_clock()
        monotonic_after = self._monotonic_now()
        if monotonic_after < monotonic_before:
            raise GatewayAccountSessionWorkerError("MONOTONIC_CLOCK_REGRESSED")

        anchor = self._wall_monotonic_anchor
        if anchor is None:
            logical_wall = captured_at + (monotonic_after - monotonic_before)
            return captured_at, monotonic_after, logical_wall, None

        anchor_wall, anchor_monotonic = anchor
        if monotonic_before < anchor_monotonic:
            raise GatewayAccountSessionWorkerError("MONOTONIC_CLOCK_REGRESSED")
        projected_floor = anchor_wall + (monotonic_before - anchor_monotonic)
        projected_after = anchor_wall + (monotonic_after - anchor_monotonic)
        # The wall sample may have occurred anywhere inside its monotonic
        # bracket. Advancing it by the full span errs toward older provider
        # data; max() also prevents the logical floor from ever moving back.
        logical_wall = max(captured_at + (monotonic_after - monotonic_before), projected_after)
        return captured_at, monotonic_after, logical_wall, projected_floor

    def _monotonic_now(self) -> float:
        return _clock_value(self._monotonic_clock)

    def _check_owner(self) -> None:
        if threading.get_ident() != self._owner_thread_id:
            raise GatewayAccountSessionWorkerError("WORKER_WRONG_THREAD")


def _observation_times(observation: AccountObservation) -> tuple[datetime, ...]:
    values = [
        observation.completed_at_utc,
        *(row.observed_at_utc for row in observation.balances),
        *(row.observed_at_utc for row in observation.positions),
    ]
    if observation.valuation is not None:
        values.append(observation.valuation.observed_at_utc)
    if observation.open_orders is not None:
        values.extend(order.observed_at_utc for order in observation.open_orders)
    return tuple(_parse_utc(value) for value in values)


def _row_times(observation: AccountObservation) -> dict[str, datetime]:
    rows: dict[str, datetime] = {}
    for balance in observation.balances:
        identity = {
            "kind": "balance",
            "resource": balance.resource.to_dict(),
            "currency": balance.currency,
        }
        rows[_canonical_json(identity)] = _parse_utc(balance.observed_at_utc)
    for position in observation.positions:
        identity = {
            "kind": "position",
            "resource": position.resource.to_dict(),
            "instrument": position.instrument.to_dict(),
            "side": position.side,
        }
        rows[_canonical_json(identity)] = _parse_utc(position.observed_at_utc)
    if observation.valuation is not None:
        rows["valuation"] = _parse_utc(observation.valuation.observed_at_utc)
    if observation.open_orders is not None:
        for order in observation.open_orders:
            identity = {
                "kind": "open_order",
                "resource": order.resource.to_dict(),
                "instrument": order.instrument.to_dict(),
                "order_id": order.order_id,
            }
            rows[_canonical_json(identity)] = _parse_utc(order.observed_at_utc)
    return rows


def _observation_schema_version(observation: AccountObservation) -> int:
    return (
        _STATE_SCHEMA_VERSION_LEGACY
        if observation.open_orders is None
        else _STATE_SCHEMA_VERSION_OPEN_ORDERS
    )


def _snapshot_generation(snapshot: GatewayAccountSnapshot) -> Optional[str]:  # noqa: UP045
    generation = snapshot.payload.get("session_generation")
    return generation if type(generation) is str else None


def _parse_utc(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except (TypeError, ValueError, IndexError) as exc:
        raise GatewayAccountSessionWorkerError("OBSERVATION_TIME_INVALID") from exc


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise GatewayAccountSessionWorkerError("OBSERVATION_SERIALIZATION_INVALID") from exc


def _plain_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain_json(item) for item in value]
    return value


def _require_scope_text(value: object, code: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise GatewayAccountSessionWorkerError(code)
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise GatewayAccountSessionWorkerError(code) from exc
    if len(encoded) > 128 or any(ord(char) < 32 or 0x7F <= ord(char) <= 0x9F for char in value):
        raise GatewayAccountSessionWorkerError(code)


def _positive_seconds(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GatewayAccountSessionWorkerError("INVALID_TIME_LIMIT")
    try:
        seconds = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise GatewayAccountSessionWorkerError("INVALID_TIME_LIMIT") from exc
    if not math.isfinite(seconds) or seconds <= 0:
        raise GatewayAccountSessionWorkerError("INVALID_TIME_LIMIT")
    return seconds


def _clock_resolutions(
    clock: Callable[[], float],
    monotonic_clock: Callable[[], float],
    configured: Optional[tuple[float, float]],  # noqa: UP045
) -> tuple[float, float]:
    if configured is None:
        try:
            configured = (
                time.get_clock_info("time").resolution if clock is time.time else 0.0,
                time.get_clock_info("monotonic").resolution
                if monotonic_clock is time.monotonic
                else 0.0,
            )
        except (AttributeError, OSError, ValueError) as exc:
            raise GatewayAccountSessionWorkerError("INVALID_CLOCK_RESOLUTION") from exc
    if type(configured) is not tuple or len(configured) != 2:
        raise GatewayAccountSessionWorkerError("INVALID_CLOCK_RESOLUTION")
    values: list[float] = []
    for value in configured:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise GatewayAccountSessionWorkerError("INVALID_CLOCK_RESOLUTION")
        try:
            seconds = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise GatewayAccountSessionWorkerError("INVALID_CLOCK_RESOLUTION") from exc
        if not math.isfinite(seconds) or seconds < 0.0:
            raise GatewayAccountSessionWorkerError("INVALID_CLOCK_RESOLUTION")
        values.append(seconds)
    if not math.isfinite(2.0 * (values[0] + values[1])):
        raise GatewayAccountSessionWorkerError("INVALID_CLOCK_RESOLUTION")
    return values[0], values[1]


def _clock_value(clock: Callable[[], float]) -> float:
    try:
        value = clock()
    except Exception as exc:
        raise GatewayAccountSessionWorkerError("CLOCK_INVALID") from exc
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GatewayAccountSessionWorkerError("CLOCK_INVALID")
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise GatewayAccountSessionWorkerError("CLOCK_INVALID") from exc
    if not math.isfinite(result):
        raise GatewayAccountSessionWorkerError("CLOCK_INVALID")
    return result


__all__ = [
    "GatewayAccountSessionProvider",
    "GatewayAccountSessionWorker",
    "GatewayAccountSessionWorkerError",
]
