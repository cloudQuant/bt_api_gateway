"""Owner-written account read model; cross-thread reads use immutable in-memory views."""

from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import cast

from bt_api_base.account_protocol import (
    MAX_ACCOUNT_ROWS,
    AccountKey,
    AccountObservation,
    AccountResourceKey,
)
from .account_position_snapshot import (
    GatewayFullPositionSnapshot,
    GatewayPositionSnapshotError,
    position_rows_sha256,
    resource_coverage_sha256,
    utc_timestamp_ns,
)
from .account_view_projection import (
    AccountViewProjectionError,
    GatewayAccountViewPolicy,
    project_account_view,
    validate_policy_set,
)
from .event_journal import GatewayAccountSnapshot, GatewayEventJournal, GatewayEventJournalError
from .router import GatewayCommandKind, GatewayPrincipal


_STATE_SCHEMA_ID = "sdk.account.state"
_STATE_SCHEMA_VERSION_LEGACY = 1
_STATE_SCHEMA_VERSION_OPEN_ORDERS = 2
_MAX_TRACKED_ROWS = 3 * MAX_ACCOUNT_ROWS + 1
_STATE_METADATA_RESERVE_BYTES = 4096
# Upper bound on the rate difference between the wall and monotonic clocks.
# NTP/adjtime slew the wall clock by at most 500 ppm, and some monotonic clocks
# (macOS mach_absolute_time) are not frequency-corrected at all, so the two
# legitimately diverge by tens of ppm. A wall clock that falls behind faster
# than this is treated as a regression.
_MAX_CLOCK_RATE_SKEW = 500e-6


class GatewayAccountSessionWorkerError(RuntimeError):
    """A finite, value-free account-session worker failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class _ReadView:
    snapshot: GatewayAccountSnapshot | None
    observation: AccountObservation | None
    generation: str | None
    cursor: int
    current: bool
    last_success: float | None
    expiry: float | None
    anchor: tuple[float, float] | None


class GatewayAccountReadModel:
    """Owner-published observations; reads never enter provider, guard or journal.

    The caller's generation callback is a local lifecycle check, not trading
    authority or a substitute for authenticating requests.
    """

    def __init__(
        self,
        journal: GatewayEventJournal,
        *,
        account_key: AccountKey,
        journal_account_scope: str,
        state_scope: str,
        required_coverage: tuple[AccountResourceKey, ...],
        assert_current_generation: Callable[[str], None],
        view_policies: tuple[GatewayAccountViewPolicy, ...] = (),
        require_open_orders: bool = False,
        refresh_interval_seconds: float = 1.0,
        max_staleness_seconds: float = 5.0,
        request_timeout_seconds: float = 2.0,
        clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
        clock_resolution_seconds: tuple[float, float] | None = None,
    ) -> None:
        if type(account_key) is not AccountKey:
            raise GatewayAccountSessionWorkerError("INVALID_ACCOUNT_KEY")
        if type(journal) is not GatewayEventJournal:
            raise GatewayAccountSessionWorkerError("INVALID_JOURNAL")
        _require_scope_text(journal_account_scope, "INVALID_JOURNAL_SCOPE")
        _require_scope_text(state_scope, "INVALID_STATE_SCOPE")
        if (
            type(required_coverage) is not tuple
            or not required_coverage
            or any(type(x) is not AccountResourceKey for x in required_coverage)
            or len(set(required_coverage)) != len(required_coverage)
        ):
            raise GatewayAccountSessionWorkerError("INVALID_REQUIRED_COVERAGE")
        if type(view_policies) is not tuple:
            raise GatewayAccountSessionWorkerError("INVALID_VIEW_POLICIES")
        try:
            policies = validate_policy_set(view_policies)
        except Exception:
            raise GatewayAccountSessionWorkerError("INVALID_VIEW_POLICIES") from None
        for policy in policies:
            if policy.view_scope == state_scope:
                raise GatewayAccountSessionWorkerError("VIEW_SCOPE_CONFLICT")
            if not frozenset(policy.resources) <= frozenset(required_coverage):
                raise GatewayAccountSessionWorkerError("VIEW_POLICY_COVERAGE_MISMATCH")
        if type(require_open_orders) is not bool:
            raise GatewayAccountSessionWorkerError("INVALID_OPEN_ORDERS_REQUIREMENT")
        if (
            not callable(clock)
            or not callable(monotonic_clock)
            or not callable(assert_current_generation)
        ):
            raise GatewayAccountSessionWorkerError("INVALID_CLOCK")
        wall_res, mono_res = _clock_resolutions(clock, monotonic_clock, clock_resolution_seconds)
        self._pid, self._owner_thread = os.getpid(), threading.current_thread()
        self._view_lock = threading.Lock()
        self._journal, self._account_key = journal, account_key
        self._journal_account_scope, self._state_scope = journal_account_scope, state_scope
        self._required_coverage, self._view_policies = tuple(required_coverage), policies
        self._require_open_orders = require_open_orders
        self._assert_generation = assert_current_generation
        self._clock, self._monotonic_clock = clock, monotonic_clock
        self._wall_clock_regression_budget = 2.0 * (wall_res + mono_res)
        self._refresh_interval = _positive_seconds(refresh_interval_seconds)
        self._max_staleness = _positive_seconds(max_staleness_seconds)
        self._request_timeout = _positive_seconds(request_timeout_seconds)
        principal_digest = hashlib.sha256(account_key.account_key_id.encode("ascii")).hexdigest()
        self._journal_principal = GatewayPrincipal(
            principal_id="gateway-account-session-" + principal_digest,
            account_scopes=frozenset({journal_account_scope}),
            strategy_scopes=frozenset({state_scope}),
            allowed_kinds=frozenset({GatewayCommandKind.READ}),
        )
        self._generation = None
        self._used_generations = set()
        self._state = "new"
        self._attempt = None
        self._cursor = 0
        self._latest_snapshot = self._latest_observation = self._latest_position_source = None
        self._last_observation_id = self._last_observation_digest = self._last_completed_at = None
        self._baseline_authorized = False
        self._last_row_times = {}
        self._last_captured_at = self._wall_monotonic_anchor = self._wall_sample_anchor = None
        self._snapshot_counter = 0
        self._last_success_monotonic = self._provider_expiry_monotonic = (
            self._next_refresh_monotonic
        ) = None
        self._freshness_invalidated = True
        self._view = _ReadView(None, None, None, 0, False, None, None, None)
        self._last_read_mono = None
        self._last_read_remaining = 0.0

    @property
    def journal(self):
        self._check_pid()
        return self._journal

    @property
    def account_key(self):
        self._check_pid()
        return self._account_key

    @property
    def journal_account_scope(self):
        self._check_pid()
        return self._journal_account_scope

    @property
    def state_scope(self):
        self._check_pid()
        return self._state_scope

    @property
    def required_coverage(self):
        self._check_pid()
        return self._required_coverage

    @property
    def view_policies(self):
        self._check_pid()
        return self._view_policies

    @property
    def latest_snapshot(self):
        self._check_pid()
        with self._view_lock:
            return self._view.snapshot

    @property
    def ready(self):
        return self.read_status()["ready"] is True

    @property
    def session_generation(self):
        self._check_pid()
        with self._view_lock:
            return self._view.generation

    def _check_pid(self):
        if os.getpid() != self._pid:
            raise GatewayAccountSessionWorkerError("WORKER_WRONG_PROCESS")

    def _check_owner(self):
        self._check_pid()
        if threading.current_thread() is not self._owner_thread:
            raise GatewayAccountSessionWorkerError("WORKER_WRONG_THREAD")

    def _check_authority(self, generation):
        if self._generation != generation:
            raise GatewayAccountSessionWorkerError("PROVIDER_RESULT_GENERATION_STALE")
        if self._assert_generation(generation) is not None:
            raise GatewayAccountSessionWorkerError("SESSION_OWNERSHIP_UNAVAILABLE")
        if self._generation != generation:
            raise GatewayAccountSessionWorkerError("PROVIDER_RESULT_GENERATION_STALE")

    def _publish_current(self):
        view = _ReadView(
            self._latest_snapshot,
            self._latest_observation,
            self._generation,
            self._cursor,
            self._state == "ready" and not self._freshness_invalidated,
            self._last_success_monotonic,
            self._provider_expiry_monotonic,
            self._wall_monotonic_anchor,
        )
        with self._view_lock:
            previous = self._view
            self._view = view
            if (
                view.snapshot is not previous.snapshot
                or view.last_success != previous.last_success
                or view.generation != previous.generation
            ):
                self._last_read_mono = None
                self._last_read_remaining = self._max_staleness

    def _invalidate(self):
        self._freshness_invalidated = True
        self._publish_current()

    def read_status(self) -> Mapping[str, object]:
        self._check_pid()
        with self._view_lock:
            view = self._view
            remaining = 0.0
            if (
                view.current
                and view.observation is not None
                and view.snapshot is not None
                and view.last_success is not None
                and view.expiry is not None
            ):
                try:
                    if (
                        view.snapshot.account_scope != self._journal_account_scope
                        or view.snapshot.strategy_scope != self._state_scope
                        or view.snapshot.cursor != view.cursor
                        or view.snapshot.payload.get("schema_id") != _STATE_SCHEMA_ID
                        or view.snapshot.payload.get("schema_version")
                        != _observation_schema_version(view.observation)
                        or _snapshot_generation(view.snapshot) != view.generation
                        or _canonical_json(_plain_json(view.snapshot.payload.get("observation")))
                        != _canonical_json(view.observation.to_dict())
                    ):
                        raise ValueError("snapshot binding changed")
                    before = self._monotonic_now()
                    wall = self._wall_clock()
                    now = self._monotonic_now()
                    if (
                        now >= before
                        and now >= view.last_success
                        and (self._last_read_mono is None or now >= self._last_read_mono)
                    ):
                        wall += now - before
                        if view.anchor is not None:
                            anchor_wall, anchor_mono = view.anchor
                            if now < anchor_mono:
                                raise ValueError("monotonic regression")
                            wall = max(wall, anchor_wall + now - anchor_mono)
                        oldest = min(t.timestamp() for t in _observation_times(view.observation))
                        remaining = max(
                            0.0,
                            min(
                                self._max_staleness,
                                self._max_staleness - max(0.0, wall - oldest),
                                view.expiry - now,
                                self._max_staleness - (now - view.last_success),
                                self._last_read_remaining,
                            ),
                        )
                        self._last_read_mono = now
                        self._last_read_remaining = remaining
                    else:
                        self._last_read_remaining = 0.0
                except Exception:
                    remaining = 0.0
                    self._last_read_remaining = 0.0
            return MappingProxyType(
                {
                    "session_generation": view.generation,
                    "ready": view.current and remaining > 0,
                    "fresh_for_seconds": float(remaining),
                }
            )

    def start_generation(self, generation: str) -> None:
        self._check_owner()
        _require_scope_text(generation, "INVALID_SESSION_GENERATION")
        self._invalidate()
        self._attempt = None
        if generation in self._used_generations or len(self._used_generations) >= 10_000:
            raise GatewayAccountSessionWorkerError("INVALID_SESSION_GENERATION")
        self._used_generations.add(generation)
        self._generation = generation
        self._state = "starting"
        self._cursor = 0
        self._latest_snapshot = self._latest_observation = self._latest_position_source = None
        self._last_observation_id = self._last_observation_digest = self._last_completed_at = None
        self._baseline_authorized = False
        self._last_row_times = {}
        self._last_captured_at = self._wall_monotonic_anchor = self._wall_sample_anchor = None
        self._snapshot_counter = 0
        self._last_success_monotonic = self._provider_expiry_monotonic = (
            self._next_refresh_monotonic
        ) = None
        self._publish_current()
        self._check_authority(generation)
        self._load_existing_state()
        self._check_authority(generation)
        self._state = "connected"
        self._publish_current()

    def begin_refresh(self):
        self._check_owner()
        if self._generation is None or self._state not in {"connected", "ready", "refresh_failed"}:
            raise GatewayAccountSessionWorkerError("SESSION_NOT_ACTIVE")
        if self._attempt is not None:
            raise GatewayAccountSessionWorkerError("REFRESH_IN_PROGRESS")
        self._state = "refreshing"
        self._invalidate()
        generation = self._generation
        try:
            self._check_authority(generation)
            token = object()
            self._attempt = (token, generation, self._monotonic_now())
            return token
        except BaseException:
            if self._generation == generation:
                self._record_refresh_failure()
            raise

    def fail_refresh(self, token):
        self._check_owner()
        if self._attempt is None or self._attempt[0] is not token:
            raise GatewayAccountSessionWorkerError("REFRESH_TOKEN_INVALID")
        self._attempt = None
        self._record_refresh_failure()

    def finish_refresh(self, token, provider_result):
        self._check_owner()
        if self._attempt is None or self._attempt[0] is not token:
            raise GatewayAccountSessionWorkerError("REFRESH_TOKEN_INVALID")
        _, generation, start_monotonic = self._attempt
        self._attempt = None
        phase = "observation_validation"
        try:
            self._check_authority(generation)
            if type(provider_result) is GatewayFullPositionSnapshot:
                position_source = provider_result
                observation = provider_result.observation
            else:
                position_source = None
                observation = provider_result
            end_monotonic = self._monotonic_now()
            self._check_authority(generation)
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
                if self._latest_observation is None or not self._baseline_authorized:
                    raise GatewayAccountSessionWorkerError("OBSERVATION_REPLAYED")
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
                self._check_authority(generation)
                self._next_refresh_monotonic = end_monotonic + self._refresh_interval
                self._freshness_invalidated = False
                self._state = "ready"
                self._publish_current()
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
            self._check_authority(generation)
            # A failed/ambiguous replace may already have committed. The old
            # baseline can no longer be promoted until a new read is proven.
            self._baseline_authorized = False
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
            self._wall_sample_anchor = (captured_at, wall_after)
            self._last_success_monotonic = wall_after
            self._provider_expiry_monotonic = wall_after + provider_remaining
            self._next_refresh_monotonic = self._last_success_monotonic + self._refresh_interval
            self._freshness_invalidated = False
            self._check_authority(generation)
            self._baseline_authorized = True
            self._state = "ready"
            self._publish_current()
            return snapshot
        except GatewayAccountSessionWorkerError:
            if self._generation == generation:
                self._record_refresh_failure()
            raise
        except GatewayEventJournalError:
            if self._generation == generation:
                self._record_refresh_failure()
            raise GatewayAccountSessionWorkerError("STATE_WRITE_FAILED") from None
        except BaseException as exc:
            if self._generation == generation:
                self._record_refresh_failure()
            if isinstance(exc, Exception):
                code = "STATE_WRITE_FAILED" if phase == "journal_replace" else "OBSERVATION_INVALID"
                raise GatewayAccountSessionWorkerError(code) from None
            raise

    def _record_refresh_failure(self):
        self._freshness_invalidated = True
        self._state = "refresh_failed"
        try:
            self._next_refresh_monotonic = self._monotonic_now() + self._refresh_interval
        except GatewayAccountSessionWorkerError:
            self._next_refresh_monotonic = None
        self._publish_current()

    def close(self):
        self._check_owner()
        self._attempt = None
        self._state = "closed"
        self._generation = None
        self._invalidate()

    def invalidate(self):
        self._check_owner()
        self._invalidate()

    def _wall_clock(self):
        return _clock_value(self._clock)

    def _monotonic_now(self):
        return _clock_value(self._monotonic_clock)

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
                and source.observed_at_ns == utc_timestamp_ns(observation.completed_at_utc)
                and source.valid_until_ns > source.observed_at_ns
            )
        except GatewayPositionSnapshotError:
            valid = False
        if not valid:
            raise GatewayAccountSessionWorkerError("POSITION_SNAPSHOT_SOURCE_INVALID")

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
        persisted_observation: AccountObservation | None = None
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
            self._last_observation_id = persisted_observation.observation_id
            self._last_observation_digest = hashlib.sha256(
                _canonical_json(persisted_observation.to_dict()).encode("utf-8")
            ).hexdigest()
            self._last_completed_at = _parse_utc(persisted_observation.completed_at_utc)
            self._last_row_times = _row_times(persisted_observation)
            self._last_captured_at = snapshot.captured_at
            current_wall, sample_after, logical_wall, _ = self._capture_wall_sample()
            if current_wall < snapshot.captured_at:
                raise GatewayAccountSessionWorkerError("WALL_CLOCK_REGRESSED")
            self._wall_monotonic_anchor = (logical_wall, sample_after)
            self._wall_sample_anchor = (current_wall, sample_after)

    def _validate_observation(
        self, candidate: object, *, now: float
    ) -> tuple[dict[str, datetime], datetime]:
        if type(candidate) is not AccountObservation:
            raise GatewayAccountSessionWorkerError("OBSERVATION_TYPE_INVALID")
        observation = cast("AccountObservation", candidate)
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

    def _capture_wall_sample(
        self,
    ) -> tuple[float, float, float, float | None]:
        monotonic_before = self._monotonic_now()
        captured_at = self._wall_clock()
        monotonic_after = self._monotonic_now()
        if monotonic_after < monotonic_before:
            raise GatewayAccountSessionWorkerError("MONOTONIC_CLOCK_REGRESSED")

        anchor = self._wall_monotonic_anchor
        sample_anchor = self._wall_sample_anchor
        if anchor is None or sample_anchor is None:
            logical_wall = captured_at + (monotonic_after - monotonic_before)
            return captured_at, monotonic_after, logical_wall, None

        anchor_wall, anchor_monotonic = anchor
        sample_wall, sample_monotonic = sample_anchor
        if monotonic_before < max(anchor_monotonic, sample_monotonic):
            raise GatewayAccountSessionWorkerError("MONOTONIC_CLOCK_REGRESSED")
        # Both projections advance at the slowest rate the wall clock may
        # legitimately run relative to the monotonic clock; projecting at the
        # full monotonic rate would let a normal rate difference accumulate
        # without bound and eventually reject every refresh.
        slowest_rate = 1.0 - _MAX_CLOCK_RATE_SKEW
        # Regression floor: the previous raw sample was read no later than
        # sample_monotonic and this one no earlier than monotonic_before.
        projected_floor = sample_wall + (monotonic_before - sample_monotonic) * slowest_rate
        projected_after = anchor_wall + (monotonic_after - anchor_monotonic) * slowest_rate
        # The wall sample may have occurred anywhere inside its monotonic
        # bracket. Advancing it by the full span errs toward older provider
        # data; max() also prevents the logical floor from ever moving back.
        logical_wall = max(captured_at + (monotonic_after - monotonic_before), projected_after)
        return captured_at, monotonic_after, logical_wall, projected_floor


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


def _snapshot_generation(snapshot: GatewayAccountSnapshot) -> str | None:
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
    configured: tuple[float, float] | None,
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
