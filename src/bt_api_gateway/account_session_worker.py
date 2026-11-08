"""One owner-thread, read-only provider session that publishes full account state.

The worker is deliberately not a provider SDK adapter. It accepts a trusted
provider object with only connect, read_account, and close operations, and
persists complete replacements through GatewayEventJournal's state-only
stream. It never writes account commands or strategy-attributed positions.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Protocol, cast

from bt_api_base.account_certification_protocol import (
    AccountConfigurationObservation,
    ExchangeServerTimeObservation,
)
from bt_api_base.account_protocol import (
    AccountKey,
    AccountObservation,
    AccountResourceKey,
)

from .account_read_model import (GatewayAccountReadModel, GatewayAccountSessionWorkerError,
    _require_scope_text, _positive_seconds, _clock_resolutions, _clock_value)

from .account_certification import (
    GatewayCertificationFactsError,
    collect_account_configuration,
    collect_exchange_server_time,
)
from .account_position_snapshot import (
    GatewayFullPositionSnapshot,
    GatewayFullPositionSnapshotReceipt,
)
from .account_view_projection import (
    GatewayAccountViewPolicy,
    validate_policy_set,
)
from .event_journal import (
    GatewayAccountSnapshot,
    GatewayEventJournal,
)
from .execution_event_publisher import (
    MAX_EXECUTION_BATCH,
    GatewayExecutionEventError,
    GatewayExecutionEventPublisher,
    GatewayExecutionPublishResult,
)
from .router import GatewayCommandKind, GatewayPrincipal
from .session_guard import LocalAccountSessionGuard, LocalAccountSessionGuardError

_INSTRUMENT_METADATA_ERROR_CODES = frozenset(
    {
        "ACCOUNT_GENERATION_INVALID",
        "EXCHANGE_ID_INVALID",
        "FEED_BINDING_INVALID",
        "INSTRUMENT_ID_INVALID",
        "INSTRUMENT_QUERY_FAILED",
        "INSTRUMENT_QUERY_LATE",
        "INSTRUMENT_QUERY_UNPROVEN",
        "MARKET_BINDING_INVALID",
        "OWNER_THREAD_REQUIRED",
        "PRICE_LIMITS_INVALID",
        "PRICE_LIMITS_PARTIAL",
        "PRICE_TICK_INVALID",
        "PRICE_TICK_UNAVAILABLE",
        "PRODUCT_CLASS_INVALID",
        "PRODUCT_CLASS_UNAVAILABLE",
        "QUOTE_SESSION_CHANGED",
        "QUOTE_SOURCE_UNAVAILABLE",
        "QUOTE_SOURCE_UNTRUSTED",
        "TIMEOUT_INVALID",
        "TRADER_SESSION_CHANGED",
        "TRADER_SESSION_UNREADY",
        "VOLUME_MULTIPLE_INVALID",
    }
)


class GatewayInstrumentMetadataCapability(Protocol):
    """Optional provider capability: fresh instrument metadata for this session.

    A provider-specific adapter (for CTP: ``bt_api_ctp.gateway_instrument_metadata``)
    implements both methods. The Gateway stays provider-neutral: it only
    requires that the provider recognize its own sealed result, that the result
    is bound to the current owner generation, and that it projects to a mapping.
    Provider errors carry a finite ``code``; codes outside
    ``_INSTRUMENT_METADATA_ERROR_CODES`` collapse to ``PROVIDER_FACT_READ_FAILED``.
    """

    def read_instrument_metadata(
        self, *, instrument_id: str, exchange_id: str, generation: str, timeout: float
    ) -> GatewayInstrumentMetadataFact: ...

    def is_current_instrument_metadata(self, value: object) -> bool: ...


class GatewayInstrumentMetadataFact(Protocol):
    """Typed instrument metadata issued by the provider capability."""

    @property
    def account_session_generation(self) -> str: ...

    def to_dict(self) -> dict[str, object]: ...


class GatewayAccountSessionProvider(Protocol):
    """Trusted provider boundary exposing account reads and lifecycle only."""

    def connect(self, *, account_key: AccountKey, generation: str, timeout: float) -> None:
        """Open the selected account read session within the adapter timeout."""

    def read_account(
        self, *, generation: str, timeout: float
    ) -> AccountObservation | GatewayFullPositionSnapshot:
        """Return an observation, optionally with trusted full-position coverage."""

    def close(self) -> bool | None:
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
        clock_resolution_seconds: tuple[float, float] | None = None,
        execution_publisher: GatewayExecutionEventPublisher | None = None,
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
        if execution_publisher is not None:
            # Iteration 60 R2-C: typed terminal-order/per-fill observations.
            if (
                type(execution_publisher) is not GatewayExecutionEventPublisher
                or execution_publisher.journal is not journal
                or execution_publisher.account_key != account_key
                or execution_publisher._account_scope != journal_account_scope
            ):
                raise GatewayAccountSessionWorkerError("INVALID_EXECUTION_PUBLISHER")
            reserved = {state_scope, *(policy.view_scope for policy in canonical_view_policies)}
            if execution_publisher.policy.scopes & reserved:
                raise GatewayAccountSessionWorkerError("EXECUTION_SCOPE_CONFLICT")
            if not callable(getattr(provider, "read_execution_observations", None)) or not callable(
                getattr(provider, "confirm_execution_observations", None)
            ):
                raise GatewayAccountSessionWorkerError("PROVIDER_EXECUTION_EVENTS_UNAVAILABLE")
        self._execution_publisher = execution_publisher
        self._execution_status: str | None = None if execution_publisher is None else "idle"
        self._refresh_interval = _positive_seconds(refresh_interval_seconds)
        self._max_staleness = _positive_seconds(max_staleness_seconds)
        self._request_timeout = _positive_seconds(request_timeout_seconds)

        self._owner_pid = os.getpid()
        self._owner_thread = threading.current_thread()
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
        self._generation: str | None = None
        self._read_model = GatewayAccountReadModel(
            journal, account_key=account_key, journal_account_scope=journal_account_scope,
            state_scope=state_scope, required_coverage=required_coverage,
            assert_current_generation=self._assert_current_generation_owned,
            view_policies=canonical_view_policies, require_open_orders=require_open_orders,
            refresh_interval_seconds=refresh_interval_seconds,
            max_staleness_seconds=max_staleness_seconds,
            request_timeout_seconds=request_timeout_seconds, clock=clock,
            monotonic_clock=monotonic_clock, clock_resolution_seconds=clock_resolution_seconds,
        )
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
    def instrument_metadata_available(self) -> bool:
        """Whether the trusted provider chain exposes an instrument metadata read.

        This is derived from the provider object constructed by the injected
        GatewaySessionOwner factory. It is not a manifest or client setting.
        The read itself still has the provider verify its own sealed result and
        the current owner generation.
        """

        try:
            return all(
                callable(getattr(self._provider, name, None))
                for name in ("read_instrument_metadata", "is_current_instrument_metadata")
            )
        except Exception:
            return False

    @property
    def state(self) -> str:
        if self._state == "ready" and not self.ready:
            return "stale"
        return self._state

    @property
    def session_generation(self) -> str | None:
        return self._generation

    @property
    def read_model(self):
        """The borrowed read model; publishing remains on this owner thread."""
        return self._read_model

    @property
    def latest_snapshot(self) -> GatewayAccountSnapshot | None:
        return self._read_model.latest_snapshot

    @property
    def _latest_snapshot(self):
        return self._read_model._latest_snapshot

    @property
    def _latest_observation(self):
        return self._read_model._latest_observation

    @property
    def _latest_position_source(self):
        return self._read_model._latest_position_source

    @property
    def _next_refresh_monotonic(self):
        return self._read_model._next_refresh_monotonic

    @property
    def ready(self) -> bool:
        return bool(self.read_status()["ready"])

    def read_status(self) -> Mapping[str, object]:
        status = self._read_model.read_status()
        if not self._guard_acquired or self._state != "ready":
            return MappingProxyType({"session_generation": self._generation,
                                     "ready": False, "fresh_for_seconds": 0.0})
        try:
            self._guard.assert_owned()
        except LocalAccountSessionGuardError:
            return MappingProxyType({"session_generation": self._generation,
                                     "ready": False, "fresh_for_seconds": 0.0})
        return status

    def start(self) -> None:
        """Acquire one local owner, connect once, and require a first full baseline."""

        self._check_owner()
        if self._state != "new":
            raise GatewayAccountSessionWorkerError("WORKER_ALREADY_STARTED")
        self._state = "starting"
        generation: str | None = None
        try:
            self._guard_attempted = True
            generation = self._guard.acquire()
            if type(generation) is not str or not generation:
                raise GatewayAccountSessionWorkerError("INVALID_SESSION_GENERATION")
            self._generation = generation
            self._guard_acquired = True
            self._assert_current_generation_owned(generation)
            self._read_model.start_generation(generation)
            self._connect_attempted = True
            self._provider_connect_active = True
            try:
                # The provider is untrusted: check it really returned None.
                result = self._provider.connect(  # type: ignore[func-returns-value]
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
                    if exc.code in {"SESSION_ALREADY_OWNED", "SESSION_RECONCILIATION_REQUIRED"}
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
        self._read_model.invalidate()
        try:
            self._guard.assert_owned()
        except LocalAccountSessionGuardError:
            self._freshness_invalidated = True
            self._state = "ownership_lost"
            self._read_model.invalidate()
            raise GatewayAccountSessionWorkerError("SESSION_OWNERSHIP_LOST") from None
        return self._refresh_impl()

    def maintain(self) -> None:
        """Refresh once when due; this is the sole periodic query path.

        With an execution publisher, every call also drains the provider's
        pending execution observations into the account journal. A failed
        drain is kept in ``execution_status`` and retried on the next call;
        it never changes account-state readiness.
        """

        self._check_owner()
        if self._state not in {"connected", "ready", "refresh_failed"}:
            return
        now = self._monotonic_now()
        due = self._next_refresh_monotonic
        try:
            if due is None or now >= due:
                self.refresh()
        finally:
            if self._execution_publisher is not None and self._state in {
                "connected",
                "ready",
                "refresh_failed",
            }:
                try:
                    self.publish_execution_events()
                except GatewayAccountSessionWorkerError:
                    pass  # recorded in execution_status; retried next call

    @property
    def execution_status(self) -> str | None:
        """``None`` (no publisher), ``idle``, ``published`` or ``failed:<CODE>``."""

        return self._execution_status

    def publish_execution_events(self) -> GatewayExecutionPublishResult | None:
        """Drain pending provider execution observations into the journal once.

        The provider keeps an observation until ``confirm_execution_observations``
        is called after every append of the batch committed; a crash or failure
        before that redelivers it, and the journal's fact ids make the
        republication idempotent. Returns ``None`` without a publisher.
        """

        self._check_owner()
        publisher = self._execution_publisher
        if publisher is None:
            return None
        generation = self._generation
        try:
            if generation is None or self._state not in {"connected", "ready", "refresh_failed"}:
                raise GatewayAccountSessionWorkerError("SESSION_NOT_ACTIVE")
            self._assert_current_generation_owned(generation)
            try:
                items = self._provider.read_execution_observations(  # type: ignore[attr-defined]
                    generation=generation,
                    timeout=self._request_timeout,
                    limit=MAX_EXECUTION_BATCH,
                )
            except Exception:
                raise GatewayAccountSessionWorkerError("EXECUTION_EVENTS_READ_FAILED") from None
            self._assert_current_generation_owned(generation)
            if type(items) is not tuple or len(items) > MAX_EXECUTION_BATCH:
                raise GatewayAccountSessionWorkerError("EXECUTION_EVENTS_INVALID")
            if not items:
                self._execution_status = "idle"
                return GatewayExecutionPublishResult()
            try:
                result = publisher.publish(items)
            except GatewayExecutionEventError as error:
                raise GatewayAccountSessionWorkerError(error.code) from None
            self._assert_current_generation_owned(generation)
            try:
                confirm = getattr(self._provider, "confirm_execution_observations")
                confirmed = confirm(generation=generation, count=len(items))
            except Exception:
                raise GatewayAccountSessionWorkerError("EXECUTION_EVENTS_CONFIRM_FAILED") from None
            if confirmed is not None:
                raise GatewayAccountSessionWorkerError("EXECUTION_EVENTS_CONFIRM_FAILED")
        except GatewayAccountSessionWorkerError as error:
            self._execution_status = "failed:" + error.code
            raise
        self._execution_status = "published"
        return result

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
        self._read_model.close()
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

    def read_instrument_metadata(
        self,
        *,
        instrument_id: str,
        exchange_id: str,
    ) -> GatewayInstrumentMetadataFact:
        """Read one typed instrument row under this ready owner generation."""

        generation = self._active_fact_generation()
        reader = getattr(self._provider, "read_instrument_metadata", None)
        is_current = getattr(self._provider, "is_current_instrument_metadata", None)
        if not callable(reader) or not callable(is_current):
            raise GatewayAccountSessionWorkerError("PROVIDER_FACT_UNAVAILABLE")
        start_monotonic = self._monotonic_now()
        self._assert_current_generation_owned(generation)
        try:
            result = reader(
                instrument_id=instrument_id,
                exchange_id=exchange_id,
                generation=generation,
                timeout=self._request_timeout,
            )
        except Exception as exc:
            code = getattr(exc, "code", None)
            if type(code) is not str or code not in _INSTRUMENT_METADATA_ERROR_CODES:
                code = "PROVIDER_FACT_READ_FAILED"
            raise GatewayAccountSessionWorkerError(code) from None
        finish_monotonic = self._monotonic_now()
        self._assert_current_generation_owned(generation)
        if finish_monotonic < start_monotonic:
            raise GatewayAccountSessionWorkerError("MONOTONIC_CLOCK_REGRESSED")
        if finish_monotonic - start_monotonic > self._request_timeout:
            raise GatewayAccountSessionWorkerError("PROVIDER_RESPONSE_LATE")
        try:
            trusted = is_current(result) is True
            bound = trusted and result.account_session_generation == generation
        except Exception:
            bound = False
        if not bound:
            raise GatewayAccountSessionWorkerError("PROVIDER_FACT_UNAVAILABLE")
        return cast("GatewayInstrumentMetadataFact", result)

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
        self._validate_full_position_source(receipt._source, receipt.observation, generation)
        if receipt.valid_until_ns <= int(self._wall_clock() * 1_000_000_000):
            raise GatewayAccountSessionWorkerError("POSITION_SNAPSHOT_RECEIPT_STALE")

    def _validate_full_position_source(self, source, observation, generation):
        return self._read_model._validate_full_position_source(source, observation, generation)

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
        generation = self._generation
        self._freshness_invalidated = True
        self._state = "refreshing"
        token = None
        try:
            if generation is None or not self._connect_attempted:
                raise GatewayAccountSessionWorkerError("SESSION_NOT_ACTIVE")
            token = self._read_model.begin_refresh()
            try:
                result = self._provider.read_account(generation=generation, timeout=self._request_timeout)
            except BaseException as exc:
                if self._generation == generation:
                    self._read_model.fail_refresh(token)
                if isinstance(exc, Exception):
                    raise GatewayAccountSessionWorkerError("PROVIDER_READ_FAILED") from None
                raise
            if self._generation != generation:
                raise GatewayAccountSessionWorkerError("PROVIDER_RESULT_GENERATION_STALE")
            snapshot = self._read_model.finish_refresh(token, result)
            self._freshness_invalidated = False
            self._state = "ready"
            return snapshot
        except BaseException as exc:
            if self._generation == generation and self._state != "ownership_lost":
                self._state = "refresh_failed"
            if isinstance(exc, GatewayAccountSessionWorkerError):
                raise
            if isinstance(exc, Exception):
                raise GatewayAccountSessionWorkerError("OBSERVATION_INVALID") from None
            raise

    def _assert_current_generation_owned(self, generation: str) -> None:
        try:
            self._guard.assert_owned()
        except LocalAccountSessionGuardError:
            self._freshness_invalidated = True
            self._state = "ownership_lost"
            self._read_model.invalidate()
            raise GatewayAccountSessionWorkerError("SESSION_OWNERSHIP_LOST") from None
        if self._generation != generation:
            raise GatewayAccountSessionWorkerError("PROVIDER_RESULT_GENERATION_STALE")

    def _reset_for_restart(self) -> None:
        self._state = "new"
        self._generation = None
        self._freshness_invalidated = True
        self._guard_attempted = False
        self._guard_acquired = False
        self._connect_attempted = False
        self._provider_connect_active = False
        self._provider_close_confirmed = False

    def _wall_clock(self) -> float:
        return _clock_value(self._clock)

    def _monotonic_now(self) -> float:
        return _clock_value(self._monotonic_clock)

    def _check_owner(self) -> None:
        if os.getpid() != self._owner_pid or threading.current_thread() is not self._owner_thread:
            raise GatewayAccountSessionWorkerError("WORKER_WRONG_THREAD")


__all__ = [
    "GatewayAccountSessionProvider",
    "GatewayAccountSessionWorker",
    "GatewayAccountSessionWorkerError",
]
