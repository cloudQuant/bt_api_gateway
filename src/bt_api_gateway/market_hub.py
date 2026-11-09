"""Owner-thread shared market subscriptions and bounded event replay.

The hub shares provider subscriptions by their complete public market key. A
server-owned registration ID is the only reference token accepted by the
subscription methods; it is never part of an RPC argument. The hub owns actual
provider handles and retains any handle whose release fails so cleanup can be
retried without starting a duplicate upstream subscription.

This module is provider-neutral. It neither imports an SDK nor claims that a
latest event is a complete order-book or ticker snapshot.
"""

from __future__ import annotations

import json
import math
import re
import secrets
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
from types import MappingProxyType
from typing import Any, Protocol, cast

from bt_api_base.market_history_protocol import (
    MAX_MARKET_HISTORY_PAGE_BYTES,
    MarketHistoryPage,
    MarketHistoryRequest,
)
from bt_api_base.market_protocol import (
    MARKET_EVENT_OPERATION,
    MARKET_EVENT_SCHEMA,
    MARKET_EVENT_SCHEMA_VERSION,
    MarketProviderEvent,
    MarketSourceDescriptor,
    MarketSubscriptionKey,
)
from bt_api_base.service_protocol import (
    MAX_REFERENCE_BYTES,
    MAX_WIRE_MESSAGE_BYTES,
    WIRE_PROTOCOL_VERSION,
    WireEnvelope,
    WireHeader,
    WireIdentity,
    WireMessageKind,
    WireRole,
    WireScope,
    encode_envelope,
    envelope_to_wire_mapping,
)

def _market_dispatch_mutation(method):
    """Bracket host-side market mutations without holding the gate lock.

    The installed gate tracks changes and rejects concurrent dispatch. The
    decorated operation may wait for the native owner, so the gate's mutex
    must be released while the method executes. No gate means legacy market
    behavior is unchanged.
    """
    @wraps(method)
    def guarded(self, *args, **kwargs):
        hub = getattr(self, "_hub", self)
        gate = getattr(hub, "_market_dispatch_gate", None)
        if gate is None:
            return method(self, *args, **kwargs)
        # Only explicitly defined, side-effect-free preflight checks run
        # before entering the change barrier.  In particular, an invalid RPC
        # identity or operation must not permanently poison market evidence;
        # any failure after the barrier remains conservatively poisoned.
        preflight = getattr(self, "_market_dispatch_preflight_" + method.__name__, None)
        if preflight is not None:
            preflight(*args, **kwargs)
        # Only operations that reduce authority or release resources may
        # proceed after the shared claim domain has irreversibly closed.
        cleanup = method.__name__ in {"close", "revoke_principal_keys"}
        with gate.market_change(cleanup=cleanup):
            return method(self, *args, **kwargs)
    return guarded


MARKET_READ_AFTER_BOUNDED_OPERATION = "market.read_after_bounded"
MARKET_CLOCK_OPERATION = "market.clock_observation"
MARKET_OPERATIONS = frozenset(
    {
        "market.bootstrap_many",
        "market.subscribe",
        "market.unsubscribe",
        "market.snapshot",
        "market.head",
        "market.read_after",
    }
)
# Potential operations for trusted capability discovery. ``SUPPORTED_OPERATIONS``
# remains the five-operation default for callers that have not configured history.
ASYNC_BOOTSTRAP_OPERATIONS = frozenset(
    {"market.bootstrap_begin", "market.bootstrap_status", "market.bootstrap_cancel"}
)
MARKET_HISTORY_OPERATION = "market.history"
ALL_MARKET_OPERATIONS = MARKET_OPERATIONS | frozenset({MARKET_HISTORY_OPERATION})
MARKET_OPERATIONS_WITH_BOUNDED_READ_AFTER = MARKET_OPERATIONS | frozenset(
    {MARKET_READ_AFTER_BOUNDED_OPERATION}
)
ALL_MARKET_OPERATIONS_WITH_BOUNDED_READ_AFTER = (
    ALL_MARKET_OPERATIONS
    | ASYNC_BOOTSTRAP_OPERATIONS
    | frozenset({MARKET_READ_AFTER_BOUNDED_OPERATION, MARKET_CLOCK_OPERATION})
)
SUPPORTED_OPERATIONS = MARKET_OPERATIONS
DEFAULT_MARKET_READ_LIMIT = 100
MAX_MARKET_READ_LIMIT = 1_000
MAX_MARKET_KEY_UNIVERSE = 1_024
MAX_MARKET_PRINCIPALS = 4_096
MAX_MARKET_REGISTRATIONS = 10_000
MAX_MARKET_REGISTRATION_REFS = 10_000
MAX_TOTAL_MARKET_REPLAY_BYTES = 64 * 1024 * 1024
MAX_MARKET_EVENT_BYTES = 256 * 1024
MAX_MARKET_READ_PAGE_BYTES = 896 * 1024
MAX_MARKET_REPLAY_EVENTS = 10_000
MAX_MARKET_HISTORY_TIMEOUT_SECONDS = 300.0
DEFAULT_MARKET_PROVIDER_POLL_LIMIT = 32
MAX_MARKET_PROVIDER_POLL_LIMIT = 256

_UTC_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_MAPPING_PROXY_TYPE: type[MappingProxyType[Any, Any]] = type(MappingProxyType({}))


class GatewayMarketHubError(RuntimeError):
    """Finite error from market hub state, configuration, or provider edges."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        self.code = code
        self.retryable = retryable
        super().__init__(code)


class GatewayMarketServiceError(GatewayMarketHubError):
    """Finite market RPC validation, registration, or authorization error."""


class MarketProvider(Protocol):
    """Synchronous subscription edge owned by the hub's owner thread.

    A provider implementation must either return a handle for an acquired
    subscription or raise before acquiring one. If it cannot establish that
    guarantee, it needs a provider-specific adapter that retains and exposes
    the uncertain handle instead of retrying this generic operation.

    A successful call must return a non-``None`` handle. Raising or returning
    ``None`` means acquisition did not happen; the hub cannot safely recover a
    handle that the provider acquired but failed to return. Manual-publish
    providers may deliver events through ``GatewayMarketHub.publish`` on the
    owner thread. Providers with worker-thread callbacks may instead implement
    ``MarketProviderPolling`` and queue observations for ``maintain`` to drain.
    """

    def subscribe(self, key: MarketSubscriptionKey, *, generation: str) -> object:
        """Acquire a stream and capture the hub-issued event generation."""

    def unsubscribe(self, handle: object) -> bool | None:
        """Release one handle idempotently, including retries after actual release.

        ``False`` or an exception means the hub retains the exact handle and
        retries it later. The provider must accept that same handle again even
        if the previous call already stopped its upstream subscription.
        """


class MarketProviderSourceDescriber(Protocol):
    """Optional capability to describe the exact active provider source."""

    def describe_source(
        self,
        handle: object,
        *,
        key: MarketSubscriptionKey,
        generation: str,
        stream_id: str,
        epoch: str,
    ) -> MarketSourceDescriptor | None:
        """Return source identity bound to this active handle, or ``None``."""


class MarketProviderPolling(Protocol):
    """Optional nonblocking queue-drain capability for a market provider.

    Implementations retain the Hub-supplied generation with every queued
    observation. The Hub calls ``poll`` on its owner thread with a finite
    per-call limit; callbacks running on other threads must enqueue immutable
    observations and must not publish directly.
    """

    def poll(self, handle: object, *, limit: int) -> tuple[MarketProviderEvent, ...]:
        """Return at most ``limit`` already-queued observations without blocking.

        An empty tuple means the queue is currently drained. The Hub does not
        synthesize events when this optional capability is absent.
        """


class MarketProviderSourceEpochResetting(Protocol):
    """Optional owner-thread handshake for a provider-confirmed source restart.

    Both methods use exact booleans as a finite capability contract. The Hub
    rotates its cursor before acknowledging a pending source transition, then
    skips polling for that stream until a later maintain cycle.
    """

    def source_epoch_reset_required(self, handle: object) -> bool:
        """Return exact ``True`` while this exact handle awaits a new epoch."""

    def acknowledge_source_epoch_reset(self, handle: object, *, epoch: str) -> bool:
        """Accept the exact Hub-generated epoch for the pending transition."""


class MarketHistoryProvider(Protocol):
    """Synchronous read-only history edge with a provider-enforced timeout.

    ``fetch`` must bound its own blocking work by ``timeout_seconds``. The hub
    checks elapsed time when the call returns and rejects a late page, but it
    cannot preempt a provider that ignores the timeout. Calls are never retried
    or cached by the hub.
    """

    def fetch(self, request: MarketHistoryRequest, timeout_seconds: float) -> MarketHistoryPage:
        """Fetch one bounded page for the exact immutable request."""


@dataclass(frozen=True)
class GatewayMarketRegistration:
    """Trusted public call registration resolved outside the RPC payload.

    Strategy-client registrations carry both strategy and run refs, created
    only after the service registry verifies that run. Application/service
    registrations carry neither; they do not invent a strategy identity to
    enter the public market scope. An optional account ref preserves the
    registry's trusted strategy-to-account association without adding account
    data to the shared market stream or its deduplication key.
    """

    principal_ref: str
    execution_domain_ref: str
    strategy_ref: str | None = None
    run_id: str | None = None
    account_ref: str | None = None

    def __post_init__(self) -> None:
        for name in ("principal_ref", "execution_domain_ref"):
            _require_reference(getattr(self, name), "INVALID_REGISTRATION")
        if (self.strategy_ref is None) is not (self.run_id is None):
            raise GatewayMarketHubError("INVALID_REGISTRATION")
        if self.strategy_ref is not None:
            _require_reference(self.strategy_ref, "INVALID_REGISTRATION")
            _require_reference(self.run_id, "INVALID_REGISTRATION")
        if self.account_ref is not None:
            _require_reference(self.account_ref, "INVALID_REGISTRATION")


@dataclass
class _ReplayEntry:
    sequence: int
    envelope: WireEnvelope
    encoded_bytes: int


@dataclass
class _MarketStream:
    key: MarketSubscriptionKey
    epoch: str
    events: deque[_ReplayEntry] = field(default_factory=deque)
    replay_bytes: int = 0
    sequence: int = 0
    handle: object | None = None
    registrations: set[str] = field(default_factory=set)
    pending_refs: dict[str, str] = field(default_factory=dict)
    ref_owners: dict[str, str] = field(default_factory=dict)
    starting: bool = False
    start_uncertain: bool = False
    releasing: bool = False
    pending_release: bool = False
    needs_new_epoch: bool = False
    generation: str | None = None


@dataclass
class _BootstrapJob:
    operation_id: str
    registration_id: str
    principal_ref: str
    registration: GatewayMarketRegistration
    payload: tuple[tuple[MarketSubscriptionKey, bool], ...] | None
    token: str
    deadline: float
    status: str = "pending"
    code: str = ""
    index: int = 0
    phase: str = "start"
    descriptors: dict[MarketSubscriptionKey, MarketSourceDescriptor] = field(default_factory=dict)
    items: list[dict[str, object]] = field(default_factory=list)
    epochs: dict[MarketSubscriptionKey, str] = field(default_factory=dict)
    waiting: dict[MarketSubscriptionKey, tuple[object | None, str | None]] = field(
        default_factory=dict
    )
    result: dict[str, object] | None = None
    result_size: int = 0
    first_reply: bool = False
    refresh_existing: bool = False
    borrowed: dict[MarketSubscriptionKey, str] = field(default_factory=dict)
    owned_handles: dict[MarketSubscriptionKey, tuple[object, str | None]] = field(
        default_factory=dict
    )
    uncertain: set[MarketSubscriptionKey] = field(default_factory=set)


class GatewayMarketHub:
    """Share bounded market streams inside one trusted execution-domain hub.

    ``key_universe`` is the complete stream audience published by the hub.
    A shared PUB audience must be allowed every exported key. A partitioned
    audience may use subsets only when the trusted hosting layer installs a
    per-peer enforcing transport. Topic filters alone are never authorization.
    The endpoint entitlement is separate from registration leases: pruning
    a registration releases upstream refs but does not revoke data access
    from an already-authorized raw SUB socket. Runtime revocation
    (``revoke_principal_keys``) therefore needs a partitioned publisher bound
    with a ``regrant`` callback that rebuilds the enforcing transport with the
    narrower grants; see that method for its exact guarantees. Provider calls and
    mutating operations run on the constructing thread. A fresh opaque
    generation accompanies each provider acquisition; delayed events from an
    older acquisition are rejected before replay or publication.
    """

    def __init__(
        self,
        provider: MarketProvider,
        *,
        key_universe: Collection[MarketSubscriptionKey],
        principal_allowed_keys: Mapping[str, Collection[MarketSubscriptionKey]],
        service_identity: WireIdentity,
        service_scope: WireScope,
        max_replay_events: int = 1_000,
        max_replay_bytes: int = 256 * 1024,
        max_provider_events_per_maintain: int = DEFAULT_MARKET_PROVIDER_POLL_LIMIT,
        publisher: Callable[[WireEnvelope], object] | None = None,
        epoch_factory: Callable[[], str] | None = None,
        history_provider: MarketHistoryProvider | None = None,
        history_timeout_seconds: float | None = None,
        history_key_universe: Collection[MarketSubscriptionKey] | None = None,
        principal_allowed_history_keys: Mapping[str, Collection[MarketSubscriptionKey]]
        | None = None,
        provider_cleanup_confirmed: Callable[[], bool] | None = None,
        bootstrap_clock: Callable[[], float] = time.monotonic,
        bootstrap_timeout_seconds: float = 30.0,
        bootstrap_max_jobs_per_registration: int = 16,
        bootstrap_max_jobs: int = 128,
        bootstrap_max_result_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        if not callable(getattr(provider, "subscribe", None)) or not callable(
            getattr(provider, "unsubscribe", None)
        ):
            raise GatewayMarketHubError("INVALID_PROVIDER")
        async_methods = tuple(
            callable(getattr(provider, name, None))
            for name in ("begin_subscribe", "subscription_ready", "probe_source")
        )
        if any(async_methods) and not all(async_methods):
            raise GatewayMarketHubError("INVALID_ASYNC_PROVIDER")
        if (
            not callable(bootstrap_clock)
            or type(bootstrap_timeout_seconds) not in (int, float)
            or not math.isfinite(bootstrap_timeout_seconds)
            or bootstrap_timeout_seconds <= 0
            or any(
                type(value) is not int or value <= 0
                for value in (
                    bootstrap_max_jobs_per_registration,
                    bootstrap_max_jobs,
                    bootstrap_max_result_bytes,
                )
            )
        ):
            raise GatewayMarketHubError("INVALID_BOOTSTRAP_CONFIGURATION")
        self._async_bootstrap = all(async_methods)
        self._bootstrap_clock = bootstrap_clock
        self._bootstrap_timeout = float(bootstrap_timeout_seconds)
        self._bootstrap_per_registration = bootstrap_max_jobs_per_registration
        self._bootstrap_max_jobs = bootstrap_max_jobs
        self._bootstrap_max_result_bytes = bootstrap_max_result_bytes
        self._bootstrap_jobs: dict[tuple[str, str], _BootstrapJob] = {}
        self._bootstrap_result_bytes = 0
        self._bootstrap_cursor = 0
        if type(max_replay_events) is not int or max_replay_events <= 0:
            raise GatewayMarketHubError("INVALID_REPLAY_LIMIT")
        if max_replay_events > MAX_MARKET_REPLAY_EVENTS:
            raise GatewayMarketHubError("INVALID_REPLAY_LIMIT")
        if type(max_replay_bytes) is not int or max_replay_bytes <= 0:
            raise GatewayMarketHubError("INVALID_REPLAY_LIMIT")
        if (
            type(max_provider_events_per_maintain) is not int
            or not 1 <= max_provider_events_per_maintain <= MAX_MARKET_PROVIDER_POLL_LIMIT
        ):
            raise GatewayMarketHubError("INVALID_PROVIDER_POLL_LIMIT")
        if publisher is not None and not callable(publisher):
            raise GatewayMarketHubError("INVALID_PUBLISHER")
        if epoch_factory is not None and not callable(epoch_factory):
            raise GatewayMarketHubError("INVALID_EPOCH_FACTORY")
        if provider_cleanup_confirmed is not None and not callable(provider_cleanup_confirmed):
            raise GatewayMarketHubError("INVALID_PROVIDER_CLEANUP_CONFIRMATION")
        normalized_history_timeout = _validate_history_configuration(
            history_provider, history_timeout_seconds
        )

        copied_keys = _copy_key_universe(key_universe)
        if len(copied_keys) > MAX_MARKET_KEY_UNIVERSE:
            raise GatewayMarketHubError("KEY_UNIVERSE_TOO_LARGE")
        if len(copied_keys) * max_replay_bytes > MAX_TOTAL_MARKET_REPLAY_BYTES:
            raise GatewayMarketHubError("TOTAL_REPLAY_BUDGET_EXCEEDED")
        copied_acl = _copy_market_acl(principal_allowed_keys, copied_keys)
        partitioned = any(allowed != frozenset(copied_keys) for allowed in copied_acl.values())
        if partitioned and publisher is not None:
            raise GatewayMarketHubError("PARTITIONED_PUBLISHER_REQUIRED")
        copied_history_keys, copied_history_acl = _copy_market_history_acl(
            history_provider,
            copied_keys,
            copied_acl,
            history_key_universe,
            principal_allowed_history_keys,
        )
        _validate_service_wire_scope(service_identity, service_scope)

        self._provider = provider
        self._provider_cleanup_confirmed = provider_cleanup_confirmed
        provider_poll = getattr(provider, "poll", None)
        self._provider_poller = provider_poll if callable(provider_poll) else None
        reset_required = getattr(provider, "source_epoch_reset_required", None)
        acknowledge_reset = getattr(provider, "acknowledge_source_epoch_reset", None)
        self._provider_epoch_resetter: MarketProviderSourceEpochResetting | None = (
            cast("MarketProviderSourceEpochResetting", provider)
            if callable(reset_required) and callable(acknowledge_reset)
            else None
        )
        self._key_universe = frozenset(copied_keys)
        self._principal_allowed_keys = MappingProxyType(copied_acl)
        self._requires_partitioned_audience = partitioned
        self._service_identity = service_identity
        self._service_scope = service_scope
        self._max_replay_events = max_replay_events
        self._max_replay_bytes = max_replay_bytes
        self._max_provider_events_per_maintain = max_provider_events_per_maintain
        self._publisher = publisher
        self._epoch_factory = epoch_factory or (lambda: uuid.uuid4().hex)
        self._history_provider = history_provider
        self._history_timeout_seconds = normalized_history_timeout
        self._history_key_universe = frozenset(copied_history_keys)
        self._principal_allowed_history_keys = MappingProxyType(copied_history_acl)
        self._owner_thread_id = threading.get_ident()
        self._market_dispatch_gate = None
        self._closing = False
        self._provider_poll_cursor = 0
        self._source_diagnostics = {
            "provider_poll_calls": 0,
            "provider_events_polled": 0,
            "provider_events_published": 0,
            "stale_generation_events_dropped": 0,
            "provider_poll_failures": 0,
            "provider_invalid_batches": 0,
            "provider_invalid_events": 0,
            "provider_event_rejections": 0,
            "provider_epoch_resets": 0,
            "provider_epoch_reset_failures": 0,
        }
        self._streams: dict[MarketSubscriptionKey, _MarketStream] = {}
        self._stream_by_id: dict[str, MarketSubscriptionKey] = {}
        self._registration_ref_count = 0
        # Runtime authorization (iteration 60, G2): a monotonic generation,
        # each registration's principal, and per (principal, key) re-grant
        # floors ``(epoch, sequence)``: events at or below a floor were
        # published while that principal was not authorized for the key.
        self._authorization_generation = 1
        self._registration_principals: dict[tuple[MarketSubscriptionKey, str], str] = {}
        self._grant_floors: dict[tuple[str, MarketSubscriptionKey], tuple[str, int]] = {}
        self._regrant: Callable[[Mapping[str, frozenset[str]]], object] | None = None
        self._delivery_suspended = False
        self._authorization_diagnostics = {
            "authorization_revocations": 0,
            "authorization_grants": 0,
            "revoked_registrations": 0,
            "authorization_floor_gaps": 0,
            "publisher_regrant_failures": 0,
        }
        for key in copied_keys:
            if key.stream_id in self._stream_by_id:
                raise GatewayMarketHubError("STREAM_ID_COLLISION")
            self._stream_by_id[key.stream_id] = key
            self._streams[key] = _MarketStream(key=key, epoch=self._new_epoch())

    def install_market_dispatch_gate(self, gate: object) -> None:
        """Bind one trusted owner-local dispatch gate before it is used.

        This is a trusted composition hook, never an RPC entry point. The SDK
        is responsible for validating the exact gate and its account authority.
        """
        self._check_owner()
        if (self._market_dispatch_gate is not None or getattr(gate, "_hub", None) is not self
                or not callable(getattr(gate, "market_change", None))
                or not callable(getattr(gate, "_published_after_success", None))):
            raise GatewayMarketHubError("INVALID_DISPATCH_GATE")
        self._market_dispatch_gate = gate

    @property
    def identity(self) -> WireIdentity:
        """The immutable service identity used on every published event."""
        return self._service_identity

    @property
    def service_identity(self) -> WireIdentity:
        """Alias used by resource factories when validating the hub resource."""
        return self._service_identity

    @property
    def scope(self) -> WireScope:
        """The immutable account-free service scope used on every event."""
        return self._service_scope

    @property
    def service_scope(self) -> WireScope:
        """Alias used by resource factories when validating the hub resource."""
        return self._service_scope

    @property
    def key_universe(self) -> frozenset[MarketSubscriptionKey]:
        """The full immutable set of keys the shared event endpoint can publish."""
        return self._key_universe

    @property
    def authorized_principals(self) -> frozenset[str]:
        """All principals with configured access to this endpoint audience."""
        return frozenset(self._principal_allowed_keys)

    @property
    def requires_partitioned_audience(self) -> bool:
        """Whether a plain whole-endpoint PUB audience would disclose data."""

        return self._requires_partitioned_audience

    @property
    def principal_allowed_keys(
        self,
    ) -> Mapping[str, frozenset[MarketSubscriptionKey]]:
        """The copied trusted principal/key ACL supplied at construction."""
        return self._principal_allowed_keys

    @property
    def supported_operations(self) -> frozenset[str]:
        """Operations available from this configured hub instance."""
        operations = (
            ALL_MARKET_OPERATIONS if self._history_provider is not None else MARKET_OPERATIONS
        )
        if callable(getattr(self._provider, "read_market_login_clock", None)):
            operations = operations | {MARKET_CLOCK_OPERATION}
        return operations | ASYNC_BOOTSTRAP_OPERATIONS if self._async_bootstrap else operations

    @property
    def history_enabled(self) -> bool:
        """Whether a trusted historical data provider was configured."""
        return self._history_provider is not None

    @property
    def history_key_universe(self) -> frozenset[MarketSubscriptionKey]:
        """The separately authorized set of keys accepted by ``market.history``."""
        return self._history_key_universe

    @property
    def principal_allowed_history_keys(
        self,
    ) -> Mapping[str, frozenset[MarketSubscriptionKey]]:
        """The copied per-principal ACL for historical requests."""
        return self._principal_allowed_history_keys

    @property
    def ready(self) -> bool:
        """Whether the publisher is configured and no release is pending."""
        state = self.readiness
        return bool(state["ready"])

    @property
    def readiness(self) -> Mapping[str, object]:
        """Finite readiness counters suitable for service-host preflight."""
        pending = sum(
            1
            for stream in self._streams.values()
            if stream.handle is not None and not stream.registrations and not stream.pending_refs
        )
        active_upstreams = sum(
            1
            for stream in self._streams.values()
            if stream.handle is not None and stream.registrations
        )
        active_registrations = sum(len(stream.registrations) for stream in self._streams.values())
        starting = sum(1 for stream in self._streams.values() if stream.starting)
        ready = not self._closing and self._publisher is not None and pending == 0 and starting == 0
        return MappingProxyType(
            {
                "ready": ready,
                "closing": self._closing,
                "publisher_configured": self._publisher is not None,
                "active_upstreams": active_upstreams,
                "active_registrations": active_registrations,
                "pending_releases": pending,
                "starting_streams": starting,
                "exported_keys": len(self._key_universe),
            }
        )

    @property
    def source_diagnostics(self) -> Mapping[str, int]:
        """Finite counters for owner-thread provider polling and projection."""
        return MappingProxyType(dict(self._source_diagnostics))

    def validate_audience(
        self,
        principal_refs: Collection[str],
        identity: WireIdentity,
        scope: WireScope,
        *,
        partitioned: bool = False,
    ) -> None:
        """Purely preflight the transport audience against this hub's identity.

        The transport must call this before constructing a PUB or RPC socket.
        Partial audiences require explicit per-peer enforcing transport from
        the trusted host; subscription filters alone are not authorization.
        """
        _validate_service_wire_scope(identity, scope)
        if type(partitioned) is not bool:
            raise GatewayMarketHubError("MARKET_AUDIENCE_INVALID")
        if identity != self._service_identity or scope != self._service_scope:
            raise GatewayMarketHubError("SERVICE_WIRE_SCOPE_MISMATCH")
        principals = _copy_principal_refs(principal_refs)
        if not principals:
            raise GatewayMarketHubError("EMPTY_MARKET_AUDIENCE")
        if frozenset(principals) != frozenset(self._principal_allowed_keys):
            raise GatewayMarketHubError("MARKET_AUDIENCE_MISMATCH")
        for principal_ref in principals:
            allowed = self._principal_allowed_keys.get(principal_ref)
            if allowed is None:
                raise GatewayMarketHubError("MARKET_AUDIENCE_DENIED")
            if allowed != self._key_universe and not partitioned:
                raise GatewayMarketHubError("MARKET_AUDIENCE_INCOMPLETE")

    @_market_dispatch_mutation
    def set_publisher(self, publisher: Callable[[WireEnvelope], object]) -> None:
        """Install the owner-thread PUB callback exactly once before use."""
        if self._requires_partitioned_audience:
            raise GatewayMarketHubError("PARTITIONED_PUBLISHER_REQUIRED")
        self._set_publisher(publisher)

    @_market_dispatch_mutation
    def set_partitioned_publisher(
        self,
        publisher: Callable[[WireEnvelope], object],
        *,
        principal_stream_grants: Mapping[str, Collection[str]],
        regrant: Callable[[Mapping[str, frozenset[str]]], object] | None = None,
    ) -> None:
        """Bind a trusted host's per-peer transport with the exact hub ACL.

        This is a trusted local composition interface, not an authentication
        proof. The host is responsible for constructing a transport that
        actually enforces these grants before invoking this method.
        ``regrant(principal_stream_grants)``, when supplied, must make that
        transport enforce new grants (rebuilding peer authorization) and
        return ``True`` only once it does; it enables runtime revocation.
        """
        if regrant is not None and not callable(regrant):
            raise GatewayMarketHubError("PARTITIONED_PUBLISHER_GRANTS_INVALID")

        expected = {
            principal: frozenset(key.stream_id for key in allowed)
            for principal, allowed in self._principal_allowed_keys.items()
        }
        if not isinstance(principal_stream_grants, Mapping):
            raise GatewayMarketHubError("PARTITIONED_PUBLISHER_GRANTS_INVALID")
        try:
            supplied = {
                principal: frozenset(grants)
                for principal, grants in principal_stream_grants.items()
            }
        except (TypeError, ValueError):
            raise GatewayMarketHubError("PARTITIONED_PUBLISHER_GRANTS_INVALID") from None
        if supplied != expected:
            raise GatewayMarketHubError("PARTITIONED_PUBLISHER_GRANTS_INVALID")
        self._set_publisher(publisher)
        self._regrant = regrant

    # -- runtime authorization (iteration 60, acceptance G2) -----------------

    @property
    def authorization_diagnostics(self) -> Mapping[str, int]:
        """Finite counters for runtime grant changes and their enforcement."""
        return MappingProxyType(dict(self._authorization_diagnostics))

    @property
    def authorization_generation(self) -> int:
        """Monotonic generation; it increases on every runtime grant change."""
        return self._authorization_generation

    def principal_stream_grants(self) -> Mapping[str, frozenset[str]]:
        """The current ``principal -> stream ids`` grants the transport must enforce."""
        return MappingProxyType(
            {
                principal: frozenset(key.stream_id for key in allowed)
                for principal, allowed in self._principal_allowed_keys.items()
            }
        )

    def grant_floor(self, principal_ref: str, key: MarketSubscriptionKey) -> tuple[str, int] | None:
        """``(epoch, sequence)`` below which ``principal_ref`` may not read ``key``."""
        return self._grant_floors.get((principal_ref, key))

    @_market_dispatch_mutation
    def revoke_principal_keys(
        self,
        principal_ref: str,
        keys: Collection[MarketSubscriptionKey] | None = None,
    ) -> Mapping[str, object]:
        """Revoke ``keys`` (default: all) from a running principal.

        In order: the ACL is narrowed (every later subscribe, head, snapshot
        and read_after of those keys is refused), the principal's
        registrations on them are dropped (releasing an upstream nobody else
        holds), and the bound ``regrant`` callback rebuilds the enforcing
        transport so the principal's open SUB sockets stop receiving them.
        If ``regrant`` is missing or fails, publication is suspended for
        every stream (fail closed) until ``regrant`` succeeds through
        ``resume_delivery``. Frames already delivered, or queued in a peer's
        socket before the rebuild, cannot be recalled: a receiver must drop
        frames it receives after learning of the revocation and resync.
        """
        self._check_owner()
        self._ensure_open()
        allowed = self._principal_allowed_keys.get(principal_ref)
        if allowed is None:
            raise GatewayMarketHubError("UNKNOWN_PRINCIPAL")
        if not self._requires_partitioned_audience:
            raise GatewayMarketHubError("REVOCATION_REQUIRES_PARTITIONED_PUBLISHER")
        revoked = frozenset(allowed) if keys is None else frozenset(keys)
        if any(type(key) is not MarketSubscriptionKey for key in revoked):
            raise GatewayMarketHubError("INVALID_MARKET_KEY")
        revoked &= allowed
        acl = dict(self._principal_allowed_keys)
        acl[principal_ref] = frozenset(allowed - revoked)
        self._principal_allowed_keys = MappingProxyType(acl)
        self._authorization_generation += 1
        self._authorization_diagnostics["authorization_revocations"] += 1
        for job in self._bootstrap_jobs.values():
            if (
                job.principal_ref == principal_ref
                and job.payload is not None
                and any(key in revoked for key, _ in job.payload)
                and (job.status == "pending" or (job.status == "active" and not job.first_reply))
            ):
                self._bootstrap_cancel(job, "MARKET_KEY_DENIED", final="rejected")
        dropped = 0
        for key in revoked:
            stream = self._streams[key]
            self._grant_floors.pop((principal_ref, key), None)
            owned = {
                registration
                for registration in stream.registrations
                if (self._registration_principals.get((key, registration)) == principal_ref)
            }
            for registration in owned:
                stream.registrations.discard(registration)
                stream.ref_owners.pop(registration, None)
                self._registration_principals.pop((key, registration), None)
                self._registration_ref_count -= 1
                dropped += 1
            if not stream.registrations and not stream.pending_refs and stream.handle is not None:
                self._attempt_release(stream)
        self._authorization_diagnostics["revoked_registrations"] += dropped
        transport = self._apply_regrant()
        return MappingProxyType(
            {
                "principal_ref": principal_ref,
                "authorization_generation": self._authorization_generation,
                "revoked_stream_ids": tuple(sorted(key.stream_id for key in revoked)),
                "dropped_registrations": dropped,
                "transport_enforced": transport,
            }
        )

    @_market_dispatch_mutation
    def grant_principal_keys(
        self, principal_ref: str, keys: Collection[MarketSubscriptionKey]
    ) -> Mapping[str, object]:
        """Re-grant ``keys``; history published while revoked stays unreadable.

        Each re-granted key records a floor at the stream's current
        ``(epoch, head)``: ``read_after`` below it reports an
        ``authorization_floor`` gap and ``snapshot`` hides an older event, so
        the principal must resync from the floor, never from data it was not
        authorized for. The principal must subscribe again.
        """
        self._check_owner()
        self._ensure_open()
        allowed = self._principal_allowed_keys.get(principal_ref)
        if allowed is None:
            raise GatewayMarketHubError("UNKNOWN_PRINCIPAL")
        if not self._requires_partitioned_audience:
            raise GatewayMarketHubError("REVOCATION_REQUIRES_PARTITIONED_PUBLISHER")
        granted = frozenset(keys)
        if not granted or any(
            type(key) is not MarketSubscriptionKey or key not in self._key_universe
            for key in granted
        ):
            raise GatewayMarketHubError("INVALID_MARKET_KEY")
        added = granted - allowed
        acl = dict(self._principal_allowed_keys)
        acl[principal_ref] = frozenset(allowed | granted)
        self._principal_allowed_keys = MappingProxyType(acl)
        self._authorization_generation += 1
        self._authorization_diagnostics["authorization_grants"] += 1
        for key in added:
            stream = self._streams[key]
            self._grant_floors[(principal_ref, key)] = (stream.epoch, stream.sequence)
        transport = self._apply_regrant()
        return MappingProxyType(
            {
                "principal_ref": principal_ref,
                "authorization_generation": self._authorization_generation,
                "granted_stream_ids": tuple(sorted(key.stream_id for key in added)),
                "transport_enforced": transport,
            }
        )

    @_market_dispatch_mutation
    def resume_delivery(self) -> bool:
        """Retry ``regrant`` after a failure; delivery resumes only on success."""
        self._check_owner()
        return self._apply_regrant()

    @property
    def delivery_suspended(self) -> bool:
        return self._delivery_suspended

    def _apply_regrant(self) -> bool:
        regrant = self._regrant
        grants = self.principal_stream_grants()
        ok = False
        if regrant is not None:
            try:
                ok = regrant(grants) is True
            except Exception:
                ok = False
        if not ok:
            self._authorization_diagnostics["publisher_regrant_failures"] += 1
        self._delivery_suspended = not ok
        return ok

    def _set_publisher(self, publisher: Callable[[WireEnvelope], object]) -> None:
        self._check_owner()
        if not callable(publisher):
            raise GatewayMarketHubError("INVALID_PUBLISHER")
        if self._publisher is not None:
            raise GatewayMarketHubError("PUBLISHER_ALREADY_CONFIGURED")
        if any(
            stream.handle is not None or stream.registrations for stream in self._streams.values()
        ):
            raise GatewayMarketHubError("PUBLISHER_CONFIGURED_AFTER_SUBSCRIBE")
        self._publisher = publisher

    @_market_dispatch_mutation
    def subscribe(
        self,
        principal_ref: str,
        key: MarketSubscriptionKey,
        registration_id: str,
        *,
        require_source_descriptor: bool = False,
    ) -> Mapping[str, object]:
        """Acquire one registration ref, starting the provider only on first use."""
        self._check_owner()
        self._ensure_open()
        stream = self._authorize_key(principal_ref, key)
        _require_reference(registration_id, "INVALID_REGISTRATION")
        if type(require_source_descriptor) is not bool:
            raise GatewayMarketHubError("INVALID_SOURCE_DESCRIPTOR_REQUEST")
        if stream.starting or stream.releasing:
            raise GatewayMarketHubError("STREAM_TRANSITION_IN_PROGRESS", retryable=True)
        if stream.start_uncertain:
            raise GatewayMarketHubError("PROVIDER_SUBSCRIBE_OUTCOME_UNKNOWN", retryable=True)

        if registration_id in stream.pending_refs or (
            stream.pending_refs and not stream.registrations
        ):
            raise GatewayMarketHubError("STREAM_TRANSITION_IN_PROGRESS", retryable=True)
        already_subscribed = registration_id in stream.registrations
        if already_subscribed:
            descriptor = self._describe_source(stream) if require_source_descriptor else None
            return self._subscription_result(
                stream,
                already_subscribed=True,
                source_descriptor=descriptor,
            )
        if self._registration_ref_count >= MAX_MARKET_REGISTRATION_REFS:
            raise GatewayMarketHubError("REGISTRATION_REF_LIMIT_EXCEEDED")

        if (
            stream.handle is not None
            and not stream.registrations
            and not stream.pending_refs
            and not self._attempt_release(stream)
        ):
            # A failed final unsubscribe leaves an uncertain handle. Retry the
            # idempotent release first; it must never be advertised as a live
            # shared upstream to a new registration.
            raise GatewayMarketHubError("PROVIDER_UNSUBSCRIBE_FAILED", retryable=True)

        acquired_here = False
        if stream.handle is None:
            if self._publisher is None:
                raise GatewayMarketHubError("PUBLISHER_NOT_CONFIGURED")
            next_epoch = self._new_epoch() if stream.needs_new_epoch else None
            if next_epoch == stream.epoch:
                raise GatewayMarketHubError("EPOCH_FACTORY_REUSED_VALUE")
            generation = secrets.token_urlsafe(32)
            _require_reference(generation, "INVALID_SOURCE_GENERATION")
            stream.starting = True
            try:
                handle = self._provider.subscribe(key, generation=generation)
            except Exception:
                # A provider may have accepted a connection before reporting
                # failure. With no returned handle, this Hub cannot prove a
                # later retry would not create a duplicate upstream stream.
                stream.start_uncertain = True
                raise GatewayMarketHubError("PROVIDER_SUBSCRIBE_FAILED", retryable=True) from None
            finally:
                stream.starting = False
            if handle is None:
                stream.start_uncertain = True
                raise GatewayMarketHubError("INVALID_PROVIDER_HANDLE", retryable=True)
            stream.handle = handle
            stream.generation = generation
            acquired_here = True
            if next_epoch is not None:
                stream.epoch = next_epoch
                stream.sequence = 0
                stream.events.clear()
                stream.replay_bytes = 0
                stream.needs_new_epoch = False

        descriptor = None
        if require_source_descriptor:
            try:
                descriptor = self._describe_source(stream)
            except GatewayMarketHubError:
                if acquired_here:
                    # The caller is not registered until its descriptor has
                    # been validated. Release a newly acquired source now; if
                    # release is uncertain, _attempt_release retains its exact
                    # handle for the ordinary owner-thread retry path.
                    self._attempt_release(stream)
                raise

        # Reuse a retained handle after an uncertain failed stop; never start a
        # second upstream stream while the original handle is still owned.
        stream.registrations.add(registration_id)
        self._registration_principals[(key, registration_id)] = principal_ref
        self._registration_ref_count += 1
        stream.pending_release = False
        return self._subscription_result(
            stream,
            already_subscribed=False,
            source_descriptor=descriptor,
        )

    @_market_dispatch_mutation
    def unsubscribe(
        self,
        principal_ref: str,
        key: MarketSubscriptionKey,
        registration_id: str,
    ) -> Mapping[str, object]:
        """Drop one registration ref and retry a pending final provider release."""
        self._check_owner()
        stream = self._authorize_key(principal_ref, key)
        _require_reference(registration_id, "INVALID_REGISTRATION")
        if stream.starting or stream.releasing:
            raise GatewayMarketHubError("STREAM_TRANSITION_IN_PROGRESS", retryable=True)
        if stream.start_uncertain:
            raise GatewayMarketHubError("PROVIDER_SUBSCRIBE_OUTCOME_UNKNOWN", retryable=True)
        if registration_id in stream.registrations:
            stream.registrations.remove(registration_id)
            stream.ref_owners.pop(registration_id, None)
            self._registration_principals.pop((key, registration_id), None)
            self._registration_ref_count -= 1
        if (
            not stream.registrations
            and not stream.pending_refs
            and stream.handle is not None
            and not self._attempt_release(stream)
        ):
            raise GatewayMarketHubError("PROVIDER_UNSUBSCRIBE_FAILED", retryable=True)
        return MappingProxyType(
            {
                "stream_id": key.stream_id,
                "epoch": stream.epoch,
                "head": stream.sequence,
                "upstream_released": stream.handle is None,
            }
        )

    def registration_active(self, key: MarketSubscriptionKey, registration_id: str) -> bool:
        """Return whether a trusted registration currently owns this stream."""
        self._check_owner()
        stream = self._stream(key)
        _require_reference(registration_id, "INVALID_REGISTRATION")
        return registration_id in stream.registrations

    @_market_dispatch_mutation
    def clock_observation(self, principal_ref: str, key: MarketSubscriptionKey,
                          registration_id: str) -> Mapping[str, object]:
        """Observe a current source using only this hub's trusted stream state."""
        self._check_owner()
        self._ensure_open()
        stream = self._authorize_key(principal_ref, key)
        _require_reference(registration_id, "INVALID_REGISTRATION")
        if (registration_id not in stream.registrations
                or self._registration_principals.get((key, registration_id)) != principal_ref
                or stream.handle is None or stream.generation is None
                or stream.pending_release or stream.starting or stream.releasing
                or stream.start_uncertain or stream.needs_new_epoch):
            raise GatewayMarketHubError("MARKET_SOURCE_UNAVAILABLE")
        method = getattr(self._provider, "read_market_login_clock", None)
        if not callable(method):
            raise GatewayMarketHubError("CAPABILITY_UNAVAILABLE")
        handle, generation, epoch = stream.handle, stream.generation, stream.epoch
        try:
            value = method(handle, key=key, generation=generation,
                           stream_id=key.stream_id, epoch=epoch)
        except Exception:
            raise GatewayMarketHubError("CLOCK_SOURCE_UNAVAILABLE") from None
        if (not isinstance(value, Mapping) or self._authorize_key(principal_ref, key) is not stream
                or stream.handle is not handle or stream.generation != generation
                or stream.epoch != epoch or registration_id not in stream.registrations
                or self._registration_principals.get((key, registration_id)) != principal_ref
                or stream.pending_release or stream.starting or stream.releasing
                or stream.start_uncertain or stream.needs_new_epoch):
            raise GatewayMarketHubError("MARKET_SOURCE_UNAVAILABLE")
        return value

    @_market_dispatch_mutation
    def dispatch_clock_observation(
        self, principal_ref: str, key: MarketSubscriptionKey, registration_id: str,
        *, epoch: str, sequence: int, message_id: str,
    ) -> Mapping[str, object]:
        """Get a same-owner source observation for the exact published tick.

        The client cursor is only an index; native sequence values are taken
        exclusively from the retained, successfully published server frame.
        The source monotonic value never leaves this process.
        """
        self._check_owner()
        self._ensure_open()
        gate = self._market_dispatch_gate
        if gate is None:
            raise GatewayMarketHubError("CAPABILITY_UNAVAILABLE")
        try:
            provider_sequence, provider_subscription_epoch = gate._published_tick(
                principal_ref, key, registration_id, epoch, sequence, message_id
            )
        except Exception:
            raise GatewayMarketHubError("MARKET_EVIDENCE_UNAVAILABLE") from None
        stream = self._authorize_key(principal_ref, key)
        handle, generation = stream.handle, stream.generation
        read = getattr(self._provider, "read_market_tick_clock", None)
        if not callable(read):
            raise GatewayMarketHubError("CAPABILITY_UNAVAILABLE")
        try:
            result = read(handle, key=key, generation=generation, stream_id=key.stream_id,
                          epoch=epoch, provider_sequence=provider_sequence,
                          provider_subscription_epoch=provider_subscription_epoch)
        except Exception:
            raise GatewayMarketHubError("CLOCK_SOURCE_UNAVAILABLE", retryable=True) from None
        if (type(result) is not tuple or len(result) != 2 or type(result[0]) is not dict
                or type(result[1]) is not int or self._authorize_key(principal_ref, key) is not stream
                or stream.handle is not handle or stream.generation != generation
                or stream.epoch != epoch or registration_id not in stream.registrations
                or self._registration_principals.get((key, registration_id)) != principal_ref
                or stream.pending_release or stream.starting or stream.releasing
                or stream.start_uncertain or stream.needs_new_epoch):
            raise GatewayMarketHubError("MARKET_SOURCE_UNAVAILABLE")
        try:
            gate._published_tick(principal_ref, key, registration_id, epoch, sequence, message_id)
            gate._clock_after_source(registration_id, principal_ref, key, result[0],
                                     observed_monotonic_ns=result[1])
        except Exception:
            raise GatewayMarketHubError("MARKET_EVIDENCE_UNAVAILABLE") from None
        return result[0]

    @_market_dispatch_mutation
    def maintain(self, active_registration_ids: Collection[str]) -> Mapping[str, int]:
        """Explicitly prune refs absent from the owner-supplied active registry.

        No timer or assumed lease expiry releases a provider subscription. Any
        stop failure leaves its exact handle in the stream for the next
        ``maintain``, idempotent ``unsubscribe``, or ``close`` attempt.
        """
        self._check_owner()
        active = frozenset(
            _copy_reference_set(active_registration_ids, "INVALID_ACTIVE_REGISTRATIONS")
        )
        for job in tuple(self._bootstrap_jobs.values()):
            if job.registration_id not in active and (
                job.status in {"pending", "active"}
                or (job.status == "unknown" and job.code == "BOOTSTRAP_STALE")
            ):
                self._bootstrap_cancel(job, "REGISTRATION_EXPIRED", final="cancelled")
        self._bootstrap_advance(32)
        pruned = 0
        released = 0
        for stream in self._streams.values():
            if stream.starting or stream.releasing:
                continue
            stale = (stream.registrations - active) - stream.ref_owners.keys()
            if stale:
                stream.registrations.difference_update(stale)
                for registration in stale:
                    self._registration_principals.pop((stream.key, registration), None)
                    stream.ref_owners.pop(registration, None)
                pruned += len(stale)
                self._registration_ref_count -= len(stale)
            if (
                not stream.registrations
                and not stream.pending_refs
                and stream.handle is not None
                and self._attempt_release(stream)
            ):
                released += 1
        pending = sum(
            1
            for stream in self._streams.values()
            if stream.handle is not None and not stream.registrations and not stream.pending_refs
        )
        self._bootstrap_forget_inactive(active)
        self._drain_provider_events()
        return MappingProxyType(
            {
                "pruned_registrations": pruned,
                "released_upstreams": released,
                "pending_releases": pending,
            }
        )

    def _drain_provider_events(self) -> None:
        """Poll active provider handles fairly under a strict per-maintain cap."""
        poller = self._provider_poller
        if poller is None and self._provider_epoch_resetter is None:
            return
        streams = tuple(
            stream
            for stream in self._streams.values()
            if (
                stream.handle is not None
                and (stream.registrations or stream.pending_refs)
                and not stream.starting
                and not stream.releasing
                and not stream.pending_release
                and stream.generation is not None
            )
        )
        if not streams:
            self._provider_poll_cursor = 0
            return

        poll_limit = self._max_provider_events_per_maintain
        cursor = self._provider_poll_cursor % len(streams)
        exhausted: set[int] = set()
        calls = 0
        returned_events = 0
        while calls < poll_limit and returned_events < poll_limit and len(exhausted) < len(streams):
            stream_index = None
            for offset in range(len(streams)):
                candidate = (cursor + offset) % len(streams)
                if candidate not in exhausted:
                    stream_index = candidate
                    break
            if stream_index is None:
                break

            stream = streams[stream_index]
            cursor = (stream_index + 1) % len(streams)
            self._provider_poll_cursor = cursor
            calls += 1
            resetter = self._provider_epoch_resetter
            if resetter is not None:
                try:
                    required = resetter.source_epoch_reset_required(stream.handle)
                    if type(required) is not bool:
                        self._source_diagnostics["provider_epoch_reset_failures"] += 1
                        exhausted.add(stream_index)
                        continue
                    if required is True:
                        new_epoch = self.reset_stream_epoch(stream.key)
                        acknowledged = resetter.acknowledge_source_epoch_reset(
                            stream.handle,
                            epoch=new_epoch,
                        )
                        if type(acknowledged) is not bool or acknowledged is not True:
                            self._source_diagnostics["provider_epoch_reset_failures"] += 1
                            exhausted.add(stream_index)
                            continue
                        self._source_diagnostics["provider_epoch_resets"] += 1
                        exhausted.add(stream_index)
                        continue
                except Exception:
                    self._source_diagnostics["provider_epoch_reset_failures"] += 1
                    exhausted.add(stream_index)
                    continue
            if not stream.registrations or poller is None:
                exhausted.add(stream_index)
                continue
            self._source_diagnostics["provider_poll_calls"] += 1
            try:
                batch = poller(stream.handle, limit=1)
            except Exception:
                self._source_diagnostics["provider_poll_failures"] += 1
                exhausted.add(stream_index)
                continue
            if type(batch) is not tuple or len(batch) > 1:
                self._source_diagnostics["provider_invalid_batches"] += 1
                exhausted.add(stream_index)
                continue
            if not batch:
                exhausted.add(stream_index)
                continue

            event = batch[0]
            returned_events += 1
            self._source_diagnostics["provider_events_polled"] += 1
            if type(event) is not MarketProviderEvent:
                self._source_diagnostics["provider_invalid_events"] += 1
                continue
            try:
                self.publish(
                    stream.key,
                    event.data,
                    event.observed_at_utc,
                    generation=event.generation,
                )
            except GatewayMarketHubError as error:
                if error.code == "STALE_SOURCE_GENERATION":
                    self._source_diagnostics["stale_generation_events_dropped"] += 1
                else:
                    self._source_diagnostics["provider_event_rejections"] += 1
            except Exception:
                self._source_diagnostics["provider_event_rejections"] += 1
            else:
                self._source_diagnostics["provider_events_published"] += 1

    @_market_dispatch_mutation
    def publish(
        self,
        key: MarketSubscriptionKey,
        data: Mapping[str, Any],
        observed_at_utc: str,
        *,
        generation: str,
    ) -> WireEnvelope:
        """Store before push, accepting events only from the active acquisition.

        The generation is provider-owned acquisition context and never appears
        in the public event. A stale callback cannot advance the current cursor.
        """
        self._check_owner()
        self._ensure_open()
        stream = self._stream(key)
        if type(generation) is not str or generation != stream.generation:
            raise GatewayMarketHubError("STALE_SOURCE_GENERATION")
        if stream.handle is None or not stream.registrations or stream.pending_release:
            raise GatewayMarketHubError("STREAM_NOT_ACTIVE")
        if stream.starting or stream.releasing:
            raise GatewayMarketHubError("STREAM_TRANSITION_IN_PROGRESS", retryable=True)
        publisher = self._publisher
        if publisher is None:
            raise GatewayMarketHubError("PUBLISHER_NOT_CONFIGURED")
        if self._delivery_suspended:
            # A revocation whose transport rebuild is unconfirmed: no frame may
            # reach a socket that might still carry the revoked grants.
            raise GatewayMarketHubError("DELIVERY_SUSPENDED", retryable=True)
        if not isinstance(data, Mapping) or any(type(name) is not str for name in data):
            raise GatewayMarketHubError("INVALID_EVENT_DATA")
        _validate_utc_timestamp(observed_at_utc, "INVALID_OBSERVED_AT")

        sequence = stream.sequence + 1
        try:
            envelope = WireEnvelope(
                header=WireHeader(
                    protocol_version=WIRE_PROTOCOL_VERSION,
                    kind=WireMessageKind.EVENT,
                    message_id=uuid.uuid4().hex,
                    correlation_id=None,
                    identity=self._service_identity,
                    scope=self._service_scope,
                    operation=MARKET_EVENT_OPERATION,
                    schema_id=MARKET_EVENT_SCHEMA,
                    schema_version=MARKET_EVENT_SCHEMA_VERSION,
                    sent_at_utc=observed_at_utc,
                    stream_id=key.stream_id,
                    stream_epoch=stream.epoch,
                    sequence=sequence,
                ),
                payload={
                    "key": key.to_dict(),
                    "data": dict(data),
                },
            )
            encoded_size = len(encode_envelope(envelope, max_bytes=MAX_MARKET_EVENT_BYTES))
        except GatewayMarketHubError:
            raise
        except Exception:
            raise GatewayMarketHubError("INVALID_EVENT") from None
        if encoded_size > self._max_replay_bytes:
            raise GatewayMarketHubError("EVENT_EXCEEDS_REPLAY_BYTE_LIMIT")

        stream.sequence = sequence
        stream.events.append(_ReplayEntry(sequence, envelope, encoded_size))
        stream.replay_bytes += encoded_size
        self._trim_replay(stream)

        try:
            outcome = publisher(envelope)
        except Exception:
            # The sequence and bounded replay entry are already committed in
            # memory. A failed push cannot erase a record needed for recovery.
            raise GatewayMarketHubError("PUBLISHER_FAILED", retryable=True) from None
        if outcome is False or (outcome is not None and outcome is not True):
            raise GatewayMarketHubError("PUBLISHER_FAILED", retryable=True)
        if self._market_dispatch_gate is not None:
            self._market_dispatch_gate._published_after_success(key, envelope)
        return envelope

    def snapshot(
        self, key: MarketSubscriptionKey, *, principal_ref: str | None = None
    ) -> Mapping[str, object]:
        """Return the latest retained event, explicitly not a full market state."""
        self._check_owner()
        stream = self._stream(key)
        latest = stream.events[-1].envelope if stream.events else None
        floor = None if principal_ref is None else self._grant_floors.get((principal_ref, key))
        if (
            latest is not None
            and floor is not None
            and floor[0] == stream.epoch
            and latest.header.sequence <= floor[1]
        ):
            latest = None  # published while this principal was not authorized
        return MappingProxyType(
            {
                "snapshot_kind": "latest_event",
                "complete": False,
                "stream_id": key.stream_id,
                "epoch": stream.epoch,
                "head": stream.sequence,
                "event": latest,
            }
        )

    def head(self, key: MarketSubscriptionKey) -> Mapping[str, object]:
        """Return the current stream cursor and replay floor."""
        self._check_owner()
        stream = self._stream(key)
        latest = stream.events[-1].envelope if stream.events else None
        observed = None if latest is None else latest.header.sent_at_utc
        return MappingProxyType(
            {
                "stream_id": key.stream_id,
                "epoch": stream.epoch,
                "head": stream.sequence,
                "oldest_sequence": _oldest_sequence(stream),
                "latest_observed_at_utc": observed,
            }
        )

    def read_after(
        self,
        key: MarketSubscriptionKey,
        *,
        epoch: str,
        after: int,
        limit: int = DEFAULT_MARKET_READ_LIMIT,
        principal_ref: str | None = None,
    ) -> Mapping[str, object]:
        """Read a bounded page only for the exact current stream epoch.

        With ``principal_ref``, a cursor below that principal's re-grant floor
        is an ``authorization_floor`` gap: events published while it was
        revoked are never returned.

        An epoch mismatch or a cursor older than retained replay returns an
        explicit gap with no partial events; callers must resynchronize from
        the separately labeled ``latest_event`` snapshot or a source-specific
        complete-state mechanism.
        """
        self._check_owner()
        stream = self._stream(key)
        _require_reference(epoch, "INVALID_EPOCH")
        _validate_cursor(after, limit)
        oldest = _oldest_sequence(stream)
        gap_reason: str | None = None
        if epoch != stream.epoch:
            gap_reason = "epoch_mismatch"
        elif oldest is not None and after < oldest - 1:
            gap_reason = "cursor_too_old"
        elif after > stream.sequence:
            raise GatewayMarketHubError("CURSOR_AHEAD")
        if gap_reason is None and principal_ref is not None:
            floor = self._grant_floors.get((principal_ref, key))
            if floor is not None and floor[0] == stream.epoch and after < floor[1]:
                gap_reason = "authorization_floor"
                self._authorization_diagnostics["authorization_floor_gaps"] += 1

        if gap_reason is not None:
            events: tuple[WireEnvelope, ...] = ()
            next_after = after
            has_more = False
        else:
            candidates = [entry for entry in stream.events if entry.sequence > after]
            selected: list[_ReplayEntry] = []
            page_bytes = 0
            for entry in candidates:
                if len(selected) >= limit:
                    break
                if page_bytes + entry.encoded_bytes > MAX_MARKET_READ_PAGE_BYTES:
                    break
                selected.append(entry)
                page_bytes += entry.encoded_bytes
            events = tuple(entry.envelope for entry in selected)
            next_after = selected[-1].sequence if selected else after
            has_more = len(selected) < len(candidates)

        return MappingProxyType(
            {
                "stream_id": key.stream_id,
                "epoch": stream.epoch,
                "head": stream.sequence,
                "oldest_sequence": oldest,
                "after": after,
                "next_after": next_after,
                "limit": limit,
                "has_more": has_more,
                "gap": gap_reason is not None,
                "gap_reason": gap_reason,
                "events": events,
            }
        )

    def fetch_history(
        self, principal_ref: str, request: MarketHistoryRequest
    ) -> Mapping[str, object]:
        """Fetch one authorized, bounded history page without changing hub state.

        History access is independently authorized by the trusted public
        registration and full-key ACL; a live subscription is not required.
        The provider receives the exact request and explicit timeout once.
        """
        self._check_owner()
        self._ensure_open()
        if self._history_provider is None or self._history_timeout_seconds is None:
            raise GatewayMarketHubError("HISTORY_NOT_CONFIGURED")
        if type(request) is not MarketHistoryRequest:
            raise GatewayMarketHubError("INVALID_HISTORY_REQUEST")
        self._authorize_history_key(principal_ref, request.key)

        started = time.monotonic()
        try:
            page = self._history_provider.fetch(request, self._history_timeout_seconds)
        except Exception:
            raise GatewayMarketHubError("HISTORY_PROVIDER_FAILED") from None
        elapsed = time.monotonic() - started
        if not math.isfinite(elapsed) or elapsed > self._history_timeout_seconds:
            raise GatewayMarketHubError("HISTORY_PROVIDER_TIMEOUT")
        if type(page) is not MarketHistoryPage:
            raise GatewayMarketHubError("INVALID_HISTORY_PAGE")
        if page.request != request:
            raise GatewayMarketHubError("HISTORY_REQUEST_MISMATCH")

        try:
            result = page.to_dict()
            encoded = json.dumps(
                result,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8", errors="strict")
        except Exception:
            raise GatewayMarketHubError("INVALID_HISTORY_PAGE") from None
        if len(encoded) > MAX_MARKET_HISTORY_PAGE_BYTES:
            raise GatewayMarketHubError("HISTORY_PAGE_TOO_LARGE")
        try:
            MarketHistoryPage.from_dict(json.loads(encoded.decode("utf-8")))
        except Exception:
            raise GatewayMarketHubError("INVALID_HISTORY_PAGE") from None
        return MappingProxyType(result)

    @_market_dispatch_mutation
    def reset_stream_epoch(self, key: MarketSubscriptionKey) -> str:
        """Rotate the public cursor after a provider-confirmed source reconnect.

        This does not change the active acquisition generation. The provider
        must drain, tag, or discard native queued events from before its source
        reconnect before publishing under the still-active generation.
        """
        self._check_owner()
        self._ensure_open()
        stream = self._stream(key)
        if stream.starting or stream.releasing:
            raise GatewayMarketHubError("STREAM_TRANSITION_IN_PROGRESS", retryable=True)
        old_epoch = stream.epoch
        new_epoch = self._new_epoch()
        if new_epoch == old_epoch:
            raise GatewayMarketHubError("EPOCH_FACTORY_REUSED_VALUE")
        stream.epoch = new_epoch
        stream.sequence = 0
        stream.events.clear()
        stream.replay_bytes = 0
        stream.needs_new_epoch = False
        return new_epoch

    @_market_dispatch_mutation
    def close(self) -> None:
        """Release handles or accept trusted confirmation of whole-provider cleanup.

        The optional callback is supplied by the owning composition, not a
        client. Only exact True confirms that the borrowed provider is closed.
        """
        self._check_owner()
        if any(stream.starting for stream in self._streams.values()):
            raise GatewayMarketHubError("PROVIDER_START_IN_PROGRESS", retryable=True)
        for job in self._bootstrap_jobs.values():
            if job.status in {"pending", "active"} or (
                job.status == "unknown" and job.code == "BOOTSTRAP_STALE"
            ):
                self._bootstrap_cancel(job, "HUB_CLOSED", final="cancelled")
            if job.status == "cancelling":
                while job.index < len(job.payload or ()):
                    self._bootstrap_cleanup_step(job)
        confirmed = False
        if self._provider_cleanup_confirmed is not None:
            try:
                confirmed = self._provider_cleanup_confirmed() is True
            except Exception:
                confirmed = False
        if confirmed:
            self._closing = True
            for stream in self._streams.values():
                stream.handle = None
                stream.generation = None
                stream.start_uncertain = False
                stream.pending_release = False
                stream.registrations.clear()
                stream.pending_refs.clear()
                stream.ref_owners.clear()
            self._registration_ref_count = 0
            self._registration_principals.clear()
            return
        if any(stream.start_uncertain for stream in self._streams.values()):
            raise GatewayMarketHubError("PROVIDER_SUBSCRIBE_OUTCOME_UNKNOWN", retryable=True)
        self._closing = True
        failed = 0
        for stream in self._streams.values():
            self._registration_ref_count -= len(stream.registrations)
            stream.registrations.clear()
            stream.pending_refs.clear()
            stream.ref_owners.clear()
        self._registration_principals.clear()
        for stream in self._streams.values():
            if stream.handle is not None and not self._attempt_release(stream):
                failed += 1
        if failed:
            raise GatewayMarketHubError("PROVIDER_UNSUBSCRIBE_FAILED", retryable=True)

    def _bootstrap_cancel(self, job: _BootstrapJob, code: str, *, final: str) -> None:
        if job.result_size:
            self._bootstrap_result_bytes -= job.result_size
            job.result_size = 0
            job.result = None
        job.items.clear()
        job.descriptors.clear()
        job.status = "cancelling"
        job.code = code
        job.phase = final
        job.index = 0
        if not job.payload:
            self._bootstrap_check_cleanup(job)

    def _bootstrap_cleanup_step(self, job: _BootstrapJob) -> None:
        payload = job.payload or ()
        if job.index < len(payload):
            key, _ = payload[job.index]
            job.index += 1
            stream = self._streams[key]
            owned = False
            if stream.pending_refs.get(job.registration_id) == job.token:
                del stream.pending_refs[job.registration_id]
                if key not in job.borrowed:
                    self._registration_ref_count -= 1
                    owned = True
            if stream.ref_owners.get(job.registration_id) == job.token:
                stream.ref_owners.pop(job.registration_id, None)
                stream.registrations.discard(job.registration_id)
                self._registration_principals.pop((key, job.registration_id), None)
                self._registration_ref_count -= 1
                owned = True
            if owned and not stream.registrations and not stream.pending_refs:
                if stream.start_uncertain:
                    job.waiting[key] = (None, None)
                elif stream.handle is not None:
                    handle, generation = stream.handle, stream.generation
                    if not self._attempt_release(stream):
                        job.waiting[key] = (handle, generation)
        self._bootstrap_check_cleanup(job)

    def _bootstrap_check_cleanup(self, job: _BootstrapJob) -> None:
        for key, (handle, generation) in tuple(job.waiting.items()):
            stream = self._streams[key]
            if handle is None:
                if not stream.start_uncertain:
                    del job.waiting[key]
            elif (
                stream.handle is not handle
                or stream.generation != generation
                or stream.registrations
                or stream.pending_refs
            ):
                del job.waiting[key]
        if job.index >= len(job.payload or ()) and not job.waiting:
            job.status = job.phase

    def _bootstrap_forget_inactive(self, active: frozenset[str]) -> None:
        for ident, job in tuple(self._bootstrap_jobs.items()):
            if job.registration_id not in active and (
                job.status in {"cancelled", "rejected"}
                or (
                    job.status == "unknown"
                    and job.code != "BOOTSTRAP_STALE"
                    and not any(self._streams[key].start_uncertain for key in job.uncertain)
                )
            ):
                self._bootstrap_result_bytes -= job.result_size
                del self._bootstrap_jobs[ident]

    def _bootstrap_advance(self, budget: int) -> None:
        jobs = tuple(self._bootstrap_jobs.values())
        if not jobs:
            return
        for _ in range(budget):
            job = jobs[self._bootstrap_cursor % len(jobs)]
            self._bootstrap_cursor = (self._bootstrap_cursor + 1) % len(jobs)
            if job.status == "cancelling":
                self._bootstrap_cleanup_step(job)
                continue
            if job.status != "pending":
                continue
            if self._bootstrap_clock() >= job.deadline:
                self._bootstrap_cancel(job, "BOOTSTRAP_TIMEOUT", final="rejected")
                continue
            if not self.ready or self.delivery_suspended:
                continue
            try:
                self._bootstrap_step(job)
            except GatewayMarketHubError as exc:
                self._bootstrap_cancel(job, exc.code, final="rejected")
            except Exception:
                self._bootstrap_cancel(job, "BOOTSTRAP_FAILED", final="rejected")

    def _bootstrap_step(self, job: _BootstrapJob) -> None:
        assert job.payload is not None
        if job.index == len(job.payload):
            result = {"operation_id": job.operation_id, "status": "active", "items": job.items}
            try:
                encoded = json.dumps(
                    result, ensure_ascii=False, allow_nan=False, separators=(",", ":")
                ).encode("utf-8", errors="strict")
            except Exception:
                raise GatewayMarketHubError("INVALID_BOOTSTRAP_REPLY") from None
            if len(encoded) > MAX_WIRE_MESSAGE_BYTES - 8192:
                raise GatewayMarketHubError("BATCH_REPLY_TOO_LARGE")
            delta = len(encoded) - job.result_size
            if self._bootstrap_result_bytes + delta > self._bootstrap_max_result_bytes:
                raise GatewayMarketHubError("BOOTSTRAP_RESULT_CAPACITY")
            job.result = result
            job.result_size = len(encoded)
            self._bootstrap_result_bytes += delta
            job.status = "active"
            return
        key, require_descriptor = job.payload[job.index]
        stream = self._authorize_key(job.principal_ref, key)
        if stream.pending_refs.get(job.registration_id) != job.token:
            raise GatewayMarketHubError("BOOTSTRAP_STALE")
        borrowed_owner = job.borrowed.get(key)
        if borrowed_owner is not None and (
            stream.ref_owners.get(job.registration_id) != borrowed_owner
            or self._registration_principals.get((key, job.registration_id)) != job.principal_ref
        ):
            raise GatewayMarketHubError("BOOTSTRAP_STALE")
        if job.phase == "start":
            if stream.handle is None:
                if stream.start_uncertain:
                    raise GatewayMarketHubError("PROVIDER_SUBSCRIBE_OUTCOME_UNKNOWN")
                next_epoch = self._new_epoch() if stream.needs_new_epoch else None
                if next_epoch == stream.epoch:
                    raise GatewayMarketHubError("EPOCH_FACTORY_REUSED_VALUE")
                generation = secrets.token_urlsafe(32)
                try:
                    handle = self._provider.begin_subscribe(key, generation=generation)  # type: ignore[attr-defined]
                except Exception:
                    stream.start_uncertain = True
                    raise GatewayMarketHubError("PROVIDER_SUBSCRIBE_OUTCOME_UNKNOWN") from None
                if handle is None:
                    stream.start_uncertain = True
                    raise GatewayMarketHubError("PROVIDER_SUBSCRIBE_OUTCOME_UNKNOWN")
                stream.handle, stream.generation = handle, generation
                stream.pending_release = False
                if next_epoch is not None:
                    stream.epoch, stream.sequence = next_epoch, 0
                    stream.events.clear()
                    stream.replay_bytes = 0
                    stream.needs_new_epoch = False
            job.phase = "ready"
            return
        if stream.handle is None or stream.generation is None:
            raise GatewayMarketHubError("BOOTSTRAP_STALE")
        if job.phase == "ready":
            try:
                ready = self._provider.subscription_ready(stream.handle)  # type: ignore[attr-defined]
            except Exception:
                raise GatewayMarketHubError("PROVIDER_SUBSCRIBE_FAILED") from None
            if type(ready) is not bool:
                raise GatewayMarketHubError("PROVIDER_SUBSCRIBE_FAILED")
            if ready:
                job.phase = "descriptor" if require_descriptor else "activate"
            return
        if job.phase == "descriptor":
            try:
                descriptor = self._provider.probe_source(  # type: ignore[attr-defined]
                    stream.handle,
                    key=key,
                    generation=stream.generation,
                    stream_id=key.stream_id,
                    epoch=stream.epoch,
                )
                if descriptor is None:
                    return
                if type(descriptor) is not MarketSourceDescriptor:
                    raise ValueError
                descriptor = MarketSourceDescriptor.from_dict(descriptor.to_dict())
                if (
                    descriptor.key != key
                    or descriptor.stream_id != key.stream_id
                    or descriptor.epoch != stream.epoch
                    or descriptor.provider != key.instrument.provider
                ):
                    raise ValueError
            except Exception:
                raise GatewayMarketHubError("MARKET_SOURCE_DESCRIPTOR_UNAVAILABLE") from None
            job.descriptors[key] = descriptor
            job.phase = "activate"
            return
        if job.phase != "activate":
            raise GatewayMarketHubError("BOOTSTRAP_FAILED")
        descriptor = job.descriptors.get(key)
        if descriptor is not None and descriptor.epoch != stream.epoch:
            raise GatewayMarketHubError("MARKET_SOURCE_DESCRIPTOR_UNAVAILABLE")
        snapshot = dict(self.snapshot(key, principal_ref=job.principal_ref))
        event = snapshot["event"]
        snapshot["event"] = None if event is None else dict(_envelope_mapping(event))
        item = {
            "subscription": dict(
                self._subscription_result(
                    stream,
                    already_subscribed=borrowed_owner is not None,
                    source_descriptor=descriptor,
                )
            ),
            "snapshot": snapshot,
            "head": dict(self.head(key)),
        }
        try:
            item_size = len(
                json.dumps(item, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode(
                    "utf-8", errors="strict"
                )
            )
        except Exception:
            raise GatewayMarketHubError("INVALID_BOOTSTRAP_REPLY") from None
        if job.result_size + item_size > MAX_WIRE_MESSAGE_BYTES - 8192:
            raise GatewayMarketHubError("BATCH_REPLY_TOO_LARGE")
        if self._bootstrap_result_bytes + item_size > self._bootstrap_max_result_bytes:
            raise GatewayMarketHubError("BOOTSTRAP_RESULT_CAPACITY")
        self._bootstrap_result_bytes += item_size
        job.result_size += item_size
        del stream.pending_refs[job.registration_id]
        if borrowed_owner is None:
            stream.registrations.add(job.registration_id)
            stream.ref_owners[job.registration_id] = job.token
            self._registration_principals[(key, job.registration_id)] = job.principal_ref
            assert stream.handle is not None
            job.owned_handles[key] = (stream.handle, stream.generation)
        job.epochs[key] = stream.epoch
        job.items.append(item)
        job.index += 1
        job.phase = "start"

    def _bootstrap_view(self, job: _BootstrapJob) -> dict[str, object]:
        if job.status == "active":
            stale = any(
                key not in self._principal_allowed_keys.get(job.principal_ref, ())
                or self._streams[key].ref_owners.get(job.registration_id)
                != job.borrowed.get(key, job.token)
                or self._streams[key].epoch != job.epochs.get(key)
                for key, _ in job.payload or ()
            )
            if stale:
                if not job.first_reply:
                    self._bootstrap_cancel(job, "BOOTSTRAP_STALE", final="rejected")
                else:
                    if job.result_size:
                        self._bootstrap_result_bytes -= job.result_size
                    job.result_size = 0
                    job.result = None
                    job.items.clear()
                    job.descriptors.clear()
                    job.status = "unknown"
                    job.code = "BOOTSTRAP_STALE"
        if job.status == "active":
            assert job.result is not None
            return job.result
        result: dict[str, object] = {"operation_id": job.operation_id, "status": job.status}
        if job.status in {"cancelling", "cancelled", "rejected", "unknown"}:
            result["code"] = job.code
        if job.status == "unknown":
            if job.code == "BOOTSTRAP_STALE":
                job.uncertain = {
                    key
                    for key, _ in job.payload or ()
                    if (
                        self._streams[key].ref_owners.get(job.registration_id)
                        == job.borrowed.get(key, job.token)
                    )
                    or (
                        key in job.owned_handles
                        and self._streams[key].handle is job.owned_handles[key][0]
                        and self._streams[key].generation == job.owned_handles[key][1]
                        and not self._streams[key].registrations
                        and not self._streams[key].pending_refs
                    )
                }
            result["uncertain_stream_ids"] = tuple(sorted(key.stream_id for key in job.uncertain))
        return result

    def _authorize_key(self, principal_ref: str, key: MarketSubscriptionKey) -> _MarketStream:
        _require_reference(principal_ref, "INVALID_PRINCIPAL_REF")
        allowed = self._principal_allowed_keys.get(principal_ref)
        if allowed is None:
            raise GatewayMarketHubError("UNKNOWN_PRINCIPAL")
        stream = self._stream(key)
        if key not in allowed:
            raise GatewayMarketHubError("MARKET_KEY_DENIED")
        return stream

    def _authorize_history_key(self, principal_ref: str, key: MarketSubscriptionKey) -> None:
        _require_reference(principal_ref, "INVALID_PRINCIPAL_REF")
        allowed = self._principal_allowed_history_keys.get(principal_ref)
        if allowed is None:
            raise GatewayMarketHubError("UNKNOWN_PRINCIPAL")
        if type(key) is not MarketSubscriptionKey:
            raise GatewayMarketHubError("INVALID_MARKET_KEY")
        if key not in self._history_key_universe:
            raise GatewayMarketHubError("HISTORY_KEY_NOT_EXPORTED")
        if key not in allowed:
            raise GatewayMarketHubError("MARKET_KEY_DENIED")

    def _stream(self, key: MarketSubscriptionKey) -> _MarketStream:
        if type(key) is not MarketSubscriptionKey:
            raise GatewayMarketHubError("INVALID_MARKET_KEY")
        stream = self._streams.get(key)
        if stream is None:
            raise GatewayMarketHubError("MARKET_KEY_NOT_EXPORTED")
        return stream

    def _subscription_result(
        self,
        stream: _MarketStream,
        *,
        already_subscribed: bool,
        source_descriptor: MarketSourceDescriptor | None = None,
    ) -> Mapping[str, object]:
        result: dict[str, object] = {
            "stream_id": stream.key.stream_id,
            "epoch": stream.epoch,
            "head": stream.sequence,
            "oldest_sequence": _oldest_sequence(stream),
            "already_subscribed": already_subscribed,
        }
        if source_descriptor is not None:
            result["source_descriptor"] = source_descriptor.to_dict()
        return MappingProxyType(result)

    def _describe_source(self, stream: _MarketStream) -> MarketSourceDescriptor:
        handle = stream.handle
        generation = stream.generation
        if handle is None or generation is None:
            raise GatewayMarketHubError("MARKET_SOURCE_DESCRIPTOR_UNAVAILABLE")
        try:
            describe = getattr(self._provider, "describe_source", None)
            if not callable(describe):
                raise ValueError("source descriptor capability is unavailable")
            descriptor = describe(
                handle,
                key=stream.key,
                generation=generation,
                stream_id=stream.key.stream_id,
                epoch=stream.epoch,
            )
            if type(descriptor) is not MarketSourceDescriptor:
                raise ValueError("invalid source descriptor")
            # Re-parse the public representation at this provider boundary so
            # malformed or forged instances cannot bypass the wire contract.
            descriptor = MarketSourceDescriptor.from_dict(descriptor.to_dict())
            if (
                descriptor.key != stream.key
                or descriptor.stream_id != stream.key.stream_id
                or descriptor.epoch != stream.epoch
                or descriptor.provider != stream.key.instrument.provider
            ):
                raise ValueError("source descriptor is bound to another stream")
        except Exception:
            raise GatewayMarketHubError("MARKET_SOURCE_DESCRIPTOR_UNAVAILABLE") from None
        return descriptor

    def _trim_replay(self, stream: _MarketStream) -> None:
        while stream.events and (
            len(stream.events) > self._max_replay_events
            or stream.replay_bytes > self._max_replay_bytes
        ):
            expired = stream.events.popleft()
            stream.replay_bytes -= expired.encoded_bytes

    def _attempt_release(self, stream: _MarketStream) -> bool:
        handle = stream.handle
        if handle is None:
            stream.pending_release = False
            return True
        if stream.releasing:
            return False
        stream.releasing = True
        try:
            result = self._provider.unsubscribe(handle)
        except Exception:
            stream.pending_release = True
            return False
        finally:
            stream.releasing = False
        if result is False or (result is not None and result is not True):
            stream.pending_release = True
            return False
        stream.handle = None
        stream.pending_release = False
        stream.generation = None
        stream.needs_new_epoch = True
        return True

    def _new_epoch(self) -> str:
        try:
            epoch = self._epoch_factory()
        except Exception:
            raise GatewayMarketHubError("EPOCH_GENERATION_FAILED") from None
        _require_reference(epoch, "INVALID_EPOCH")
        return epoch

    def _ensure_open(self) -> None:
        if self._closing:
            raise GatewayMarketHubError("HUB_CLOSED")

    def _check_owner(self) -> None:
        if threading.get_ident() != self._owner_thread_id:
            raise GatewayMarketHubError("OWNER_THREAD_REQUIRED")


class GatewayMarketService:
    """RPC adapter for registration-scoped reads and shared market refs."""

    def __init__(
        self,
        hub: GatewayMarketHub,
        *,
        registrations: Mapping[str, GatewayMarketRegistration] | None = None,
        enable_bounded_read_after: bool = False,
    ) -> None:
        if type(hub) is not GatewayMarketHub:
            raise GatewayMarketServiceError("INVALID_MARKET_HUB")
        if registrations is None:
            registrations = {}
        if type(enable_bounded_read_after) is not bool:
            raise GatewayMarketServiceError("INVALID_BOUNDED_READ_AFTER_FLAG")
        if not isinstance(registrations, Mapping):
            raise GatewayMarketServiceError("INVALID_REGISTRATIONS")
        if len(registrations) > MAX_MARKET_REGISTRATIONS:
            raise GatewayMarketServiceError("REGISTRATION_LIMIT_EXCEEDED")
        copied: dict[str, GatewayMarketRegistration] = {}
        for registration_id, registration in registrations.items():
            self._validate_registration(hub, registration_id, registration)
            copied[registration_id] = registration
        self._hub = hub
        self._registrations = copied
        self._enable_bounded_read_after = enable_bounded_read_after

    @property
    def ready(self) -> bool:
        """Whether the underlying hub can accept calls and publish events."""
        return self._hub.ready

    @property
    def readiness(self) -> Mapping[str, object]:
        """The hub's finite readiness projection."""
        return self._hub.readiness

    @property
    def supported_operations(self) -> frozenset[str]:
        """Configured operation set for resource and capability advertisement."""
        operations = self._hub.supported_operations
        if self._enable_bounded_read_after:
            operations = operations | frozenset({MARKET_READ_AFTER_BOUNDED_OPERATION})
        return operations

    @_market_dispatch_mutation
    def register_registration(
        self, registration_id: str, registration: GatewayMarketRegistration
    ) -> None:
        """Bind a server-generated ID to its immutable trusted call context."""
        self._hub._check_owner()
        self._validate_registration(self._hub, registration_id, registration)
        existing = self._registrations.get(registration_id)
        if any(
            job.registration_id == registration_id and job.registration != registration
            for job in self._hub._bootstrap_jobs.values()
        ):
            raise GatewayMarketServiceError("REGISTRATION_REBIND_DENIED")
        if existing is not None and existing != registration:
            raise GatewayMarketServiceError("REGISTRATION_REBIND_DENIED")
        if existing is None and len(self._registrations) >= MAX_MARKET_REGISTRATIONS:
            raise GatewayMarketServiceError("REGISTRATION_LIMIT_EXCEEDED")
        self._registrations[registration_id] = registration

    @_market_dispatch_mutation
    def maintain(self, active_registration_ids: Collection[str]) -> Mapping[str, int]:
        """Prune local contexts and their hub refs using an owner registry view."""
        self._hub._check_owner()
        active = frozenset(
            _copy_reference_set(active_registration_ids, "INVALID_ACTIVE_REGISTRATIONS")
        )
        result = self._hub.maintain(active)
        for registration_id in tuple(self._registrations):
            if registration_id not in active:
                del self._registrations[registration_id]
        return result

    def _market_dispatch_preflight_handle(
        self,
        operation: str,
        *,
        principal_ref: str,
        scope: WireScope,
        arguments: Mapping[str, object],
        registration_id: str,
        result_fits: Callable[[Mapping[str, object]], bool] | None = None,
    ) -> None:
        """Reject invalid RPC identity/operation without mutating the Hub.

        Only exact wire dictionaries are prevalidated here.  Arbitrary local
        mappings and any provider or result callbacks remain inside the
        change barrier, where uncertain or partial mutations fail closed.
        """
        self._hub._check_owner()
        if type(operation) is not str or operation not in self.supported_operations:
            raise GatewayMarketServiceError("UNSUPPORTED_OPERATION")
        self._resolve_registration(principal_ref, scope, registration_id)
        if type(arguments) is not dict:
            return
        if any(type(name) is not str for name in arguments):
            raise GatewayMarketServiceError("INVALID_ARGUMENTS")
        if self._hub._async_bootstrap and operation in {"market.subscribe", "market.bootstrap_many"}:
            raise GatewayMarketServiceError("ASYNC_BOOTSTRAP_REQUIRED")
        if operation in ASYNC_BOOTSTRAP_OPERATIONS:
            if not _plain_wire_tree(arguments):
                return
            if operation == "market.bootstrap_begin":
                if set(arguments) not in (
                    {"operation_id", "subscriptions"},
                    {"operation_id", "subscriptions", "refresh_existing"},
                ):
                    raise GatewayMarketServiceError("INVALID_ARGUMENTS")
            else:
                _require_exact_arguments(arguments, {"operation_id"})
            operation_id = arguments["operation_id"]
            if type(operation_id) is not str or re.fullmatch(r"[0-9a-f]{32}", operation_id) is None:
                raise GatewayMarketServiceError("INVALID_OPERATION_ID")
            if operation == "market.bootstrap_begin":
                if type(arguments.get("refresh_existing", False)) is not bool:
                    raise GatewayMarketServiceError("INVALID_ARGUMENTS")
                items = arguments["subscriptions"]
                if type(items) not in (list, tuple) or not 1 <= len(items) <= 20:
                    raise GatewayMarketServiceError("INVALID_BOOTSTRAP_BATCH")
                seen = set()
                for item in items:
                    if (type(item) is not dict or set(item) not in (
                            {"key"}, {"key", "require_source_descriptor"})
                            or type(item.get("require_source_descriptor", False)) is not bool):
                        raise GatewayMarketServiceError("INVALID_BOOTSTRAP_BATCH")
                    key = _parse_key(item["key"])
                    if key in seen:
                        raise GatewayMarketServiceError("DUPLICATE_MARKET_KEY")
                    seen.add(key)
            return
        if operation == "market.bootstrap_many":
            _require_exact_arguments(arguments, {"subscriptions"})
            items = arguments["subscriptions"]
            if type(items) not in (list, tuple) or not 1 <= len(items) <= 20:
                raise GatewayMarketServiceError("INVALID_BOOTSTRAP_BATCH")
            # Per-item rejections have an existing structured reply; their
            # validation in _handle_bootstrap_many occurs before provider use.
            return
        simple_operations = {
            "market.subscribe", "market.unsubscribe", "market.snapshot", "market.head",
            "market.read_after", MARKET_READ_AFTER_BOUNDED_OPERATION, MARKET_CLOCK_OPERATION,
            MARKET_HISTORY_OPERATION,
        }
        if operation not in simple_operations:
            return
        fields = set(arguments)
        if operation == "market.subscribe":
            if fields not in ({"key"}, {"key", "require_source_descriptor"}):
                raise GatewayMarketServiceError("INVALID_ARGUMENTS")
            if ("require_source_descriptor" in arguments
                    and type(arguments["require_source_descriptor"]) is not bool):
                raise GatewayMarketServiceError("INVALID_ARGUMENTS")
        elif operation in {"market.read_after", MARKET_READ_AFTER_BOUNDED_OPERATION}:
            _require_exact_arguments(arguments, {"key", "epoch", "after", "limit"})
        elif operation == MARKET_HISTORY_OPERATION:
            _require_exact_arguments(arguments, {"key", "start_time_utc", "end_time_utc", "limit"})
        elif operation == MARKET_CLOCK_OPERATION and fields == {"key", "epoch", "sequence", "message_id"}:
            pass
        else:
            _require_exact_arguments(arguments, {"key"})
        # Decoded wire values are built-in JSON trees.  Never call a user
        # supplied Mapping or value method before the change barrier.
        if not _plain_wire_tree(arguments):
            return
        if operation == MARKET_HISTORY_OPERATION:
            request = _parse_history_request(arguments)
            self._hub._authorize_history_key(principal_ref, request.key)
            return
        key = _parse_key(arguments["key"])
        self._hub._authorize_key(principal_ref, key)
        if (operation not in {"market.subscribe", "market.unsubscribe"}
                and not self._hub.registration_active(key, registration_id)):
            raise GatewayMarketServiceError("MARKET_SUBSCRIPTION_REQUIRED")
        if operation in {"market.read_after", MARKET_READ_AFTER_BOUNDED_OPERATION}:
            if type(arguments["epoch"]) is not str:
                raise GatewayMarketServiceError("INVALID_EPOCH")
            try:
                _validate_cursor(arguments["after"], arguments["limit"])
            except GatewayMarketHubError as exc:
                raise GatewayMarketServiceError(exc.code, retryable=exc.retryable) from None
        elif operation == MARKET_CLOCK_OPERATION and fields == {"key", "epoch", "sequence", "message_id"}:
            if (any(type(arguments[name]) is not str or not arguments[name]
                    or arguments[name] != arguments[name].strip() or len(arguments[name]) > 256
                    for name in ("epoch", "message_id"))
                    or type(arguments["sequence"]) is not int or arguments["sequence"] <= 0):
                raise GatewayMarketServiceError("MARKET_EVIDENCE_UNAVAILABLE")

    @_market_dispatch_mutation
    def handle(
        self,
        operation: str,
        *,
        principal_ref: str,
        scope: WireScope,
        arguments: Mapping[str, object],
        registration_id: str,
        result_fits: Callable[[Mapping[str, object]], bool] | None = None,
    ) -> Mapping[str, object]:
        """Handle one exact market RPC under a trusted strategy-run mapping."""
        self._hub._check_owner()
        if type(operation) is not str or operation not in self.supported_operations:
            raise GatewayMarketServiceError("UNSUPPORTED_OPERATION")
        self._resolve_registration(principal_ref, scope, registration_id)
        raw = _require_arguments(arguments)
        if self._hub._async_bootstrap and operation in {
            "market.subscribe",
            "market.bootstrap_many",
        }:
            raise GatewayMarketServiceError("ASYNC_BOOTSTRAP_REQUIRED")
        if operation in ASYNC_BOOTSTRAP_OPERATIONS:
            return self._handle_async_bootstrap(
                operation, principal_ref, registration_id, raw, result_fits
            )
        if operation == "market.bootstrap_many":
            return self._handle_bootstrap_many(
                principal_ref=principal_ref,
                registration_id=registration_id,
                raw=raw,
            )
        require_source_descriptor = False
        if operation == "market.subscribe":
            if set(raw) == {"key"}:
                pass
            elif set(raw) == {"key", "require_source_descriptor"}:
                requested_descriptor = raw["require_source_descriptor"]
                if type(requested_descriptor) is not bool:
                    raise GatewayMarketServiceError("INVALID_ARGUMENTS")
                require_source_descriptor = requested_descriptor
            else:
                raise GatewayMarketServiceError("INVALID_ARGUMENTS")
        elif operation == MARKET_HISTORY_OPERATION:
            expected = {"key", "start_time_utc", "end_time_utc", "limit"}
        elif operation in {"market.read_after", MARKET_READ_AFTER_BOUNDED_OPERATION}:
            expected = {"key", "epoch", "after", "limit"}
        elif operation == MARKET_CLOCK_OPERATION and set(raw) == {"key", "epoch", "sequence", "message_id"}:
            expected = {"key", "epoch", "sequence", "message_id"}
        else:
            expected = {"key"}
        if operation != "market.subscribe":
            _require_exact_arguments(raw, expected)
        if operation == MARKET_HISTORY_OPERATION:
            request = _parse_history_request(raw)
            try:
                return self._hub.fetch_history(principal_ref, request)
            except GatewayMarketHubError as exc:
                raise GatewayMarketServiceError(exc.code, retryable=exc.retryable) from None

        key = _parse_key(raw["key"])
        self._hub._authorize_key(principal_ref, key)

        if operation == "market.subscribe":
            try:
                return self._hub.subscribe(
                    principal_ref,
                    key,
                    registration_id,
                    require_source_descriptor=require_source_descriptor,
                )
            except GatewayMarketHubError as exc:
                raise GatewayMarketServiceError(exc.code, retryable=exc.retryable) from None
        if operation == "market.unsubscribe":
            return self._hub.unsubscribe(principal_ref, key, registration_id)
        if not self._hub.registration_active(key, registration_id):
            raise GatewayMarketServiceError("MARKET_SUBSCRIPTION_REQUIRED")
        if operation == MARKET_CLOCK_OPERATION:
            try:
                if set(raw) == {"key", "epoch", "sequence", "message_id"}:
                    return self._hub.dispatch_clock_observation(
                        principal_ref, key, registration_id, epoch=raw["epoch"],
                        sequence=raw["sequence"], message_id=raw["message_id"]
                    )
                return self._hub.clock_observation(principal_ref, key, registration_id)
            except GatewayMarketHubError as exc:
                raise GatewayMarketServiceError(exc.code, retryable=exc.retryable) from None
        if operation == "market.head":
            return self._hub.head(key)
        if operation == "market.snapshot":
            result = dict(self._hub.snapshot(key, principal_ref=principal_ref))
            event = result["event"]
            result["event"] = None if event is None else _envelope_mapping(event)
            return MappingProxyType(result)

        epoch = raw.get("epoch")
        after = raw.get("after")
        limit = raw["limit"]
        if type(epoch) is not str:
            raise GatewayMarketServiceError("INVALID_EPOCH")
        try:
            batch = self._hub.read_after(
                key,
                epoch=epoch,
                after=after,  # type: ignore[arg-type]  # the hub validates the exact type.
                limit=limit,  # type: ignore[arg-type]  # the hub validates the exact type.
                principal_ref=principal_ref,
            )
        except GatewayMarketHubError as exc:
            raise GatewayMarketServiceError(exc.code, retryable=exc.retryable) from None
        result = dict(batch)
        envelopes = tuple(cast("tuple[WireEnvelope, ...]", batch["events"]))
        result["events"] = tuple(_envelope_mapping(event) for event in envelopes)
        if operation == MARKET_READ_AFTER_BOUNDED_OPERATION:
            if result_fits is None or not callable(result_fits):
                raise GatewayMarketServiceError("CAPABILITY_UNAVAILABLE")
            return self._fit_read_after_reply(
                result,
                envelopes=envelopes,
                result_fits=result_fits,
            )
        return MappingProxyType(result)

    @staticmethod
    def _fit_read_after_reply(
        result: Mapping[str, object],
        *,
        envelopes: tuple[WireEnvelope, ...],
        result_fits: Callable[[Mapping[str, object]], bool],
    ) -> Mapping[str, object]:
        """Return the largest continuous replay prefix fitting the real reply.

        The trusted registry callback checks the complete normalized service
        reply against both the server frame limit and the caller's requested
        reply limit.  Event count and the hub's event-page byte cap remain
        independent bounds.
        """
        if not callable(result_fits):
            raise GatewayMarketServiceError("INVALID_REPLY_SIZE_CHECKER")

        event_mappings = tuple(cast("tuple[Mapping[str, object], ...]", result["events"]))
        if len(event_mappings) != len(envelopes):
            raise GatewayMarketServiceError("INVALID_REPLAY_PAGE")
        requested_after = result["after"]
        original_has_more = result["has_more"]

        def candidate(prefix_length: int) -> Mapping[str, object]:
            selected = event_mappings[:prefix_length]
            next_after = (
                envelopes[prefix_length - 1].header.sequence if prefix_length else requested_after
            )
            page = dict(result)
            page["events"] = selected
            page["next_after"] = next_after
            page["has_more"] = original_has_more or prefix_length < len(event_mappings)
            return MappingProxyType(page)

        def fits(page: Mapping[str, object]) -> bool:
            try:
                accepted = result_fits(page)
            except Exception:
                raise GatewayMarketServiceError("INVALID_REPLY_SIZE_CHECKER") from None
            if type(accepted) is not bool:
                raise GatewayMarketServiceError("INVALID_REPLY_SIZE_CHECKER")
            return accepted

        full = candidate(len(event_mappings))
        if fits(full):
            return full

        low = 0
        high = len(event_mappings)
        while low < high:
            middle = (low + high + 1) // 2
            if fits(candidate(middle)):
                low = middle
            else:
                high = middle - 1
        if low == 0:
            raise GatewayMarketServiceError("REPLAY_PAGE_TOO_LARGE")
        return candidate(low)

    def _handle_async_bootstrap(
        self,
        operation: str,
        principal_ref: str,
        registration_id: str,
        raw: Mapping[str, object],
        result_fits: Callable[[Mapping[str, object]], bool] | None,
    ) -> Mapping[str, object]:
        """Refresh existing refs without ownership transfer; descriptors are opt-in per item."""
        hub = self._hub
        if operation == "market.bootstrap_begin":
            if set(raw) not in (
                {"operation_id", "subscriptions"},
                {"operation_id", "subscriptions", "refresh_existing"},
            ):
                raise GatewayMarketServiceError("INVALID_ARGUMENTS")
        else:
            _require_exact_arguments(raw, {"operation_id"})
        operation_id = raw["operation_id"]
        if type(operation_id) is not str or re.fullmatch(r"[0-9a-f]{32}", operation_id) is None:
            raise GatewayMarketServiceError("INVALID_OPERATION_ID")
        ident = (registration_id, operation_id)
        job = hub._bootstrap_jobs.get(ident)
        if job is not None and job.registration != self._registrations[registration_id]:
            raise GatewayMarketServiceError("REGISTRATION_REBIND_DENIED")
        if operation == "market.bootstrap_begin":
            refresh_existing = raw.get("refresh_existing", False)
            if type(refresh_existing) is not bool:
                raise GatewayMarketServiceError("INVALID_ARGUMENTS")
            raw_items = raw["subscriptions"]
            if type(raw_items) not in (tuple, list) or not 1 <= len(raw_items) <= 20:
                raise GatewayMarketServiceError("INVALID_BOOTSTRAP_BATCH")
            parsed = []
            seen = set()
            for item in raw_items:
                if not isinstance(item, Mapping) or set(item) not in (
                    {"key"},
                    {"key", "require_source_descriptor"},
                ):
                    raise GatewayMarketServiceError("INVALID_BOOTSTRAP_BATCH")
                requested = item.get("require_source_descriptor", False)
                if type(requested) is not bool:
                    raise GatewayMarketServiceError("INVALID_BOOTSTRAP_BATCH")
                key = _parse_key(item["key"])
                if key in seen:
                    raise GatewayMarketServiceError("DUPLICATE_MARKET_KEY")
                seen.add(key)
                parsed.append((key, requested))
            payload = tuple(parsed)
            if job is not None:
                if job.payload is not None and (
                    job.payload != payload or job.refresh_existing != refresh_existing
                ):
                    raise GatewayMarketServiceError("OPERATION_ID_CONFLICT")
            else:
                if not callable(result_fits):
                    raise GatewayMarketServiceError("REPLY_BUDGET_REQUIRED")
                job = self._new_bootstrap_job(operation_id, registration_id, principal_ref, payload)
                job.refresh_existing = refresh_existing
                try:
                    if not hub.ready or hub.delivery_suspended:
                        raise GatewayMarketHubError("MARKET_NOT_READY")
                    hub._ensure_open()
                    if hub._publisher is None:
                        raise GatewayMarketHubError("PUBLISHER_NOT_CONFIGURED")
                    for key, _ in payload:
                        stream = hub._authorize_key(principal_ref, key)
                        if registration_id in stream.pending_refs:
                            raise GatewayMarketHubError("MARKET_ALREADY_SUBSCRIBED")
                        if registration_id in stream.registrations:
                            owner = stream.ref_owners.get(registration_id)
                            if (
                                not refresh_existing
                                or owner is None
                                or hub._registration_principals.get((key, registration_id))
                                != principal_ref
                            ):
                                raise GatewayMarketHubError("MARKET_ALREADY_SUBSCRIBED")
                            job.borrowed[key] = owner
                        if stream.start_uncertain:
                            job.uncertain.add(key)
                            continue
                        if (
                            stream.starting
                            or stream.releasing
                            or stream.pending_release
                            or (
                                stream.handle is not None
                                and not stream.registrations
                                and not stream.pending_refs
                            )
                        ):
                            raise GatewayMarketHubError("STREAM_TRANSITION_IN_PROGRESS")
                    if (
                        hub._registration_ref_count + len(payload) - len(job.borrowed)
                        > MAX_MARKET_REGISTRATION_REFS
                    ):
                        raise GatewayMarketHubError("REGISTRATION_REF_LIMIT_EXCEEDED")
                    if job.uncertain:
                        job.status, job.code = "unknown", "BATCH_SUBSCRIBE_OUTCOME_UNKNOWN"
                    else:
                        for key, _ in payload:
                            hub._streams[key].pending_refs[registration_id] = job.token
                            if key not in job.borrowed:
                                hub._registration_ref_count += 1
                except GatewayMarketHubError as exc:
                    job.status, job.code = "rejected", exc.code
        elif operation == "market.bootstrap_cancel":
            if job is None:
                job = self._new_bootstrap_job(operation_id, registration_id, principal_ref, None)
                job.status, job.code = "cancelled", "BOOTSTRAP_CANCELLED"
            elif job.status in {"pending", "active"} or (
                job.status == "unknown" and job.code == "BOOTSTRAP_STALE"
            ):
                hub._bootstrap_cancel(job, "BOOTSTRAP_CANCELLED", final="cancelled")
        elif job is None:
            result = {"operation_id": operation_id, "status": "not_found"}
            if result_fits is not None:
                if not callable(result_fits):
                    raise GatewayMarketServiceError("INVALID_REPLY_SIZE_CHECKER")
                try:
                    fits = result_fits(result)
                except Exception:
                    raise GatewayMarketServiceError("INVALID_REPLY_SIZE_CHECKER") from None
                if type(fits) is not bool:
                    raise GatewayMarketServiceError("INVALID_REPLY_SIZE_CHECKER")
                if not fits:
                    raise GatewayMarketServiceError("REPLY_TOO_LARGE")
            return MappingProxyType(result)
        assert job is not None
        if job.status == "pending":
            hub._bootstrap_advance(1)
        elif job.status == "cancelling":
            hub._bootstrap_cleanup_step(job)
        result = hub._bootstrap_view(job)
        if job.status == "active" and (not hub.ready or hub.delivery_suspended):
            result = {
                "operation_id": operation_id,
                "status": "unknown",
                "code": "MARKET_NOT_READY",
                "uncertain_stream_ids": tuple(
                    sorted(
                        key.stream_id
                        for key, _ in job.payload or ()
                        if hub._streams[key].ref_owners.get(registration_id)
                        == job.borrowed.get(key, job.token)
                    )
                ),
            }
        if result["status"] == "active" and not callable(result_fits):
            raise GatewayMarketServiceError("REPLY_BUDGET_REQUIRED")
        if result_fits is not None:
            if not callable(result_fits):
                raise GatewayMarketServiceError("INVALID_REPLY_SIZE_CHECKER")
            try:
                fits = result_fits(result)
            except Exception:
                raise GatewayMarketServiceError("INVALID_REPLY_SIZE_CHECKER") from None
            if type(fits) is not bool:
                raise GatewayMarketServiceError("INVALID_REPLY_SIZE_CHECKER")
            if not fits:
                if result["status"] == "active" and not job.first_reply:
                    hub._bootstrap_cancel(job, "BATCH_REPLY_TOO_LARGE", final="rejected")
                    hub._bootstrap_cleanup_step(job)
                    raise GatewayMarketServiceError("REPLY_TOO_LARGE")
                raise GatewayMarketServiceError("REPLY_TOO_LARGE")
        if result["status"] == "active":
            job.first_reply = True
        return MappingProxyType(json.loads(json.dumps(result, allow_nan=False)))

    def _new_bootstrap_job(
        self,
        operation_id: str,
        registration_id: str,
        principal_ref: str,
        payload: tuple[tuple[MarketSubscriptionKey, bool], ...] | None,
    ) -> _BootstrapJob:
        hub = self._hub
        if (
            len(hub._bootstrap_jobs) >= hub._bootstrap_max_jobs
            or sum(job.registration_id == registration_id for job in hub._bootstrap_jobs.values())
            >= hub._bootstrap_per_registration
        ):
            raise GatewayMarketServiceError("BOOTSTRAP_JOB_CAPACITY")
        job = _BootstrapJob(
            operation_id,
            registration_id,
            principal_ref,
            self._registrations[registration_id],
            payload,
            secrets.token_urlsafe(32),
            hub._bootstrap_clock() + hub._bootstrap_timeout,
        )
        hub._bootstrap_jobs[(registration_id, operation_id)] = job
        return job

    def _handle_bootstrap_many(
        self,
        *,
        principal_ref: str,
        registration_id: str,
        raw: Mapping[str, object],
    ) -> Mapping[str, object]:
        """Acquire a bounded set of public streams under one exact registration.

        All authorization and capacity checks happen before the first provider
        call. If a later acquisition or reply-size check fails, newly acquired
        refs are released in reverse order. The result distinguishes a clean
        rejection from any provider state whose cleanup cannot be confirmed.
        """
        _require_exact_arguments(raw, {"subscriptions"})
        subscriptions = raw["subscriptions"]
        if (
            not isinstance(subscriptions, (tuple, list))
            or type(subscriptions) not in (tuple, list)
            or not 1 <= len(subscriptions) <= 20
        ):
            raise GatewayMarketServiceError("INVALID_BOOTSTRAP_BATCH")

        parsed: list[tuple[MarketSubscriptionKey, bool, bool]] = []
        seen: set[MarketSubscriptionKey] = set()
        preflight_uncertain: set[str] = set()
        try:
            self._hub._ensure_open()
            if self._hub._publisher is None:
                raise GatewayMarketHubError("PUBLISHER_NOT_CONFIGURED")
            if (
                self._hub._registration_ref_count + len(subscriptions)
                > MAX_MARKET_REGISTRATION_REFS
            ):
                raise GatewayMarketHubError("REGISTRATION_REF_LIMIT_EXCEEDED")
            for item in subscriptions:
                if not isinstance(item, Mapping) or set(item) not in (
                    {"key"},
                    {"key", "require_source_descriptor"},
                ):
                    raise GatewayMarketServiceError("INVALID_BOOTSTRAP_BATCH")
                requested_descriptor = item.get("require_source_descriptor", False)
                if type(requested_descriptor) is not bool:
                    raise GatewayMarketServiceError("INVALID_BOOTSTRAP_BATCH")
                key = _parse_key(item["key"])
                if key in seen:
                    raise GatewayMarketServiceError("DUPLICATE_MARKET_KEY")
                seen.add(key)
                # Each item receives the same independently enforced public
                # market ACL as a standalone market.subscribe call.
                stream = self._hub._authorize_key(principal_ref, key)
                if registration_id in stream.registrations:
                    raise GatewayMarketServiceError("MARKET_ALREADY_SUBSCRIBED")
                if stream.starting or stream.releasing:
                    raise GatewayMarketServiceError("STREAM_TRANSITION_IN_PROGRESS")
                if stream.start_uncertain:
                    preflight_uncertain.add(key.stream_id)
                # Descriptor rejection on a stream already held by another
                # registration creates no new provider state for this caller.
                had_shared_handle = stream.handle is not None and bool(stream.registrations)
                parsed.append((key, requested_descriptor, had_shared_handle))
        except GatewayMarketServiceError as exc:
            return MappingProxyType({"status": "rejected", "code": exc.code})
        except GatewayMarketHubError as exc:
            return MappingProxyType({"status": "rejected", "code": exc.code})

        if preflight_uncertain:
            return MappingProxyType(
                {
                    "status": "unknown",
                    "code": "BATCH_SUBSCRIBE_OUTCOME_UNKNOWN",
                    "uncertain_stream_ids": tuple(sorted(preflight_uncertain)),
                }
            )

        acquired: list[MarketSubscriptionKey] = []
        uncertain: set[str] = set()
        items: list[dict[str, object]] = []
        failure_code: str | None = None
        for key, require_source_descriptor, had_shared_handle in parsed:
            try:
                subscription = self._hub.subscribe(
                    principal_ref,
                    key,
                    registration_id,
                    require_source_descriptor=require_source_descriptor,
                )
                acquired.append(key)
                snapshot = dict(self._hub.snapshot(key, principal_ref=principal_ref))
                event = snapshot["event"]
                snapshot["event"] = None if event is None else dict(_envelope_mapping(event))
                head = dict(self._hub.head(key))
                items.append(
                    {
                        "subscription": dict(subscription),
                        "snapshot": snapshot,
                        "head": head,
                    }
                )
            except GatewayMarketHubError as exc:
                failure_code = exc.code
                # Provider acquisition and failed-release errors can leave a
                # resource whose exact state cannot be inferred by the caller.
                if exc.code in {
                    "PROVIDER_SUBSCRIBE_FAILED",
                    "PROVIDER_SUBSCRIBE_OUTCOME_UNKNOWN",
                    "INVALID_PROVIDER_HANDLE",
                    "PROVIDER_UNSUBSCRIBE_FAILED",
                }:
                    uncertain.add(key.stream_id)
                elif exc.code == "MARKET_SOURCE_DESCRIPTOR_UNAVAILABLE" and not had_shared_handle:
                    stream = self._hub._stream(key)
                    if stream.start_uncertain or stream.handle is not None:
                        # Hub.subscribe tried to release a newly acquired
                        # provider handle before reporting the descriptor
                        # failure. A retained handle means that release was
                        # not confirmed, so the caller must retain uncertainty.
                        uncertain.add(key.stream_id)
                break
            except Exception:
                failure_code = "BOOTSTRAP_FAILED"
                break

        if failure_code is None:
            reply: dict[str, object] = {"status": "active", "items": items}
            try:
                encoded_size = len(
                    json.dumps(
                        reply,
                        ensure_ascii=False,
                        allow_nan=False,
                        separators=(",", ":"),
                    ).encode("utf-8", errors="strict")
                )
            except Exception:
                failure_code = "INVALID_BOOTSTRAP_REPLY"
                uncertain.update(key.stream_id for key in acquired)
            else:
                # Leave margin for the enclosing WireEnvelope and protocol
                # headers; never let serialization fail after acquiring refs.
                if encoded_size > MAX_WIRE_MESSAGE_BYTES - 8_192:
                    failure_code = "BATCH_REPLY_TOO_LARGE"

        if failure_code is None:
            return MappingProxyType(reply)

        for key in reversed(acquired):
            try:
                self._hub.unsubscribe(principal_ref, key, registration_id)
            except GatewayMarketHubError:
                uncertain.add(key.stream_id)
            except Exception:
                uncertain.add(key.stream_id)
        if uncertain:
            return MappingProxyType(
                {
                    "status": "unknown",
                    "code": "BATCH_SUBSCRIBE_OUTCOME_UNKNOWN",
                    "uncertain_stream_ids": tuple(sorted(uncertain)),
                }
            )
        return MappingProxyType({"status": "rejected", "code": failure_code})

    @staticmethod
    def _validate_registration(
        hub: GatewayMarketHub, registration_id: str, registration: object
    ) -> None:
        try:
            _require_reference(registration_id, "INVALID_REGISTRATIONS")
        except GatewayMarketHubError as exc:
            raise GatewayMarketServiceError(exc.code) from None
        if type(registration) is not GatewayMarketRegistration:
            raise GatewayMarketServiceError("INVALID_REGISTRATIONS")
        if registration.execution_domain_ref != hub.scope.execution_domain_ref:
            raise GatewayMarketServiceError("REGISTRATION_EXECUTION_DOMAIN_MISMATCH")
        if registration.principal_ref not in hub.authorized_principals:
            raise GatewayMarketServiceError("REGISTRATION_PRINCIPAL_DENIED")

    def _resolve_registration(
        self, principal_ref: str, scope: WireScope, registration_id: str
    ) -> GatewayMarketRegistration:
        try:
            _require_reference(principal_ref, "INVALID_PRINCIPAL_REF")
            _require_reference(registration_id, "INVALID_REGISTRATION")
        except GatewayMarketHubError as exc:
            raise GatewayMarketServiceError(exc.code) from None
        registration = self._registrations.get(registration_id)
        if registration is None:
            raise GatewayMarketServiceError("UNKNOWN_REGISTRATION")
        if principal_ref not in self._hub.authorized_principals:
            raise GatewayMarketServiceError("UNKNOWN_PRINCIPAL")
        if registration.principal_ref != principal_ref:
            raise GatewayMarketServiceError("REGISTRATION_PRINCIPAL_MISMATCH")
        if type(scope) is not WireScope:
            raise GatewayMarketServiceError("INVALID_SCOPE")
        if (
            scope.account_refs
            or scope.manual_book_ref is not None
            or scope.portfolio_ref is not None
            or scope.group_id is not None
            or scope.leg_id is not None
        ):
            raise GatewayMarketServiceError("PUBLIC_MARKET_SCOPE_REQUIRED")
        if scope.account_ref is not None and registration.account_ref is None:
            raise GatewayMarketServiceError("PUBLIC_MARKET_SCOPE_REQUIRED")
        if scope.account_ref != registration.account_ref:
            raise GatewayMarketServiceError("ACCOUNT_SCOPE_DENIED")
        if scope.execution_domain_ref != registration.execution_domain_ref:
            raise GatewayMarketServiceError("EXECUTION_DOMAIN_DENIED")
        if (scope.strategy_ref, scope.run_id) != (
            registration.strategy_ref,
            registration.run_id,
        ):
            raise GatewayMarketServiceError("STRATEGY_RUN_SCOPE_DENIED")
        return registration


def _copy_key_universe(
    keys: Collection[MarketSubscriptionKey],
) -> tuple[MarketSubscriptionKey, ...]:
    if type(keys) not in (tuple, list, set, frozenset) or not keys:
        raise GatewayMarketHubError("INVALID_KEY_UNIVERSE")
    if len(keys) > MAX_MARKET_KEY_UNIVERSE:
        raise GatewayMarketHubError("KEY_UNIVERSE_TOO_LARGE")
    copied = tuple(keys)
    if any(type(key) is not MarketSubscriptionKey for key in copied):
        raise GatewayMarketHubError("INVALID_KEY_UNIVERSE")
    if len(set(copied)) != len(copied):
        raise GatewayMarketHubError("INVALID_KEY_UNIVERSE")
    return copied


def _copy_market_acl(
    value: Mapping[str, Collection[MarketSubscriptionKey]],
    key_universe: tuple[MarketSubscriptionKey, ...],
) -> dict[str, frozenset[MarketSubscriptionKey]]:
    if not isinstance(value, Mapping) or not value:
        raise GatewayMarketHubError("INVALID_MARKET_ACL")
    if len(value) > MAX_MARKET_PRINCIPALS:
        raise GatewayMarketHubError("MARKET_PRINCIPAL_LIMIT_EXCEEDED")
    universe = frozenset(key_universe)
    copied: dict[str, frozenset[MarketSubscriptionKey]] = {}
    for principal_ref, allowed_keys in value.items():
        _require_reference(principal_ref, "INVALID_MARKET_ACL")
        if type(allowed_keys) not in (tuple, list, set, frozenset):
            raise GatewayMarketHubError("INVALID_MARKET_ACL")
        if len(allowed_keys) > len(key_universe):
            raise GatewayMarketHubError("INCOMPLETE_MARKET_AUDIENCE")
        allowed = frozenset(allowed_keys)
        if any(type(key) is not MarketSubscriptionKey for key in allowed):
            raise GatewayMarketHubError("INVALID_MARKET_ACL")
        if not allowed or not allowed <= universe:
            raise GatewayMarketHubError("INVALID_MARKET_ACL")
        copied[principal_ref] = allowed
    return copied


def _copy_market_history_acl(
    provider: MarketHistoryProvider | None,
    stream_keys: tuple[MarketSubscriptionKey, ...],
    stream_acl: Mapping[str, frozenset[MarketSubscriptionKey]],
    history_keys: Collection[MarketSubscriptionKey] | None,
    history_acl: Mapping[str, Collection[MarketSubscriptionKey]] | None,
) -> tuple[tuple[MarketSubscriptionKey, ...], dict[str, frozenset[MarketSubscriptionKey]]]:
    """Copy history-only keys without adding them to the live stream audience.

    Existing direct Hub callers that configure a history provider without an
    explicit history audience retain the original shared-key behavior. New
    operator compositions pass both history-only fields so a bar entitlement
    cannot also become a live-subscription entitlement.
    """
    if provider is None:
        if history_keys is not None or history_acl is not None:
            raise GatewayMarketHubError("HISTORY_ACL_WITHOUT_PROVIDER")
        return (), {}
    if history_keys is None and history_acl is None:
        return stream_keys, dict(stream_acl)
    if history_keys is None or history_acl is None:
        raise GatewayMarketHubError("INCOMPLETE_HISTORY_ACL")

    copied_keys = _copy_key_universe(history_keys)
    if len(copied_keys) > MAX_MARKET_KEY_UNIVERSE:
        raise GatewayMarketHubError("HISTORY_KEY_UNIVERSE_TOO_LARGE")
    if any(key.channel != "bar" for key in copied_keys):
        raise GatewayMarketHubError("INVALID_HISTORY_KEY_UNIVERSE")
    if frozenset(copied_keys).intersection(stream_keys):
        raise GatewayMarketHubError("HISTORY_KEY_OVERLAPS_STREAM_UNIVERSE")
    if not isinstance(history_acl, Mapping) or set(history_acl) != set(stream_acl):
        raise GatewayMarketHubError("INVALID_HISTORY_ACL")

    universe = frozenset(copied_keys)
    copied_acl: dict[str, frozenset[MarketSubscriptionKey]] = {}
    for principal_ref, allowed_keys in history_acl.items():
        _require_reference(principal_ref, "INVALID_HISTORY_ACL")
        if type(allowed_keys) not in (tuple, list, set, frozenset):
            raise GatewayMarketHubError("INVALID_HISTORY_ACL")
        allowed = frozenset(allowed_keys)
        if any(type(key) is not MarketSubscriptionKey for key in allowed):
            raise GatewayMarketHubError("INVALID_HISTORY_ACL")
        if not allowed <= universe:
            raise GatewayMarketHubError("INCOMPLETE_HISTORY_AUDIENCE")
        copied_acl[principal_ref] = allowed
    return copied_keys, copied_acl


def _copy_principal_refs(values: Collection[str]) -> tuple[str, ...]:
    if type(values) not in (tuple, list, set, frozenset):
        raise GatewayMarketHubError("INVALID_PRINCIPAL_SET")
    if len(values) > MAX_MARKET_PRINCIPALS:
        raise GatewayMarketHubError("MARKET_PRINCIPAL_LIMIT_EXCEEDED")
    copied = tuple(values)
    for value in copied:
        _require_reference(value, "INVALID_PRINCIPAL_SET")
    if len(set(copied)) != len(copied):
        raise GatewayMarketHubError("INVALID_PRINCIPAL_SET")
    return copied


def _validate_service_wire_scope(identity: WireIdentity, scope: WireScope) -> None:
    if type(identity) is not WireIdentity or identity.role is not WireRole.SERVICE:
        raise GatewayMarketHubError("INVALID_SERVICE_IDENTITY")
    if identity.delegate_ref is not None:
        raise GatewayMarketHubError("INVALID_SERVICE_IDENTITY")
    if type(scope) is not WireScope:
        raise GatewayMarketHubError("INVALID_SERVICE_SCOPE")
    if (
        scope.account_ref is not None
        or scope.account_refs
        or scope.strategy_ref is not None
        or scope.run_id is not None
        or scope.manual_book_ref is not None
        or scope.portfolio_ref is not None
        or scope.group_id is not None
        or scope.leg_id is not None
    ):
        raise GatewayMarketHubError("MARKET_SERVICE_SCOPE_MUST_BE_PUBLIC")


def _require_reference(value: object, code: str) -> str:
    if type(value) is not str:
        raise GatewayMarketHubError(code)
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise GatewayMarketHubError(code) from None
    if (
        not encoded
        or len(encoded) > MAX_REFERENCE_BYTES
        or value != value.strip()
        or not value.isprintable()
    ):
        raise GatewayMarketHubError(code)
    return value


def _validate_history_configuration(
    provider: MarketHistoryProvider | None,
    timeout_seconds: float | None,
) -> float | None:
    if provider is None:
        if timeout_seconds is not None:
            raise GatewayMarketHubError("HISTORY_TIMEOUT_WITHOUT_PROVIDER")
        return None
    if not callable(getattr(provider, "fetch", None)):
        raise GatewayMarketHubError("INVALID_HISTORY_PROVIDER")
    if timeout_seconds is None:
        raise GatewayMarketHubError("HISTORY_TIMEOUT_REQUIRED")
    if type(timeout_seconds) not in (int, float):
        raise GatewayMarketHubError("INVALID_HISTORY_TIMEOUT")
    try:
        normalized = float(timeout_seconds)
    except (OverflowError, ValueError):
        raise GatewayMarketHubError("INVALID_HISTORY_TIMEOUT") from None
    if not math.isfinite(normalized) or not 0 < normalized <= MAX_MARKET_HISTORY_TIMEOUT_SECONDS:
        raise GatewayMarketHubError("INVALID_HISTORY_TIMEOUT")
    return normalized


def _validate_utc_timestamp(value: object, code: str) -> str:
    if type(value) is not str or _UTC_TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise GatewayMarketHubError(code)
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise GatewayMarketHubError(code) from None
    return value


def _format_utc(value: object) -> str:
    if type(value) is not datetime or value.tzinfo is None:
        raise GatewayMarketHubError("INVALID_CLOCK_VALUE")
    offset = value.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise GatewayMarketHubError("INVALID_CLOCK_VALUE")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _validate_cursor(after: object, limit: object) -> None:
    if type(after) is not int or after < 0:
        raise GatewayMarketHubError("INVALID_CURSOR")
    if type(limit) is not int or not 1 <= limit <= MAX_MARKET_READ_LIMIT:
        raise GatewayMarketHubError("INVALID_READ_LIMIT")


def _oldest_sequence(stream: _MarketStream) -> int:
    return stream.events[0].sequence if stream.events else stream.sequence + 1


def _require_arguments(arguments: Mapping[str, object]) -> Mapping[str, object]:
    if not isinstance(arguments, Mapping) or any(type(key) is not str for key in arguments):
        raise GatewayMarketServiceError("INVALID_ARGUMENTS")
    return arguments


def _plain_wire_tree(value: object) -> bool:
    """Recognize bounded built-in JSON values without invoking user objects."""
    stack = [(value, 0)]
    remaining = 100_000
    while stack:
        item, depth = stack.pop()
        remaining -= 1
        if remaining < 0 or depth > 16:
            return False
        if item is None or type(item) in (str, int, float, bool):
            continue
        if type(item) in (list, tuple):
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is dict and all(type(key) in (str, int, float, bool) or key is None for key in item):
            stack.extend((child, depth + 1) for child in item.values())
        else:
            return False
    return True


def _require_exact_arguments(arguments: Mapping[str, object], expected: set[str]) -> None:
    if set(arguments) != expected:
        raise GatewayMarketServiceError("INVALID_ARGUMENTS")


def _copy_reference_set(values: Collection[str], code: str) -> tuple[str, ...]:
    if type(values) not in (tuple, list, set, frozenset):
        raise GatewayMarketHubError(code)
    if len(values) > MAX_MARKET_REGISTRATIONS:
        raise GatewayMarketHubError(code)
    copied = tuple(values)
    for value in copied:
        _require_reference(value, code)
    if len(set(copied)) != len(copied):
        raise GatewayMarketHubError(code)
    return copied


def _parse_key(value: object) -> MarketSubscriptionKey:
    if type(value) is not dict and not isinstance(value, Mapping):
        raise GatewayMarketServiceError("INVALID_MARKET_KEY")
    try:
        return MarketSubscriptionKey.from_dict(value)
    except (TypeError, ValueError):
        raise GatewayMarketServiceError("INVALID_MARKET_KEY") from None


def _parse_history_request(value: Mapping[str, object]) -> MarketHistoryRequest:
    try:
        request = MarketHistoryRequest.from_dict(value)
    except (TypeError, ValueError):
        raise GatewayMarketServiceError("INVALID_HISTORY_REQUEST") from None
    if type(request) is not MarketHistoryRequest:
        raise GatewayMarketServiceError("INVALID_HISTORY_REQUEST")
    return request


def _envelope_mapping(envelope: WireEnvelope) -> Mapping[str, object]:
    try:
        encode_envelope(envelope, max_bytes=MAX_WIRE_MESSAGE_BYTES)  # bounded and valid
        value = envelope_to_wire_mapping(envelope)
    except Exception:
        raise GatewayMarketServiceError("INVALID_REPLAY_ENVELOPE") from None
    return MappingProxyType(value)


__all__ = [
    "ALL_MARKET_OPERATIONS",
    "ALL_MARKET_OPERATIONS_WITH_BOUNDED_READ_AFTER",
    "DEFAULT_MARKET_READ_LIMIT",
    "GatewayMarketHub",
    "GatewayMarketHubError",
    "GatewayMarketRegistration",
    "GatewayMarketService",
    "GatewayMarketServiceError",
    "MARKET_HISTORY_OPERATION",
    "MARKET_READ_AFTER_BOUNDED_OPERATION",
    "MARKET_OPERATIONS",
    "MARKET_OPERATIONS_WITH_BOUNDED_READ_AFTER",
    "MarketProviderSourceDescriber",
    "SUPPORTED_OPERATIONS",
    "MAX_MARKET_EVENT_BYTES",
    "MAX_MARKET_HISTORY_TIMEOUT_SECONDS",
    "MAX_MARKET_KEY_UNIVERSE",
    "MAX_MARKET_PRINCIPALS",
    "MAX_MARKET_REGISTRATIONS",
    "MAX_MARKET_REGISTRATION_REFS",
    "MAX_MARKET_READ_LIMIT",
    "MAX_MARKET_READ_PAGE_BYTES",
    "MAX_MARKET_REPLAY_EVENTS",
    "MAX_TOTAL_MARKET_REPLAY_BYTES",
    "MarketProvider",
    "MarketProviderPolling",
    "MarketProviderSourceEpochResetting",
    "MarketHistoryProvider",
]
