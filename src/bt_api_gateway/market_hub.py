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
from types import MappingProxyType
from typing import Any, Optional, Protocol

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
)

MARKET_READ_AFTER_BOUNDED_OPERATION = "market.read_after_bounded"
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
MARKET_HISTORY_OPERATION = "market.history"
ALL_MARKET_OPERATIONS = MARKET_OPERATIONS | frozenset({MARKET_HISTORY_OPERATION})
MARKET_OPERATIONS_WITH_BOUNDED_READ_AFTER = MARKET_OPERATIONS | frozenset(
    {MARKET_READ_AFTER_BOUNDED_OPERATION}
)
ALL_MARKET_OPERATIONS_WITH_BOUNDED_READ_AFTER = (
    ALL_MARKET_OPERATIONS | frozenset({MARKET_READ_AFTER_BOUNDED_OPERATION})
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
_MAPPING_PROXY_TYPE = type(MappingProxyType({}))


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
    strategy_ref: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.
    run_id: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.
    account_ref: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.

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
    handle: Optional[object] = None  # noqa: UP045 -- Python 3.9 support.
    registrations: set[str] = field(default_factory=set)
    starting: bool = False
    start_uncertain: bool = False
    releasing: bool = False
    pending_release: bool = False
    needs_new_epoch: bool = False
    generation: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.


class GatewayMarketHub:
    """Share bounded market streams inside one trusted execution-domain hub.

    ``key_universe`` is the complete stream audience published by the hub.
    Every accepted principal is required to be allowed every exported key;
    topic filters on a PUB socket are never treated as authorization. The
    whole-endpoint entitlement is separate from registration leases: pruning
    a registration releases upstream refs but does not revoke data access
    from an already-authorized raw SUB socket. Revocation requires controlled
    publisher shutdown/restart with a new audience map. Provider calls and
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
        publisher: Optional[Callable[[WireEnvelope], object]] = None,  # noqa: UP045
        epoch_factory: Optional[Callable[[], str]] = None,  # noqa: UP045 -- Python 3.9 support.
        history_provider: Optional[MarketHistoryProvider] = None,  # noqa: UP045
        history_timeout_seconds: Optional[float] = None,  # noqa: UP045
        history_key_universe: Optional[Collection[MarketSubscriptionKey]] = None,  # noqa: UP045
        principal_allowed_history_keys: Optional[
            Mapping[str, Collection[MarketSubscriptionKey]]
        ] = None,  # noqa: UP045
    ) -> None:
        if not callable(getattr(provider, "subscribe", None)) or not callable(
            getattr(provider, "unsubscribe", None)
        ):
            raise GatewayMarketHubError("INVALID_PROVIDER")
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
        normalized_history_timeout = _validate_history_configuration(
            history_provider, history_timeout_seconds
        )

        copied_keys = _copy_key_universe(key_universe)
        if len(copied_keys) > MAX_MARKET_KEY_UNIVERSE:
            raise GatewayMarketHubError("KEY_UNIVERSE_TOO_LARGE")
        if len(copied_keys) * max_replay_bytes > MAX_TOTAL_MARKET_REPLAY_BYTES:
            raise GatewayMarketHubError("TOTAL_REPLAY_BUDGET_EXCEEDED")
        copied_acl = _copy_market_acl(principal_allowed_keys, copied_keys)
        copied_history_keys, copied_history_acl = _copy_market_history_acl(
            history_provider,
            copied_keys,
            copied_acl,
            history_key_universe,
            principal_allowed_history_keys,
        )
        _validate_service_wire_scope(service_identity, service_scope)

        self._provider = provider
        provider_poll = getattr(provider, "poll", None)
        self._provider_poller = provider_poll if callable(provider_poll) else None
        reset_required = getattr(provider, "source_epoch_reset_required", None)
        acknowledge_reset = getattr(provider, "acknowledge_source_epoch_reset", None)
        self._provider_epoch_resetter = (
            provider
            if callable(reset_required) and callable(acknowledge_reset)
            else None
        )
        self._key_universe = frozenset(copied_keys)
        self._principal_allowed_keys = MappingProxyType(copied_acl)
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
        for key in copied_keys:
            if key.stream_id in self._stream_by_id:
                raise GatewayMarketHubError("STREAM_ID_COLLISION")
            self._stream_by_id[key.stream_id] = key
            self._streams[key] = _MarketStream(key=key, epoch=self._new_epoch())

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
    def principal_allowed_keys(
        self,
    ) -> Mapping[str, frozenset[MarketSubscriptionKey]]:
        """The copied trusted principal/key ACL supplied at construction."""
        return self._principal_allowed_keys

    @property
    def supported_operations(self) -> frozenset[str]:
        """Operations available from this configured hub instance."""
        return ALL_MARKET_OPERATIONS if self._history_provider is not None else MARKET_OPERATIONS

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
            if stream.handle is not None and not stream.registrations
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
    ) -> None:
        """Purely preflight the transport audience against this hub's identity.

        The transport must call this before constructing a PUB or RPC socket.
        Every transport-authorized principal must have the entire finite key
        universe, because the PUB channel itself is not a per-key ACL.
        """
        _validate_service_wire_scope(identity, scope)
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
            if allowed != self._key_universe:
                raise GatewayMarketHubError("MARKET_AUDIENCE_INCOMPLETE")

    def set_publisher(self, publisher: Callable[[WireEnvelope], object]) -> None:
        """Install the owner-thread PUB callback exactly once before use."""
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

        descriptor: MarketSourceDescriptor | None = None
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
        self._registration_ref_count += 1
        stream.pending_release = False
        return self._subscription_result(
            stream,
            already_subscribed=False,
            source_descriptor=descriptor,
        )

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
            self._registration_ref_count -= 1
        if (
            not stream.registrations
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
        pruned = 0
        released = 0
        for stream in self._streams.values():
            if stream.starting or stream.releasing:
                continue
            stale = stream.registrations - active
            if stale:
                stream.registrations.difference_update(stale)
                pruned += len(stale)
                self._registration_ref_count -= len(stale)
            if (
                not stream.registrations
                and stream.handle is not None
                and self._attempt_release(stream)
            ):
                released += 1
        pending = sum(
            1
            for stream in self._streams.values()
            if stream.handle is not None and not stream.registrations
        )
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
        if poller is None:
            return
        streams = tuple(
            stream
            for stream in self._streams.values()
            if (
                stream.handle is not None
                and stream.registrations
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
        return envelope

    def snapshot(self, key: MarketSubscriptionKey) -> Mapping[str, object]:
        """Return the latest retained event, explicitly not a full market state."""
        self._check_owner()
        stream = self._stream(key)
        latest = stream.events[-1].envelope if stream.events else None
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
    ) -> Mapping[str, object]:
        """Read a bounded page only for the exact current stream epoch.

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
        gap_reason: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.
        if epoch != stream.epoch:
            gap_reason = "epoch_mismatch"
        elif oldest is not None and after < oldest - 1:
            gap_reason = "cursor_too_old"
        elif after > stream.sequence:
            raise GatewayMarketHubError("CURSOR_AHEAD")

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

    def close(self) -> None:
        """Release all actual handles, retaining failures for an explicit retry."""
        self._check_owner()
        if any(stream.starting for stream in self._streams.values()):
            raise GatewayMarketHubError("PROVIDER_START_IN_PROGRESS", retryable=True)
        if any(stream.start_uncertain for stream in self._streams.values()):
            raise GatewayMarketHubError("PROVIDER_SUBSCRIBE_OUTCOME_UNKNOWN", retryable=True)
        self._closing = True
        failed = 0
        for stream in self._streams.values():
            self._registration_ref_count -= len(stream.registrations)
            stream.registrations.clear()
            if stream.handle is not None and not self._attempt_release(stream):
                failed += 1
        if failed:
            raise GatewayMarketHubError("PROVIDER_UNSUBSCRIBE_FAILED", retryable=True)

    def _authorize_key(self, principal_ref: str, key: MarketSubscriptionKey) -> _MarketStream:
        _require_reference(principal_ref, "INVALID_PRINCIPAL_REF")
        allowed = self._principal_allowed_keys.get(principal_ref)
        if allowed is None:
            raise GatewayMarketHubError("UNKNOWN_PRINCIPAL")
        stream = self._stream(key)
        if key not in allowed:
            raise GatewayMarketHubError("MARKET_KEY_DENIED")
        return stream

    def _authorize_history_key(
        self, principal_ref: str, key: MarketSubscriptionKey
    ) -> None:
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
        registrations: Optional[Mapping[str, GatewayMarketRegistration]] = None,  # noqa: UP045
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

    def register_registration(
        self, registration_id: str, registration: GatewayMarketRegistration
    ) -> None:
        """Bind a server-generated ID to its immutable trusted call context."""
        self._hub._check_owner()
        self._validate_registration(self._hub, registration_id, registration)
        existing = self._registrations.get(registration_id)
        if existing is not None and existing != registration:
            raise GatewayMarketServiceError("REGISTRATION_REBIND_DENIED")
        if existing is None and len(self._registrations) >= MAX_MARKET_REGISTRATIONS:
            raise GatewayMarketServiceError("REGISTRATION_LIMIT_EXCEEDED")
        self._registrations[registration_id] = registration

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

    def handle(
        self,
        operation: str,
        *,
        principal_ref: str,
        scope: WireScope,
        arguments: Mapping[str, object],
        registration_id: str,
        result_fits: Optional[Callable[[Mapping[str, object]], bool]] = None,  # noqa: UP045
    ) -> Mapping[str, object]:
        """Handle one exact market RPC under a trusted strategy-run mapping."""
        self._hub._check_owner()
        if type(operation) is not str or operation not in self.supported_operations:
            raise GatewayMarketServiceError("UNSUPPORTED_OPERATION")
        self._resolve_registration(principal_ref, scope, registration_id)
        raw = _require_arguments(arguments)
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
        if operation == "market.head":
            return self._hub.head(key)
        if operation == "market.snapshot":
            result = dict(self._hub.snapshot(key))
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
                after=after,  # type: ignore[arg-type] -- the hub validates the exact type.
                limit=limit,  # type: ignore[arg-type] -- the hub validates the exact type.
            )
        except GatewayMarketHubError as exc:
            raise GatewayMarketServiceError(exc.code, retryable=exc.retryable) from None
        result = dict(batch)
        event_mappings = tuple(_envelope_mapping(event) for event in batch["events"])
        result["events"] = event_mappings
        if operation == MARKET_READ_AFTER_BOUNDED_OPERATION:
            if result_fits is None or not callable(result_fits):
                raise GatewayMarketServiceError("CAPABILITY_UNAVAILABLE")
            return self._fit_read_after_reply(
                result,
                envelopes=tuple(batch["events"]),
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

        event_mappings = tuple(result["events"])
        if len(event_mappings) != len(envelopes):
            raise GatewayMarketServiceError("INVALID_REPLAY_PAGE")
        requested_after = result["after"]
        original_has_more = result["has_more"]

        def candidate(prefix_length: int) -> Mapping[str, object]:
            selected = event_mappings[:prefix_length]
            next_after = (
                envelopes[prefix_length - 1].header.sequence
                if prefix_length
                else requested_after
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
        if type(subscriptions) not in (tuple, list) or not 1 <= len(subscriptions) <= 20:
            raise GatewayMarketServiceError("INVALID_BOOTSTRAP_BATCH")

        parsed: list[tuple[MarketSubscriptionKey, bool, bool]] = []
        seen: set[MarketSubscriptionKey] = set()
        preflight_uncertain: set[str] = set()
        try:
            self._hub._ensure_open()
            if self._hub._publisher is None:
                raise GatewayMarketHubError("PUBLISHER_NOT_CONFIGURED")
            if self._hub._registration_ref_count + len(subscriptions) > MAX_MARKET_REGISTRATION_REFS:
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
                snapshot = dict(self._hub.snapshot(key))
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
        if allowed != universe:
            raise GatewayMarketHubError("INCOMPLETE_MARKET_AUDIENCE")
        copied[principal_ref] = allowed
    return copied


def _copy_market_history_acl(
    provider: Optional[MarketHistoryProvider],  # noqa: UP045 -- Python 3.9 support.
    stream_keys: tuple[MarketSubscriptionKey, ...],
    stream_acl: Mapping[str, frozenset[MarketSubscriptionKey]],
    history_keys: Optional[Collection[MarketSubscriptionKey]],  # noqa: UP045
    history_acl: Optional[
        Mapping[str, Collection[MarketSubscriptionKey]]
    ],  # noqa: UP045
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
    provider: Optional[MarketHistoryProvider],  # noqa: UP045 -- Python 3.9 support.
    timeout_seconds: Optional[float],  # noqa: UP045 -- Python 3.9 support.
) -> Optional[float]:  # noqa: UP045 -- Python 3.9 support.
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
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise GatewayMarketHubError("INVALID_CLOCK_VALUE")
    if value.utcoffset().total_seconds() != 0:
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
        value = json.loads(encode_envelope(envelope, max_bytes=MAX_WIRE_MESSAGE_BYTES))
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
