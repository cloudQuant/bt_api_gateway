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
import re
import secrets
import threading
import uuid
from collections import deque
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Optional, Protocol

from bt_api_base.market_protocol import (
    MARKET_EVENT_OPERATION,
    MARKET_EVENT_SCHEMA,
    MARKET_EVENT_SCHEMA_VERSION,
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

MARKET_OPERATIONS = frozenset(
    {
        "market.subscribe",
        "market.unsubscribe",
        "market.snapshot",
        "market.head",
        "market.read_after",
    }
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
    """Synchronous provider edge owned and invoked on the hub's owner thread.

    A provider implementation must either return a handle for an acquired
    subscription or raise before acquiring one. If it cannot establish that
    guarantee, it needs a provider-specific adapter that retains and exposes
    the uncertain handle instead of retrying this generic operation.

    A successful call must return a non-``None`` handle. Raising or returning
    ``None`` means acquisition did not happen; the hub cannot safely recover a
    handle that the provider acquired but failed to return. The provider must
    emit events only after acquisition returns, and retain the supplied
    generation with every queued event so old callbacks can be rejected.
    """

    def subscribe(self, key: MarketSubscriptionKey, *, generation: str) -> object:
        """Acquire a stream and capture the hub-issued event generation."""

    def unsubscribe(self, handle: object) -> bool | None:
        """Release one handle idempotently, including retries after actual release.

        ``False`` or an exception means the hub retains the exact handle and
        retries it later. The provider must accept that same handle again even
        if the previous call already stopped its upstream subscription.
        """


@dataclass(frozen=True)
class GatewayMarketRegistration:
    """Trusted public call registration resolved outside the RPC payload.

    Strategy-client registrations carry both strategy and run refs, created
    only after the service registry verifies that run. Application/service
    registrations carry neither; they do not invent a strategy identity to
    enter the public market scope.
    """

    principal_ref: str
    execution_domain_ref: str
    strategy_ref: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.
    run_id: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.

    def __post_init__(self) -> None:
        for name in ("principal_ref", "execution_domain_ref"):
            _require_reference(getattr(self, name), "INVALID_REGISTRATION")
        if (self.strategy_ref is None) is not (self.run_id is None):
            raise GatewayMarketHubError("INVALID_REGISTRATION")
        if self.strategy_ref is not None:
            _require_reference(self.strategy_ref, "INVALID_REGISTRATION")
            _require_reference(self.run_id, "INVALID_REGISTRATION")


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
        publisher: Optional[Callable[[WireEnvelope], object]] = None,  # noqa: UP045
        epoch_factory: Optional[Callable[[], str]] = None,  # noqa: UP045 -- Python 3.9 support.
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
        if publisher is not None and not callable(publisher):
            raise GatewayMarketHubError("INVALID_PUBLISHER")
        if epoch_factory is not None and not callable(epoch_factory):
            raise GatewayMarketHubError("INVALID_EPOCH_FACTORY")

        copied_keys = _copy_key_universe(key_universe)
        if len(copied_keys) > MAX_MARKET_KEY_UNIVERSE:
            raise GatewayMarketHubError("KEY_UNIVERSE_TOO_LARGE")
        if len(copied_keys) * max_replay_bytes > MAX_TOTAL_MARKET_REPLAY_BYTES:
            raise GatewayMarketHubError("TOTAL_REPLAY_BUDGET_EXCEEDED")
        copied_acl = _copy_market_acl(principal_allowed_keys, copied_keys)
        _validate_service_wire_scope(service_identity, service_scope)

        self._provider = provider
        self._key_universe = frozenset(copied_keys)
        self._principal_allowed_keys = MappingProxyType(copied_acl)
        self._service_identity = service_identity
        self._service_scope = service_scope
        self._max_replay_events = max_replay_events
        self._max_replay_bytes = max_replay_bytes
        self._publisher = publisher
        self._epoch_factory = epoch_factory or (lambda: uuid.uuid4().hex)
        self._owner_thread_id = threading.get_ident()
        self._closing = False
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
    ) -> Mapping[str, object]:
        """Acquire one registration ref, starting the provider only on first use."""
        self._check_owner()
        self._ensure_open()
        stream = self._authorize_key(principal_ref, key)
        _require_reference(registration_id, "INVALID_REGISTRATION")
        if stream.starting or stream.releasing:
            raise GatewayMarketHubError("STREAM_TRANSITION_IN_PROGRESS", retryable=True)

        already_subscribed = registration_id in stream.registrations
        if already_subscribed:
            return self._subscription_result(stream, already_subscribed=True)
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
                raise GatewayMarketHubError("PROVIDER_SUBSCRIBE_FAILED", retryable=True) from None
            finally:
                stream.starting = False
            if handle is None:
                raise GatewayMarketHubError("INVALID_PROVIDER_HANDLE", retryable=True)
            stream.handle = handle
            stream.generation = generation
            if next_epoch is not None:
                stream.epoch = next_epoch
                stream.sequence = 0
                stream.events.clear()
                stream.replay_bytes = 0
                stream.needs_new_epoch = False

        # Reuse a retained handle after an uncertain failed stop; never start a
        # second upstream stream while the original handle is still owned.
        stream.registrations.add(registration_id)
        self._registration_ref_count += 1
        stream.pending_release = False
        return self._subscription_result(stream, already_subscribed=False)

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
        return MappingProxyType(
            {
                "pruned_registrations": pruned,
                "released_upstreams": released,
                "pending_releases": pending,
            }
        )

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

    def _stream(self, key: MarketSubscriptionKey) -> _MarketStream:
        if type(key) is not MarketSubscriptionKey:
            raise GatewayMarketHubError("INVALID_MARKET_KEY")
        stream = self._streams.get(key)
        if stream is None:
            raise GatewayMarketHubError("MARKET_KEY_NOT_EXPORTED")
        return stream

    def _subscription_result(
        self, stream: _MarketStream, *, already_subscribed: bool
    ) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "stream_id": stream.key.stream_id,
                "epoch": stream.epoch,
                "head": stream.sequence,
                "oldest_sequence": _oldest_sequence(stream),
                "already_subscribed": already_subscribed,
            }
        )

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
    ) -> None:
        if type(hub) is not GatewayMarketHub:
            raise GatewayMarketServiceError("INVALID_MARKET_HUB")
        if registrations is None:
            registrations = {}
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

    @property
    def ready(self) -> bool:
        """Whether the underlying hub can accept calls and publish events."""
        return self._hub.ready

    @property
    def readiness(self) -> Mapping[str, object]:
        """The hub's finite readiness projection."""
        return self._hub.readiness

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
    ) -> Mapping[str, object]:
        """Handle one exact market RPC under a trusted strategy-run mapping."""
        self._hub._check_owner()
        if type(operation) is not str or operation not in MARKET_OPERATIONS:
            raise GatewayMarketServiceError("UNSUPPORTED_OPERATION")
        self._resolve_registration(principal_ref, scope, registration_id)
        raw = _require_arguments(arguments)
        expected = (
            {"key", "epoch", "after", "limit"} if operation == "market.read_after" else {"key"}
        )
        _require_exact_arguments(raw, expected)
        key = _parse_key(raw["key"])
        self._hub._authorize_key(principal_ref, key)

        if operation == "market.subscribe":
            return self._hub.subscribe(principal_ref, key, registration_id)
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
        result["events"] = tuple(_envelope_mapping(event) for event in batch["events"])
        return MappingProxyType(result)

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
            scope.account_ref is not None
            or scope.account_refs
            or scope.manual_book_ref is not None
            or scope.portfolio_ref is not None
            or scope.group_id is not None
            or scope.leg_id is not None
        ):
            raise GatewayMarketServiceError("PUBLIC_MARKET_SCOPE_REQUIRED")
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


def _envelope_mapping(envelope: WireEnvelope) -> Mapping[str, object]:
    try:
        value = json.loads(encode_envelope(envelope, max_bytes=MAX_WIRE_MESSAGE_BYTES))
    except Exception:
        raise GatewayMarketServiceError("INVALID_REPLAY_ENVELOPE") from None
    return MappingProxyType(value)


__all__ = [
    "DEFAULT_MARKET_READ_LIMIT",
    "GatewayMarketHub",
    "GatewayMarketHubError",
    "GatewayMarketRegistration",
    "GatewayMarketService",
    "GatewayMarketServiceError",
    "MARKET_OPERATIONS",
    "SUPPORTED_OPERATIONS",
    "MAX_MARKET_EVENT_BYTES",
    "MAX_MARKET_KEY_UNIVERSE",
    "MAX_MARKET_PRINCIPALS",
    "MAX_MARKET_REGISTRATIONS",
    "MAX_MARKET_REGISTRATION_REFS",
    "MAX_MARKET_READ_LIMIT",
    "MAX_MARKET_READ_PAGE_BYTES",
    "MAX_MARKET_REPLAY_EVENTS",
    "MAX_TOTAL_MARKET_REPLAY_BYTES",
    "MarketProvider",
]
