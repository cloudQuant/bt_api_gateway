"""Process-local credential-reference resolution for Gateway session owners.

The ServiceHost owner is the only caller expected to construct this object.
Operator deployment configuration supplies an ``account_session_ref`` to
``credential_ref`` mapping; the resolver and provider factory are trusted
in-process capabilities injected by that owner. This module deliberately does
not implement a secret store or read credentials from a file, environment, or
wire request. A deployment must bind ``resolve_credential`` to its actual
secret-management system before using provider credentials.
The injected callbacks are trusted owner capabilities and must not log or
project their arguments, return values, or exception details.

Create a fresh owner for each ServiceHost process. Each session reference is
claimed before resolution and can be resolved/provider-built only once by that
owner. AFI clients receive service projections and never call this API.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from threading import Lock
from types import MappingProxyType
from typing import Any, Optional, Protocol

_SESSION_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CREDENTIAL_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_MAX_BINDINGS = 4096


class GatewaySessionOwnerError(RuntimeError):
    """Finite, value-free error from trusted session-owner configuration."""

    _CODES = frozenset(
        {
            "INVALID_SESSION_REF",
            "INVALID_CREDENTIAL_BINDINGS",
            "SESSION_NOT_CONFIGURED",
            "SESSION_ALREADY_CLAIMED",
            "CREDENTIAL_RESOLUTION_FAILED",
            "CREDENTIAL_UNAVAILABLE",
            "PROVIDER_CREATION_FAILED",
            "PROVIDER_INVALID",
            "PROVIDER_CLOSE_UNCONFIRMED",
        }
    )

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in self._CODES:
            code = "SESSION_OWNER_FAILED"
        self.code = code
        super().__init__(code)


class GatewayAccountSessionProvider(Protocol):
    """Minimum provider lifecycle expected by ``GatewayAccountSessionWorker``."""

    def connect(self, *, account_key: Any, generation: str, timeout: float) -> None:
        """Connect the selected account session."""

    def read_account(self, *, generation: str, timeout: float) -> Any:
        """Read one account observation for the active generation."""

    def close(self) -> Optional[bool]:  # noqa: UP045 -- Python 3.9 support.
        """Close the provider; only None or literal True confirms success."""


class GatewaySessionOwner:
    """Resolve provider credentials once inside the Gateway owner process.

    ``session_credential_refs`` is trusted operator configuration and contains
    identifiers only. ``resolve_credential`` receives a credential reference
    and returns opaque secret material. ``provider_factory`` receives the
    account-session reference and that material, and constructs the actual
    provider object. Neither callback may be exposed to AFI or wire clients.

    Call :meth:`create_provider` from the Gateway ServiceHost's existing
    ``resource_provider`` callback before constructing its owner worker. The
    worker/ServiceHost then owns connect, refresh, recovery, and close. This
    class prevents a second resource request in the same owner process from
    resolving or connecting the same account session again.
    """

    def __init__(
        self,
        session_credential_refs: Mapping[str, str],
        *,
        resolve_credential: Callable[[str], object],
        provider_factory: Callable[[str, object], GatewayAccountSessionProvider],
    ) -> None:
        if not isinstance(session_credential_refs, Mapping):
            raise GatewaySessionOwnerError("INVALID_CREDENTIAL_BINDINGS")
        try:
            binding_count = len(session_credential_refs)
        except BaseException:
            raise GatewaySessionOwnerError("INVALID_CREDENTIAL_BINDINGS") from None
        if binding_count == 0 or binding_count > _MAX_BINDINGS:
            raise GatewaySessionOwnerError("INVALID_CREDENTIAL_BINDINGS")
        if not callable(resolve_credential) or not callable(provider_factory):
            raise GatewaySessionOwnerError("INVALID_CREDENTIAL_BINDINGS")

        copied: dict[str, str] = {}
        try:
            entries = tuple(session_credential_refs.items())
        except BaseException:
            raise GatewaySessionOwnerError("INVALID_CREDENTIAL_BINDINGS") from None
        for entry in entries:
            if type(entry) is not tuple or len(entry) != 2:
                raise GatewaySessionOwnerError("INVALID_CREDENTIAL_BINDINGS")
            session_ref, credential_ref = entry
            if not _valid_ref(session_ref, _SESSION_REF) or not _valid_ref(
                credential_ref, _CREDENTIAL_REF
            ):
                raise GatewaySessionOwnerError("INVALID_CREDENTIAL_BINDINGS")
            copied[session_ref] = credential_ref
        if len(copied) != len(entries):
            raise GatewaySessionOwnerError("INVALID_CREDENTIAL_BINDINGS")

        self._session_credential_refs = MappingProxyType(copied)
        self._resolve_credential = resolve_credential
        self._provider_factory = provider_factory
        self._claimed_session_refs: set[str] = set()
        self._uncertain_providers: dict[str, object] = {}
        self._lock = Lock()

    def create_provider(self, account_session_ref: str) -> GatewayAccountSessionProvider:
        """Resolve and construct one provider for a configured session ref.

        Any callback exception is collapsed to a finite code and discarded
        before it reaches the ServiceHost caller. The exception text, cause,
        and context therefore cannot expose a credential or provider detail.
        Failed references remain claimed so a callback retry cannot cause an
        accidental second lookup or provider session.
        """

        if not _valid_ref(account_session_ref, _SESSION_REF):
            raise GatewaySessionOwnerError("INVALID_SESSION_REF")
        credential_ref = self._session_credential_refs.get(account_session_ref)
        if credential_ref is None:
            raise GatewaySessionOwnerError("SESSION_NOT_CONFIGURED")
        with self._lock:
            if account_session_ref in self._claimed_session_refs:
                raise GatewaySessionOwnerError("SESSION_ALREADY_CLAIMED")
            self._claimed_session_refs.add(account_session_ref)

        provider, error_code = _resolve_and_build_provider(
            account_session_ref,
            credential_ref,
            self._resolve_credential,
            self._provider_factory,
        )
        if error_code is not None:
            if provider is not None and not _close_unclaimed_provider(provider):
                with self._lock:
                    self._uncertain_providers[account_session_ref] = provider
                raise GatewaySessionOwnerError("PROVIDER_CLOSE_UNCONFIRMED")
            raise GatewaySessionOwnerError(error_code)
        return provider  # type: ignore[return-value] -- validated by the builder.

    @property
    def claimed_session_count(self) -> int:
        """Return a finite owner-local count without exposing references."""

        with self._lock:
            return len(self._claimed_session_refs)

    @property
    def uncertain_provider_count(self) -> int:
        """Count provider objects retained after an unconfirmed early close."""

        with self._lock:
            return len(self._uncertain_providers)


def _resolve_and_build_provider(
    account_session_ref: str,
    credential_ref: str,
    resolver: Callable[[str], object],
    factory: Callable[[str, object], GatewayAccountSessionProvider],
) -> tuple[GatewayAccountSessionProvider | None, str | None]:
    """Run secret-bearing callbacks in a frame that never escapes on failure."""

    credential: object = None
    provider: object = None
    try:
        try:
            credential = resolver(credential_ref)
        except BaseException:
            return None, "CREDENTIAL_RESOLUTION_FAILED"
        if credential is None:
            return None, "CREDENTIAL_UNAVAILABLE"
        try:
            provider = factory(account_session_ref, credential)
        except BaseException:
            return None, "PROVIDER_CREATION_FAILED"
        if provider is None:
            return None, "PROVIDER_CREATION_FAILED"
        if not _provider_has_required_methods(provider):
            return provider, "PROVIDER_INVALID"  # type: ignore[return-value]
        return provider, None  # type: ignore[return-value]
    except BaseException:
        return provider, "PROVIDER_CREATION_FAILED" if provider is None else "PROVIDER_INVALID"
    finally:
        credential = None


def _provider_has_required_methods(provider: object) -> bool:
    try:
        return all(
            callable(getattr(provider, method, None))
            for method in ("connect", "read_account", "close")
        )
    except BaseException:
        return False


def _close_unclaimed_provider(provider: object) -> bool:
    """Best-effort close before worker ownership; expose no provider detail."""

    try:
        close = getattr(provider, "close", None)
        if not callable(close):
            return False
        result = close()
        return result is None or result is True
    except BaseException:
        return False


def _valid_ref(value: object, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


__all__ = ["GatewayAccountSessionProvider", "GatewaySessionOwner", "GatewaySessionOwnerError"]
