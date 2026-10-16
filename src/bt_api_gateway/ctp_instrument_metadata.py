"""Trusted CTP instrument-metadata binding for the account session worker.

The decorated account provider must expose the exact request feed, market
stream, and connected TraderClient that it owns.  This module never constructs
a second CTP session or accepts a wire-supplied capability flag.
"""

from __future__ import annotations

import threading
from typing import Optional

from .account_session_worker import GatewayAccountSessionWorkerError


class GatewayCtpInstrumentMetadataBindingError(RuntimeError):
    """Finite, value-free failure to bind CTP metadata to an account owner."""

    _CODES = frozenset(
        {
            "INVALID_ACCOUNT_PROVIDER",
            "INVALID_CTP_FEED_BINDING",
            "INVALID_CTP_MARKET_BINDING",
            "CTP_SESSION_BINDING_INVALID",
            "CTP_SESSION_BINDING_CHANGED",
            "CTP_ACCOUNT_GENERATION_INVALID",
        }
    )

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in self._CODES:
            code = "CTP_SESSION_BINDING_INVALID"
        self.code = code
        super().__init__(code)


class GatewayCtpInstrumentMetadataProvider:
    """Add fresh typed instrument reads to one existing CTP account provider.

    The trusted ``GatewaySessionOwner.provider_factory`` constructs the base
    provider and passes the exact ``ctp_request_feed`` and
    ``ctp_market_stream`` objects owned by that provider.  The base provider
    must expose those same objects and, after connect, its exact current
    ``ctp_trader_client``.  If that identity contract is unavailable or changes,
    metadata reads fail closed.
    """

    __slots__ = (
        "_provider",
        "_request_feed",
        "_market_stream",
        "_reader",
        "_owner_thread_id",
        "_generation",
        "_connected_trader",
        "_account_key",
    )

    def __init__(self, provider: object, *, request_feed: object, market_stream: object) -> None:
        if not all(
            callable(getattr(provider, name, None))
            for name in ("connect", "read_account", "close")
        ):
            raise GatewayCtpInstrumentMetadataBindingError("INVALID_ACCOUNT_PROVIDER")
        try:
            from bt_api_ctp.feeds.live_ctp_feed import CtpMarketStream, CtpRequestDataFuture
            from bt_api_ctp.instrument_metadata import CtpInstrumentMetadataReader
        except Exception:
            raise GatewayCtpInstrumentMetadataBindingError("INVALID_CTP_FEED_BINDING") from None
        if type(request_feed) is not CtpRequestDataFuture:
            raise GatewayCtpInstrumentMetadataBindingError("INVALID_CTP_FEED_BINDING")
        if type(market_stream) is not CtpMarketStream:
            raise GatewayCtpInstrumentMetadataBindingError("INVALID_CTP_MARKET_BINDING")
        try:
            if (
                getattr(provider, "ctp_request_feed", None) is not request_feed
                or getattr(provider, "ctp_market_stream", None) is not market_stream
            ):
                raise GatewayCtpInstrumentMetadataBindingError("CTP_SESSION_BINDING_INVALID")
            reader = CtpInstrumentMetadataReader(request_feed, market_stream)
        except GatewayCtpInstrumentMetadataBindingError:
            raise
        except Exception:
            raise GatewayCtpInstrumentMetadataBindingError("CTP_SESSION_BINDING_INVALID") from None
        self._provider = provider
        self._request_feed = request_feed
        self._market_stream = market_stream
        self._reader = reader
        self._owner_thread_id = threading.get_ident()
        self._generation: Optional[str] = None  # noqa: UP045 -- Python 3.9 support.
        self._connected_trader: object | None = None
        self._account_key: object | None = None

    @property
    def ctp_request_feed(self) -> object:
        return self._request_feed

    @property
    def ctp_market_stream(self) -> object:
        return self._market_stream

    @property
    def ctp_trader_client(self) -> object | None:
        return self._connected_trader

    def connect(self, *, account_key: object, generation: str, timeout: float) -> object:
        self._check_owner()
        if type(generation) is not str or not generation or generation != generation.strip():
            raise GatewayCtpInstrumentMetadataBindingError("CTP_ACCOUNT_GENERATION_INVALID")
        self._generation = None
        self._connected_trader = None
        self._account_key = None
        result = self._provider.connect(  # type: ignore[attr-defined]
            account_key=account_key,
            generation=generation,
            timeout=timeout,
        )
        self._assert_fixed_feed_binding()
        try:
            trader = getattr(self._request_feed, "trader_client", None)
            provider_trader = getattr(self._provider, "ctp_trader_client", None)
            provider_account_key = getattr(self._provider, "ctp_account_key", None)
        except Exception:
            raise GatewayCtpInstrumentMetadataBindingError(
                "CTP_SESSION_BINDING_INVALID"
            ) from None
        if trader is None or provider_trader is not trader or provider_account_key is not account_key:
            raise GatewayCtpInstrumentMetadataBindingError("CTP_SESSION_BINDING_INVALID")
        self._connected_trader = trader
        self._generation = generation
        self._account_key = account_key
        return result

    def read_account(self, *, generation: str, timeout: float) -> object:
        self._check_owner()
        self._assert_current_binding(generation)
        return self._provider.read_account(  # type: ignore[attr-defined]
            generation=generation,
            timeout=timeout,
        )

    def read_instrument_metadata(
        self,
        *,
        instrument_id: str,
        exchange_id: str,
        generation: str,
        timeout: float,
    ) -> object:
        self._check_owner()
        self._assert_current_binding(generation)
        try:
            return self._reader.read(
                instrument_id,
                exchange_id,
                account_session_generation=generation,
                timeout=timeout,
            )
        except Exception as exc:
            if type(getattr(exc, "code", None)) is str:
                raise GatewayAccountSessionWorkerError(exc.code) from None
            raise GatewayAccountSessionWorkerError("PROVIDER_FACT_READ_FAILED") from None

    def close(self) -> Optional[bool]:  # noqa: UP045 -- Python 3.9 support.
        self._check_owner()
        result = self._provider.close()  # type: ignore[attr-defined]
        if result is None or result is True:
            self._generation = None
            self._connected_trader = None
            self._account_key = None
        return result  # type: ignore[return-value]

    def _assert_current_binding(self, generation: str) -> None:
        if self._generation is None or generation != self._generation:
            raise GatewayAccountSessionWorkerError("PROVIDER_RESULT_GENERATION_STALE")
        self._assert_fixed_feed_binding()
        try:
            trader = getattr(self._request_feed, "trader_client", None)
            provider_trader = getattr(self._provider, "ctp_trader_client", None)
            provider_account_key = getattr(self._provider, "ctp_account_key", None)
        except Exception:
            raise GatewayAccountSessionWorkerError("PROVIDER_RESULT_GENERATION_STALE") from None
        if (
            trader is None
            or trader is not self._connected_trader
            or provider_trader is not trader
            or provider_account_key is not self._account_key
        ):
            raise GatewayAccountSessionWorkerError("PROVIDER_RESULT_GENERATION_STALE")

    def _assert_fixed_feed_binding(self) -> None:
        try:
            matches = (
                getattr(self._provider, "ctp_request_feed", None) is self._request_feed
                and getattr(self._provider, "ctp_market_stream", None) is self._market_stream
            )
        except Exception:
            matches = False
        if not matches:
            raise GatewayAccountSessionWorkerError("PROVIDER_RESULT_GENERATION_STALE")

    def _check_owner(self) -> None:
        if threading.get_ident() != self._owner_thread_id:
            raise GatewayAccountSessionWorkerError("WORKER_WRONG_THREAD")


def bind_ctp_instrument_metadata_provider(
    provider: object,
    *,
    request_feed: object,
    market_stream: object,
) -> GatewayCtpInstrumentMetadataProvider:
    """Bind metadata to the exact CTP feed pair owned by a trusted factory."""

    return GatewayCtpInstrumentMetadataProvider(
        provider,
        request_feed=request_feed,
        market_stream=market_stream,
    )


__all__ = [
    "GatewayCtpInstrumentMetadataBindingError",
    "GatewayCtpInstrumentMetadataProvider",
    "bind_ctp_instrument_metadata_provider",
]
