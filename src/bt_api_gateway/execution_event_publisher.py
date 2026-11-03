"""Publish provider execution observations into per-strategy account streams.

Iteration 60, R2-C. The account owner (``GatewayAccountSessionWorker``) drains
the trusted provider's typed terminal-order and per-fill observations (Base
``AccountExecutionOrderObservation`` / ``AccountExecutionTradeObservation``)
and hands them to this publisher, which appends each one as an account-journal
event:

* **Stream.** Each observation goes to one event-mode journal stream inside the
  account scope: a strategy's execution stream when its verified client order
  id matches a configured prefix, otherwise the optional account-level
  ``unattributed_scope`` (or it is counted and dropped). A fill follows the
  stream of its provider order id; the route is persisted with the first order
  observation, in the same SQLite transaction, so it survives a restart.
  Routing is server configuration, never a client claim.
* **Sequence/cursor.** The journal assigns the per-stream sequence that
  consumers use as cursor, with tracked delivery and ACK as for any stream.
* **Idempotent ids.** The event id is the Base fact id; a redelivered fact is
  a duplicate (``created=False``) and a different fact under the same id is
  refused with ``EXECUTION_FACT_CONFLICT`` (fail closed).
* **Fill fees (iteration 60 R3).** A trade observation carries the provider
  fee of the fill when the provider supplies it (Base execution event v2). The
  fee is part of the trade fact: a re-report with a higher fee is a new event
  (a fee correction for consumers such as Backtrader's ``notify_fee_correction``),
  a lower fee (``EXECUTION_FEE_REGRESSED``) or another currency
  (``EXECUTION_FEE_CURRENCY_CONFLICT``) is refused and nothing is appended.

The publisher does not contact a provider, verify a fill or bind an intent;
the observations remain provider declarations.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from bt_api_base.account_protocol import AccountKey
from bt_api_base.execution_row_observation_protocol import (
    AccountExecutionOrderObservation,
    AccountExecutionTradeObservation,
    execution_observation_event,
    strategy_client_order_prefix,
)

from .event_journal import GatewayEventJournal, GatewayEventJournalError

MAX_EXECUTION_BATCH = 1000


class GatewayExecutionEventError(RuntimeError):
    """A finite, value-free execution publication failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _text(value: object, code: str) -> str:
    if type(value) is not str or not value or value != value.strip() or len(value) > 128:
        raise GatewayExecutionEventError(code)
    return value


@dataclass(frozen=True)
class GatewayExecutionScopePolicy:
    """Trusted routing from verified client order ids to execution streams.

    ``client_order_prefixes`` maps a client-order-id prefix to the journal
    strategy scope of that strategy's execution stream; the longest matching
    prefix wins. ``unattributed_scope`` (optional) receives everything else.
    """

    client_order_prefixes: Mapping[str, str] = field(default_factory=dict)
    unattributed_scope: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.client_order_prefixes, Mapping):
            raise GatewayExecutionEventError("INVALID_EXECUTION_ROUTES")
        copied = {
            _text(prefix, "INVALID_EXECUTION_ROUTES"): _text(scope, "INVALID_EXECUTION_ROUTES")
            for prefix, scope in self.client_order_prefixes.items()
        }
        if self.unattributed_scope is not None:
            _text(self.unattributed_scope, "INVALID_UNATTRIBUTED_SCOPE")
            if self.unattributed_scope in copied.values():
                raise GatewayExecutionEventError("AMBIGUOUS_UNATTRIBUTED_SCOPE")
        object.__setattr__(self, "client_order_prefixes", MappingProxyType(copied))

    @classmethod
    def for_strategies(
        cls, strategy_streams: Mapping[str, str], *, unattributed_scope: str | None = None
    ) -> GatewayExecutionScopePolicy:
        """Routes from strategy refs, with the Base-derived client-order prefixes.

        ``strategy_streams`` maps a strategy reference to its execution stream.
        The prefix of each strategy is
        :func:`bt_api_base.execution_row_observation_protocol.strategy_client_order_prefix`,
        the same derivation the order-entry owner uses when it generates the
        provider client order id (iteration 60 R3), so routing is not typed twice.
        """

        if not isinstance(strategy_streams, Mapping) or not strategy_streams:
            raise GatewayExecutionEventError("INVALID_EXECUTION_ROUTES")
        prefixes: dict[str, str] = {}
        for strategy_ref, stream in strategy_streams.items():
            try:
                prefix = strategy_client_order_prefix(strategy_ref)
            except ValueError:
                raise GatewayExecutionEventError("INVALID_EXECUTION_ROUTES") from None
            if prefix in prefixes:
                raise GatewayExecutionEventError("AMBIGUOUS_EXECUTION_ROUTES")
            prefixes[prefix] = stream
        return cls(prefixes, unattributed_scope)

    @property
    def scopes(self) -> frozenset[str]:
        extra = () if self.unattributed_scope is None else (self.unattributed_scope,)
        return frozenset((*self.client_order_prefixes.values(), *extra))

    def scope_for_client_order(self, client_order_id: str | None) -> str | None:
        if client_order_id is not None:
            best = None
            for prefix, scope in self.client_order_prefixes.items():
                if client_order_id.startswith(prefix) and (
                    best is None or len(prefix) > len(best[0])
                ):
                    best = (prefix, scope)
            if best is not None:
                return best[1]
        return self.unattributed_scope


@dataclass(frozen=True)
class GatewayExecutionPublishResult:
    """Counts of one publication; no observation values."""

    appended: int = 0
    duplicates: int = 0
    unattributed_dropped: int = 0


class GatewayExecutionEventPublisher:
    """Append execution observations of one account to its execution streams."""

    def __init__(
        self,
        journal: GatewayEventJournal,
        *,
        account_key: AccountKey,
        journal_account_scope: str,
        policy: GatewayExecutionScopePolicy,
    ) -> None:
        if type(journal) is not GatewayEventJournal:
            raise GatewayExecutionEventError("INVALID_JOURNAL")
        if type(account_key) is not AccountKey:
            raise GatewayExecutionEventError("INVALID_ACCOUNT_KEY")
        if type(policy) is not GatewayExecutionScopePolicy or not policy.scopes:
            raise GatewayExecutionEventError("INVALID_EXECUTION_ROUTES")
        self._journal = journal
        self._account_key = account_key
        self._account_scope = _text(journal_account_scope, "INVALID_JOURNAL_SCOPE")
        self._policy = policy
        self.unattributed_dropped = 0

    @property
    def journal(self) -> GatewayEventJournal:
        return self._journal

    @property
    def policy(self) -> GatewayExecutionScopePolicy:
        return self._policy

    @property
    def account_key(self) -> AccountKey:
        return self._account_key

    def publish(self, observations: Iterable[object]) -> GatewayExecutionPublishResult:
        """Append ``observations`` in order; every failure leaves later ones unwritten.

        Each append is its own transaction, so a failure (or a crash) after
        some appends leaves those durable; republishing the same batch is
        idempotent. Order routes in the batch are resolved before any fill so
        a fill reported ahead of its order observation still follows it.
        """

        items = tuple(observations)
        if len(items) > MAX_EXECUTION_BATCH:
            raise GatewayExecutionEventError("EXECUTION_BATCH_TOO_LARGE")
        batch_routes: dict[str, str | None] = {}
        for item in items:
            if type(item) is AccountExecutionOrderObservation:
                self._check_account(item)
                order = item.order
                client = order.client_order_id if order.intent_binding == "verified" else None
                route = self._policy.scope_for_client_order(client)
                if batch_routes.setdefault(order.order_id, route) != route:
                    raise GatewayExecutionEventError("EXECUTION_ROUTE_CONFLICT")
            elif type(item) is AccountExecutionTradeObservation:
                self._check_account(item)
            else:
                raise GatewayExecutionEventError("EXECUTION_OBSERVATION_INVALID")
        appended = duplicates = dropped = 0
        for item in items:
            if type(item) is AccountExecutionOrderObservation:
                order_id = item.order.order_id
                # The configured route of this observation; a different
                # persisted route is refused by the journal (fail closed).
                client = item.order.client_order_id
                if item.order.intent_binding != "verified":
                    client = None
                scope = self._policy.scope_for_client_order(client)
                bind = order_id
            else:
                order_id = item.trade.order_id
                scope = None
                if order_id is not None:
                    scope = self._persisted_route(order_id) or batch_routes.get(order_id)
                if scope is None:
                    scope = self._policy.unattributed_scope
                bind = None
            if scope is None:
                dropped += 1
                continue
            kind, event_id, payload = execution_observation_event(item)
            trade_fee = None
            if type(item) is AccountExecutionTradeObservation:
                # A fill's provider fee is cumulative for that fill: a higher
                # later fee is a fee correction, a lower one is refused.
                trade_fee = (
                    item.trade.instrument.instrument_id + "\x1f" + item.trade.trade_id,
                    item.fee,
                    item.fee_currency,
                )
            try:
                _event, created = self._journal.append_execution_fact(
                    self._account_scope,
                    scope,
                    event_id,
                    kind,
                    payload,
                    fact_digest=payload["fact_digest"],
                    bind_order_route=bind,
                    trade_fee=trade_fee,
                )
            except GatewayEventJournalError as error:
                code = error.code
                if not code.startswith("EXECUTION_"):
                    code = "EXECUTION_APPEND_FAILED"
                raise GatewayExecutionEventError(code) from None
            if created:
                appended += 1
            else:
                duplicates += 1
        self.unattributed_dropped += dropped
        return GatewayExecutionPublishResult(appended, duplicates, dropped)

    def _persisted_route(self, order_id: str) -> str | None:
        try:
            return self._journal.execution_order_route(self._account_scope, order_id)
        except (GatewayEventJournalError, ValueError):
            raise GatewayExecutionEventError("EXECUTION_ROUTE_UNAVAILABLE") from None

    def _check_account(self, item) -> None:
        if item.account_key != self._account_key:
            raise GatewayExecutionEventError("EXECUTION_ACCOUNT_MISMATCH")


__all__ = (
    "GatewayExecutionEventError",
    "GatewayExecutionEventPublisher",
    "GatewayExecutionPublishResult",
    "GatewayExecutionScopePolicy",
)
