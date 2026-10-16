"""Trusted provider-side proof for an unfiltered account-position read.

These objects are internal worker/provider contracts. They are deliberately
not account-snapshot wire DTOs: a client must not be able to turn a serialized
``positions_complete`` flag into a full-account risk baseline.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from bt_api_base.account_protocol import AccountKey, AccountObservation

if TYPE_CHECKING:
    from .account_session_worker import GatewayAccountSessionWorker
    from .event_journal import GatewayAccountSnapshot


class GatewayPositionSnapshotError(RuntimeError):
    """Finite, payload-free full-position source failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def position_rows_sha256(observation: AccountObservation) -> str:
    if type(observation) is not AccountObservation:
        raise GatewayPositionSnapshotError("POSITION_OBSERVATION_INVALID")
    return _sha256(_canonical_json([item.to_dict() for item in observation.positions]))


def resource_coverage_sha256(observation: AccountObservation) -> str:
    if type(observation) is not AccountObservation:
        raise GatewayPositionSnapshotError("POSITION_OBSERVATION_INVALID")
    return _sha256(_canonical_json([item.to_dict() for item in observation.coverage]))


def utc_timestamp_ns(value: str) -> int:
    if type(value) is not str:
        raise GatewayPositionSnapshotError("POSITION_TIMESTAMP_INVALID")
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        raise GatewayPositionSnapshotError("POSITION_TIMESTAMP_INVALID") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise GatewayPositionSnapshotError("POSITION_TIMESTAMP_INVALID")
    delta = parsed - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


@dataclass(frozen=True, slots=True)
class GatewayFullPositionSnapshot:
    """Provider-adapter result for an explicitly complete position query.

    Only a configured server-side provider adapter may return this result.
    The worker rechecks every binding against the exact observation before it
    records this as the current source. A bare ``AccountObservation`` remains
    supported for ordinary Gateway reads, but cannot authorize DIM03 baseline
    ingestion.
    """

    observation: AccountObservation
    account_key_id: str
    session_generation: str
    query_scope: str
    filters: tuple[str, ...]
    permission_scope: str
    permission_revision: str
    pagination_exhausted: bool
    page_count: int
    account_revision: int
    source_schema_version: str
    snapshot_version: str
    positions_sha256: str
    resource_coverage_sha256: str
    valid_until_utc: str

    def __post_init__(self) -> None:
        if type(self.observation) is not AccountObservation:
            raise GatewayPositionSnapshotError("POSITION_OBSERVATION_INVALID")
        for name in (
            "account_key_id",
            "session_generation",
            "query_scope",
            "permission_scope",
            "permission_revision",
            "source_schema_version",
            "snapshot_version",
            "valid_until_utc",
        ):
            value = getattr(self, name)
            if type(value) is not str or not value or value != value.strip():
                raise GatewayPositionSnapshotError("POSITION_COVERAGE_INVALID")
        if type(self.filters) is not tuple or any(
            type(item) is not str for item in self.filters
        ):
            raise GatewayPositionSnapshotError("POSITION_COVERAGE_INVALID")
        if type(self.pagination_exhausted) is not bool:
            raise GatewayPositionSnapshotError("POSITION_COVERAGE_INVALID")
        for name in ("page_count", "account_revision"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0 or value > 9_223_372_036_854_775_807:
                raise GatewayPositionSnapshotError("POSITION_COVERAGE_INVALID")
        for name in ("positions_sha256", "resource_coverage_sha256"):
            value = getattr(self, name)
            if (
                type(value) is not str
                or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)
            ):
                raise GatewayPositionSnapshotError("POSITION_COVERAGE_INVALID")
        valid_until_ns = utc_timestamp_ns(self.valid_until_utc)
        observed_ns = utc_timestamp_ns(self.observation.completed_at_utc)
        if valid_until_ns <= observed_ns:
            raise GatewayPositionSnapshotError("POSITION_COVERAGE_INVALID")

    @property
    def observed_at_ns(self) -> int:
        return utc_timestamp_ns(self.observation.completed_at_utc)

    @property
    def valid_until_ns(self) -> int:
        return utc_timestamp_ns(self.valid_until_utc)

    def to_coverage_payload(self, *, valid_until_ns: int | None = None) -> dict[str, object]:
        return {
            "account_revision": self.account_revision,
            "filters": list(self.filters),
            "observed_at_ns": self.observed_at_ns,
            "page_count": self.page_count,
            "pagination_exhausted": self.pagination_exhausted,
            "permission_revision": self.permission_revision,
            "permission_scope": self.permission_scope,
            "query_scope": self.query_scope,
            "snapshot_version": self.snapshot_version,
            "source_schema_version": self.source_schema_version,
            "valid_until_ns": self.valid_until_ns if valid_until_ns is None else valid_until_ns,
        }

    def source_payload(self) -> dict[str, object]:
        return {
            "account_key_id": self.account_key_id,
            "account_revision": self.account_revision,
            "filters": list(self.filters),
            "observation_id": self.observation.observation_id,
            "page_count": self.page_count,
            "pagination_exhausted": self.pagination_exhausted,
            "permission_revision": self.permission_revision,
            "permission_scope": self.permission_scope,
            "positions_sha256": self.positions_sha256,
            "query_scope": self.query_scope,
            "resource_coverage_sha256": self.resource_coverage_sha256,
            "session_generation": self.session_generation,
            "snapshot_version": self.snapshot_version,
            "source_schema_version": self.source_schema_version,
            "valid_until_utc": self.valid_until_utc,
        }


@dataclass(frozen=True, slots=True, repr=False)
class GatewayFullPositionSnapshotReceipt:
    """Owner-thread receipt tied by object identity to one live Gateway snapshot."""

    _issuer: object = field(repr=False, compare=False)
    _snapshot: object = field(repr=False, compare=False)
    _source: GatewayFullPositionSnapshot = field(repr=False, compare=False)
    account_key: AccountKey
    observation: AccountObservation = field(repr=False, compare=False)
    session_generation: str
    snapshot_cursor: int
    valid_until_ns: int

    def __post_init__(self) -> None:
        if type(self.account_key) is not AccountKey:
            raise GatewayPositionSnapshotError("POSITION_RECEIPT_INVALID")
        if type(self.observation) is not AccountObservation:
            raise GatewayPositionSnapshotError("POSITION_RECEIPT_INVALID")
        if type(self.session_generation) is not str or not self.session_generation:
            raise GatewayPositionSnapshotError("POSITION_RECEIPT_INVALID")
        if type(self.snapshot_cursor) is not int or self.snapshot_cursor <= 0:
            raise GatewayPositionSnapshotError("POSITION_RECEIPT_INVALID")
        if type(self.valid_until_ns) is not int or self.valid_until_ns <= 0:
            raise GatewayPositionSnapshotError("POSITION_RECEIPT_INVALID")

    @property
    def coverage(self) -> GatewayFullPositionSnapshot:
        return self._source

    @property
    def fingerprint(self) -> str:
        return _sha256(
            _canonical_json(
                {
                    "account_key_id": self.account_key.account_key_id,
                    "observation_id": self.observation.observation_id,
                    "observation_sha256": _sha256(
                        _canonical_json(self.observation.to_dict())
                    ),
                    "session_generation": self.session_generation,
                    "snapshot_cursor": self.snapshot_cursor,
                    "source": self._source.source_payload(),
                    "valid_until_ns": self.valid_until_ns,
                }
            )
        )

    def assert_current(self) -> None:
        verifier = getattr(self._issuer, "_assert_current_position_snapshot_receipt", None)
        if not callable(verifier):
            raise GatewayPositionSnapshotError("POSITION_RECEIPT_INVALID")
        verifier(self)

