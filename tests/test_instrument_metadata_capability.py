"""Provider-neutral instrument metadata capability of the account session worker.

The worker never imports a provider package. A provider opts in by
implementing ``read_instrument_metadata`` and ``is_current_instrument_metadata``;
the worker accepts a result only if the provider recognizes it as its own
sealed fact and it is bound to the current owner generation.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from test_account_session_worker import Clocks, FakeProvider, _observation, _worker

from bt_api_gateway.account_session_worker import GatewayAccountSessionWorkerError


@dataclass(frozen=True)
class _Metadata:
    account_session_generation: str
    instrument_id: str

    def to_dict(self) -> dict[str, object]:
        return {"instrument_id": self.instrument_id}


class _ProviderError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _MetadataProvider(FakeProvider):
    def __init__(self, observations: list[object]) -> None:
        super().__init__(observations)
        self.issued: list[object] = []
        self.result_override: object | None = None
        self.read_error: BaseException | None = None
        self.generation_override: str | None = None

    def read_instrument_metadata(
        self, *, instrument_id: str, exchange_id: str, generation: str, timeout: float
    ) -> object:
        assert timeout > 0 and exchange_id == "SHFE"
        if self.read_error is not None:
            raise self.read_error
        result = self.result_override or _Metadata(
            self.generation_override or generation, instrument_id
        )
        self.issued.append(result)
        return result

    def is_current_instrument_metadata(self, value: object) -> bool:
        return any(value is issued for issued in self.issued)


def _ready_worker(tmp_path, provider):
    clocks = Clocks()
    provider.observations.append(_observation(clocks, observation_id="metadata-base"))
    worker, _journal = _worker(tmp_path, provider, clocks)
    worker.start()
    return worker


def test_capability_is_only_advertised_when_both_methods_exist(tmp_path) -> None:
    plain = _ready_worker(tmp_path / "plain", FakeProvider([]))
    try:
        assert plain.instrument_metadata_available is False
        with pytest.raises(GatewayAccountSessionWorkerError) as raised:
            plain.read_instrument_metadata(instrument_id="rb2701", exchange_id="SHFE")
        assert raised.value.code == "PROVIDER_FACT_UNAVAILABLE"
    finally:
        plain.close()

    capable = _ready_worker(tmp_path / "capable", _MetadataProvider([]))
    try:
        assert capable.instrument_metadata_available is True
    finally:
        capable.close()


def test_sealed_current_generation_result_is_returned(tmp_path) -> None:
    provider = _MetadataProvider([])
    worker = _ready_worker(tmp_path, provider)
    try:
        metadata = worker.read_instrument_metadata(instrument_id="rb2701", exchange_id="SHFE")
        assert metadata.to_dict() == {"instrument_id": "rb2701"}
        assert metadata.account_session_generation == provider.connect_generations[-1]
    finally:
        worker.close()


@pytest.mark.parametrize("case", ["foreign_result", "stale_generation"])
def test_unsealed_or_stale_results_are_rejected(tmp_path, case) -> None:
    provider = _MetadataProvider([])
    worker = _ready_worker(tmp_path, provider)
    if case == "foreign_result":
        # Same shape, but not issued by the provider: not trusted.
        provider.result_override = _Metadata("ignored", "rb2701")
        provider.is_current_instrument_metadata = lambda value: False  # type: ignore[method-assign]
    else:
        provider.generation_override = "an-older-generation"
    try:
        with pytest.raises(GatewayAccountSessionWorkerError) as raised:
            worker.read_instrument_metadata(instrument_id="rb2701", exchange_id="SHFE")
        assert raised.value.code == "PROVIDER_FACT_UNAVAILABLE"
    finally:
        worker.close()


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (_ProviderError("INSTRUMENT_QUERY_LATE"), "INSTRUMENT_QUERY_LATE"),
        (_ProviderError("SOMETHING_PROVIDER_SPECIFIC"), "PROVIDER_FACT_READ_FAILED"),
        (RuntimeError("secret detail"), "PROVIDER_FACT_READ_FAILED"),
    ],
    ids=["known-code", "unknown-code", "no-code"],
)
def test_provider_errors_collapse_to_finite_codes(tmp_path, error, expected) -> None:
    provider = _MetadataProvider([])
    provider.read_error = error
    worker = _ready_worker(tmp_path, provider)
    try:
        with pytest.raises(GatewayAccountSessionWorkerError) as raised:
            worker.read_instrument_metadata(instrument_id="rb2701", exchange_id="SHFE")
        assert raised.value.code == expected
        assert "secret" not in str(raised.value)
    finally:
        worker.close()


def test_gateway_package_does_not_import_provider_packages() -> None:
    import ast
    from pathlib import Path

    import bt_api_gateway

    root = Path(bt_api_gateway.__file__).parent
    offenders = []
    for path in sorted(root.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            offenders += [
                f"{path.name}:{name}"
                for name in names
                if name.startswith("bt_api_")
                and not name.startswith(("bt_api_base", "bt_api_gateway"))
            ]
    assert offenders == []


def test_quota_session_passes_the_seal_check_through_without_admission(tmp_path) -> None:
    from test_quota_admission import _owner

    from bt_api_gateway.quota_admission import GatewayQuotaProviderSession, GatewayQuotaSubject

    provider = _MetadataProvider([])
    admission = _owner(tmp_path / "quota.sqlite3")
    session = GatewayQuotaProviderSession(
        provider,
        admission,
        GatewayQuotaSubject("acct:meta", "strategy:meta", "SHFE", "run:meta"),
    )
    issued = _Metadata("g1", "rb2701")
    provider.issued.append(issued)
    assert session.is_current_instrument_metadata(issued) is True  # type: ignore[attr-defined]
    assert session.is_current_instrument_metadata(_Metadata("g1", "rb2701")) is False  # type: ignore[attr-defined]

    plain = GatewayQuotaProviderSession(
        FakeProvider([]),
        admission,
        GatewayQuotaSubject("acct:plain", "strategy:plain", "SHFE", "run:plain"),
    )
    assert not hasattr(plain, "is_current_instrument_metadata")
    assert not hasattr(plain, "read_instrument_metadata")
