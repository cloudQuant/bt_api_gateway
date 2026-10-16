"""Focused tests for the process-local Gateway session-owner seam."""

from __future__ import annotations

import pytest

from bt_api_gateway.session_owner import GatewaySessionOwner, GatewaySessionOwnerError

_SESSION_REF = "gateway-account-session-v1"
_CREDENTIAL_REF = "operator-vault://gateway/account-a"
_SYNTHETIC_SECRET = "AFI09-LOCAL-SYNTHETIC-SECRET"  # noqa: S105 -- synthetic test sentinel.


class _Provider:
    def connect(self, *, account_key: object, generation: str, timeout: float) -> None:
        return None

    def read_account(self, *, generation: str, timeout: float) -> object:
        return object()

    def close(self) -> bool:
        return True


def test_owner_resolves_once_and_rejects_a_second_provider_claim() -> None:
    resolutions: list[str] = []
    constructions: list[tuple[str, object]] = []
    provider = _Provider()

    def resolve(credential_ref: str) -> object:
        resolutions.append(credential_ref)
        return _SYNTHETIC_SECRET

    def build(session_ref: str, credential: object) -> _Provider:
        constructions.append((session_ref, credential))
        assert credential == _SYNTHETIC_SECRET
        return provider

    owner = GatewaySessionOwner(
        {_SESSION_REF: _CREDENTIAL_REF},
        resolve_credential=resolve,
        provider_factory=build,
    )

    assert owner.create_provider(_SESSION_REF) is provider
    with pytest.raises(GatewaySessionOwnerError) as duplicate:
        owner.create_provider(_SESSION_REF)

    assert duplicate.value.code == "SESSION_ALREADY_CLAIMED"
    assert resolutions == [_CREDENTIAL_REF]
    assert constructions == [(_SESSION_REF, _SYNTHETIC_SECRET)]
    assert owner.claimed_session_count == 1
    assert owner.uncertain_provider_count == 0
    assert _SYNTHETIC_SECRET not in str(duplicate.value)
    assert _CREDENTIAL_REF not in repr(owner)


def test_unknown_session_ref_fails_before_resolver_or_factory() -> None:
    calls: list[str] = []
    owner = GatewaySessionOwner(
        {_SESSION_REF: _CREDENTIAL_REF},
        resolve_credential=lambda ref: calls.append(f"resolve:{ref}"),
        provider_factory=lambda ref, secret: calls.append(f"build:{ref}"),
    )

    with pytest.raises(GatewaySessionOwnerError) as raised:
        owner.create_provider("different-account-session")

    assert raised.value.code == "SESSION_NOT_CONFIGURED"
    assert calls == []
    assert owner.claimed_session_count == 0


@pytest.mark.parametrize(
    ("resolve", "build", "expected_code"),
    [
        (
            lambda _ref: (_ for _ in ()).throw(RuntimeError(_SYNTHETIC_SECRET)),
            lambda _ref, _credential: _Provider(),
            "CREDENTIAL_RESOLUTION_FAILED",
        ),
        (
            lambda _ref: _SYNTHETIC_SECRET,
            lambda _ref, credential: (_ for _ in ()).throw(RuntimeError(str(credential))),
            "PROVIDER_CREATION_FAILED",
        ),
    ],
)
def test_callback_errors_are_finite_and_secret_free(
    resolve: object, build: object, expected_code: str
) -> None:
    owner = GatewaySessionOwner(
        {_SESSION_REF: _CREDENTIAL_REF},
        resolve_credential=resolve,  # type: ignore[arg-type]
        provider_factory=build,  # type: ignore[arg-type]
    )

    with pytest.raises(GatewaySessionOwnerError) as raised:
        owner.create_provider(_SESSION_REF)

    assert raised.value.code == expected_code
    assert str(raised.value) == expected_code
    assert _SYNTHETIC_SECRET not in str(raised.value)
    assert _CREDENTIAL_REF not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    with pytest.raises(GatewaySessionOwnerError) as retry:
        owner.create_provider(_SESSION_REF)
    assert retry.value.code == "SESSION_ALREADY_CLAIMED"


def test_unavailable_credential_never_calls_provider_factory() -> None:
    builds: list[str] = []
    owner = GatewaySessionOwner(
        {_SESSION_REF: _CREDENTIAL_REF},
        resolve_credential=lambda _ref: None,
        provider_factory=lambda ref, _credential: builds.append(ref),
    )

    with pytest.raises(GatewaySessionOwnerError) as raised:
        owner.create_provider(_SESSION_REF)

    assert raised.value.code == "CREDENTIAL_UNAVAILABLE"
    assert builds == []
    assert raised.value.__context__ is None


def test_invalid_provider_close_failure_is_retained_without_error_text() -> None:
    class _UnclosableInvalidProvider:
        def __init__(self) -> None:
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1
            raise RuntimeError(_SYNTHETIC_SECRET)

    provider = _UnclosableInvalidProvider()
    owner = GatewaySessionOwner(
        {_SESSION_REF: _CREDENTIAL_REF},
        resolve_credential=lambda _ref: _SYNTHETIC_SECRET,
        provider_factory=lambda _ref, _credential: provider,
    )

    with pytest.raises(GatewaySessionOwnerError) as raised:
        owner.create_provider(_SESSION_REF)

    assert raised.value.code == "PROVIDER_CLOSE_UNCONFIRMED"
    assert str(raised.value) == "PROVIDER_CLOSE_UNCONFIRMED"
    assert raised.value.__context__ is None
    assert provider.close_calls == 1
    assert owner.uncertain_provider_count == 1


@pytest.mark.parametrize(
    "bindings",
    [
        {},
        {" invalid session": _CREDENTIAL_REF},
        {_SESSION_REF: "contains whitespace"},
        {_SESSION_REF: _CREDENTIAL_REF, "gateway-account-session-v2": "bad ref"},
    ],
)
def test_invalid_operator_reference_map_is_rejected(bindings: object) -> None:
    with pytest.raises(GatewaySessionOwnerError) as raised:
        GatewaySessionOwner(
            bindings,  # type: ignore[arg-type]
            resolve_credential=lambda _ref: _SYNTHETIC_SECRET,
            provider_factory=lambda _ref, _credential: _Provider(),
        )

    assert raised.value.code == "INVALID_CREDENTIAL_BINDINGS"
    assert _SYNTHETIC_SECRET not in str(raised.value)
