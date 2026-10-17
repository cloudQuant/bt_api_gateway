from __future__ import annotations

import json
from collections import deque
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

import pytest
from bt_api_base.account_protocol import (
    AccountBalance,
    AccountKey,
    AccountObservation,
    AccountResourceKey,
)

from bt_api_gateway.account_process import (
    _MAX_FRAME_BYTES,
    GatewayAccountSessionProcessBinding,
    GatewayAccountSessionProcessError,
    GatewayAccountSessionProcessProvider,
    GatewayAccountSessionProfileUnavailableError,
    _encode_frame,
    _envelope,
    serve_account_session_child,
)

_GENERATION = "0123456789abcdef0123456789abcdef"
_NATIVE_GENERATION = 7
_ACCOUNT_KEY = AccountKey(
    provider="synthetic",
    venue="local",
    environment="test",
    account_id="account-a",
)


def _child_target(connection: Any) -> None:
    del connection


def _native_free_factory(profile_ref: str) -> GatewayAccountSessionProcessBinding:
    if profile_ref != "synthetic.read-only.v1":
        raise GatewayAccountSessionProfileUnavailableError()
    return GatewayAccountSessionProcessBinding(_ACCOUNT_KEY, _NativeFreeProvider())


def _native_free_close_projector(provider: object, generation: int) -> dict[str, object]:
    del provider, generation
    raise AssertionError("native-free providers have no native receipt")


_NATIVE_PROJECTED_GENERATIONS: list[int] = []
_PARTIAL_NATIVE_PROVIDERS: list[_PartialConnectNativeProvider] = []


class _NativeOwnedProvider:
    native_owner_created = True
    native_connection_generation = _NATIVE_GENERATION

    def connect(self, *, account_key: AccountKey, generation: str, timeout: float) -> None:
        assert account_key == _ACCOUNT_KEY
        assert generation == _GENERATION
        assert timeout > 0

    def read_account(self, *, generation: str, timeout: float) -> AccountObservation:
        del generation, timeout
        raise AssertionError("read is not part of this close receipt test")

    def close(self) -> bool:
        return True


def _native_owned_factory(profile_ref: str) -> GatewayAccountSessionProcessBinding:
    if profile_ref != "synthetic.native.v1":
        raise GatewayAccountSessionProfileUnavailableError()
    return GatewayAccountSessionProcessBinding(_ACCOUNT_KEY, _NativeOwnedProvider())


def _native_owned_close_projector(
    provider: object, expected_native_generation: int
) -> dict[str, object]:
    assert type(expected_native_generation) is int
    assert expected_native_generation == _NATIVE_GENERATION
    assert type(provider) is _NativeOwnedProvider
    assert provider.native_connection_generation == expected_native_generation
    _NATIVE_PROJECTED_GENERATIONS.append(expected_native_generation)
    return {
        "connection_generation": expected_native_generation,
        "join_required": True,
        "join_completed": True,
        "native_released": True,
        "thread_alive": False,
        "timed_out": False,
        "complete": True,
    }


class _PartialNativeConnectError(Exception):
    code = "NATIVE_CONNECT_INTERRUPTED"


class _PartialConnectNativeProvider:
    def __init__(
        self, *, close_failures: int = 0, owner_after_close: bool = True
    ) -> None:
        self.close_failures_remaining = close_failures
        self.owner_after_close = owner_after_close
        self._native_owner_created: bool | None = None
        self._native_object: object | None = None
        self.close_native_objects: list[object] = []
        self.last_native_stop_receipt: dict[str, object] | None = None

    @property
    def native_owner_created(self) -> bool | None:
        return self._native_owner_created

    @property
    def native_connection_generation(self) -> int | None:
        if self._native_owner_created is True or self._native_owner_created is None:
            return _NATIVE_GENERATION if self._native_object is not None else None
        return None

    def connect(self, *, account_key: AccountKey, generation: str, timeout: float) -> None:
        assert account_key == _ACCOUNT_KEY
        assert generation == _GENERATION
        assert timeout > 0
        # A native object exists, but the provider deliberately cannot yet
        # report its ownership state after this interrupted startup.
        self._native_object = object()
        self._native_owner_created = None
        raise _PartialNativeConnectError()

    def read_account(self, *, generation: str, timeout: float) -> AccountObservation:
        del generation, timeout
        raise AssertionError("partial-connect provider is not readable")

    def close(self) -> bool:
        if self._native_object is None:
            return False
        self.close_native_objects.append(self._native_object)
        if self.close_failures_remaining:
            self.close_failures_remaining -= 1
            return False
        self._native_owner_created = self.owner_after_close
        if self.owner_after_close:
            self.last_native_stop_receipt = {
                "connection_generation": _NATIVE_GENERATION,
                "join_required": True,
                "join_completed": True,
                "native_released": True,
                "thread_alive": False,
                "timed_out": False,
                "complete": True,
            }
        return True


def _partial_native_factory(profile_ref: str) -> GatewayAccountSessionProcessBinding:
    if profile_ref != "synthetic.partial-native.v1":
        raise GatewayAccountSessionProfileUnavailableError()
    provider = _PartialConnectNativeProvider()
    _PARTIAL_NATIVE_PROVIDERS.append(provider)
    return GatewayAccountSessionProcessBinding(_ACCOUNT_KEY, provider)


def _partial_native_retry_factory(profile_ref: str) -> GatewayAccountSessionProcessBinding:
    if profile_ref != "synthetic.partial-native-retry.v1":
        raise GatewayAccountSessionProfileUnavailableError()
    provider = _PartialConnectNativeProvider(close_failures=1)
    _PARTIAL_NATIVE_PROVIDERS.append(provider)
    return GatewayAccountSessionProcessBinding(_ACCOUNT_KEY, provider)


def _partial_native_unresolved_factory(profile_ref: str) -> GatewayAccountSessionProcessBinding:
    if profile_ref != "synthetic.partial-native-unresolved.v1":
        raise GatewayAccountSessionProfileUnavailableError()
    provider = _PartialConnectNativeProvider(owner_after_close=False)
    _PARTIAL_NATIVE_PROVIDERS.append(provider)
    return GatewayAccountSessionProcessBinding(_ACCOUNT_KEY, provider)


def _partial_native_close_projector(
    provider: object, expected_native_generation: int
) -> dict[str, object]:
    assert type(expected_native_generation) is int
    assert expected_native_generation == _NATIVE_GENERATION
    assert type(provider) is _PartialConnectNativeProvider
    assert provider.native_owner_created is True
    assert provider.native_connection_generation == expected_native_generation
    assert provider.last_native_stop_receipt is not None
    return dict(provider.last_native_stop_receipt)


def _partial_native_requests(profile_ref: str, *, close_count: int) -> list[dict[str, object]]:
    operations = ["bootstrap", "connect", *(["close"] * close_count)]
    requests: list[dict[str, object]] = []
    for index, operation in enumerate(operations, start=1):
        requests.append(
            _envelope(
                message_type="request",
                request_id=f"{index:032x}",
                generation=_GENERATION,
                operation=operation,
                status="request",
                payload=(
                    {"profile_ref": profile_ref, "read_only": True}
                    if operation == "bootstrap"
                    else {"timeout_seconds": 1.0}
                ),
            )
        )
    return requests


class _ChildConnection:
    def __init__(self, requests: list[dict[str, object]]) -> None:
        self.incoming = deque(_encode_frame(request) for request in requests)
        self.sent: list[dict[str, object]] = []
        self.closed = False

    def recv_bytes(self, maxlength: int) -> bytes:
        raw = self.incoming.popleft()
        if len(raw) > maxlength:
            raise OSError("oversized")
        return raw

    def send_bytes(self, value: bytes) -> None:
        self.sent.append(json.loads(value.decode("ascii")))

    def close(self) -> None:
        self.closed = True


class _NativeFreeProvider:
    native_owner_created = False
    native_connection_generation = None

    def connect(self, *, account_key: AccountKey, generation: str, timeout: float) -> None:
        assert account_key == _ACCOUNT_KEY
        assert generation == _GENERATION
        assert timeout > 0

    def read_account(self, *, generation: str, timeout: float) -> AccountObservation:
        assert generation == _GENERATION
        assert timeout > 0
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        resource = AccountResourceKey(product_type="spot", margin_pool="cross")
        balance = AccountBalance(
            resource=resource,
            currency="USD",
            total="100",
            available="100",
            locked="0",
            observed_at_utc=now,
        )
        return AccountObservation(
            account_key=_ACCOUNT_KEY,
            observation_id="synthetic-observation-1",
            coverage=(resource,),
            balances=(balance,),
            positions=(),
            valuation=None,
            started_at_utc=now,
            completed_at_utc=now,
            consistency="provider_atomic",
            balances_complete=True,
            positions_complete=True,
        )

    def close(self) -> bool:
        return True


class _FakeWorld:
    def __init__(self) -> None:
        self.incoming: deque[bytes | object] = deque()
        self.requests: list[dict[str, object]] = []
        self.parent = _FakeConnection(self, "parent")
        self.child = _FakeConnection(self, "child")
        self.process = _FakeProcess(self)
        self.timeout_next_wait = False
        self.delay_read_reply = False
        self.delayed_read_reply: bytes | None = None
        self.defer_shutdown = False
        self.eof_ready = False
        self.close_receipt: dict[str, object] | None = None
        self.close_unconfirmed_remaining = 0
        self.connect_error_code: str | None = None
        self.mutate_generation = False
        self.oversize_bootstrap = False
        self.profile_unavailable = False
        self.process_construct_error = False

    def respond(self, raw: bytes) -> None:
        request = json.loads(raw.decode("ascii"))
        self.requests.append(request)
        operation = request["operation"]
        if operation == "bootstrap":
            if self.oversize_bootstrap:
                self.incoming.append(b"x" * (_MAX_FRAME_BYTES + 1))
                return
            if self.profile_unavailable:
                status = "profile_unavailable"
                payload: dict[str, object] = {"error_code": "PROFILE_UNAVAILABLE"}
                self.process.exitcode = 0
                self.eof_ready = True
            else:
                status = "ready"
                payload = {"account_key_id": _ACCOUNT_KEY.account_key_id}
        elif operation == "connect":
            if self.connect_error_code is not None:
                status = "operation_failed"
                payload = {"error_code": self.connect_error_code}
            else:
                status = "connected"
                payload = {
                    "native_owner_created": self.close_receipt is not None,
                    "native_connection_generation": _NATIVE_GENERATION
                    if self.close_receipt is not None
                    else None,
                }
        elif operation == "read_account":
            status = "account_read"
            payload = {"kind": "discarded-late-result"}
        elif operation == "close":
            if self.close_unconfirmed_remaining:
                self.close_unconfirmed_remaining -= 1
                self.incoming.append(
                    _encode_frame(
                        _envelope(
                            message_type="response",
                            request_id=request["request_id"],
                            generation=request["generation"],
                            operation=operation,
                            status="close_unconfirmed",
                            payload={"error_code": "PROVIDER_CLOSE_UNCONFIRMED"},
                        )
                    )
                )
                return
            if self.close_receipt is None:
                payload = {
                    "native_owner_created": False,
                    "native_connection_generation": None,
                    "native_stop_receipt": None,
                    "close_confirmed": True,
                }
            else:
                payload = {
                    "native_owner_created": True,
                    "native_connection_generation": _NATIVE_GENERATION,
                    "native_stop_receipt": self.close_receipt,
                    "close_confirmed": True,
                }
            status = "closed"
            if not self.defer_shutdown:
                self.process.exitcode = 0
                self.eof_ready = True
        else:
            status = "operation_failed"
            payload = {"error_code": "UNEXPECTED_OPERATION"}
        generation = "f" * 32 if self.mutate_generation else request["generation"]
        response = _envelope(
            message_type="response",
            request_id=request["request_id"],
            generation=generation,
            operation=operation,
            status=status,
            payload=payload,
        )
        encoded = _encode_frame(response)
        if operation == "read_account" and self.delay_read_reply:
            self.delayed_read_reply = encoded
            return
        self.incoming.append(encoded)

    def wait(self, objects: list[object], timeout: float) -> list[object]:
        del timeout
        if self.timeout_next_wait:
            self.timeout_next_wait = False
            return []
        ready: list[object] = []
        if self.incoming and self.parent in objects:
            ready.append(self.parent)
        if self.eof_ready and self.parent in objects:
            ready.append(self.parent)
        if self.process.exitcode is not None and self.process.sentinel in objects:
            ready.append(self.process.sentinel)
        return ready


class _FakeConnection:
    def __init__(self, world: _FakeWorld, side: str) -> None:
        self.world = world
        self.side = side
        self.closed = False
        self.close_error = False

    def send_bytes(self, raw: bytes) -> None:
        if self.closed:
            raise OSError("closed")
        if self.side == "parent":
            self.world.respond(raw)

    def recv_bytes(self, maxlength: int = 2**31 - 1) -> bytes:
        if self.closed:
            raise OSError("closed")
        if not self.world.incoming:
            if self.world.eof_ready:
                raise EOFError()
            raise AssertionError("no queued fake frame")
        value = self.world.incoming.popleft()
        if len(value) > maxlength:
            raise OSError("bad message length")
        return value  # type: ignore[return-value]

    def close(self) -> None:
        if self.close_error:
            raise OSError("synthetic endpoint close uncertainty")
        self.closed = True


class _FakeProcess:
    def __init__(self, world: _FakeWorld) -> None:
        self.world = world
        self.sentinel = object()
        self.pid: int | None = None
        self.exitcode: int | None = None
        self.closed = False
        self.start_error = False
        self.close_error = False

    def start(self) -> None:
        if self.start_error:
            raise OSError("synthetic startup failure")
        self.pid = 123

    def join(self, timeout: float = 0) -> None:
        del timeout

    def close(self) -> None:
        if self.close_error:
            raise OSError("synthetic process close uncertainty")
        self.closed = True


class _FakeContext:
    def __init__(self, world: _FakeWorld) -> None:
        self.world = world

    def Pipe(self, *, duplex: bool) -> tuple[_FakeConnection, _FakeConnection]:  # noqa: N802
        assert duplex is True
        return self.world.parent, self.world.child

    def Process(  # noqa: N802
        self, *, target: object, args: tuple[object, ...]
    ) -> _FakeProcess:
        assert target is _child_target
        assert args == (self.world.child,)
        if self.world.process_construct_error:
            raise OSError("synthetic process construction failure")
        return self.world.process


def _provider(world: _FakeWorld) -> GatewayAccountSessionProcessProvider:
    result = GatewayAccountSessionProcessProvider(
        account_key=_ACCOUNT_KEY,
        profile_ref="synthetic.read-only.v1",
        child_target=_child_target,
    )
    result._context = _FakeContext(world)
    result._wait = world.wait
    return result


def test_partial_process_start_closes_unspawned_pipe_endpoints() -> None:
    world = _FakeWorld()
    world.process.start_error = True
    provider = _provider(world)

    with pytest.raises(GatewayAccountSessionProcessError) as error:
        provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)

    assert error.value.code == "PROCESS_START_FAILED"
    assert world.parent.closed and world.child.closed
    assert world.process.closed
    assert not provider.custody_retained
    assert provider.close() is True


def test_partial_start_cleanup_uncertainty_retains_exact_local_handles() -> None:
    world = _FakeWorld()
    world.process.start_error = True
    world.parent.close_error = True
    provider = _provider(world)

    with pytest.raises(GatewayAccountSessionProcessError) as error:
        provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)

    assert error.value.code == "PROCESS_START_CLEANUP_UNCERTAIN"
    assert provider.process_state == "unknown"
    assert provider.custody_retained
    assert provider._process is world.process
    assert provider._connection is world.parent
    assert provider._child_connection is world.child
    assert world.parent.closed is False
    assert world.child.closed is True
    assert world.process.closed is True


@pytest.mark.parametrize("failing_side", ["parent", "child"])
def test_process_constructor_failure_pipe_close_retries_explicitly(
    failing_side: str,
) -> None:
    world = _FakeWorld()
    world.process_construct_error = True
    getattr(world, failing_side).close_error = True
    provider = _provider(world)

    with pytest.raises(GatewayAccountSessionProcessError) as error:
        provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)

    assert error.value.code == "PROCESS_START_CLEANUP_UNCERTAIN"
    assert provider.process_state == "unknown"
    assert provider.custody_retained
    assert provider._process is None
    assert provider._connection is (world.parent if failing_side == "parent" else None)
    assert provider._child_connection is (world.child if failing_side == "child" else None)
    assert world.parent.closed is (failing_side != "parent")
    assert world.child.closed is (failing_side != "child")
    assert provider.close() is False
    assert provider.custody_retained
    assert provider._connection is (world.parent if failing_side == "parent" else None)
    assert provider._child_connection is (world.child if failing_side == "child" else None)

    getattr(world, failing_side).close_error = False
    assert provider.close() is True
    assert provider.process_state == "closed"
    assert not provider.custody_retained
    assert provider._connection is None
    assert provider._child_connection is None


def test_partial_start_process_close_uncertainty_retains_exact_local_handles() -> None:
    world = _FakeWorld()
    world.process.start_error = True
    world.process.close_error = True
    provider = _provider(world)

    with pytest.raises(GatewayAccountSessionProcessError) as error:
        provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)

    assert error.value.code == "PROCESS_START_CLEANUP_UNCERTAIN"
    assert provider.process_state == "unknown"
    assert provider.custody_retained
    assert provider._process is world.process
    assert provider._connection is world.parent
    assert provider._child_connection is world.child
    assert world.parent.closed and world.child.closed
    assert world.process.closed is False


def test_late_profile_rejection_is_validated_then_closed_without_command_replay() -> None:
    world = _FakeWorld()
    world.profile_unavailable = True
    world.timeout_next_wait = True
    provider = _provider(world)

    with pytest.raises(GatewayAccountSessionProcessError) as error:
        provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)

    assert error.value.code == "PROCESS_RESPONSE_TIMEOUT"
    assert provider.custody_retained
    assert provider.close() is True
    assert [item["operation"] for item in world.requests] == ["bootstrap"]
    assert not provider.custody_retained


def test_late_read_reply_is_drained_once_before_close_without_replay() -> None:
    world = _FakeWorld()
    provider = _provider(world)
    provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)
    world.delay_read_reply = True
    world.timeout_next_wait = True

    with pytest.raises(GatewayAccountSessionProcessError) as error:
        provider.read_account(generation=_GENERATION, timeout=0.1)
    assert error.value.code == "PROCESS_RESPONSE_TIMEOUT"
    assert provider.custody_retained
    assert [item["operation"] for item in world.requests].count("read_account") == 1

    assert world.delayed_read_reply is not None
    world.incoming.append(world.delayed_read_reply)
    assert provider.close() is True
    assert [item["operation"] for item in world.requests].count("read_account") == 1
    assert [item["operation"] for item in world.requests].count("close") == 1
    assert not provider.custody_retained


def test_wrong_generation_reply_retains_exact_process_and_pipe() -> None:
    world = _FakeWorld()
    world.mutate_generation = True
    provider = _provider(world)

    with pytest.raises(GatewayAccountSessionProcessError):
        provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)

    assert provider.process_state == "unknown"
    assert provider.custody_retained
    assert provider._process is world.process
    assert provider._connection is world.parent
    assert world.process.exitcode is None
    assert [item["operation"] for item in world.requests] == ["bootstrap"]
    assert world.process.closed is False
    assert world.parent.closed is False


def test_oversized_frame_retains_exact_process_and_pipe() -> None:
    world = _FakeWorld()
    world.oversize_bootstrap = True
    provider = _provider(world)

    with pytest.raises(GatewayAccountSessionProcessError):
        provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)

    assert provider.process_state == "unknown"
    assert provider.custody_retained
    assert provider._process is world.process
    assert provider._connection is world.parent
    assert world.process.closed is False
    assert world.parent.closed is False


def test_close_requires_process_exit_and_eof_after_valid_ack() -> None:
    world = _FakeWorld()
    world.defer_shutdown = True
    provider = _provider(world)
    provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)

    assert provider.close() is False
    assert provider.process_state == "connected"
    assert provider.custody_retained
    assert [item["operation"] for item in world.requests].count("close") == 1

    world.process.exitcode = 0
    world.eof_ready = True
    assert provider.close() is True
    assert provider.process_state == "closed"
    assert not provider.custody_retained
    assert [item["operation"] for item in world.requests].count("close") == 1


def test_native_close_ack_requires_exact_complete_generation_receipt() -> None:
    world = _FakeWorld()
    world.close_receipt = {
        "connection_generation": _NATIVE_GENERATION,
        "join_required": True,
        "join_completed": True,
        "native_released": True,
        "thread_alive": False,
        "timed_out": False,
        "complete": True,
    }
    provider = _provider(world)
    provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)
    assert provider.close() is True

    bad_world = _FakeWorld()
    bad_world.close_receipt = dict(world.close_receipt)
    bad_world.close_receipt["connection_generation"] = _NATIVE_GENERATION + 1
    bad_provider = _provider(bad_world)
    bad_provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)
    assert bad_provider.close() is False
    assert bad_provider.custody_retained
    assert bad_world.process.closed is False


def test_native_child_close_projector_receives_acknowledged_native_generation() -> None:
    _NATIVE_PROJECTED_GENERATIONS.clear()
    requests = [
        _envelope(
            message_type="request",
            request_id="a" * 32,
            generation=_GENERATION,
            operation="bootstrap",
            status="request",
            payload={"profile_ref": "synthetic.native.v1", "read_only": True},
        ),
        _envelope(
            message_type="request",
            request_id="b" * 32,
            generation=_GENERATION,
            operation="connect",
            status="request",
            payload={"timeout_seconds": 1.0},
        ),
        _envelope(
            message_type="request",
            request_id="c" * 32,
            generation=_GENERATION,
            operation="close",
            status="request",
            payload={"timeout_seconds": 1.0},
        ),
    ]
    connection = _ChildConnection(requests)

    serve_account_session_child(
        connection,
        provider_factory=_native_owned_factory,
        close_receipt_projector=_native_owned_close_projector,
    )

    assert _NATIVE_PROJECTED_GENERATIONS == [_NATIVE_GENERATION]
    assert [frame["status"] for frame in connection.sent] == ["ready", "connected", "closed"]
    assert all(frame["generation"] == _GENERATION for frame in connection.sent)
    close_payload = connection.sent[-1]["payload"]
    assert close_payload == {
        "native_owner_created": True,
        "native_connection_generation": _NATIVE_GENERATION,
        "native_stop_receipt": {
            "connection_generation": _NATIVE_GENERATION,
            "join_required": True,
            "join_completed": True,
            "native_released": True,
            "thread_alive": False,
            "timed_out": False,
            "complete": True,
        },
        "close_confirmed": True,
    }
    assert connection.closed


@pytest.mark.parametrize(
    ("close_failures", "factory", "profile_ref"),
    [
        (0, _partial_native_factory, "synthetic.partial-native.v1"),
        (
            1,
            _partial_native_retry_factory,
            "synthetic.partial-native-retry.v1",
        ),
    ],
)
def test_partial_connect_unknown_owner_closes_same_provider_and_requires_receipt(
    close_failures: int,
    factory: Any,
    profile_ref: str,
) -> None:
    _PARTIAL_NATIVE_PROVIDERS.clear()
    close_count = close_failures + 1
    connection = _ChildConnection(
        _partial_native_requests(profile_ref, close_count=close_count)
    )

    serve_account_session_child(
        connection,
        provider_factory=factory,
        close_receipt_projector=_partial_native_close_projector,
    )

    assert len(_PARTIAL_NATIVE_PROVIDERS) == 1
    provider = _PARTIAL_NATIVE_PROVIDERS[0]
    assert type(provider) is _PartialConnectNativeProvider
    assert len(provider.close_native_objects) == close_count
    assert provider._native_object is not None
    assert all(item is provider._native_object for item in provider.close_native_objects)
    expected_statuses = ["ready", "operation_failed"]
    expected_statuses.extend(["close_unconfirmed"] * close_failures)
    expected_statuses.append("closed")
    assert [frame["status"] for frame in connection.sent] == expected_statuses
    assert connection.sent[1]["payload"] == {"error_code": "NATIVE_CONNECT_INTERRUPTED"}
    for frame in connection.sent[2:-1]:
        assert frame["payload"] == {"error_code": "PROVIDER_CLOSE_UNCONFIRMED"}
    assert connection.sent[-1]["payload"] == {
        "native_owner_created": True,
        "native_connection_generation": _NATIVE_GENERATION,
        "native_stop_receipt": {
            "connection_generation": _NATIVE_GENERATION,
            "join_required": True,
            "join_completed": True,
            "native_released": True,
            "thread_alive": False,
            "timed_out": False,
            "complete": True,
        },
        "close_confirmed": True,
    }
    assert connection.closed


def test_partial_connect_never_closes_as_native_free_after_unknown_owner() -> None:
    _PARTIAL_NATIVE_PROVIDERS.clear()
    connection = _ChildConnection(
        _partial_native_requests(
            "synthetic.partial-native-unresolved.v1", close_count=2
        )
    )

    serve_account_session_child(
        connection,
        provider_factory=_partial_native_unresolved_factory,
        close_receipt_projector=_partial_native_close_projector,
    )

    assert len(_PARTIAL_NATIVE_PROVIDERS) == 1
    provider = _PARTIAL_NATIVE_PROVIDERS[0]
    # The fake pipe reports EOF after the two explicit requests, which also
    # exercises the child's existing best-effort close on parent disappearance.
    assert len(provider.close_native_objects) == 3
    assert all(item is provider._native_object for item in provider.close_native_objects)
    assert [frame["status"] for frame in connection.sent] == [
        "ready",
        "operation_failed",
        "close_unconfirmed",
        "close_unconfirmed",
    ]
    assert all(
        frame["payload"] == {"error_code": "NATIVE_OWNER_STATE_UNAVAILABLE"}
        for frame in connection.sent[-2:]
    )
    assert connection.closed


def test_parent_accepts_exact_owner_receipt_when_connect_ack_is_unavailable() -> None:
    receipt = {
        "connection_generation": _NATIVE_GENERATION,
        "join_required": True,
        "join_completed": True,
        "native_released": True,
        "thread_alive": False,
        "timed_out": False,
        "complete": True,
    }
    world = _FakeWorld()
    world.connect_error_code = "NATIVE_CONNECT_INTERRUPTED"
    world.close_receipt = receipt
    provider = _provider(world)

    with pytest.raises(GatewayAccountSessionProcessError):
        provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)

    assert provider._connect_ack is None
    assert provider.close() is True
    diagnostic = provider.process_diagnostics
    assert diagnostic["native_owner_created"] is True
    assert diagnostic["native_connection_generation"] == _NATIVE_GENERATION
    assert diagnostic["native_stop_receipt"] == receipt


def test_close_retry_requires_a_completed_unconfirmed_reply() -> None:
    world = _FakeWorld()
    world.close_unconfirmed_remaining = 1
    provider = _provider(world)
    provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)

    assert provider.close() is False
    assert provider.custody_retained
    assert [item["operation"] for item in world.requests].count("close") == 1

    assert provider.close() is True
    assert [item["operation"] for item in world.requests].count("close") == 2
    assert not provider.custody_retained


def test_process_diagnostics_preserve_only_finite_close_response_facts() -> None:
    receipt = {
        "connection_generation": _NATIVE_GENERATION,
        "join_required": True,
        "join_completed": True,
        "native_released": True,
        "thread_alive": False,
        "timed_out": False,
        "complete": True,
    }
    world = _FakeWorld()
    world.close_receipt = receipt
    world.close_unconfirmed_remaining = 1
    provider = _provider(world)
    provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)

    assert provider.close() is False
    diagnostic = provider.process_diagnostics
    assert set(diagnostic) == {
        "state",
        "custody_retained",
        "poisoned",
        "pending_operation",
        "last_response_operation",
        "last_response_status",
        "error_code",
        "native_owner_created",
        "native_connection_generation",
        "native_stop_receipt",
    }
    assert dict(diagnostic) == {
        "state": "close_retryable",
        "custody_retained": True,
        "poisoned": False,
        "pending_operation": None,
        "last_response_operation": "close",
        "last_response_status": "close_unconfirmed",
        "error_code": "PROVIDER_CLOSE_UNCONFIRMED",
        "native_owner_created": True,
        "native_connection_generation": _NATIVE_GENERATION,
        "native_stop_receipt": None,
    }
    assert _ACCOUNT_KEY.account_id not in repr(diagnostic)
    with pytest.raises(TypeError):
        diagnostic["state"] = "closed"  # type: ignore[index]

    assert provider.close() is True
    closed = provider.process_diagnostics
    assert closed["state"] == "closed"
    assert closed["custody_retained"] is False
    assert closed["last_response_status"] == "closed"
    assert closed["error_code"] is None
    projected_receipt = closed["native_stop_receipt"]
    assert projected_receipt == receipt
    assert isinstance(projected_receipt, Mapping)
    with pytest.raises(TypeError):
        projected_receipt["complete"] = False  # type: ignore[index]


def test_process_diagnostics_preserve_finite_connect_error_code_only() -> None:
    world = _FakeWorld()
    world.connect_error_code = "NATIVE_LOGIN_REJECTED"
    provider = _provider(world)

    with pytest.raises(GatewayAccountSessionProcessError) as error:
        provider.connect(account_key=_ACCOUNT_KEY, generation=_GENERATION, timeout=1.0)

    assert error.value.code == "PROCESS_CONNECT_UNCERTAIN"
    assert dict(provider.process_diagnostics) == {
        "state": "unknown",
        "custody_retained": True,
        "poisoned": False,
        "pending_operation": None,
        "last_response_operation": "connect",
        "last_response_status": "operation_failed",
        "error_code": "NATIVE_LOGIN_REJECTED",
        "native_owner_created": None,
        "native_connection_generation": None,
        "native_stop_receipt": None,
    }
    assert provider.close() is True


def test_nested_child_callable_is_rejected_as_not_module_level() -> None:
    def nested(connection: object) -> None:
        del connection

    with pytest.raises(GatewayAccountSessionProcessError) as error:
        GatewayAccountSessionProcessProvider(
            account_key=_ACCOUNT_KEY,
            profile_ref="synthetic.read-only.v1",
            child_target=nested,
        )
    assert error.value.code == "CHILD_TARGET_INVALID"


def test_child_factory_is_local_and_rejects_unknown_profile_without_provider() -> None:
    class ChildConnection:
        def __init__(self) -> None:
            self.received = deque(
                [
                    _encode_frame(
                        _envelope(
                            message_type="request",
                            request_id="a" * 32,
                            generation=_GENERATION,
                            operation="bootstrap",
                            status="request",
                            payload={"profile_ref": "not-configured", "read_only": True},
                        )
                    )
                ]
            )
            self.sent: list[dict[str, object]] = []

        def recv_bytes(self, maxlength: int) -> bytes:
            value = self.received.popleft()
            if len(value) > maxlength:
                raise OSError("oversized")
            return value

        def send_bytes(self, value: bytes) -> None:
            self.sent.append(json.loads(value.decode("ascii")))

        def close(self) -> None:
            pass

    connection = ChildConnection()
    serve_account_session_child(
        connection,
        provider_factory=_native_free_factory,
        close_receipt_projector=_native_free_close_projector,
    )

    assert len(connection.sent) == 1
    assert connection.sent[0]["status"] == "profile_unavailable"
    assert connection.sent[0]["payload"] == {"error_code": "PROFILE_UNAVAILABLE"}
