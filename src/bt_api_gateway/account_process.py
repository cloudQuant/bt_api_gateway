"""Bounded, read-only account-provider process transport.

This module is the Gateway-side process adapter.  It deliberately does not
resolve credentials or import a venue SDK.  A deployment supplies one trusted
module-level child entry; that entry resolves the fixed profile reference in
the child and calls :func:`serve_account_session_child` with its local
provider factory and close-receipt projector.

Every command is one canonical JSON frame, one request is in flight at a time,
and an uncertain response never causes a replacement process or a replay.
The owning ``GatewayAccountSessionWorker`` therefore keeps its local session
guard until the exact child confirms provider shutdown, process exit, and pipe
EOF.
"""

from __future__ import annotations

import contextlib
import inspect
import json
import math
import multiprocessing
import multiprocessing.connection
import re
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable

from bt_api_base.account_protocol import (
    MAX_ACCOUNT_OBSERVATION_BYTES,
    AccountKey,
    AccountObservation,
)

from .account_position_snapshot import GatewayFullPositionSnapshot
from .account_session_worker import GatewayAccountSessionWorkerError

_PROTOCOL_VERSION = 1
_MAX_FRAME_BYTES = MAX_ACCOUNT_OBSERVATION_BYTES + 32 * 1024
_MAX_TIMEOUT_SECONDS = 300.0
_GENERATION_RE = re.compile(r"^[0-9a-f]{32}$")
_PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ERROR_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_ENVELOPE_FIELDS = frozenset(
    {
        "protocol_version",
        "message_type",
        "request_id",
        "generation",
        "operation",
        "status",
        "payload",
    }
)
_STOP_RECEIPT_FIELDS = frozenset(
    {
        "connection_generation",
        "join_required",
        "join_completed",
        "native_released",
        "thread_alive",
        "timed_out",
        "complete",
    }
)


class GatewayAccountSessionProcessError(GatewayAccountSessionWorkerError):
    """Finite process-adapter error; never includes provider values."""


class GatewayAccountSessionProfileUnavailableError(RuntimeError):
    """A profile factory's explicit proof that it created no provider owner.

    A child factory may raise this only before creating a provider, native
    client, thread, or other external resource.  It lets the parent safely
    release its local guard after the child exits.  Any other factory failure
    is uncertain and retains process custody.
    """


@dataclass(frozen=True)
class GatewayAccountSessionProcessBinding:
    """Child-local account identity and provider returned by a trusted factory."""

    account_key: AccountKey
    provider: object

    def __post_init__(self) -> None:
        if type(self.account_key) is not AccountKey:
            raise GatewayAccountSessionProcessError("PROFILE_ACCOUNT_KEY_INVALID")
        if self.provider is None:
            raise GatewayAccountSessionProcessError("PROFILE_PROVIDER_INVALID")


@dataclass(frozen=True)
class _PendingRequest:
    request_id: str
    operation: str
    generation: str


class GatewayAccountSessionProcessProvider:
    """Implement the account-session provider protocol over one spawned child.

    ``child_target`` must be a module-level function with no closure.  It is a
    trusted deployment-code capability, not a value selected by a client or
    profile document.  The child receives only its Pipe connection; its target
    reads the fixed bootstrap frame and resolves the profile locally.
    """

    def __init__(
        self,
        *,
        account_key: AccountKey,
        profile_ref: str,
        child_target: Callable[[Any], None],
        close_timeout_seconds: float = 3.0,
    ) -> None:
        if type(account_key) is not AccountKey:
            raise GatewayAccountSessionProcessError("ACCOUNT_KEY_INVALID")
        if type(profile_ref) is not str or _PROFILE_RE.fullmatch(profile_ref) is None:
            raise GatewayAccountSessionProcessError("PROFILE_REF_INVALID")
        _validate_module_entry(child_target, "CHILD_TARGET_INVALID")
        self._close_timeout = _positive_timeout(close_timeout_seconds)
        self._owner_thread = threading.get_ident()
        self._account_key = account_key
        self._profile_ref = profile_ref
        self._child_target = child_target
        self._context = multiprocessing.get_context("spawn")
        self._wait = multiprocessing.connection.wait
        self._monotonic = time.monotonic
        self._process: Any | None = None
        self._connection: Any | None = None
        self._child_connection: Any | None = None
        self._startup_cleanup_only = False
        self._generation: str | None = None
        self._state = "new"
        self._pending: _PendingRequest | None = None
        self._poisoned = False
        self._safe_profile_rejection = False
        self._connect_ack: tuple[bool, int | None] | None = None
        self._close_ack: dict[str, object] | None = None
        self._eof_seen = False

    @property
    def process_state(self) -> str:
        """Finite local lifecycle state for diagnostics and tests."""

        return self._state

    @property
    def session_generation(self) -> str | None:
        return self._generation

    @property
    def custody_retained(self) -> bool:
        """Whether this object still owns any child/process/pipe reference."""

        return (
            self._process is not None
            or self._connection is not None
            or self._child_connection is not None
        )

    def connect(self, *, account_key: AccountKey, generation: str, timeout: float) -> None:
        self._check_owner()
        if self._state != "new":
            raise GatewayAccountSessionProcessError("PROCESS_ALREADY_STARTED")
        if type(account_key) is not AccountKey or account_key != self._account_key:
            raise GatewayAccountSessionProcessError("ACCOUNT_KEY_MISMATCH")
        _validate_generation(generation)
        timeout_value = _positive_timeout(timeout)
        deadline = self._monotonic() + timeout_value
        self._generation = generation
        self._state = "starting"
        self._start_child()
        bootstrap = self._issue(
            "bootstrap",
            {"profile_ref": self._profile_ref, "read_only": True},
            deadline,
        )
        if bootstrap["status"] == "profile_unavailable":
            try:
                _validate_profile_unavailable_payload(bootstrap["payload"])
            except GatewayAccountSessionProcessError:
                self._poisoned = True
                self._state = "unknown"
                raise GatewayAccountSessionProcessError("PROCESS_BOOTSTRAP_UNKNOWN") from None
            self._safe_profile_rejection = True
            self._state = "profile_unavailable"
            raise GatewayAccountSessionProcessError("PROFILE_UNAVAILABLE")
        if bootstrap["status"] != "ready":
            self._state = "unknown"
            raise GatewayAccountSessionProcessError("PROCESS_BOOTSTRAP_UNKNOWN")
        ready_payload = bootstrap["payload"]
        if (
            type(ready_payload) is not dict
            or set(ready_payload) != {"account_key_id"}
            or ready_payload.get("account_key_id") != self._account_key.account_key_id
        ):
            self._poisoned = True
            self._state = "unknown"
            raise GatewayAccountSessionProcessError("PROCESS_ACCOUNT_BINDING_MISMATCH")
        remaining = self._remaining(deadline)
        if remaining <= 0:
            self._state = "unknown"
            raise GatewayAccountSessionProcessError("PROCESS_CONNECT_TIMEOUT")
        connected = self._issue("connect", {"timeout_seconds": remaining}, deadline)
        if connected["status"] != "connected":
            self._state = "unknown"
            raise GatewayAccountSessionProcessError("PROCESS_CONNECT_UNCERTAIN")
        self._connect_ack = _native_state_payload(connected["payload"])
        self._state = "connected"
        return None

    def read_account(
        self, *, generation: str, timeout: float
    ) -> AccountObservation | GatewayFullPositionSnapshot:
        self._check_owner()
        self._assert_generation(generation)
        if self._state != "connected" or self._poisoned:
            raise GatewayAccountSessionProcessError("PROCESS_SESSION_NOT_READABLE")
        deadline = self._monotonic() + _positive_timeout(timeout)
        remaining = self._remaining(deadline)
        if remaining <= 0:
            self._state = "unknown"
            raise GatewayAccountSessionProcessError("PROCESS_READ_TIMEOUT")
        response = self._issue("read_account", {"timeout_seconds": remaining}, deadline)
        if response["status"] != "account_read":
            self._state = "unknown"
            raise GatewayAccountSessionProcessError("PROCESS_READ_UNCERTAIN")
        try:
            return _decode_account_result(response["payload"], self._account_key, generation)
        except Exception:
            self._poisoned = True
            self._state = "unknown"
            raise GatewayAccountSessionProcessError("PROCESS_ACCOUNT_RESULT_INVALID") from None

    def close(self) -> bool:
        """Boundedly close this exact child; false keeps worker guard/custody.

        A timed-out operation is never replayed.  A later explicit close call
        first waits for its exact late response; only a completed
        ``close_unconfirmed`` response permits another close command.
        """

        self._check_owner()
        if self._state == "closed":
            return True
        if self._startup_cleanup_only:
            return self._close_unstarted_custody()
        if self._process is None:
            if self._connection is not None or self._child_connection is not None:
                # This can only occur after a partial startup cleanup failure.
                # Do not report success while a Pipe endpoint is still owned.
                self._startup_cleanup_only = True
                return self._close_unstarted_custody()
            self._state = "closed"
            return True
        if self._poisoned:
            return False
        deadline = self._monotonic() + self._close_timeout

        if self._safe_profile_rejection:
            return self._finish_shutdown(deadline, expect_close_ack=False)

        if self._close_ack is None and self._pending is not None:
            late = self._receive_pending(deadline)
            if late is None:
                return False
            if late["operation"] == "close":
                status = late["status"]
                if status == "closed":
                    try:
                        self._close_ack = _validate_close_payload(
                            late["payload"], self._generation, self._connect_ack
                        )
                    except Exception:
                        self._poisoned = True
                        self._state = "unknown"
                        return False
                elif status != "close_unconfirmed":
                    self._poisoned = True
                    self._state = "unknown"
                    return False
                else:
                    self._state = "close_retryable"
                    return False
            elif late["operation"] == "bootstrap" and late["status"] == "profile_unavailable":
                try:
                    _validate_profile_unavailable_payload(late["payload"])
                except Exception:
                    self._poisoned = True
                    self._state = "unknown"
                    return False
                self._safe_profile_rejection = True
                self._state = "profile_unavailable"
                return self._finish_shutdown(deadline, expect_close_ack=False)
            # A late bootstrap/connect/read reply is deliberately discarded.

        if self._close_ack is None:
            if self._pending is not None:
                return False
            remaining = self._remaining(deadline)
            if remaining <= 0:
                return False
            try:
                response = self._issue("close", {"timeout_seconds": remaining}, deadline)
            except GatewayAccountSessionProcessError:
                self._state = "unknown"
                return False
            if response["status"] == "close_unconfirmed":
                self._state = "close_retryable"
                return False
            if response["status"] != "closed":
                self._state = "unknown"
                return False
            try:
                self._close_ack = _validate_close_payload(
                    response["payload"], self._generation, self._connect_ack
                )
            except Exception:
                self._poisoned = True
                self._state = "unknown"
                return False

        if self._remaining(deadline) <= 0:
            return False
        return self._finish_shutdown(deadline, expect_close_ack=True)

    def _start_child(self) -> None:
        parent_connection: Any | None = None
        child_connection: Any | None = None
        process: Any | None = None
        try:
            parent_connection, child_connection = self._context.Pipe(duplex=True)
            process = self._context.Process(target=self._child_target, args=(child_connection,))
            self._process = process
            self._connection = parent_connection
            self._child_connection = child_connection
            process.start()
            # The parent must not keep the child endpoint alive; otherwise EOF
            # cannot prove that the child closed its writer.
            child_connection.close()
            self._child_connection = None
        except Exception:
            pid = None
            try:
                pid = None if process is None else process.pid
            except Exception:
                pid = -1
            if pid is None:
                cleanup_confirmed = True
                remaining_parent = parent_connection
                remaining_child = child_connection
                remaining_process = process
                for name, endpoint in (
                    ("parent", parent_connection),
                    ("child", child_connection),
                ):
                    if endpoint is not None:
                        try:
                            endpoint.close()
                            if name == "parent":
                                remaining_parent = None
                            else:
                                remaining_child = None
                        except Exception:
                            cleanup_confirmed = False
                if process is not None:
                    try:
                        process.close()
                        remaining_process = None
                    except Exception:
                        cleanup_confirmed = False
                if not cleanup_confirmed:
                    # Startup did not report a PID, but local handle cleanup
                    # itself is uncertain. Retain every exact object and keep
                    # the account-session guard held until an owner can inspect
                    # or retry cleanup explicitly.
                    self._process = remaining_process
                    self._connection = remaining_parent
                    self._child_connection = remaining_child
                    self._startup_cleanup_only = True
                    self._poisoned = True
                    self._state = "unknown"
                    raise GatewayAccountSessionProcessError(
                        "PROCESS_START_CLEANUP_UNCERTAIN"
                    ) from None
                self._process = None
                self._connection = None
                self._child_connection = None
                self._startup_cleanup_only = False
                self._state = "new"
                raise GatewayAccountSessionProcessError("PROCESS_START_FAILED") from None
            # A PID means start may have crossed the OS boundary. Keep every
            # exact handle; never compensate with terminate/kill or a rerun.
            child_endpoint_closed = child_connection is None
            if child_connection is not None:
                try:
                    child_connection.close()
                    child_endpoint_closed = True
                except Exception:
                    child_endpoint_closed = False
            self._process = process
            self._connection = parent_connection
            self._child_connection = None if child_endpoint_closed else child_connection
            self._poisoned = True
            self._state = "unknown"
            raise GatewayAccountSessionProcessError("PROCESS_START_UNCERTAIN") from None

    def _close_unstarted_custody(self) -> bool:
        """Retry only local handles after startup proved no child PID exists."""

        deadline = self._monotonic() + self._close_timeout
        for attribute in ("_connection", "_child_connection", "_process"):
            if self._remaining(deadline) <= 0:
                self._state = "unknown"
                return False
            resource = getattr(self, attribute)
            if resource is None:
                continue
            try:
                resource.close()
            except Exception:
                self._state = "unknown"
                return False
            setattr(self, attribute, None)

        if (
            self._process is not None
            or self._connection is not None
            or self._child_connection is not None
        ):
            self._state = "unknown"
            return False
        self._startup_cleanup_only = False
        self._poisoned = False
        self._state = "closed"
        return True

    def _issue(
        self, operation: str, payload: dict[str, object], deadline: float
    ) -> dict[str, object]:
        if self._pending is not None:
            raise GatewayAccountSessionProcessError("PROCESS_REQUEST_ALREADY_PENDING")
        connection = self._connection
        generation = self._generation
        if connection is None or generation is None or self._poisoned:
            raise GatewayAccountSessionProcessError("PROCESS_TRANSPORT_UNAVAILABLE")
        request_id = uuid.uuid4().hex
        request = _envelope(
            message_type="request",
            request_id=request_id,
            generation=generation,
            operation=operation,
            status="request",
            payload=payload,
        )
        self._pending = _PendingRequest(request_id, operation, generation)
        try:
            encoded = _encode_frame(request)
            connection.send_bytes(encoded)
        except Exception:
            self._poisoned = True
            self._state = "unknown"
            raise GatewayAccountSessionProcessError("PROCESS_SEND_UNCERTAIN") from None
        response = self._receive_pending(deadline)
        if response is None:
            self._state = "unknown"
            raise GatewayAccountSessionProcessError("PROCESS_RESPONSE_TIMEOUT")
        return response

    def _receive_pending(self, deadline: float) -> dict[str, object] | None:
        pending = self._pending
        connection = self._connection
        process = self._process
        if pending is None or connection is None or process is None:
            return None
        remaining = self._remaining(deadline)
        if remaining <= 0:
            return None
        try:
            ready = self._wait([connection, process.sentinel], remaining)
        except Exception:
            self._poisoned = True
            self._state = "unknown"
            return None
        if connection not in ready:
            if process.sentinel in ready:
                self._poisoned = True
                self._state = "unknown"
            return None
        try:
            raw = connection.recv_bytes(maxlength=_MAX_FRAME_BYTES)
            response = _decode_frame(raw, expected_message_type="response")
            _match_response(response, pending)
        except EOFError:
            self._poisoned = True
            self._state = "unknown"
            return None
        except Exception:
            # Oversized frames, malformed JSON, correlation mismatch, or an
            # unexpected shape permanently poison this transport generation.
            self._poisoned = True
            self._state = "unknown"
            return None
        self._pending = None
        return response

    def _finish_shutdown(self, deadline: float, *, expect_close_ack: bool) -> bool:
        process = self._process
        connection = self._connection
        if process is None or connection is None:
            return False
        saw_exit = False
        exit_code: int | None = None
        while self._remaining(deadline) > 0:
            waitables = [connection]
            try:
                sentinel = process.sentinel
            except Exception:
                self._poisoned = True
                self._state = "unknown"
                return False
            waitables.append(sentinel)
            try:
                ready = self._wait(waitables, self._remaining(deadline))
            except Exception:
                return False
            if not ready:
                return False
            if connection in ready and not self._eof_seen:
                try:
                    connection.recv_bytes(maxlength=_MAX_FRAME_BYTES)
                except EOFError:
                    self._eof_seen = True
                except Exception:
                    self._poisoned = True
                    self._state = "unknown"
                    return False
                else:
                    # No frame is allowed after close acknowledgement.
                    self._poisoned = True
                    self._state = "unknown"
                    return False
            if sentinel in ready:
                try:
                    process.join(timeout=0)
                    exit_code = process.exitcode
                except Exception:
                    return False
                saw_exit = exit_code is not None
            if saw_exit and self._eof_seen:
                if exit_code != 0 or (expect_close_ack and self._close_ack is None):
                    self._state = "unknown"
                    return False
                return self._drop_confirmed_child(process, connection)
        return False

    def _drop_confirmed_child(self, process: Any, connection: Any) -> bool:
        try:
            connection.close()
        except Exception:
            return False
        try:
            process.close()
        except Exception:
            # Once process.close fails, keep its identity in this object so the
            # caller's session guard is not released on ambiguous cleanup.
            self._state = "unknown"
            return False
        self._connection = None
        self._process = None
        self._child_connection = None
        self._pending = None
        self._state = "closed"
        return True

    def _assert_generation(self, generation: str) -> None:
        self._check_owner()
        _validate_generation(generation)
        if generation != self._generation:
            raise GatewayAccountSessionProcessError("PROCESS_GENERATION_MISMATCH")

    def _remaining(self, deadline: float) -> float:
        try:
            value = float(deadline - self._monotonic())
        except Exception:
            return 0.0
        return max(0.0, value) if math.isfinite(value) else 0.0

    def _check_owner(self) -> None:
        if threading.get_ident() != self._owner_thread:
            raise GatewayAccountSessionProcessError("PROCESS_WRONG_THREAD")


def serve_account_session_child(
    connection: Any,
    *,
    provider_factory: Callable[[str], GatewayAccountSessionProcessBinding],
    close_receipt_projector: Callable[[object, str], Mapping[str, object]] | None = None,
) -> None:
    """Serve one typed account-session connection inside a trusted child entry.

    ``provider_factory`` and ``close_receipt_projector`` must be module-level
    callables selected by the deployment's importable child target. They are
    never accepted from the parent frame.
    """

    _validate_module_entry(provider_factory, "PROVIDER_FACTORY_INVALID")
    if close_receipt_projector is not None:
        _validate_module_entry(close_receipt_projector, "CLOSE_PROJECTOR_INVALID")
    binding: GatewayAccountSessionProcessBinding | None = None
    generation: str | None = None
    native_owner_created = False
    native_generation: int | None = None
    connected = False
    native_state_known = False
    try:
        request = _recv_request(connection)
        if request is None:
            return
        if request["operation"] != "bootstrap":
            return
        payload = request["payload"]
        if (
            type(payload) is not dict
            or set(payload) != {"profile_ref", "read_only"}
            or type(payload.get("profile_ref")) is not str
            or _PROFILE_RE.fullmatch(payload.get("profile_ref", "")) is None
            or payload.get("read_only") is not True
        ):
            _send_response(
                connection, request, "bootstrap_rejected", {"error_code": "BOOTSTRAP_INVALID"}
            )
            return
        generation = request["generation"]
        profile_ref = payload["profile_ref"]
        try:
            binding = provider_factory(profile_ref)
        except GatewayAccountSessionProfileUnavailableError:
            _send_response(
                connection, request, "profile_unavailable", {"error_code": "PROFILE_UNAVAILABLE"}
            )
            return
        except Exception:
            _send_response(
                connection,
                request,
                "bootstrap_uncertain",
                {"error_code": "PROFILE_RESOLUTION_FAILED"},
            )
            return
        if type(binding) is not GatewayAccountSessionProcessBinding:
            _send_response(
                connection,
                request,
                "bootstrap_uncertain",
                {"error_code": "PROFILE_BINDING_INVALID"},
            )
            return
        provider = binding.provider
        if not _valid_provider(provider):
            _send_response(
                connection,
                request,
                "bootstrap_uncertain",
                {"error_code": "PROFILE_PROVIDER_INVALID"},
            )
            return
        _send_response(
            connection,
            request,
            "ready",
            {"account_key_id": binding.account_key.account_key_id},
        )

        while True:
            request = _recv_request(connection)
            if request is None:
                # The parent vanished without a close receipt. Best-effort
                # provider close is required, but cannot certify the parent.
                with contextlib.suppress(Exception):
                    provider.close()
                return
            if request["generation"] != generation:
                _send_response(
                    connection, request, "operation_failed", {"error_code": "GENERATION_MISMATCH"}
                )
                continue
            operation = request["operation"]
            payload = request["payload"]
            if operation == "connect":
                timeout = _command_timeout(payload)
                try:
                    result = provider.connect(
                        account_key=binding.account_key,
                        generation=generation,
                        timeout=timeout,
                    )
                    if result is not None:
                        raise ValueError("invalid connect result")
                    native_owner_created, native_generation = _native_owner_state(provider)
                    native_state_known = True
                    connected = True
                    _send_response(
                        connection,
                        request,
                        "connected",
                        {
                            "native_owner_created": native_owner_created,
                            "native_connection_generation": native_generation,
                        },
                    )
                except Exception as exc:
                    # Connect can fail after a provider has created its native
                    # owner. Capture the explicit state while still in the
                    # child so a later close can preserve and validate it.
                    with contextlib.suppress(Exception):
                        native_owner_created, native_generation = _native_owner_state(provider)
                        native_state_known = True
                    _send_response(
                        connection,
                        request,
                        "operation_failed",
                        {"error_code": _finite_error_code(exc, "PROVIDER_CONNECT_FAILED")},
                    )
            elif operation == "read_account":
                timeout = _command_timeout(payload)
                if not connected:
                    _send_response(
                        connection,
                        request,
                        "operation_failed",
                        {"error_code": "SESSION_NOT_CONNECTED"},
                    )
                    continue
                try:
                    result = provider.read_account(generation=generation, timeout=timeout)
                    encoded_result = _encode_account_result(result, binding.account_key, generation)
                    _send_response(connection, request, "account_read", encoded_result)
                except Exception as exc:
                    _send_response(
                        connection,
                        request,
                        "operation_failed",
                        {"error_code": _finite_error_code(exc, "PROVIDER_READ_FAILED")},
                    )
            elif operation == "close":
                _command_timeout(payload)
                try:
                    if not native_state_known:
                        _send_response(
                            connection,
                            request,
                            "close_unconfirmed",
                            {"error_code": "NATIVE_OWNER_STATE_UNAVAILABLE"},
                        )
                        continue
                    close_result = provider.close()
                    if close_result is not True:
                        _send_response(
                            connection,
                            request,
                            "close_unconfirmed",
                            {"error_code": "PROVIDER_CLOSE_UNCONFIRMED"},
                        )
                        continue
                    # Native ownership must be explicit.  This is deliberately
                    # checked again after close; the sticky child values bind
                    # the exact generation reported by connect.
                    receipt: dict[str, object] | None = None
                    if native_owner_created:
                        if close_receipt_projector is None:
                            raise ValueError("native receipt projector unavailable")
                        raw_receipt = close_receipt_projector(provider, generation)
                        if native_generation is None:
                            raise ValueError("native generation missing")
                        receipt = _validate_stop_receipt(raw_receipt, native_generation)
                    close_payload = {
                        "native_owner_created": native_owner_created,
                        "native_connection_generation": native_generation,
                        "native_stop_receipt": receipt,
                        "close_confirmed": True,
                    }
                    _send_response(connection, request, "closed", close_payload)
                    return
                except Exception as exc:
                    _send_response(
                        connection,
                        request,
                        "close_unconfirmed",
                        {"error_code": _finite_error_code(exc, "NATIVE_CLOSE_UNCONFIRMED")},
                    )
            else:
                _send_response(
                    connection, request, "operation_failed", {"error_code": "OPERATION_UNSUPPORTED"}
                )
    except Exception:
        # No exception detail or provider value crosses the process boundary.
        return
    finally:
        with contextlib.suppress(Exception):
            connection.close()


def _valid_provider(provider: object) -> bool:
    return all(
        callable(getattr(provider, name, None)) for name in ("connect", "read_account", "close")
    )


def _validate_module_entry(value: object, code: str) -> None:
    if (
        not inspect.isfunction(value)
        or type(getattr(value, "__module__", None)) is not str
        or type(getattr(value, "__qualname__", None)) is not str
        or value.__qualname__ != value.__name__
        or value.__closure__ is not None
        or "<locals>" in value.__qualname__
    ):
        raise GatewayAccountSessionProcessError(code)


def _positive_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GatewayAccountSessionProcessError("TIMEOUT_INVALID")
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        raise GatewayAccountSessionProcessError("TIMEOUT_INVALID") from None
    if not math.isfinite(result) or result <= 0 or result > _MAX_TIMEOUT_SECONDS:
        raise GatewayAccountSessionProcessError("TIMEOUT_INVALID")
    return result


def _validate_generation(value: object) -> None:
    if type(value) is not str or _GENERATION_RE.fullmatch(value) is None:
        raise GatewayAccountSessionProcessError("GENERATION_INVALID")


def _envelope(
    *,
    message_type: str,
    request_id: str,
    generation: str,
    operation: str,
    status: str,
    payload: object,
) -> dict[str, object]:
    return {
        "protocol_version": _PROTOCOL_VERSION,
        "message_type": message_type,
        "request_id": request_id,
        "generation": generation,
        "operation": operation,
        "status": status,
        "payload": payload,
    }


def _encode_frame(frame: Mapping[str, object]) -> bytes:
    try:
        encoded = json.dumps(
            frame,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise GatewayAccountSessionProcessError("FRAME_SERIALIZATION_INVALID") from None
    if len(encoded) > _MAX_FRAME_BYTES:
        raise GatewayAccountSessionProcessError("FRAME_TOO_LARGE")
    return encoded


def _decode_frame(raw: bytes, *, expected_message_type: str) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_FRAME_BYTES:
        raise GatewayAccountSessionProcessError("FRAME_INVALID")
    try:
        decoded = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object)
    except Exception:
        raise GatewayAccountSessionProcessError("FRAME_INVALID") from None
    if type(decoded) is not dict or set(decoded) != _ENVELOPE_FIELDS:
        raise GatewayAccountSessionProcessError("FRAME_SHAPE_INVALID")
    if (
        type(decoded["protocol_version"]) is not int
        or decoded["protocol_version"] != _PROTOCOL_VERSION
    ):
        raise GatewayAccountSessionProcessError("FRAME_VERSION_INVALID")
    if decoded["message_type"] != expected_message_type:
        raise GatewayAccountSessionProcessError("FRAME_TYPE_INVALID")
    if (
        type(decoded["request_id"]) is not str
        or re.fullmatch(r"[0-9a-f]{32}", decoded["request_id"]) is None
    ):
        raise GatewayAccountSessionProcessError("FRAME_REQUEST_ID_INVALID")
    _validate_generation(decoded["generation"])
    if type(decoded["operation"]) is not str or decoded["operation"] not in {
        "bootstrap",
        "connect",
        "read_account",
        "close",
    }:
        raise GatewayAccountSessionProcessError("FRAME_OPERATION_INVALID")
    if type(decoded["status"]) is not str or not decoded["status"]:
        raise GatewayAccountSessionProcessError("FRAME_STATUS_INVALID")
    if type(decoded["payload"]) is not dict:
        raise GatewayAccountSessionProcessError("FRAME_PAYLOAD_INVALID")
    if _encode_frame(decoded) != raw:
        raise GatewayAccountSessionProcessError("FRAME_NOT_CANONICAL")
    return decoded


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _match_response(response: dict[str, object], pending: _PendingRequest) -> None:
    if (
        response["request_id"] != pending.request_id
        or response["generation"] != pending.generation
        or response["operation"] != pending.operation
    ):
        raise GatewayAccountSessionProcessError("FRAME_CORRELATION_MISMATCH")


def _command_timeout(payload: object) -> float:
    if type(payload) is not dict or set(payload) != {"timeout_seconds"}:
        raise GatewayAccountSessionProcessError("COMMAND_PAYLOAD_INVALID")
    return _positive_timeout(payload["timeout_seconds"])


def _validate_profile_unavailable_payload(value: object) -> None:
    if type(value) is not dict or set(value) != {"error_code"}:
        raise GatewayAccountSessionProcessError("PROFILE_UNAVAILABLE_ACK_INVALID")
    if value["error_code"] != "PROFILE_UNAVAILABLE":
        raise GatewayAccountSessionProcessError("PROFILE_UNAVAILABLE_ACK_INVALID")


def _recv_request(connection: Any) -> dict[str, object] | None:
    try:
        raw = connection.recv_bytes(maxlength=_MAX_FRAME_BYTES)
    except EOFError:
        return None
    except Exception:
        return None
    try:
        request = _decode_frame(raw, expected_message_type="request")
        if request["status"] != "request":
            return None
        return request
    except GatewayAccountSessionProcessError:
        return None


def _send_response(
    connection: Any, request: Mapping[str, object], status: str, payload: dict[str, object]
) -> None:
    frame = _envelope(
        message_type="response",
        request_id=request["request_id"],  # type: ignore[arg-type]
        generation=request["generation"],  # type: ignore[arg-type]
        operation=request["operation"],  # type: ignore[arg-type]
        status=status,
        payload=payload,
    )
    connection.send_bytes(_encode_frame(frame))


def _native_owner_state(provider: object) -> tuple[bool, int | None]:
    try:
        owner = provider.native_owner_created
        native_generation = provider.native_connection_generation
    except Exception:
        raise GatewayAccountSessionProcessError("NATIVE_OWNER_STATE_UNAVAILABLE") from None
    if type(owner) is not bool:
        raise GatewayAccountSessionProcessError("NATIVE_OWNER_STATE_INVALID")
    if owner:
        if type(native_generation) is not int or native_generation <= 0:
            raise GatewayAccountSessionProcessError("NATIVE_GENERATION_INVALID")
        return True, native_generation
    if native_generation is not None:
        raise GatewayAccountSessionProcessError("NATIVE_OWNER_STATE_INVALID")
    return False, None


def _validate_stop_receipt(value: object, native_generation: int) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != _STOP_RECEIPT_FIELDS:
        raise GatewayAccountSessionProcessError("NATIVE_STOP_RECEIPT_INVALID")
    receipt = dict(value)
    if (
        type(receipt["connection_generation"]) is not int
        or receipt["connection_generation"] <= 0
        or receipt["connection_generation"] != native_generation
        or type(receipt["join_required"]) is not bool
        or type(receipt["join_completed"]) is not bool
        or type(receipt["native_released"]) is not bool
        or type(receipt["thread_alive"]) is not bool
        or type(receipt["timed_out"]) is not bool
        or type(receipt["complete"]) is not bool
        or receipt["join_required"]
        and not receipt["join_completed"]
        or not receipt["native_released"]
        or receipt["thread_alive"]
        or receipt["timed_out"]
        or not receipt["complete"]
    ):
        raise GatewayAccountSessionProcessError("NATIVE_STOP_RECEIPT_INVALID")
    return receipt


def _native_state_payload(value: object) -> tuple[bool, int | None]:
    if type(value) is not dict or set(value) != {
        "native_owner_created",
        "native_connection_generation",
    }:
        raise GatewayAccountSessionProcessError("NATIVE_STATE_RESPONSE_INVALID")
    owner = value["native_owner_created"]
    native_generation = value["native_connection_generation"]
    if type(owner) is not bool:
        raise GatewayAccountSessionProcessError("NATIVE_STATE_RESPONSE_INVALID")
    if owner:
        if type(native_generation) is not int or native_generation <= 0:
            raise GatewayAccountSessionProcessError("NATIVE_GENERATION_INVALID")
        return True, native_generation
    if native_generation is not None:
        raise GatewayAccountSessionProcessError("NATIVE_STATE_RESPONSE_INVALID")
    return False, None


def _validate_close_payload(
    value: object,
    generation: str | None,
    connect_ack: tuple[bool, int | None] | None,
) -> dict[str, object]:
    if generation is None:
        raise GatewayAccountSessionProcessError("CLOSE_GENERATION_INVALID")
    _validate_generation(generation)
    expected_fields = {
        "native_owner_created",
        "native_connection_generation",
        "native_stop_receipt",
        "close_confirmed",
    }
    if (
        type(value) is not dict
        or set(value) != expected_fields
        or value["close_confirmed"] is not True
    ):
        raise GatewayAccountSessionProcessError("CLOSE_ACK_INVALID")
    owner = value["native_owner_created"]
    native_generation = value["native_connection_generation"]
    receipt = value["native_stop_receipt"]
    if type(owner) is not bool:
        raise GatewayAccountSessionProcessError("CLOSE_ACK_INVALID")
    if connect_ack is not None and (owner, native_generation) != connect_ack:
        raise GatewayAccountSessionProcessError("CLOSE_OWNER_CHANGED")
    if owner:
        if type(native_generation) is not int or native_generation <= 0:
            raise GatewayAccountSessionProcessError("CLOSE_GENERATION_INVALID")
        receipt = _validate_stop_receipt(receipt, native_generation)
    elif native_generation is not None or receipt is not None:
        raise GatewayAccountSessionProcessError("CLOSE_ACK_INVALID")
    return {
        "native_owner_created": owner,
        "native_connection_generation": native_generation,
        "native_stop_receipt": receipt,
        "close_confirmed": True,
    }


def _encode_account_result(
    result: object, account_key: AccountKey, generation: str
) -> dict[str, object]:
    if type(result) is AccountObservation:
        if result.account_key != account_key:
            raise GatewayAccountSessionProcessError("OBSERVATION_ACCOUNT_MISMATCH")
        return {"kind": "observation", "observation": result.to_dict()}
    if type(result) is GatewayFullPositionSnapshot:
        if (
            result.observation.account_key != account_key
            or result.account_key_id != account_key.account_key_id
            or result.session_generation != generation
        ):
            raise GatewayAccountSessionProcessError("POSITION_SNAPSHOT_BINDING_MISMATCH")
        return {
            "kind": "full_position_snapshot",
            "observation": result.observation.to_dict(),
            "source": result.source_payload(),
        }
    raise GatewayAccountSessionProcessError("PROVIDER_RESULT_TYPE_INVALID")


def _decode_account_result(
    payload: object, account_key: AccountKey, generation: str
) -> AccountObservation | GatewayFullPositionSnapshot:
    if type(payload) is not dict or type(payload.get("kind")) is not str:
        raise GatewayAccountSessionProcessError("ACCOUNT_RESULT_SHAPE_INVALID")
    observation = AccountObservation.from_dict(payload.get("observation"))
    if observation.account_key != account_key:
        raise GatewayAccountSessionProcessError("OBSERVATION_ACCOUNT_MISMATCH")
    if payload["kind"] == "observation" and set(payload) == {"kind", "observation"}:
        return observation
    if payload["kind"] != "full_position_snapshot" or set(payload) != {
        "kind",
        "observation",
        "source",
    }:
        raise GatewayAccountSessionProcessError("ACCOUNT_RESULT_KIND_INVALID")
    source = payload["source"]
    source_fields = {
        "account_key_id",
        "account_revision",
        "filters",
        "observation_id",
        "page_count",
        "pagination_exhausted",
        "permission_revision",
        "permission_scope",
        "positions_sha256",
        "query_scope",
        "resource_coverage_sha256",
        "session_generation",
        "snapshot_version",
        "source_schema_version",
        "valid_until_utc",
    }
    if type(source) is not dict or set(source) != source_fields:
        raise GatewayAccountSessionProcessError("POSITION_SOURCE_SHAPE_INVALID")
    if (
        source["observation_id"] != observation.observation_id
        or source["session_generation"] != generation
    ):
        raise GatewayAccountSessionProcessError("POSITION_SOURCE_BINDING_MISMATCH")
    return GatewayFullPositionSnapshot(
        observation=observation,
        account_key_id=source["account_key_id"],
        session_generation=source["session_generation"],
        query_scope=source["query_scope"],
        filters=tuple(source["filters"]),
        permission_scope=source["permission_scope"],
        permission_revision=source["permission_revision"],
        pagination_exhausted=source["pagination_exhausted"],
        page_count=source["page_count"],
        account_revision=source["account_revision"],
        source_schema_version=source["source_schema_version"],
        snapshot_version=source["snapshot_version"],
        positions_sha256=source["positions_sha256"],
        resource_coverage_sha256=source["resource_coverage_sha256"],
        valid_until_utc=source["valid_until_utc"],
    )


def _finite_error_code(exc: Exception, fallback: str) -> str:
    value = getattr(exc, "code", None)
    if type(value) is str and _ERROR_CODE_RE.fullmatch(value) is not None:
        return value
    return fallback


__all__ = [
    "GatewayAccountSessionProcessBinding",
    "GatewayAccountSessionProcessError",
    "GatewayAccountSessionProcessProvider",
    "GatewayAccountSessionProfileUnavailableError",
    "serve_account_session_child",
]
