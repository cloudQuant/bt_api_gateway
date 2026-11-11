"""Local HTTP adapter over an already authenticated Gateway client.

The host supplies authentication, CSRF material, and a per-user Gateway runtime.
This module does not open, own, or close the Gateway or its trading session.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr

_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MODES = frozenset({"STOP_NEW", "FREEZE", "DRAIN"})
_SECRET_KEYS = ("password", "secret", "token", "credential", "apikey", "privatekey", "authorization", "cookie")


def _ref(value: object) -> bool:
    return type(value) is str and _REF.fullmatch(value) is not None


def _gateway_ref(value: object) -> bool:
    if type(value) is not str or not value or value != value.strip() or not value.isprintable():
        return False
    try:
        return len(value.encode("utf-8", errors="strict")) <= 256
    except UnicodeError:
        return False


def _operator_origin(principal_ref: str, actor_ref: str) -> str:
    # The origin the Gateway stores on a cause an operator applied, derived by the
    # Gateway from the authenticated registration (gateway_direct_service). Used
    # only to recognise this operator's own cause; it never grants anything.
    encoded = json.dumps([principal_ref, actor_ref], separators=(',', ':')).encode()
    return 'operator:' + hashlib.sha256(encoded).hexdigest()


def _route_fingerprint(scope: WebScope) -> str:
    # Opaque route identity lets a persisted browser request detect remapping.
    encoded = json.dumps([scope.account_ref, scope.scope_ref, scope.strategy_ref],
                         ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class WebScope:
    """A trusted server-side route selection, never a client-supplied identity."""

    scope_id: str
    account_ref: str
    scope_ref: str
    strategy_ref: str | None = None

    def __post_init__(self):
        if not _ref(self.scope_id) or not all(_gateway_ref(v) for v in (self.account_ref, self.scope_ref)):
            raise ValueError("INVALID_WEB_SCOPE")
        if self.strategy_ref is not None and not _gateway_ref(self.strategy_ref):
            raise ValueError("INVALID_WEB_SCOPE")


@dataclass(frozen=True)
class AuthenticatedWebSession:
    """Returned by trusted authentication middleware, not parsed from JSON."""

    principal_ref: str
    actor_ref: str
    csrf_token: str = field(repr=False)
    scopes: tuple[WebScope, ...] = ()

    def __post_init__(self):
        if not _gateway_ref(self.principal_ref) or not _gateway_ref(self.actor_ref):
            raise ValueError("INVALID_WEB_SESSION")
        if (type(self.csrf_token) is not str or not self.csrf_token.isascii()
                or not 32 <= len(self.csrf_token) <= 256):
            raise ValueError("INVALID_WEB_SESSION")
        if type(self.scopes) is not tuple or any(type(x) is not WebScope for x in self.scopes):
            raise ValueError("INVALID_WEB_SESSION")
        if len({x.scope_id for x in self.scopes}) != len(self.scopes):
            raise ValueError("INVALID_WEB_SESSION")


class _Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cause_id: StrictStr
    reservation_id: StrictStr
    operation_id: StrictStr
    view_receipt: StrictStr


class _Prepare(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: StrictStr
    mode: StrictStr
    cause_id: StrictStr = ""
    expected_version: StrictInt = 0
    view_receipt: StrictStr


class _Receipt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    receipt: StrictStr


class _TargetQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    view_receipt: StrictStr
    after: StrictStr = ''
    limit: StrictInt = 100


def _copy_safe(value: Any, depth: int = 0) -> Any:
    """Bound the public response and reject accidental credential fields."""
    if depth > 24:
        raise ValueError("RESPONSE_INVALID")
    if value is None or type(value) in (bool, int, str):
        return value
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", key.lower()) if type(key) is str else ""
            if type(key) is not str or any(secret in normalized for secret in _SECRET_KEYS):
                raise ValueError("RESPONSE_INVALID")
            result[key] = _copy_safe(item, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [_copy_safe(item, depth + 1) for item in value]
    if type(value) is float:
        import math

        if math.isfinite(value):
            return value
    raise ValueError("RESPONSE_INVALID")


def _local_origin(origin: str) -> tuple[str, str]:
    parsed = urlsplit(origin)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username or parsed.password or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        raise ValueError("INVALID_LOCAL_ORIGIN")
    try:
        local = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        local = False
    if not local:
        raise ValueError("INVALID_LOCAL_ORIGIN")
    return origin.rstrip("/"), parsed.netloc.lower()


def create_app(*, origin: str, authenticate: Callable[[Request], AuthenticatedWebSession],
               resolve_runtime: Callable[[AuthenticatedWebSession, WebScope], object],
               read_snapshot: Callable[[AuthenticatedWebSession, WebScope], Mapping[str, Any]] | None = None,
               static_dir: str | Path | None = None,
               receipt_key: bytes | None = None, receipt_key_id: str = "ephemeral",
               timeout_seconds: float = 2.0) -> FastAPI:
    """Create a local-only adapter; all supplied callbacks are trusted host code.

    ``authenticate`` must revalidate the browser session on every request;
    ``resolve_runtime`` must return that exact principal's already running SDK
    runtime, with account/strategy grants rather than a shared privileged actor.
    ``read_snapshot`` is reserved for a future provenance-bound reader and is
    not invoked until a same-journal account-view contract is available.
    """
    origin, authority = _local_origin(origin)
    if not callable(authenticate) or not callable(resolve_runtime):
        raise ValueError("AUTHENTICATION_REQUIRED")
    if read_snapshot is not None and not callable(read_snapshot):
        raise ValueError("SNAPSHOT_READER_INVALID")
    if type(timeout_seconds) not in (float, int) or not 0 < timeout_seconds <= 10:
        raise ValueError("INVALID_TIMEOUT")
    if receipt_key is not None and (type(receipt_key) is not bytes or len(receipt_key) < 32):
        raise ValueError("INVALID_RECEIPT_KEY")
    if not _ref(receipt_key_id):
        raise ValueError("INVALID_RECEIPT_KEY_ID")
    receipt_key_is_persistent = receipt_key is not None
    signing_key = receipt_key if receipt_key is not None else secrets.token_bytes(32)
    app = FastAPI(title="Gateway local operator API", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        try:
            host = request.client.host if request.client else ""
            if not ipaddress.ip_address(host).is_loopback:
                return JSONResponse({"error": "LOCAL_ACCESS_REQUIRED"}, status_code=403)
        except ValueError:
            return JSONResponse({"error": "LOCAL_ACCESS_REQUIRED"}, status_code=403)
        if request.headers.get("host", "").lower() != authority:
            return JSONResponse({"error": "HOST_DENIED"}, status_code=403)
        if request.method not in ("GET", "HEAD", "POST"):
            return JSONResponse({"error": "METHOD_DENIED"}, status_code=405)
        if request.method == "POST":
            length = request.headers.get("content-length", "")
            if (len(length) > 6 or not length.isascii() or not length.isdigit()
                    or int(length) > 8192):
                return JSONResponse({"error": "BODY_SIZE_INVALID"}, status_code=413)
            if request.headers.get("origin") != origin:
                return JSONResponse({"error": "ORIGIN_DENIED"}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        return response

    def session_for(request: Request, *, write: bool = False) -> AuthenticatedWebSession:
        try:
            session = authenticate(request)
        except Exception:
            raise HTTPException(401, "AUTHENTICATION_REQUIRED") from None
        if type(session) is not AuthenticatedWebSession:
            raise HTTPException(401, "AUTHENTICATION_REQUIRED")
        if write:
            token = request.headers.get("x-csrf-token", "")
            if not token.isascii() or not hmac.compare_digest(token, session.csrf_token):
                raise HTTPException(403, "CSRF_DENIED")
        return session

    def route_for(session: AuthenticatedWebSession, scope_id: str, operation: str,
                  *, mount: str = "application.direct_write"):
        matches = [scope for scope in session.scopes if scope.scope_id == scope_id]
        if len(matches) != 1:
            raise HTTPException(403, "SCOPE_DENIED")
        scope = matches[0]
        try:
            runtime = resolve_runtime(session, scope)
            state = runtime.status()
            identity = state.identity
            if (state.state != "running" or not state.thread_alive or not state.healthy
                    or identity is None or identity.role.value != "application_client"
                    or identity.principal_ref != session.principal_ref
                    or identity.actor_ref != session.actor_ref or identity.delegate_ref is not None):
                raise ValueError
            bindings = [b for b in state.bindings if b.active and b.mount == mount
                        and b.scope_ref == scope.scope_ref and b.scope is not None
                        and b.scope.account_ref == scope.account_ref
                        and b.scope.strategy_ref == scope.strategy_ref
                        and b.operations is not None and operation in b.operations]
            if len(bindings) != 1:
                raise ValueError
        except Exception:
            raise HTTPException(403, "GATEWAY_SCOPE_OR_GRANT_UNAVAILABLE") from None
        return scope, runtime

    @app.get("/api/v1/session")
    def session_endpoint(request: Request):
        session = session_for(request)
        namespace = hashlib.sha256((session.principal_ref + "\0" + session.actor_ref).encode()).hexdigest()
        return {"csrf_token": session.csrf_token, "namespace": namespace,
                "receipt_key_persistent": receipt_key_is_persistent,
                "scopes": [{"scope_id": s.scope_id, "strategy_ref": s.strategy_ref,
                            "route_fingerprint": _route_fingerprint(s)}
                           for s in session.scopes]}

    def check_write_route(request: Request, session: AuthenticatedWebSession, scope_id: str):
        scopes = [s for s in session.scopes if s.scope_id == scope_id]
        route = request.headers.get('x-gateway-route', '')
        if len(scopes) != 1 or re.fullmatch(r'[0-9a-f]{64}', route) is None or not hmac.compare_digest(route, _route_fingerprint(scopes[0])):
            raise HTTPException(409, 'ROUTE_CHANGED')

    def binding_proof(runtime, session, scope, operation):
        from bt_api_base.service_protocol import WireIdentity, WireRole

        state = runtime.status()
        if (state.state != 'running' or not state.thread_alive or not state.healthy
                or state.identity is None or state.identity.role != WireRole.APPLICATION_CLIENT
                or state.identity.principal_ref != session.principal_ref
                or state.identity.actor_ref != session.actor_ref or state.identity.delegate_ref is not None):
            raise ValueError('RUNTIME_UNAVAILABLE')
        bindings = [b for b in state.bindings if b.active and b.mount == 'application.direct_write'
                    and b.scope_ref == scope.scope_ref and b.scope is not None
                    and b.scope.account_ref == scope.account_ref and b.scope.strategy_ref == scope.strategy_ref
                    and b.operations is not None and {operation, 'direct.control.identity'} <= b.operations]
        if len(bindings) != 1:
            raise ValueError('BINDING_UNAVAILABLE')
        b = bindings[0]
        peer = b.authenticated_peer
        if (type(peer) is not WireIdentity or peer.role != WireRole.SERVICE or peer.delegate_ref is not None
                or type(b.server_key_fingerprint) is not str
                or re.fullmatch(r'[0-9a-f]{64}', b.server_key_fingerprint) is None
                or not _gateway_ref(b.registration_id) or not _gateway_ref(b.service_epoch)):
            raise ValueError('PEER_UNAVAILABLE')
        return (b.registration_id, b.service_epoch, peer.principal_ref, peer.actor_ref, b.server_key_fingerprint)

    def proof(runtime, session, scope, operation):
        before = binding_proof(runtime, session, scope, operation)
        result = runtime.call('application.direct_write', 'direct.control.identity', {},
                              account_ref=scope.account_ref, scope_ref=scope.scope_ref,
                              timeout_seconds=timeout_seconds)
        if (binding_proof(runtime, session, scope, operation) != before or not isinstance(result, Mapping)
                or result.get('status') != 'OBSERVED' or result.get('schema_version') != 1
                or result.get('account_scope') != scope.account_ref or not _gateway_ref(result.get('journal_id'))):
            raise ValueError('JOURNAL_UNAVAILABLE')
        return before, {'peer_principal': before[2], 'peer_actor': before[3], 'peer_key': before[4],
                        'journal_id': result['journal_id']}

    def encode_receipt(data):
        raw = json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('ascii')
        mac = hmac.new(signing_key, raw, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(raw).decode('ascii') + '.' + base64.urlsafe_b64encode(mac).decode('ascii')

    def decode_receipt(token):
        if type(token) is not str or len(token) > 4096 or token.count('.') != 1:
            raise ValueError('INVALID_RECEIPT')
        body, signature = token.split('.')
        raw = base64.b64decode(body, altchars=b'-_', validate=True)
        actual = base64.b64decode(signature, altchars=b'-_', validate=True)
        if not hmac.compare_digest(actual, hmac.new(signing_key, raw, hashlib.sha256).digest()):
            raise ValueError('INVALID_RECEIPT')
        value = json.loads(raw)
        if type(value) is not dict or value.get('key_id') != receipt_key_id:
            raise ValueError('INVALID_RECEIPT')
        return value

    def receipt_context(session, scope_id, receipt, operation):
        value = decode_receipt(receipt)
        scope, runtime = route_for(session, scope_id, operation)
        if (value.get('principal') != session.principal_ref or value.get('actor') != session.actor_ref
                or value.get('scope_id') != scope_id or value.get('route') != _route_fingerprint(scope)):
            raise ValueError('RECEIPT_SCOPE_MISMATCH')
        binding, stable = proof(runtime, session, scope, operation)
        if value.get('gateway') != stable:
            raise ValueError('RECEIPT_GATEWAY_MISMATCH')
        return value, scope, runtime, binding, stable

    def view_data(session, scope, scope_id, stable, view):
        return {'key_id': receipt_key_id, 'principal': session.principal_ref, 'actor': session.actor_ref,
                'scope_id': scope_id, 'route': _route_fingerprint(scope), 'gateway': stable, 'view': view}

    def read_bound(session, scope_id, operation, args):
        scope, runtime = route_for(session, scope_id, operation)
        before, stable = proof(runtime, session, scope, operation)
        result = runtime.call('application.direct_write', operation, args, account_ref=scope.account_ref,
                              scope_ref=scope.scope_ref, timeout_seconds=timeout_seconds)
        after, stable_after = proof(runtime, session, scope, operation)
        if before != after or stable != stable_after or resolve_runtime(session, scope) is not runtime:
            raise ValueError('BINDING_CHANGED')
        return scope, stable, _copy_safe(result)

    def receipt_call(session, scope_id, receipt, operation, args, *, write=False):
        value, scope, runtime, binding, stable = receipt_context(session, scope_id, receipt, operation)
        if write:
            args = {**args, 'expected_journal_id': stable['journal_id']}
        result = runtime.call('application.direct_write', operation, args, account_ref=scope.account_ref,
                              scope_ref=scope.scope_ref, timeout_seconds=timeout_seconds)
        current, stable_after = proof(runtime, session, scope, operation)
        if current != binding or stable_after != stable or resolve_runtime(session, scope) is not runtime:
            raise ValueError('BINDING_CHANGED')
        return _copy_safe(result)

    def command_status(session, scope_id, token, command):
        if command['mode'] == 'DRAIN_TARGET':
            operation = 'direct.control.target_status'
            args = {'cause_id': command['cause_id'], 'operation_id': command['operation_id']}
        elif command['mode'] == 'RESUME':
            operation = 'direct.control.resume_status'
            args = {'operation_id': command['request_id']}
        else:
            operation = 'direct.control.status'
            args = {'cause_id': command['request_id']}
        result = receipt_call(session, scope_id, token, operation, args)
        if type(result) is not dict:
            raise ValueError('INVALID_RESULT')
        if command['mode'] == 'DRAIN_TARGET' and result.get('status') == 'OBSERVED':
            row = result.get('target')
            if (not isinstance(row, Mapping) or row.get('cause_id') != command['cause_id']
                    or row.get('reservation_id') != command['reservation_id']
                    or row.get('operation_id') != command['operation_id']):
                raise ValueError('INVALID_TARGET')
            if row.get('state') == 'OBSERVED_TERMINAL':
                return {'status': 'OBSERVED_TERMINAL', 'cause_id': command['cause_id'],
                        'reservation_id': command['reservation_id']}
            if row.get('state') != 'PENDING':
                return {'status': 'UNKNOWN', 'cause_id': command['cause_id'],
                        'reservation_id': command['reservation_id'], 'target_state': row.get('state')}
        if result.get('status') == 'NOT_FOUND':
            name = 'operation_id' if command['mode'] in {'RESUME', 'DRAIN_TARGET'} else 'cause_id'
            expected = command['operation_id'] if command['mode'] == 'DRAIN_TARGET' else command['request_id']
            if result.get(name) != expected:
                raise ValueError('INVALID_RESULT')
        elif (result.get('status') == 'OBSERVED' and command['mode'] != 'DRAIN_TARGET'
                and not own_record(session, scope_id, command, result)):
            # The id is taken by another command (another operator's cause, a contract
            # cause, or a release of another cause). Never report it as this request,
            # and never send this request under that id.
            return {'status': 'REQUEST_REJECTED', 'code': 'REQUEST_ID_CONFLICT'}
        return result

    def own_record(session, scope_id, command, result):
        """Whether an observed record is this request: same id and same content as the Gateway keeps it."""
        if command['mode'] == 'RESUME':
            return (result.get('cause_id') == command['cause_id']
                    and result.get('operation_id') == command['request_id']
                    and result.get('version') == command['expected_version'] + 1
                    and result.get('active') is False)
        scope, = [s for s in session.scopes if s.scope_id == scope_id]
        cause = result.get('cause')
        expected = {'cause_id': command['request_id'], 'mode': command['mode'],
                    'scope_kind': 'account' if scope.strategy_ref is None else 'strategy',
                    'scope_value': '' if scope.strategy_ref is None else scope.strategy_ref,
                    'origin': _operator_origin(session.principal_ref, session.actor_ref)}
        return isinstance(cause, Mapping) and all(cause.get(k) == v for k, v in expected.items())

    @app.post('/api/v1/scopes/{scope_id}/requests/prepare')
    def prepare_request(request: Request, scope_id: str, command: _Prepare):
        session = session_for(request, write=True)
        check_write_route(request, session, scope_id)
        if (not _ref(command.request_id) or command.mode not in _MODES | {'RESUME'}
                or (command.mode == 'RESUME' and (not _gateway_ref(command.cause_id) or command.expected_version < 1))
                or (command.mode != 'RESUME' and (command.cause_id != '' or command.expected_version != 0))):
            raise HTTPException(400, 'INVALID_COMMAND')
        operation = 'direct.control.resume' if command.mode == 'RESUME' else 'direct.control.apply'
        try:
            view, scope, runtime, binding, stable = receipt_context(session, scope_id, command.view_receipt, operation)
            expected_view = ({'kind': 'cause', 'cause_id': command.cause_id,
                              'version': command.expected_version, 'active': True}
                             if command.mode == 'RESUME' else {'kind': 'scope'})
            saved_view = view.get('view')
            if not isinstance(saved_view, Mapping) or any(saved_view.get(k) != v for k, v in expected_view.items()):
                raise ValueError('VIEW_MISMATCH')
            if binding_proof(runtime, session, scope, operation) != binding or resolve_runtime(session, scope) is not runtime:
                raise ValueError('BINDING_CHANGED')
            value = {'key_id': receipt_key_id, 'principal': session.principal_ref, 'actor': session.actor_ref,
                     'scope_id': scope_id, 'route': _route_fingerprint(scope), 'gateway': stable,
                     'command': command.model_dump(exclude={'view_receipt'})}
            return {'status': 'PREPARED', 'receipt': encode_receipt(value)}
        except Exception:
            return {'status': 'UNKNOWN', 'code': 'IDENTITY_UNAVAILABLE'}

    @app.post('/api/v1/scopes/{scope_id}/targets/prepare')
    def prepare_target(request: Request, scope_id: str, target: _Target):
        session = session_for(request, write=True)
        check_write_route(request, session, scope_id)
        if not all(_gateway_ref(v) for v in (target.cause_id, target.reservation_id, target.operation_id)):
            raise HTTPException(400, 'INVALID_TARGET')
        try:
            view, scope, runtime, binding, stable = receipt_context(session, scope_id, target.view_receipt, 'direct.control.drain_target')
            saved_view = view.get('view')
            expected = {'kind': 'target', 'cause_id': target.cause_id, 'reservation_id': target.reservation_id,
                        'operation_id': target.operation_id, 'state': 'PENDING'}
            if not isinstance(saved_view, Mapping) or any(saved_view.get(k) != v for k, v in expected.items()):
                raise ValueError('VIEW_MISMATCH')
            if resolve_runtime(session, scope) is not runtime or binding_proof(runtime, session, scope, 'direct.control.drain_target') != binding:
                raise ValueError('BINDING_CHANGED')
            command = {'mode': 'DRAIN_TARGET', **target.model_dump(exclude={'view_receipt'})}
            value = {'key_id': receipt_key_id, 'principal': session.principal_ref, 'actor': session.actor_ref,
                     'scope_id': scope_id, 'route': _route_fingerprint(scope), 'gateway': stable, 'command': command}
            token = encode_receipt(value)
            observed = command_status(session, scope_id, token, command)
            row = observed.get('target')
            if (observed.get('status') != 'OBSERVED' or not isinstance(row, Mapping)
                    or row.get('cause_id') != target.cause_id or row.get('reservation_id') != target.reservation_id
                    or row.get('operation_id') != target.operation_id or row.get('state') != 'PENDING'):
                return {'status': 'UNKNOWN', 'code': 'TARGET_UNAVAILABLE'}
            return {'status': 'PREPARED', 'receipt': token}
        except Exception:
            return {'status': 'UNKNOWN', 'code': 'IDENTITY_UNAVAILABLE'}

    @app.post('/api/v1/scopes/{scope_id}/requests/status')
    def request_status(request: Request, scope_id: str, receipt: _Receipt):
        session = session_for(request, write=True)
        check_write_route(request, session, scope_id)
        try:
            value = decode_receipt(receipt.receipt)
            return command_status(session, scope_id, receipt.receipt, value['command'])
        except Exception:
            return {'status': 'UNKNOWN', 'code': 'IDENTITY_UNAVAILABLE'}

    @app.post('/api/v1/scopes/{scope_id}/requests/run')
    def run_request(request: Request, scope_id: str, receipt: _Receipt):
        session = session_for(request, write=True)
        check_write_route(request, session, scope_id)
        try:
            value = decode_receipt(receipt.receipt)
            command = value['command']
            observed = command_status(session, scope_id, receipt.receipt, command)
            if command['mode'] == 'DRAIN_TARGET':
                target = observed.get('target')
                if (observed.get('status') != 'OBSERVED' or not isinstance(target, Mapping)
                        or target.get('cause_id') != command['cause_id'] or target.get('reservation_id') != command['reservation_id']
                        or target.get('operation_id') != command['operation_id'] or target.get('state') != 'PENDING'):
                    return observed
                operation = 'direct.control.drain_target'
                args = {'cause_id': command['cause_id'], 'reservation_id': command['reservation_id']}
            elif observed.get('status') != 'NOT_FOUND':
                return observed
            elif command['mode'] == 'RESUME':
                operation = 'direct.control.resume'
                args = {'cause_id': command['cause_id'], 'expected_version': command['expected_version'],
                        'operation_id': command['request_id']}
            else:
                operation = 'direct.control.apply'
                args = {'cause_id': command['request_id'], 'mode': command['mode']}
            result = receipt_call(session, scope_id, receipt.receipt, operation, args, write=True)
            return result if type(result) is dict else {'status': 'UNKNOWN'}
        except Exception:
            return {'status': 'UNKNOWN', 'code': 'IDENTITY_UNAVAILABLE'}

    @app.get("/api/v1/scopes/{scope_id}/snapshot")
    def snapshot(request: Request, scope_id: str):
        session = session_for(request)
        try:
            route_for(session, scope_id, "account.snapshot.typed", mount="application.account")
        except HTTPException:
            route_for(session, scope_id, "account.snapshot", mount="application.account")
        # Account callbacks currently have no verifiable source/journal binding
        # to the control view. Never present their output as the same Gateway.
        return {"status": "UNAVAILABLE", "reason": "SOURCE_PROVENANCE_UNAVAILABLE"}

    @app.get("/api/v1/scopes/{scope_id}/causes")
    def list_causes(request: Request, scope_id: str, after: str = "", limit: int = 100):
        if (after and not _gateway_ref(after)) or not 1 <= limit <= 256:
            raise HTTPException(400, "INVALID_PAGE")
        session = session_for(request)
        try:
            scope, stable, result = read_bound(session, scope_id, 'direct.control.list', {'after': after, 'limit': limit})
            if type(result) is not dict or result.get('status') != 'OBSERVED' or type(result.get('causes')) is not list:
                raise ValueError('INVALID_RESULT')
            scope_receipt = encode_receipt(view_data(session, scope, scope_id, stable, {'kind': 'scope'}))
            for row in result['causes']:
                if (type(row) is not dict or not _gateway_ref(row.get('cause_id')) or type(row.get('version')) is not int
                        or row['version'] < 1 or row.get('mode') not in _MODES
                        or type(row.get('active')) not in (int, bool) or row.get('active') not in (0, 1)):
                    raise ValueError('INVALID_CAUSE')
                row['view_receipt'] = encode_receipt(view_data(session, scope, scope_id, stable,
                    {'kind': 'cause', 'cause_id': row['cause_id'], 'version': row['version'],
                     'active': bool(row['active']), 'mode': row['mode']}))
            return {**result, 'scope_receipt': scope_receipt}
        except HTTPException:
            raise
        except Exception:
            return {'status': 'UNKNOWN', 'code': 'IDENTITY_UNAVAILABLE'}

    @app.post("/api/v1/scopes/{scope_id}/targets/query")
    def cause_targets(request: Request, scope_id: str, query: _TargetQuery):
        session = session_for(request, write=True)
        check_write_route(request, session, scope_id)
        if (query.after and not _gateway_ref(query.after)) or not 1 <= query.limit <= 256:
            raise HTTPException(400, "INVALID_PAGE")
        try:
            view, scope, _, _, stable = receipt_context(session, scope_id, query.view_receipt, 'direct.control.targets')
            cause = view.get('view')
            if not isinstance(cause, Mapping) or cause.get('kind') != 'cause' or cause.get('mode') != 'DRAIN':
                raise ValueError('VIEW_MISMATCH')
            result = receipt_call(session, scope_id, query.view_receipt, 'direct.control.targets',
                {'cause_id': cause['cause_id'], 'after': query.after, 'limit': query.limit})
            if type(result) is not dict or result.get('status') != 'OBSERVED' or type(result.get('targets')) is not list:
                raise ValueError('INVALID_RESULT')
            for row in result['targets']:
                if (type(row) is not dict or row.get('cause_id') != cause['cause_id']
                        or not all(_gateway_ref(row.get(k)) for k in ('reservation_id', 'operation_id', 'state'))):
                    raise ValueError('INVALID_TARGET')
                row['view_receipt'] = encode_receipt(view_data(session, scope, scope_id, stable,
                    {'kind': 'target', 'cause_id': row['cause_id'], 'reservation_id': row['reservation_id'],
                     'operation_id': row['operation_id'], 'state': row['state']}))
            return result
        except Exception:
            return {'status': 'UNKNOWN', 'code': 'IDENTITY_UNAVAILABLE'}

    if static_dir is not None:
        from fastapi.staticfiles import StaticFiles

        directory = Path(static_dir).resolve(strict=True)
        if not directory.is_dir() or not (directory / "index.html").is_file():
            raise ValueError("STATIC_DIRECTORY_INVALID")
        app.mount("/", StaticFiles(directory=directory, html=True), name="gateway-web")

    return app


def bundled_static_dir() -> Path:
    """Return built assets or explicitly fail when only API sources are installed."""
    path = Path(__file__).resolve().parent / "static"
    index = path / "index.html"
    notices = path / "THIRD_PARTY_NOTICES.txt"
    module_manifest = path / "THIRD_PARTY_MODULES.json"
    if not index.is_file() or not notices.is_file() or not module_manifest.is_file():
        raise RuntimeError("GATEWAY_WEB_STATIC_NOT_BUILT")
    try:
        assets = re.findall(r'(?:src|href)="/assets/([A-Za-z0-9_.-]+)"', index.read_text("utf-8"))
        if (not any(name.endswith(".js") for name in assets)
                or not any(name.endswith(".css") for name in assets)
                or any(not (path / "assets" / name).is_file() for name in assets)):
            raise ValueError
    except (OSError, UnicodeError, ValueError):
        raise RuntimeError("GATEWAY_WEB_STATIC_NOT_BUILT") from None
    return path


def run_local(app: FastAPI, *, origin: str) -> None:
    """Run only on the configured loopback address; host owns dependencies."""
    import uvicorn

    _local_origin(origin)
    parsed = urlsplit(origin)
    if parsed.scheme != "http" or parsed.port is None:
        raise ValueError("LOCAL_HTTP_PORT_REQUIRED")
    host = "127.0.0.1" if parsed.hostname == "localhost" else parsed.hostname
    uvicorn.run(app, host=host, port=parsed.port, proxy_headers=False)
