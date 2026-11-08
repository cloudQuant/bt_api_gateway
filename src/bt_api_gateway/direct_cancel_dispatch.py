"""Trusted owner-thread cancel bridge; no provider or ACL authority is implied."""

from __future__ import annotations

import os
from collections.abc import Callable

from bt_api_base.direct_write_protocol import PreDispatchRecord, WriteOperation

from .direct_cancel_journal import CancelRecord, GatewayDirectCancelJournal, _target_json
from .direct_dispatch import (
    DirectDispatchError,
    GatewayDirectDispatcher,
    NativeDispatchOutcome,
    _request_scope,
)
from .session_guard import LocalAccountSessionGuard


class GatewayDirectCancelDispatcher:
    """Reuse the existing exact owner, guard and journal for cancel attempts."""

    def __init__(
        self,
        cancel_journal: GatewayDirectCancelJournal,
        owner_dispatcher: GatewayDirectDispatcher,
        guard: LocalAccountSessionGuard,
        exchange_name: str,
        native_cancel: Callable,
        assert_admitted: Callable,
    ) -> None:
        if (
            type(cancel_journal) is not GatewayDirectCancelJournal
            or type(owner_dispatcher) is not GatewayDirectDispatcher
            or type(guard) is not LocalAccountSessionGuard
            or type(exchange_name) is not str
            or not exchange_name
            or not callable(native_cancel)
            or not callable(assert_admitted)
        ):
            raise DirectDispatchError("INVALID_COMPOSITION")
        if not owner_dispatcher.is_bound_to(cancel_journal.journal, guard, exchange_name):
            raise DirectDispatchError("INVALID_COMPOSITION")
        self._journal = cancel_journal
        self._owner = owner_dispatcher
        self._exchange = exchange_name
        self._native_cancel = native_cancel
        self._admission = assert_admitted
        self._pid = os.getpid()
        self._active = False

    @property
    def journal(self) -> GatewayDirectCancelJournal:
        return self._journal

    def is_bound_to(self, owner_dispatcher: object) -> bool:
        if os.getpid() != self._pid:
            raise DirectDispatchError("WRONG_OWNER")
        return self._owner is owner_dispatcher

    def _owned(self) -> None:
        self._owner.assert_owned()

    def _admitted(self, row: CancelRecord) -> None:
        try:
            accepted = self._admission(row)
        except Exception:
            raise DirectDispatchError("ADMISSION_DENIED") from None
        if accepted is not True:
            raise DirectDispatchError("ADMISSION_DENIED")

    def dispatch(
        self,
        strategy: str,
        operation_id: str,
        principal: str,
        *,
        expected_version: int,
        request_fence=None,
    ) -> CancelRecord:
        if request_fence is not None and not callable(request_fence):
            raise DirectDispatchError("INVALID_REQUEST_FENCE")
        self._owned()
        if self._active:
            raise DirectDispatchError("DISPATCH_REENTRANT")
        row = self._journal.get(strategy, operation_id, principal)
        if row.status != "REQUESTED":
            return row
        if row.generation != self._journal.journal.generation:
            raise DirectDispatchError("GENERATION_MISMATCH")
        if type(expected_version) is not int or row.version != expected_version:
            raise DirectDispatchError("VERSION_CONFLICT")
        self._active = True
        try:
            with _request_scope(request_fence, row):
                self._owned()
                self._admitted(row)
                self._owned()
            port = _CancelCommitPort(self, row, request_fence)
            try:
                outcome = self._native_cancel(
                    row.target_identity, row.symbol, port, self._journal.journal.account_scope
                )
            except Exception:
                outcome = None
            finally:
                port.close()
            self._owned()
            current = port.current_after_attempt()
            if current is None:
                raise DirectDispatchError("PRE_DISPATCH_FAILED")
            sent = None
            error_code = "OUTCOME_UNCERTAIN"
            if type(outcome) is NativeDispatchOutcome and outcome.marker_id == current.marker_id:
                try:
                    matches = outcome.identity is not None and _target_json(
                        outcome.identity
                    ) == _target_json(row.target_identity)
                except Exception:
                    matches = False
                if matches:
                    sent = outcome.sent
                    error_code = outcome.error_code
                    if error_code is not None:
                        from .direct_cancel_journal import _error

                        try:
                            _error(error_code)
                        except Exception:
                            error_code = "OUTCOME_UNCERTAIN"
                            sent = None
            self._owned()
            try:
                return self._journal.finish(
                    strategy,
                    operation_id,
                    principal,
                    current.version,
                    current.marker_id,
                    current.prepared_digest,
                    current.generation,
                    sent,
                    error_code=error_code,
                )
            except Exception:
                raise DirectDispatchError("FINISH_FAILED") from None
        finally:
            self._active = False


class _CancelCommitPort:
    def __init__(self, owner, record, request_fence):
        self._owner, self._record, self._request_fence = owner, record, request_fence
        self._attempted = False
        self._closed = False
        self._known_not_new = False
        self._prepared_digest = None

    def close(self):
        self._closed = True

    def commit(self, record: PreDispatchRecord) -> str | None:
        self._owner._owned()
        if self._closed or not self._owner._active:
            raise DirectDispatchError("COMMIT_CLOSED")
        if self._attempted:
            raise DirectDispatchError("COMMIT_REUSED")
        self._attempted = True
        try:
            if type(record) is not PreDispatchRecord:
                raise ValueError
            record.to_dict()
            prepared = record.prepared_cancel
            if (
                record.operation is not WriteOperation.CANCEL
                or prepared is None
                or record.identity is not None
                or record.host_scope != self._owner._journal.journal.account_scope
                or record.exchange_name != self._owner._exchange
                or record.symbol != self._record.symbol
                or _target_json(record.target_identity)
                != _target_json(self._record.target_identity)
            ):
                raise ValueError
            digest = prepared.digest()
        except Exception:
            raise DirectDispatchError("COMMIT_RECORD_INVALID") from None
        with _request_scope(self._request_fence, self._record) as recheck:
            self._owner._owned()
            current = self._owner._journal.get(
                self._record.strategy_scope, self._record.operation_id, self._record.principal
            )
            if current != self._record:
                raise DirectDispatchError("REQUEST_CONFLICT")
            self._owner._admitted(current)
            self._owner._owned()
            self._prepared_digest = digest

            def before_dispatch():
                self._owner._owned()
                self._owner._admitted(current)
                self._owner._owned()
                if recheck is not None:
                    recheck()

            result = self._owner._journal.begin_dispatch(
                current.strategy_scope,
                current.operation_id,
                current.principal,
                current.version,
                prepared,
                before_dispatch=before_dispatch,
            )
            if not result.newly_started:
                self._known_not_new = True
        return None if self._known_not_new else current.attempt_id

    def current_after_attempt(self):
        if self._prepared_digest is None or self._known_not_new:
            return None
        row = self._owner._journal.get(
            self._record.strategy_scope, self._record.operation_id, self._record.principal
        )
        if (
            row.status != "DISPATCHING"
            or row.attempt_id != self._record.attempt_id
            or row.version != self._record.version + 1
            or row.marker_id != self._record.attempt_id
            or row.prepared_digest != self._prepared_digest
        ):
            return None
        return row
