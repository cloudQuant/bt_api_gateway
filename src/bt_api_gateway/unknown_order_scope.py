"""Same-transaction minimum-scope fence for known system-order uncertainty.

Unmatched account facts are not automatically system orders. No risk-service
approval is consulted; this checks Gateway's own identity/ownership boundary.
"""
from __future__ import annotations

import sqlite3

from .direct_command_journal import DirectCommandJournalError
from .strategy_position_ledger import StrategyInstrumentBinding, _decode_fact, _decoded_payload, _direction

_MAX_ROWS = 1_000_000


def check_unknown_order_scope(db: sqlite3.Connection, account: str, strategy: str, payload: dict, *,
                              resolve_binding, exclude_reservation_id: str | None = None,
                              verify_other_close_capacity=None) -> None:
    """Reject only orders affected by a known uncertain system reservation.

    Call with the exact same write transaction before and after reserve or
    dispatch. The owner-installed resolver must resolve full instrument identity
    on both commands; missing or ambiguous identity cannot prove independence.
    Source-unknown facts lacking any system strong identity are not assigned to
    a strategy by this check. Verified external facts likewise remain external.
    """
    if not db.in_transaction or type(payload) is not dict or type(strategy) is not str or not strategy:
        raise DirectCommandJournalError("UNKNOWN_SCOPE_UNAVAILABLE")
    try:
        rows = db.execute("SELECT reservation_id,strategy,status,payload_json FROM direct_journal_commands WHERE account=? LIMIT ?", (account, _MAX_ROWS + 1)).fetchall()
        if len(rows) > _MAX_ROWS:
            raise DirectCommandJournalError("UNKNOWN_SCOPE_UNAVAILABLE")
        commands = {row[0]: (row[1], row[2], _decoded_payload(row[3])) for row in rows}
        unknown = {reservation for reservation, (_, status, _) in commands.items() if status == "UNKNOWN"}
        facts = db.execute("SELECT fact_json,disposition,reason,reservation_id FROM direct_execution_facts WHERE account=? AND (disposition IN ('UNATTRIBUTED','CONFLICT') OR reason IN ('NOT_SENT_CONTRADICTION','CANCEL_NOT_SENT_CONTRADICTION','OVERFILL','NOT_SENT_OVERFILL')) LIMIT ?", (account, _MAX_ROWS + 1)).fetchall()
        if len(facts) > _MAX_ROWS:
            raise DirectCommandJournalError("UNKNOWN_SCOPE_UNAVAILABLE")
        for raw, disposition, reason, reservation in facts:
            fact = _decode_fact(raw)
            if fact.account_scope != account:
                raise DirectCommandJournalError("UNKNOWN_SCOPE_UNAVAILABLE")
            if reservation is not None:
                if reservation not in commands:
                    raise DirectCommandJournalError("UNKNOWN_SCOPE_UNAVAILABLE")
                unknown.add(reservation)
            for key in fact.identity_keys:
                row = db.execute("SELECT reservation_id FROM direct_journal_strong_keys WHERE account=? AND strong_key=?", (account, key)).fetchone()
                if row is not None:
                    if row[0] not in commands:
                        raise DirectCommandJournalError("UNKNOWN_SCOPE_UNAVAILABLE")
                    unknown.add(row[0])
        if exclude_reservation_id is not None:
            unknown.discard(exclude_reservation_id)
        if not unknown:
            return
        if not callable(resolve_binding):
            raise DirectCommandJournalError("UNKNOWN_SCOPE_UNAVAILABLE")
        current = resolve_binding(payload)
        if type(current) is not StrategyInstrumentBinding:
            raise DirectCommandJournalError("UNKNOWN_SCOPE_UNAVAILABLE")
        offset = payload.get("offset")
        dependencies = []
        for reservation in unknown:
            owner, _, pending = commands[reservation]
            other = resolve_binding(pending)
            if type(other) is not StrategyInstrumentBinding:
                raise DirectCommandJournalError("UNKNOWN_SCOPE_UNAVAILABLE")
            if other.instrument != current.instrument:
                continue
            if owner == strategy:
                raise DirectCommandJournalError("SYSTEM_ORDER_UNKNOWN")
            if offset not in {"close", "close_today", "close_yesterday"}:
                continue
            prior_offset = pending.get("offset")
            if prior_offset == "open":
                continue
            if prior_offset not in {"close", "close_today", "close_yesterday"}:
                dependencies.append(reservation)
                continue
            if (current.split_close_required and prior_offset in {"close_today", "close_yesterday"}
                    and offset in {"close_today", "close_yesterday"} and prior_offset != offset):
                continue
            if _direction(payload.get("side"), offset) == _direction(pending.get("side"), prior_offset):
                dependencies.append(reservation)
        if dependencies and (not callable(verify_other_close_capacity)
                or verify_other_close_capacity(db, account, strategy, payload, current,
                                               tuple(sorted(dependencies))) is not True):
            raise DirectCommandJournalError("SYSTEM_ORDER_UNKNOWN")
    except DirectCommandJournalError:
        raise
    except Exception as exc:
        raise DirectCommandJournalError("UNKNOWN_SCOPE_UNAVAILABLE") from exc
