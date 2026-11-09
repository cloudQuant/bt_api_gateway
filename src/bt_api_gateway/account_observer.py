"""Account observer cursor table; independent from strategy ACK state."""
from dataclasses import dataclass

from .direct_command_journal import DirectCommandJournalError, _text

_ACCOUNT_OBSERVER_DDL = {
    "direct_account_observer_consumers": "CREATE TABLE direct_account_observer_consumers (account TEXT NOT NULL, principal TEXT NOT NULL, consumer TEXT NOT NULL, offered_sequence INTEGER NOT NULL, acknowledged_sequence INTEGER NOT NULL, PRIMARY KEY(account, principal, consumer))",
}
_MAX_ACCOUNT_OBSERVERS = 8192


@dataclass(frozen=True)
class AccountObserverProgress:
    principal_id: str
    consumer_ref: str
    epoch: str
    offered_sequence: int
    acknowledged_sequence: int


def verify_account_observers(db, account):
    try:
        rows = db.execute("SELECT * FROM direct_account_observer_consumers LIMIT ?",
                          (_MAX_ACCOUNT_OBSERVERS + 1,)).fetchall()
        if len(rows) > _MAX_ACCOUNT_OBSERVERS:
            raise ValueError
        for row in rows:
            if row["account"] != account:
                raise ValueError
            _text(row["principal"])
            _text(row["consumer"])
            offered, ack = row["offered_sequence"], row["acknowledged_sequence"]
            if type(offered) is not int or type(ack) is not int or not 0 <= ack <= offered < 2**63:
                raise ValueError
            for sequence in (offered, ack):
                if sequence and db.execute(
                    "SELECT 1 FROM direct_execution_events WHERE account=? AND sequence=?",
                    (account, sequence),
                ).fetchone() is None:
                    raise ValueError
    except Exception:
        raise DirectCommandJournalError("INVALID_DATABASE") from None
