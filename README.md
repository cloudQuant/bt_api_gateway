# bt_api_gateway

Provider-neutral shared-account gateway contracts and a durable command router.

The package has no provider client, does not own credentials, and does not
start a socket server.  An authenticated server process supplies a principal
and an injected account-owner executor.  The router persists a command before
dispatch, de-duplicates command IDs, rejects scope/privilege/secret violations,
and never retries an incomplete dispatch automatically.

Every non-`READ` command also requires an injected server-owned admission
callback. It must return the literal `True` after checking the command against
current session, execution, risk, and control authority. Missing, negative, or
failed admission is durably rejected before the account-owner executor runs.
The callback is a read-only check: it must not perform provider I/O or dispatch
the command itself. `receipt_digest` and client command permissions alone do
not authorize a write. Deployments that have not connected an accepted
admission implementation remain read-only.

Non-`READ` routing also requires an injected `GatewayAccountWriterAuthority`
opened on the exact same SQLite file as the router. Its durable per-account
epoch/lease and unique action claim are revalidated immediately before the
executor call. Expired or revoked leases cannot be reacquired while a prior
action is unresolved, and an unresolved action blocks later writes under the
same lease as well; process restart never clears or replays such an action.
An executor return is recorded as `returned_unverified`, not as a provider
acknowledgement. This is a local same-database contract among cooperating
processes only: it cannot exclude manual writes, other hosts, or provider
sessions that do not consult this database, and it does not prove a coherent
provider snapshot. No default production writer route is configured.
The final lease check is performed immediately before the executor call, but
SQLite cannot revoke an executor call already in progress when wall-clock lease
expiry passes; a provider-enforced fencing token or bounded/cancellable owner
is required for a hard external expiry guarantee.

`GatewayEventJournal` provides a local durable read-side stream keyed by
opaque account and strategy scopes. It assigns monotonic cursors, deduplicates
stable event IDs, and can compact replay history only when an owner-supplied
snapshot matches the current cursor; readers behind that snapshot receive the
snapshot followed by later events. The account owner must produce a snapshot
from that same read-model version. This local contract does not implement
remote authentication, a provider session/writer fence, upstream subscription
sharing, or proof of a coherent provider account snapshot.

The network transport (including the planned ZMQ adapter) remains a separate
package and must authenticate clients before it creates a `GatewayPrincipal`.
