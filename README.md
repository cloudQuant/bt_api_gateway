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

## Local provider-query resolution candidate

The optional `GatewayResolutionCapability` is constructor-injected by the
server and defaults to unavailable. It requires a `GatewayQueryVerifier`
implementation owned by that server; no real provider verifier or registered
runtime is shipped. A proof dataclass, source label or digest is not an
authentication authority. Client wire payloads cannot select a verifier or
submit a proof/status to the resolution API.

An admitted account owner can call `bind_provider_action` after the router's
begin-dispatch check and before provider I/O, persisting exact provider account,
session, request and operation correlation. `resolve_action(lease, action_id,
proof_reference)` invokes the configured independent query verifier with all
SQLite connections closed, then atomically appends an immutable resolution
after rechecking the exact claim/command snapshot, current original lease,
configured verifier identity/policy, query freshness and monotonic source frame.
Duplicate identical references are idempotent; conflicting proof reuse fails.

A queried working submit can clear command uncertainty for another write in
the same writer epoch. This does not release its order exposure or risk
reservation. Cancel resolution requires a queried terminal cancel result and
terminal target order. Every following write still needs normal router
admission. Historical `UNKNOWN`/`RETURNED_UNVERIFIED` claim and router records
remain unchanged; the separate resolution is the additional fact.

Provider binding schema v2 declares an authentication profile and the meaning
of its request reference (`client_order_id`, `provider_request_id`, or, for
non-REST fixtures/session adapters, `local_action_id`). `provider_session`
requires actual provider account and session identities. `signed_rest` has no
provider session; the provider UID may be absent. It instead requires a
`sha256:` credential-key fingerprint reference, local capture scope, and exact
internal account scope. These are local correlation values, not a provider UID
or evidence-issuer authority. A known REST UID can be retained without inventing
a session. `offline_fake` explicitly labels synthetic identities. Profile
substitution, contradictory fields and missing required bindings fail closed;
the verifier must still independently verify its query source.

Writer takeover remains closed while historical unresolved claims exist,
even after current-epoch resolution. An expired/revoked lease cannot resolve;
there is no implicit recovery authority. This candidate does not provide
provider authentication, query completeness, a cross-host writer fence, risk
settlement, a production adapter, or live permission. The tests use an explicit
fake query source only. Existing deployments without a capability retain their
original fail-closed behavior.
