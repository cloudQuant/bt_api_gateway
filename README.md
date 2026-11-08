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

The default network transport is the separate `bt_api_transport_zmq` package.
The SDK `gateway` extra installs it by default. Future middleware belongs in
new transport packages behind the neutral service contracts. Transport must
authenticate clients before it creates a `GatewayPrincipal`; Gateway does not
implement another ZeroMQ stack.

## Role in the trading-system architecture

`bt_api_gateway` provides server-side, provider-neutral command routing and durable account event/read views. The hosting service supplies authenticated principals, the account-owner executor, current admission checks, and provider integration. Its SQLite leases and journals coordinate only cooperating processes on the configured database; they do not fence external writers or prove provider state. An executor return is not a provider acknowledgement, and no production writer route is enabled by default.

[Trading system architecture overview](https://github.com/cloudQuant/backtrader/blob/dev/docs/TRADING_SYSTEM_ARCHITECTURE.md).

## Market hub provider event delivery

`GatewayMarketHub` requires providers to implement `subscribe` and
`unsubscribe`. Event polling is a separate optional `MarketProviderPolling`
capability. Existing providers without a callable `poll` remain compatible:
they may publish through `GatewayMarketHub.publish` on the hub's owner thread,
and `maintain` does not invent events for them.

Polling providers enqueue immutable `MarketProviderEvent` values in their
worker-thread callbacks and implement nonblocking `poll(handle, limit=...)`.
The hub calls that method only from owner-thread `maintain`, with a bounded
per-call and per-maintenance budget. Each event carries an acquisition
generation that the hub checks before retaining or publishing; the generation
is not part of the public `sdk.market.event` payload. Providers must not call
`publish` from a callback thread.

## Durable consumer progress

`GatewayEventJournal.read_for_consumer` returns a bounded snapshot/replay page
and a `GatewayConsumerProgress` from one SQLite transaction. Progress contains
the persistent `stream_epoch`, `offered_cursor`, and `acknowledged_cursor`.
The epoch identifies this journal stream, independently of a provider session
generation or a service process epoch. Reopening the same database preserves
it; rebuilding a stream requires a new journal identity rather than resetting
sequence numbers under an old epoch.

Progress is isolated by principal, trusted consumer reference, account, and
view. A read cannot skip beyond the range previously offered to that consumer;
resuming from a positive cursor requires the matching epoch. An initial read
from zero replays the stream, while `cursor=None` explicitly requests the
current snapshot baseline. Compaction may also replace a lagging cursor with
a newer snapshot, which the receiver must apply before later events.
`offered_cursor` records a response prepared by the journal, not proof that a
network peer received it. A lost reply can be requested again.

`acknowledge` requires the matching epoch and a cursor no higher than the
consumer's offered range. Repeating an older or equal ACK never lowers its
progress. ACK only records the consumer's assertion of durable processing: it
does not confirm a provider order, remove replay/audit history, release risk,
or establish account freshness. The receiver must atomically save its own
projection and cursor before ACK, then deduplicate redelivery. The journal
does not perform that receiver transaction. Progress queries do not create a
consumer. New stream/progress record counts are bounded; reaching a bound
does not prevent an existing consumer from continuing.

The `GatewayReadService` exposes this through `account.read_after` with
`track_delivery=True`, `account.progress`, and `account.ack`. These calls use
the SDK registry's authenticated `WireIdentity` and authorized view, never a
client-supplied consumer ID. Identity includes the actor and delegation; the
run/registration ID is deliberately excluded so the same logical consumer
can resume after restart. Different actors and strategy views stay separate.
The service is not an authentication layer when called directly in Python.

SDK clients explicitly request the new operations and their server grants;
the default account-read operation set remains snapshot/head/read_after.
Ordinary reads without tracking keep their previous behavior. Journal errors
use the registry's existing `HANDLER_FAILED` response, except a tracked read
that cannot fit its first event or required snapshot: that transaction rolls
back and the SDK reports `REPLY_TOO_LARGE`. Trusted service context supplies
the complete reply-size check before the journal persists an offer. The page
contains a contiguous event prefix; it never skips an oversized event. Direct
Python calls retain the finite `GatewayEventJournalError.code`. Server
checkpoints do not replace a receiver's local recovery point.

## Permission-filtered provider views

The optional `GatewayAccountSessionWorker(view_policies=...)` publishes
resource-filtered account views in the same SQLite transaction as its canonical
account snapshot. An empty tuple preserves the existing single-snapshot path.
Policies belong to trusted server resource assembly; client requests cannot
choose resources, fact kinds, or a projection function.

```python
from bt_api_base.account_protocol import AccountResourceKey
from bt_api_gateway.account_view_projection import GatewayAccountViewPolicy

view_policy = GatewayAccountViewPolicy(
    view_scope="view:strategy-a",
    resources=(AccountResourceKey("spot", "cross"),),
    fact_kinds=frozenset({"balances", "positions", "open_orders"}),
    include_valuation=False,
)
# Pass view_policies=(view_policy,) to the account worker, then route the
# authenticated strategy through GatewayServiceAccountScope with
# strategy_scope_map={"strategy-a": "view:strategy-a"} and explicit grants.
```

Resource permission exposes every requested fact kind in that resource; it
does not filter by strategy order ownership or allocate virtual positions.
Provider account-wide valuation requires its own explicit permission. Missing
requested coverage, incomplete balances/positions/orders, absent open-order
facts, or absent requested valuation reject the entire update. They cannot
delete previously known facts. All views and the canonical snapshot either
commit together or remain unchanged, including when a later view write fails.

A view starts with a complete `sdk.account.view` version 1 snapshot at cursor
1. Later `account.view_delta` events carry `sdk.account.view.delta` version 1
payloads with row `upsert`/`delete` operations and an explicitly authorized
valuation replacement when changed. Balances use resource/currency identity;
positions use resource/instrument/side; orders use resource/instrument/order
ID. The `view_scope` binds the payload to its journal view. Baselines explicitly
report conservative `multi_query` consistency and preserve visible row times.
They do not claim a provider-atomic observation. Apply the baseline and later
events through the receiver's local projection/cursor transaction before ACK.

Each view has an independent continuous cursor. Hidden-only changes update
private source bindings without producing a visible event, new snapshot ID,
or sequence gap. Source account identity, observation ID, source revision and
policy digest remain outside public view payloads and IDs. The journal retains
bounded replay and compacts to a complete view snapshot; lagging consumers use
the existing snapshot recovery path. Consumer ACK never controls compaction.

The first publication fixes the source account and policy set. Restart checks
the same binding before connecting the provider; omission, policy changes,
scope collisions, and manual appends/snapshot writes to managed views are
rejected. Adding policies to an already-used legacy source requires an explicit
migration into fresh stream identities; there is no silent rewrite/reset.
Changing permissions likewise requires a deliberate migration and corresponding
grant changes, not reuse of an old view cursor under a different policy.
The `sdk.account.view` schemas, `account.view_delta` kind and `account-view:`
snapshot IDs are reserved for managed views. Reads reject missing bindings or
corrupt retained baselines/deltas instead of treating them as legacy streams.

The service may expose a subset of configured views through exact strategy
mappings. Full-account reads still require their separate canonical mapping
and grant. A filtered page is ready only when it reaches the current view head
and its private source binding matches the worker's fresh accepted observation.
Persisted views after restart remain diagnostic until that new observation.
These view payloads are for a generic schema-aware consumer, not the existing
full-account Backtrader facade. No provider SDK is embedded on the strategy side.

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

## Optional instrument metadata capability

`account.instrument_metadata` is advertised only when the trusted account
provider implements both `read_instrument_metadata(...)` and
`is_current_instrument_metadata(value)` (see
`GatewayInstrumentMetadataCapability` in `account_session_worker`). The worker
accepts a result only when the provider recognizes it as its own sealed fact
bound to the current owner generation; provider error codes outside the
documented finite set collapse to `PROVIDER_FACT_READ_FAILED`. This package
imports no provider package: the CTP implementation is
`bt_api_ctp.gateway_instrument_metadata.bind_ctp_instrument_metadata_provider`.

## Development

Requires Python 3.10 or newer.

```bash
python -m pip install -e ".[dev]"
python -m pytest -q          # offline unit tests
ruff check src tests && ruff format --check src tests
mypy                         # configured in pyproject.toml
```

CI runs the tests on Python 3.10–3.13, Ruff (lint and format), mypy, and a
wheel/sdist build on every push to `dev` and every pull request.

## Iteration 63 internal command journal (development slice)

`bt_api_gateway.direct_command_journal.GatewayDirectCommandJournal` adds bounded
two-phase command storage. It is independent of the existing router and is not
yet a trading owner or authenticated service. `create` exclusively creates a
new database; reopening requires the externally retained journal identity and
minimum revision. Recovery pages share one revision and reject intervening
mutations. The external anchor may lag later commits, so these checks alone do
not certify a restored backup.

Reserve binds a strategy/request key, principal label and canonical payload to
a UUID without allocating a native OrderRef. Release, expiry and dispatch
compete in SQLite transactions. Dispatch persists the native identity and
provider-neutral strong keys with unique ownership; retries never grant a new
start. Terminal tombstones are retained. Identity keys, authentication, writer
fencing and generation lifetime must be supplied by the trusted owner; labels
and storage states do not prove provider facts or that a request was unsent.

The current storage TTL is 10 seconds by default, bounded to 30 seconds, in the
owner generation's monotonic clock domain. Payload numeric quantities must use
canonical decimal strings or integers; binary floats are rejected. Native
identity keys must be complete, sorted and unique. Recovery exposes all records
to the trusted owner, not to unauthenticated remote clients. No provider sends,
strategy ledger integration, automatic takeover or production route is enabled
by this module. Version `0.2.0.dev63` is a development build, not release acceptance.

### Iteration 63 trusted local dispatch bridge

`GatewayDirectDispatcher` binds a command journal to an acquired
`LocalAccountSessionGuard` for the same account and generation. It calls a
trusted native port only at dispatch, and the SDK pre-dispatch commit port
records the native identity and strong keys before it returns a send marker.
A repeated dispatch reads the original state instead of allocating or sending
again; an incomplete final write stays DISPATCHING for recovery.

The SDK supplies the canonical OrderRequest adapter. Comparing request_summary
alone does not prove the actual native request matches it. This internal bridge
is not authentication, account readiness, a strategy ledger, or a remote client.
Its admission callback and native port remain trusted composition inputs.
Admission must return the literal `True`; missing returns and other values deny
dispatch. An optional per-request `request_fence` scopes the initial check and
the local durable commit separately, without holding that fence during native
I/O. Its yielded recheck runs after SQLite acquires the journal write lock and
before DISPATCHING is written, so waiting for that lock cannot bypass a lease
deadline. The SDK supplies Registry authorization and the separate owner-thread
queue; this package does not interpret wire principals or own ZMQ sockets.
The guard remains held on native/cleanup uncertainty. These are local,
cooperating-owner guarantees, not an external venue fencing mechanism.
`observe()` is read-only and reports the local remaining reservation TTL and
generation match; zero remaining TTL is not durable expiry or NOT_SENT.

### Iteration 63 daily settlement journal

Journal schema v3 adds settlement records to the same anchored SQLite database.
The account/route/trading-day key retains its initial observation, native and
owner generations, and optional attempt marker. ATTEMPTING is durable before
confirmation; UNKNOWN retains the attempt; CONFIRMED requires a trusted
provider observation supplied by the SDK owner. An existing daily record never
grants another send marker. A fresh confirmed read may create a record without
a send attempt. Commands and settlement records share the configured capacity.

Existing v2 databases require explicit `upgrade_v2` with the matching acquired
account guard, saved journal identity and revision anchor. The transaction
validates the old schema and record relationships, rejects extra triggers,
retains command/release/identity data, adds the table and advances the revision.
Failure rolls back; it never replaces the old database with an empty one.
Older objects cannot write after the schema upgrade. Schema upgrade checks do
not establish the authority of a restored backup or fence external writers.

Settlement insertion checks the caller's owner/observation/admission fence after
SQLite acquires its write lock and again before commit. Storage does not validate
provider provenance itself. The SDK controller supplies that validation and
readback policy; this package still owns no native client or ZMQ socket.

### Iteration 63 owner-published account read model

`GatewayAccountReadModel` extracts the existing account worker's observation,
coverage, clock and journal checks. A single owner thread starts a generation
and uses `begin_refresh` / `finish_refresh` / `fail_refresh`; an injected
generation callback checks that owner's lifecycle. Beginning a read invalidates
freshness before provider I/O. Cross-thread snapshot/status reads use an
immutable cached view and trusted clocks, without entering a provider or guard.
The original `GatewayAccountSessionWorker` composes this same model and retains
its own provider, guard and cleanup responsibilities.

Reopened journal snapshots are diagnostic only: the same observation ID cannot
establish a new generation's baseline. A successfully published observation may
be repeated within its generation without extending freshness. An ambiguous
journal commit or failed final owner check revokes baseline reuse. Freshness
cannot be restored by replaying that observation; a new validated read is needed.

`GatewayReadService(state_worker=model)` exposes exactly six account operations:
snapshot, typed snapshot, head, read_after, ack and progress. It rejects the
execution stream and does not advertise provider metadata, configuration,
server-time or reconciliation capabilities. Its read-only `accounts` mapping
lets the SDK verify public account routing against the command binding. This
read model owns no native lifecycle and grants no trading authority; local tests
are not deployment or account acceptance.
