# Gateway local Web API, version 1

This is the reference of the HTTP interface in `bt_api_gateway.web.app` and of the
login routes added by the built-in local host `bt_api_py.gateway_web_local_host`.
It describes the code as it is; it is not evidence that any account, venue or
deployment has been checked. Browser pages are not part of this interface and are
not delivered with it.

## 1. What the interface is

- An optional, local-only adapter between a browser or another local HTTP client
  and an already running Gateway. It lists control causes, applies `STOP_NEW`,
  `FREEZE` or `DRAIN`, releases one cause at a time (`RESUME`), and cancels one
  frozen order of a `DRAIN` cause on request.
- It has no authority of its own. Every Gateway call is made with the operator's
  own authenticated CURVE registration (`application_client` role, the operator's
  principal and actor, no delegate). The Gateway's Registry and its control grants
  decide every call for that exact principal, account and strategy scope, exactly
  as for an operator's own SDK client (the CLI path).
- It does not start, own, or stop the Gateway, its account owner or the trading
  session. Starting, stopping or killing the Web host changes nothing in the
  Gateway except the host's own registrations.

## 2. Transport rules (every request)

| Rule | Failure |
| --- | --- |
| The TCP peer must be a loopback address. | 403 `{"error": "LOCAL_ACCESS_REQUIRED"}` |
| The `Host` header must equal the configured origin's host and port. | 403 `{"error": "HOST_DENIED"}` |
| Only `GET`, `HEAD` and `POST` pass the filter. `HEAD` is useful only for static files; API routes answer `GET` or `POST` and return 405 otherwise. | 405 `{"error": "METHOD_DENIED"}` |
| A `POST` must carry a decimal `Content-Length` of at most 8192 bytes. | 413 `{"error": "BODY_SIZE_INVALID"}` |
| A `POST` must carry `Origin` equal to the configured origin (for example `http://127.0.0.1:8000`). | 403 `{"error": "ORIGIN_DENIED"}` |

The configured origin must be `http` or `https` on `localhost` or a loopback IP.
`run_local` listens only on that loopback address and ignores proxy headers. Every
answer that passed these rules carries `Cache-Control: no-store`,
`X-Content-Type-Options: nosniff` and a `Content-Security-Policy` that forbids
framing.

## 3. Authentication and authorisation

- Authentication is done by the host on every request; the adapter never reads
  an identity from a request body. The built-in host expects the header
  `X-Gateway-Session: <64 lowercase hex characters>` obtained from `POST /login`
  (section 8). Without a valid session: 401 `{"detail": "AUTHENTICATION_REQUIRED"}`.
- Every `POST` under `/api/v1/scopes/` also needs `X-CSRF-Token` equal to the
  `csrf_token` returned by `GET /api/v1/session` (403 `{"detail": "CSRF_DENIED"}`)
  and `X-Gateway-Route` equal to the scope's `route_fingerprint` from the same
  response (409 `{"detail": "ROUTE_CHANGED"}`). A changed fingerprint means the
  host now maps the `scope_id` to a different account, scope or strategy: read
  the session and the causes again; never reuse older receipts on the new route.
- A `scope_id` is a local name chosen by the host. It must be one of the session's
  scopes (403 `{"detail": "SCOPE_DENIED"}`); it is not an authorisation by itself.
- Before any Gateway call the adapter checks that the operator's runtime is
  running and healthy, has the session's principal and actor, and holds exactly
  one active binding for the scope's account, scope and strategy that includes
  the operation. When this fails, `GET .../causes` and `GET .../snapshot` answer
  403 `{"detail": "GATEWAY_SCOPE_OR_GRANT_UNAVAILABLE"}`; the `POST` routes answer
  `{"status": "UNKNOWN", "code": "IDENTITY_UNAVAILABLE"}` and send nothing. A
  view-only operator therefore lists causes but cannot prepare a request.
- The Gateway then authorises the call itself. A caller authorised for one
  strategy sees and changes only that strategy's causes. A caller authorised for
  the whole account sees the account's causes and the contract causes; it does
  not see strategy causes. A caller registered for another account is refused.
  A revoked principal or an expired registration is refused. When the Gateway
  refuses after the adapter's own checks passed, the adapter cannot prove the
  Gateway's identity and answers `{"status": "UNKNOWN", "code":
  "IDENTITY_UNAVAILABLE"}` (HTTP 200); nothing is shown and nothing is applied.
- Malformed input can be answered before authentication: 422 (body schema, with
  FastAPI's `detail` list), 400 `INVALID_PAGE`. These answers carry no account data.

Gateway operations the operator's registration needs, per route (grant only what
the operator should do; a missing read grant is never replaced by a write grant):

| Route | Gateway operations |
| --- | --- |
| `GET /causes` | `direct.control.identity`, `direct.control.list` |
| prepare/status/run of `STOP_NEW`, `FREEZE`, `DRAIN` | `direct.control.identity`, `direct.control.status`, `direct.control.apply` |
| prepare/status/run of `RESUME` | `direct.control.identity`, `direct.control.resume_status`, `direct.control.resume` |
| `targets/query` | `direct.control.identity`, `direct.control.targets` |
| `targets/prepare` and its status/run | `direct.control.identity`, `direct.control.target_status`, `direct.control.drain_target` |
| `GET /snapshot` | `account.snapshot.typed` or `account.snapshot` on the `application.account` mount (checked, never read; see 6.2) |

## 4. Route index

Paths are relative to the configured origin. `{scope_id}` is one of the session's
`scope_id` values.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/session` | Session, CSRF token and the session's scopes |
| `GET` | `/api/v1/scopes/{scope_id}/causes` | One page of causes, with signed view receipts |
| `POST` | `/api/v1/scopes/{scope_id}/requests/prepare` | Sign a control request; sends nothing |
| `POST` | `/api/v1/scopes/{scope_id}/requests/status` | Look up the signed request in the Gateway journal |
| `POST` | `/api/v1/scopes/{scope_id}/requests/run` | Look up, and send only if the journal has no record |
| `POST` | `/api/v1/scopes/{scope_id}/targets/query` | One page of frozen orders of a `DRAIN` cause |
| `POST` | `/api/v1/scopes/{scope_id}/targets/prepare` | Sign a cancel request for one frozen order; sends nothing |
| `GET` | `/api/v1/scopes/{scope_id}/snapshot` | Always `UNAVAILABLE` (section 6.2) |

When the host passes `static_dir`, files of that directory are served under `/`
after the API routes. No other route exists.

## 5. Receipts

The adapter signs receipts with HMAC-SHA256. A receipt binds the principal, the
actor, the `scope_id`, the route fingerprint, the Gateway's authenticated service
identity and CURVE key fingerprint, and the Gateway journal id; a request receipt
also binds the full request content. Clients treat receipts as opaque strings.

- A *view receipt* is returned with each listed cause and target, and as
  `scope_receipt` for the scope. A request must be prepared from a view of the
  same Gateway journal.
- A *request receipt* is returned by `prepare`. It is the identity of one request.
- A receipt is refused when any bound value differs at use time: another
  Gateway identity, another journal, another route, another operator, an edited
  receipt, or another signing key or key id. The answer is then `UNKNOWN`.
- With a persistent `receipt_key` (the built-in host reads one from its protected
  file) receipts stay valid across Web host restarts. Without one
  (`receipt_key_persistent: false`) a restart makes every older receipt `UNKNOWN`.

## 6. Routes

### 6.1 `GET /api/v1/session`

Response:

```json
{"csrf_token": "<token>", "namespace": "<64 hex>", "receipt_key_persistent": true,
 "scopes": [{"scope_id": "desk", "strategy_ref": null, "route_fingerprint": "<64 hex>"}]}
```

`namespace` is a hash of principal and actor for keeping local client state
apart. `strategy_ref` is `null` for an account-scope route.

### 6.2 `GET /api/v1/scopes/{scope_id}/snapshot`

Checks that the operator holds an account read grant on the `application.account`
mount, then always answers `{"status": "UNAVAILABLE", "reason":
"SOURCE_PROVENANCE_UNAVAILABLE"}`. No account data is read or shown: the account
read service answers from its own event journal and nothing in its reply proves
that it is the same Gateway and journal as the control view. Without the grant
(this includes the built-in host, which registers only the control mount): 403
`GATEWAY_SCOPE_OR_GRANT_UNAVAILABLE`.

### 6.3 `GET /api/v1/scopes/{scope_id}/causes?after=&limit=100`

`after` is a cause id (exclusive; empty for the first page), `limit` is 1 to 256.
Response:

```json
{"status": "OBSERVED", "scope_receipt": "<view receipt>",
 "causes": [{"cause_id": "unresolved-return:SHFE:rb:0123456789abcdef", "scope_kind": "instrument",
             "scope_value": "SHFE:rb", "mode": "FREEZE", "active": 1, "version": 1,
             "origin": "system:unresolved_return:<hash>", "resume_id": null,
             "account": "<account>", "generation": "<owner generation>", "view_receipt": "<view receipt>"}]}
```

- Rows are the Gateway's cause records, ordered by `cause_id`. `active` is 1 or
  0; `version` is 1 while active and 2 after its release. `scope_kind` is
  `account`, `strategy` or `instrument`.
- A contract cause (`scope_kind: "instrument"`, `scope_value: "<venue>:<symbol>"`,
  always `FREEZE`) is applied by the Gateway when a return on that contract
  belongs to none of its orders. It appears only for an account-scope caller,
  in the same pages as the account's causes.
- A page shorter than `limit` is the last page; otherwise ask again with `after`
  set to the last `cause_id`.
- On any failure after the authorisation checks: `{"status": "UNKNOWN", "code":
  "IDENTITY_UNAVAILABLE"}`.

### 6.4 `POST /api/v1/scopes/{scope_id}/requests/prepare`

Body (all fields; no other field is accepted):

| Field | Apply (`STOP_NEW`, `FREEZE`, `DRAIN`) | Release (`RESUME`) |
| --- | --- | --- |
| `request_id` | New id, 1 to 128 characters `[A-Za-z0-9._:-]`, starting with a letter or digit. It becomes the cause id. | New id, same form. It becomes the release's operation id. |
| `mode` | `STOP_NEW`, `FREEZE` or `DRAIN` | `RESUME` |
| `cause_id` | `""` | The cause to release |
| `expected_version` | `0` | The `version` shown in the cause's row (1) |
| `view_receipt` | The page's `scope_receipt` | That cause's `view_receipt`; the view must show it active |

Response: `{"status": "PREPARED", "receipt": "<request receipt>"}`. Nothing is sent
to the Gateway's journal. Other answers: 400 `INVALID_COMMAND`, or `{"status":
"UNKNOWN", "code": "IDENTITY_UNAVAILABLE"}` when the operation is not granted to
the operator's registration, or the view, the route or the Gateway identity
cannot be verified (for example a view of another operator, of another scope or
of an earlier Gateway journal).

### 6.5 `POST /api/v1/scopes/{scope_id}/requests/status`

Body `{"receipt": "<request receipt>"}`. Looks the request up; never sends it.

| Answer | Meaning |
| --- | --- |
| `{"status": "NOT_FOUND", "cause_id": "<request_id>"}` (apply) or `{"status": "NOT_FOUND", "operation_id": "<request_id>"}` (release) | The current journal has no record of this request id. This does not prove that an earlier attempt never reached the Gateway of another journal. |
| `{"status": "OBSERVED", "cause": {<cause row>}}` (apply) | The cause with this id is this operator's cause with this mode and scope. Its current `active` value is shown. |
| `{"status": "OBSERVED", "cause_id", "operation_id", "version": 2, "active": false}` (release) | This release of this cause is recorded. |
| `{"status": "REQUEST_REJECTED", "code": "REQUEST_ID_CONFLICT"}` | The id is already used by another command: a cause of another operator, mode or scope (a contract cause included), or a release of another cause. This request was not applied and will not be sent under that id. |
| `{"status": "UNKNOWN", "code": "IDENTITY_UNAVAILABLE"}` | No verified answer (Gateway refused, unreachable, identity or journal changed, receipt invalid). |

For a cancel receipt (from `targets/prepare`) the answers are those of 6.8.

### 6.6 `POST /api/v1/scopes/{scope_id}/requests/run`

Body `{"receipt": "<request receipt>"}`. First does exactly what `status` does. If
that answer is `NOT_FOUND`, it sends the original request, with the original id,
to the Gateway, fenced to the journal id bound in the receipt; otherwise it
returns that answer unchanged and sends nothing.

Answers after sending:

| Answer | Meaning |
| --- | --- |
| `{"status": "OBSERVED", "cause_id", "version": 1, "active": true}` | Cause applied (or it already existed with the same content). |
| `{"status": "OBSERVED", "cause_id", "version": 2, "active": false}` | Cause released. Only this cause; others may still block (read the list). |
| `{"status": "REQUEST_REJECTED", "code": "<code>"}` | The Gateway refused; nothing was changed by this call. Codes in section 7. |
| `{"status": "UNKNOWN", ...}` | The outcome is not known. The Gateway may or may not have applied it. |

### 6.7 `POST /api/v1/scopes/{scope_id}/targets/query`

Body `{"view_receipt": "<view receipt of a DRAIN cause>", "after": "", "limit": 100}`.
Response `{"status": "OBSERVED", "targets": [...]}`; each row has `cause_id`,
`strategy`, `request_key`, `reservation_id`, `operation_id`, `state` (`PENDING`,
`UNKNOWN`, `CANCELLED` or `OBSERVED_TERMINAL`), `terminal_fact_digest`,
`terminal_sequence`, `account` and its own `view_receipt`. On failure
`{"status": "UNKNOWN", "code": "IDENTITY_UNAVAILABLE"}`; a bad page is 400
`INVALID_PAGE`.

### 6.8 `POST /api/v1/scopes/{scope_id}/targets/prepare`

Body `{"cause_id", "reservation_id", "operation_id", "view_receipt"}` from one
`PENDING` target row. Checks with the Gateway that the target is still `PENDING`
and answers `{"status": "PREPARED", "receipt": ...}`; sends no cancel. Other
answers: 400 `INVALID_TARGET`, `{"status": "UNKNOWN", "code": "TARGET_UNAVAILABLE"}`
(not pending any more), `{"status": "UNKNOWN", "code": "IDENTITY_UNAVAILABLE"}`.

Running the receipt cancels the order once: the target is claimed before the
cancel is sent. `status` answers `{"status": "OBSERVED", "target": {...}}` while
it is pending (then `run` sends the cancel), `{"status": "OBSERVED_TERMINAL",
"cause_id", "reservation_id"}` when a terminal order return was observed,
`{"status": "UNKNOWN", "cause_id", "reservation_id", "target_state"}` for any
other state, and `{"status": "NOT_FOUND", "cause_id", "operation_id"}` when the
journal has no such target. `run` sends nothing in the last three cases. After
sending, `run` answers `OBSERVED_TERMINAL` or `UNKNOWN` with `cause_id` and
`reservation_id`. A claimed target is never claimed again: an `UNKNOWN` cancel is
not retried by the API.

## 7. Status values and codes

Status values: `PREPARED`, `NOT_FOUND`, `OBSERVED`, `OBSERVED_TERMINAL`, `UNKNOWN`,
`REQUEST_REJECTED`, `UNAVAILABLE`.

Codes set by the adapter:

| Code | Where | Meaning |
| --- | --- | --- |
| `LOCAL_ACCESS_REQUIRED`, `HOST_DENIED`, `METHOD_DENIED`, `BODY_SIZE_INVALID`, `ORIGIN_DENIED` | `error`, section 2 | Transport rule failed |
| `AUTHENTICATION_REQUIRED` | 401 `detail` | No valid session |
| `CSRF_DENIED` | 403 `detail` | Missing or wrong `X-CSRF-Token` |
| `SCOPE_DENIED` | 403 `detail` | `scope_id` is not one of the session's scopes |
| `GATEWAY_SCOPE_OR_GRANT_UNAVAILABLE` | 403 `detail` | Runtime not healthy, other identity, or no exact binding with the operation |
| `ROUTE_CHANGED` | 409 `detail` | `X-Gateway-Route` missing or not the current fingerprint |
| `INVALID_COMMAND`, `INVALID_TARGET`, `INVALID_PAGE` | 400 `detail` | Input outside the rules above |
| `IDENTITY_UNAVAILABLE` | `UNKNOWN` | No verified Gateway identity, journal or answer |
| `TARGET_UNAVAILABLE` | `UNKNOWN` | The frozen order is not pending any more |
| `REQUEST_ID_CONFLICT` | `REQUEST_REJECTED` | The request id belongs to another command |
| `SOURCE_PROVENANCE_UNAVAILABLE` | `UNAVAILABLE` `reason` | Snapshot not offered (6.2) |

Codes passed through from the Gateway with `REQUEST_REJECTED` (not exhaustive;
the Gateway may add codes and a client must treat any other code as a refusal):
`SCOPE_DENIED`, `INVALID_REQUEST`, `ADMISSION_DENIED`, `JOURNAL_ID_MISMATCH`,
`CONTROL_UNAVAILABLE`, `CANCEL_UNAVAILABLE`, `CONTROL_CANCEL_PROOF_REQUIRED`,
`RECOVERY_REQUIRED` (a lease DRAIN cause whose recovery conditions are not met),
`CONTRACT_ORDERS_UNDECIDED` (a contract cause cannot be released while one of the
Gateway's own orders on that contract is being sent or has an unknown outcome).
The Gateway's own `{"status": "UNKNOWN", "cause_id": ...}` (for example an owner
timeout or a version conflict) is passed through unchanged by `status` and `run`;
`causes` and `targets/query` answer `IDENTITY_UNAVAILABLE` instead.

## 8. Built-in host routes

Added by `bt_api_py.gateway_web_local_host`, outside `/api/v1/`:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/login` | Login form |
| `POST` | `/login` | Form body `token=<64 hex>`; answers `{"session": "<64 hex>"}` |
| `GET` | `/gateway-local-login.js` | Script of the login form |
| `GET` | `/logout` | Logout page |
| `POST` | `/logout` | Header `X-Gateway-Session`; answers `{"status": "SIGNED_OUT"}` |
| `GET` | `/gateway-local-logout.js` | Script of the logout page |

`POST /login` is subject to the `Origin` rule. A wrong token answers 401; more
than 128 live sessions answer 503. A session lasts at most 30 minutes. Any
detected change of the host's protected configuration file ends every session
until the host is restarted. Revoking an operator in the Web host is not a
Gateway revocation: revoke the principal or its grant in the Gateway's Registry.

## 9. Sequence and client rules

1. `GET /api/v1/session`; keep `csrf_token` and the scope's `route_fingerprint`.
2. `GET .../causes` to obtain `scope_receipt` and the causes with their
   `view_receipt`.
3. `POST .../requests/prepare` with a new `request_id`. Store the returned receipt
   durably (and share it between tabs) before going on.
4. `POST .../requests/run` with that receipt.
5. On `UNKNOWN`, on a lost or timed-out HTTP reply, on a closed tab, or when a
   second tab finds a stored receipt: call `status` with the same receipt.
   - `OBSERVED`: done; show the returned state.
   - `NOT_FOUND`: the current journal has no record. After the operator confirms,
     call `run` again with the same receipt; the Gateway write is idempotent on
     the id and fenced to the journal id in the receipt.
   - `UNKNOWN`: keep the receipt and ask again later. When it stays `UNKNOWN`
     (another Gateway identity, journal or signing key) the outcome must be
     checked by hand in the Gateway journal, for example with the operator's own
     SDK client.
6. Never prepare a new `request_id` to retry an unresolved request, and never
   treat `UNKNOWN` as success or as "not applied".
7. `REQUEST_ID_CONFLICT`: the id is taken by another command; read the list
   again and prepare a new request with a new id if still wanted.
8. A double click or several tabs running the same receipt at the same time
   produce one Gateway change; every call answers with the same record.
9. After a release, read the list again: releasing one cause does not release
   the others, and a released cause does not mean that trading is ready.

## 10. Audit

- An applied cause is stored in the Gateway journal with `origin =
  "operator:" + SHA-256 of the JSON array [principal, actor]`, computed by the
  Gateway from the authenticated registration. A cause applied through the Web
  therefore carries the Web operator's own identity, the same way as a cause
  applied by that operator's SDK client. The Web host adds no identity of its own.
- A release stores the request id as the cause's `resume_id`. The journal does
  not store who released a cause, for the Web and for the CLI alike.
- A cancel of a frozen order stores the requesting principal and actor, the
  registration id and the service epoch with the cancel.
- Browser storage and Web host memory are not an audit record.

## 11. What this API never does

- It never places, changes or closes an order, and never changes a position,
  balance or ledger.
- It never clears an `UNKNOWN` order or command, never releases a cause by
  itself, and never retries a request under a new id.
- It never shows account or strategy money or positions (6.2).
- It never accepts an identity, account or strategy from a request body or URL,
  never uses a shared or more privileged Gateway identity, and never grants a
  Gateway operation.
- It never cancels or rolls back a request that the Gateway accepted when a tab
  closes, a reply is lost or the Web host stops.
- It never listens on a non-loopback address, uses cookies (built-in host) or
  follows proxy headers.
- It never starts, stops or takes over the Gateway or its account owner.
