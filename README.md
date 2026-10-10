# wolf-access-client

The Python client library for **wolf-access**, the Nice-Wolf-Studio authorization service, and
the **shared WRN library** every service uses to build, read and check WRNs (INT-B3).

A service embeds it to register its types (INT-D1), to keep its resources in wolf-access's tree
with synchronous creates, moves and deletes (INT-D2..D5), to reconcile its full list (INT-D7), to
exchange a principal's token (INT-C5), and to ask wolf-access whether a principal, calling
through a connected app, may act on one of its resources (INT-F2).

This version targets wolf-access `development` as redesigned by wolf-access PR #329
(@ ffe20ed). **0.7.0 breaks 0.6.0**: see [Changes from 0.6.0](#changes-from-060).

## Install

Install it by release tag, the same way as
[gateway-client](https://github.com/Nice-Wolf-Studio/gateway-client). No token or other credential
is needed:

```bash
pip install "git+https://github.com/Nice-Wolf-Studio/wolf-access-client@v0.7.0"
```

Python 3.10+, standard library only.

## What is public and what is not

- This repo is public. It holds the client code only: **no secrets and no data**.
- The wolf-access service and its specification are in a private repo. The client talks to a
  running wolf-access service with a per-service credential that the service supplies at run
  time; no credential is ever committed here.

## WRNs (INT-B3)

A WRN is `wrn:<service>:<type>/<id>` (INT-B1, AC-17). `wolf_access_client.wrn` is the one
validator every service uses; its grammar is wolf-access's, byte for byte (`registry.py`
`_SEGMENT`, `_WRN`, `parse_wrn`, and the SQL `canonical_wrn()` of migration 0035).

```python
from wolf_access_client import Wrn, WrnError, parse_wrn, is_canonical_wrn

task = Wrn.new("tasks", "task")          # a fresh UUID id (INT-OPEN-5)
same = parse_wrn(str(task))              # WrnError (a ValueError) if not canonical
assert same == task and same.resource_type == "tasks.task"
print(str(task))                         # str(Wrn) is the only formatter
```

| Name | What |
|---|---|
| `Wrn(service, type, id)` | A frozen, hashable value, checked when made: every `Wrn` is canonical. `.resource_type` = `<service>.<type>` (the registered type and AuthZEN `resource.type`), `.definition` = `<service>/<type>`. `repr` is `Wrn('wrn:…')`. A `Wrn` never equals a string. |
| `Wrn.new(service, type)` | A new WRN with a `uuid4` id. |
| `parse_wrn(value) -> Wrn` | Raises `WrnError` for anything not canonical, a non-string included. |
| `is_canonical_wrn(value) -> bool` | The Python twin of the SQL function. |
| `WrnError` | A `ValueError`; `.code` = `bad_arguments` (wolf-access's code); its message never repeats the value. |
| `CANONICAL_WRN_SQL` | `CREATE FUNCTION canonical_wrn(w text) …`, exactly migration 0035's. Run it once in a migration, then `CHECK (canonical_wrn(<column>))` on every WRN column. |
| `ACCESS_KINDS`, `PRINCIPAL_KINDS` | wolf-access's own types (`org`, `project`, `personal`, `user`, `agent`) and the principals (`user`, `agent`). |
| `wrn_conformance.CASES` | The conformance table: `WrnCase(value, parts, source, note)`, accept and refuse, including every case of wolf-access `tests/test_registry.py:38-70`. Run any other copy of the grammar over it. |

The grammar: `<service>` and `<type>` are 3 to 63 of `[a-z0-9_]`, starting with a letter, ending
with a letter or digit, without `__`; `<id>` is 1 to 512 of `[A-Za-z0-9._~-]`.
**Upper-case ids are accepted and kept**, as wolf-access does today; whether INT-B2's "lower
case" covers the id is open (wolf-access#331), and the library changes when the server does.

### The WRN literal check

INT-B3: "A linter rule refuses building WRN strings outside that library." The package installs
`wolf-access-wrn-lint`, which reports every string, bytes or f-string literal in `.py` files
that begins with `wrn:` (a hard-coded WRN, or one built with `+`, `%`, `.format` or an
f-string). Run it in CI:

```bash
wolf-access-wrn-lint src/ --exclude 'tests/fixtures/*'   # or: python -m wolf_access_client.wrn_lint
```

Exit 0 clean, 1 findings (`path:line:col: …`), 2 a path that does not exist. To let one
statement through, put `# wrn-ok` (optionally `# wrn-ok: why`) on any of its lines.
`find_wrn_literals(paths, exclude=())` is the same check for a test.

## The client at a glance

```python
from wolf_access_client import ACCESS_AUDIENCE, WolfAccessClient, Wrn

client = WolfAccessClient("https://wolf-access.railway.internal", credential, service="tasks")
```

| Call | wolf-access endpoint | Bearer | Returns |
|---|---|---|---|
| `register_schema(*, types, permissions, roles, principal_token=None)` | `PUT /v1/services/{service}/schema` | service; an operator's token to add a permission to an existing role (AC-9) | `Written(zedtoken)` |
| `create_resource(wrn, parent_wrn=None, *, name=None, principal_token=None)` | `POST /v1/resources` | service for a root; **the principal's token** under a parent (AC-3) | `Versioned(version, zedtoken)` |
| `get_resource(wrn)` | `GET /v1/resources/{wrn}` | service | `Resource(wrn, parent_wrn, name)` |
| `move_resource(wrn, parent_wrn, *, version)` | `PATCH /v1/resources/{wrn}` | service | `Versioned(version, zedtoken)` |
| `delete_resource(wrn, *, version)` | `DELETE /v1/resources/{wrn}?version=` | service | `Written(zedtoken)` |
| `reconcile(resources)` | `POST /v1/services/{service}/reconcile` | service | `Reconciled(added, changes, zedtoken)` |
| `exchange_token(subject, audience, *, client_wrn=None)` | `POST /v1/token` (RFC 8693, form) | service | `ExchangedToken` |
| `evaluation(*, subject, action, resource, client_wrn, end_to_end=False, consistency_token=None)` | `POST /access/v1/evaluation` | service | `Decision` |
| `evaluations(*, subject, client_wrn, items, semantic="execute_all", end_to_end=False, consistency_token=None)` | `POST /access/v1/evaluations` | service | `list[Decision]`, one per item |
| `search_resources(*, subject, action, resource_type, client_wrn, end_to_end=False, page_size=None)` | `POST /access/v1/search/resource` | service | iterator of `Wrn` |

Every WRN argument is a `Wrn` or its text (text is parsed first; a bad one raises `WrnError`
and nothing is sent). Every WRN in an answer is parsed: one that is not canonical is a
`WolfAccessResponseError`.

### Authentication (AC-10, AC-20, AC-22)

wolf-access's `gate()` takes a bearer token that is the service's credential, a JWT the service
signs (checked against its key set, `WOLFACCESS_SERVICE_JWKS`), or, on the calls wolf-access
makes "for a principal", the token `POST /v1/token` issued the service for that principal with
audience `access`.

- `service_credential` is the credential string, or a callable returning a fresh bearer token
  per request (a service-signed JWT).
- `principal_token=` (an `ExchangedToken` or its text) replaces it on the calls that name a
  principal: `create_resource` under a parent, and `register_schema` adding a permission to an
  existing role (an operator).

```python
token = client.exchange_token(Wrn("access", "user", user_id), ACCESS_AUDIENCE)
created = client.create_resource(Wrn.new("tasks", "task"), list_wrn, principal_token=token)
```

A token lives at most 60 seconds; exchange one per operation. It is a secret: it is kept out
of `repr` and `str`.

### The tree: synchronous writes (INT-D3, AC-6)

A create, a delete, and a move that removes access call wolf-access **before the service
commits**; if the call raises, do not commit. A create or move answers the resource's new
`version`; store it with the resource and pass it to the next `move_resource` or
`delete_resource`. A stale version is a `ConflictError`; so is deleting a resource that still
has children (AC-7) or grants. Under a parent, a refused create and a missing parent are both
`NotFoundError` (AC-15). A `WolfAccessUnavailable` on a write means the outcome is unknown:
`get_resource` tells what wolf-access holds, and `reconcile` repairs the rest.

### Reconcile (INT-D7, AC-14)

`reconcile(pairs)` sends the service's **full** list of `(wrn, parent_wrn)` (`parent_wrn` None
for a root). wolf-access adds what it lacks at once; every move and removal it finds waits for
an operator's approval and is answered in `changes` (`ReconcileChange(id, service, wrn, kind,
parent_wrn, found_at, approved_by, approved_at)`, `kind` `move` or `removal`). Grants are never
removed.

### Token exchange (INT-C5, AC-20)

`exchange_token(subject, audience, *, client_wrn=None)`: a token for the principal `subject`
(`wrn:access:user/<id>` or `wrn:access:agent/<id>`) to call `audience`. The principal must be
active and hold `<service>.use` and `<audience>.use` (AC-21). `client_wrn`, the connected app
(INT-F6), is the optional form parameter of wolf-access#334 (PR #339): with it the token carries
the claim `client_wrn`; a server without #339 ignores it. A refusal is a `TokenExchangeError`
whose `.error` is the RFC 6749 code (`invalid_request`, `invalid_target`, `invalid_client`,
`temporarily_unavailable`, …) and `.description` the server's text.

## Decisions (`/access/v1`, AuthZEN 1.0)

The subject is a principal's WRN, sent as `{"type": "user" | "agent", "id": <WRN>}`; a
resource is a WRN, sent as `{"type": "<service>.<type>", "id": <WRN>}`; the action is a
registered permission (`tasks.task.read`). Every decision names the connected app,
`client_wrn` (`context.client_wrn`), and whether it uses end-to-end encryption, `end_to_end`
(AC-19). The library never supplies the subject or the app: they are keyword-only and required.

```python
d = client.evaluation(subject=user, action="tasks.task.read", resource=task, client_wrn=app)
if d:            # d.allowed
    ...
```

`evaluations` checks up to 1000 `EvaluationItem(action, resource)` for one subject and app;
`semantic` is `execute_all`, `deny_on_first_deny` or `permit_on_first_permit`, and items after
the one that stopped the batch are `Decision(False, evaluated=False)`. An item wolf-access could
not evaluate is a deny whose `.error` is `{status, message}`. `search_resources` lists the WRNs
of one type the principal may act on (then filter in the service's own database, INT-F2), a page
at a time; there is never a total.

### Fail closed (INT-F4)

A real deny is a `Decision(allowed=False)` value, never an exception. Every failure to get a
decision raises `AccessUnavailable`: unreachable, timeout or TLS failure
(`WolfAccessUnavailable`), any status but 200 (`DecisionRefused`, which also carries `.status`
and `.retry_after`), or a malformed or misaligned answer (`WolfAccessResponseError`). Treat it as
deny.

### Consistency (AC-6)

The client keeps the consistency token (ZedToken) of the last write it made, or one passed to
`remember_zedtoken`, and sends it as `context.consistency_token` on every evaluation, so a check
made after a write is at least as fresh as it. Pass `consistency_token=` to use another. The
client keeps no decision between calls. (wolf-access's search reads no consistency token.)

### Errors

```
WolfAccessError                      every failure the client raises
├── AccessUnavailable                no decision was obtained: treat as deny
│   ├── WolfAccessUnavailable        unreachable, timeout, TLS failure, broken HTTP
│   ├── WolfAccessResponseError      a success status with a malformed or oversized body
│   └── DecisionRefused              any status but 200 from /access/v1
└── WolfAccessHTTPError              wolf-access answered with an error status
    ├── DecisionRefused
    ├── TokenExchangeError           RFC 6749 error from POST /v1/token (.error, .description)
    └── ProblemError                 RFC 9457 problem from /v1 (.name, .detail)
        ├── BadRequestError          400 bad_request
        ├── UnauthorizedError        401 unauthorized (.www_authenticate)
        ├── ForbiddenError           403 forbidden
        ├── NotFoundError            404 not_found
        ├── ConflictError            409 conflict
        └── UnavailableError         503 unavailable (.retry_after)
```

A problem name without a class (`internal`, or one a later wolf-access adds) is a plain
`ProblemError` with its `.name`. `.retryable` is true for transport failures, 408, 429 and 5xx.
No exception's `str` or `repr` carries text the server sent; `ProblemError.detail` and
`TokenExchangeError.description` hold it for callers that want it. A bad argument is a
`ValueError` / `TypeError` (`WrnError` for a WRN), raised before anything is sent.

## Transport

- `https://` for any host; plain `http://` is refused except for private hosts (loopback,
  `localhost`, `*.railway.internal`). Certificates are always verified, environment proxies are
  ignored and redirects are not followed, so the credential only goes to `base_url`'s host.
- **Timeout.** `timeout` (default 5 s, at most 3600 s) is a per-operation limit: each connect
  attempt, the send and each socket read wait at most `timeout`, and between reads of the
  response body the call stops once `timeout` has passed since it began. It does **not** bound
  the whole call: several connect attempts, slowly sent headers or slow chunked framing can make
  one call take several times `timeout`
  ([#2](https://github.com/Nice-Wolf-Studio/wolf-access-client/issues/2)). Such a call still
  ends in `WolfAccessUnavailable`, i.e. deny. A search makes one call per page. Name lookup
  uses the system resolver's own limits. Calls run on the caller's thread and start no threads.
- Body limits: 1 MiB for a decision or write answer, 4 MiB for a search page, 64 MiB for a
  reconcile answer.
- A credential or token must be an RFC 6750 bearer token (no spaces, line breaks or control
  characters; strip a trailing newline from a secret file). It is never logged, put in `repr`,
  or included in an error.

## Changes from 0.6.0

0.7.0 targets wolf-access `development` after PR #329 (the redesign to the spec), which removed
every route 0.6.0 called except the AuthZEN evaluation and resource search, and changed those.
It adds the shared WRN library (#50).

**New**

- `wolf_access_client.wrn`: `Wrn`, `Wrn.new`, `parse_wrn`, `is_canonical_wrn`, `WrnError`,
  `CANONICAL_WRN_SQL`, `ACCESS_KINDS`, `PRINCIPAL_KINDS`; `wolf_access_client.wrn_conformance`
  (`CASES`, `WrnCase`); `wolf_access_client.wrn_lint` and the console script
  `wolf-access-wrn-lint` (#50, INT-B3).
- `register_schema` (`PUT /v1/services/{service}/schema`) with `SchemaType`,
  `SchemaPermission`, `SchemaRole`.
- `get_resource`, `move_resource`, `reconcile`, `exchange_token`; `Versioned`, `Resource`,
  `Reconciled`, `ReconcileChange`, `ExchangedToken`; `TokenExchangeError`; `ACCESS_AUDIENCE`,
  `MAX_EVALUATIONS` exported.
- `service_credential` may be a callable (a service-signed JWT per call, AC-22);
  `principal_token=` on `create_resource` and `register_schema` (AC-3, AC-9).

**Breaking**

| 0.6.0 | 0.7.0 |
|---|---|
| `WolfAccessClient(url, credential, service=None)` | `service=` is required: the service's WRN segment. |
| `evaluation(user_id=, client_id=, action=, resource_type=, resource_id=, context=, zedtoken=)` | `evaluation(subject=<principal WRN>, action=<permission>, resource=<WRN>, client_wrn=<app WRN>, end_to_end=, consistency_token=)`. The wire body is `{type: user\|agent, id: WRN}` / `{type: <service>.<type>, id: WRN}` / `context.client_wrn`, `context.consistency_token` (was `context.client_id`, `context.zedtoken`). No free `context`. |
| `evaluations(user_id=, client_id=, items=[EvaluationItem(action, resource_type, resource_id)], context=, zedtoken=)` | `evaluations(subject=, client_wrn=, items=[EvaluationItem(action, resource)], end_to_end=, consistency_token=)` |
| `search_resources(user_id=, client_id=, action=, resource_type="svc/type", context=, zedtoken=)` → `ResourceRef`s | `search_resources(subject=, action=, resource_type="svc.type", client_wrn=, end_to_end=)` → `Wrn`s |
| `register_type(...)` (`PUT /v1/types/...`), `Permission`, `Parent` | `register_schema(...)`, `SchemaType`, `SchemaPermission`, `SchemaRole` |
| `create_resource(resource_type, resource_id, owner=, author=, parent=, private=, idempotency_key=)` → `Written \| Pending` | `create_resource(wrn, parent_wrn, name=, principal_token=)` → `Versioned` |
| `update_resource(...)`, `delete_resource(resource_type, resource_id)` | `move_resource(wrn, parent_wrn, version=)`, `delete_resource(wrn, version=)` |
| `Decision.signoff_required` | removed |

**Removed** (the routes are gone from wolf-access `development`): `search_resources_with_hints`,
`search_actions`, `search_subjects`, `request_access`, `create_signoff`, `consume_signoff`,
`set_topic_level`, `topic_examples`, `report_state`, `send_changes`, `changes_page`,
`changes_since`; the values `ResourceRef`, `PrincipalRef`, `Pending`, `RequestFiled`,
`SignoffFiled`, `Proposed`, `Hint`, `ResourceSearch`, `TopicExample`, `TOPIC_LEVELS`,
`TOPIC_SOURCES`, `TOPIC_CATEGORIES`, `Change`, `OutboxRow`, `ChangeResult`, `ChangesAnswer`,
`OutboxProgress`; the errors `OwnerRequiredError`, `OwnershipMismatchError`,
`HttpsRequiredError`, `RateLimitedError`, `IdempotencyKeyReusedError`,
`IdempotencyKeyInUseError`, `UseOutboxError`, `SeedNotVerified`.

**Removed: the cut-over outbox, relay and gate** (`wolf_access_client.outbox`, `.relay`,
`.mode`: `OutboxStore`, `SQLiteOutboxStore`, `PostgresOutboxStore`, `OutboxRelay`,
`RelayState`, `AccessMode`, `AccessGate`, `GateHealth`). They delivered lifecycle rows to
`POST /v1/services/{service}/changes` for the CUT-D1 side-by-side cut-over, which wolf-access
no longer serves; INT-L1 drops the side-by-side cut-over. Their replacement is the synchronous
tree calls (INT-D3) plus `reconcile` (INT-D7). INT-D6's repair outbox of `(operation, wrn,
parent_wrn, version)` is not shipped here: replaying a create under a parent needs the acting
principal's token (AC-3), which that row does not carry (wolf-access-client#51).

**Kept**: `canonical_json` and `diff_hash` (standalone; the sign-off calls they served are
gone), the transport and its rules, `Decision`, `Written`, `ProblemError` and its parsing.

**What breaks for consumers** (each pins an older tag, so nothing breaks until it moves the
pin; every one of these calls fails against wolf-access `development` regardless):

- **finOps** (`v0.3.1`; `finops/wolf_access.py`): `AccessGate`, `AccessMode`, `Change`,
  `OutboxRelay`, `PostgresOutboxStore`, `Permission`, `PrincipalRef`, `ResourceRef`,
  `register_type`, and `evaluation` / `evaluations` / `search_resources` with `user_id` /
  `client_id`; its migration 115 copies 0.3.1's `PostgresOutboxStore.DDL`.
- **WolfNotes** (`v0.6.0`; `wolfnotes/wolf_access.py`, `wolfnotes/lifecycle.py`): the gate,
  `OutboxRelay`, `SQLiteOutboxStore`, `Change`, `Parent`, `register_type(topics=)`,
  `create_signoff` / `consume_signoff`, `Decision.signoff_required`, and the decisions by
  `user_id`. `diff_hash` still imports.
- **wolf-notify** (`v0.2.0`): `evaluation(user_id=, client_id=, resource_type="org", …)`.

## Changes from 0.5.0

Topics and hints (wolf-access M7: WN-2..WN-8, WN-D3, SCP-D2, API-D3, API-D5; decisions
Q-T7, Q-T17..Q-T24).

- **`set_topic_level(type, id, topic, *, level, reason, source, category, user_id=None,
  client_id=None)`** sets one topic's level (`PUT /v1/resources/{type}/{id}/topics/{topic}`).
  `topic` is the topic child's resource id; `level` is `readable`, `hinted` or `hidden`
  (`needs_input` is never a level: ask the owner, WN-6) with a non-empty `reason` (WN-2);
  `category` is `people`, `money`, `health`, `legal` or `other` (WN-4). `source="ai"` is the
  service's classifier: a tightening applies (`Written` / `Pending`); a loosening, or a level
  above the scope's ceiling, answers `Proposed(proposal)` and waits for the owner (WN-5,
  WN-D1). `source="owner"` is the owner's answer and needs the gateway Caller's `user_id` and
  `client_id`; above the ceiling it is a 422 `above_ceiling` `ProblemError`. Levels are set
  directly, never through the outbox (Q-T7).
- **`Change.create_topic(topic, *, note, owner, author)`**: the topic child resource, created
  through the outbox under its note (Q-T7), with the note's owner and author. Its id must be
  opaque (no note id, no title): hints show it. Before a note's `delete` row, append a
  `delete` row for each of its topics (wolf-access does not cascade).
- **`search_resources_with_hints(...)`**: `search_resources`, every page fetched now, plus
  `context.hints` as `Hint(person, topic, hint)`. A hint carrying anything else (a title,
  content, a count, a score) is dropped (WN-8, WN-P2). Pass `hint.hint` to
  `request_access(hint=...)` to ask for that topic (SCP-D2).
- **`AccessGate.hints(hints)`**: the hints to show now. `on` shows them only while every
  outbox row is applied and the restart gate is open (a hint has no resource id, so a stale
  resource cannot be singled out, CUT-D1 (2)); `off` and `shadow` show none.
- **`topic_examples(limit=None)`**: the owner answers wolf-access keeps as classification
  examples (WN-7, WN-D8), as `TopicExample(topic, category, level, reason, decision, by, at,
  topic_type)`: `decision` is `set` (the owner's own level), `approved` or `denied` (an answer
  to an AI proposal; a `denied` example's level did not take effect).

## Changes from 0.4.0

Sign-off of a delegate's or agent's write (wolf-access CLI-D4 (ii), CLI-P6, DEL-S1).

- **`Decision.signoff_required`**: an allowed evaluation of a write made through a client bound
  to an agent whose delegation needs the principal's sign-off for that action
  (`context.signoff_required`). Hold the write.
- **`diff_hash(change)`** / **`canonical_json(value)`**: RFC 8785 (JCS) and its SHA-256 (lowercase
  hex) — the hash of exactly the change you will commit. JSON data only (dict with str keys,
  list, str, bool, None, int within ±(2**53 − 1), finite float); anything else is a
  `ValueError`.
- **`create_signoff(*, user_id, client_id, resource, action, diff_hash)`** → `SignoffFiled`:
  files the held write for sign-off; `user_id` / `client_id` are the gateway Caller's.
  wolf-access tells the signer (E18). `ConflictError` when the call is the person's own (an
  unbound client) or the write needs no sign-off; `ForbiddenError` when it is not allowed.
- **`consume_signoff(signoff, diff_hash)`**: just before committing, consume the approved
  sign-off with the same hash. Single use. A pending, rejected, expired or consumed sign-off,
  or a different hash (the change moved since the preview), is a `ConflictError`: do not
  commit.

```python
decision = client.evaluation(user_id=c.user_id, client_id=c.client_id, action="edit",
                             resource_type="wolfnotes/project", resource_id=project)
if decision.signoff_required:
    h = diff_hash(change)
    filed = client.create_signoff(user_id=c.user_id, client_id=c.client_id,
                                  resource=ResourceRef("wolfnotes/project", project),
                                  action="edit", diff_hash=h)
    hold(change, filed.signoff, h)          # later, once the signer approved:
    client.consume_signoff(filed.signoff, diff_hash(change))   # ConflictError -> do not commit
    commit(change)
```

## Changes from 0.3.1

- **`request_access(*, user_id, client_id, role, resource=None, scope=None, hint=None,
  reason=None, idempotency_key=None)`** files an access request for the person the service
  is serving (`POST /v1/requests`, REQ-D1). `user_id` and `client_id` are the gateway
  `Caller`'s, never an argument from a tool (API-D8, CLI-P1). The target is exactly one of
  `resource` (a `ResourceRef` of the service's own type, or a `PrincipalRef` of an org,
  relationship or project), `scope` (RFC 9396 `authorization_details`) or `hint`. wolf-access
  stores and decides the request: the service keeps no request or approval state. The answer,
  `RequestFiled(request, continue_token)`, is the same whether or not the target exists; the
  `continue_token` is the requester's single-use secret (kept out of `repr`). A resubmit inside
  the cooldown is a `ConflictError`; another service's type is a `ForbiddenError`. With
  `idempotency_key`, a repeat returns the same `request` with a fresh token.

## Changes from 0.3.0

- **`shadow` never changes an answer.** 0.3.0 left stale resources out of `filter` and
  `withheld` in `shadow`; now `shadow` keeps them (it answers exactly like `off`) and logs a
  `shadow_deny` for each with `reason=stale`. Only `on` leaves them out. The stale reason is
  `stale` everywhere (it was `outbox_unapplied`).
- `withheld(resources, *, user_id=None, client_id=None, action=None)`: the keywords fill in the
  `shadow_deny` record.
- A `Retry-After` longer than one hour is waited one hour (`MAX_RETRY_AFTER`); a huge one no
  longer kills the relay thread
  ([#33](https://github.com/Nice-Wolf-Studio/wolf-access-client/issues/33)).
- README: run exactly one relay per service
  ([#39](https://github.com/Nice-Wolf-Studio/wolf-access-client/issues/39)).

## Changes from 0.2.0

- **Breaking:** `AccessGate` in `shadow` and `on` needs `outbox=` (the service's
  `OutboxStore`) and `ancestors=` (its parent chain), so it never answers from stale data
  (CUT-D1 (2)). `off` is unchanged.
- **Breaking (type):** `Written.zedtoken` is `str | None`. An empty token from wolf-access is now
  `Written(None)` instead of a `WolfAccessResponseError`, and leaves `client.zedtoken` as it was
  ([#26](https://github.com/Nice-Wolf-Studio/wolf-access-client/issues/26)).
- New: `WolfAccessClient(..., service=)`, `report_state`, `send_changes`, `changes_page`,
  `changes_since`; `Change`, `OutboxRow`, `ChangeResult`, `ChangesAnswer`, `OutboxProgress`;
  `OutboxStore` with `PostgresOutboxStore` and `SQLiteOutboxStore`; `OutboxRelay` and
  `RelayState`; `AccessGate.withheld`, `AccessGate.health` and `GateHealth`
  ([#28](https://github.com/Nice-Wolf-Studio/wolf-access-client/issues/28)); `SeedNotVerified`;
  `UseOutboxError`.
- `IdempotencyKeyInUseError.retryable` is True
  ([#25](https://github.com/Nice-Wolf-Studio/wolf-access-client/issues/25)).
- Logged fields have control characters escaped
  ([#29](https://github.com/Nice-Wolf-Studio/wolf-access-client/issues/29)); a problem name
  that is not a plain `[a-z][a-z0-9_]{0,63}` is dropped
  ([#30](https://github.com/Nice-Wolf-Studio/wolf-access-client/issues/30)).

## Changes from 0.1.0

- **Breaking:** `evaluation` takes keyword-only `user_id=` and `client_id=` (was positional
  `subject_user_id` with `client_id` inside `context`), and `zedtoken=` (was
  `context["zedtoken"]`). `context` may no longer hold `client_id`, `user_id` or `zedtoken`.
- A non-200 decision answer is now `DecisionRefused`, still a `WolfAccessHTTPError`, and all
  decision failures share the base `AccessUnavailable`.
- New: `evaluations`, the three searches, the write API, typed problem errors, `AccessMode` and
  `AccessGate`. `Decision` gained `evaluated` and `.error`.

## Develop

```bash
pip install -e ".[test]"
python -m pytest -q
```

Tests run against an in-process fake wolf-access server that records every request, so they
check request shapes as well as answers. The WRN tests run every conformance case through
`parse_wrn`, the `Wrn` constructor and, on Postgres, the SQL `canonical_wrn` function: set
`TEST_DATABASE_URL` (an owner URL on a scratch server, e.g.
`postgresql://postgres@127.0.0.1:5432/postgres`) to run the SQL half, which is otherwise
skipped. CI runs everything on Python 3.10 and 3.12 against a throwaway Postgres
(`WAC_REQUIRE_POSTGRES=1` makes a skip a failure), scans the full git history for secrets
(TruffleHog), and on every release tag installs that tag in a clean environment with no
credentials. A release tag `vX.Y.Z` must match the `pyproject.toml` version `X.Y.Z`.

`tests/test_live.py` runs the client against a real wolf-access server (Postgres and SpiceDB
behind it). CI does not run it: wolf-access is private. Start one with
`scripts/live_wolf_access.py` (its docstring has the command: a wolf-access checkout on
`PYTHONPATH`, a scratch Postgres, `spicedb serve-testing`), then
`WAC_LIVE=<the JSON it wrote> python -m pytest tests/test_live.py`.
