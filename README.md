# wolf-access-client

The Python client library for **wolf-access**, the Nice-Wolf-Studio authorization service.
A service embeds it to ask wolf-access whether the person behind a call may see or change one of
the service's resources, to filter lists and search results down to what that person may see,
to register its resource types and resources, and, for a service that existed before
wolf-access (WolfNotes, finOps), to cut over: a lifecycle outbox in the service's own database,
a relay that delivers it, and an `off` / `shadow` / `on` gate.

## Install

Install it by release tag, the same way as
[gateway-client](https://github.com/Nice-Wolf-Studio/gateway-client). No token or other credential
is needed:

```bash
pip install "git+https://github.com/Nice-Wolf-Studio/wolf-access-client@v0.5.0"
```

Python 3.10+, standard library only. The Postgres outbox store works over the DB-API driver
the service already uses (psycopg2 or psycopg 3); the library does not depend on one.

## What is public and what is not

- This repo is public. It holds the client code only: **no secrets and no data**.
- The wolf-access service and its specification are in a private repo. The client talks to a
  running wolf-access service with a per-service credential that the service supplies at run
  time; no credential is ever committed here.

## The API at a glance

| Call | wolf-access endpoint | Returns |
|---|---|---|
| `evaluation(...)` | `POST /access/v1/evaluation` | `Decision` |
| `evaluations(...)` | `POST /access/v1/evaluations` | `list[Decision]`, one per item |
| `search_resources(...)` | `POST /access/v1/search/resource` | iterator of `ResourceRef` |
| `search_actions(...)` | `POST /access/v1/search/action` | iterator of action names |
| `search_subjects(...)` | `POST /access/v1/search/subject` | iterator of gateway `user_id`s |
| `register_type(...)` | `PUT /v1/types/{service}/{type}` | `Written` or `Pending` |
| `create_resource(...)` | `POST /v1/resources` | `Written` or `Pending` |
| `update_resource(...)` | `PATCH /v1/resources/{type}/{id}` | `Written` or `Pending` |
| `delete_resource(...)` | `DELETE /v1/resources/{type}/{id}` | `Written` or `Pending` |
| `request_access(...)` | `POST /v1/requests` | `RequestFiled(request, continue_token)` |
| `create_signoff(...)` | `POST /v1/signoffs` | `SignoffFiled(signoff, status, expires_at)` |
| `consume_signoff(signoff, diff_hash)` | `POST /v1/signoffs/{id}/consume` | `None` (refused: `ConflictError`) |
| `report_state(mode, registration_start)` | `PUT /v1/services/{service}/state` | `None` |
| `send_changes(rows)` | `POST /v1/services/{service}/changes` | `ChangesAnswer` |
| `changes_page(after)` | `GET /v1/services/{service}/changes?after=n` | `ChangesAnswer` (one page, at most 1000 rows) |
| `changes_since(after)` | `GET …/changes?after=n`, every page | iterator of `ChangeResult`, oldest first |
| `OutboxStore.append(conn, change)` | (none: the service's own database) | `OutboxRow` with the next sequence number |
| `OutboxRelay` | the state report, then `POST …/changes` in sequence | `.state`: `ok`, `behind`, `refused`, `unavailable` |
| `AccessMode`, `AccessGate` | `/access/v1` (except in `off`) | the `off` / `shadow` / `on` switch (CUT-D1); `.health` |

The cut-over calls need the client's service name: `WolfAccessClient(url, credential,
service="wolfnotes")`. They are accepted only with that service's own credential.

## A consumer `PermissionProvider`

A service asks wolf-access through a small provider of its own. WolfNotes
(`wolfnotes/access.py`) and finOps (`finops/access.py`) already define the provider protocol and
their own mode handling; a provider for them only has to answer, and **raise when it cannot**,
which their gates treat as deny:

```python
from wolf_access_client import AccessGate, EvaluationItem, ResourceRef, WolfAccessClient

NOTE = "wolfnotes/note"


class WolfAccessProvider:
    """WolfNotes' PermissionProvider, backed by wolf-access."""

    def __init__(self, client: WolfAccessClient, gate: AccessGate) -> None:
        self._client = client
        self._gate = gate       # only for gate.withheld: WolfNotes applies its own mode

    def permitted_note_ids(self, user_id, client_id):
        # The list-filter (CLI-3): every page, or an exception. Never a partial set.
        refs = list(self._client.search_resources(
            user_id=user_id, client_id=client_id, action="view", resource_type=NOTE))
        held = self._gate.withheld(refs)    # no answer from stale data (CUT-D1 (2))
        return frozenset(ref.id for ref in refs if ref not in held)

    def can_view(self, user_id, client_id, note_id):
        if self._gate.withheld([ResourceRef(NOTE, note_id)]):
            return False
        return self._client.evaluation(
            user_id=user_id, client_id=client_id, action="view",
            resource_type=NOTE, resource_id=note_id).allowed

    def visible(self, user_id, client_id, note_ids):
        # Not part of the protocol: one call for up to 1000 candidates (e.g. search hits).
        held = self._gate.withheld([ResourceRef(NOTE, n) for n in note_ids])
        note_ids = [n for n in note_ids if ResourceRef(NOTE, n) not in held]
        if not note_ids:
            return []
        decisions = self._client.evaluations(
            user_id=user_id, client_id=client_id,
            items=[EvaluationItem("view", NOTE, n) for n in note_ids])
        return [n for n, d in zip(note_ids, decisions) if d.allowed]


client = WolfAccessClient("https://<wolf-access host>", service_credential,
                          service="wolfnotes")
provider = WolfAccessProvider(client, gate)   # gate: see "Cut-over" below
```

`user_id` and `client_id` are always the gateway `Caller`'s, taken from the frame of the call
being served, never from a tool argument (API-D8, CLI-P1). A `None` from a legacy frame is a
`ValueError` before anything is sent, so it fails closed too.

A service without a gate of its own uses `AccessGate`, which applies the mode for it (see
"Cut-over" below for the outbox and the parent chain it needs in `shadow` and `on`):

```python
from wolf_access_client import AccessGate, AccessMode, WolfAccessClient

gate = AccessGate(AccessMode.from_env("myservice"),       # reads MYSERVICE_ACCESS_MODE
                  WolfAccessClient("https://<wolf-access host>", service_credential,
                                   service="myservice"),
                  outbox=store, ancestors=lambda ref: ())

if not gate.check(user_id=caller.user_id, client_id=caller.client_id, action="view",
                  resource_type="myservice/thing", resource_id=thing_id):
    raise NotFound()          # a hidden resource looks exactly like a missing one (CLI-2)

shown = gate.filter(candidate_ids, user_id=caller.user_id, client_id=caller.client_id,
                    action="view", resource_type="myservice/thing")
```

## Decisions (`/access/v1`, AuthZEN 1.0)

Every decision call takes `user_id` (the gateway `user_id`) and `client_id` (the gateway
`client_id`) as **keyword-only, required** parameters. The library never supplies either.

- `evaluation(*, user_id, client_id, action, resource_type, resource_id, context=None,
  zedtoken=None) -> Decision`. A deny is `Decision(allowed=False)`, a value, not an error.
  `context` adds AuthZEN context keys (for example `review_case`); it may not carry
  `client_id`, `user_id` or `zedtoken`, which are parameters.
- `evaluations(*, user_id, client_id, items, semantic="execute_all", context=None,
  zedtoken=None) -> list[Decision]`. `items` is a list of 1 to 1000
  `EvaluationItem(action, resource_type, resource_id)`. The answer has one `Decision` per item,
  in order. `semantic` is `execute_all`, `deny_on_first_deny` or `permit_on_first_permit`;
  items after the one that stopped the batch are `Decision(allowed=False, evaluated=False)`.
  An item wolf-access could not evaluate is a deny whose `.error` is `{status, message}`.
  An answer that does not line up with the items is no answer (`WolfAccessResponseError`).
- `search_resources(*, user_id, client_id, action, resource_type, page_size=None, ...)` →
  iterator of `ResourceRef(type, id)`; `search_actions(*, user_id, client_id, resource_type,
  resource_id, ...)` → iterator of action names; `search_subjects(*, user_id, client_id,
  action, resource_type, resource_id, ...)` → iterator of the gateway `user_id`s holding
  `action` (asked for `user_id`, sent as `context.user_id`; wolf-access answers it only to a
  holder of `share`, and refuses 403 to one with `view` alone).
  - Each is lazy: a page is fetched (`page.limit` = `page_size`, 1 to 1000; wolf-access
    defaults to 100) only when the iterator needs it, following `page.next_token` until it is
    empty. **There is never a total**, and nothing to count.
  - A failure on any page raises `AccessUnavailable` from the iterator. Treat the whole result
    as failed: `list(...)` it inside your `try`.
  - Arguments are checked when the search is created, not at the first page.

### Fail closed (CLI-P2)

Every way a decision call can end without a decision raises **`AccessUnavailable`**, which the
caller treats as deny / "not found". It is never confused with a real deny:

| Cause | Raised |
|---|---|
| Unreachable, timeout, TLS failure, broken HTTP | `WolfAccessUnavailable` (cause chained) |
| A 200 that is malformed, misaligned, or over the size limit | `WolfAccessResponseError` |
| Any other status: 400, 401, 403, 429, 5xx, a redirect (never followed) | `DecisionRefused` (`.status`, `.retry_after`) |
| 409: the service reported a mode and its seed is not verified yet (CUT-D1) | `SeedNotVerified`, a `DecisionRefused` |

All three are subclasses of `AccessUnavailable`. AuthZEN error bodies are plain text and are not
kept: no exception carries text the server sent.

### Consistency (CLI-D2)

The client keeps no decision between calls, so a revoke takes effect at the next check. It keeps
the ZedToken of the last write it made (`client.zedtoken`) and sends it as `context.zedtoken`
(API-D4) on every decision, so a check after a write is at least as fresh as that write.
`remember_zedtoken(token)` records a token obtained elsewhere. One client holds one token, the
last one recorded (ZedTokens are opaque and cannot be ordered); when several threads write
concurrently, pass each request's own token as `zedtoken=`. wolf-access also evaluates every
check at least as fresh as its own newest relationship write, so a change made by someone else
(an MCP tool call, another service) is seen too.

## Writes (`/v1`, API-D3)

A service writes only its own types, named `<service>/<type>`.

```python
from wolf_access_client import (Parent, Pending, Permission, PrincipalRef, ResourceRef,
                                WolfAccessError, Written)

client.register_type("wolfnotes/note",
                     permissions=[Permission("comment", ["Editor", "Viewer"])],
                     parents=[Parent("folder", ["wolfnotes/folder"])],
                     topics=True)

result = client.create_resource("wolfnotes/note", note_id,
                                owner=PrincipalRef.user(caller.user_id),
                                author=caller.user_id,
                                parent=ResourceRef("wolfnotes/folder", folder_id),
                                idempotency_key=f"create-{note_id}")
if isinstance(result, Pending):
    ...   # committed; checks fail closed until its relationships are applied

client.update_resource("wolfnotes/note", note_id, parent=None)    # detach; or private=True
client.delete_resource("wolfnotes/note", note_id)                 # the id stays a tombstone
```

- `register_type(resource_type, *, permissions, parents=(), topics=False)`. `permissions` are
  `Permission(name, default_roles)`; the base permissions (`view`, `edit`, `share`, ...) exist
  on every type and are not registered. `default_roles` are built-in roles. `parents` are
  `Parent(relation, parent_types)`, the service's own types.
- `create_resource(resource_type, resource_id, *, owner, author, parent=None, private=None,
  idempotency_key=None)`. `owner` is `PrincipalRef.user(<user_id>)` or
  `PrincipalRef("org" | "relationship" | "project" | "agent", <principal id>)`; `author` is the
  gateway `user_id` of the person filing it. `parent` and `private` are sent only when given.
- `update_resource(resource_type, resource_id, *, parent=..., private=...)` sends only the
  fields given (at least one); `parent=None` detaches. Owner changes never go here (OWN-5,
  OWN-D4).
- `delete_resource(resource_type, resource_id)`. Creating the id again is a `ConflictError`.
- Resource ids are percent-encoded in the path, so any string id works.

Each write returns:

- `Written(zedtoken)` for 200 or 201. The client records the token and sends it with the
  decisions that follow. wolf-access answers an empty token while it holds no watermark yet:
  that is `Written(None)`, the write happened, and the client keeps the token it already had.
- `Pending()` for 202 `{"status": "pending"}`: committed, but its relationships are not applied
  yet, and wolf-access fails every check closed until they are.

**`Idempotency-Key`** (`create_resource(..., idempotency_key=...)`, sent as a header on the
`POST`): a repeat with the same key and body returns the first answer; the same key with a
different body is `IdempotencyKeyReusedError`, and one still running is
`IdempotencyKeyInUseError`. The key is yours to choose and to reuse on a retry; the library
never makes one up. It must be printable ASCII without leading or trailing spaces.

### Errors (RFC 9457 problem details)

A refusal from `/v1` raises a `ProblemError` subclass chosen by the problem `type`
`urn:wolfaccess:problem:<name>`. Each carries `.status`, `.name`, `.type`, `.title`, `.detail`
(the server's explanation; never in `str(exc)`), `.retry_after` (seconds, from `Retry-After`)
and `.retryable`.

| Name | Status | Exception | Retryable |
|---|---|---|---|
| `owner_required` | 422 | `OwnerRequiredError` | no |
| `ownership_mismatch` | 422 | `OwnershipMismatchError` | no |
| `conflict` | 409 | `ConflictError` | no |
| `forbidden` | 403 | `ForbiddenError` | no |
| `not_found` | 404 | `NotFoundError` | no |
| `bad_request` | 400 | `BadRequestError` | no |
| `unauthorized` | 401 | `UnauthorizedError` (`.www_authenticate`) | no |
| `https_required` | 403 | `HttpsRequiredError` | no |
| `rate_limited` | 429 | `RateLimitedError` | yes, after `.retry_after` |
| `unavailable` | 503 | `UnavailableError` | yes, after `.retry_after`; nothing was stored |
| `idempotency_key_reused` | 422 | `IdempotencyKeyReusedError` | no |
| `idempotency_key_in_use` | 409 | `IdempotencyKeyInUseError` | yes: the first request is still running; once it ends, the same request gets its answer |
| `use_outbox` | 409 | `UseOutboxError` | no: the service has a mode; change resources through its outbox |

- A name this version has no class for arrives as a plain `ProblemError` with its `.name`.
  A name is kept only if it is a plain `[a-z][a-z0-9_]{0,63}`; anything else is `.name = None`,
  so the server never controls `str(exc)`.
- An error that is not a problem document (an edge proxy's HTML page) is a plain
  `WolfAccessHTTPError`.
- A write that got no answer at all is `WolfAccessUnavailable`: its outcome is unknown, and it
  is retryable (with an `Idempotency-Key` on a create, a retry is safe).
- `retryable` is true for transport failures, 408, 429 and 5xx: `except WolfAccessError as e:
  if e.retryable: ...`.

```
WolfAccessError
├── AccessUnavailable            no decision: treat as deny
│   ├── WolfAccessUnavailable
│   ├── WolfAccessResponseError
│   └── DecisionRefused          (also a WolfAccessHTTPError)
│       └── SeedNotVerified      409 from the seed gate
└── WolfAccessHTTPError
    └── ProblemError
        └── OwnerRequiredError, ConflictError, UseOutboxError, UnavailableError, ...
```

## Cut-over: integrating a service that existed before wolf-access (CUT-D1)

WolfNotes and finOps keep their own records and add wolf-access underneath them. Three pieces do
that, and the service wires all three at start-up:

| Piece | What it does | Runs in |
|---|---|---|
| **Outbox** (`OutboxStore`) | Every resource lifecycle change is written to the service's own database, in the same transaction as the change, with the next number of a gapless per-service sequence. | every mode, `off` included |
| **Relay** (`OutboxRelay`) | Reports the service's state at start-up, then sends the outbox to wolf-access in sequence and records each row's result. | every mode, `off` included |
| **Gate** (`AccessGate`) | Applies the mode to decisions, and gives no answer from stale data. | the decision path |

### 1. The outbox: what to append, and when

Append a `Change` for **every** lifecycle change of one of the service's own resources:

| The service... | Append |
|---|---|
| files a new resource | `Change.create(ref, owner=PrincipalRef.user(caller.user_id), author=caller.user_id, parent=..., private=...)` |
| moves or re-parents it | `Change.move(ref, parent=new_parent_ref)` (`parent=None`: to the root) |
| makes it private or public | `Change.set_private(ref, True)` |
| deletes it (or confirms a purge) | `Change.delete(ref)` |

`ref` is `ResourceRef("<service>/<type>", id)`, the same id the service uses on decisions.
`owner` and `author` are the ones the filing settled (OWN-2, OWN-3, OWN-D5), never a tool
argument. Owner changes never go in the outbox: they are made in wolf-access (CUT-D1 (4),
wolf-access M1c-3).

**The transaction boundary.** `append` writes through the connection you pass, inside the
transaction you already have open, and never commits. Commit (or roll back) the change and its
outbox row together:

```python
import sqlite3
from wolf_access_client import Change, PrincipalRef, ResourceRef, SQLiteOutboxStore

store = SQLiteOutboxStore(lambda: sqlite3.connect(DB_PATH, timeout=30), "wolfnotes")
store.create_schema()                       # once; or put store.DDL in your migrations

def move_note(conn, note_id, folder_id, caller):
    with conn:                              # one transaction: both or neither
        conn.execute("UPDATE notes SET folder_id = ? WHERE id = ?", (folder_id, note_id))
        store.append(conn, Change.move(ResourceRef("wolfnotes/note", note_id),
                                       parent=ResourceRef("wolfnotes/folder", folder_id)))
    relay.wake()                            # optional: send it now, not at the next poll
```

```python
import psycopg2
from wolf_access_client import Change, PostgresOutboxStore, ResourceRef

store = PostgresOutboxStore(lambda: psycopg2.connect(DSN), "finops")

with conn:                                  # psycopg2: commit on success, roll back on error
    with conn.cursor() as cur:
        cur.execute("DELETE FROM accounts WHERE id = %s", (account_id,))
        store.append(cur, Change.delete(ResourceRef("finops/account", account_id)))
```

- A rolled-back transaction removes the row and gives its number back: the sequence stays
  gapless. Concurrent transactions queue on the service's sequence row until each commits, so
  rows always commit in sequence order.
- A `Change` is checked when it is built (a create needs `owner` and `author`, a move needs
  `parent`, a `private` change needs the flag), and `append` refuses another service's type, so
  a change wolf-access could only refuse for its shape never enters the sequence.
- Never edit or delete outbox rows by hand: the sequence is the contract with wolf-access.

**The tables.** `create_schema()` creates them if missing; to manage them in your own
migrations, use `PostgresOutboxStore.DDL` / `SQLiteOutboxStore.DDL`. On Postgres:

```sql
CREATE TABLE IF NOT EXISTS wolf_access_outbox_state (
    service            text        PRIMARY KEY,
    last_sequence      bigint      NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    applied_through    bigint      NOT NULL DEFAULT 0 CHECK (applied_through >= 0),
    registration_start timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS wolf_access_outbox (
    service       text        NOT NULL REFERENCES wolf_access_outbox_state (service),
    sequence      bigint      NOT NULL CHECK (sequence >= 1),
    change_id     text        NOT NULL,
    action        text        NOT NULL,
    resource_type text        NOT NULL,
    resource_id   text        NOT NULL,
    body          jsonb       NOT NULL,     -- the row exactly as it is sent
    status        text        NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'held', 'refused', 'applied', 'resolved')),
    reason        text,                     -- wolf-access's reason for held / refused
    created_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    answered_at   timestamptz,
    PRIMARY KEY (service, sequence),
    UNIQUE (service, change_id)
);
CREATE INDEX IF NOT EXISTS wolf_access_outbox_resource
    ON wolf_access_outbox (service, resource_type, resource_id);
```

`wolf_access_outbox_state` has one row per service: the sequence counter, `applied_through`
(every row up to it is applied in wolf-access) and the **registration start**, the moment the
service first ran the library (CUT-D1), recorded once.

A store of your own implements `OutboxStore`: `append(conn, change, *, change_id=None)`,
`unapplied_rows(limit)`, `record(answer)`, `unapplied(resources)`, `progress()` and
`registration_start()`, with the same gapless and transactional guarantees.

### 2. The relay: a background task

```python
from wolf_access_client import AccessMode, OutboxRelay, WolfAccessClient

mode = AccessMode.from_env("wolfnotes")                     # WOLFNOTES_ACCESS_MODE
client = WolfAccessClient(WOLF_ACCESS_URL, credential, service="wolfnotes")
relay = OutboxRelay(client, store, mode=mode)
relay.start()                                               # a daemon thread
...
relay.stop(timeout=10)                                      # at shutdown
```

In an asyncio service, run it on a worker thread instead: `task =
asyncio.create_task(asyncio.to_thread(relay.run_forever))`, and `relay.stop()` at shutdown.
Run **exactly one** relay per service. Every row is idempotent on wolf-access's side, but two
relays recording into one store can record answers out of order and hide a dead letter
([#39](https://github.com/Nice-Wolf-Studio/wolf-access-client/issues/39)).

What it does, step by step:

1. **State report** (CUT-D1, CUT-S1): `PUT /v1/services/{service}/state` with the mode and the
   store's registration start, at every start-up, in every mode, retried until it succeeds.
   From the first report on, wolf-access refuses the service's direct `POST`/`PATCH`/`DELETE
   /v1/resources` (`UseOutboxError`) and answers its decisions only once its seed is verified.
2. **Delivery in sequence**: the unapplied rows from the head of the sequence, at most 500 per
   `POST`, and every row's result recorded in the store. A row wolf-access already applied is
   answered with its stored result and changes nothing, so sending again is always safe, also
   across restarts.
3. **Held** rows (a resource wolf-access does not know yet waits for the seed import; a row with
   a gap before it waits for the gap) are sent again every `held_interval` (30 s).
4. **Refused** rows are dead-lettered: the row stays at the head, every later row waits behind
   it, an ERROR is logged once (`event=outbox_refused`, with the sequence and wolf-access's
   reason) and `relay.state` is `refused`. It is never sent again on its own. Fix the cause,
   then call `relay.retry_refused()` (one more delivery). Meanwhile the relay polls `GET
   …/changes` every `refused_interval` (60 s), so a row reconcile resolves is picked up.
5. **Failures**: on 408, 429, 5xx, a network error or a malformed answer it backs off
   exponentially with jitter (1 s up to 300 s) and never retries before a `Retry-After`
   (a `Retry-After` longer than one hour is capped at one hour, `MAX_RETRY_AFTER`). Any
   other refusal (a wrong credential or service name) waits 300 s and is logged as an error;
   the rows are kept, so fixing the configuration needs no restart.

`relay.wake()` runs the next step now (call it after a commit); a backoff or `Retry-After` still
holds. With nothing to send the relay checks the store every `idle_interval` (2 s).

### 3. The gate

```python
from wolf_access_client import AccessGate, ResourceRef

def parent_chain(ref):                      # the service's own parents, nearest first
    folder = folder_of(ref.id)              # your database
    return [ResourceRef("wolfnotes/folder", f) for f in folder_and_its_ancestors(folder)]

gate = AccessGate(mode, client, outbox=store, ancestors=parent_chain)
```

`shadow` and `on` need `outbox=` and `ancestors=` (for types without parents: `lambda ref: ()`);
`off` needs neither and never reads the outbox.

| Mode | `check` / `filter` |
|---|---|
| `off` | Never calls the decision API and never reads the outbox. Allows everything (today's behaviour). |
| `shadow` | **Never changes an answer**: answers exactly like `off`, and logs what `on` would do. Each check or filter entry `on` would deny is logged as `shadow_deny` (logger `wolf_access_client`, level WARNING, with `user_id`, `client_id`, `action`, `resource_type`, `resource_id` and `reason` as record attributes: `decision` for a deny from wolf-access, `stale` for stale data, below). With no answer (wolf-access unreachable, the seed not verified) the call proceeds. |
| `on` | Enforced. A deny, and every failure to get an answer, is a deny. |

**No answer from stale data** (CUT-D1 (2)). While a resource, or any resource in its parent
chain, has an outbox row wolf-access has not applied (not sent yet, held, or dead-lettered), the
gate does not ask wolf-access about it. In `on`, a `check` on it denies and `filter` leaves it
out. In `shadow` the answer is unchanged (allowed, kept) and it is logged as `shadow_deny` with
`reason=stale`. The parent chain is read only while some row is unapplied.

**Restart gate** (`on` only). After start-up, every check denies and every `filter` is empty
until wolf-access has applied every row written before start-up and none is dead-lettered. Then
the gate opens and stays open.

**The seed gate.** Until the service's seed is verified, wolf-access refuses its decisions with
409 (`SeedNotVerified`, logged as `seed_not_verified`): `on` denies, `shadow` blocks nothing.

**A service with a gate of its own** (WolfNotes' and finOps' `access.py`) keeps its own mode
handling and asks this gate which resources to withhold:

```python
refs = [ResourceRef("wolfnotes/note", n) for n in permitted_ids]
held = gate.withheld(refs, user_id=caller.user_id, client_id=caller.client_id, action="view")
permitted_ids = [r.id for r in refs if r not in held]
```

In `on`, `withheld` holds the stale resources, every resource during the restart gate, and every
resource when the outbox cannot be read. In `shadow` it is always empty (shadow never changes an
answer) and logs `shadow_deny reason=stale` for each resource `on` would hold for stale data; the
`user_id`, `client_id` and `action` keywords only fill in that log record. In `off` it is always
empty and the outbox is not read.

- `AccessMode.parse(value)` accepts exactly `off`, `shadow` or `on`; anything else is a
  `ValueError`. `AccessGate` parses its mode the same way, so an unknown mode is refused when the
  gate is built.
- `AccessMode.from_env("wolfnotes")` reads `WOLFNOTES_ACCESS_MODE`. Unset or empty is `off`
  (the CUT-S1 default); any other value that is not an exact mode name is a `ValueError`, so a
  typo never silently means `off`.
- `gate.filter(ids, ...)` asks in batches of 1000 and keeps the order; in `on`, if any batch
  gets no answer, it keeps none.
- A call with a missing `user_id` or `client_id` is logged as `invalid_request`: a deny in `on`,
  allowed in `shadow`, and nothing is sent.
- Every logged field has its control characters escaped (`\x0a` for a line break), so no
  request field can forge a log line; the record attributes keep the raw values.

### 4. `/health`

Both report in the body; the service's `/health` keeps answering HTTP 200:

```python
from wolf_access_client import RelayState

async def health(request):
    gate_health = gate.health                   # GateHealth: never raises
    outbox = relay.state                        # RelayState: never raises
    degraded = gate_health.status != "ok" or outbox is not RelayState.OK
    return JSONResponse({"status": "degraded" if degraded else "ok",
                         "access": gate_health.as_dict(), "outbox": outbox.value})
```

| `gate.health` | Meaning |
|---|---|
| `{"status": "ok"}` | the last decision call was answered |
| `degraded`, `unavailable` | the last decision call got no answer (wolf-access unreachable or erroring) |
| `degraded`, `seed_not_verified` | wolf-access answers no decision until the seed is verified |
| `degraded`, `outbox_error` | the outbox store or the parent chain could not be read |
| `degraded`, `restart_gate` | `on`, after a restart, waiting for the rows written before start-up |

| `relay.state` | Meaning |
|---|---|
| `ok` | the state is reported and every row is applied |
| `behind` | rows (or the state report) still to deliver, or held |
| `refused` | a row is dead-lettered: an operator must fix its cause and call `retry_refused()` |
| `unavailable` | wolf-access or the store could not be reached on the last attempt |

### 5. Debugging and reconcile

`client.changes_since(after)` iterates wolf-access's result for every row after `after`, oldest
first (`GET …/changes`, a page of up to 1000 at a time); `client.changes_page(after)` is one page
with `applied_through`. `store.unapplied_rows(n)` and `store.progress()` show the local side.

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
- Body limits: 1 MiB for a decision or write answer, 4 MiB for a search page.
- The credential must be an RFC 6750 bearer token (no spaces, line breaks or control
  characters; strip a trailing newline from a secret file). It is never logged, put in `repr`,
  or included in an error.

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

## Seams: what arrives with wolf-access M1c-2 and M1c-3

These are not built yet; each has a named place to plug in, on the same transport and error
parsing (`WolfAccessClient._request` and `_problem` in `client.py`).

| Seam | Spec | Where it plugs in |
|---|---|---|
| **Intent tokens** (M1c-2): `POST /v1/resources/{type}/{id}/intent` before committing a move, `private` change or delete; the granted token goes in the outbox row | CUT-D1 (3) | a `WolfAccessClient.request_intent(...)` method; the token is already carried by `Change.move/set_private/delete(..., intent=token)` and sent as the row's `intent`. Until then wolf-access refuses such a row for a resource owned by an org, relationship or project. |
| **Ownership requests** (M1c-3): `POST /v1/resources/{type}/{id}/ownership`, answered 409 `behind` until wolf-access has applied `after_sequence` | CUT-D1 (4) | a `WolfAccessClient` method taking `after_sequence` from `store.progress().last_sequence`; `behind` and `under_review` already arrive as a `ProblemError` with that `.name`. |
| **Ownership feed and acknowledgements** (M1c-3): `GET /v1/services/{service}/ownership-changes?after=<cursor>`, applied in feed order with an `ack_ownership` outbox row in the same transaction | CUT-D1 (4) | the action `ack_ownership` is reserved (`Change` refuses it today) and the row's `entry` field is not sent yet; the feed poller will live beside `OutboxRelay`, and the cursor and pre-entry records beside the outbox tables. |
| **Hints** on WolfNotes searches | CUT-D1 (2), WN-8 | Not read yet ([#31](https://github.com/Nice-Wolf-Studio/wolf-access-client/issues/31)): the library returns no hint in any mode. When they arrive: `shadow` returns none (it answers exactly like `off`, which makes no decision call); `on` drops every hint while `store.progress()` shows any unapplied row (`applied_through < last_sequence`) and during the restart gate. |
| **Reconcile snapshot**: `PUT /v1/services/{service}/snapshot` | CUT-D1 (5) | tagged with `store.progress().last_sequence`; `changes_since` shows what reconcile resolved. |

## Develop

```bash
pip install -e ".[test]"
python -m pytest -q
```

Tests run against an in-process fake wolf-access server that records every request, so they
check request shapes as well as answers; its cut-over intake follows wolf-access's own rules
(rows applied in sequence, a gap held, a replay answered with its stored result, a refused row
dead-lettered). The outbox store tests run on SQLite and on Postgres: set
`TEST_DATABASE_URL` (an owner URL on a scratch server, e.g.
`postgresql://postgres@127.0.0.1:5432/postgres`) to run the Postgres half, which is otherwise
skipped. CI runs everything on Python 3.10 and 3.12 against a throwaway Postgres
(`WAC_REQUIRE_POSTGRES=1` makes a skip a failure), scans the full git history for secrets
(TruffleHog), and on every release tag installs that tag in a clean environment with no
credentials. A release tag `vX.Y.Z` must match the `pyproject.toml` version `X.Y.Z`.
