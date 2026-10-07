# wolf-access-client

The Python client library for **wolf-access**, the Nice-Wolf-Studio authorization service.
A service embeds it to ask wolf-access whether the person behind a call may see or change one of
the service's resources, to filter lists and search results down to what that person may see,
and to register its resource types and resources.

## Install

Install it by release tag, the same way as
[gateway-client](https://github.com/Nice-Wolf-Studio/gateway-client). No token or other credential
is needed:

```bash
pip install "git+https://github.com/Nice-Wolf-Studio/wolf-access-client@v0.2.0"
```

Python 3.10+, standard library only.

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
| `AccessMode`, `AccessGate` | (none: local) | the `off` / `shadow` / `on` switch (CUT-D1) |

## A consumer `PermissionProvider`

A service asks wolf-access through a small provider of its own. WolfNotes
(`wolfnotes/access.py`) and finOps (`finops/access.py`) already define the provider protocol and
their own mode handling; a provider for them only has to answer, and **raise when it cannot**,
which their gates treat as deny:

```python
from wolf_access_client import EvaluationItem, WolfAccessClient

NOTE = "wolfnotes/note"


class WolfAccessProvider:
    """WolfNotes' PermissionProvider, backed by wolf-access."""

    def __init__(self, client: WolfAccessClient) -> None:
        self._client = client

    def permitted_note_ids(self, user_id, client_id):
        # The list-filter (CLI-3): every page, or an exception. Never a partial set.
        return frozenset(ref.id for ref in self._client.search_resources(
            user_id=user_id, client_id=client_id, action="view", resource_type=NOTE))

    def can_view(self, user_id, client_id, note_id):
        return self._client.evaluation(
            user_id=user_id, client_id=client_id, action="view",
            resource_type=NOTE, resource_id=note_id).allowed

    def visible(self, user_id, client_id, note_ids):
        # Not part of the protocol: one call for up to 1000 candidates (e.g. search hits).
        note_ids = list(note_ids)
        decisions = self._client.evaluations(
            user_id=user_id, client_id=client_id,
            items=[EvaluationItem("view", NOTE, n) for n in note_ids])
        return [n for n, d in zip(note_ids, decisions) if d.allowed]


client = WolfAccessClient("https://<wolf-access host>", service_credential)
provider = WolfAccessProvider(client)
```

`user_id` and `client_id` are always the gateway `Caller`'s, taken from the frame of the call
being served, never from a tool argument (API-D8, CLI-P1). A `None` from a legacy frame is a
`ValueError` before anything is sent, so it fails closed too.

A service without a gate of its own uses `AccessGate`, which applies the mode for it:

```python
from wolf_access_client import AccessGate, AccessMode, WolfAccessClient

gate = AccessGate(AccessMode.from_env("myservice"),       # reads MYSERVICE_ACCESS_MODE
                  WolfAccessClient("https://<wolf-access host>", service_credential))

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
  decisions that follow.
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
| `idempotency_key_in_use` | 409 | `IdempotencyKeyInUseError` | no |

- A name this version has no class for arrives as a plain `ProblemError` with its `.name`.
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
└── WolfAccessHTTPError
    └── ProblemError
        └── OwnerRequiredError, ConflictError, UnavailableError, ...
```

## Enforcement mode (CUT-D1)

`AccessMode` is `off`, `shadow` or `on`, and `AccessGate(mode, client)` applies it:

| Mode | `check` / `filter` |
|---|---|
| `off` | Never calls the decision API. Allows everything (today's behaviour). |
| `shadow` | Calls; each deny is logged as `shadow_deny` (logger `wolf_access_client`, level WARNING, with `user_id`, `client_id`, `action`, `resource_type`, `resource_id` as record attributes) and allowed. With wolf-access unreachable the call proceeds (logged `access_unavailable`). |
| `on` | Enforced. A deny, and every failure to get an answer, is a deny. |

- `AccessMode.parse(value)` accepts exactly `off`, `shadow` or `on`; anything else is a
  `ValueError`. `AccessGate` parses its mode the same way, so an unknown mode is refused when the
  gate is built, and `shadow`/`on` need a client.
- `AccessMode.from_env("wolfnotes")` reads `WOLFNOTES_ACCESS_MODE`. Unset or empty is `off`
  (the CUT-S1 default); any other value that is not an exact mode name is a `ValueError`, so a
  typo never silently means `off`.
- `gate.filter(ids, ...)` asks in batches of 1000 and keeps the order; in `on`, if any batch
  gets no answer, it keeps none.
- A call with a missing `user_id` or `client_id` is logged as `invalid_request`: a deny in `on`,
  allowed in `shadow`, and nothing is sent.

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

## Changes from 0.1.0

- **Breaking:** `evaluation` takes keyword-only `user_id=` and `client_id=` (was positional
  `subject_user_id` with `client_id` inside `context`), and `zedtoken=` (was
  `context["zedtoken"]`). `context` may no longer hold `client_id`, `user_id` or `zedtoken`.
- A non-200 decision answer is now `DecisionRefused`, still a `WolfAccessHTTPError`, and all
  decision failures share the base `AccessUnavailable`.
- New: `evaluations`, the three searches, the write API, typed problem errors, `AccessMode` and
  `AccessGate`. `Decision` gained `evaluated` and `.error`.

## Not yet: wolf-access M1c

The CUT-D1 lifecycle outbox (`POST/GET /v1/services/{service}/changes`), intent checks
(`POST /v1/resources/{type}/{id}/intent`), ownership requests and feed
(`POST /v1/resources/{type}/{id}/ownership`, `GET /v1/services/{service}/ownership-changes`),
the start-up state report and the reconcile snapshot (`PUT /v1/services/{service}/state`,
`/snapshot`) arrive with wolf-access M1c. They will be methods on `WolfAccessClient` built on
the same transport and error parsing (`WolfAccessClient._request` and `_problem` in
`client.py`), and their problem names (`under_review`,
`use_outbox`, `behind`) already arrive as a `ProblemError` with that `.name`.
`AccessGate` is where the CUT-D1 (2) "no answer from stale data" and restart gates will plug in.

## Develop

```bash
pip install -e ".[test]"
python -m pytest -q
```

Tests run against an in-process fake wolf-access server that records every request, so they
check request shapes as well as answers. CI runs them on Python 3.10 and 3.12, scans the full git
history for secrets (TruffleHog), and on every release tag installs that tag in a clean
environment with no credentials. A release tag `vX.Y.Z` must match the `pyproject.toml` version
`X.Y.Z`.
