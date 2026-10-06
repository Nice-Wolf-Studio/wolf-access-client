# wolf-access-client

The Python client library for **wolf-access**, the Nice-Wolf-Studio authorization service.
A service embeds it to ask wolf-access whether the person behind a call may see or change one of
the service's resources, and to filter lists and search results down to what that person may see.

## Install

Install it by release tag, the same way as
[gateway-client](https://github.com/Nice-Wolf-Studio/gateway-client). No token or other credential
is needed:

```bash
pip install "git+https://github.com/Nice-Wolf-Studio/wolf-access-client@vX.Y.Z"
```

Replace `vX.Y.Z` with a release tag from this repo.

## What is public and what is not

- This repo is public. It holds the client code only: **no secrets and no data**.
- The wolf-access service and its specification are in a private repo. The client talks to a
  running wolf-access service with a per-service credential that the service supplies at run
  time; no credential is ever committed here.

## Use

Python 3.10+, standard library only. Version 0.1.0 has one call, `evaluation` (one check per
call, one connection per check). Batch evaluation and search, which list filtering needs, come
in a later version.

```python
from wolf_access_client import WolfAccessClient, WolfAccessError

client = WolfAccessClient("https://<wolf-access host>", service_credential)

def can_view(caller, note_id) -> bool:
    try:
        return client.evaluation(caller.user_id, "view", "wolfnotes/note", note_id,
                                 {"client_id": caller.client_id}).allowed
    except WolfAccessError:
        return False   # no answer = deny / "not found" (fail closed)
```

`evaluation(subject_user_id, action, resource_type, resource_id, context)` sends one
[AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html) evaluation request to
`POST {base_url}/access/v1/evaluation` with `Authorization: Bearer <service_credential>`:

```json
{"subject":  {"type": "user", "id": "<gateway user_id>"},
 "action":   {"name": "view"},
 "resource": {"type": "wolfnotes/note", "id": "<note id>"},
 "context":  {"client_id": "<gateway client_id>", "zedtoken": "<newest ZedToken, if any>"}}
```

- `subject_user_id` (the gateway `user_id`), `action`, `resource_type`, `resource_id` and
  `context["client_id"]` (the gateway `client_id`) are required non-empty strings, and
  `context` must be JSON-serializable; otherwise nothing is sent and `ValueError` is raised.
- It returns `Decision(allowed, context)`. A deny is `Decision(allowed=False)`, a value, not
  an error.
- **Fail closed.** Every failure to get a decision raises a `WolfAccessError` subclass, so the
  caller can tell it apart from a deny and must treat it as deny:
  `WolfAccessUnavailable` (unreachable, timeout, broken HTTP, TLS failure; the cause is
  chained), `WolfAccessHTTPError` (any status but 200, `.status`; redirects are never
  followed), `WolfAccessResponseError` (200 without a boolean `decision`, or a body over
  1 MiB).
- **Consistency.** The client keeps no decision between calls. It sends the last ZedToken
  recorded with `client.remember_zedtoken(token)` (after a wolf-access write) as
  `context.zedtoken`, so a check after that write is at least as fresh as it. A non-empty
  `zedtoken` string passed in `context` wins.
- **Transport.** `https://` for any host; plain `http://` is refused except for private hosts
  (loopback, `localhost`, `*.railway.internal`). Certificates are always verified, environment
  proxies are ignored and redirects are not followed, so the credential only goes to
  `base_url`'s host. `timeout` (default 5 s) bounds the whole call, name lookup to last byte.
- The credential must be an RFC 6750 bearer token (no spaces, line breaks or control
  characters; strip a trailing newline from a secret file). It is never logged, put in `repr`,
  or included in an error.
- One client holds one remembered ZedToken, the last one recorded (ZedTokens are opaque and
  cannot be ordered). When several threads write concurrently, pass each request's own token in
  `context["zedtoken"]`.

## Develop

```bash
pip install -e ".[test]"
python -m pytest -q
```

Tests run against an in-process fake wolf-access server. CI runs them on Python 3.10 and 3.12,
scans the full git history for secrets (TruffleHog), and on every release tag installs that tag
in a clean environment with no credentials. A release tag `vX.Y.Z` must match the
`pyproject.toml` version `X.Y.Z`.
