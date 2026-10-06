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

Python 3.10+, standard library only.

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

- `subject_user_id` (the gateway `user_id`) and `context["client_id"]` (the gateway
  `client_id`) are required; without them nothing is sent and `ValueError` is raised.
- It returns `Decision(allowed, context)`. A deny is `Decision(allowed=False)`, a value, not
  an error.
- **Fail closed.** Every failure to get a decision raises a `WolfAccessError` subclass, so the
  caller can tell it apart from a deny and must treat it as deny:
  `WolfAccessUnavailable` (unreachable, timeout), `WolfAccessHTTPError` (non-2xx, `.status`;
  redirects are never followed, so the credential never goes to another host),
  `WolfAccessResponseError` (2xx without a boolean `decision`).
- **Consistency.** The client keeps no decision between calls. It carries the newest ZedToken
  it was given (`client.remember_zedtoken(token)` after a wolf-access write) as
  `context.zedtoken`, so a check after a write is at least as fresh as that write. A
  `zedtoken` passed in `context` wins.
- The credential is never logged, put in `repr`, or included in an error.
- Use `https://` over the public internet. Plain `http://` is accepted only for private
  networking (for example inside the same Railway project).

## Develop

```bash
pip install -e ".[test]"
python -m pytest -q
```

Tests run against an in-process fake wolf-access server. CI runs them on Python 3.10 and 3.12,
scans the full git history for secrets (TruffleHog), and on every release tag installs that tag
in a clean environment with no credentials. A release tag `vX.Y.Z` must match the
`pyproject.toml` version `X.Y.Z`.
