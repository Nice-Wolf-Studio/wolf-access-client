"""`WolfAccessClient`: ask wolf-access for an access decision.

`evaluation(...)` sends one AuthZEN 1.0 evaluation request to
`POST {base_url}/access/v1/evaluation` with the service's bearer credential:

    {"subject":  {"type": "user", "id": <gateway user_id>},
     "action":   {"name": <action>},
     "resource": {"type": <resource type>, "id": <resource id>},
     "context":  {"client_id": <gateway client_id>, "zedtoken"?: ..., ...}}

It returns a `Decision` for a 2xx AuthZEN response and raises a
`WolfAccessError` subclass for anything else (unreachable, timeout, non-2xx,
redirect, malformed body). The client keeps no decision between calls; it
only carries the newest ZedToken it was given (`remember_zedtoken`), so a
check after a write is at least as fresh as that write (CLI-D2).

Standard library only.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

from .errors import (
    WolfAccessHTTPError,
    WolfAccessResponseError,
    WolfAccessUnavailable,
)

EVALUATION_PATH = "/access/v1/evaluation"
DEFAULT_TIMEOUT = 5.0


@dataclass(frozen=True)
class Decision:
    """An AuthZEN decision. `context` holds what wolf-access returned under
    `context` (for example `reason_user`); it never holds a score."""

    allowed: bool
    context: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.allowed


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: it would resend the credential elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _nonblank(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


class WolfAccessClient:
    def __init__(self, base_url: str, service_credential: str, *,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        parts = urlsplit(base_url or "")
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("base_url must be an http:// or https:// URL")
        if not _nonblank(service_credential):
            raise ValueError("service_credential is required")
        self._base_url = base_url.rstrip("/")
        self._credential = service_credential
        self._timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)
        self._zedtoken: str | None = None

    def __repr__(self) -> str:
        return f"WolfAccessClient({self._base_url!r})"

    @property
    def zedtoken(self) -> str | None:
        """The newest ZedToken this client was given, sent with every check."""
        return self._zedtoken

    def remember_zedtoken(self, token: str) -> None:
        """Record the ZedToken a wolf-access write returned."""
        if not _nonblank(token):
            raise ValueError("token must be a non-empty string")
        self._zedtoken = token

    def evaluation(self, subject_user_id: str, action: str, resource_type: str,
                   resource_id: str, context: Mapping[str, Any] | None) -> Decision:
        """May `subject_user_id` do `action` on the resource? `context` must
        hold the call's gateway `client_id`."""
        if not _nonblank(subject_user_id):
            raise ValueError("subject_user_id is required (the gateway user_id)")
        ctx = dict(context or {})
        if not _nonblank(ctx.get("client_id")):
            raise ValueError("context['client_id'] is required (the gateway client_id)")
        if self._zedtoken and "zedtoken" not in ctx:
            ctx["zedtoken"] = self._zedtoken
        body = {
            "subject": {"type": "user", "id": subject_user_id},
            "action": {"name": action},
            "resource": {"type": resource_type, "id": resource_id},
            "context": ctx,
        }
        return _decision(self._post(EVALUATION_PATH, body))

    def _post(self, path: str, body: Mapping[str, Any]) -> bytes:
        request = urllib.request.Request(
            self._base_url + path, data=json.dumps(body).encode("utf-8"), method="POST",
            headers={"Authorization": f"Bearer {self._credential}",
                     "Content-Type": "application/json",
                     "Accept": "application/json"})
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            exc.close()
            raise WolfAccessHTTPError(exc.code) from None
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
            raise WolfAccessUnavailable(
                f"wolf-access is unreachable ({type(exc).__name__})") from None


def _decision(raw: bytes) -> Decision:
    try:
        data = json.loads(raw)
    except ValueError:
        raise WolfAccessResponseError("response is not JSON") from None
    if not isinstance(data, dict) or not isinstance(data.get("decision"), bool):
        raise WolfAccessResponseError("response has no boolean 'decision'")
    context = data.get("context", {})
    if not isinstance(context, dict):
        raise WolfAccessResponseError("response 'context' is not an object")
    return Decision(allowed=data["decision"], context=context)
