"""`WolfAccessClient`: ask wolf-access for an access decision.

`evaluation(...)` sends one AuthZEN 1.0 evaluation request to
`POST {base_url}/access/v1/evaluation` with the service's bearer credential:

    {"subject":  {"type": "user", "id": <gateway user_id>},
     "action":   {"name": <action>},
     "resource": {"type": <resource type>, "id": <resource id>},
     "context":  {"client_id": <gateway client_id>, "zedtoken"?: ..., ...}}

It returns a `Decision` for a 2xx AuthZEN response and raises a
`WolfAccessError` subclass for anything else (unreachable, timeout, broken
HTTP, non-2xx, redirect, malformed body). The client keeps no decision
between calls; it only carries the newest ZedToken it was given
(`remember_zedtoken`), so a check after a write is at least as fresh as that
write (CLI-D2).

Transport rules: `https://` for any host, `http://` only for private hosts
(loopback, `localhost`, `*.railway.internal`; spec API-D1); environment
proxies are ignored and redirects are never followed, so the credential only
ever goes to `base_url`'s host. `timeout` bounds the whole call.

Standard library only.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import math
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlsplit

from .errors import (
    WolfAccessHTTPError,
    WolfAccessResponseError,
    WolfAccessUnavailable,
)

EVALUATION_PATH = "/access/v1/evaluation"
DEFAULT_TIMEOUT = 5.0
_CHUNK = 65536
# RFC 6750 section 2.1 b64token: what a bearer credential may contain.
_BEARER = re.compile(r"[A-Za-z0-9\-._~+/]+=*")
_PRIVATE_SUFFIX = ".railway.internal"


@dataclass(frozen=True)
class Decision:
    """An AuthZEN decision. `context` (read-only) holds what wolf-access
    returned under `context`, for example `reason_user`; never a score."""

    allowed: bool
    context: Mapping[str, Any] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "context", MappingProxyType(dict(self.context)))

    def __bool__(self) -> bool:
        return self.allowed


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: it would resend the credential elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _nonblank(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _private_host(host: str) -> bool:
    if host == "localhost" or host.endswith(_PRIVATE_SUFFIX):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check_base_url(base_url: Any) -> str:
    if not isinstance(base_url, str):
        raise ValueError("base_url must be a string")
    parts = urlsplit(base_url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("base_url must be an http:// or https:// URL")
    if parts.query or parts.fragment or "@" in parts.netloc:
        raise ValueError("base_url must not carry a query, fragment or user info")
    try:
        parts.port
    except ValueError:
        raise ValueError("base_url has an invalid port") from None
    if parts.scheme == "http" and not _private_host(parts.hostname):
        raise ValueError("plain http:// is allowed only for private hosts; use https://")
    return base_url.rstrip("/")


def _check_timeout(timeout: Any) -> float:
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("timeout must be a positive number of seconds")
    return float(timeout)


class WolfAccessClient:
    def __init__(self, base_url: str, service_credential: str, *,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        self._base_url = _check_base_url(base_url)
        if not isinstance(service_credential, str) or not _BEARER.fullmatch(
                service_credential):
            raise ValueError("service_credential must be a bearer token (RFC 6750 "
                             "b64token: no spaces, line breaks or control characters)")
        self._credential = service_credential
        self._timeout = _check_timeout(timeout)
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                   _NoRedirect)
        self._zedtoken: str | None = None

    def __repr__(self) -> str:
        return f"WolfAccessClient({self._base_url!r})"

    @property
    def zedtoken(self) -> str | None:
        """The newest ZedToken this client was given, sent with every check."""
        return self._zedtoken

    def remember_zedtoken(self, token: str) -> None:
        """Record the ZedToken a wolf-access write returned. The client holds
        one token; the last one recorded is sent."""
        if not _nonblank(token):
            raise ValueError("token must be a non-empty string")
        self._zedtoken = token

    def evaluation(self, subject_user_id: str, action: str, resource_type: str,
                   resource_id: str, context: Mapping[str, Any] | None) -> Decision:
        """May `subject_user_id` do `action` on the resource? `context` must
        hold the call's gateway `client_id`."""
        for name, value in (("subject_user_id", subject_user_id), ("action", action),
                            ("resource_type", resource_type), ("resource_id", resource_id)):
            if not _nonblank(value):
                raise ValueError(f"{name} must be a non-empty string")
        ctx = dict(context or {})
        if not _nonblank(ctx.get("client_id")):
            raise ValueError("context['client_id'] is required (the gateway client_id)")
        if not _nonblank(ctx.get("zedtoken")):
            ctx.pop("zedtoken", None)
            if self._zedtoken:
                ctx["zedtoken"] = self._zedtoken
        body = {
            "subject": {"type": "user", "id": subject_user_id},
            "action": {"name": action},
            "resource": {"type": resource_type, "id": resource_id},
            "context": ctx,
        }
        return _decision(self._post(EVALUATION_PATH, body))

    def _post(self, path: str, body: Mapping[str, Any]) -> bytes:
        deadline = time.monotonic() + self._timeout
        request = urllib.request.Request(
            self._base_url + path, data=json.dumps(body).encode("utf-8"), method="POST",
            headers={"Authorization": f"Bearer {self._credential}",
                     "Content-Type": "application/json",
                     "Accept": "application/json"})
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                chunks = []
                while True:
                    if time.monotonic() > deadline:
                        raise TimeoutError("deadline passed")
                    chunk = response.read1(_CHUNK)
                    if not chunk:
                        break
                    chunks.append(chunk)
                if getattr(response, "length", None):  # closed before Content-Length
                    raise http.client.IncompleteRead(b"".join(chunks), response.length)
                return b"".join(chunks)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise WolfAccessHTTPError(exc.code) from None
        except (urllib.error.URLError, http.client.HTTPException, OSError,
                ValueError) as exc:
            # socket.timeout and TimeoutError are OSError subclasses.
            raise WolfAccessUnavailable(
                f"no answer from wolf-access ({type(exc).__name__})") from None


def _decision(raw: bytes) -> Decision:
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        raise WolfAccessResponseError("response is not JSON") from None
    if not isinstance(data, dict) or not isinstance(data.get("decision"), bool):
        raise WolfAccessResponseError("response has no boolean 'decision'")
    context = data.get("context")
    if context is None:
        context = {}
    if not isinstance(context, dict):
        raise WolfAccessResponseError("response 'context' is not an object")
    return Decision(allowed=data["decision"], context=context)
