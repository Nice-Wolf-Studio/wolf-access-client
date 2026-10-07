"""`WolfAccessClient`: ask wolf-access for an access decision.

`evaluation(...)` sends one AuthZEN 1.0 evaluation request to
`POST {base_url}/access/v1/evaluation` with the service's bearer credential:

    {"subject":  {"type": "user", "id": <gateway user_id>},
     "action":   {"name": <action>},
     "resource": {"type": <resource type>, "id": <resource id>},
     "context":  {"client_id": <gateway client_id>, "zedtoken"?: ..., ...}}

It returns a `Decision` for an HTTP 200 AuthZEN response and raises a
`WolfAccessError` subclass for anything else (unreachable, timeout, TLS
failure, broken HTTP, any other status, malformed body). The client keeps no
decision between calls. It sends the last ZedToken recorded with
`remember_zedtoken` (or a non-empty one passed in `context`), so a check made
after recording a write's token is at least as fresh as that write, unless
another write's token was recorded in between (ZedTokens are opaque and
cannot be ordered; concurrent writers pass their own token in `context`).

Transport rules: `https://` for any host, `http://` only for private hosts
(loopback, `localhost`, `*.railway.internal`; spec API-D1). It speaks HTTP
with `http.client` directly: no environment proxies, no redirects, and
certificates are always verified with the client's own SSL context, so the
credential only ever goes to `base_url`'s host.

`timeout` is a per-operation limit: each connect attempt, the send and each
socket read wait at most `timeout`. Between reads of the response body the
call also stops once `timeout` has passed since it began. It does NOT bound
the whole call: several connect attempts, slowly sent headers or slow chunked
framing can make one call take several times `timeout` (issue #2). Every such
call still ends in `WolfAccessUnavailable` (deny). Name lookup uses the system
resolver's own limits. The call runs on the caller's thread and starts no
threads.

Standard library only.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import math
import re
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

from .errors import (
    WolfAccessError,
    WolfAccessHTTPError,
    WolfAccessResponseError,
    WolfAccessUnavailable,
)

EVALUATION_PATH = "/access/v1/evaluation"
DEFAULT_TIMEOUT = 5.0
MAX_TIMEOUT = 3600.0
MAX_BODY = 1024 * 1024  # an AuthZEN evaluation answer is a few hundred bytes
_CHUNK = 65536
# RFC 6750 section 2.1 b64token: what a bearer credential may contain.
_BEARER = re.compile(r"[A-Za-z0-9\-._~+/]+=*")
_PRIVATE_SUFFIX = ".railway.internal"


@dataclass(frozen=True)
class Decision:
    """An AuthZEN decision. `context` is a shallow copy of what wolf-access
    returned under `context`, for example `reason_user`; never a score. The
    fields cannot be reassigned; the `context` dict itself is a plain dict.
    Equality compares both fields; the hash uses `allowed` only."""

    allowed: bool
    context: dict[str, Any] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise TypeError("Decision.allowed must be a bool")
        object.__setattr__(self, "context", dict(self.context))

    def __bool__(self) -> bool:
        return self.allowed


def _nonblank(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _private_host(host: str) -> bool:
    if host == "localhost" or host.endswith(_PRIVATE_SUFFIX):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check_timeout(timeout: Any) -> float:
    problem = ValueError(f"timeout must be a number of seconds in (0, {MAX_TIMEOUT:g}]")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise problem
    try:
        value = float(timeout)
    except OverflowError:
        raise problem from None
    if not math.isfinite(value) or not 0 < value <= MAX_TIMEOUT:
        raise problem
    return value


@dataclass(frozen=True)
class _Target:
    https: bool
    host: str
    port: int
    path_prefix: str
    display: str


def _target(base_url: Any) -> _Target:
    if not isinstance(base_url, str) or not base_url.isascii() or any(
            ord(c) <= 32 or ord(c) == 127 for c in base_url):
        raise ValueError("base_url must be a printable ASCII URL without whitespace")
    parts = urlsplit(base_url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("base_url must be an http:// or https:// URL")
    if parts.query or parts.fragment or "@" in parts.netloc:
        raise ValueError("base_url must not carry a query, fragment or user info")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("base_url has an invalid port") from None
    if port is None:
        # Always explicit: http.client would otherwise read the last group of
        # a bare IPv6 host as the port.
        port = 443 if parts.scheme == "https" else 80
    if parts.scheme == "http" and not _private_host(parts.hostname):
        raise ValueError("plain http:// is allowed only for private hosts; use https://")
    return _Target(https=parts.scheme == "https", host=parts.hostname, port=port,
                   path_prefix=parts.path.rstrip("/"), display=base_url.rstrip("/"))


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


class WolfAccessClient:
    def __init__(self, base_url: str, service_credential: str, *,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        self._target = _target(base_url)
        if not isinstance(service_credential, str) or not _BEARER.fullmatch(
                service_credential):
            raise ValueError("service_credential must be a bearer token (RFC 6750 "
                             "b64token: no spaces, line breaks or control characters)")
        self._credential = service_credential
        self._timeout = _check_timeout(timeout)
        self._ssl_context = ssl.create_default_context()
        self._zedtoken: str | None = None

    def __repr__(self) -> str:
        return f"WolfAccessClient({self._target.display!r})"

    @property
    def zedtoken(self) -> str | None:
        """The last ZedToken recorded, sent with every check that does not
        pass its own."""
        return self._zedtoken

    def remember_zedtoken(self, token: str) -> None:
        """Record the ZedToken a wolf-access write returned. The client holds
        one token, the last one recorded; concurrent writers should pass their
        own in `context`."""
        if not _nonblank(token):
            raise ValueError("token must be a non-empty string")
        self._zedtoken = token

    def evaluation(self, subject_user_id: str, action: str, resource_type: str,
                   resource_id: str, context: Mapping[str, Any]) -> Decision:
        """May `subject_user_id` do `action` on the resource? `context` must
        hold the call's gateway `client_id`."""
        for name, value in (("subject_user_id", subject_user_id), ("action", action),
                            ("resource_type", resource_type), ("resource_id", resource_id)):
            if not _nonblank(value):
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(context, Mapping):
            raise ValueError("context must be a mapping holding 'client_id'")
        ctx = dict(context)
        if not all(isinstance(key, str) for key in ctx):
            raise ValueError("context keys must be strings")
        if not _nonblank(ctx.get("client_id")):
            raise ValueError("context['client_id'] is required (the gateway client_id)")
        explicit = ctx.get("zedtoken")
        if explicit is not None and not isinstance(explicit, str):
            raise ValueError("context['zedtoken'] must be a string")
        if not _nonblank(explicit):
            ctx.pop("zedtoken", None)
            if self._zedtoken:
                ctx["zedtoken"] = self._zedtoken
        body = {
            "subject": {"type": "user", "id": subject_user_id},
            "action": {"name": action},
            "resource": {"type": resource_type, "id": resource_id},
            "context": ctx,
        }
        try:
            data = json.dumps(body, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, RecursionError):
            raise ValueError("context must be JSON-serializable") from None
        return _decision(self._post(EVALUATION_PATH, data))

    # --- transport ------------------------------------------------------------------

    def _connection(self) -> http.client.HTTPConnection:
        t = self._target
        if t.https:
            return http.client.HTTPSConnection(t.host, t.port, timeout=self._timeout,
                                               context=self._ssl_context)
        return http.client.HTTPConnection(t.host, t.port, timeout=self._timeout)

    def _post(self, path: str, data: bytes) -> bytes:
        deadline = time.monotonic() + self._timeout
        conn: http.client.HTTPConnection | None = None
        response: http.client.HTTPResponse | None = None
        try:
            conn = self._connection()
            conn.request("POST", self._target.path_prefix + path, body=data, headers={
                "Authorization": f"Bearer {self._credential}",
                "Content-Type": "application/json",
                "Accept": "application/json"})
            response = conn.getresponse()
            if response.status != 200:
                raise WolfAccessHTTPError(response.status)
            chunks: list[bytes] = []
            size = 0
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError("deadline passed while reading the body")
                chunk = response.read1(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_BODY:
                    raise WolfAccessResponseError("response is too large")
                chunks.append(chunk)
            if response.length:  # the connection closed before Content-Length
                raise http.client.IncompleteRead(b"".join(chunks), response.length)
            return b"".join(chunks)
        except WolfAccessError:
            raise
        except (http.client.HTTPException, OSError, ValueError) as exc:
            # OSError covers timeouts, refused connections and TLS failures.
            raise WolfAccessUnavailable(
                f"no answer from wolf-access ({type(exc).__name__})") from exc
        finally:
            if response is not None:
                response.close()
            if conn is not None:
                conn.close()


def _decision(raw: bytes) -> Decision:
    try:
        data = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
    except (ValueError, RecursionError):
        raise WolfAccessResponseError("response is not a JSON object with unique keys") \
            from None
    if not isinstance(data, dict) or not isinstance(data.get("decision"), bool):
        raise WolfAccessResponseError("response has no boolean 'decision'")
    context = data.get("context")
    if context is None:
        context = {}
    if not isinstance(context, dict):
        raise WolfAccessResponseError("response 'context' is not an object")
    return Decision(allowed=data["decision"], context=context)
