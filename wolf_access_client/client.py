"""`WolfAccessClient`: one service's client for wolf-access (wolf-access
`development` @ ffe20ed, `wolf_access/api.py`).

Everything is named by WRN (`Wrn` or its text; INT-B, AC-17).

Type registry (INT-D1, AC-9, AC-10): `register_schema`,
`PUT /v1/services/{service}/schema`.

The tree (INT-D2..D5, AC-1, AC-3, AC-6, AC-7): `create_resource`
(`POST /v1/resources`), `get_resource`, `move_resource` (`PATCH`) and
`delete_resource` (`DELETE ?version=`) on `/v1/resources/{wrn}`. Each write
is synchronous (INT-D3): make it before the service commits, and do not
commit if it raises. A create or move answers the resource's new `version`
(`Versioned`); a move or delete carries the version it read, and a stale
one is a `ConflictError` (AC-6).

Reconcile (INT-D7, AC-14): `reconcile`, the service's full list of
`(wrn, parent_wrn)`, `POST /v1/services/{service}/reconcile`.

Token exchange (INT-C5, AC-20): `exchange_token`, `POST /v1/token`
(RFC 8693, form-encoded).

Decisions (INT-F2, AC-19; OpenID AuthZEN 1.0): `evaluation`, `evaluations`
and `search_resources` on `/access/v1`. The subject is a principal's WRN
(`wrn:access:user/<id>` or `wrn:access:agent/<id>`), a resource is a WRN
(sent as `{type: <service>.<type>, id: <WRN>}`), and every decision names
the connected app, `client_wrn` (`context.client_wrn`); the library never
supplies any of them. A deny is a `Decision(allowed=False)` value; every
failure to get a decision raises `AccessUnavailable`, which callers treat as
deny (INT-F4).

Authentication (AC-10, AC-20, AC-22; `api.py` `gate()`). Every call carries
the service's own bearer token: its service credential, or a JWT it signs
(pass a callable as `service_credential` to mint one per call). The calls
wolf-access makes "for a principal" take that principal's token instead: a
token `exchange_token(principal, "access")` issued, passed as
`principal_token=`. Of the calls here those are `create_resource` under a
parent (the principal needs `<service>.<type>.create` on the parent, AC-3)
and `register_schema` when it adds a permission to an existing role (an
operator's token, AC-9).

Consistency (AC-6): the client keeps the consistency token (ZedToken) of the
last write it made (or one passed to `remember_zedtoken`) and sends it as
`context.consistency_token` on every evaluation, so a check made after a
write is at least as fresh as that write. It keeps no decision.

Transport rules: `https://` for any host, `http://` only for private hosts
(loopback, `localhost`, `*.railway.internal`; wolf-access refuses plain HTTP
at its edge, AC-22). It speaks HTTP with `http.client` directly: no
environment proxies, no redirects, and certificates are always verified with
the client's own SSL context, so a credential only ever goes to `base_url`'s
host.

`timeout` is a per-operation limit: each connect attempt, the send and each
socket read wait at most `timeout`. Between reads of the response body the
call also stops once `timeout` has passed since it began. It does NOT bound
the whole call: several connect attempts, slowly sent headers or slow chunked
framing can make one call take several times `timeout` (issue #2). Every such
call still ends in `WolfAccessUnavailable` (deny; on a write, the outcome is
unknown). A search makes one call per page. Calls run on the caller's thread
and start no threads.

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
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import Message
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence, Union
from urllib.parse import quote, urlencode, urlsplit

from .errors import (
    PROBLEM_TYPES,
    DecisionRefused,
    ProblemError,
    TokenExchangeError,
    WolfAccessError,
    WolfAccessHTTPError,
    WolfAccessResponseError,
    WolfAccessUnavailable,
)
from .models import (
    Decision,
    EvaluationItem,
    ExchangedToken,
    ReconcileChange,
    Reconciled,
    Resource,
    SchemaPermission,
    SchemaRole,
    SchemaType,
    Versioned,
    Written,
    as_wrn,
)
from .wrn import PRINCIPAL_KINDS, Wrn, WrnError, _segment_ok, parse_wrn

EVALUATION_PATH = "/access/v1/evaluation"
EVALUATIONS_PATH = "/access/v1/evaluations"
SEARCH_RESOURCE_PATH = "/access/v1/search/resource"
RESOURCES_PATH = "/v1/resources"
SERVICES_PATH = "/v1/services"
TOKEN_PATH = "/v1/token"

#: The audience of a principal's token for wolf-access's own calls (AC-20).
ACCESS_AUDIENCE = "access"
#: RFC 8693 token exchange, as wolf-access takes it (`wolf_access/tokens.py`).
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
WRN_TOKEN_TYPE = "urn:wolfaccess:token-type:wrn"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"

#: `options.evaluations_semantic` values (AuthZEN 1.0).
SEMANTICS = ("execute_all", "deny_on_first_deny", "permit_on_first_permit")
#: wolf-access answers at most this many items in one `evaluations` call.
MAX_EVALUATIONS = 1000
#: AuthZEN `page.limit` bounds on wolf-access (default 100, max 1000).
PAGE_MAX = 1000

DEFAULT_TIMEOUT = 5.0
MAX_TIMEOUT = 3600.0
MAX_BODY = 1024 * 1024          # a decision or write answer is a few hundred bytes
# A search page holds up to 1000 results, each a type and a WRN (<= 640 bytes).
MAX_SEARCH_BODY = 4 * 1024 * 1024
# A reconcile answer lists every WRN it added: as long as the service's list.
MAX_LIST_BODY = 64 * 1024 * 1024
MAX_ERROR_BODY = 64 * 1024      # a problem document; a bigger error body is not parsed
_CHUNK = 65536
# RFC 6750 section 2.1 b64token: what a bearer credential may contain.
_BEARER = re.compile(r"[A-Za-z0-9\-._~+/]+=*")
_PRIVATE_SUFFIX = ".railway.internal"
_PROBLEM_PREFIX = "urn:wolfaccess:problem:"
# A problem or error name kept from the server: short and plain, never text (#30).
_PLAIN_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
_JSON_ACCEPT = "application/json, application/problem+json"

Credential = Union[str, Callable[[], str]]
Token = Union[str, ExchangedToken]


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


def _bearer(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _BEARER.fullmatch(value):
        raise ValueError(f"{name} must be a bearer token (RFC 6750 b64token: no spaces, "
                         "line breaks or control characters)")
    return value


def _service_name(value: Any) -> str:
    """A registered service's name: one WRN segment (`finops`, `wolf_notes`)."""
    if not isinstance(value, str) or not _segment_ok(value):
        raise ValueError("service must be the service's WRN segment, lower case letters, "
                         "digits and _ (3 to 63 characters)")
    return value


def _resource_type(value: Any) -> str:
    """`<service>.<type>`, two WRN segments."""
    parts = value.split(".") if isinstance(value, str) else []
    if len(parts) != 2 or not all(_segment_ok(p) for p in parts):
        raise ValueError("resource_type must be '<service>.<type>'")
    return value


def _principal(value: Any, name: str = "subject") -> Wrn:
    """A principal's WRN, `wrn:access:user/<id>` or `wrn:access:agent/<id>`."""
    w = as_wrn(value, name)
    if w.service != "access" or w.type not in PRINCIPAL_KINDS:
        raise ValueError(f"{name} must be a principal's WRN, wrn:access:user/<id> or "
                         "wrn:access:agent/<id>")
    return w


def _optional(value: Any, name: str) -> Wrn | None:
    return None if value is None else as_wrn(value, name)


def _text(w: Wrn | None) -> str | None:
    return None if w is None else str(w)


def _version(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("version must be the resource's version, a whole number >= 1")
    return value


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        data = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
    except (ValueError, RecursionError):
        raise WolfAccessResponseError("response is not a JSON object with unique keys") \
            from None
    if not isinstance(data, dict):
        raise WolfAccessResponseError("response is not a JSON object")
    return data


def _encode(body: Mapping[str, Any], what: str = "the request") -> bytes:
    try:
        return json.dumps(body, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise ValueError(f"{what} must be JSON-serializable") from None


def _retry_after(headers: Message) -> float | None:
    """RFC 9110 section 10.2.3: delay-seconds or an HTTP-date."""
    value = (headers.get("Retry-After") or "").strip()
    if not value:
        return None
    if value.isdigit() and value.isascii():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None or when.tzinfo is None:
        return None
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


@dataclass(frozen=True)
class _Response:
    status: int
    headers: Message
    body: bytes


class WolfAccessClient:
    """The client of one registering service, `service` (its WRN segment:
    `finops`, `wolf_notes`), authenticating with `service_credential`: its
    service credential, or a callable returning a fresh bearer token per call
    (a JWT the service signs, AC-22)."""

    def __init__(self, base_url: str, service_credential: Credential, *, service: str,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        self._target = _target(base_url)
        self._service = _service_name(service)
        if callable(service_credential):
            self._credential: Credential = service_credential
        else:
            self._credential = _bearer(service_credential, "service_credential")
        self._timeout = _check_timeout(timeout)
        self._ssl_context = ssl.create_default_context()
        self._zedtoken: str | None = None

    def __repr__(self) -> str:
        return f"WolfAccessClient({self._target.display!r}, service={self._service!r})"

    @property
    def service(self) -> str:
        """The service this client registers and calls for."""
        return self._service

    # --- consistency (AC-6) -----------------------------------------------------------

    @property
    def zedtoken(self) -> str | None:
        """The last consistency token recorded, sent with every evaluation that
        does not pass its own."""
        return self._zedtoken

    def remember_zedtoken(self, token: str) -> None:
        """Record a consistency token. The client records each write's token
        itself; call this for one obtained elsewhere. It holds one token, the
        last recorded (tokens are opaque and cannot be ordered); concurrent
        writers pass their own as `consistency_token=`."""
        if not isinstance(token, str) or not token.strip():
            raise ValueError("token must be a non-empty string")
        self._zedtoken = token

    def _record(self, token: str | None) -> None:
        if token:
            self._zedtoken = token

    # --- type registry: PUT /v1/services/{service}/schema (INT-D1, AC-9) ---------------

    def register_schema(self, *, types: Sequence[SchemaType] = (),
                        permissions: Sequence[SchemaPermission] = (),
                        roles: Sequence[SchemaRole] = (),
                        principal_token: Token | None = None) -> Written:
        """Register this service's types, permissions and role bundles.
        Registrations are additive: sending what is registered again changes
        nothing, changing it is a `ConflictError`. Adding a permission to an
        existing role needs an operator: pass an operator's
        `principal_token` (`exchange_token(<operator>, "access")`), else it
        is a `ForbiddenError`. A 503 (`UnavailableError`) stored nothing."""
        body = {"types": [_item(t, SchemaType, "types").wire() for t in _seq(types, "types")],
                "permissions": [_item(p, SchemaPermission, "permissions").wire()
                                for p in _seq(permissions, "permissions")],
                "roles": [_item(r, SchemaRole, "roles").wire() for r in _seq(roles, "roles")]}
        path = f"{SERVICES_PATH}/{quote(self._service, safe='')}/schema"
        data = self._ok(self._json("PUT", path, body, principal_token), (200,))
        return self._written(data)

    # --- the tree: /v1/resources (INT-D2..D5, AC-1, AC-3, AC-6, AC-7) ------------------

    def create_resource(self, wrn: Wrn | str, parent_wrn: Wrn | str | None = None, *,
                        name: str | None = None,
                        principal_token: Token | None = None) -> Versioned:
        """Register a new resource of this service under `parent_wrn` (None
        only for a root, an org: AC-1). Under a parent, wolf-access checks
        `<service>.<type>.create` on the parent against the principal named in
        `principal_token` (`exchange_token(<principal>, "access")`, AC-3); no
        grant is written for them. A refused create and a missing parent are
        both `NotFoundError` (AC-15); an existing WRN is `ConflictError`.
        `name` is for a container wolf-access owns (org, project) only (AC-16)."""
        w = as_wrn(wrn)
        parent = _optional(parent_wrn, "parent_wrn")
        body: dict[str, Any] = {"wrn": str(w), "parent_wrn": _text(parent)}
        if name is not None:
            if not isinstance(name, str) or not name:
                raise ValueError("name must be a non-empty string")
            body["name"] = name
        response = self._json("POST", RESOURCES_PATH, body, principal_token)
        return self._versioned(self._ok(response, (201,)))

    def get_resource(self, wrn: Wrn | str) -> Resource:
        """Where a registered resource sits, and a container's name. A
        resource wolf-access does not hold is `NotFoundError`."""
        w = as_wrn(wrn)
        response = self._request("GET", self._resource_path(w), None, max_body=MAX_BODY,
                                 accept=_JSON_ACCEPT)
        data = self._ok(response, (200,))
        parent, name = data.get("parent_wrn"), data.get("name")
        if "parent_wrn" not in data or not (parent is None or isinstance(parent, str)) \
                or not (name is None or isinstance(name, str)):
            raise WolfAccessResponseError("a resource answer is not {parent_wrn[, name]}")
        return Resource(w, _answer_wrn(parent) if parent is not None else None, name)

    def move_resource(self, wrn: Wrn | str, parent_wrn: Wrn | str | None, *,
                      version: int) -> Versioned:
        """Move a resource under `parent_wrn` (None: make it a root, AC-1),
        carrying the `version` the service holds; a stale one is a
        `ConflictError` (AC-6). A move that removes access is synchronous
        (INT-D3): make it before committing."""
        w = as_wrn(wrn)
        body = {"parent_wrn": _text(_optional(parent_wrn, "parent_wrn")),
                "version": _version(version)}
        response = self._json("PATCH", self._resource_path(w), body, None)
        return self._versioned(self._ok(response, (200,)))

    def delete_resource(self, wrn: Wrn | str, *, version: int) -> Written:
        """Delete a resource, carrying its `version` (AC-6). A resource with
        children (AC-7) or grants is a `ConflictError`; a delete removes no
        grant."""
        w = as_wrn(wrn)
        path = f"{self._resource_path(w)}?version={_version(version)}"
        response = self._request("DELETE", path, None, max_body=MAX_BODY,
                                 accept=_JSON_ACCEPT)
        return self._written(self._ok(response, (200,)))

    def _resource_path(self, w: Wrn) -> str:
        return f"{RESOURCES_PATH}/{quote(str(w), safe=':/')}"

    # --- reconcile: POST /v1/services/{service}/reconcile (INT-D7, AC-14) ---------------

    def reconcile(self, resources: Iterable[tuple[Wrn | str, Wrn | str | None]]
                  ) -> Reconciled:
        """Send this service's FULL list of `(wrn, parent_wrn)`. wolf-access
        adds what it lacks at once; every move and removal it finds waits for
        an operator's approval and is answered in `changes`. A refused list
        changes nothing. Pass a mapping's `.items()` or any iterable of pairs."""
        listed = []
        for pair in resources:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise ValueError("resources must be (wrn, parent_wrn) pairs")
            listed.append({"wrn": str(as_wrn(pair[0])),
                           "parent_wrn": _text(_optional(pair[1], "parent_wrn"))})
        path = f"{SERVICES_PATH}/{quote(self._service, safe='')}/reconcile"
        response = self._json("POST", path, {"resources": listed}, None,
                              max_body=MAX_LIST_BODY)
        data = self._ok(response, (200,))
        added, changes = data.get("added"), data.get("changes")
        if not isinstance(added, list) or not isinstance(changes, list):
            raise WolfAccessResponseError("a reconcile answer is not {added, changes, "
                                          "zedtoken}")
        token = self._zedtoken_of(data)
        return Reconciled(tuple(_answer_wrn(a) for a in added),
                          tuple(_change(c) for c in changes), token)

    # --- token exchange: POST /v1/token (INT-C5, AC-20) ---------------------------------

    def exchange_token(self, subject: Wrn | str, audience: str, *,
                       client_wrn: Wrn | str | None = None) -> ExchangedToken:
        """A token for the principal `subject` (`wrn:access:user/<id>` or
        `wrn:access:agent/<id>`) to call the service `audience`, issued to this
        service (RFC 8693). The principal must be active and hold
        `<service>.use` and `<audience>.use` (AC-21). With audience `access`
        (`ACCESS_AUDIENCE`) it is the principal's token for wolf-access's own
        calls (`principal_token=`).

        `client_wrn`, the connected app the call is for (INT-F6), is sent as
        the optional form parameter `client_wrn` (wolf-access#334, PR #339:
        checked as a canonical WRN, else `invalid_request`; the token then
        carries the claim `client_wrn`; entitlement is unchanged). wolf-access
        `development` @ ffe20ed, before #339, ignores the parameter and issues
        a token without it. Either way an evaluation names the app itself, in
        `context.client_wrn`.

        A refusal is a `TokenExchangeError` with the RFC 6749 `error`."""
        p = _principal(subject)
        if not isinstance(audience, str) or not audience:
            raise ValueError("audience must be the target service's name")
        form = {"grant_type": TOKEN_EXCHANGE_GRANT, "subject_token": str(p),
                "subject_token_type": WRN_TOKEN_TYPE, "audience": audience}
        if client_wrn is not None:
            form["client_wrn"] = str(as_wrn(client_wrn, "client_wrn"))
        response = self._request("POST", TOKEN_PATH, urlencode(form).encode("ascii"),
                                 max_body=MAX_BODY, accept="application/json",
                                 content_type="application/x-www-form-urlencoded")
        if response.status != 200:
            raise _token_error(response)
        data = _json_object(response.body)
        token, expires_in = data.get("access_token"), data.get("expires_in")
        token_type, issued = data.get("token_type"), data.get("issued_token_type")
        if not isinstance(token, str) or not _BEARER.fullmatch(token) \
                or not isinstance(token_type, str) or token_type.lower() != "bearer" \
                or issued != JWT_TOKEN_TYPE or isinstance(expires_in, bool) \
                or not isinstance(expires_in, int) or expires_in < 1:
            raise WolfAccessResponseError("a token answer is not {access_token, "
                                          "issued_token_type, token_type, expires_in}")
        return ExchangedToken(token, expires_in, issued, token_type)

    # --- decisions: /access/v1 (INT-F2, AC-19) ------------------------------------------

    def evaluation(self, *, subject: Wrn | str, action: str, resource: Wrn | str,
                   client_wrn: Wrn | str, end_to_end: bool = False,
                   consistency_token: str | None = None) -> Decision:
        """May the principal `subject`, calling through the app `client_wrn`,
        do `action` (a permission) on `resource`? A missing resource is a deny
        like any other (AC-15). `end_to_end`: the app uses end-to-end
        encryption (AC-19)."""
        body = {"subject": _subject(subject), "action": _action(action),
                "resource": _resource(resource),
                "context": self._context(client_wrn, end_to_end, consistency_token)}
        return _decision(self._decide(EVALUATION_PATH, _encode(body), MAX_BODY))

    def evaluations(self, *, subject: Wrn | str, client_wrn: Wrn | str,
                    items: Sequence[EvaluationItem], semantic: str = "execute_all",
                    end_to_end: bool = False,
                    consistency_token: str | None = None) -> list[Decision]:
        """Several checks for one principal and app in one call (at most 1000).
        Returns one `Decision` per item, in order. `semantic` is the AuthZEN
        `evaluations_semantic`; items after the one that stopped the batch are
        `Decision(allowed=False, evaluated=False)`. An item wolf-access could
        not evaluate is a deny whose `error` says why."""
        if not isinstance(semantic, str) or semantic not in SEMANTICS:
            raise ValueError("semantic must be one of " + ", ".join(SEMANTICS))
        if not isinstance(items, (list, tuple)) or not items:
            raise ValueError("items must be a non-empty list of EvaluationItem")
        if len(items) > MAX_EVALUATIONS:
            raise ValueError(f"at most {MAX_EVALUATIONS} items per call")
        if not all(isinstance(item, EvaluationItem) for item in items):
            raise ValueError("items must be EvaluationItem values")
        body = {"subject": _subject(subject),
                "context": self._context(client_wrn, end_to_end, consistency_token),
                "options": {"evaluations_semantic": semantic},
                "evaluations": [{"action": _action(i.action), "resource": _resource(i.resource)}
                                for i in items]}
        data = self._decide(EVALUATIONS_PATH, _encode(body), MAX_BODY)
        answers = data.get("evaluations")
        if not isinstance(answers, list):
            raise WolfAccessResponseError("response has no 'evaluations' list")
        decisions = [_decision(answer) for answer in answers]
        _check_alignment(semantic, decisions, len(items))
        return decisions + [Decision(False, evaluated=False)] * (len(items) - len(decisions))

    def search_resources(self, *, subject: Wrn | str, action: str, resource_type: str,
                         client_wrn: Wrn | str, end_to_end: bool = False,
                         page_size: int | None = None) -> Iterator[Wrn]:
        """The WRNs of `resource_type` (`<service>.<type>`) the principal may
        `action` through the app (INT-F2: then filter in the service's own
        database), fetched a page at a time as the iterator is consumed.
        There is never a total. A failure on any page raises
        `AccessUnavailable` from the iterator: discard what it gave."""
        rtype = _resource_type(resource_type)
        if page_size is not None and (isinstance(page_size, bool) or not isinstance(
                page_size, int) or not 1 <= page_size <= PAGE_MAX):
            raise ValueError(f"page_size must be an integer from 1 to {PAGE_MAX}")
        body = {"subject": _subject(subject), "action": _action(action),
                "resource": {"type": rtype},
                "context": self._context(client_wrn, end_to_end, None, consistency=False)}
        return self._search_pages(body, rtype, page_size)

    def _search_pages(self, body: dict[str, Any], rtype: str,
                      page_size: int | None) -> Iterator[Wrn]:
        token: str | None = None
        seen: set[str] = set()
        while True:
            page: dict[str, Any] = {}
            if page_size is not None:
                page["limit"] = page_size
            if token:
                page["token"] = token
            data = self._decide(SEARCH_RESOURCE_PATH,
                                _encode({**body, "page": page} if page else body),
                                MAX_SEARCH_BODY)
            results, next_token = _search_page(data)
            found = []
            for item in results:
                w = _answer_wrn(item.get("id") if isinstance(item, dict) else None)
                if item.get("type") != rtype or w.resource_type != rtype:
                    raise WolfAccessResponseError(f"a result is not a {rtype} WRN")
                found.append(w)
            if next_token and next_token in seen:
                raise WolfAccessResponseError("wolf-access repeated a page token")
            yield from found
            if not next_token:
                return
            seen.add(next_token)
            token = next_token

    def _context(self, client_wrn: Any, end_to_end: Any, consistency_token: Any, *,
                 consistency: bool = True) -> dict[str, Any]:
        if client_wrn is None:
            raise ValueError("client_wrn, the connected app, is required (AC-19)")
        if not isinstance(end_to_end, bool):
            raise ValueError("end_to_end must be True or False")
        if consistency_token is not None and not isinstance(consistency_token, str):
            raise ValueError("consistency_token must be a string")
        out: dict[str, Any] = {"client_wrn": str(as_wrn(client_wrn, "client_wrn")),
                               "end_to_end": end_to_end}
        token = consistency_token if consistency_token and consistency_token.strip() \
            else self._zedtoken
        if consistency and token:
            out["consistency_token"] = token
        return out

    def _decide(self, path: str, data: bytes, max_body: int) -> dict[str, Any]:
        response = self._request("POST", path, data, max_body=max_body)
        if response.status != 200:
            raise DecisionRefused(response.status, retry_after=_retry_after(response.headers))
        return _json_object(response.body)

    # --- /v1 answers ------------------------------------------------------------------

    def _json(self, method: str, path: str, body: Mapping[str, Any],
              principal_token: Token | None, *, max_body: int = MAX_BODY) -> _Response:
        bearer = None
        if principal_token is not None:
            raw = principal_token.access_token if isinstance(
                principal_token, ExchangedToken) else principal_token
            bearer = _bearer(raw, "principal_token")
        return self._request(method, path, _encode(body), max_body=max_body,
                             accept=_JSON_ACCEPT, bearer=bearer)

    @staticmethod
    def _ok(response: _Response, statuses: tuple[int, ...]) -> dict[str, Any]:
        if not 200 <= response.status < 300:
            raise _problem(response)
        if response.status not in statuses:
            raise WolfAccessResponseError(f"HTTP {response.status} is not the documented "
                                          "answer")
        return _json_object(response.body)

    def _zedtoken_of(self, data: dict[str, Any]) -> str | None:
        token = data.get("zedtoken")
        if not isinstance(token, str):
            raise WolfAccessResponseError("a write answer has no 'zedtoken'")
        token = token if token.strip() else None
        self._record(token)
        return token

    def _written(self, data: dict[str, Any]) -> Written:
        return Written(self._zedtoken_of(data))

    def _versioned(self, data: dict[str, Any]) -> Versioned:
        version = data.get("version")
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise WolfAccessResponseError("a write answer has no 'version'")
        return Versioned(version, self._zedtoken_of(data))

    # --- transport --------------------------------------------------------------------

    def _connection(self) -> http.client.HTTPConnection:
        t = self._target
        if t.https:
            return http.client.HTTPSConnection(t.host, t.port, timeout=self._timeout,
                                               context=self._ssl_context)
        return http.client.HTTPConnection(t.host, t.port, timeout=self._timeout)

    def _service_bearer(self) -> str:
        if callable(self._credential):
            return _bearer(self._credential(), "service_credential()")
        return self._credential

    def _request(self, method: str, path: str, data: bytes | None, *, max_body: int,
                 accept: str = "application/json", bearer: str | None = None,
                 content_type: str = "application/json") -> _Response:
        """Send one request and read the whole answer. A success body over
        `max_body` is a `WolfAccessResponseError`; an error body is read up to
        `MAX_ERROR_BODY` and dropped beyond it."""
        token = bearer if bearer is not None else self._service_bearer()
        deadline = time.monotonic() + self._timeout
        conn: http.client.HTTPConnection | None = None
        response: http.client.HTTPResponse | None = None
        headers = {"Authorization": f"Bearer {token}", "Accept": accept}
        if data is not None:
            headers["Content-Type"] = content_type
        try:
            conn = self._connection()
            conn.request(method, self._target.path_prefix + path, body=data, headers=headers)
            response = conn.getresponse()
            success = 200 <= response.status < 300
            limit = max_body if success else MAX_ERROR_BODY
            chunks: list[bytes] = []
            size = 0
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError("deadline passed while reading the body")
                chunk = response.read1(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    if success:
                        raise WolfAccessResponseError("response is too large")
                    chunks = []
                    break
                chunks.append(chunk)
            if success and response.length:  # the connection closed before Content-Length
                raise http.client.IncompleteRead(b"".join(chunks), response.length)
            return _Response(response.status, response.msg, b"".join(chunks))
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


# --- request parts ----------------------------------------------------------------------

def _seq(value: Any, name: str) -> list[Any]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise ValueError(f"{name} must be a list")
    return list(value)


def _item(value: Any, cls: type, name: str) -> Any:
    if not isinstance(value, cls):
        raise ValueError(f"{name} must hold {cls.__name__} values")
    return value


def _subject(value: Any) -> dict[str, str]:
    """AuthZEN `subject`: `{type: user | agent, id: <principal WRN>}`."""
    p = _principal(value)
    return {"type": p.type, "id": str(p)}


def _action(value: Any) -> dict[str, str]:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("action must be a non-empty permission name")
    return {"name": value}


def _resource(value: Any) -> dict[str, str]:
    """AuthZEN `resource`: `{type: <service>.<type>, id: <WRN>}`."""
    w = as_wrn(value, "resource")
    return {"type": w.resource_type, "id": str(w)}


# --- answers ----------------------------------------------------------------------------

def _answer_wrn(value: Any) -> Wrn:
    try:
        return parse_wrn(value)
    except WrnError:
        raise WolfAccessResponseError("wolf-access answered a value that is not a "
                                      "canonical WRN") from None


def _answer_time(value: Any) -> datetime:
    try:
        when = datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        when = None
    if when is None:
        raise WolfAccessResponseError("a change's time is not an ISO 8601 time")
    return when


def _change(item: Any) -> ReconcileChange:
    fields = ("id", "service", "wrn", "kind", "parent_wrn", "found_at", "approved_by",
              "approved_at")
    if not isinstance(item, dict) or not all(f in item for f in fields) \
            or not isinstance(item["id"], str) or not isinstance(item["service"], str) \
            or item["kind"] not in ("move", "removal") \
            or not (item["approved_by"] is None or isinstance(item["approved_by"], str)):
        raise WolfAccessResponseError("a reconcile change is not {id, service, wrn, kind, "
                                      "parent_wrn, found_at, approved_by, approved_at}")
    return ReconcileChange(
        item["id"], item["service"], _answer_wrn(item["wrn"]), item["kind"],
        None if item["parent_wrn"] is None else _answer_wrn(item["parent_wrn"]),
        _answer_time(item["found_at"]), item["approved_by"],
        None if item["approved_at"] is None else _answer_time(item["approved_at"]))


def _decision(item: Any) -> Decision:
    if not isinstance(item, dict) or not isinstance(item.get("decision"), bool):
        raise WolfAccessResponseError("an answer has no boolean 'decision'")
    context = item.get("context")
    if context is None:
        context = {}
    if not isinstance(context, dict):
        raise WolfAccessResponseError("an answer's 'context' is not an object")
    return Decision(allowed=item["decision"], context=context)


def _check_alignment(semantic: str, decisions: list[Decision], asked: int) -> None:
    """Every answer must belong to the item at its position: a misaligned
    batch could allow the wrong resource, so it is no answer at all."""
    got = len(decisions)
    aligned = 0 < got <= asked
    if semantic == "execute_all":
        aligned = aligned and got == asked
    elif aligned:
        stop_on = semantic == "permit_on_first_permit"   # the decision that stops it
        aligned = all(d.allowed != stop_on for d in decisions[:-1]) and (
            got == asked or decisions[-1].allowed == stop_on)
    if not aligned:
        raise WolfAccessResponseError(f"{got} answers do not match {asked} items "
                                      f"under {semantic}")


def _search_page(data: dict[str, Any]) -> tuple[list[Any], str]:
    results, page = data.get("results"), data.get("page")
    if not isinstance(results, list) or not isinstance(page, dict):
        raise WolfAccessResponseError("a search page has no 'results' list or 'page'")
    next_token, count = page.get("next_token"), page.get("count")
    if not isinstance(next_token, str) or isinstance(count, bool) \
            or not isinstance(count, int) or count != len(results):
        raise WolfAccessResponseError("a search page's 'page' is malformed")
    return results, next_token


def _problem(response: _Response) -> WolfAccessHTTPError:
    retry_after = _retry_after(response.headers)
    media = (response.headers.get_content_type() or "").lower()
    data: Any = None
    if media == "application/problem+json":
        try:
            data = json.loads(response.body)
        except (ValueError, RecursionError):
            data = None
    if not isinstance(data, dict):
        return WolfAccessHTTPError(response.status, retry_after=retry_after)

    def text(key: str) -> str | None:
        value = data.get(key)
        return value if isinstance(value, str) else None   # RFC 9457 section 3.1
    type_ = text("type")
    name = type_[len(_PROBLEM_PREFIX):] if type_ and type_.startswith(_PROBLEM_PREFIX) \
        else None
    if name is not None and not _PLAIN_NAME.fullmatch(name):
        name = None
    cls = PROBLEM_TYPES.get(name, ProblemError) if name else ProblemError
    return cls(response.status, name=name, type=type_, title=text("title"),
               detail=text("detail"), retry_after=retry_after,
               www_authenticate=response.headers.get("WWW-Authenticate"))


def _token_error(response: _Response) -> WolfAccessHTTPError:
    """An RFC 6749 section 5.2 error answer, `{error, error_description}`."""
    retry_after = _retry_after(response.headers)
    try:
        data = json.loads(response.body) if response.body else None
    except (ValueError, RecursionError):
        data = None
    if not isinstance(data, dict) or not isinstance(data.get("error"), str):
        return TokenExchangeError(response.status, retry_after=retry_after,
                                  www_authenticate=response.headers.get("WWW-Authenticate"))
    error = data["error"] if _PLAIN_NAME.fullmatch(data["error"]) else None
    description = data.get("error_description")
    return TokenExchangeError(response.status, error=error,
                              description=description if isinstance(description, str)
                              else None, retry_after=retry_after,
                              www_authenticate=response.headers.get("WWW-Authenticate"))
