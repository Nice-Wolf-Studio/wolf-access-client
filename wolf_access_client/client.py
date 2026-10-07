"""`WolfAccessClient`: the wolf-access decision API and service write API.

Decision API, `/access/v1` (OpenID AuthZEN 1.0; API-P1, API-D4, API-D5):
`evaluation`, `evaluations`, and the searches `search_resources`,
`search_actions`, `search_subjects`. Every decision names the person
(`user_id`, the gateway `user_id`) and the client (`client_id`, the gateway
`client_id`) explicitly; the library never supplies either (API-D8, CLI-P1).
A deny is a `Decision(allowed=False)` value; every failure to get a decision
raises `AccessUnavailable`, which callers treat as deny (CLI-P2).

Service write API, `/v1` (API-D3): `register_type`, `create_resource`,
`update_resource`, `delete_resource`. A write returns `Written(zedtoken)` or
`Pending` (HTTP 202); a refusal raises a typed RFC 9457 `ProblemError`.

Consistency (CLI-D2): the client keeps no decision between calls. It keeps
the ZedToken of the last write it made (or one passed to `remember_zedtoken`)
and sends it as `context.zedtoken` (API-D4) on every decision, so a check
made after a write is evaluated at least as fresh as that write.

Transport rules: `https://` for any host, `http://` only for private hosts
(loopback, `localhost`, `*.railway.internal`; API-D1). It speaks HTTP with
`http.client` directly: no environment proxies, no redirects, and
certificates are always verified with the client's own SSL context, so the
credential only ever goes to `base_url`'s host.

`timeout` is a per-operation limit: each connect attempt, the send and each
socket read wait at most `timeout`. Between reads of the response body the
call also stops once `timeout` has passed since it began. It does NOT bound
the whole call: several connect attempts, slowly sent headers or slow chunked
framing can make one call take several times `timeout` (issue #2). Every such
call still ends in `WolfAccessUnavailable` (deny). A search makes one call
per page. Name lookup uses the system resolver's own limits. Calls run on the
caller's thread and start no threads.

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
from typing import Any, Callable, Iterator, Mapping, Sequence, TypeVar
from urllib.parse import quote, urlsplit

from .errors import (
    PROBLEM_TYPES,
    DecisionRefused,
    ProblemError,
    WolfAccessError,
    WolfAccessHTTPError,
    WolfAccessResponseError,
    WolfAccessUnavailable,
)
from .models import (
    Decision,
    EvaluationItem,
    Parent,
    Pending,
    Permission,
    PrincipalRef,
    ResourceRef,
    Written,
)

EVALUATION_PATH = "/access/v1/evaluation"
EVALUATIONS_PATH = "/access/v1/evaluations"
SEARCH_RESOURCE_PATH = "/access/v1/search/resource"
SEARCH_ACTION_PATH = "/access/v1/search/action"
SEARCH_SUBJECT_PATH = "/access/v1/search/subject"
TYPES_PATH = "/v1/types"
RESOURCES_PATH = "/v1/resources"

#: `options.evaluations_semantic` values (AuthZEN 1.0).
SEMANTICS = ("execute_all", "deny_on_first_deny", "permit_on_first_permit")
#: wolf-access answers at most this many items in one `evaluations` call.
MAX_EVALUATIONS = 1000
#: AuthZEN `page.limit` bounds on wolf-access (API-D5: default 100, max 1000).
PAGE_MAX = 1000
#: Principal kinds an owner may be (API-D3).
PRINCIPAL_TYPES = ("user", "org", "relationship", "project", "agent")
#: `context` keys that are parameters of their own, never passed in `context`.
RESERVED_CONTEXT = ("client_id", "user_id", "zedtoken")

DEFAULT_TIMEOUT = 5.0
MAX_TIMEOUT = 3600.0
MAX_BODY = 1024 * 1024          # a decision or write answer is a few hundred bytes
# A search page holds up to 1000 results, each a type (< 64 chars) and an id
# (<= 768 bytes on wolf-access), possibly JSON-escaped: about 1.8 MB at most.
MAX_SEARCH_BODY = 4 * 1024 * 1024
MAX_ERROR_BODY = 64 * 1024      # a problem document; a bigger error body is not parsed
_CHUNK = 65536
# RFC 6750 section 2.1 b64token: what a bearer credential may contain.
_BEARER = re.compile(r"[A-Za-z0-9\-._~+/]+=*")
# A header-safe Idempotency-Key: printable ASCII, no edge whitespace.
_IDEMPOTENCY_KEY = re.compile(r"[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?")
_PRIVATE_SUFFIX = ".railway.internal"
_PROBLEM_PREFIX = "urn:wolfaccess:problem:"
_UNSET: Any = object()

T = TypeVar("T")


def _nonblank(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require(**values: Any) -> None:
    for name, value in values.items():
        if not _nonblank(value):
            raise ValueError(f"{name} must be a non-empty string")


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


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        data = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
    except (ValueError, RecursionError):
        raise WolfAccessResponseError("response is not a JSON object with unique keys") \
            from None
    if not isinstance(data, dict):
        raise WolfAccessResponseError("response is not a JSON object")
    return data


def _encode(body: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(body, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise ValueError("context must be JSON-serializable") from None


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


def _resource_type(resource_type: Any) -> tuple[str, str]:
    """`<service>/<type>`: exactly one `/`, two non-empty parts, no whitespace."""
    if not isinstance(resource_type, str):
        raise ValueError("resource_type must be '<service>/<type>'")
    service, sep, name = resource_type.partition("/")
    if not sep or not service or not name or "/" in name or any(
            c.isspace() or ord(c) < 32 for c in resource_type):
        raise ValueError("resource_type must be '<service>/<type>'")
    return service, name


def _strings(value: Any, name: str, *, allow_empty: bool) -> list[str]:
    if not isinstance(value, (list, tuple)) or (not value and not allow_empty) \
            or not all(_nonblank(v) for v in value):
        raise ValueError(f"{name} must be a list of non-empty strings")
    return list(value)


def _sequence(value: Any, name: str) -> list[Any]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{name} must be a list")
    return list(value)


@dataclass(frozen=True)
class _Response:
    status: int
    headers: Message
    body: bytes


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

    # --- ZedToken (CLI-D2) -----------------------------------------------------------

    @property
    def zedtoken(self) -> str | None:
        """The last ZedToken recorded, sent with every decision that does not
        pass its own."""
        return self._zedtoken

    def remember_zedtoken(self, token: str) -> None:
        """Record a ZedToken. The client records each `Written.zedtoken` itself;
        call this for a token obtained elsewhere. The client holds one token,
        the last one recorded (ZedTokens are opaque and cannot be ordered);
        concurrent writers pass their own as `zedtoken=`."""
        if not _nonblank(token):
            raise ValueError("token must be a non-empty string")
        self._zedtoken = token

    # --- decision API: /access/v1 ----------------------------------------------------

    def evaluation(self, *, user_id: str, client_id: str, action: str, resource_type: str,
                   resource_id: str, context: Mapping[str, Any] | None = None,
                   zedtoken: str | None = None) -> Decision:
        """May the person `user_id`, calling through `client_id`, do `action`
        on the resource? `context` adds AuthZEN context keys (for example
        `review_case`, API-D6)."""
        _require(user_id=user_id, action=action, resource_type=resource_type,
                 resource_id=resource_id)
        body = {"subject": {"type": "user", "id": user_id},
                "action": {"name": action},
                "resource": {"type": resource_type, "id": resource_id},
                "context": self._context(client_id, context, zedtoken)}
        return _decision(self._decide(EVALUATION_PATH, _encode(body), MAX_BODY))

    def evaluations(self, *, user_id: str, client_id: str, items: Sequence[EvaluationItem],
                    semantic: str = "execute_all", context: Mapping[str, Any] | None = None,
                    zedtoken: str | None = None) -> list[Decision]:
        """Several checks for one person in one call (at most 1000). Returns one
        `Decision` per item, in order. `semantic` is the AuthZEN
        `evaluations_semantic`: `execute_all`, `deny_on_first_deny` or
        `permit_on_first_permit`; items after the one that stopped the batch
        are `Decision(allowed=False, evaluated=False)`."""
        _require(user_id=user_id)
        if not isinstance(semantic, str) or semantic not in SEMANTICS:
            raise ValueError("semantic must be one of " + ", ".join(SEMANTICS))
        if not isinstance(items, (list, tuple)) or not items:
            raise ValueError("items must be a non-empty list of EvaluationItem")
        if len(items) > MAX_EVALUATIONS:
            raise ValueError(f"at most {MAX_EVALUATIONS} items per call")
        checks = []
        for item in items:
            if not isinstance(item, EvaluationItem):
                raise ValueError("items must be EvaluationItem values")
            _require(action=item.action, resource_type=item.resource_type,
                     resource_id=item.resource_id)
            checks.append({"action": {"name": item.action},
                           "resource": {"type": item.resource_type, "id": item.resource_id}})
        body = {"subject": {"type": "user", "id": user_id},
                "context": self._context(client_id, context, zedtoken),
                "options": {"evaluations_semantic": semantic},
                "evaluations": checks}
        data = self._decide(EVALUATIONS_PATH, _encode(body), MAX_BODY)
        answers = data.get("evaluations")
        if not isinstance(answers, list):
            raise WolfAccessResponseError("response has no 'evaluations' list")
        decisions = [_decision(answer) for answer in answers]
        _check_alignment(semantic, decisions, len(checks))
        skipped = [Decision(False, evaluated=False)] * (len(checks) - len(decisions))
        return decisions + skipped

    def search_resources(self, *, user_id: str, client_id: str, action: str,
                         resource_type: str, page_size: int | None = None,
                         context: Mapping[str, Any] | None = None,
                         zedtoken: str | None = None) -> Iterator[ResourceRef]:
        """The resources of `resource_type` the person may `action` (the
        list-filter, CLI-3), fetched a page at a time as the iterator is
        consumed. There is never a total. A failure on any page raises
        `AccessUnavailable` from the iterator: discard what it gave."""
        _require(user_id=user_id, action=action, resource_type=resource_type)
        body = {"subject": {"type": "user", "id": user_id},
                "action": {"name": action},
                "resource": {"type": resource_type},
                "context": self._context(client_id, context, zedtoken)}

        def parse(item: Any) -> ResourceRef:
            if not isinstance(item, dict) or item.get("type") != resource_type \
                    or not _nonblank(item.get("id")):
                raise WolfAccessResponseError(f"a result is not a {resource_type} reference")
            return ResourceRef(resource_type, item["id"])
        return self._search(SEARCH_RESOURCE_PATH, body, page_size, parse)

    def search_actions(self, *, user_id: str, client_id: str, resource_type: str,
                       resource_id: str, page_size: int | None = None,
                       context: Mapping[str, Any] | None = None,
                       zedtoken: str | None = None) -> Iterator[str]:
        """The actions the person may do on one resource (none for a resource
        they cannot see), a page at a time. Never a total."""
        _require(user_id=user_id, resource_type=resource_type, resource_id=resource_id)
        body = {"subject": {"type": "user", "id": user_id},
                "resource": {"type": resource_type, "id": resource_id},
                "context": self._context(client_id, context, zedtoken)}

        def parse(item: Any) -> str:
            if not isinstance(item, dict) or not _nonblank(item.get("name")):
                raise WolfAccessResponseError("a result is not an action")
            return item["name"]
        return self._search(SEARCH_ACTION_PATH, body, page_size, parse)

    def search_subjects(self, *, user_id: str, client_id: str, action: str,
                        resource_type: str, resource_id: str, page_size: int | None = None,
                        context: Mapping[str, Any] | None = None,
                        zedtoken: str | None = None) -> Iterator[str]:
        """The gateway `user_id`s of the persons who may `action` the resource,
        asked for the person `user_id` (sent as `context.user_id`, API-D5).
        Empty when that person cannot see the resource; `DecisionRefused`
        (403) when they can see it but do not hold `share`. Never a total."""
        _require(user_id=user_id, action=action, resource_type=resource_type,
                 resource_id=resource_id)
        ctx = self._context(client_id, context, zedtoken)
        ctx["user_id"] = user_id
        body = {"subject": {"type": "user"},
                "action": {"name": action},
                "resource": {"type": resource_type, "id": resource_id},
                "context": ctx}

        def parse(item: Any) -> str:
            if not isinstance(item, dict) or item.get("type") != "user" \
                    or not _nonblank(item.get("id")):
                raise WolfAccessResponseError("a result is not a user reference")
            return item["id"]
        return self._search(SEARCH_SUBJECT_PATH, body, page_size, parse)

    def _context(self, client_id: Any, context: Any, zedtoken: Any) -> dict[str, Any]:
        _require(client_id=client_id)
        if context is None:
            extra: dict[Any, Any] = {}
        elif isinstance(context, Mapping):
            extra = dict(context)
        else:
            raise ValueError("context must be a mapping")
        if not all(isinstance(key, str) for key in extra):
            raise ValueError("context keys must be strings")
        reserved = sorted(set(extra) & set(RESERVED_CONTEXT))
        if reserved:
            raise ValueError(f"pass {', '.join(reserved)} as parameters, not in context")
        if zedtoken is not None and not isinstance(zedtoken, str):
            raise ValueError("zedtoken must be a string")
        out = {"client_id": client_id, **extra}
        token = zedtoken if _nonblank(zedtoken) else self._zedtoken
        if token:
            out["zedtoken"] = token
        return out

    def _decide(self, path: str, data: bytes, max_body: int) -> dict[str, Any]:
        response = self._request("POST", path, data, max_body=max_body)
        if response.status != 200:
            raise DecisionRefused(response.status, retry_after=_retry_after(response.headers))
        return _json_object(response.body)

    def _search(self, path: str, body: dict[str, Any], page_size: Any,
                parse: Callable[[Any], T]) -> Iterator[T]:
        if page_size is not None and (isinstance(page_size, bool) or not isinstance(
                page_size, int) or not 1 <= page_size <= PAGE_MAX):
            raise ValueError(f"page_size must be an integer from 1 to {PAGE_MAX}")
        _encode(body)  # an unserializable context is refused now, not at the first page
        return self._pages(path, body, page_size, parse)

    def _pages(self, path: str, body: dict[str, Any], page_size: int | None,
               parse: Callable[[Any], T]) -> Iterator[T]:
        token: str | None = None
        seen: set[str] = set()
        while True:
            page: dict[str, Any] = {}
            if page_size is not None:
                page["limit"] = page_size
            if token:
                page["token"] = token
            data = self._decide(path, _encode({**body, "page": page} if page else body),
                                MAX_SEARCH_BODY)
            results, next_token = _search_page(data)
            if next_token and next_token in seen:
                raise WolfAccessResponseError("wolf-access repeated a page token")
            items = [parse(item) for item in results]
            yield from items
            if not next_token:
                return
            seen.add(next_token)
            token = next_token

    # --- write API: /v1 (API-D3) -----------------------------------------------------

    def register_type(self, resource_type: str, *, permissions: Sequence[Permission],
                      parents: Sequence[Parent] = (), topics: bool = False
                      ) -> Written | Pending:
        """Register (or re-register) one of this service's resource types,
        `<service>/<type>`. A 503 (`UnavailableError`, retryable) means SpiceDB
        was unreachable and nothing was stored."""
        service, name = _resource_type(resource_type)
        perms = []
        for perm in _sequence(permissions, "permissions"):
            if not isinstance(perm, Permission) or not _nonblank(perm.name):
                raise ValueError("permissions must be Permission values with a name")
            perms.append({"name": perm.name, "default_roles": _strings(
                perm.default_roles, "default_roles", allow_empty=True)})
        rels = []
        for parent in _sequence(parents, "parents"):
            if not isinstance(parent, Parent) or not _nonblank(parent.relation):
                raise ValueError("parents must be Parent values with a relation")
            rels.append({"relation": parent.relation, "parent_types": _strings(
                parent.parent_types, "parent_types", allow_empty=False)})
        if not isinstance(topics, bool):
            raise ValueError("topics must be True or False")
        path = f"{TYPES_PATH}/{quote(service, safe='')}/{quote(name, safe='')}"
        return self._write("PUT", path, {"permissions": perms, "parents": rels,
                                         "topics": topics})

    def create_resource(self, resource_type: str, resource_id: str, *, owner: PrincipalRef,
                        author: str, parent: ResourceRef | None = None,
                        private: bool | None = None,
                        idempotency_key: str | None = None) -> Written | Pending:
        """Register a resource with its owner and author (the gateway `user_id`
        of the person filing it). `parent` and `private` are sent only when
        given. With `idempotency_key`, a repeat of the same request returns the
        first answer (API-D3)."""
        _resource_type(resource_type)
        _require(resource_id=resource_id, author=author)
        if not isinstance(owner, PrincipalRef) or owner.type not in PRINCIPAL_TYPES \
                or not _nonblank(owner.id):
            raise ValueError("owner must be a PrincipalRef of type " + ", ".join(
                PRINCIPAL_TYPES))
        body: dict[str, Any] = {"type": resource_type, "id": resource_id,
                                "owner": {"type": owner.type, "id": owner.id},
                                "author": author}
        if parent is not None:
            body["parent"] = _parent_ref(parent)
        if private is not None:
            if not isinstance(private, bool):
                raise ValueError("private must be True or False")
            body["private"] = private
        headers = {}
        if idempotency_key is not None:
            if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_KEY.fullmatch(
                    idempotency_key):
                raise ValueError("idempotency_key must be printable ASCII without "
                                 "leading or trailing whitespace")
            headers["Idempotency-Key"] = idempotency_key
        return self._write("POST", RESOURCES_PATH, body, headers)

    def update_resource(self, resource_type: str, resource_id: str, *,
                        parent: ResourceRef | None = _UNSET,
                        private: bool = _UNSET) -> Written | Pending:
        """Change a resource's `parent` (None detaches it) and/or `private`;
        only the fields given are sent. Owner changes go through OWN-5 /
        OWN-D4, never here."""
        path = self._resource_path(resource_type, resource_id)
        body: dict[str, Any] = {}
        if parent is not _UNSET:
            body["parent"] = None if parent is None else _parent_ref(parent)
        if private is not _UNSET:
            if not isinstance(private, bool):
                raise ValueError("private must be True or False")
            body["private"] = private
        if not body:
            raise ValueError("give parent and/or private")
        return self._write("PATCH", path, body)

    def delete_resource(self, resource_type: str, resource_id: str) -> Written | Pending:
        """Delete a resource and all its relations. Its id stays a tombstone:
        creating it again is a `ConflictError`."""
        return self._write("DELETE", self._resource_path(resource_type, resource_id), None)

    def _resource_path(self, resource_type: Any, resource_id: Any) -> str:
        service, name = _resource_type(resource_type)
        _require(resource_id=resource_id)
        return "/".join((RESOURCES_PATH, quote(service, safe=""), quote(name, safe=""),
                         quote(resource_id, safe="")))

    def _write(self, method: str, path: str, body: dict[str, Any] | None,
               headers: dict[str, str] | None = None) -> Written | Pending:
        """One `/v1` write answered `{zedtoken}` (200/201) or `{status:
        pending}` (202); an error status raises `_problem(...)`. The M1c calls
        (outbox, intent, ownership, state, snapshot) answer other shapes: they
        use `_request` and `_problem` with their own result parsing."""
        data = None if body is None else _encode(body)
        response = self._request(method, path, data, max_body=MAX_BODY,
                                 extra_headers=headers or {},
                                 accept="application/json, application/problem+json")
        if 200 <= response.status < 300:
            result = _write_result(response.status, response.body)
            if isinstance(result, Written):
                self._zedtoken = result.zedtoken
            return result
        raise _problem(response)

    # --- transport -------------------------------------------------------------------

    def _connection(self) -> http.client.HTTPConnection:
        t = self._target
        if t.https:
            return http.client.HTTPSConnection(t.host, t.port, timeout=self._timeout,
                                               context=self._ssl_context)
        return http.client.HTTPConnection(t.host, t.port, timeout=self._timeout)

    def _request(self, method: str, path: str, data: bytes | None, *, max_body: int,
                 extra_headers: Mapping[str, str] | None = None,
                 accept: str = "application/json") -> _Response:
        """Send one request and read the whole answer. A success body over
        `max_body` is a `WolfAccessResponseError`; an error body is read up to
        `MAX_ERROR_BODY` and dropped beyond it."""
        deadline = time.monotonic() + self._timeout
        conn: http.client.HTTPConnection | None = None
        response: http.client.HTTPResponse | None = None
        headers = {"Authorization": f"Bearer {self._credential}", "Accept": accept}
        if data is not None:
            headers["Content-Type"] = "application/json"
        headers.update(extra_headers or {})
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


def _parent_ref(parent: Any) -> dict[str, str]:
    if not isinstance(parent, ResourceRef):
        raise ValueError("parent must be a ResourceRef or None")
    _resource_type(parent.type)
    _require(parent_id=parent.id)
    return {"type": parent.type, "id": parent.id}


def _write_result(status: int, raw: bytes) -> Written | Pending:
    data = _json_object(raw)
    if status in (200, 201):
        token = data.get("zedtoken")
        if not _nonblank(token):
            raise WolfAccessResponseError("a write answer has no 'zedtoken'")
        return Written(token)
    if status == 202 and data.get("status") == "pending":
        return Pending()
    raise WolfAccessResponseError(f"HTTP {status} is not a write answer")


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
        and len(type_) > len(_PROBLEM_PREFIX) else None
    cls = PROBLEM_TYPES.get(name, ProblemError) if name else ProblemError
    return cls(response.status, name=name, type=type_, title=text("title"),
               detail=text("detail"), retry_after=retry_after,
               www_authenticate=response.headers.get("WWW-Authenticate"))
