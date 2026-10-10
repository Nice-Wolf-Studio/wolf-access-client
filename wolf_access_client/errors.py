"""Every way a call can end without the answer it asked for.

    WolfAccessError                      every failure the client raises
    ├── AccessUnavailable                no decision was obtained: treat as deny (INT-F4)
    │   ├── WolfAccessUnavailable        unreachable, timeout, TLS failure, broken HTTP
    │   ├── WolfAccessResponseError      a success status with a malformed or oversized body
    │   └── DecisionRefused              any status but 200 from the decision API
    └── WolfAccessHTTPError              wolf-access answered with an error status
        ├── DecisionRefused              (also an AccessUnavailable, above)
        ├── TokenExchangeError           an RFC 6749 error from POST /v1/token
        └── ProblemError                 an RFC 9457 problem from /v1
            └── BadRequestError, UnauthorizedError, ForbiddenError, NotFoundError,
                ConflictError, UnavailableError: one per problem name

A real deny is never an exception: it is a `Decision(allowed=False)` value,
so a caller can always tell "wolf-access said no" from "no answer". A bad
argument (a WRN that is not canonical: `WrnError`; anything else:
`ValueError`/`TypeError`) is raised before anything is sent and is not a
`WolfAccessError`.

No exception carries text the server sent in its message (`str`/`repr`):
the status and problem or error name only. `ProblemError.detail` and
`TokenExchangeError.description` hold the server's own explanation for
callers that want it.
"""

from __future__ import annotations

from typing import Any


def _rebuild(cls: type, state: dict[str, Any]) -> "WolfAccessError":
    err = cls.__new__(cls)
    err.__dict__.update(state)
    Exception.__init__(err, err._describe())
    return err


class WolfAccessError(Exception):
    """The call did not get the answer it asked for. On a decision, treat it
    as deny / "not found" (INT-F4)."""

    #: Worth trying again later (transport failures, 408, 429 and 5xx; see
    #: `retry_after`). Never true for a refusal the same request would get again.
    retryable: bool = False

    def _describe(self) -> str:
        return str(self)


class AccessUnavailable(WolfAccessError):
    """No decision was obtained (INT-F4): wolf-access was unreachable, timed
    out, answered with an error status, or answered something malformed.
    Callers treat it as deny; it is never a real deny."""


class WolfAccessUnavailable(AccessUnavailable):
    """wolf-access could not be reached, the TLS handshake failed, the HTTP
    exchange broke, or no answer came within the timeout. The cause is
    chained. On a write, the outcome is unknown."""

    retryable = True


class WolfAccessResponseError(AccessUnavailable):
    """wolf-access answered with a success status but not with the documented
    answer (or the body was over the size limit)."""


class WolfAccessHTTPError(WolfAccessError):
    """wolf-access answered with an error status (redirects are never
    followed). `retry_after` is the `Retry-After` header in seconds, if any."""

    def __init__(self, status: int, *, retry_after: float | None = None) -> None:
        self.status = status
        self.retry_after = retry_after
        super().__init__(self._describe())

    def _describe(self) -> str:
        return f"wolf-access answered HTTP {self.status}"

    @property
    def retryable(self) -> bool:  # type: ignore[override]
        return self.status in (408, 429) or self.status >= 500

    def __reduce__(self):  # noqa: ANN204  (pickle/copy rebuild from the fields)
        return (_rebuild, (type(self), dict(self.__dict__)))


class DecisionRefused(AccessUnavailable, WolfAccessHTTPError):
    """The decision API (`/access/v1`) answered a status other than 200: 400
    (a malformed request, a WRN that is not canonical, a missing
    `context.client_wrn`), 401 (credential), 403 (plain HTTP), 5xx. No
    decision: treat as deny. AuthZEN error bodies are plain text and are not
    kept."""


class TokenExchangeError(WolfAccessHTTPError):
    """`POST /v1/token` refused the exchange (RFC 6749 section 5.2, RFC 8693
    section 2.2.2). `error` is the error code: `invalid_request` (the
    subject is not an active principal this service is entitled to),
    `invalid_target` (the principal may not use the audience),
    `invalid_client` (401: no service credential),
    `temporarily_unavailable` (503: wolf-access has no signing key), ... ;
    None when the answer is not an RFC 6749 error. `description` is the
    server's `error_description`, kept out of `str`."""

    def __init__(self, status: int, *, error: str | None = None,
                 description: str | None = None, retry_after: float | None = None,
                 www_authenticate: str | None = None) -> None:
        self.error = error
        self.description = description
        self.www_authenticate = www_authenticate
        super().__init__(status, retry_after=retry_after)

    def _describe(self) -> str:
        base = f"wolf-access answered HTTP {self.status}"
        return f"{base} ({self.error})" if self.error else base


class ProblemError(WolfAccessHTTPError):
    """An RFC 9457 problem from `/v1` (`type` `urn:wolfaccess:problem:<name>`). `name` is the
    part after `urn:wolfaccess:problem:` (None for a problem from elsewhere);
    a name this version has no class for arrives as a plain `ProblemError`."""

    problem_name: str | None = None

    def __init__(self, status: int, *, name: str | None = None, type: str | None = None,
                 title: str | None = None, detail: str | None = None,
                 retry_after: float | None = None,
                 www_authenticate: str | None = None) -> None:
        self.name = name
        self.type = type
        self.title = title
        self.detail = detail
        self.www_authenticate = www_authenticate
        super().__init__(status, retry_after=retry_after)

    def _describe(self) -> str:
        base = f"wolf-access answered HTTP {self.status}"
        return f"{base} ({self.name})" if self.name else base


class BadRequestError(ProblemError):
    """400: the request is malformed or refused as given: a WRN that is not
    canonical, an unregistered type (AC-8), a registration that is not
    additive in shape, a root that may not be one (AC-1)."""
    problem_name = "bad_request"


class UnauthorizedError(ProblemError):
    """401: no service credential, or not the principal's token a call made
    for a principal needs (`create_resource` under a parent, AC-3);
    `www_authenticate` holds the challenge."""
    problem_name = "unauthorized"


class ForbiddenError(ProblemError):
    """403: another service's type or resource (AC-10), plain HTTP (AC-22),
    or a registration that needs an operator (AC-9)."""
    problem_name = "forbidden"


class NotFoundError(ProblemError):
    """404: no such resource, or a create the principal may not make: a
    refused create and a missing parent get the same answer (AC-15)."""
    problem_name = "not_found"


class ConflictError(ProblemError):
    """409: the resource exists; the `version` is stale (AC-6); it still has
    children (AC-7) or grants; or a registration changes what is registered
    (AC-9)."""
    problem_name = "conflict"


class UnavailableError(ProblemError):
    """503: SpiceDB is unreachable or did not apply the change within the
    wait; retry after `retry_after`. A registration was not stored; a tree
    change is stored and applied when SpiceDB answers (AC-6)."""
    problem_name = "unavailable"


#: Problem name -> exception class. A name missing here (`internal`, or one a
#: later wolf-access adds) is raised as a plain `ProblemError` with its name.
PROBLEM_TYPES: dict[str, type[ProblemError]] = {
    cls.problem_name: cls for cls in (
        BadRequestError, UnauthorizedError, ForbiddenError, NotFoundError, ConflictError,
        UnavailableError)
}
