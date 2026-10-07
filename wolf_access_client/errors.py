"""Every way a call can end without the answer it asked for.

    WolfAccessError                      every failure the client raises
    ├── AccessUnavailable                no decision was obtained: treat as deny (CLI-P2)
    │   ├── WolfAccessUnavailable        unreachable, timeout, TLS failure, broken HTTP
    │   ├── WolfAccessResponseError      a success status with a malformed or oversized body
    │   └── DecisionRefused              any status but 200 from the decision API
    └── WolfAccessHTTPError              wolf-access answered with an error status
        ├── DecisionRefused              (also an AccessUnavailable, above)
        └── ProblemError                 an RFC 9457 problem from the write API (/v1)
            └── OwnerRequiredError, ConflictError, ... one per problem name

A real deny is never an exception: it is a `Decision(allowed=False)` value,
so a caller can always tell "wolf-access said no" from "no answer".

No exception carries text the server sent in its message (`str`/`repr`):
the status and problem name only. `ProblemError.detail` holds the server's
own explanation for callers that want it.
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
    as deny / "not found" (CLI-P2)."""

    #: Worth trying again later (transport failures, 408, 429 and 5xx; see
    #: `retry_after`). Never true for a refusal the same request would get again.
    retryable: bool = False

    def _describe(self) -> str:
        return str(self)


class AccessUnavailable(WolfAccessError):
    """No decision was obtained (CLI-P2): wolf-access was unreachable, timed
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
    (bad request), 401 (credential), 403 (another service's type, plain HTTP,
    or, on a subject search, `view` without `share`), 429 (rate limit), 5xx.
    No decision: treat as deny. AuthZEN error bodies are plain text and are
    not kept."""


class ProblemError(WolfAccessHTTPError):
    """An RFC 9457 problem from the write API (`/v1`, API-D3). `name` is the
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


class OwnerRequiredError(ProblemError):
    """422: a resource needs an owner (OWN-3)."""
    problem_name = "owner_required"


class OwnershipMismatchError(ProblemError):
    """422: parent, owner, author or `private` break the OWN rules; nothing
    was written."""
    problem_name = "ownership_mismatch"


class ConflictError(ProblemError):
    """409: the resource exists, or was deleted (its id is a tombstone)."""
    problem_name = "conflict"


class ForbiddenError(ProblemError):
    """403: not this service's type, or not allowed."""
    problem_name = "forbidden"


class NotFoundError(ProblemError):
    """404: no such resource (or one this service may not see)."""
    problem_name = "not_found"


class BadRequestError(ProblemError):
    """400: the request is malformed, or the type registration was refused."""
    problem_name = "bad_request"


class UnauthorizedError(ProblemError):
    """401: missing or unknown service credential; `www_authenticate` holds
    the challenge."""
    problem_name = "unauthorized"


class HttpsRequiredError(ProblemError):
    """403: the call reached the public edge over plain HTTP (API-D1)."""
    problem_name = "https_required"


class RateLimitedError(ProblemError):
    """429: over the per-service limit (API-S1); retry after `retry_after`."""
    problem_name = "rate_limited"


class UnavailableError(ProblemError):
    """503: SpiceDB is unreachable; nothing was stored. Retry after
    `retry_after` (API-D3)."""
    problem_name = "unavailable"


class IdempotencyKeyReusedError(ProblemError):
    """422: this `Idempotency-Key` was used for a different request."""
    problem_name = "idempotency_key_reused"


class IdempotencyKeyInUseError(ProblemError):
    """409: a request with this `Idempotency-Key` is still running."""
    problem_name = "idempotency_key_in_use"


#: Problem name -> exception class. A name missing here (a later milestone's,
#: such as `under_review`) is raised as a plain `ProblemError` with its name.
PROBLEM_TYPES: dict[str, type[ProblemError]] = {
    cls.problem_name: cls for cls in (
        OwnerRequiredError, OwnershipMismatchError, ConflictError, ForbiddenError,
        NotFoundError, BadRequestError, UnauthorizedError, HttpsRequiredError,
        RateLimitedError, UnavailableError, IdempotencyKeyReusedError,
        IdempotencyKeyInUseError)
}
