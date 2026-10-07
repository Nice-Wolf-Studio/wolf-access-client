"""Python client library for wolf-access, the Nice-Wolf-Studio authorization
service. See README.md."""

from .client import SEMANTICS, WolfAccessClient
from .errors import (
    PROBLEM_TYPES,
    AccessUnavailable,
    BadRequestError,
    ConflictError,
    DecisionRefused,
    ForbiddenError,
    HttpsRequiredError,
    IdempotencyKeyInUseError,
    IdempotencyKeyReusedError,
    NotFoundError,
    OwnerRequiredError,
    OwnershipMismatchError,
    ProblemError,
    RateLimitedError,
    UnauthorizedError,
    UnavailableError,
    WolfAccessError,
    WolfAccessHTTPError,
    WolfAccessResponseError,
    WolfAccessUnavailable,
)
from .mode import AccessGate, AccessMode
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

__version__ = "0.2.0"

__all__ = [
    # client and values
    "WolfAccessClient", "Decision", "EvaluationItem", "SEMANTICS", "ResourceRef",
    "PrincipalRef", "Permission", "Parent", "Written", "Pending",
    # enforcement mode (CUT-D1)
    "AccessMode", "AccessGate",
    # errors
    "WolfAccessError", "AccessUnavailable", "WolfAccessUnavailable",
    "WolfAccessResponseError", "WolfAccessHTTPError", "DecisionRefused", "ProblemError",
    "PROBLEM_TYPES", "OwnerRequiredError", "OwnershipMismatchError", "ConflictError",
    "ForbiddenError", "NotFoundError", "BadRequestError", "UnauthorizedError",
    "HttpsRequiredError", "RateLimitedError", "UnavailableError",
    "IdempotencyKeyReusedError", "IdempotencyKeyInUseError",
    "__version__",
]
