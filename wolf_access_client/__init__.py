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
    SeedNotVerified,
    UnauthorizedError,
    UnavailableError,
    UseOutboxError,
    WolfAccessError,
    WolfAccessHTTPError,
    WolfAccessResponseError,
    WolfAccessUnavailable,
)
from .mode import AccessGate, AccessMode, GateHealth
from .models import (
    Change,
    ChangeResult,
    ChangesAnswer,
    Decision,
    EvaluationItem,
    OutboxProgress,
    OutboxRow,
    Parent,
    Pending,
    Permission,
    PrincipalRef,
    ResourceRef,
    Written,
)
from .outbox import OutboxStore, PostgresOutboxStore, SQLiteOutboxStore
from .relay import OutboxRelay, RelayState

__version__ = "0.3.0"

__all__ = [
    # client and values
    "WolfAccessClient", "Decision", "EvaluationItem", "SEMANTICS", "ResourceRef",
    "PrincipalRef", "Permission", "Parent", "Written", "Pending",
    # enforcement mode (CUT-D1)
    "AccessMode", "AccessGate", "GateHealth",
    # cut-over: lifecycle outbox and relay (CUT-D1 (1), API-D10)
    "Change", "OutboxRow", "ChangeResult", "ChangesAnswer", "OutboxProgress", "OutboxStore",
    "SQLiteOutboxStore", "PostgresOutboxStore", "OutboxRelay", "RelayState",
    # errors
    "WolfAccessError", "AccessUnavailable", "WolfAccessUnavailable",
    "WolfAccessResponseError", "WolfAccessHTTPError", "DecisionRefused", "ProblemError",
    "PROBLEM_TYPES", "OwnerRequiredError", "OwnershipMismatchError", "ConflictError",
    "ForbiddenError", "NotFoundError", "BadRequestError", "UnauthorizedError",
    "HttpsRequiredError", "RateLimitedError", "UnavailableError",
    "IdempotencyKeyReusedError", "IdempotencyKeyInUseError", "UseOutboxError",
    "SeedNotVerified",
    "__version__",
]
