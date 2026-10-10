"""Python client library for wolf-access, the Nice-Wolf-Studio authorization
service, and the shared WRN library (INT-B3). See README.md."""

from .client import (
    ACCESS_AUDIENCE,
    MAX_EVALUATIONS,
    SEMANTICS,
    WolfAccessClient,
)
from .errors import (
    PROBLEM_TYPES,
    AccessUnavailable,
    BadRequestError,
    ConflictError,
    DecisionRefused,
    ForbiddenError,
    NotFoundError,
    ProblemError,
    TokenExchangeError,
    UnauthorizedError,
    UnavailableError,
    WolfAccessError,
    WolfAccessHTTPError,
    WolfAccessResponseError,
    WolfAccessUnavailable,
)
from .jcs import canonical_json, diff_hash
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
)
from .wrn import (
    ACCESS_KINDS,
    CANONICAL_WRN_SQL,
    PRINCIPAL_KINDS,
    Wrn,
    WrnError,
    is_canonical_wrn,
    parse_wrn,
)

__version__ = "0.7.0"

__all__ = [
    # WRNs (INT-B3)
    "Wrn", "WrnError", "parse_wrn", "is_canonical_wrn", "CANONICAL_WRN_SQL",
    "ACCESS_KINDS", "PRINCIPAL_KINDS",
    # client
    "WolfAccessClient", "ACCESS_AUDIENCE", "SEMANTICS", "MAX_EVALUATIONS",
    # values
    "Decision", "EvaluationItem", "SchemaType", "SchemaPermission", "SchemaRole",
    "Written", "Versioned", "Resource", "ReconcileChange", "Reconciled", "ExchangedToken",
    # canonical JSON
    "canonical_json", "diff_hash",
    # errors
    "WolfAccessError", "AccessUnavailable", "WolfAccessUnavailable",
    "WolfAccessResponseError", "WolfAccessHTTPError", "DecisionRefused",
    "TokenExchangeError", "ProblemError", "PROBLEM_TYPES", "BadRequestError",
    "UnauthorizedError", "ForbiddenError", "NotFoundError", "ConflictError",
    "UnavailableError",
    "__version__",
]
