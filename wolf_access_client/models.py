"""The values the client takes and returns. Arguments are frozen dataclasses
checked when they are made; a WRN argument may be a `Wrn` or its text, and
text is parsed (`WrnError`) before anything is sent."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Sequence

from .wrn import Wrn, parse_wrn


def as_wrn(value: Any, name: str = "wrn") -> Wrn:
    """`value` as a `Wrn`: a `Wrn` as is, text parsed (`WrnError`)."""
    if isinstance(value, Wrn):
        return value
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a Wrn or its text")
    return parse_wrn(value)


def _nonblank(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _names(value: Any, what: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, (list, tuple, frozenset, set)) \
            or not all(_nonblank(v) for v in value):
        raise ValueError(f"{what} must be a list of non-empty names")
    return tuple(sorted(value)) if isinstance(value, (set, frozenset)) else tuple(value)


# --- decisions (AuthZEN, /access/v1) --------------------------------------------------

@dataclass(frozen=True)
class Decision:
    """An AuthZEN decision. A deny is `allowed=False`, a value, not an error.

    In an `evaluations` batch, an item wolf-access could not evaluate is a
    deny whose `error` says why (`{status, message}`), and an item a
    short-circuit semantic skipped is `evaluated=False` (also a deny).
    Equality compares every field; the hash uses `allowed` only."""

    allowed: bool
    context: dict[str, Any] = field(default_factory=dict, hash=False)
    evaluated: bool = field(default=True, hash=False)

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise TypeError("Decision.allowed must be a bool")
        if not isinstance(self.evaluated, bool):
            raise TypeError("Decision.evaluated must be a bool")
        object.__setattr__(self, "context", dict(self.context))

    def __bool__(self) -> bool:
        return self.allowed

    @property
    def error(self) -> dict[str, Any] | None:
        """`{status, message}` when wolf-access could not evaluate this batch
        item; else None."""
        error = self.context.get("error")
        return error if isinstance(error, dict) else None


@dataclass(frozen=True)
class EvaluationItem:
    """One check in an `evaluations` batch: `action` (a permission,
    `<service>.<type>.<verb>`) on `resource` (a WRN)."""

    action: str
    resource: Wrn

    def __post_init__(self) -> None:
        if not _nonblank(self.action):
            raise ValueError("action must be a non-empty permission name")
        object.__setattr__(self, "resource", as_wrn(self.resource, "resource"))


# --- the type registry (PUT /v1/services/{service}/schema) ----------------------------

@dataclass(frozen=True)
class SchemaType:
    """A type a service registers (AC-8, AC-9): `<service>.<type>`, whether
    it gets resource rows (`registered`), and the types its parent may be
    (`allowed_parents`, `<service>.<type>` names, wolf-access's own
    `access.org` / `access.project` included)."""

    type: str
    registered: bool = True
    allowed_parents: Sequence[str] = ()

    def __post_init__(self) -> None:
        if not _nonblank(self.type):
            raise ValueError("type must be '<service>.<type>'")
        if not isinstance(self.registered, bool):
            raise ValueError("registered must be True or False")
        object.__setattr__(self, "allowed_parents",
                           _names(self.allowed_parents, "allowed_parents"))

    def wire(self) -> dict[str, Any]:
        return {"type": self.type, "registered": self.registered,
                "allowed_parents": list(self.allowed_parents)}


@dataclass(frozen=True)
class SchemaPermission:
    """A permission a service registers, `<service>.<type>.<verb>`; one with
    `requires_end_to_end` is denied to an app without end-to-end encryption
    (AC-19)."""

    name: str
    requires_end_to_end: bool = False

    def __post_init__(self) -> None:
        if not _nonblank(self.name):
            raise ValueError("name must be '<service>.<type>.<verb>'")
        if not isinstance(self.requires_end_to_end, bool):
            raise ValueError("requires_end_to_end must be True or False")

    def wire(self) -> dict[str, Any]:
        return {"name": self.name, "requires_end_to_end": self.requires_end_to_end}


@dataclass(frozen=True)
class SchemaRole:
    """A role bundle (AC-9): its `rank` (a granter grants only at or below
    their own, AC-5) and the permissions it holds. Adding a permission to an
    existing role is an operator's: make that registration with an
    operator's principal token."""

    name: str
    rank: int
    permissions: Sequence[str] = ()

    def __post_init__(self) -> None:
        if not _nonblank(self.name):
            raise ValueError("name must be a role name")
        if isinstance(self.rank, bool) or not isinstance(self.rank, int):
            raise ValueError("rank must be a whole number")
        object.__setattr__(self, "permissions", _names(self.permissions, "permissions"))

    def wire(self) -> dict[str, Any]:
        return {"name": self.name, "rank": self.rank, "permissions": list(self.permissions)}


# --- the tree (/v1/resources) ---------------------------------------------------------

@dataclass(frozen=True)
class Written:
    """A write wolf-access applied: its consistency token (a ZedToken, AC-6).
    The client keeps it and sends it with the decisions that follow. None
    when wolf-access answered an empty one: the write happened."""

    zedtoken: str | None = None


@dataclass(frozen=True)
class Versioned:
    """A create or move wolf-access applied: the resource's new `version`
    (AC-6: every change raises it; pass it to the next move or delete) and
    the write's consistency token."""

    version: int
    zedtoken: str | None = None


@dataclass(frozen=True)
class Resource:
    """`GET /v1/resources/{wrn}`: where a registered resource sits, and the
    `name` of a container wolf-access owns (an org or project; None for
    anything else)."""

    wrn: Wrn
    parent_wrn: Wrn | None
    name: str | None = None


@dataclass(frozen=True)
class ReconcileChange:
    """A move or removal reconcile found, waiting for an operator's approval
    (AC-14). `parent_wrn` is where a move goes (None for a removal)."""

    id: str
    service: str
    wrn: Wrn
    kind: str
    parent_wrn: Wrn | None
    found_at: datetime
    approved_by: str | None = None
    approved_at: datetime | None = None


@dataclass(frozen=True)
class Reconciled:
    """`POST /v1/services/{service}/reconcile`: the WRNs added, and the
    service's changes waiting for approval."""

    added: tuple[Wrn, ...]
    changes: tuple[ReconcileChange, ...]
    zedtoken: str | None = None


# --- token exchange (POST /v1/token) --------------------------------------------------

@dataclass(frozen=True)
class ExchangedToken:
    """An RFC 8693 token wolf-access issued (AC-20): a JWT for one principal
    (`sub`) to call one service (`aud`), at most 60 seconds. With audience
    `access` it is the principal's token for wolf-access's own calls made for
    a principal (`create_resource` under a parent, AC-3). A secret: it is
    left out of `repr`; never log it. `expires_at` is `time.time()` when it
    expires, by this machine's clock."""

    access_token: str = field(repr=False)
    expires_in: int
    issued_token_type: str
    token_type: str = "Bearer"
    expires_at: float = field(default=0.0, compare=False)

    def __post_init__(self) -> None:
        if not self.expires_at:
            object.__setattr__(self, "expires_at", time.time() + self.expires_in)

    def __str__(self) -> str:
        return f"ExchangedToken(expires_in={self.expires_in})"
