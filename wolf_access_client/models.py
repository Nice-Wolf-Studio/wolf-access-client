"""The values the client takes and returns. Arguments are plain frozen
dataclasses; the client checks them when they are used, and nothing is sent
when one is wrong (`ValueError`)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence


@dataclass(frozen=True)
class Decision:
    """An AuthZEN decision. A deny is `allowed=False`, a value, not an error.

    `context` is a shallow copy of the response `context` (for example
    `reason_user`; never a score, API-P2). In an `evaluations` batch, an item
    wolf-access could not evaluate is a deny whose `error` says why, and an
    item a short-circuit semantic skipped is `evaluated=False` (also a deny).
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
        item (invalid, or another service's type); else None."""
        error = self.context.get("error")
        return error if isinstance(error, dict) else None


@dataclass(frozen=True)
class EvaluationItem:
    """One check in an `evaluations` batch."""

    action: str
    resource_type: str
    resource_id: str


@dataclass(frozen=True)
class ResourceRef:
    """A resource: its registered type (`<service>/<type>`) and id."""

    type: str
    id: str


@dataclass(frozen=True)
class PrincipalRef:
    """An owner (API-D3): `PrincipalRef.user(<gateway user_id>)`, or
    `PrincipalRef("org" | "relationship" | "project" | "agent", <principal id>)`."""

    type: str
    id: str

    @classmethod
    def user(cls, user_id: str) -> "PrincipalRef":
        return cls("user", user_id)


@dataclass(frozen=True)
class Permission:
    """A permission a type registers, and the built-in roles that get it
    (`Owner`, `Co-owner`, `Editor`, `Viewer`). The base permissions (`view`,
    `edit`, `share`, ...) exist on every type and are not registered."""

    name: str
    default_roles: Sequence[str] = ()


@dataclass(frozen=True)
class Parent:
    """A parent relation a type registers, and the service's own types that
    may be the parent."""

    relation: str
    parent_types: Sequence[str]


@dataclass(frozen=True)
class Written:
    """A write wolf-access has applied. The client keeps `zedtoken` and sends
    it with the decisions that follow (CLI-D2)."""

    zedtoken: str


@dataclass(frozen=True)
class Pending:
    """HTTP 202: the write is committed but its relationships are not applied
    yet (EVT-D3). Until they are, wolf-access fails every check closed."""

    status: str = "pending"
