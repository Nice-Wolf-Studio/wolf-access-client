"""The values the client takes and returns. Arguments are plain frozen
dataclasses; the client checks them when they are used, and nothing is sent
when one is wrong (`ValueError`)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from ._checks import PRINCIPAL_TYPES, nonblank, resource_type


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
    it with the decisions that follow (CLI-D2). `zedtoken` is None when
    wolf-access answered an empty one (it holds no watermark yet, #26): the
    write happened, and the client keeps the token it already had."""

    zedtoken: str | None = None


@dataclass(frozen=True)
class Pending:
    """HTTP 202: the write is committed but its relationships are not applied
    yet (EVT-D3). Until they are, wolf-access fails every check closed."""

    status: str = "pending"


# --- the lifecycle outbox (CUT-D1 (1), API-D10) ---------------------------------------

#: The lifecycle actions a service writes to its outbox. `ack_ownership`
#: (CUT-D1 (4)) is written by the library itself from wolf-access M1c-3 on.
ACTIONS = ("create", "move", "private", "delete")
#: A row's result from wolf-access. `resolved` is a refused row that
#: reconcile has resolved; it counts as applied (CUT-D1 (1)).
RESULTS = ("applied", "held", "refused", "resolved")
#: A row in the outbox: not answered yet (`pending`), or its last result.
ROW_STATUSES = ("pending",) + RESULTS


def _ref(value: Any, name: str) -> "ResourceRef":
    if not isinstance(value, ResourceRef):
        raise ValueError(f"{name} must be a ResourceRef")
    resource_type(value.type)
    if not nonblank(value.id):
        raise ValueError(f"{name}.id must be a non-empty string")
    return value


def _ref_wire(ref: "ResourceRef") -> dict[str, str]:
    return {"type": ref.type, "id": ref.id}


def _ref_from(value: Any, name: str) -> "ResourceRef":
    if not isinstance(value, Mapping) or set(value) != {"type", "id"}:
        raise ValueError(f"{name} must be {{type, id}}")
    return _ref(ResourceRef(value["type"], value["id"]), name)


@dataclass(frozen=True)
class Change:
    """One resource lifecycle change, as the service commits it (CUT-D1 (1)).
    Build it with `Change.create`, `Change.move`, `Change.set_private` or
    `Change.delete`; it is checked when it is built, so a change wolf-access
    could only refuse for its shape never reaches the outbox.

    - `create`: `owner` and `author` (the gateway `user_id` of the person
      filing it) are required; `parent` (None: no parent) and `private` are
      sent only when given.
    - `move`: `parent` is the new parent; None moves it to the root.
    - `private`: `private` is the new flag.
    - `delete`: nothing else.

    `intent` is the single-use token wolf-access grants for a move, `private`
    change or delete (CUT-D1 (3), wolf-access M1c-2); creates need none."""

    action: str
    resource: ResourceRef
    parent: ResourceRef | None = None
    private: bool | None = None
    owner: PrincipalRef | None = None
    author: str | None = None
    intent: str | None = None

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError("action must be one of " + ", ".join(ACTIONS) + (
                " (ack_ownership rows arrive with wolf-access M1c-3)"
                if self.action == "ack_ownership" else ""))
        _ref(self.resource, "resource")
        if self.parent is not None:
            if self.action not in ("create", "move"):
                raise ValueError(f"a {self.action} change has no parent")
            _ref(self.parent, "parent")
        if self.private is not None and not isinstance(self.private, bool):
            raise ValueError("private must be True or False")
        if self.action == "private" and self.private is None:
            raise ValueError("a private change names private: True or False")
        if self.action in ("move", "delete") and self.private is not None:
            raise ValueError(f"a {self.action} change has no private flag")
        if self.action == "create":
            owner = self.owner
            if not isinstance(owner, PrincipalRef) or owner.type not in PRINCIPAL_TYPES \
                    or not nonblank(owner.id):
                raise ValueError("a create needs owner, a PrincipalRef of type " +
                                 ", ".join(PRINCIPAL_TYPES))
            if not nonblank(self.author):
                raise ValueError("a create needs author, the gateway user_id of the person "
                                 "filing it")
            if self.intent is not None:
                raise ValueError("a create needs no intent token (CUT-D1 (3))")
        elif self.owner is not None or self.author is not None:
            raise ValueError("only a create names an owner and an author (owner changes "
                             "go through wolf-access, CUT-D1 (4))")
        if self.intent is not None and not nonblank(self.intent):
            raise ValueError("intent must be a non-empty string")

    @classmethod
    def create(cls, resource: ResourceRef, *, owner: PrincipalRef, author: str,
               parent: ResourceRef | None = None, private: bool | None = None) -> "Change":
        return cls("create", resource, parent=parent, private=private, owner=owner,
                   author=author)

    @classmethod
    def move(cls, resource: ResourceRef, *, parent: ResourceRef | None,
             intent: str | None = None) -> "Change":
        return cls("move", resource, parent=parent, intent=intent)

    @classmethod
    def set_private(cls, resource: ResourceRef, private: bool, *,
                    intent: str | None = None) -> "Change":
        return cls("private", resource, private=private, intent=intent)

    @classmethod
    def delete(cls, resource: ResourceRef, *, intent: str | None = None) -> "Change":
        return cls("delete", resource, intent=intent)

    def wire(self) -> dict[str, Any]:
        """The row's fields as wolf-access takes them (API-D10 (a)), without
        `sequence` and `change_id`."""
        out: dict[str, Any] = {"action": self.action, "resource": _ref_wire(self.resource)}
        if self.action == "create":
            out["owner"] = {"type": self.owner.type, "id": self.owner.id}  # type: ignore[union-attr]
            out["author"] = self.author
            if self.parent is not None:
                out["parent"] = _ref_wire(self.parent)
        elif self.action == "move":
            out["parent"] = None if self.parent is None else _ref_wire(self.parent)
        if self.private is not None:
            out["private"] = self.private
        if self.intent is not None:
            out["intent"] = self.intent
        return out

    @classmethod
    def from_wire(cls, data: Mapping[str, Any]) -> "Change":
        """The `Change` a stored row holds (the inverse of `wire`)."""
        if not isinstance(data, Mapping):
            raise ValueError("a row is an object")
        known = {"sequence", "change_id", "action", "resource", "parent", "private", "owner",
                 "author", "intent"}
        if set(data) - known:
            raise ValueError("a row has unknown fields: " + ", ".join(sorted(set(data) - known)))
        owner = data.get("owner")
        if owner is not None:
            if not isinstance(owner, Mapping) or set(owner) != {"type", "id"}:
                raise ValueError("owner must be {type, id}")
            owner = PrincipalRef(owner["type"], owner["id"])
        parent = data.get("parent")
        return cls(data.get("action"), _ref_from(data.get("resource"), "resource"),  # type: ignore[arg-type]
                   parent=None if parent is None else _ref_from(parent, "parent"),
                   private=data.get("private"), owner=owner, author=data.get("author"),
                   intent=data.get("intent"))


@dataclass(frozen=True)
class OutboxRow:
    """A change in the outbox: its place in the service's gapless sequence,
    its change id, and its last result from wolf-access (`pending` until
    it has one; `reason` says why a row is held or refused)."""

    sequence: int
    change_id: str
    change: Change
    status: str = "pending"
    reason: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) \
                or self.sequence < 1:
            raise ValueError("sequence must be a positive integer")
        if not nonblank(self.change_id):
            raise ValueError("change_id must be a non-empty string")
        if not isinstance(self.change, Change):
            raise ValueError("change must be a Change")
        if self.status not in ROW_STATUSES:
            raise ValueError("status must be one of " + ", ".join(ROW_STATUSES))

    @property
    def resource(self) -> ResourceRef:
        return self.change.resource

    def wire(self) -> dict[str, Any]:
        """The row as `POST /v1/services/{service}/changes` takes it."""
        return {"sequence": self.sequence, "change_id": self.change_id, **self.change.wire()}


@dataclass(frozen=True)
class ChangeResult:
    """wolf-access's answer for one row: `applied`, `held` (waiting in
    sequence, or for the seed import), `refused` (dead-lettered), or
    `resolved` (a refused row reconcile resolved). `reason` is wolf-access's
    explanation for a held or refused row."""

    sequence: int
    status: str
    reason: str | None = None


@dataclass(frozen=True)
class ChangesAnswer:
    """An answer of `POST` or `GET /v1/services/{service}/changes`: one result
    per row, and `applied_through`, the sequence number up to which wolf-access
    has applied every row."""

    results: tuple[ChangeResult, ...]
    applied_through: int


@dataclass(frozen=True)
class OutboxProgress:
    """Where a service's outbox stands: the newest row written
    (`last_sequence`, 0 for none), the row up to which wolf-access has applied
    every row (`applied_through`), and the refused row at the head of the
    sequence, if one is dead-lettered (`dead_letter`)."""

    last_sequence: int
    applied_through: int
    dead_letter: OutboxRow | None = None
