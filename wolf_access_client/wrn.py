"""WRNs: the one shared validator (INT-B3) for `wrn:<service>:<type>/<id>`
(INT-B1, AC-17).

The grammar is wolf-access's, copied byte for byte (owner, 2026-10-10):
`_SEGMENT`, `_WRN` and `parse_wrn` from `wolf_access/registry.py:52-100`, and
the SQL function `canonical_wrn()` from
`migrations/versions/0035_principals_sign_in_invites.py:33-39` (wolf-access
`development` @ ffe20ed). `wrn_conformance.CASES` is the table every copy is
checked against; this package's tests run both the Python parser and the SQL
function over it.

- `<service>` and `<type>` are lower-case segments of 3 to 63 characters,
  `[a-z][a-z0-9_]{1,61}[a-z0-9]`, without `__`.
- `<id>` is 1 to 512 of `[A-Za-z0-9._~-]`. WRN ids are minted as UUIDs
  (INT-OPEN-5, owner 2026-10-10; `Wrn.new`), but the grammar accepts the
  wider set, as wolf-access does.
- Upper-case letters in `<id>` are ACCEPTED and kept: that is wolf-access's
  current behaviour, and wolf-access#331 (whether INT-B2's "lower case"
  covers the id) is open and undecided. The library follows the server so
  the two never disagree; it changes when wolf-access does.
- wolf-access's own WRNs are `wrn:access:<type>/<id>` with `<type>` one of
  `ACCESS_KINDS`; a principal is `wrn:access:user/<id>` or
  `wrn:access:agent/<id>`.

`str(Wrn)` is the only formatter: build a WRN with `Wrn(service, type, id)`
(checked) or `parse_wrn`, never by string formatting. `wrn_lint` is the
check that refuses `"wrn:` literals outside this module.

Every WRN column gets a CHECK constraint (INT-B3): create the function with
`CANONICAL_WRN_SQL` in a migration and add `CHECK (canonical_wrn(<column>))`.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any

__all__ = ["ACCESS_KINDS", "PRINCIPAL_KINDS", "CANONICAL_WRN_SQL", "Wrn", "WrnError",
           "parse_wrn", "is_canonical_wrn"]

#: The types of wolf-access's own WRNs, `wrn:access:<type>/<id>` (Identifiers).
ACCESS_KINDS = ("org", "project", "personal", "user", "agent")
#: The principals, the only subjects of access (INT-C2): `wrn:access:<kind>/<id>`.
PRINCIPAL_KINDS = ("user", "agent")

_SEGMENT = re.compile(r"[a-z][a-z0-9_]{1,61}[a-z0-9]")
_WRN = re.compile(r"wrn:([^:/]+):([^:/]+)/([A-Za-z0-9._~-]{1,512})")  # wrn-ok: the grammar itself

#: The SQL function a WRN column's CHECK constraint calls (INT-B3). It is
#: `CREATE FUNCTION`, as wolf-access's migration 0035 has it: run it once per
#: database, in a migration.
CANONICAL_WRN_SQL = r"""
CREATE FUNCTION canonical_wrn(w text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT w ~ '^wrn:[a-z][a-z0-9_]{1,61}[a-z0-9]:[a-z][a-z0-9_]{1,61}[a-z0-9]/[A-Za-z0-9._~-]+$'
     AND length(split_part(w, '/', 2)) <= 512
     AND position('__' in split_part(w, '/', 1)) = 0
     AND (w !~ '^wrn:access:' OR w ~ '^wrn:access:(org|project|personal|user|agent)/')
$$"""

_MESSAGE = "not a canonical WRN, wrn:<service>:<type>/<id> (AC-17)"


class WrnError(ValueError):
    """A value that is not a canonical WRN. `code` is wolf-access's error code
    for it, `bad_arguments`; the message never repeats the value."""

    code = "bad_arguments"

    def __init__(self, message: str = _MESSAGE) -> None:
        super().__init__(message)
        self.message = message


def _segment_ok(value: str) -> bool:
    return bool(_SEGMENT.fullmatch(value)) and "__" not in value


def _parts(value: Any) -> tuple[str, str, str]:
    """wolf-access's `parse_wrn`, returning the parts."""
    match = _WRN.fullmatch(value) if isinstance(value, str) else None
    if match is None or not (_segment_ok(match.group(1)) and _segment_ok(match.group(2))) \
            or (match.group(1) == "access" and match.group(2) not in ACCESS_KINDS):
        raise WrnError()
    return match.group(1), match.group(2), match.group(3)


@dataclass(frozen=True, repr=False)
class Wrn:
    """A canonical WRN, `wrn:<service>:<type>/<id>`. Constructing one checks
    it, so every `Wrn` is canonical and `str(w)` is its one canonical text.

    `type` is the type's own segment (`task`); `resource_type` is the
    registered type name, `<service>.<type>` (`tasks.task`), which is also
    the AuthZEN `resource.type`. (wolf-access's private copy names the
    segment `kind` and `<service>.<kind>` `type`.)"""

    service: str
    type: str
    id: str

    def __post_init__(self) -> None:
        if not all(isinstance(p, str) for p in (self.service, self.type, self.id)):
            raise WrnError()
        if _parts(f"wrn:{self.service}:{self.type}/{self.id}") != (  # wrn-ok
                self.service, self.type, self.id):
            raise WrnError()

    @classmethod
    def new(cls, service: str, type: str) -> "Wrn":
        """A new WRN with a fresh UUID id (INT-OPEN-5: ids are UUIDs, opaque
        and never reused, INT-B1)."""
        return cls(service, type, str(uuid.uuid4()))

    @property
    def resource_type(self) -> str:
        """`<service>.<type>`: the registered type and AuthZEN `resource.type`."""
        return f"{self.service}.{self.type}"

    @property
    def definition(self) -> str:
        """`<service>/<type>`: the type's SpiceDB definition."""
        return f"{self.service}/{self.type}"

    def __str__(self) -> str:
        return f"wrn:{self.service}:{self.type}/{self.id}"  # wrn-ok

    def __repr__(self) -> str:
        return f"Wrn({str(self)!r})"


def parse_wrn(value: Any) -> Wrn:
    """The WRN `value`, checked against the canonical form (AC-17). Raises
    `WrnError` for anything else, a non-string included."""
    return Wrn(*_parts(value))


def is_canonical_wrn(value: Any) -> bool:
    """Whether `value` is a canonical WRN (the Python twin of the SQL
    `canonical_wrn`)."""
    try:
        _parts(value)
    except WrnError:
        return False
    return True
