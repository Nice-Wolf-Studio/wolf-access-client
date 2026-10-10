"""The WRN conformance table (INT-B3, AC-17): values every WRN implementation
must accept or refuse, and the parts of each accepted one.

Run any copy of the grammar over `CASES` (a Python parser, a SQL CHECK, a
service's own validator) and fail on the first disagreement. This package's
tests run `wrn.parse_wrn`, the `Wrn` constructor and the SQL
`CANONICAL_WRN_SQL` function over every case. Non-string values exist only
for parsers that take any value; skip them for SQL.

The `wolf-access` cases are wolf-access's own,
`tests/test_registry.py:38-70` on `development` @ ffe20ed; the
`wolf-access-client` cases add edges of the same grammar (segment and id
lengths, characters, upper case: wolf-access#331).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["WrnCase", "CASES"]

_REGISTRY = "wolf-access tests/test_registry.py"
_HERE = "wolf-access-client"


@dataclass(frozen=True)
class WrnCase:
    """One value and the answer: `parts` = `(service, type, id)` when it is
    accepted, None when it is refused."""

    value: Any
    parts: tuple[str, str, str] | None
    source: str
    note: str = ""

    @property
    def accepted(self) -> bool:
        return self.parts is not None


def _ok(value: str, parts: tuple[str, str, str], source: str = _HERE,
        note: str = "") -> WrnCase:
    return WrnCase(value, parts, source, note)


def _no(value: Any, source: str = _HERE, note: str = "") -> WrnCase:
    return WrnCase(value, None, source, note)


_SEG63 = "a" + "b" * 61 + "c"
_SEG64 = "a" + "b" * 62 + "c"
_UUID = "0b9e4c1a-6f2d-4e8b-9a71-3c5d2e1f0a9b"

CASES: tuple[WrnCase, ...] = (
    # wolf-access test_ac17_a_canonical_wrn_parses
    _ok("wrn:access:user/u1", ("access", "user", "u1"), _REGISTRY),
    _ok("wrn:tasks:task/0b9e-4c1a.x_y~z", ("tasks", "task", "0b9e-4c1a.x_y~z"), _REGISTRY),
    _ok("wrn:wolf_notes:note/N1", ("wolf_notes", "note", "N1"), _REGISTRY,
        "upper case in the id is accepted (wolf-access#331, undecided)"),
    # wolf-access test_ac17_anything_else_is_refused
    _no(None, _REGISTRY), _no(5, _REGISTRY), _no("", _REGISTRY),
    _no("tasks:task/t1", _REGISTRY), _no("wrn:tasks:task", _REGISTRY),
    _no("wrn:tasks:task/", _REGISTRY), _no("wrn:Tasks:task/t1", _REGISTRY),
    _no("wrn:tasks:task/t 1", _REGISTRY), _no("wrn:tasks:task/t1/x", _REGISTRY),
    _no("wrn:tasks:ta-sk/t1", _REGISTRY), _no("wrn:tasks__x:task/t1", _REGISTRY),
    _no("wrn:ab:task/t1", _REGISTRY), _no("wrn:tasks:task/" + "x" * 513, _REGISTRY),
    _no("urn:tasks:task/t1", _REGISTRY),
    # wolf-access test_ac17_an_access_wrn_names_one_of_the_identifier_types
    *(_ok(f"wrn:access:{k}/x1", ("access", k, "x1"), _REGISTRY)
      for k in ("org", "project", "personal", "user", "agent")),
    *(_no(f"wrn:access:{k}/x1", _REGISTRY) for k in ("team", "person", "client", "orgs")),
    # edges of the same grammar
    _ok("wrn:abc:def/x", ("abc", "def", "x"), note="3-character segments, 1-character id"),
    _ok(f"wrn:{_SEG63}:{_SEG63}/1", (_SEG63, _SEG63, "1"), note="63-character segments"),
    _ok("wrn:tasks:task/" + "x" * 512, ("tasks", "task", "x" * 512), note="512-character id"),
    _ok(f"wrn:tasks:task/{_UUID}", ("tasks", "task", _UUID), note="a UUID id (INT-OPEN-5)"),
    _ok(f"wrn:tasks:task/{_UUID.upper()}", ("tasks", "task", _UUID.upper()),
        note="an upper-case UUID is accepted and kept (wolf-access#331)"),
    _ok("wrn:a_b:c_d/._~-", ("a_b", "c_d", "._~-"), note="single _ and every id symbol"),
    _ok("wrn:t1_2:t99/0", ("t1_2", "t99", "0"), note="digits after the first letter"),
    _no(f"wrn:{_SEG64}:task/t1", note="64-character service"),
    _no(f"wrn:tasks:{_SEG64}/t1", note="64-character type"),
    _no("wrn:tasks:ta/t1", note="2-character type"),
    _no("wrn:tasks_:task/t1", note="a segment ends in _"),
    _no("wrn:1asks:task/t1", note="a segment starts with a digit"),
    _no("wrn:_tasks:task/t1", note="a segment starts with _"),
    _no("wrn:tasks:task__x/t1", note="__ in the type"),
    _no("wrn:tasks:tAsk/t1", note="upper case in the type"),
    _no("WRN:tasks:task/t1", note="upper-case scheme"),
    _no(" wrn:tasks:task/t1", note="leading space"),
    _no("wrn:tasks:task/t1 ", note="trailing space"),
    _no("wrn:tasks:task/t1\n", note="trailing newline"),
    _no("wrn::task/t1", note="empty service"),
    _no("wrn:tasks:/t1", note="empty type"),
    _no("wrn:tasks:task:x/t1", note="a third segment"),
    _no("wrn:tasks/task/t1", note="/ for :"),
    _no("wrn:tasks:task/t:1", note=": in the id"),
    _no("wrn:tasks:task/t#1", note="# in the id"),
    _no("wrn:tasks:task/t%201", note="percent-encoding in the id"),
    _no("wrn:tasks:task/café", note="a non-ASCII letter in the id"),
    _no("wrn:täsks:task/t1", note="a non-ASCII letter in a segment"),
    _no("wrn:access:Org/x1", note="wolf-access's own types are lower case"),
    _no("wrn:access:org/", note="an access WRN with no id"),
    _no(b"wrn:tasks:task/t1", note="bytes are not text"),
)
