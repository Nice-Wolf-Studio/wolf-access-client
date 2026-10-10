"""The shared WRN module (issue #50, INT-B3, AC-17): parse, format and
validate with wolf-access's grammar, the `canonical_wrn` SQL text, and the
conformance table every implementation is checked against."""
from __future__ import annotations

import pickle
import uuid

import pytest

from wolf_access_client import wrn as wrn_module
from wolf_access_client.wrn import (
    ACCESS_KINDS,
    CANONICAL_WRN_SQL,
    PRINCIPAL_KINDS,
    Wrn,
    WrnError,
    is_canonical_wrn,
    parse_wrn,
)
from wolf_access_client.wrn_conformance import CASES, WrnCase


# --- the grammar is wolf-access's, byte for byte --------------------------------------

def test_the_patterns_are_wolf_access_registry_patterns():
    """wolf-access `development` @ ffe20ed, `wolf_access/registry.py:52-55`."""
    assert wrn_module._SEGMENT.pattern == r"[a-z][a-z0-9_]{1,61}[a-z0-9]"
    assert wrn_module._WRN.pattern == r"wrn:([^:/]+):([^:/]+)/([A-Za-z0-9._~-]{1,512})"
    assert ACCESS_KINDS == ("org", "project", "personal", "user", "agent")
    assert PRINCIPAL_KINDS == ("user", "agent")


def test_the_sql_function_is_wolf_access_migration_0035():
    """`migrations/versions/0035_principals_sign_in_invites.py:33-39`."""
    assert CANONICAL_WRN_SQL == r"""
CREATE FUNCTION canonical_wrn(w text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT w ~ '^wrn:[a-z][a-z0-9_]{1,61}[a-z0-9]:[a-z][a-z0-9_]{1,61}[a-z0-9]/[A-Za-z0-9._~-]+$'
     AND length(split_part(w, '/', 2)) <= 512
     AND position('__' in split_part(w, '/', 1)) = 0
     AND (w !~ '^wrn:access:' OR w ~ '^wrn:access:(org|project|personal|user|agent)/')
$$"""


# --- the conformance table ------------------------------------------------------------

def test_the_table_holds_every_wolf_access_registry_case():
    """`tests/test_registry.py:38-70` on wolf-access `development` @ ffe20ed."""
    sourced = [c for c in CASES if c.source.startswith("wolf-access")]
    accepted = {c.value for c in sourced if c.accepted}
    refused = [c.value for c in sourced if not c.accepted]
    assert {"wrn:access:user/u1", "wrn:tasks:task/0b9e-4c1a.x_y~z",
            "wrn:wolf_notes:note/N1"} <= accepted
    for value in (None, 5, "", "tasks:task/t1", "wrn:tasks:task", "wrn:tasks:task/",
                  "wrn:Tasks:task/t1", "wrn:tasks:task/t 1", "wrn:tasks:task/t1/x",
                  "wrn:tasks:ta-sk/t1", "wrn:tasks__x:task/t1", "wrn:ab:task/t1",
                  "wrn:tasks:task/" + "x" * 513, "urn:tasks:task/t1"):
        assert value in refused, value
    for kind in ("org", "project", "personal", "user", "agent"):
        assert f"wrn:access:{kind}/x1" in accepted
    for kind in ("team", "person", "client", "orgs"):
        assert f"wrn:access:{kind}/x1" in refused


def test_every_case_is_well_formed():
    assert len({repr(c.value) for c in CASES}) == len(CASES), "a case is listed twice"
    for case in CASES:
        assert isinstance(case, WrnCase) and case.source
        if case.accepted:
            assert isinstance(case.value, str) and len(case.parts) == 3


@pytest.mark.parametrize("case", CASES, ids=lambda c: repr(c.value)[:60])
def test_parse_wrn_agrees_with_the_table(case):
    if case.accepted:
        w = parse_wrn(case.value)
        assert (w.service, w.type, w.id) == case.parts
        assert str(w) == case.value
        assert is_canonical_wrn(case.value)
    else:
        with pytest.raises(WrnError):
            parse_wrn(case.value)
        assert not is_canonical_wrn(case.value)


@pytest.mark.parametrize("case", [c for c in CASES if c.accepted],
                         ids=lambda c: c.value[:60])
def test_the_constructor_agrees_with_the_table(case):
    assert str(Wrn(*case.parts)) == case.value


def test_sql_canonical_wrn_agrees_with_the_table(pg_connect):
    """The SQL function and `parse_wrn` give the same answer on every string
    case (Postgres has no non-string text)."""
    conn = pg_connect()
    try:
        with conn.cursor() as cur:
            cur.execute(CANONICAL_WRN_SQL)
            disagree = []
            for case in CASES:
                if not isinstance(case.value, str):
                    continue
                cur.execute("SELECT canonical_wrn(%s)", (case.value,))
                if cur.fetchone()[0] is not case.accepted:
                    disagree.append(case.value)
        conn.rollback()
    finally:
        conn.close()
    assert disagree == []


# --- the value ------------------------------------------------------------------------

def test_wrn_parts_and_names():
    w = parse_wrn("wrn:tasks:task/t1")
    assert (w.service, w.type, w.id) == ("tasks", "task", "t1")
    assert w.resource_type == "tasks.task"      # AuthZEN resource.type, registry type
    assert w.definition == "tasks/task"         # the SpiceDB definition
    assert str(w) == "wrn:tasks:task/t1"
    assert repr(w) == "Wrn('wrn:tasks:task/t1')"


def test_wrn_is_a_frozen_hashable_value():
    a, b = parse_wrn("wrn:tasks:task/t1"), Wrn("tasks", "task", "t1")
    assert a == b and hash(a) == hash(b) and len({a, b}) == 1
    with pytest.raises(AttributeError):
        a.id = "t2"  # type: ignore[misc]
    assert pickle.loads(pickle.dumps(a)) == a


def test_a_wrn_is_not_equal_to_its_string():
    """Compare `str(w)` to a string explicitly; a WRN never equals text."""
    assert parse_wrn("wrn:tasks:task/t1") != "wrn:tasks:task/t1"


@pytest.mark.parametrize("parts", [
    ("Tasks", "task", "t1"), ("tasks", "task", ""), ("tasks", "ta:sk", "t1"),
    ("tasks", "task", "t1/x"), ("access", "team", "x1"), ("tasks", "task", 5),
    ("tasks", None, "t1"), ("tasks__x", "task", "t1"), ("ab", "task", "t1"),
])
def test_the_constructor_refuses_what_parse_refuses(parts):
    """`str(Wrn)` is the only formatter, so a Wrn is canonical by
    construction."""
    with pytest.raises(WrnError):
        Wrn(*parts)


def test_new_mints_a_uuid_id():
    """INT-OPEN-5, owner 2026-10-10: WRN ids are UUIDs."""
    w = Wrn.new("tasks", "task")
    assert (w.service, w.type) == ("tasks", "task")
    assert str(uuid.UUID(w.id)) == w.id
    assert Wrn.new("tasks", "task") != w
    with pytest.raises(WrnError):
        Wrn.new("Tasks", "task")


def test_upper_case_ids_are_accepted_as_wolf_access_does():
    """wolf-access#331 (open, undecided): the server accepts A-Z in ids, so
    the library does too, and keeps the case."""
    assert parse_wrn("wrn:wolf_notes:note/N1").id == "N1"
    assert parse_wrn("wrn:tasks:task/0B9E4C1A-0000-4000-8000-000000000000").id[0] == "0"


def test_the_error_is_typed_and_names_no_value():
    with pytest.raises(WrnError) as exc:
        parse_wrn("wrn:Tasks:task/secret-ish")
    err = exc.value
    assert isinstance(err, ValueError)
    assert err.code == "bad_arguments"
    assert "secret-ish" not in str(err)
    assert "wrn:<service>:<type>/<id>" in str(err)


def test_the_module_is_exported_from_the_package():
    import wolf_access_client as w
    for name in ("Wrn", "WrnError", "parse_wrn", "is_canonical_wrn", "CANONICAL_WRN_SQL"):
        assert getattr(w, name) is getattr(wrn_module, name)
