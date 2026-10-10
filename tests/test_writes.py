"""The service calls on `/v1` (wolf-access `api.py`, `core.py` on
`development` @ ffe20ed): the type registry (`PUT
/v1/services/{service}/schema`, AC-9), the tree (`POST /v1/resources`,
`GET`/`PATCH`/`DELETE /v1/resources/{wrn}`, AC-1, AC-3, AC-6, AC-7) and
reconcile (`POST /v1/services/{service}/reconcile`, AC-14). Each answer is
checked; a refusal is a typed RFC 9457 problem."""
from datetime import datetime, timezone

import pytest

from tests.fake_server import FakeWolfAccess, Reply, problem
from tests.helpers import CRED, LIST, ORG, TASK, TASK2, make
from wolf_access_client import (
    ConflictError,
    ExchangedToken,
    ForbiddenError,
    NotFoundError,
    ReconcileChange,
    Reconciled,
    Resource,
    SchemaPermission,
    SchemaRole,
    SchemaType,
    UnauthorizedError,
    UnavailableError,
    Versioned,
    WolfAccessResponseError,
    Written,
    Wrn,
    WrnError,
)

JSON = "application/json, application/problem+json"
PRINCIPAL_JWT = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2ln"


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        yield fake


def resource_path(w: Wrn) -> str:
    return f"/v1/resources/{w}"


# --- PUT /v1/services/{service}/schema ------------------------------------------------

TYPES = [SchemaType("tasks.list", allowed_parents=["access.org", "tasks.list"]),
         SchemaType("tasks.task", allowed_parents=("tasks.list",)),
         SchemaType("tasks.comment", registered=False, allowed_parents=["tasks.task"])]
PERMISSIONS = [SchemaPermission("tasks.task.read"),
               SchemaPermission("tasks.task.secret", requires_end_to_end=True)]
ROLES = [SchemaRole("viewer", 10, ["tasks.task.read"])]


def test_register_schema_request_shape(server):
    server.reply = Reply(body={"zedtoken": "zt-schema"})
    client = make(server.url)
    assert client.register_schema(types=TYPES, permissions=PERMISSIONS, roles=ROLES) \
        == Written("zt-schema")
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("PUT", "/v1/services/tasks/schema")
    assert seen.headers["authorization"] == f"Bearer {CRED}"
    assert seen.headers["accept"] == JSON
    assert seen.body == {
        "types": [
            {"type": "tasks.list", "registered": True,
             "allowed_parents": ["access.org", "tasks.list"]},
            {"type": "tasks.task", "registered": True, "allowed_parents": ["tasks.list"]},
            {"type": "tasks.comment", "registered": False, "allowed_parents": ["tasks.task"]}],
        "permissions": [{"name": "tasks.task.read", "requires_end_to_end": False},
                        {"name": "tasks.task.secret", "requires_end_to_end": True}],
        "roles": [{"name": "viewer", "rank": 10, "permissions": ["tasks.task.read"]}]}
    assert client.zedtoken == "zt-schema"


def test_register_schema_with_an_operators_token(server):
    """AC-9: adding a permission to an existing role is made with an
    operator's principal token instead of the service credential."""
    server.reply = Reply(body={"zedtoken": "zt"})
    make(server.url).register_schema(roles=ROLES, principal_token=PRINCIPAL_JWT)
    assert server.requests[0].headers["authorization"] == f"Bearer {PRINCIPAL_JWT}"
    assert server.requests[0].body == {"types": [], "permissions": [], "roles": [
        {"name": "viewer", "rank": 10, "permissions": ["tasks.task.read"]}]}


@pytest.mark.parametrize("name, status, cls", [
    ("forbidden", 403, ForbiddenError), ("conflict", 409, ConflictError),
    ("unavailable", 503, UnavailableError)])
def test_register_schema_refusals_are_typed(server, name, status, cls):
    server.reply = problem(name, status)
    with pytest.raises(cls):
        make(server.url).register_schema(types=TYPES)


@pytest.mark.parametrize("kwargs", [
    {"types": "tasks.task"}, {"types": [{"type": "tasks.task"}]},
    {"permissions": ["tasks.task.read"]}, {"roles": [("viewer", 10)]},
    {"principal_token": "has space"}])
def test_register_schema_checks_its_arguments(server, kwargs):
    with pytest.raises(ValueError):
        make(server.url).register_schema(**kwargs)
    assert server.requests == []


@pytest.mark.parametrize("make_value", [
    lambda: SchemaType(""), lambda: SchemaType("tasks.task", registered="yes"),
    lambda: SchemaType("tasks.task", allowed_parents="tasks.list"),
    lambda: SchemaPermission(" "), lambda: SchemaPermission("p", requires_end_to_end=1),
    lambda: SchemaRole("viewer", "10"), lambda: SchemaRole("viewer", True),
    lambda: SchemaRole("", 1), lambda: SchemaRole("viewer", 1, ["", "x"])])
def test_schema_values_are_checked_when_made(make_value):
    with pytest.raises(ValueError):
        make_value()


# --- POST /v1/resources ---------------------------------------------------------------

def test_create_a_root(server):
    """AC-1: an org is a root; the service credential creates it."""
    server.reply = Reply(status=201, body={"zedtoken": "zt-1", "version": 7})
    client = make(server.url)
    assert client.create_resource(ORG, name="Home") == Versioned(7, "zt-1")
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("POST", "/v1/resources")
    assert seen.body == {"wrn": str(ORG), "parent_wrn": None, "name": "Home"}
    assert seen.headers["authorization"] == f"Bearer {CRED}"
    assert client.zedtoken == "zt-1"


def test_create_under_a_parent_with_the_principals_token(server):
    """AC-3: the create is checked against the principal named in the
    caller's token: the exchanged token goes in Authorization."""
    server.reply = Reply(status=201, body={"zedtoken": "zt-2", "version": 8})
    token = ExchangedToken(PRINCIPAL_JWT, 60, "urn:ietf:params:oauth:token-type:jwt")
    result = make(server.url).create_resource(str(TASK), LIST, principal_token=token)
    assert result == Versioned(8, "zt-2")
    (seen,) = server.requests
    assert seen.body == {"wrn": str(TASK), "parent_wrn": str(LIST)}
    assert seen.headers["authorization"] == f"Bearer {PRINCIPAL_JWT}"


def test_create_takes_the_token_text_too(server):
    server.reply = Reply(status=201, body={"zedtoken": "zt", "version": 1})
    make(server.url).create_resource(TASK, LIST, principal_token=PRINCIPAL_JWT)
    assert server.requests[0].headers["authorization"] == f"Bearer {PRINCIPAL_JWT}"


@pytest.mark.parametrize("name, status, cls", [
    ("not_found", 404, NotFoundError),          # a refused create looks like a missing parent
    ("conflict", 409, ConflictError),           # the WRN exists
    ("unauthorized", 401, UnauthorizedError),   # under a parent without a principal's token
    ("forbidden", 403, ForbiddenError)])        # another service's resource
def test_create_refusals_are_typed(server, name, status, cls):
    server.reply = problem(name, status)
    with pytest.raises(cls):
        make(server.url).create_resource(TASK, LIST, principal_token=PRINCIPAL_JWT)


@pytest.mark.parametrize("body", [
    {"zedtoken": "zt"}, {"version": 1}, {"zedtoken": 5, "version": 1},
    {"zedtoken": "zt", "version": 0}, {"zedtoken": "zt", "version": "1"},
    {"zedtoken": "zt", "version": True}])
def test_a_malformed_create_answer_is_a_response_error(server, body):
    server.reply = Reply(status=201, body=body)
    with pytest.raises(WolfAccessResponseError):
        make(server.url).create_resource(ORG, name="Home")


def test_a_create_answered_200_is_not_the_documented_answer(server):
    server.reply = Reply(status=200, body={"zedtoken": "zt", "version": 1})
    with pytest.raises(WolfAccessResponseError):
        make(server.url).create_resource(ORG, name="Home")


def test_an_empty_token_is_none_and_keeps_the_remembered_one(server):
    server.reply = Reply(status=201, body={"zedtoken": "", "version": 1})
    client = make(server.url)
    client.remember_zedtoken("zt-old")
    assert client.create_resource(ORG, name="Home") == Versioned(1, None)
    assert client.zedtoken == "zt-old"


@pytest.mark.parametrize("args, kwargs, error", [
    (("t1",), {}, WrnError), ((TASK, "l1"), {}, WrnError), ((5,), {}, TypeError),
    ((ORG,), {"name": ""}, ValueError), ((ORG,), {"name": 5}, ValueError),
    ((TASK, LIST), {"principal_token": "a b"}, ValueError)])
def test_create_checks_its_arguments(server, args, kwargs, error):
    with pytest.raises(error):
        make(server.url).create_resource(*args, **kwargs)
    assert server.requests == []


# --- GET /v1/resources/{wrn} -----------------------------------------------------------

def test_get_a_resource(server):
    server.reply = Reply(body={"parent_wrn": str(LIST)})
    assert make(server.url).get_resource(TASK) == Resource(TASK, LIST, None)
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("GET", resource_path(TASK))
    assert seen.headers["authorization"] == f"Bearer {CRED}"


def test_get_a_container_with_its_name(server):
    server.reply = Reply(body={"parent_wrn": None, "name": "Home"})
    assert make(server.url).get_resource(str(ORG)) == Resource(ORG, None, "Home")


def test_get_a_missing_resource_is_not_found(server):
    server.reply = problem("not_found", 404)
    with pytest.raises(NotFoundError):
        make(server.url).get_resource(TASK)


@pytest.mark.parametrize("body", [{}, {"parent_wrn": 5}, {"parent_wrn": "l1"},
                                  {"parent_wrn": None, "name": 5}])
def test_a_malformed_resource_answer_is_a_response_error(server, body):
    server.reply = Reply(body=body)
    with pytest.raises(WolfAccessResponseError):
        make(server.url).get_resource(TASK)


# --- PATCH /v1/resources/{wrn} ---------------------------------------------------------

def test_move_carries_the_version(server):
    server.reply = Reply(body={"zedtoken": "zt-3", "version": 9})
    new_list = Wrn("tasks", "list", "l2")
    assert make(server.url).move_resource(TASK, new_list, version=8) == Versioned(9, "zt-3")
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("PATCH", resource_path(TASK))
    assert seen.body == {"parent_wrn": str(new_list), "version": 8}
    assert seen.headers["authorization"] == f"Bearer {CRED}"


def test_move_to_the_root(server):
    server.reply = Reply(body={"zedtoken": "zt", "version": 2})
    make(server.url).move_resource(ORG, None, version=1)
    assert server.requests[0].body == {"parent_wrn": None, "version": 1}


def test_a_stale_move_is_a_conflict(server):
    server.reply = problem("conflict", 409, "the resource has changed since that version")
    with pytest.raises(ConflictError) as exc:
        make(server.url).move_resource(TASK, LIST, version=3)
    assert "changed" not in str(exc.value) and "changed" in exc.value.detail


@pytest.mark.parametrize("version", [0, -1, None, "8", True, 1.0])
def test_move_and_delete_need_a_version(server, version):
    with pytest.raises((ValueError, TypeError)):
        make(server.url).move_resource(TASK, LIST, version=version)
    with pytest.raises((ValueError, TypeError)):
        make(server.url).delete_resource(TASK, version=version)
    assert server.requests == []


def test_version_is_keyword_only(server):
    with pytest.raises(TypeError):
        make(server.url).move_resource(TASK, LIST, 8)  # type: ignore[misc]
    with pytest.raises(TypeError):
        make(server.url).delete_resource(TASK, 8)  # type: ignore[misc]


# --- DELETE /v1/resources/{wrn}?version= ----------------------------------------------

def test_delete_carries_the_version_in_the_query(server):
    server.reply = Reply(body={"zedtoken": "zt-4"})
    assert make(server.url).delete_resource(TASK2, version=12) == Written("zt-4")
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("DELETE", f"{resource_path(TASK2)}?version=12")
    assert seen.body is None


def test_deleting_a_resource_with_children_is_a_conflict(server):
    server.reply = problem("conflict", 409)
    with pytest.raises(ConflictError):
        make(server.url).delete_resource(LIST, version=2)


# --- POST /v1/services/{service}/reconcile --------------------------------------------

def change(**overrides):
    item = {"id": "7b0c", "service": "tasks", "wrn": str(TASK2), "kind": "move",
            "parent_wrn": str(LIST), "found_at": "2026-10-10T12:00:00.123456+00:00",
            "approved_by": None, "approved_at": None}
    item.update(overrides)
    return item


def test_reconcile_sends_the_full_list(server):
    server.reply = Reply(body={"added": [str(TASK)], "changes": [change()],
                               "zedtoken": "zt-5"})
    client = make(server.url)
    result = client.reconcile([(LIST, ORG), (str(TASK), str(LIST)), (ORG, None)])
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("POST", "/v1/services/tasks/reconcile")
    assert seen.body == {"resources": [
        {"wrn": str(LIST), "parent_wrn": str(ORG)},
        {"wrn": str(TASK), "parent_wrn": str(LIST)},
        {"wrn": str(ORG), "parent_wrn": None}]}
    assert result == Reconciled(
        (TASK,), (ReconcileChange("7b0c", "tasks", TASK2, "move", LIST,
                                  datetime(2026, 10, 10, 12, 0, 0, 123456, timezone.utc)),),
        "zt-5")
    assert client.zedtoken == "zt-5"


def test_reconcile_takes_a_mappings_items(server):
    server.reply = Reply(body={"added": [], "changes": [], "zedtoken": "zt"})
    make(server.url).reconcile({TASK: LIST}.items())
    assert server.requests[0].body == {"resources": [{"wrn": str(TASK),
                                                      "parent_wrn": str(LIST)}]}


def test_an_approved_removal_parses(server):
    server.reply = Reply(body={"added": [], "zedtoken": "zt", "changes": [change(
        kind="removal", parent_wrn=None, approved_by="wrn:access:user/op",  # wrn-ok: answer
        approved_at="2026-10-10T13:00:00+00:00")]})
    (c,) = make(server.url).reconcile([]).changes
    assert (c.kind, c.parent_wrn, c.approved_by) == ("removal", None, "wrn:access:user/op")  # wrn-ok
    assert c.approved_at == datetime(2026, 10, 10, 13, tzinfo=timezone.utc)


@pytest.mark.parametrize("body", [
    {"added": [], "changes": []},                                       # no zedtoken
    {"added": {}, "changes": [], "zedtoken": "zt"},
    {"added": ["t1"], "changes": [], "zedtoken": "zt"},                 # not a WRN
    {"added": [], "changes": [change(kind="delete")], "zedtoken": "zt"},
    {"added": [], "changes": [change(found_at="yesterday")], "zedtoken": "zt"},
    {"added": [], "changes": [change(wrn="t2")], "zedtoken": "zt"},
    {"added": [], "changes": [{"id": "1"}], "zedtoken": "zt"},
])
def test_a_malformed_reconcile_answer_is_a_response_error(server, body):
    server.reply = Reply(body=body)
    with pytest.raises(WolfAccessResponseError):
        make(server.url).reconcile([])


@pytest.mark.parametrize("resources, error", [
    ([TASK], ValueError), ([(TASK,)], ValueError), ([("t1", None)], WrnError),
    ([(TASK, "l1")], WrnError)])
def test_reconcile_checks_the_list(server, resources, error):
    with pytest.raises(error):
        make(server.url).reconcile(resources)
    assert server.requests == []


def test_a_refused_reconcile_is_typed(server):
    server.reply = problem("forbidden", 403)
    with pytest.raises(ForbiddenError):
        make(server.url).reconcile([(TASK, LIST)])
