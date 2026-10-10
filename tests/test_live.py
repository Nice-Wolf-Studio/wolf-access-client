"""The client against a real wolf-access `development` server (Postgres and
SpiceDB behind it), seeded by `scripts/live_wolf_access.py`.

Skipped unless `WAC_LIVE` names the JSON file that script wrote; CI does not
run it (wolf-access is private, and CI installs nothing with credentials).
Every run makes fresh WRNs, so it can run again against the same server."""
from __future__ import annotations

import base64
import json
import os

import pytest

from wolf_access_client import (
    ACCESS_AUDIENCE,
    ConflictError,
    Decision,
    EvaluationItem,
    NotFoundError,
    SchemaPermission,
    SchemaRole,
    SchemaType,
    TokenExchangeError,
    UnauthorizedError,
    WolfAccessClient,
    Wrn,
    parse_wrn,
)

LIVE = os.environ.get("WAC_LIVE", "").strip()
pytestmark = pytest.mark.skipif(not LIVE, reason="WAC_LIVE is not set (see "
                                                 "scripts/live_wolf_access.py)")
APP = Wrn("gateway", "client", "app-1")


@pytest.fixture(scope="module")
def live():
    with open(LIVE) as f:
        info = json.load(f)
    client = WolfAccessClient(info["url"], info["tasks_credential"], service="tasks",
                              timeout=15)
    return client, {k: parse_wrn(v) for k, v in info.items()
                    if k not in ("url", "tasks_credential")}


def test_the_whole_lifecycle(live):
    client, w = live
    org, builder, reader, stranger = w["org"], w["builder"], w["reader"], w["stranger"]

    # INT-D1: registering what is registered again is additive and accepted.
    written = client.register_schema(
        types=[SchemaType("tasks.list", allowed_parents=["access.org", "tasks.list"]),
               SchemaType("tasks.task", allowed_parents=["tasks.list"])],
        permissions=[SchemaPermission("tasks.task.read"),
                     SchemaPermission("tasks.task.secret", requires_end_to_end=True)],
        roles=[SchemaRole("reader", 10, ["tasks.list.read", "tasks.task.read",
                                         "tasks.task.secret", "tasks.use"])])
    assert written.zedtoken

    # INT-C5 / AC-20: the builder's token for wolf-access's own calls.
    token = client.exchange_token(builder, ACCESS_AUDIENCE, client_wrn=APP)
    assert token.expires_in <= 60 and token.access_token.count(".") == 2

    # AC-3: create under a parent with the principal's token.
    lst, task = Wrn.new("tasks", "list"), Wrn.new("tasks", "task")
    created = client.create_resource(lst, org, principal_token=token)
    assert created.version >= 1 and created.zedtoken
    t = client.create_resource(task, lst, principal_token=token)
    with pytest.raises(UnauthorizedError):          # under a parent, no principal's token
        client.create_resource(Wrn.new("tasks", "task"), lst)
    with pytest.raises(ConflictError):               # the WRN exists
        client.create_resource(task, lst, principal_token=token)
    with pytest.raises(NotFoundError):               # AC-15: a missing parent
        client.create_resource(Wrn.new("tasks", "task"), Wrn.new("tasks", "list"),
                               principal_token=token)

    got = client.get_resource(task)
    assert got.wrn == task and got.parent_wrn == lst and got.name is None
    assert client.get_resource(org).name == "Home"
    with pytest.raises(NotFoundError):
        client.get_resource(Wrn.new("tasks", "task"))

    # AuthZEN with WRN subjects, after the writes (consistency token sent).
    assert client.evaluation(subject=reader, action="tasks.task.read", resource=task,
                             client_wrn=APP).allowed
    assert not client.evaluation(subject=stranger, action="tasks.task.read", resource=task,
                                 client_wrn=APP).allowed
    # AC-19: a permission that requires end-to-end encryption.
    assert not client.evaluation(subject=reader, action="tasks.task.secret", resource=task,
                                 client_wrn=APP).allowed
    assert client.evaluation(subject=reader, action="tasks.task.secret", resource=task,
                             client_wrn=APP, end_to_end=True).allowed
    # AC-15: a missing resource is a deny like any other.
    assert not client.evaluation(subject=reader, action="tasks.task.read",
                                 resource=Wrn.new("tasks", "task"), client_wrn=APP).allowed

    decisions = client.evaluations(subject=reader, client_wrn=APP, items=[
        EvaluationItem("tasks.task.read", task), EvaluationItem("tasks.list.read", lst),
        EvaluationItem("tasks.task.nope", task)])           # an unregistered permission
    assert [d.allowed for d in decisions] == [True, True, False]
    assert decisions[2].error is not None
    assert client.evaluations(subject=reader, client_wrn=APP, semantic="deny_on_first_deny",
                              items=[EvaluationItem("tasks.task.read", Wrn.new("tasks", "task")),
                                     EvaluationItem("tasks.task.read", task)]) == [
        Decision(False), Decision(False, evaluated=False)]

    found = list(client.search_resources(subject=reader, action="tasks.task.read",
                                         resource_type="tasks.task", client_wrn=APP,
                                         page_size=1))
    assert task in found and all(f.resource_type == "tasks.task" for f in found)

    # AC-6: a move carries the version; a stale one is refused.
    lst2 = Wrn.new("tasks", "list")
    client.create_resource(lst2, org, principal_token=client.exchange_token(builder, "access"))
    moved = client.move_resource(task, lst2, version=t.version)
    assert moved.version > t.version
    assert client.get_resource(task).parent_wrn == lst2
    with pytest.raises(ConflictError):
        client.move_resource(task, lst, version=t.version)

    # AC-7: a list with children is not deleted; a stale delete is refused.
    with pytest.raises(ConflictError):
        client.delete_resource(lst2, version=1)
    with pytest.raises(ConflictError):
        client.delete_resource(task, version=t.version)
    assert client.delete_resource(task, version=moved.version).zedtoken
    with pytest.raises(NotFoundError):
        client.get_resource(task)

    # AC-14: the full list; an addition applies at once, a removal waits.
    extra = Wrn.new("tasks", "list")
    result = client.reconcile([(lst, org), (lst2, org), (extra, org)])
    assert extra in result.added
    assert client.get_resource(extra).parent_wrn == org
    result = client.reconcile([(lst, org), (extra, org)])
    assert any(c.wrn == lst2 and c.kind == "removal" for c in result.changes)


def test_token_exchange_refusals_are_typed(live):
    client, w = live
    with pytest.raises(TokenExchangeError) as exc:
        client.exchange_token(w["stranger"], ACCESS_AUDIENCE)   # holds no tasks.use
    assert (exc.value.status, exc.value.error) == (400, "invalid_request")
    with pytest.raises(TokenExchangeError) as exc:
        client.exchange_token(w["builder"], "notes")             # no notes.use
    assert exc.value.error == "invalid_target"


def test_a_wrong_credential_is_refused(live):
    client, w = live
    other = WolfAccessClient(client._target.display, "not-the-credential", service="tasks")
    with pytest.raises(UnauthorizedError):
        other.get_resource(w["org"])
    with pytest.raises(TokenExchangeError) as exc:
        other.exchange_token(w["builder"], ACCESS_AUDIENCE)
    assert (exc.value.status, exc.value.error) == (401, "invalid_client")


def test_client_wrn_reaches_the_token_on_a_server_that_reads_it(live):
    """wolf-access#334 / PR #339: the optional `client_wrn` form parameter
    becomes the token's `client_wrn` claim. A server with #339 also stamps
    `iat` and `jti`; one without it (development @ ffe20ed) ignores the
    parameter, and the token names no app."""
    client, w = live
    token = client.exchange_token(w["builder"], ACCESS_AUDIENCE, client_wrn=APP)
    part = token.access_token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    assert claims["sub"] == str(w["builder"]) and claims["act"] == {"sub": "tasks"}
    if "jti" in claims:
        assert claims["client_wrn"] == str(APP)
    else:
        assert "client_wrn" not in claims
