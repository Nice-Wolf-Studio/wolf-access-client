"""Filing an access request for the person the service is serving (REQ-D1,
API-D3 `POST /v1/requests`): the request is stored and decided in
wolf-access; the library holds no request or approval state. `user_id` and
`client_id` are the gateway Caller's, passed explicitly (API-D8, CLI-P1)."""
import pytest

from tests.fake_server import FakeWolfAccess, Reply, problem
from wolf_access_client import (
    ConflictError,
    ForbiddenError,
    PrincipalRef,
    RequestFiled,
    ResourceRef,
    WolfAccessClient,
    WolfAccessResponseError,
)

CRED = "svc-credential-not-a-secret"
FILED = Reply(status=201, body={"request": "r-1", "continue": "c-secret"})


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        yield fake


def test_request_on_a_resource(server):
    server.reply = FILED
    out = WolfAccessClient(server.url, CRED).request_access(
        user_id="user-1", client_id="client-1",
        resource=ResourceRef("wolfnotes/note", "n-1"), role="Editor", reason="to fix typos")
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("POST", "/v1/requests")
    assert seen.body == {"user_id": "user-1", "client_id": "client-1",
                         "target": {"resource": {"type": "wolfnotes/note", "id": "n-1"}},
                         "role": "Editor", "reason": "to fix typos"}
    assert out == RequestFiled(request="r-1", continue_token="c-secret")
    assert "c-secret" not in repr(out)


def test_request_on_a_membership_scope_or_hint(server):
    server.reply = FILED
    client = WolfAccessClient(server.url, CRED)
    client.request_access(user_id="u", client_id="c", resource=PrincipalRef("org", "o-1"),
                          role="Viewer")
    scope = {"type": "wolfnotes/note", "locations": ["org:o-1"]}
    client.request_access(user_id="u", client_id="c", scope=scope, role="Viewer")
    client.request_access(user_id="u", client_id="c", hint="h-1", role="Viewer")
    targets = [s.body["target"] for s in server.requests]
    assert targets == [{"resource": {"type": "org", "id": "o-1"}}, {"scope": scope},
                       {"hint": "h-1"}]
    assert all("reason" not in s.body for s in server.requests)


@pytest.mark.parametrize("kwargs", [
    {},                                                               # no target
    {"resource": ResourceRef("wolfnotes/note", "n"), "hint": "h"},    # two targets
    {"resource": PrincipalRef.user("someone")},                       # a person is no target
    {"scope": {"locations": ["org:o"]}},                              # scope without type
    {"hint": ""},
])
def test_exactly_one_well_formed_target(server, kwargs):
    with pytest.raises(ValueError):
        WolfAccessClient(server.url, CRED).request_access(user_id="u", client_id="c",
                                                          role="Viewer", **kwargs)
    assert server.requests == []


@pytest.mark.parametrize("missing", ["user_id", "client_id", "role"])
def test_caller_and_role_are_required(server, missing):
    args = dict(user_id="u", client_id="c", role="Viewer")
    args[missing] = ""
    with pytest.raises(ValueError):
        WolfAccessClient(server.url, CRED).request_access(
            resource=ResourceRef("wolfnotes/note", "n"), **args)


def test_idempotency_key_is_sent(server):
    server.reply = FILED
    WolfAccessClient(server.url, CRED).request_access(
        user_id="u", client_id="c", resource=ResourceRef("wolfnotes/note", "n"),
        role="Viewer", idempotency_key="req-n-1")
    assert server.requests[0].headers["idempotency-key"] == "req-n-1"


def test_refusals_are_typed(server):
    client = WolfAccessClient(server.url, CRED)
    server.reply = problem("conflict", 409, "held by the cooldown")
    with pytest.raises(ConflictError):
        client.request_access(user_id="u", client_id="c",
                              resource=ResourceRef("wolfnotes/note", "n"), role="Viewer")
    server.reply = problem("forbidden", 403)
    with pytest.raises(ForbiddenError):
        client.request_access(user_id="u", client_id="c",
                              resource=ResourceRef("other/thing", "n"), role="Viewer")


def test_a_malformed_answer_is_an_error(server):
    server.reply = Reply(status=201, body={"request": "r-1"})
    with pytest.raises(WolfAccessResponseError):
        WolfAccessClient(server.url, CRED).request_access(
            user_id="u", client_id="c", resource=ResourceRef("wolfnotes/note", "n"),
            role="Viewer")
