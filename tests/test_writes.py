"""The service write API, `/v1` (API-D3): register a type, create, update and
delete a resource. A write answers `Written(zedtoken)` (the client then
carries that token, CLI-D2) or `Pending` (202, EVT-D3); a refusal is a typed
RFC 9457 problem; a 503 with `Retry-After` is retryable."""
import pytest

from tests.fake_server import FakeWolfAccess, Reply, problem
from wolf_access_client import (
    AccessUnavailable,
    ConflictError,
    OwnerRequiredError,
    Parent,
    Pending,
    Permission,
    PrincipalRef,
    ProblemError,
    ResourceRef,
    UnavailableError,
    WolfAccessClient,
    WolfAccessHTTPError,
    WolfAccessResponseError,
    WolfAccessUnavailable,
    Written,
)

CRED = "svc-credential-not-a-secret"
OWNER = PrincipalRef.user("user-1")


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        yield fake


def written(token="zt-1", status=200):
    return Reply(status=status, body={"zedtoken": token})


PENDING = Reply(status=202, body={"status": "pending"})


def register(client, **overrides):
    args = dict(permissions=[Permission("comment", ["Editor", "Viewer"]),
                             Permission("export")],
                parents=[Parent("folder", ["wolfnotes/folder"])], topics=True)
    args.update(overrides)
    return client.register_type("wolfnotes/note", **args)


def create(client, **overrides):
    args = dict(owner=OWNER, author="user-1")
    args.update(overrides)
    return client.create_resource("wolfnotes/note", "n-1", **args)


# --- PUT /v1/types/{service}/{type} -------------------------------------------------

def test_register_type_request_shape(server):
    server.reply = written("zt-type")
    result = register(WolfAccessClient(server.url, CRED))
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("PUT", "/v1/types/wolfnotes/note")
    assert seen.body == {
        "permissions": [{"name": "comment", "default_roles": ["Editor", "Viewer"]},
                        {"name": "export", "default_roles": []}],
        "parents": [{"relation": "folder", "parent_types": ["wolfnotes/folder"]}],
        "topics": True,
    }
    assert seen.headers["authorization"] == f"Bearer {CRED}"
    assert seen.headers["content-type"] == "application/json"
    assert result == Written("zt-type")


def test_register_type_defaults(server):
    server.reply = written()
    WolfAccessClient(server.url, CRED).register_type("wolfnotes/note",
                                                     permissions=[Permission("comment")])
    assert server.requests[0].body == {
        "permissions": [{"name": "comment", "default_roles": []}], "parents": [],
        "topics": False}


def test_register_type_pending_is_a_pending_result(server):
    server.reply = PENDING
    client = WolfAccessClient(server.url, CRED)
    assert register(client) == Pending()
    assert client.zedtoken is None


def test_register_type_503_is_retryable_and_stores_nothing(server):
    """A schema change while SpiceDB is unreachable: nothing stored, 503
    `unavailable` with `Retry-After` (API-D3)."""
    server.reply = problem("unavailable", 503, "SpiceDB is unreachable", Retry_After="5")
    client = WolfAccessClient(server.url, CRED)
    with pytest.raises(UnavailableError) as exc:
        register(client)
    assert exc.value.retryable is True and exc.value.retry_after == 5.0
    assert exc.value.status == 503 and exc.value.name == "unavailable"
    assert isinstance(exc.value, ProblemError) and not isinstance(exc.value, AccessUnavailable)
    assert client.zedtoken is None


@pytest.mark.parametrize("resource_type", ["wolfnotes", "wolfnotes/note/x", "/note",
                                           "wolfnotes/", "", None, "a b/c"])
def test_resource_type_is_service_slash_name(server, resource_type):
    with pytest.raises(ValueError):
        WolfAccessClient(server.url, CRED).register_type(resource_type,
                                                         permissions=[Permission("comment")])
    with pytest.raises(ValueError):
        WolfAccessClient(server.url, CRED).delete_resource(resource_type, "n-1")
    assert server.requests == []


@pytest.mark.parametrize("overrides", [
    {"permissions": [{"name": "comment", "default_roles": []}]},
    {"permissions": "comment"},
    {"permissions": [Permission("")]},
    {"permissions": [Permission("comment", "Viewer")]},
    {"permissions": [Permission("comment", [""])]},
    {"parents": [("folder", ["wolfnotes/folder"])]},
    {"parents": [Parent("", ["wolfnotes/folder"])]},
    {"parents": [Parent("folder", [])]},
    {"parents": [Parent("folder", "wolfnotes/folder")]},
    {"topics": "yes"},
    {"topics": None},
])
def test_register_type_arguments_are_checked(server, overrides):
    with pytest.raises(ValueError):
        register(WolfAccessClient(server.url, CRED), **overrides)
    assert server.requests == []


# --- POST /v1/resources ---------------------------------------------------------------

def test_create_resource_request_shape(server):
    server.reply = written("zt-c", status=201)
    client = WolfAccessClient(server.url, CRED)
    assert create(client) == Written("zt-c")
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("POST", "/v1/resources")
    assert seen.body == {"type": "wolfnotes/note", "id": "n-1",
                         "owner": {"type": "user", "id": "user-1"}, "author": "user-1"}
    assert "idempotency-key" not in seen.headers
    assert client.zedtoken == "zt-c"


def test_create_resource_with_parent_and_private(server):
    server.reply = written(status=201)
    create(WolfAccessClient(server.url, CRED),
           owner=PrincipalRef("org", "6f1c0e1a-0000-4000-8000-000000000001"),
           parent=ResourceRef("wolfnotes/folder", "f-1"), private=True)
    assert server.requests[0].body == {
        "type": "wolfnotes/note", "id": "n-1",
        "owner": {"type": "org", "id": "6f1c0e1a-0000-4000-8000-000000000001"},
        "author": "user-1", "parent": {"type": "wolfnotes/folder", "id": "f-1"},
        "private": True}


def test_create_resource_private_false_is_sent(server):
    server.reply = written(status=201)
    create(WolfAccessClient(server.url, CRED), private=False)
    assert server.requests[0].body["private"] is False


def test_idempotency_key_is_sent_as_a_header(server):
    server.reply = written(status=201)
    create(WolfAccessClient(server.url, CRED), idempotency_key="create-n-1-attempt")
    assert server.requests[0].headers["idempotency-key"] == "create-n-1-attempt"


@pytest.mark.parametrize("key", ["", " ", "a\r\nX-Evil: 1", "tab\tkey", "café", 5,
                                 b"key", " lead", "trail "])
def test_idempotency_key_must_be_a_printable_ascii_string(server, key):
    with pytest.raises(ValueError):
        create(WolfAccessClient(server.url, CRED), idempotency_key=key)
    assert server.requests == []


def test_create_resource_pending(server):
    server.reply = PENDING
    client = WolfAccessClient(server.url, CRED)
    assert create(client) == Pending()
    assert client.zedtoken is None


@pytest.mark.parametrize("overrides", [
    {"owner": None}, {"owner": "user-1"}, {"owner": {"type": "user", "id": "user-1"}},
    {"owner": PrincipalRef("team", "x")}, {"owner": PrincipalRef("user", "")},
    {"author": None}, {"author": ""}, {"author": 5},
    {"parent": ("wolfnotes/folder", "f-1")}, {"parent": ResourceRef("wolfnotes/folder", "")},
    {"private": "true"}, {"private": 1},
])
def test_create_resource_arguments_are_checked(server, overrides):
    with pytest.raises(ValueError):
        create(WolfAccessClient(server.url, CRED), **overrides)
    assert server.requests == []


@pytest.mark.parametrize("resource_id", ["", None, 5])
def test_resource_id_is_a_non_empty_string(server, resource_id):
    client = WolfAccessClient(server.url, CRED)
    with pytest.raises(ValueError):
        client.create_resource("wolfnotes/note", resource_id, owner=OWNER, author="user-1")
    with pytest.raises(ValueError):
        client.update_resource("wolfnotes/note", resource_id, private=False)
    with pytest.raises(ValueError):
        client.delete_resource("wolfnotes/note", resource_id)
    assert server.requests == []


def test_owner_required_is_typed(server):
    server.reply = problem("owner_required", 422, "a resource needs an owner (OWN-3)")
    with pytest.raises(OwnerRequiredError) as exc:
        create(WolfAccessClient(server.url, CRED))
    assert exc.value.detail == "a resource needs an owner (OWN-3)"
    assert exc.value.retryable is False


def test_re_creating_a_deleted_id_is_a_conflict(server):
    """DELETE leaves a tombstone; a re-POST of that id is 409 `conflict`."""
    server.queue("DELETE", "/v1/resources/wolfnotes/note/n-1", written("zt-d"))
    server.queue("POST", "/v1/resources", problem("conflict", 409, "this resource already exists"))
    client = WolfAccessClient(server.url, CRED)
    assert client.delete_resource("wolfnotes/note", "n-1") == Written("zt-d")
    with pytest.raises(ConflictError):
        create(client)
    assert client.zedtoken == "zt-d"


# --- PATCH / DELETE /v1/resources/{type}/{id} ----------------------------------------

@pytest.mark.parametrize("kwargs, body", [
    ({"parent": ResourceRef("wolfnotes/folder", "f-2")},
     {"parent": {"type": "wolfnotes/folder", "id": "f-2"}}),
    ({"parent": None}, {"parent": None}),
    ({"private": True}, {"private": True}),
    ({"private": False, "parent": None}, {"private": False, "parent": None}),
])
def test_update_resource_sends_only_the_fields_given(server, kwargs, body):
    server.reply = written("zt-u")
    client = WolfAccessClient(server.url, CRED)
    assert client.update_resource("wolfnotes/note", "n-1", **kwargs) == Written("zt-u")
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("PATCH", "/v1/resources/wolfnotes/note/n-1")
    assert seen.body == body
    assert client.zedtoken == "zt-u"


@pytest.mark.parametrize("kwargs", [{}, {"private": None}, {"private": "no"},
                                    {"parent": ("wolfnotes/folder", "f-1")}])
def test_update_resource_needs_a_valid_parent_or_private(server, kwargs):
    with pytest.raises(ValueError):
        WolfAccessClient(server.url, CRED).update_resource("wolfnotes/note", "n-1", **kwargs)
    assert server.requests == []


def test_update_resource_cannot_change_the_owner(server):
    """Owner changes go through OWN-5 / OWN-D4, never PATCH (API-D3)."""
    with pytest.raises(TypeError):
        WolfAccessClient(server.url, CRED).update_resource("wolfnotes/note", "n-1",
                                                           owner=OWNER)
    assert server.requests == []


def test_delete_resource_request_shape(server):
    server.reply = written("zt-del")
    client = WolfAccessClient(server.url, CRED)
    assert client.delete_resource("wolfnotes/note", "n-1") == Written("zt-del")
    (seen,) = server.requests
    assert (seen.method, seen.path, seen.body) == (
        "DELETE", "/v1/resources/wolfnotes/note/n-1", None)
    assert seen.headers.get("content-length", "0") == "0"


def test_resource_id_is_percent_encoded_in_the_path(server):
    server.reply = written()
    client = WolfAccessClient(server.url, CRED)
    client.delete_resource("wolfnotes/note", "a/b c?d#e%f")
    client.update_resource("wolfnotes/note", "a/b c?d#e%f", private=False)
    assert [r.path for r in server.requests] == [
        "/v1/resources/wolfnotes/note/a%2Fb%20c%3Fd%23e%25f"] * 2


def test_update_and_delete_pending(server):
    server.reply = PENDING
    client = WolfAccessClient(server.url, CRED)
    assert client.update_resource("wolfnotes/note", "n-1", private=False) == Pending()
    assert client.delete_resource("wolfnotes/note", "n-1") == Pending()


# --- ZedToken carried to the next decision (CLI-D2) ----------------------------------

def test_a_write_s_zedtoken_is_sent_with_the_next_decision(server):
    server.queue("POST", "/v1/resources", written("zt-after-create", status=201))
    server.queue("POST", "/access/v1/evaluation", Reply(body={"decision": True}))
    client = WolfAccessClient(server.url, CRED)
    create(client)
    client.evaluation(user_id="user-1", client_id="client-1", action="view",
                      resource_type="wolfnotes/note", resource_id="n-1")
    assert server.requests[1].body["context"] == {"client_id": "client-1",
                                                  "zedtoken": "zt-after-create"}


# --- malformed and failed writes -----------------------------------------------------

@pytest.mark.parametrize("reply", [
    Reply(status=200, body={}),
    Reply(status=200, body={"zedtoken": ""}),
    Reply(status=201, body={"zedtoken": 5}),
    Reply(status=200, body=[]),
    Reply(status=200, raw=b"not json"),
    Reply(status=202, body={"status": "done"}),
    Reply(status=202, body={}),
    Reply(status=204, raw=b""),
    Reply(status=206, body={"zedtoken": "zt"}),
])
def test_malformed_write_answer_is_a_response_error(server, reply):
    server.reply = reply
    client = WolfAccessClient(server.url, CRED)
    with pytest.raises(WolfAccessResponseError):
        create(client)
    assert client.zedtoken is None


def test_unreachable_write_is_unavailable_and_retryable():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        client = WolfAccessClient(f"http://127.0.0.1:{s.getsockname()[1]}", CRED, timeout=1)
        with pytest.raises(WolfAccessUnavailable) as exc:
            create(client)
    assert exc.value.retryable is True


@pytest.mark.parametrize("status, retryable", [(502, True), (504, True), (404, False),
                                               (307, False), (408, True)])
def test_non_problem_error_is_an_http_error(server, status, retryable):
    """An answer that is not a wolf-access problem (e.g. an HTML error page
    from the edge) is a plain `WolfAccessHTTPError`, retryable on 408 and 5xx."""
    server.reply = Reply(status=status, raw=b"<html>bad gateway</html>",
                         content_type="text/html")
    with pytest.raises(WolfAccessHTTPError) as exc:
        create(WolfAccessClient(server.url, CRED))
    assert not isinstance(exc.value, ProblemError)
    assert exc.value.status == status and exc.value.retryable is retryable
