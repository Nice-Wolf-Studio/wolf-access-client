"""AuthZEN searches (API-P1, API-D5): resource (list-filter, CLI-3), action
and subject. Each is an iterator that follows `page.next_token` and never
exposes a total; every failure, before or between pages, is
`AccessUnavailable` (CLI-P2)."""
import pytest

from tests.fake_server import FakeWolfAccess, Reply
from wolf_access_client import (
    AccessUnavailable,
    ResourceRef,
    WolfAccessClient,
    WolfAccessResponseError,
)

CRED = "svc-credential-not-a-secret"
RES, ACT, SUB = ("/access/v1/search/resource", "/access/v1/search/action",
                 "/access/v1/search/subject")


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        yield fake


def page(results, next_token="", **extra):
    return Reply(body={"results": results,
                       "page": {"next_token": next_token, "count": len(results), **extra}})


def notes(*ids):
    return [{"type": "wolfnotes/note", "id": i} for i in ids]


def resources(client, **overrides):
    args = dict(user_id="user-1", client_id="client-1", action="view",
                resource_type="wolfnotes/note")
    args.update(overrides)
    return client.search_resources(**args)


def actions(client, **overrides):
    args = dict(user_id="user-1", client_id="client-1", resource_type="wolfnotes/note",
                resource_id="n-1")
    args.update(overrides)
    return client.search_actions(**args)


def subjects(client, **overrides):
    args = dict(user_id="user-1", client_id="client-1", action="view",
                resource_type="wolfnotes/note", resource_id="n-1")
    args.update(overrides)
    return client.search_subjects(**args)


# --- search/resource ---------------------------------------------------------------

def test_resource_search_request_shape(server):
    server.queue("POST", RES, page(notes("n-1")))
    assert list(resources(WolfAccessClient(server.url, CRED))) == [
        ResourceRef("wolfnotes/note", "n-1")]
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("POST", RES)
    assert seen.body == {"subject": {"type": "user", "id": "user-1"},
                         "action": {"name": "view"},
                         "resource": {"type": "wolfnotes/note"},
                         "context": {"client_id": "client-1"}}


def test_resource_search_follows_next_token_until_it_is_empty(server):
    server.queue("POST", RES, page(notes("n-1", "n-2"), "tok-1"), page(notes("n-3"), "tok-2"),
                 page([], ""))
    found = list(resources(WolfAccessClient(server.url, CRED), page_size=2))
    assert [r.id for r in found] == ["n-1", "n-2", "n-3"]
    bodies = [r.body for r in server.requests]
    assert [b.get("page") for b in bodies] == [
        {"limit": 2}, {"limit": 2, "token": "tok-1"}, {"limit": 2, "token": "tok-2"}]
    # Every page repeats the same query (a token works only for its query).
    assert all({k: v for k, v in b.items() if k != "page"} ==
               {k: v for k, v in bodies[0].items() if k != "page"} for b in bodies)


def test_search_is_lazy_and_never_returns_a_total(server):
    server.queue("POST", RES, page(notes("n-1"), "tok-1", total=99), page(notes("n-2")))
    it = resources(WolfAccessClient(server.url, CRED))
    assert iter(it) is it
    assert not hasattr(it, "__len__") and not hasattr(it, "total")
    assert server.requests == []          # nothing is asked until iteration starts
    assert next(it) == ResourceRef("wolfnotes/note", "n-1")
    assert len(server.requests) == 1      # the second page is fetched only when needed
    assert [r.id for r in it] == ["n-2"]


def test_remembered_zedtoken_and_extra_context_are_sent_on_every_page(server):
    server.queue("POST", RES, page(notes("n-1"), "tok-1"), page(notes("n-2")))
    client = WolfAccessClient(server.url, CRED)
    client.remember_zedtoken("zt-3")
    list(resources(client, context={"purpose": "list"}))
    assert [r.body["context"] for r in server.requests] == [
        {"client_id": "client-1", "purpose": "list", "zedtoken": "zt-3"}] * 2


def test_failure_between_pages_raises_after_the_pages_already_given(server):
    server.queue("POST", RES, page(notes("n-1"), "tok-1"),
                 Reply(status=503, raw=b"unavailable", content_type="text/plain"))
    it = resources(WolfAccessClient(server.url, CRED))
    assert next(it).id == "n-1"
    with pytest.raises(AccessUnavailable):
        next(it)


@pytest.mark.parametrize("body", [
    {"results": notes("n-1")},                                             # no page
    {"results": notes("n-1"), "page": {"count": 1}},                       # no next_token
    {"results": notes("n-1"), "page": {"next_token": None, "count": 1}},
    {"results": notes("n-1"), "page": {"next_token": "", "count": 2}},     # count is wrong
    {"results": notes("n-1"), "page": {"next_token": "", "count": True}},
    {"results": {"n-1": 1}, "page": {"next_token": "", "count": 1}},
    {"results": [{"type": "wolfnotes/note"}], "page": {"next_token": "", "count": 1}},
    {"results": [{"type": "wolfnotes/note", "id": ""}], "page": {"next_token": "", "count": 1}},
    {"results": [{"type": "wolfnotes/note", "id": 5}], "page": {"next_token": "", "count": 1}},
    {"results": [{"type": "finops/account", "id": "a-1"}],               # another type
     "page": {"next_token": "", "count": 1}},
    {"results": ["n-1"], "page": {"next_token": "", "count": 1}},
    [],
])
def test_malformed_resource_page_is_a_response_error(server, body):
    server.reply = Reply(body=body)
    with pytest.raises(WolfAccessResponseError):
        list(resources(WolfAccessClient(server.url, CRED)))


def test_a_repeated_next_token_is_a_response_error_not_an_endless_loop(server):
    server.queue("POST", RES, page(notes("n-1"), "tok-1"), page(notes("n-2"), "tok-1"))
    with pytest.raises(WolfAccessResponseError):
        list(resources(WolfAccessClient(server.url, CRED)))


@pytest.mark.parametrize("status", [400, 401, 403, 429, 500, 503])
def test_any_status_but_200_is_access_unavailable(server, status):
    server.reply = Reply(status=status, raw=b"refused", content_type="text/plain")
    with pytest.raises(AccessUnavailable) as exc:
        list(resources(WolfAccessClient(server.url, CRED)))
    assert exc.value.status == status


@pytest.mark.parametrize("size", [0, -1, 1001, True, 2.5, "10"])
def test_page_size_is_1_to_1000(server, size):
    with pytest.raises(ValueError):
        resources(WolfAccessClient(server.url, CRED), page_size=size)
    assert server.requests == []


@pytest.mark.parametrize("field_name", ["user_id", "client_id", "action", "resource_type"])
@pytest.mark.parametrize("value", [None, "", " ", 5])
def test_resource_search_arguments_are_checked_at_the_call(server, field_name, value):
    """Checked when the search is created, not at the first `next()`."""
    with pytest.raises(ValueError):
        resources(WolfAccessClient(server.url, CRED), **{field_name: value})
    assert server.requests == []


@pytest.mark.parametrize("key", ["client_id", "user_id", "zedtoken"])
def test_context_cannot_carry_the_explicit_parameters(server, key):
    client = WolfAccessClient(server.url, CRED)
    for search in (resources, actions, subjects):
        with pytest.raises(ValueError):
            search(client, context={key: "x"})
    assert server.requests == []


# --- search/action -------------------------------------------------------------------

def test_action_search_request_shape_and_results(server):
    server.queue("POST", ACT, Reply(body={"results": [{"name": "view"}, {"name": "edit"}],
                                          "page": {"next_token": "", "count": 2}}))
    assert list(actions(WolfAccessClient(server.url, CRED))) == ["view", "edit"]
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("POST", ACT)
    assert seen.body == {"subject": {"type": "user", "id": "user-1"},
                         "resource": {"type": "wolfnotes/note", "id": "n-1"},
                         "context": {"client_id": "client-1"}}


def test_action_search_paginates(server):
    server.queue("POST", ACT,
                 Reply(body={"results": [{"name": "view"}],
                             "page": {"next_token": "a1", "count": 1}}),
                 Reply(body={"results": [{"name": "share"}],
                             "page": {"next_token": "", "count": 1}}))
    assert list(actions(WolfAccessClient(server.url, CRED), page_size=1)) == ["view", "share"]
    assert server.requests[1].body["page"] == {"limit": 1, "token": "a1"}


@pytest.mark.parametrize("result", [{}, {"name": ""}, {"name": 5}, "view"])
def test_malformed_action_result_is_a_response_error(server, result):
    server.reply = Reply(body={"results": [result], "page": {"next_token": "", "count": 1}})
    with pytest.raises(WolfAccessResponseError):
        list(actions(WolfAccessClient(server.url, CRED)))


@pytest.mark.parametrize("field_name", ["user_id", "client_id", "resource_type",
                                        "resource_id"])
def test_action_search_arguments_are_checked_at_the_call(server, field_name):
    with pytest.raises(ValueError):
        actions(WolfAccessClient(server.url, CRED), **{field_name: ""})
    assert server.requests == []


# --- search/subject ------------------------------------------------------------------

def test_subject_search_request_shape_and_results(server):
    """The AuthZEN subject carries only its type; the person the service is
    serving goes in `context.user_id` (API-D5)."""
    server.queue("POST", SUB, Reply(body={"results": [{"type": "user", "id": "user-1"},
                                                      {"type": "user", "id": "user-2"}],
                                          "page": {"next_token": "", "count": 2}}))
    client = WolfAccessClient(server.url, CRED)
    client.remember_zedtoken("zt-1")
    assert list(subjects(client)) == ["user-1", "user-2"]
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("POST", SUB)
    assert seen.body == {"subject": {"type": "user"},
                         "action": {"name": "view"},
                         "resource": {"type": "wolfnotes/note", "id": "n-1"},
                         "context": {"client_id": "client-1", "user_id": "user-1",
                                     "zedtoken": "zt-1"}}


def test_subject_search_paginates(server):
    server.queue("POST", SUB,
                 Reply(body={"results": [{"type": "user", "id": "u-1"}],
                             "page": {"next_token": "s1", "count": 1}}),
                 Reply(body={"results": [{"type": "user", "id": "u-2"}],
                             "page": {"next_token": "", "count": 1}}))
    assert list(subjects(WolfAccessClient(server.url, CRED), page_size=1)) == ["u-1", "u-2"]
    assert server.requests[1].body["page"] == {"limit": 1, "token": "s1"}


def test_view_without_share_is_access_unavailable_with_its_status(server):
    """403: the caller may see the resource but not who holds it (API-D5)."""
    server.reply = Reply(status=403, raw=b"only a holder of share", content_type="text/plain")
    with pytest.raises(AccessUnavailable) as exc:
        list(subjects(WolfAccessClient(server.url, CRED)))
    assert exc.value.status == 403


@pytest.mark.parametrize("result", [{"type": "org", "id": "o-1"}, {"type": "user"},
                                    {"type": "user", "id": ""}, "user-1"])
def test_malformed_subject_result_is_a_response_error(server, result):
    server.reply = Reply(body={"results": [result], "page": {"next_token": "", "count": 1}})
    with pytest.raises(WolfAccessResponseError):
        list(subjects(WolfAccessClient(server.url, CRED)))


@pytest.mark.parametrize("field_name", ["user_id", "client_id", "action", "resource_type",
                                        "resource_id"])
def test_subject_search_arguments_are_checked_at_the_call(server, field_name):
    with pytest.raises(ValueError):
        subjects(WolfAccessClient(server.url, CRED), **{field_name: None})
    assert server.requests == []
