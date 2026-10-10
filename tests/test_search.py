"""AuthZEN `search/resource` (INT-F2, wolf-access `api.py` `search_resource`):
the WRNs of one type a principal may act on through an app. An iterator that
follows `page.next_token` and never exposes a total; every failure, before or
between pages, is `AccessUnavailable` (INT-F4). wolf-access `development`
serves no action or subject search."""
import pytest

from tests.fake_server import FakeWolfAccess, Reply
from tests.helpers import APP, USER, make
from wolf_access_client import AccessUnavailable, Wrn, WolfAccessResponseError, WrnError

RES = "/access/v1/search/resource"
T1, T2, T3 = (Wrn("tasks", "task", i) for i in ("t1", "t2", "t3"))


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        yield fake


def page(results, next_token="", **extra):
    return Reply(body={"results": results,
                       "page": {"next_token": next_token, "count": len(results), **extra}})


def tasks(*wrns):
    return [{"type": "tasks.task", "id": str(w)} for w in wrns]


def resources(client, **overrides):
    args = dict(subject=USER, action="tasks.task.read", resource_type="tasks.task",
                client_wrn=APP)
    args.update(overrides)
    return client.search_resources(**args)


def test_resource_search_request_shape(server):
    server.reply = page(tasks(T1))
    assert list(resources(make(server.url))) == [T1]
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("POST", RES)
    assert seen.body == {"subject": {"type": "user", "id": str(USER)},
                         "action": {"name": "tasks.task.read"},
                         "resource": {"type": "tasks.task"},
                         "context": {"client_wrn": str(APP), "end_to_end": False}}


def test_search_sends_no_consistency_token(server):
    """wolf-access's search reads no `consistency_token`; none is sent."""
    server.reply = page([])
    client = make(server.url)
    client.remember_zedtoken("zt-1")
    list(resources(client, end_to_end=True))
    assert server.requests[0].body["context"] == {"client_wrn": str(APP), "end_to_end": True}


def test_resource_search_follows_next_token_until_it_is_empty(server):
    server.queue("POST", RES, page(tasks(T1), "tok-1"), page(tasks(T2), "tok-2"),
                 page(tasks(T3), ""))
    assert list(resources(make(server.url), page_size=1)) == [T1, T2, T3]
    assert [r.body.get("page") for r in server.requests] == [
        {"limit": 1}, {"limit": 1, "token": "tok-1"}, {"limit": 1, "token": "tok-2"}]


def test_search_is_lazy_and_never_returns_a_total(server):
    server.queue("POST", RES, page(tasks(T1, T2), "tok-1"), page(tasks(T3)))
    it = resources(make(server.url))
    assert server.requests == []
    assert next(it) == T1
    assert len(server.requests) == 1
    assert not hasattr(it, "__len__")


def test_failure_between_pages_raises_after_the_pages_already_given(server):
    server.queue("POST", RES, page(tasks(T1), "tok-1"),
                 Reply(status=503, raw=b"unavailable", content_type="text/plain"))
    it = resources(make(server.url))
    assert next(it) == T1
    with pytest.raises(AccessUnavailable):
        next(it)


@pytest.mark.parametrize("body", [
    {"results": tasks(T1)},                                                # no page
    {"results": tasks(T1), "page": {"count": 1}},                          # no next_token
    {"results": tasks(T1), "page": {"next_token": None, "count": 1}},
    {"results": tasks(T1), "page": {"next_token": "", "count": 2}},        # count is wrong
    {"results": tasks(T1), "page": {"next_token": "", "count": True}},
    {"results": {"t1": 1}, "page": {"next_token": "", "count": 1}},
    {"results": [{"type": "tasks.task"}], "page": {"next_token": "", "count": 1}},
    {"results": [{"type": "tasks.task", "id": "t1"}],                    # not a WRN
     "page": {"next_token": "", "count": 1}},
    {"results": [{"type": "tasks.task", "id": 5}], "page": {"next_token": "", "count": 1}},
    {"results": [{"type": "tasks.list", "id": str(Wrn("tasks", "list", "l1"))}],
     "page": {"next_token": "", "count": 1}},                             # another type
    {"results": [{"type": "tasks.task", "id": str(Wrn("tasks", "list", "l1"))}],
     "page": {"next_token": "", "count": 1}},                             # id of another type
    {"results": [str(T1)], "page": {"next_token": "", "count": 1}},
    [],
])
def test_malformed_resource_page_is_a_response_error(server, body):
    server.reply = Reply(body=body)
    with pytest.raises(WolfAccessResponseError):
        list(resources(make(server.url)))


def test_a_repeated_next_token_is_a_response_error_not_an_endless_loop(server):
    server.queue("POST", RES, page(tasks(T1), "tok-1"), page(tasks(T2), "tok-1"))
    with pytest.raises(WolfAccessResponseError):
        list(resources(make(server.url)))


@pytest.mark.parametrize("status", [400, 401, 403, 429, 500, 503])
def test_any_status_but_200_is_access_unavailable(server, status):
    server.reply = Reply(status=status, raw=b"refused", content_type="text/plain")
    with pytest.raises(AccessUnavailable) as exc:
        list(resources(make(server.url)))
    assert exc.value.status == status


@pytest.mark.parametrize("size", [0, -1, 1001, True, 2.5, "10"])
def test_page_size_is_1_to_1000(server, size):
    with pytest.raises(ValueError):
        resources(make(server.url), page_size=size)
    assert server.requests == []


@pytest.mark.parametrize("field_name, value, error", [
    ("subject", None, TypeError), ("subject", "u1", WrnError),
    ("client_wrn", None, ValueError), ("action", "", ValueError), ("action", 5, ValueError),
    ("resource_type", "tasks/task", ValueError), ("resource_type", "Tasks.task", ValueError),
    ("resource_type", "tasks.task.read", ValueError), ("resource_type", None, ValueError),
])
def test_resource_search_arguments_are_checked_at_the_call(server, field_name, value, error):
    """Checked when the search is created, not at the first `next()`."""
    with pytest.raises(error):
        resources(make(server.url), **{field_name: value})
    assert server.requests == []
