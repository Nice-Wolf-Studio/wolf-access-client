"""WolfAccessClient.evaluation: AuthZEN 1.0 request shape (API-P1, API-D4,
API-D5), ZedToken carried (CLI-D2), fail closed (CLI-P2)."""
import socket

import pytest

from tests.fake_server import FakeWolfAccess, Reply
from wolf_access_client import (
    Decision,
    WolfAccessClient,
    WolfAccessError,
    WolfAccessHTTPError,
    WolfAccessResponseError,
    WolfAccessUnavailable,
)

CRED = "svc-credential-not-a-secret"


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        yield fake


def evaluate(client, **overrides):
    args = dict(subject_user_id="user-1", action="view", resource_type="wolfnotes/note",
                resource_id="n-1", context={"client_id": "client-1"})
    args.update(overrides)
    return client.evaluation(**args)


# --- request shape ----------------------------------------------------------------

def test_request_is_the_authzen_evaluation_shape(server):
    evaluate(WolfAccessClient(server.url, CRED))
    (seen,) = server.requests
    assert seen.method == "POST"
    assert seen.path == "/access/v1/evaluation"
    assert seen.body == {
        "subject": {"type": "user", "id": "user-1"},
        "action": {"name": "view"},
        "resource": {"type": "wolfnotes/note", "id": "n-1"},
        "context": {"client_id": "client-1"},
    }
    assert seen.headers["authorization"] == f"Bearer {CRED}"
    assert seen.headers["content-type"] == "application/json"
    assert seen.headers["accept"] == "application/json"


def test_base_url_with_path_and_trailing_slash(server):
    evaluate(WolfAccessClient(server.url + "/prefix/", CRED))
    assert server.requests[0].path == "/prefix/access/v1/evaluation"


def test_extra_context_is_passed_through(server):
    evaluate(WolfAccessClient(server.url, CRED),
             context={"client_id": "client-1", "review_case": "case-9"})
    assert server.requests[0].body["context"] == {"client_id": "client-1",
                                                  "review_case": "case-9"}


def test_callers_context_is_not_mutated(server):
    ctx = {"client_id": "client-1"}
    client = WolfAccessClient(server.url, CRED)
    client.remember_zedtoken("zt-1")
    evaluate(client, context=ctx)
    assert ctx == {"client_id": "client-1"}


# --- decisions --------------------------------------------------------------------

def test_allow(server):
    server.reply = Reply(body={"decision": True, "context": {"reason_user": "owner"}})
    d = evaluate(WolfAccessClient(server.url, CRED))
    assert d == Decision(allowed=True, context={"reason_user": "owner"})
    assert bool(d) is True


def test_deny_is_a_value_not_an_error(server):
    server.reply = Reply(body={"decision": False})
    d = evaluate(WolfAccessClient(server.url, CRED))
    assert d == Decision(allowed=False, context={})
    assert bool(d) is False


# --- client_id and ZedToken ---------------------------------------------------------

@pytest.mark.parametrize("ctx", [None, {}, {"client_id": ""}, {"client_id": None}])
def test_client_id_is_required_and_nothing_is_sent_without_it(server, ctx):
    with pytest.raises(ValueError):
        evaluate(WolfAccessClient(server.url, CRED), context=ctx)
    assert server.requests == []


@pytest.mark.parametrize("user", [None, "", "   "])
def test_subject_user_id_is_required(server, user):
    with pytest.raises(ValueError):
        evaluate(WolfAccessClient(server.url, CRED), subject_user_id=user)
    assert server.requests == []


def test_remembered_zedtoken_is_sent(server):
    client = WolfAccessClient(server.url, CRED)
    evaluate(client)
    client.remember_zedtoken("zt-1")
    evaluate(client)
    assert "zedtoken" not in server.requests[0].body["context"]
    assert server.requests[1].body["context"]["zedtoken"] == "zt-1"
    assert client.zedtoken == "zt-1"


def test_explicit_zedtoken_in_context_wins(server):
    client = WolfAccessClient(server.url, CRED)
    client.remember_zedtoken("zt-old")
    evaluate(client, context={"client_id": "c", "zedtoken": "zt-explicit"})
    assert server.requests[0].body["context"]["zedtoken"] == "zt-explicit"


def test_client_keeps_no_decision_across_calls(server):
    """CLI-D2: every check goes to wolf-access; an allow is never cached."""
    client = WolfAccessClient(server.url, CRED)
    server.reply = Reply(body={"decision": True})
    assert evaluate(client).allowed
    server.reply = Reply(body={"decision": False})
    assert not evaluate(client).allowed
    assert len(server.requests) == 2


# --- fail closed (CLI-P2) -----------------------------------------------------------

def _closed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_unreachable_is_a_typed_error():
    client = WolfAccessClient(f"http://127.0.0.1:{_closed_port()}", CRED, timeout=1)
    with pytest.raises(WolfAccessUnavailable):
        evaluate(client)


def test_timeout_is_a_typed_error(server):
    server.reply = Reply(delay=1.0)
    with pytest.raises(WolfAccessUnavailable):
        evaluate(WolfAccessClient(server.url, CRED, timeout=0.2))


@pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500, 502, 503])
def test_non_2xx_is_a_typed_error(server, status):
    server.reply = Reply(status=status, body={"decision": True})
    with pytest.raises(WolfAccessHTTPError) as exc:
        evaluate(WolfAccessClient(server.url, CRED))
    assert exc.value.status == status


def test_redirect_is_not_followed(server):
    with FakeWolfAccess() as other:
        server.reply = Reply(status=307, headers={"Location": other.url +
                                                  "/access/v1/evaluation"})
        with pytest.raises(WolfAccessHTTPError) as exc:
            evaluate(WolfAccessClient(server.url, CRED))
        assert exc.value.status == 307
        assert other.requests == []  # the credential never left for another host


@pytest.mark.parametrize("raw", [b"not json", b"[]", b"{}", b'{"decision": "true"}',
                                 b'{"decision": 1}', b'{"decision": true, "context": []}'])
def test_malformed_2xx_is_a_typed_error(server, raw):
    server.reply = Reply(raw=raw)
    with pytest.raises(WolfAccessResponseError):
        evaluate(WolfAccessClient(server.url, CRED))


def test_every_failure_is_a_wolf_access_error_and_never_a_decision(server):
    for error in (WolfAccessUnavailable, WolfAccessHTTPError, WolfAccessResponseError):
        assert issubclass(error, WolfAccessError)
    assert not issubclass(WolfAccessError, ValueError)


# --- the credential never leaks ---------------------------------------------------

def test_credential_is_not_in_repr_or_errors(server):
    client = WolfAccessClient(server.url, CRED)
    assert CRED not in repr(client)
    server.reply = Reply(status=500, raw=CRED.encode())
    with pytest.raises(WolfAccessError) as exc:
        evaluate(client)
    assert CRED not in str(exc.value)


@pytest.mark.parametrize("url", ["ftp://x", "x", "", "file:///etc/passwd"])
def test_base_url_must_be_http_or_https(url):
    with pytest.raises(ValueError):
        WolfAccessClient(url, CRED)


def test_credential_is_required():
    with pytest.raises(ValueError):
        WolfAccessClient("https://wolf-access.example", "")


# --- review round 1 -----------------------------------------------------------------

from tests.fake_server import RawServer  # noqa: E402


@pytest.mark.parametrize("cred", [CRED + "\n", CRED + "\r\nX-Evil: 1", "a b", " " + CRED,
                                  "tok\x00en"])
def test_credential_must_be_a_bearer_token(cred):
    with pytest.raises(ValueError) as exc:
        WolfAccessClient("https://wolf-access.example", cred)
    assert CRED not in str(exc.value)


@pytest.mark.parametrize("raw", [
    (b"garbage\r\n\r\n",),                                                  # bad status line
    (b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"decision\": ",),    # cut short
    (b"HTTP/1.1 200 OK\r\nX-Long: " + b"a" * 70000 + b"\r\n\r\n",),         # header too long
])
def test_broken_http_is_unavailable_not_an_escape(raw):
    with RawServer(*raw) as srv:
        with pytest.raises(WolfAccessUnavailable):
            evaluate(WolfAccessClient(srv.url, CRED, timeout=2))


def test_slow_drip_body_cannot_outlast_the_timeout():
    head = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n"
    drip = [b"{"] + [b" "] * 30
    with RawServer(head, *drip, gap=0.1) as srv:
        with pytest.raises(WolfAccessUnavailable):
            evaluate(WolfAccessClient(srv.url, CRED, timeout=0.5))


def test_deeply_nested_json_is_a_response_error(server):
    server.reply = Reply(raw=b"[" * 200000)
    with pytest.raises(WolfAccessResponseError):
        evaluate(WolfAccessClient(server.url, CRED))


def test_environment_proxy_is_never_used(server, monkeypatch):
    with FakeWolfAccess() as proxy:
        for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
            monkeypatch.setenv(name, proxy.url)
        for name in ("no_proxy", "NO_PROXY"):
            monkeypatch.delenv(name, raising=False)
        evaluate(WolfAccessClient(server.url, CRED))
        assert proxy.requests == []
        assert len(server.requests) == 1


def test_null_context_in_the_response_is_an_empty_context(server):
    server.reply = Reply(body={"decision": True, "context": None})
    assert evaluate(WolfAccessClient(server.url, CRED)) == Decision(allowed=True, context={})


@pytest.mark.parametrize("url", ["http://wolf-access.example.com",
                                 "http://203.0.113.7:8080"])
def test_plain_http_is_refused_for_public_hosts(url):
    with pytest.raises(ValueError):
        WolfAccessClient(url, CRED)


@pytest.mark.parametrize("url", ["https://wolf-access.example.com",
                                 "http://wolf-access.railway.internal:8000",
                                 "http://localhost:8000", "http://127.0.0.1:9",
                                 "http://[::1]:9"])
def test_https_anywhere_and_http_only_on_private_hosts(url):
    WolfAccessClient(url, CRED)


@pytest.mark.parametrize("url", ["https://host/?env=prod", "https://host/#x",
                                 "https://u:pw@host", "https://host:notaport"])
def test_base_url_without_query_fragment_userinfo_or_bad_port(url):
    with pytest.raises(ValueError) as exc:
        WolfAccessClient(url, CRED)
    assert "pw" not in str(exc.value)


@pytest.mark.parametrize("timeout", [None, 0, -1, float("inf"), float("nan"), "5", True])
def test_timeout_must_be_a_positive_finite_number(timeout):
    with pytest.raises(ValueError):
        WolfAccessClient("https://wolf-access.example", CRED, timeout=timeout)


@pytest.mark.parametrize("field_name", ["action", "resource_type", "resource_id"])
@pytest.mark.parametrize("value", [None, "", "  ", 5])
def test_action_and_resource_are_required(server, field_name, value):
    with pytest.raises(ValueError):
        evaluate(WolfAccessClient(server.url, CRED), **{field_name: value})
    assert server.requests == []


@pytest.mark.parametrize("blank", [None, ""])
def test_blank_explicit_zedtoken_does_not_hide_the_remembered_one(server, blank):
    client = WolfAccessClient(server.url, CRED)
    client.remember_zedtoken("zt-remembered")
    evaluate(client, context={"client_id": "c", "zedtoken": blank})
    assert server.requests[0].body["context"]["zedtoken"] == "zt-remembered"


def test_blank_explicit_zedtoken_with_nothing_remembered_is_omitted(server):
    evaluate(WolfAccessClient(server.url, CRED), context={"client_id": "c", "zedtoken": None})
    assert "zedtoken" not in server.requests[0].body["context"]


def test_decision_is_hashable_and_its_context_read_only(server):
    server.reply = Reply(body={"decision": True, "context": {"reason_user": "owner"}})
    d = evaluate(WolfAccessClient(server.url, CRED))
    assert hash(d) == hash(Decision(allowed=True, context={"reason_user": "owner"}))
    with pytest.raises(TypeError):
        d.context["reason_user"] = "x"
