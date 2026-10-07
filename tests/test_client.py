"""WolfAccessClient.evaluation: AuthZEN 1.0 request shape (API-P1, API-D4,
API-D5), ZedToken carried (CLI-D2), fail closed (CLI-P2), transport rules
(API-D1)."""
import concurrent.futures
import contextlib
import copy
import dataclasses
import json
import pickle
import socket
import ssl
import threading
import time

import pytest

from tests.fake_server import FakeWolfAccess, RawServer, Reply
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


@contextlib.contextmanager
def refused_port():
    """A bound, non-listening socket: connections to it are refused, and no
    other process can take the port while it is held."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        yield s.getsockname()[1]


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


# --- input validation: nothing is sent --------------------------------------------

@pytest.mark.parametrize("ctx", [None, {}, {"client_id": ""}, {"client_id": None}, 5,
                                 [("client_id", "c")]])
def test_context_must_be_a_mapping_with_a_client_id(server, ctx):
    with pytest.raises(ValueError):
        evaluate(WolfAccessClient(server.url, CRED), context=ctx)
    assert server.requests == []


@pytest.mark.parametrize("field_name", ["subject_user_id", "action", "resource_type",
                                        "resource_id"])
@pytest.mark.parametrize("value", [None, "", "  ", 5])
def test_subject_action_and_resource_are_required(server, field_name, value):
    with pytest.raises(ValueError):
        evaluate(WolfAccessClient(server.url, CRED), **{field_name: value})
    assert server.requests == []


@pytest.mark.parametrize("ctx", [{"client_id": "c", "when": {1, 2}},
                                 {"client_id": "c", "x": float("nan")},
                                 {"client_id": "c", "x": object()}])
def test_context_must_be_json_serializable(server, ctx):
    with pytest.raises(ValueError):
        evaluate(WolfAccessClient(server.url, CRED), context=ctx)
    assert server.requests == []


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


def test_null_context_in_the_response_is_an_empty_context(server):
    server.reply = Reply(body={"decision": True, "context": None})
    assert evaluate(WolfAccessClient(server.url, CRED)) == Decision(allowed=True, context={})


def test_decision_is_hashable_copyable_and_serializable(server):
    server.reply = Reply(body={"decision": True, "context": {"reason_user": "owner"}})
    d = evaluate(WolfAccessClient(server.url, CRED))
    assert hash(d) == hash(Decision(allowed=True, context={"reason_user": "owner"}))
    assert pickle.loads(pickle.dumps(d)) == d
    assert copy.deepcopy(d) == d
    assert json.loads(json.dumps(dataclasses.asdict(d))) == {
        "allowed": True, "context": {"reason_user": "owner"}}


@pytest.mark.parametrize("allowed", ["false", None, 1])
def test_decision_allowed_must_be_a_bool(allowed):
    with pytest.raises(TypeError):
        Decision(allowed=allowed)


def test_client_keeps_no_decision_across_calls(server):
    """CLI-D2: every check goes to wolf-access; an allow is never cached."""
    client = WolfAccessClient(server.url, CRED)
    server.reply = Reply(body={"decision": True})
    assert evaluate(client).allowed
    server.reply = Reply(body={"decision": False})
    assert not evaluate(client).allowed
    assert len(server.requests) == 2


# --- ZedToken (CLI-D2) --------------------------------------------------------------

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


@pytest.mark.parametrize("blank", [None, ""])
def test_blank_explicit_zedtoken_does_not_hide_the_remembered_one(server, blank):
    client = WolfAccessClient(server.url, CRED)
    client.remember_zedtoken("zt-remembered")
    evaluate(client, context={"client_id": "c", "zedtoken": blank})
    assert server.requests[0].body["context"]["zedtoken"] == "zt-remembered"


def test_blank_explicit_zedtoken_with_nothing_remembered_is_omitted(server):
    evaluate(WolfAccessClient(server.url, CRED), context={"client_id": "c", "zedtoken": None})
    assert "zedtoken" not in server.requests[0].body["context"]


@pytest.mark.parametrize("token", [b"GhUK", 5, ["t"]])
def test_non_string_explicit_zedtoken_is_refused(server, token):
    with pytest.raises(ValueError):
        evaluate(WolfAccessClient(server.url, CRED),
                 context={"client_id": "c", "zedtoken": token})
    assert server.requests == []


# --- fail closed (CLI-P2) -----------------------------------------------------------

def test_every_failure_class_is_a_wolf_access_error():
    for error in (WolfAccessUnavailable, WolfAccessHTTPError, WolfAccessResponseError):
        assert issubclass(error, WolfAccessError)
    assert not issubclass(WolfAccessError, ValueError)


def test_unreachable_is_unavailable_with_its_cause():
    with refused_port() as port:
        with pytest.raises(WolfAccessUnavailable) as exc:
            evaluate(WolfAccessClient(f"http://127.0.0.1:{port}", CRED, timeout=1))
    assert exc.value.__cause__ is not None


def test_tls_failure_is_unavailable(server):
    """https to a server that speaks plain HTTP: the handshake fails."""
    https_url = server.url.replace("http://", "https://")
    with pytest.raises(WolfAccessUnavailable) as exc:
        evaluate(WolfAccessClient(https_url, CRED, timeout=2))
    assert isinstance(exc.value.__cause__, (ssl.SSLError, OSError))


@pytest.mark.parametrize("status", [201, 202, 204, 206, 307, 400, 401, 403, 404, 429, 500,
                                    503])
def test_any_status_but_200_is_an_http_error(server, status):
    server.reply = Reply(status=status, body={"decision": True})
    with pytest.raises(WolfAccessHTTPError) as exc:
        evaluate(WolfAccessClient(server.url, CRED))
    assert exc.value.status == status


def test_redirect_is_not_followed(server):
    with FakeWolfAccess() as other:
        server.reply = Reply(status=307, headers={"Location": other.url +
                                                  "/access/v1/evaluation"})
        with pytest.raises(WolfAccessHTTPError):
            evaluate(WolfAccessClient(server.url, CRED))
        assert other.requests == []  # the credential never left for another host


@pytest.mark.parametrize("raw", [b"not json", b"[]", b"{}", b'{"decision": "true"}',
                                 b'{"decision": 1}', b'{"decision": true, "context": []}',
                                 b"[" * 200000,
                                 b'{"decision": false, "decision": true}'])
def test_malformed_200_is_a_response_error(server, raw):
    server.reply = Reply(raw=raw)
    with pytest.raises(WolfAccessResponseError):
        evaluate(WolfAccessClient(server.url, CRED))


def test_oversized_body_is_a_response_error(server):
    server.reply = Reply(raw=b'{"decision": true, "pad": "' + b"a" * (2 * 1024 * 1024) + b'"}')
    with pytest.raises(WolfAccessResponseError):
        evaluate(WolfAccessClient(server.url, CRED))


@pytest.mark.parametrize("raw", [
    (b"garbage\r\n\r\n",),                                                  # bad status line
    (b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"decision\": ",),    # cut short
    (b"HTTP/1.1 200 OK\r\nX-Long: " + b"a" * 70000 + b"\r\n\r\n",),         # header too long
])
def test_broken_http_is_unavailable(raw):
    with RawServer(*raw) as srv:
        with pytest.raises(WolfAccessUnavailable):
            evaluate(WolfAccessClient(srv.url, CRED, timeout=2))


# --- timeout ------------------------------------------------------------------------

def _timed_out_fast(srv, timeout=0.5):
    start = time.monotonic()
    with pytest.raises(WolfAccessUnavailable):
        evaluate(WolfAccessClient(srv.url, CRED, timeout=timeout))
    return time.monotonic() - start


def test_slow_server_times_out(server):
    server.reply = Reply(delay=1.0)
    with pytest.raises(WolfAccessUnavailable):
        evaluate(WolfAccessClient(server.url, CRED, timeout=0.2))


def test_slow_drip_body_cannot_outlast_the_timeout():
    head = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n"
    with RawServer(head, b"{", *([b" "] * 30), gap=0.1) as srv:
        assert _timed_out_fast(srv) < 1.0


def test_concurrent_calls_are_not_capped(server):
    server.reply = Reply(delay=0.3)
    client = WolfAccessClient(server.url, CRED, timeout=3)
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as pool:
        results = list(pool.map(lambda _: evaluate(client), range(60)))
    assert all(r.allowed for r in results)


@pytest.mark.parametrize("timeout", [None, 0, -1, float("inf"), float("nan"), "5", True,
                                     1e10])
def test_timeout_must_be_a_sane_positive_number(timeout):
    with pytest.raises(ValueError):
        WolfAccessClient("https://wolf-access.example", CRED, timeout=timeout)


# --- transport rules (API-D1) and the credential -----------------------------------

@pytest.mark.parametrize("url", ["ftp://x", "x", "", "file:///etc/passwd", None])
def test_base_url_must_be_http_or_https(url):
    with pytest.raises(ValueError):
        WolfAccessClient(url, CRED)


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
                                 "https://u:pw@host", "https://host:notaport",
                                 "https://wolf-access.example\n", " https://wolf-access.example",
                                 "https://wolf-access.example\t/x"])
def test_base_url_is_a_plain_origin_and_path(url):
    with pytest.raises(ValueError) as exc:
        WolfAccessClient(url, CRED)
    assert "pw" not in str(exc.value)


def test_environment_proxy_is_never_used(server, monkeypatch):
    with FakeWolfAccess() as proxy:
        for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
            monkeypatch.setenv(name, proxy.url)
        for name in ("no_proxy", "NO_PROXY"):
            monkeypatch.delenv(name, raising=False)
        evaluate(WolfAccessClient(server.url, CRED))
        assert proxy.requests == []
        assert len(server.requests) == 1


def test_https_always_verifies_certificates(monkeypatch):
    monkeypatch.setattr(ssl, "_create_default_https_context", ssl._create_unverified_context)
    client = WolfAccessClient("https://wolf-access.example", CRED)
    ctx = client._ssl_context
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


def test_credential_is_required():
    with pytest.raises(ValueError):
        WolfAccessClient("https://wolf-access.example", "")


@pytest.mark.parametrize("cred", [CRED + "\n", CRED + "\r\nX-Evil: 1", "a b", " " + CRED,
                                  "tok\x00en", None])
def test_credential_must_be_a_bearer_token(cred):
    with pytest.raises(ValueError) as exc:
        WolfAccessClient("https://wolf-access.example", cred)
    assert CRED not in str(exc.value)


def test_credential_is_not_in_repr_or_errors(server):
    client = WolfAccessClient(server.url, CRED)
    assert CRED not in repr(client)
    server.reply = Reply(status=500, raw=CRED.encode())
    with pytest.raises(WolfAccessError) as exc:
        evaluate(client)
    assert CRED not in str(exc.value)


@pytest.mark.parametrize("timeout", [10**400, -10**400])
def test_huge_integer_timeout_is_a_value_error(timeout):
    with pytest.raises(ValueError):
        WolfAccessClient("https://wolf-access.example", CRED, timeout=timeout)


# --- hosts, IPv6, HTTPS -------------------------------------------------------------

@pytest.mark.parametrize("url, host, port", [
    ("http://[::1]", "::1", 80), ("http://[::1]/", "::1", 80),
    ("https://[2001:db8::5]", "2001:db8::5", 443), ("https://[fe80::a]", "fe80::a", 443),
    ("https://wolf-access.example", "wolf-access.example", 443),
    ("http://localhost:8123/x", "localhost", 8123),
])
def test_host_and_port_are_parsed_once(url, host, port):
    conn = WolfAccessClient(url, CRED)._connection()
    assert (conn.host, conn.port) == (host, port)


@pytest.mark.parametrize("url", ["https://wolf-access.example/pr\u00e9fix",
                                 "https://wolf-access.example/a\x01b",
                                 "https://host\x01name.example", "https://h\x7fost"])
def test_base_url_must_be_printable_ascii(url):
    with pytest.raises(ValueError):
        WolfAccessClient(url, CRED)


def test_context_keys_must_be_strings(server):
    with pytest.raises(ValueError):
        evaluate(WolfAccessClient(server.url, CRED),
                 context={"client_id": "c", 1: "x", "1": "y"})
    assert server.requests == []


def test_http_error_survives_pickling():
    err = pickle.loads(pickle.dumps(WolfAccessHTTPError(503)))
    assert err.status == 503 and str(err) == "wolf-access answered HTTP 503"


@pytest.fixture
def tls_server(tmp_path):
    """A loopback HTTPS wolf-access with a self-signed certificate for
    localhost; yields (url, cert_path)."""
    import subprocess
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1",
                    "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                   check=True, capture_output=True)
    with FakeWolfAccess(tls=(str(cert), str(key))) as fake:
        yield fake, str(cert)


def test_https_evaluation_succeeds_against_a_trusted_certificate(tls_server, monkeypatch):
    fake, cert = tls_server
    monkeypatch.setenv("SSL_CERT_FILE", cert)
    url = fake.url.replace("http://127.0.0.1", "https://localhost")
    assert evaluate(WolfAccessClient(url, CRED)).allowed
    assert fake.requests[0].headers["authorization"] == f"Bearer {CRED}"


def test_https_refuses_an_untrusted_certificate(tls_server, monkeypatch):
    fake, _ = tls_server
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    url = fake.url.replace("http://127.0.0.1", "https://localhost")
    with pytest.raises(WolfAccessUnavailable) as exc:
        evaluate(WolfAccessClient(url, CRED))
    assert isinstance(exc.value.__cause__, ssl.SSLCertVerificationError)
    assert fake.requests == []
