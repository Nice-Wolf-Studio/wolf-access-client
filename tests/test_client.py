"""WolfAccessClient.evaluation: the AuthZEN 1.0 request shape with WRN
subjects and resources and `context.client_wrn` (wolf-access `api.py`
`_subject`, `_resource`, `_client`), the consistency token carried (AC-6),
fail closed (INT-F4), the service's bearer token, and the transport rules
(AC-22)."""
import concurrent.futures
import contextlib
import copy
import dataclasses
import json
import pickle
import socket
import ssl
import time

import pytest

from tests.fake_server import FakeWolfAccess, RawServer, Reply
from tests.helpers import AGENT, APP, CRED, ORG, SERVICE, TASK, USER, make
from wolf_access_client import (
    AccessUnavailable,
    Decision,
    DecisionRefused,
    WolfAccessClient,
    WolfAccessError,
    WolfAccessHTTPError,
    WolfAccessResponseError,
    WolfAccessUnavailable,
    Wrn,
    WrnError,
)


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
    args = dict(subject=USER, action="tasks.task.read", resource=TASK, client_wrn=APP)
    args.update(overrides)
    return client.evaluation(**args)


# --- request shape ----------------------------------------------------------------

def test_request_is_the_authzen_evaluation_shape(server):
    evaluate(make(server.url))
    (seen,) = server.requests
    assert seen.method == "POST"
    assert seen.path == "/access/v1/evaluation"
    assert seen.body == {
        "subject": {"type": "user", "id": str(USER)},
        "action": {"name": "tasks.task.read"},
        "resource": {"type": "tasks.task", "id": str(TASK)},
        "context": {"client_wrn": str(APP), "end_to_end": False},
    }
    assert seen.headers["authorization"] == f"Bearer {CRED}"
    assert seen.headers["content-type"] == "application/json"
    assert seen.headers["accept"] == "application/json"


def test_an_agent_subject_is_type_agent(server):
    evaluate(make(server.url), subject=AGENT)
    assert server.requests[0].body["subject"] == {"type": "agent", "id": str(AGENT)}


def test_wrn_text_is_accepted_and_sent_canonical(server):
    evaluate(make(server.url), subject=str(USER), resource=str(TASK), client_wrn=str(APP))
    body = server.requests[0].body
    assert body["subject"]["id"] == str(USER) and body["resource"]["id"] == str(TASK)


def test_a_wolf_access_resource_is_typed_access(server):
    evaluate(make(server.url), resource=ORG, action="access.org.read")
    assert server.requests[0].body["resource"] == {"type": "access.org", "id": str(ORG)}


def test_end_to_end_is_sent(server):
    """AC-19: an app with end-to-end encryption says so on every decision."""
    evaluate(make(server.url), end_to_end=True)
    assert server.requests[0].body["context"]["end_to_end"] is True


def test_base_url_with_path_and_trailing_slash(server):
    evaluate(make(server.url + "/prefix/"))
    assert server.requests[0].path == "/prefix/access/v1/evaluation"


# --- input validation: nothing is sent --------------------------------------------

def test_every_part_is_keyword_only(server):
    """Positional WRNs could be swapped silently; the identity of the call is
    named at every call site."""
    with pytest.raises(TypeError):
        make(server.url).evaluation(USER, "tasks.task.read", TASK, APP)
    assert server.requests == []


@pytest.mark.parametrize("missing", ["subject", "client_wrn", "resource", "action"])
def test_subject_app_and_resource_are_never_supplied_by_the_library(server, missing):
    args = dict(subject=USER, action="tasks.task.read", resource=TASK, client_wrn=APP)
    del args[missing]
    with pytest.raises(TypeError):
        make(server.url).evaluation(**args)
    assert server.requests == []


@pytest.mark.parametrize("field_name, value, error", [
    ("subject", "wrn:Access:user/u1", WrnError),                    # wrn-ok: refused text
    ("subject", TASK, ValueError),                     # not a principal
    ("subject", ORG, ValueError),                      # an org is not a principal (INT-C2)
    ("subject", None, TypeError),
    ("resource", "tasks.task/t1", WrnError),
    ("resource", 5, TypeError),
    ("client_wrn", "app-1", WrnError),
    ("client_wrn", None, ValueError),
    ("action", "", ValueError), ("action", "  ", ValueError), ("action", None, ValueError),
    ("end_to_end", "yes", ValueError), ("end_to_end", None, ValueError),
    ("consistency_token", b"GhUK", ValueError), ("consistency_token", 5, ValueError),
])
def test_bad_arguments_are_refused_before_sending(server, field_name, value, error):
    with pytest.raises(error):
        evaluate(make(server.url), **{field_name: value})
    assert server.requests == []


def test_a_wrn_error_is_a_value_error_not_a_wolf_access_error(server):
    with pytest.raises(ValueError) as exc:
        evaluate(make(server.url), resource="nope")
    assert not isinstance(exc.value, WolfAccessError)


# --- decisions --------------------------------------------------------------------

def test_allow(server):
    server.reply = Reply(body={"decision": True})
    d = evaluate(make(server.url))
    assert d == Decision(allowed=True, context={})
    assert bool(d) is True


def test_deny_is_a_value_not_an_error(server):
    server.reply = Reply(body={"decision": False})
    d = evaluate(make(server.url))
    assert d == Decision(allowed=False, context={})
    assert bool(d) is False


def test_null_context_in_the_response_is_an_empty_context(server):
    server.reply = Reply(body={"decision": True, "context": None})
    assert evaluate(make(server.url)) == Decision(allowed=True, context={})


def test_decision_is_hashable_copyable_and_serializable(server):
    server.reply = Reply(body={"decision": True, "context": {"k": "v"}})
    d = evaluate(make(server.url))
    assert hash(d) == hash(Decision(allowed=True, context={"k": "v"}))
    assert pickle.loads(pickle.dumps(d)) == d
    assert copy.deepcopy(d) == d
    assert json.loads(json.dumps(dataclasses.asdict(d))) == {
        "allowed": True, "context": {"k": "v"}, "evaluated": True}
    assert d.evaluated is True and d.error is None


@pytest.mark.parametrize("allowed", ["false", None, 1])
def test_decision_allowed_must_be_a_bool(allowed):
    with pytest.raises(TypeError):
        Decision(allowed=allowed)


def test_client_keeps_no_decision_across_calls(server):
    """Every check goes to wolf-access; an allow is never cached."""
    client = make(server.url)
    server.reply = Reply(body={"decision": True})
    assert evaluate(client).allowed
    server.reply = Reply(body={"decision": False})
    assert not evaluate(client).allowed
    assert len(server.requests) == 2


# --- consistency token (AC-6) --------------------------------------------------------

def test_remembered_token_is_sent_as_the_consistency_token(server):
    client = make(server.url)
    evaluate(client)
    client.remember_zedtoken("zt-1")
    evaluate(client)
    assert "consistency_token" not in server.requests[0].body["context"]
    assert server.requests[1].body["context"]["consistency_token"] == "zt-1"
    assert client.zedtoken == "zt-1"


def test_explicit_consistency_token_wins(server):
    client = make(server.url)
    client.remember_zedtoken("zt-old")
    evaluate(client, consistency_token="zt-explicit")
    assert server.requests[0].body["context"]["consistency_token"] == "zt-explicit"
    assert client.zedtoken == "zt-old"


@pytest.mark.parametrize("blank", [None, "", "  "])
def test_blank_explicit_token_does_not_hide_the_remembered_one(server, blank):
    client = make(server.url)
    client.remember_zedtoken("zt-remembered")
    evaluate(client, consistency_token=blank)
    assert server.requests[0].body["context"]["consistency_token"] == "zt-remembered"


@pytest.mark.parametrize("token", ["", "  ", None, 5])
def test_remember_zedtoken_needs_a_token(token):
    with pytest.raises(ValueError):
        make("https://wolf-access.example").remember_zedtoken(token)


# --- the service and its credential ---------------------------------------------------

def test_service_is_required_and_is_a_wrn_segment():
    with pytest.raises(TypeError):
        WolfAccessClient("https://wolf-access.example", CRED)  # type: ignore[call-arg]
    for bad in ("", "Tasks", "ab", "wolf__notes", "tasks/x", None):
        with pytest.raises(ValueError):
            WolfAccessClient("https://wolf-access.example", CRED, service=bad)
    client = WolfAccessClient("https://wolf-access.example", CRED, service="wolf_notes")
    assert client.service == "wolf_notes"
    assert repr(client) == "WolfAccessClient('https://wolf-access.example', service='wolf_notes')"


def test_a_callable_credential_is_called_for_every_request(server):
    """AC-22: a service may authenticate with a JWT it signs, fresh per call."""
    minted = iter(["jwt.one.a", "jwt.two.b"])
    client = make(server.url, cred=lambda: next(minted))
    evaluate(client)
    evaluate(client)
    assert [r.headers["authorization"] for r in server.requests] == [
        "Bearer jwt.one.a", "Bearer jwt.two.b"]


def test_a_callable_credential_must_return_a_bearer_token(server):
    with pytest.raises(ValueError):
        evaluate(make(server.url, cred=lambda: "has space"))
    assert server.requests == []


# --- fail closed (INT-F4) -----------------------------------------------------------

def test_every_failure_class_is_a_wolf_access_error():
    for error in (WolfAccessUnavailable, WolfAccessHTTPError, WolfAccessResponseError,
                  AccessUnavailable, DecisionRefused):
        assert issubclass(error, WolfAccessError)
    assert not issubclass(WolfAccessError, ValueError)


def test_every_way_a_decision_can_fail_is_access_unavailable():
    """INT-F4: one type the caller treats as deny, distinct from a real deny
    (which is a `Decision(allowed=False)` value)."""
    for error in (WolfAccessUnavailable, WolfAccessResponseError, DecisionRefused):
        assert issubclass(error, AccessUnavailable)


def test_unreachable_is_unavailable_with_its_cause():
    with refused_port() as port:
        with pytest.raises(WolfAccessUnavailable) as exc:
            evaluate(make(f"http://127.0.0.1:{port}", CRED, timeout=1))
    assert exc.value.__cause__ is not None


def test_tls_failure_is_unavailable(server):
    """https to a server that speaks plain HTTP: the handshake fails."""
    https_url = server.url.replace("http://", "https://")
    with pytest.raises(WolfAccessUnavailable) as exc:
        evaluate(make(https_url, CRED, timeout=2))
    assert isinstance(exc.value.__cause__, (ssl.SSLError, OSError))


@pytest.mark.parametrize("status", [201, 202, 204, 206, 307, 400, 401, 403, 404, 429, 500,
                                    503])
def test_any_status_but_200_is_an_http_error(server, status):
    server.reply = Reply(status=status, body={"decision": True})
    with pytest.raises(DecisionRefused) as exc:
        evaluate(make(server.url, CRED))
    assert exc.value.status == status
    assert isinstance(exc.value, AccessUnavailable)
    assert isinstance(exc.value, WolfAccessHTTPError)


@pytest.mark.parametrize("status, retry_after, retryable", [
    (429, "30", True), (503, "5", True), (500, None, True), (403, None, False),
    (401, None, False)])
def test_decision_refusal_carries_status_and_retry_after(server, status, retry_after,
                                                         retryable):
    """The decision API answers errors in plain text (AuthZEN); the client
    keeps the status and `Retry-After`, never the server's text."""
    server.reply = Reply(status=status, raw=b"too many requests (API-S1)",
                         content_type="text/plain",
                         headers={"Retry-After": retry_after} if retry_after else {})
    with pytest.raises(DecisionRefused) as exc:
        evaluate(make(server.url, CRED))
    assert exc.value.retry_after == (float(retry_after) if retry_after else None)
    assert exc.value.retryable is retryable
    assert "API-S1" not in str(exc.value)


def test_redirect_is_not_followed(server):
    with FakeWolfAccess() as other:
        server.reply = Reply(status=307, headers={"Location": other.url +
                                                  "/access/v1/evaluation"})
        with pytest.raises(WolfAccessHTTPError):
            evaluate(make(server.url, CRED))
        assert other.requests == []  # the credential never left for another host


@pytest.mark.parametrize("raw", [b"not json", b"[]", b"{}", b'{"decision": "true"}',
                                 b'{"decision": 1}', b'{"decision": true, "context": []}',
                                 b"[" * 200000,
                                 b'{"decision": false, "decision": true}'])
def test_malformed_200_is_a_response_error(server, raw):
    server.reply = Reply(raw=raw)
    with pytest.raises(WolfAccessResponseError):
        evaluate(make(server.url, CRED))


def test_oversized_body_is_a_response_error(server):
    server.reply = Reply(raw=b'{"decision": true, "pad": "' + b"a" * (2 * 1024 * 1024) + b'"}')
    with pytest.raises(WolfAccessResponseError):
        evaluate(make(server.url, CRED))


@pytest.mark.parametrize("raw", [
    (b"garbage\r\n\r\n",),                                                  # bad status line
    (b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"decision\": ",),    # cut short
    (b"HTTP/1.1 200 OK\r\nX-Long: " + b"a" * 70000 + b"\r\n\r\n",),         # header too long
])
def test_broken_http_is_unavailable(raw):
    with RawServer(*raw) as srv:
        with pytest.raises(WolfAccessUnavailable):
            evaluate(make(srv.url, CRED, timeout=2))


# --- timeout ------------------------------------------------------------------------

def _timed_out_fast(srv, timeout=0.5):
    start = time.monotonic()
    with pytest.raises(WolfAccessUnavailable):
        evaluate(make(srv.url, CRED, timeout=timeout))
    return time.monotonic() - start


def test_slow_server_times_out(server):
    server.reply = Reply(delay=1.0)
    with pytest.raises(WolfAccessUnavailable):
        evaluate(make(server.url, CRED, timeout=0.2))


def test_slow_drip_body_cannot_outlast_the_timeout():
    head = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n"
    with RawServer(head, b"{", *([b" "] * 30), gap=0.1) as srv:
        assert _timed_out_fast(srv) < 1.0


def test_concurrent_calls_are_not_capped(server):
    server.reply = Reply(delay=0.3)
    client = make(server.url, CRED, timeout=3)
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as pool:
        results = list(pool.map(lambda _: evaluate(client), range(60)))
    assert all(r.allowed for r in results)


@pytest.mark.parametrize("timeout", [None, 0, -1, float("inf"), float("nan"), "5", True,
                                     1e10])
def test_timeout_must_be_a_sane_positive_number(timeout):
    with pytest.raises(ValueError):
        make("https://wolf-access.example", CRED, timeout=timeout)


# --- transport rules (AC-22) and the credential ------------------------------------

@pytest.mark.parametrize("url", ["ftp://x", "x", "", "file:///etc/passwd", None])
def test_base_url_must_be_http_or_https(url):
    with pytest.raises(ValueError):
        make(url, CRED)


@pytest.mark.parametrize("url", ["http://wolf-access.example.com",
                                 "http://203.0.113.7:8080"])
def test_plain_http_is_refused_for_public_hosts(url):
    with pytest.raises(ValueError):
        make(url, CRED)


@pytest.mark.parametrize("url", ["https://wolf-access.example.com",
                                 "http://wolf-access.railway.internal:8000",
                                 "http://localhost:8000", "http://127.0.0.1:9",
                                 "http://[::1]:9"])
def test_https_anywhere_and_http_only_on_private_hosts(url):
    make(url, CRED)


@pytest.mark.parametrize("url", ["https://host/?env=prod", "https://host/#x",
                                 "https://u:pw@host", "https://host:notaport",
                                 "https://wolf-access.example\n", " https://wolf-access.example",
                                 "https://wolf-access.example\t/x"])
def test_base_url_is_a_plain_origin_and_path(url):
    with pytest.raises(ValueError) as exc:
        make(url, CRED)
    assert "pw" not in str(exc.value)


def test_environment_proxy_is_never_used(server, monkeypatch):
    with FakeWolfAccess() as proxy:
        for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
            monkeypatch.setenv(name, proxy.url)
        for name in ("no_proxy", "NO_PROXY"):
            monkeypatch.delenv(name, raising=False)
        evaluate(make(server.url, CRED))
        assert proxy.requests == []
        assert len(server.requests) == 1


def test_https_always_verifies_certificates(monkeypatch):
    monkeypatch.setattr(ssl, "_create_default_https_context", ssl._create_unverified_context)
    client = make("https://wolf-access.example", CRED)
    ctx = client._ssl_context
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


def test_credential_is_required():
    with pytest.raises(ValueError):
        make("https://wolf-access.example", "")


@pytest.mark.parametrize("cred", [CRED + "\n", CRED + "\r\nX-Evil: 1", "a b", " " + CRED,
                                  "tok\x00en", None])
def test_credential_must_be_a_bearer_token(cred):
    with pytest.raises(ValueError) as exc:
        make("https://wolf-access.example", cred)
    assert CRED not in str(exc.value)


def test_credential_is_not_in_repr_or_errors(server):
    client = make(server.url, CRED)
    assert CRED not in repr(client)
    server.reply = Reply(status=500, raw=CRED.encode())
    with pytest.raises(WolfAccessError) as exc:
        evaluate(client)
    assert CRED not in str(exc.value)


@pytest.mark.parametrize("timeout", [10**400, -10**400])
def test_huge_integer_timeout_is_a_value_error(timeout):
    with pytest.raises(ValueError):
        make("https://wolf-access.example", CRED, timeout=timeout)


# --- hosts, IPv6, HTTPS -------------------------------------------------------------

@pytest.mark.parametrize("url, host, port", [
    ("http://[::1]", "::1", 80), ("http://[::1]/", "::1", 80),
    ("https://[2001:db8::5]", "2001:db8::5", 443), ("https://[fe80::a]", "fe80::a", 443),
    ("https://wolf-access.example", "wolf-access.example", 443),
    ("http://localhost:8123/x", "localhost", 8123),
])
def test_host_and_port_are_parsed_once(url, host, port):
    conn = make(url, CRED)._connection()
    assert (conn.host, conn.port) == (host, port)


@pytest.mark.parametrize("url", ["https://wolf-access.example/pr\u00e9fix",
                                 "https://wolf-access.example/a\x01b",
                                 "https://host\x01name.example", "https://h\x7fost"])
def test_base_url_must_be_printable_ascii(url):
    with pytest.raises(ValueError):
        make(url, CRED)


def test_http_error_survives_pickling():
    err = pickle.loads(pickle.dumps(WolfAccessHTTPError(503)))
    assert err.status == 503 and str(err) == "wolf-access answered HTTP 503"
    err = pickle.loads(pickle.dumps(DecisionRefused(429, retry_after=7.0)))
    assert (type(err), err.status, err.retry_after) == (DecisionRefused, 429, 7.0)


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
    assert evaluate(make(url, CRED)).allowed
    assert fake.requests[0].headers["authorization"] == f"Bearer {CRED}"


def test_https_refuses_an_untrusted_certificate(tls_server, monkeypatch):
    fake, _ = tls_server
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    url = fake.url.replace("http://127.0.0.1", "https://localhost")
    with pytest.raises(WolfAccessUnavailable) as exc:
        evaluate(make(url, CRED))
    assert isinstance(exc.value.__cause__, ssl.SSLCertVerificationError)
    assert fake.requests == []
