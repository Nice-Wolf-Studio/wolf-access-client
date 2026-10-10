"""Token exchange, `POST /v1/token` (INT-C5, AC-20; RFC 8693): form-encoded,
the subject a principal's WRN, the service authenticated by its credential;
an RFC 6749 section 5.2 refusal is a `TokenExchangeError`. wolf-access
`api.py` `post_token` / `_token_form`, `core.py` `exchange_token`,
`tokens.py` on `development` @ ffe20ed."""
import pickle
import time
from urllib.parse import parse_qsl

import pytest

from tests.fake_server import FakeWolfAccess, Reply
from tests.helpers import AGENT, APP, CRED, ORG, TASK, USER, make
from wolf_access_client import (
    ACCESS_AUDIENCE,
    ExchangedToken,
    TokenExchangeError,
    WolfAccessHTTPError,
    WolfAccessResponseError,
    WrnError,
)

JWT = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
WRN_TYPE = "urn:wolfaccess:token-type:wrn"
JWT_TYPE = "urn:ietf:params:oauth:token-type:jwt"
OK = Reply(body={"access_token": JWT, "issued_token_type": JWT_TYPE, "token_type": "Bearer",
                 "expires_in": 60}, headers={"Cache-Control": "no-store"})


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        fake.reply = OK
        yield fake


def form(seen) -> dict[str, str]:
    pairs = parse_qsl(seen.body.decode("ascii"), keep_blank_values=True, strict_parsing=True)
    assert len(pairs) == len(dict(pairs)), "a parameter is sent twice"
    return dict(pairs)


def test_request_is_an_rfc8693_form(server):
    token = make(server.url).exchange_token(USER, ACCESS_AUDIENCE)
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("POST", "/v1/token")
    assert seen.headers["content-type"] == "application/x-www-form-urlencoded"
    assert seen.headers["authorization"] == f"Bearer {CRED}"
    assert form(seen) == {"grant_type": GRANT, "subject_token": str(USER),
                          "subject_token_type": WRN_TYPE, "audience": "access"}
    assert token.access_token == JWT and token.expires_in == 60
    assert token.token_type == "Bearer" and token.issued_token_type == JWT_TYPE


def test_an_agent_and_another_audience(server):
    """INT-C5: a token for an agent whose work the service runs, to call
    another service."""
    make(server.url).exchange_token(str(AGENT), "wolf_notify")
    assert form(server.requests[0])["subject_token"] == str(AGENT)
    assert form(server.requests[0])["audience"] == "wolf_notify"


def test_client_wrn_is_sent_when_given(server):
    """wolf-access#334: the optional `client_wrn` parameter names the app."""
    make(server.url).exchange_token(USER, "access", client_wrn=APP)
    assert form(server.requests[0])["client_wrn"] == str(APP)


def test_client_wrn_is_absent_when_not_given(server):
    make(server.url).exchange_token(USER, "access")
    assert "client_wrn" not in form(server.requests[0])


def test_the_token_is_a_secret(server):
    token = make(server.url).exchange_token(USER, "access")
    assert JWT not in repr(token) and JWT not in str(token)
    assert abs(token.expires_at - (time.time() + 60)) < 5
    assert pickle.loads(pickle.dumps(token)) == token


@pytest.mark.parametrize("subject, error", [
    (TASK, ValueError), (ORG, ValueError), ("u1", WrnError), (None, TypeError)])
def test_the_subject_is_a_principal(server, subject, error):
    with pytest.raises(error):
        make(server.url).exchange_token(subject, "access")
    assert server.requests == []


@pytest.mark.parametrize("kwargs", [{"audience": ""}, {"audience": None},
                                    {"client_wrn": "app"}])
def test_audience_and_client_wrn_are_checked(server, kwargs):
    args = {"audience": "access", **kwargs}
    with pytest.raises((ValueError, WrnError)):
        make(server.url).exchange_token(USER, **args)
    assert server.requests == []


@pytest.mark.parametrize("status, error", [
    (400, "invalid_request"), (400, "invalid_target"), (400, "unsupported_grant_type"),
    (401, "invalid_client"), (503, "temporarily_unavailable"), (500, "server_error")])
def test_refusals_are_token_exchange_errors(server, status, error):
    server.reply = Reply(status=status, body={"error": error,
                                              "error_description": "no token for this one"},
                         headers={"Retry-After": "5"} if status == 503 else {})
    with pytest.raises(TokenExchangeError) as exc:
        make(server.url).exchange_token(USER, "access")
    err = exc.value
    assert isinstance(err, WolfAccessHTTPError)
    assert (err.status, err.error, err.description) == (status, error, "no token for this one")
    assert "no token" not in str(err) and error in str(err)
    assert err.retryable == (status >= 500)
    if status == 503:
        assert err.retry_after == 5.0
    assert pickle.loads(pickle.dumps(err)).error == error


@pytest.mark.parametrize("reply", [
    Reply(status=400, raw=b"not json", content_type="text/plain"),
    Reply(status=400, body={"error": 5}),
    Reply(status=400, body={"error": "Not A Plain Name"}),
])
def test_an_unparsed_refusal_has_no_error_code(server, reply):
    server.reply = reply
    with pytest.raises(TokenExchangeError) as exc:
        make(server.url).exchange_token(USER, "access")
    assert exc.value.error is None


@pytest.mark.parametrize("body", [
    {"access_token": JWT, "issued_token_type": JWT_TYPE, "token_type": "Bearer"},
    {"access_token": JWT, "issued_token_type": JWT_TYPE, "token_type": "Bearer",
     "expires_in": 0},
    {"access_token": JWT, "issued_token_type": JWT_TYPE, "token_type": "MAC",
     "expires_in": 60},
    {"access_token": JWT, "issued_token_type": "urn:x", "token_type": "Bearer",
     "expires_in": 60},
    {"access_token": "a b", "issued_token_type": JWT_TYPE, "token_type": "Bearer",
     "expires_in": 60},
    {"access_token": JWT, "issued_token_type": JWT_TYPE, "token_type": "Bearer",
     "expires_in": True},
])
def test_a_malformed_token_answer_is_a_response_error(server, body):
    server.reply = Reply(body=body)
    with pytest.raises(WolfAccessResponseError):
        make(server.url).exchange_token(USER, "access")


def test_token_type_is_case_insensitive(server):
    server.reply = Reply(body={"access_token": JWT, "issued_token_type": JWT_TYPE,
                               "token_type": "bearer", "expires_in": 60})
    assert make(server.url).exchange_token(USER, "access").token_type == "bearer"


def test_the_exchanged_token_is_used_for_a_create_under_a_parent(server):
    """The round trip a service makes for AC-3: exchange for audience
    `access`, then create under the parent with that token."""
    client = make(server.url)
    token = client.exchange_token(USER, ACCESS_AUDIENCE)
    server.reply = Reply(status=201, body={"zedtoken": "zt", "version": 1})
    client.create_resource(TASK, ORG, principal_token=token)
    assert server.requests[1].headers["authorization"] == f"Bearer {JWT}"
    assert isinstance(token, ExchangedToken)
