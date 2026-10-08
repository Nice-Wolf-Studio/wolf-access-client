"""Sign-off of delegate and agent writes (wolf-access CLI-D4 (ii), CLI-P6,
DEL-S1): the change's RFC 8785 (JCS) + SHA-256 hash, `POST /v1/signoffs` and
`POST /v1/signoffs/{id}/consume`, and the evaluation's `signoff_required`."""
import hashlib

import pytest

from tests.fake_server import FakeWolfAccess, Reply, problem
from wolf_access_client import (
    ConflictError,
    Decision,
    ResourceRef,
    SignoffFiled,
    WolfAccessClient,
    WolfAccessResponseError,
    canonical_json,
    diff_hash,
)

CRED = "svc-credential-not-a-secret"
H = "a" * 64


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        yield fake


# --- RFC 8785 (JCS) ------------------------------------------------------------------------

def test_jcs_sorts_keys_by_utf16_and_drops_whitespace():
    assert canonical_json({"b": 1, "a": [True, None, "x"], "€": 0, "\U0001f600": 0}) \
        == '{"a":[true,null,"x"],"b":1,"€":0,"\U0001f600":0}'
    # UTF-16 order: U+1F600 (surrogates D83D...) sorts before U+FB01.
    assert canonical_json({"ﬁ": 1, "\U0001f600": 2}) == '{"\U0001f600":2,"ﬁ":1}'


def test_jcs_strings_escape_only_what_json_needs():
    assert canonical_json("a\"\\\n\t\x01é/") == '"a\\"\\\\\\n\\t\\u0001é/"'


@pytest.mark.parametrize("number, text", [
    (0, "0"), (-0.0, "0"), (1.0, "1"), (100, "100"), (1e21, "1e+21"), (1e20, "100000000000000000000"),
    (1.5, "1.5"), (0.000001, "0.000001"), (1e-7, "1e-7"), (123.456e-10, "1.23456e-8"),
    (-2.5e30, "-2.5e+30"), (9007199254740991, "9007199254740991"),
])
def test_jcs_numbers_follow_ecmascript(number, text):
    assert canonical_json(number) == text


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 2 ** 53 + 1, {1: "x"}, b"x"])
def test_jcs_refuses_what_has_no_canonical_form(bad):
    with pytest.raises(ValueError):
        canonical_json(bad)


def test_diff_hash_is_sha256_of_the_jcs_form():
    change = {"note": "n-1", "body": "hello", "n": 2}
    expected = hashlib.sha256(b'{"body":"hello","n":2,"note":"n-1"}').hexdigest()
    assert diff_hash(change) == expected
    assert diff_hash({"n": 2, "note": "n-1", "body": "hello"}) == expected
    assert diff_hash({**change, "body": "hello!"}) != expected


# --- POST /v1/signoffs ---------------------------------------------------------------------

def test_create_signoff(server):
    server.reply = Reply(status=201, body={"signoff": "s-1", "status": "pending",
                                           "expires_at": "2026-10-09T12:00:00+00:00"})
    out = WolfAccessClient(server.url, CRED).create_signoff(
        user_id="user-1", client_id="client-agent", resource=ResourceRef("wolfnotes/note", "n-1"),
        action="edit", diff_hash=H)
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("POST", "/v1/signoffs")
    assert seen.body == {"resource": {"type": "wolfnotes/note", "id": "n-1"},
                         "action": "edit", "diff_hash": H,
                         "actor": {"client_id": "client-agent"},
                         "on_behalf_of": {"type": "user", "id": "user-1"}}
    assert out == SignoffFiled(signoff="s-1", status="pending",
                               expires_at=out.expires_at)
    assert out.expires_at.tzinfo is not None


@pytest.mark.parametrize("kwargs", [
    {"diff_hash": "A" * 64}, {"diff_hash": "a" * 63}, {"action": ""}, {"user_id": ""},
    {"client_id": ""}, {"resource": "wolfnotes/note:n-1"},
])
def test_create_signoff_checks_arguments(server, kwargs):
    args = {"user_id": "u", "client_id": "c", "resource": ResourceRef("wolfnotes/note", "n"),
            "action": "edit", "diff_hash": H, **kwargs}
    with pytest.raises((ValueError, TypeError)):
        WolfAccessClient(server.url, CRED).create_signoff(**args)
    assert server.requests == []


def test_create_signoff_refusals_are_typed(server):
    server.reply = problem("conflict", 409, "this write needs no sign-off")
    with pytest.raises(ConflictError):
        WolfAccessClient(server.url, CRED).create_signoff(
            user_id="u", client_id="c", resource=ResourceRef("wolfnotes/note", "n"),
            action="edit", diff_hash=H)
    server.reply = Reply(status=200, body={"signoff": "s"})
    with pytest.raises(WolfAccessResponseError):
        WolfAccessClient(server.url, CRED).create_signoff(
            user_id="u", client_id="c", resource=ResourceRef("wolfnotes/note", "n"),
            action="edit", diff_hash=H)


# --- POST /v1/signoffs/{id}/consume ----------------------------------------------------------

def test_consume_signoff(server):
    server.reply = Reply(status=200, body={"signoff": "s/1", "status": "consumed"})
    assert WolfAccessClient(server.url, CRED).consume_signoff("s/1", H) is None
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("POST", "/v1/signoffs/s%2F1/consume")
    assert seen.body == {"diff_hash": H}


def test_consume_refused_is_a_conflict(server):
    server.reply = problem("conflict", 409, "the change differs from the one signed off")
    with pytest.raises(ConflictError):
        WolfAccessClient(server.url, CRED).consume_signoff("s-1", H)


def test_consume_needs_a_consumed_answer(server):
    server.reply = Reply(status=200, body={"signoff": "s-1", "status": "approved"})
    with pytest.raises(WolfAccessResponseError):
        WolfAccessClient(server.url, CRED).consume_signoff("s-1", H)


# --- the evaluation says when a write needs sign-off (DEL-S1) --------------------------------

def test_decision_signoff_required(server):
    server.reply = Reply(body={"decision": True, "context": {"signoff_required": True}})
    d = WolfAccessClient(server.url, CRED).evaluation(
        user_id="u", client_id="c", action="edit", resource_type="wolfnotes/note",
        resource_id="n")
    assert d.allowed and d.signoff_required
    assert Decision(True).signoff_required is False
    assert Decision(False, {"signoff_required": True}).signoff_required is False
