"""RFC 9457 problem details from `/v1` (API-D3), parsed into typed
exceptions by name (`urn:wolfaccess:problem:<name>`), plus `Retry-After`."""
import copy
import pickle

import pytest

from tests.fake_server import PROBLEM, FakeWolfAccess, Reply, problem
from wolf_access_client import (
    PROBLEM_TYPES,
    AccessUnavailable,
    BadRequestError,
    ConflictError,
    ForbiddenError,
    HttpsRequiredError,
    IdempotencyKeyInUseError,
    IdempotencyKeyReusedError,
    NotFoundError,
    OwnerRequiredError,
    OwnershipMismatchError,
    PrincipalRef,
    ProblemError,
    RateLimitedError,
    UnauthorizedError,
    UnavailableError,
    WolfAccessClient,
    WolfAccessError,
    WolfAccessHTTPError,
)

CRED = "svc-credential-not-a-secret"

NAMES = [
    ("owner_required", 422, OwnerRequiredError, False),
    ("ownership_mismatch", 422, OwnershipMismatchError, False),
    ("conflict", 409, ConflictError, False),
    ("forbidden", 403, ForbiddenError, False),
    ("not_found", 404, NotFoundError, False),
    ("bad_request", 400, BadRequestError, False),
    ("unauthorized", 401, UnauthorizedError, False),
    ("https_required", 403, HttpsRequiredError, False),
    ("rate_limited", 429, RateLimitedError, True),
    ("unavailable", 503, UnavailableError, True),
    ("idempotency_key_reused", 422, IdempotencyKeyReusedError, False),
    ("idempotency_key_in_use", 409, IdempotencyKeyInUseError, False),
]


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        yield fake


def create(client):
    return client.create_resource("wolfnotes/note", "n-1", owner=PrincipalRef.user("user-1"),
                                  author="user-1", idempotency_key="k-1")


@pytest.mark.parametrize("name, status, cls, retryable", NAMES)
def test_each_problem_name_is_its_own_exception(server, name, status, cls, retryable):
    server.reply = problem(name, status, f"detail for {name}")
    with pytest.raises(cls) as exc:
        create(WolfAccessClient(server.url, CRED))
    err = exc.value
    assert type(err) is cls and PROBLEM_TYPES[name] is cls
    assert isinstance(err, ProblemError) and isinstance(err, WolfAccessHTTPError)
    assert isinstance(err, WolfAccessError) and not isinstance(err, AccessUnavailable)
    assert (err.name, err.status, err.type, err.title, err.detail) == (
        name, status, PROBLEM + name, name.replace("_", " "), f"detail for {name}")
    assert err.retryable is retryable


def test_problem_names_cover_the_m1b_api():
    assert sorted(PROBLEM_TYPES) == sorted(n for n, *_ in NAMES)


def test_unauthorized_keeps_the_challenge(server):
    server.reply = problem("unauthorized", 401, "a service credential is required",
                           WWW_Authenticate='Bearer realm="wolf-access"')
    with pytest.raises(UnauthorizedError) as exc:
        create(WolfAccessClient(server.url, CRED))
    assert exc.value.www_authenticate == 'Bearer realm="wolf-access"'


def test_rate_limited_carries_retry_after(server):
    server.reply = problem("rate_limited", 429, "too many requests (API-S1)", Retry_After="42")
    with pytest.raises(RateLimitedError) as exc:
        create(WolfAccessClient(server.url, CRED))
    assert exc.value.retry_after == 42.0 and exc.value.retryable


@pytest.mark.parametrize("value, expected", [
    ("0", 0.0), ("120", 120.0), (" 7 ", 7.0), ("-1", None), ("soon", None), ("1.5", None),
    ("Wed, 21 Oct 2015 07:28:00 GMT", 0.0),       # an HTTP-date in the past
    ("", None),
])
def test_retry_after_is_seconds_or_an_http_date(server, value, expected):
    server.reply = problem("unavailable", 503, "later", Retry_After=value)
    with pytest.raises(UnavailableError) as exc:
        create(WolfAccessClient(server.url, CRED))
    assert exc.value.retry_after == expected


def test_retry_after_http_date_in_the_future(server):
    from email.utils import format_datetime
    from datetime import datetime, timedelta, timezone
    when = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=90), usegmt=True)
    server.reply = problem("unavailable", 503, "later", Retry_After=when)
    with pytest.raises(UnavailableError) as exc:
        create(WolfAccessClient(server.url, CRED))
    assert 80 <= exc.value.retry_after <= 91


def test_unknown_problem_name_is_a_problem_error_with_its_name(server):
    """A name this version does not know (e.g. M1c's `under_review`) still
    arrives typed as a `ProblemError` carrying the name."""
    server.reply = problem("under_review", 409, "an open review case freezes it")
    with pytest.raises(ProblemError) as exc:
        create(WolfAccessClient(server.url, CRED))
    assert type(exc.value) is ProblemError
    assert (exc.value.name, exc.value.status) == ("under_review", 409)


@pytest.mark.parametrize("body", [
    {"type": "about:blank", "title": "Not Found", "status": 404},
    {"type": "https://example.com/probs/out-of-credit", "status": 404},
    {"title": "no type", "status": 404},
])
def test_a_problem_from_elsewhere_has_no_name(server, body):
    server.reply = Reply(status=404, body=body, content_type="application/problem+json")
    with pytest.raises(ProblemError) as exc:
        create(WolfAccessClient(server.url, CRED))
    assert type(exc.value) is ProblemError and exc.value.name is None


@pytest.mark.parametrize("reply", [
    Reply(status=409, raw=b"not json", content_type="application/problem+json"),
    Reply(status=409, body=["conflict"], content_type="application/problem+json"),
    Reply(status=409, body={"type": PROBLEM + "conflict"}, content_type="application/json"),
])
def test_a_body_that_is_not_a_problem_is_a_plain_http_error(server, reply):
    server.reply = reply
    with pytest.raises(WolfAccessHTTPError) as exc:
        create(WolfAccessClient(server.url, CRED))
    assert not isinstance(exc.value, ProblemError) and exc.value.status == 409


def test_problem_media_type_parameters_are_allowed(server):
    reply = problem("conflict", 409)
    reply.content_type = "application/problem+json; charset=utf-8"
    server.reply = reply
    with pytest.raises(ConflictError):
        create(WolfAccessClient(server.url, CRED))


@pytest.mark.parametrize("field_name, value", [("title", 5), ("detail", ["x"])])
def test_non_string_problem_members_are_dropped(server, field_name, value):
    """RFC 9457 §3.1: a member with the wrong type is ignored."""
    reply = problem("conflict", 409)
    reply.body[field_name] = value
    server.reply = reply
    with pytest.raises(ConflictError) as exc:
        create(WolfAccessClient(server.url, CRED))
    assert getattr(exc.value, field_name) is None


def test_server_text_and_credential_never_reach_str(server):
    server.reply = problem("conflict", 409, f"echo {CRED}")
    with pytest.raises(ConflictError) as exc:
        create(WolfAccessClient(server.url, CRED))
    assert CRED not in str(exc.value) and CRED not in repr(exc.value)
    assert str(exc.value) == "wolf-access answered HTTP 409 (conflict)"


@pytest.mark.parametrize("name, status, cls, retryable", NAMES)
def test_problems_survive_pickle_and_copy(name, status, cls, retryable):
    err = cls(status, name=name, type=PROBLEM + name, title="t", detail="d", retry_after=3.0)
    for clone in (pickle.loads(pickle.dumps(err)), copy.deepcopy(err)):
        assert type(clone) is cls
        assert (clone.status, clone.name, clone.type, clone.title, clone.detail,
                clone.retry_after) == (status, name, PROBLEM + name, "t", "d", 3.0)
