"""WolfAccessClient.evaluations: the AuthZEN 1.0 batch (API-P1, API-D5) with
`options.evaluations_semantic`, a per-item `context.error`, and every answer
aligned with the item it is about (fail closed, CLI-P2)."""
import pytest

from tests.fake_server import FakeWolfAccess, Reply
from wolf_access_client import (
    AccessUnavailable,
    Decision,
    EvaluationItem,
    WolfAccessClient,
    WolfAccessResponseError,
)

CRED = "svc-credential-not-a-secret"
PATH = "/access/v1/evaluations"
ITEMS = [EvaluationItem("view", "wolfnotes/note", "n-1"),
         EvaluationItem("edit", "wolfnotes/note", "n-2"),
         EvaluationItem("view", "wolfnotes/folder", "f-1")]


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        yield fake


def batch(client, **overrides):
    args = dict(user_id="user-1", client_id="client-1", items=ITEMS)
    args.update(overrides)
    return client.evaluations(**args)


def answers(*decisions):
    return Reply(body={"evaluations": [{"decision": d} for d in decisions]})


def test_request_is_the_authzen_batch_shape(server):
    server.reply = answers(True, False, True)
    batch(WolfAccessClient(server.url, CRED))
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("POST", PATH)
    assert seen.body == {
        "subject": {"type": "user", "id": "user-1"},
        "context": {"client_id": "client-1"},
        "options": {"evaluations_semantic": "execute_all"},
        "evaluations": [
            {"action": {"name": "view"}, "resource": {"type": "wolfnotes/note", "id": "n-1"}},
            {"action": {"name": "edit"}, "resource": {"type": "wolfnotes/note", "id": "n-2"}},
            {"action": {"name": "view"},
             "resource": {"type": "wolfnotes/folder", "id": "f-1"}},
        ],
    }
    assert seen.headers["authorization"] == f"Bearer {CRED}"


def test_answers_are_aligned_with_the_items(server):
    server.reply = Reply(body={"evaluations": [
        {"decision": True, "context": {"reason_user": "owner"}},
        {"decision": False},
        {"decision": True}]})
    assert batch(WolfAccessClient(server.url, CRED)) == [
        Decision(True, {"reason_user": "owner"}), Decision(False), Decision(True)]


def test_remembered_zedtoken_and_extra_context_go_in_the_shared_context(server):
    server.reply = answers(True, True, True)
    client = WolfAccessClient(server.url, CRED)
    client.remember_zedtoken("zt-9")
    batch(client, context={"purpose": "list"})
    assert server.requests[0].body["context"] == {"client_id": "client-1", "purpose": "list",
                                                  "zedtoken": "zt-9"}


def test_an_item_error_is_a_deny_that_says_why(server):
    """An invalid item, or one naming a foreign type, is answered
    `{"decision": false, "context": {"error": {status, message}}}`."""
    error = {"status": 403, "message": "a service asks only about its own types"}
    server.reply = Reply(body={"evaluations": [
        {"decision": True}, {"decision": False, "context": {"error": error}},
        {"decision": False}]})
    results = batch(WolfAccessClient(server.url, CRED))
    assert results[1].allowed is False and results[1].error == error
    assert results[2].allowed is False and results[2].error is None
    assert results[0].error is None


@pytest.mark.parametrize("semantic, decisions, expected", [
    ("deny_on_first_deny", [True, False], [True, False, None]),
    ("deny_on_first_deny", [False], [False, None, None]),
    ("deny_on_first_deny", [True, True, True], [True, True, True]),
    ("deny_on_first_deny", [True, True, False], [True, True, False]),
    ("permit_on_first_permit", [False, True], [False, True, None]),
    ("permit_on_first_permit", [True], [True, None, None]),
    ("permit_on_first_permit", [False, False, False], [False, False, False]),
])
def test_short_circuit_semantics_leave_the_rest_unevaluated_and_denied(
        server, semantic, decisions, expected):
    server.reply = answers(*decisions)
    results = batch(WolfAccessClient(server.url, CRED), semantic=semantic)
    assert server.requests[0].body["options"] == {"evaluations_semantic": semantic}
    assert len(results) == len(ITEMS)
    for result, want in zip(results, expected, strict=True):
        if want is None:
            assert result == Decision(False, evaluated=False)
            assert not result
        else:
            assert (result.allowed, result.evaluated) == (want, True)


@pytest.mark.parametrize("semantic", ["", "all", "EXECUTE_ALL", None, 1])
def test_unknown_semantic_is_refused(server, semantic):
    with pytest.raises(ValueError):
        batch(WolfAccessClient(server.url, CRED), semantic=semantic)
    assert server.requests == []


@pytest.mark.parametrize("items", [
    [], (), None, "view", [("view", "wolfnotes/note", "n-1")], [{"action": "view"}],
    [EvaluationItem("", "wolfnotes/note", "n-1")], [EvaluationItem("view", "", "n-1")],
    [EvaluationItem("view", "wolfnotes/note", "")], [EvaluationItem("view", "t", None)],
])
def test_items_must_be_a_non_empty_list_of_evaluation_items(server, items):
    with pytest.raises(ValueError):
        batch(WolfAccessClient(server.url, CRED), items=items)
    assert server.requests == []


def test_more_than_1000_items_is_refused_before_sending(server):
    """wolf-access refuses a batch over 1000 (BATCH_MAX); the client says so
    instead of turning it into a silent deny of everything."""
    with pytest.raises(ValueError):
        batch(WolfAccessClient(server.url, CRED),
              items=[EvaluationItem("view", "wolfnotes/note", str(i)) for i in range(1001)])
    assert server.requests == []


def test_exactly_1000_items_are_sent(server):
    server.reply = answers(*([True] * 1000))
    results = batch(WolfAccessClient(server.url, CRED),
                    items=[EvaluationItem("view", "wolfnotes/note", str(i))
                           for i in range(1000)])
    assert len(results) == 1000 and all(results)


@pytest.mark.parametrize("missing", ["user_id", "client_id"])
def test_user_id_and_client_id_are_required(server, missing):
    args = dict(user_id="user-1", client_id="client-1", items=ITEMS)
    del args[missing]
    with pytest.raises(TypeError):
        WolfAccessClient(server.url, CRED).evaluations(**args)
    with pytest.raises(ValueError):
        WolfAccessClient(server.url, CRED).evaluations(**{**args, missing: ""})
    assert server.requests == []


@pytest.mark.parametrize("key", ["client_id", "user_id", "zedtoken"])
def test_context_cannot_carry_the_explicit_parameters(server, key):
    with pytest.raises(ValueError):
        batch(WolfAccessClient(server.url, CRED), context={key: "x"})
    assert server.requests == []


# --- a misaligned or malformed answer is no answer (fail closed) -------------------

@pytest.mark.parametrize("semantic, body", [
    ("execute_all", {"evaluations": [{"decision": True}, {"decision": True}]}),   # short
    ("execute_all", {"evaluations": [{"decision": True}] * 4}),                    # long
    ("execute_all", {"decision": True}),                       # the single-check answer
    ("execute_all", {"evaluations": {"0": {"decision": True}}}),
    ("execute_all", {"evaluations": [{"decision": True}, {"decision": "false"},
                                     {"decision": True}]}),
    ("execute_all", {"evaluations": [{"decision": True}, [], {"decision": True}]}),
    ("execute_all", {"evaluations": [{"decision": True, "context": []},
                                     {"decision": True}, {"decision": True}]}),
    ("deny_on_first_deny", {"evaluations": []}),
    ("deny_on_first_deny", {"evaluations": [{"decision": True}]}),             # stopped on a permit
    ("deny_on_first_deny", {"evaluations": [{"decision": False}, {"decision": True}]}),
    ("permit_on_first_permit", {"evaluations": [{"decision": False}]}),        # stopped on a deny
    ("permit_on_first_permit", {"evaluations": [{"decision": True}, {"decision": False}]}),
])
def test_misaligned_or_malformed_answer_is_a_response_error(server, semantic, body):
    server.reply = Reply(body=body)
    with pytest.raises(WolfAccessResponseError):
        batch(WolfAccessClient(server.url, CRED), semantic=semantic)


@pytest.mark.parametrize("status", [400, 403, 429, 500, 503])
def test_any_status_but_200_is_access_unavailable(server, status):
    server.reply = Reply(status=status, raw=b"refused", content_type="text/plain")
    with pytest.raises(AccessUnavailable) as exc:
        batch(WolfAccessClient(server.url, CRED))
    assert exc.value.status == status
