"""WolfAccessClient.evaluations: the AuthZEN 1.0 batch with
`options.evaluations_semantic` (wolf-access `api.py` `evaluations`): one
subject and app for the batch, a per-item `context.error`, and every answer
aligned with the item it is about (fail closed, INT-F4)."""
import pytest

from tests.fake_server import FakeWolfAccess, Reply
from tests.helpers import APP, LIST, TASK, TASK2, USER, make
from wolf_access_client import (
    AccessUnavailable,
    Decision,
    EvaluationItem,
    WolfAccessResponseError,
    WrnError,
)

PATH = "/access/v1/evaluations"
ITEMS = [EvaluationItem("tasks.task.read", TASK),
         EvaluationItem("tasks.task.edit", TASK2),
         EvaluationItem("tasks.list.read", LIST)]


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        yield fake


def batch(client, **overrides):
    args = dict(subject=USER, client_wrn=APP, items=ITEMS)
    args.update(overrides)
    return client.evaluations(**args)


def answers(*decisions):
    return Reply(body={"evaluations": [{"decision": d} for d in decisions]})


def test_request_is_the_authzen_batch_shape(server):
    server.reply = answers(True, False, True)
    batch(make(server.url))
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("POST", PATH)
    assert seen.body == {
        "subject": {"type": "user", "id": str(USER)},
        "context": {"client_wrn": str(APP), "end_to_end": False},
        "options": {"evaluations_semantic": "execute_all"},
        "evaluations": [
            {"action": {"name": "tasks.task.read"},
             "resource": {"type": "tasks.task", "id": str(TASK)}},
            {"action": {"name": "tasks.task.edit"},
             "resource": {"type": "tasks.task", "id": str(TASK2)}},
            {"action": {"name": "tasks.list.read"},
             "resource": {"type": "tasks.list", "id": str(LIST)}},
        ]}


def test_answers_are_aligned_with_the_items(server):
    server.reply = Reply(body={"evaluations": [
        {"decision": True}, {"decision": False}, {"decision": True}]})
    assert batch(make(server.url)) == [Decision(True), Decision(False), Decision(True)]


def test_remembered_token_and_end_to_end_go_in_the_shared_context(server):
    server.reply = answers(True, True, True)
    client = make(server.url)
    client.remember_zedtoken("zt-9")
    batch(client, end_to_end=True)
    assert server.requests[0].body["context"] == {
        "client_wrn": str(APP), "end_to_end": True, "consistency_token": "zt-9"}


def test_an_item_error_is_a_deny_that_says_why(server):
    """wolf-access answers an item it cannot evaluate `{"decision": false,
    "context": {"error": {status, message}}}`."""
    error = {"status": 400, "message": "resource.id must be a WRN of resource.type"}
    server.reply = Reply(body={"evaluations": [
        {"decision": True}, {"decision": False, "context": {"error": error}},
        {"decision": False}]})
    results = batch(make(server.url))
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
    results = batch(make(server.url), semantic=semantic)
    assert server.requests[0].body["options"] == {"evaluations_semantic": semantic}
    assert len(results) == len(ITEMS)
    for result, want in zip(results, expected, strict=True):
        if want is None:
            assert result == Decision(False, evaluated=False)
            assert not result
        else:
            assert (result.allowed, result.evaluated) == (want, True)


@pytest.mark.parametrize("semantic", ["", "all", None, "EXECUTE_ALL"])
def test_unknown_semantic_is_refused(server, semantic):
    with pytest.raises(ValueError):
        batch(make(server.url), semantic=semantic)
    assert server.requests == []


@pytest.mark.parametrize("items", [[], (), None, "x", [("tasks.task.read", TASK)]])
def test_items_must_be_a_non_empty_list_of_evaluation_items(server, items):
    with pytest.raises(ValueError):
        batch(make(server.url), items=items)
    assert server.requests == []


def test_more_than_1000_items_is_refused_before_sending(server):
    with pytest.raises(ValueError):
        batch(make(server.url), items=[ITEMS[0]] * 1001)
    assert server.requests == []


def test_exactly_1000_items_are_sent(server):
    server.reply = Reply(body={"evaluations": [{"decision": True}] * 1000})
    assert len(batch(make(server.url), items=[ITEMS[0]] * 1000)) == 1000


def test_an_item_is_checked_when_it_is_made():
    assert EvaluationItem("tasks.task.read", str(TASK)).resource == TASK
    with pytest.raises(WrnError):
        EvaluationItem("tasks.task.read", "t1")
    with pytest.raises(ValueError):
        EvaluationItem("", TASK)


@pytest.mark.parametrize("missing", ["subject", "client_wrn"])
def test_subject_and_app_are_required(server, missing):
    args = dict(subject=USER, client_wrn=APP, items=ITEMS)
    args[missing] = None
    with pytest.raises((TypeError, ValueError)):
        make(server.url).evaluations(**args)
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
        batch(make(server.url), semantic=semantic)


@pytest.mark.parametrize("status", [400, 403, 429, 500, 503])
def test_any_status_but_200_is_access_unavailable(server, status):
    server.reply = Reply(status=status, raw=b"refused", content_type="text/plain")
    with pytest.raises(AccessUnavailable) as exc:
        batch(make(server.url))
    assert exc.value.status == status
