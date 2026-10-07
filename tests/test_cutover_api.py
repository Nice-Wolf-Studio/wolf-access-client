"""The cut-over calls on `WolfAccessClient` (API-D10, CUT-D1, CUT-S1): the
start-up state report, changes in (`POST …/changes`), changes out (`GET
…/changes?after=n`), the seed gate on decisions (409) and `use_outbox` on
direct writes. Each is made with the service's own credential, to its own
`/v1/services/{service}` path."""
from __future__ import annotations

import datetime as dt

import pytest

from tests.fake_server import FakeIntake, FakeWolfAccess, Reply, problem
from wolf_access_client import (
    AccessMode,
    AccessUnavailable,
    BadRequestError,
    ChangeResult,
    ChangesAnswer,
    DecisionRefused,
    ForbiddenError,
    PrincipalRef,
    ProblemError,
    SeedNotVerified,
    UseOutboxError,
    WolfAccessClient,
    WolfAccessHTTPError,
    WolfAccessResponseError,
    WolfAccessUnavailable,
)

CRED = "svc-credential-not-a-secret"
START = dt.datetime(2026, 10, 7, 12, 0, tzinfo=dt.timezone.utc)
CHANGES = "/v1/services/wolfnotes/changes"
STATE = "/v1/services/wolfnotes/state"


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        yield fake


def client_for(server, service="wolfnotes"):
    return WolfAccessClient(server.url, CRED, service=service)


def wire(seq, action="create", rid=None, **extra):
    row = {"sequence": seq, "change_id": f"c-{seq}", "action": action,
           "resource": {"type": "wolfnotes/note", "id": rid or f"n-{seq}"}}
    if action == "create":
        row.update(owner={"type": "user", "id": "u-1"}, author="u-1")
    row.update(extra)
    return row


# --- the service name -------------------------------------------------------------

@pytest.mark.parametrize("service", ["", " ", "wolf/notes", "wolf notes", "a\nb", 5])
def test_service_must_be_a_plain_name(server, service):
    with pytest.raises(ValueError):
        WolfAccessClient(server.url, CRED, service=service)


def test_cut_over_calls_need_a_service(server):
    client = WolfAccessClient(server.url, CRED)
    with pytest.raises(ValueError):
        client.report_state("off", START)
    with pytest.raises(ValueError):
        client.send_changes([wire(1)])
    with pytest.raises(ValueError):
        client.changes_page(0)
    assert server.requests == []


def test_client_reports_its_service(server):
    assert client_for(server).service == "wolfnotes"
    assert WolfAccessClient(server.url, CRED).service is None


# --- state (CUT-S1, API-D10 (c)) -----------------------------------------------------

@pytest.mark.parametrize("mode", ["off", "shadow", "on", AccessMode.SHADOW])
def test_report_state_puts_mode_and_registration_start(server, mode):
    intake = FakeIntake(server)
    assert client_for(server).report_state(mode, START) is None
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("PUT", STATE)
    assert seen.headers["authorization"] == f"Bearer {CRED}"
    assert seen.headers["content-type"] == "application/json"
    assert seen.body == {"mode": AccessMode.parse(mode).value,
                         "registration_start": "2026-10-07T12:00:00+00:00"}
    assert intake.states == [seen.body]


def test_registration_start_keeps_its_own_zone(server):
    FakeIntake(server)
    zone = dt.timezone(dt.timedelta(hours=-4))
    client_for(server).report_state("on", dt.datetime(2026, 10, 7, 8, 0, 0, 5, tzinfo=zone))
    assert server.requests[0].body["registration_start"] == "2026-10-07T08:00:00.000005-04:00"


@pytest.mark.parametrize("mode", ["", "OFF", "enforce", None])
def test_report_state_refuses_an_unknown_mode(server, mode):
    with pytest.raises(ValueError):
        client_for(server).report_state(mode, START)
    assert server.requests == []


@pytest.mark.parametrize("start", [dt.datetime(2026, 10, 7, 12, 0), "2026-10-07T12:00:00Z",
                                   None, 0])
def test_registration_start_is_an_aware_datetime(server, start):
    with pytest.raises(ValueError):
        client_for(server).report_state("off", start)
    assert server.requests == []


def test_report_state_refusal_is_a_problem(server):
    server.queue("PUT", STATE, problem("forbidden", 403, "only the service's own credential"))
    with pytest.raises(ForbiddenError):
        client_for(server).report_state("on", START)


@pytest.mark.parametrize("reply", [Reply(body=[]), Reply(raw=b"nope"),
                                   Reply(status=204, raw=b"")])
def test_report_state_malformed_answer(server, reply):
    server.queue("PUT", STATE, reply)
    with pytest.raises(WolfAccessResponseError):
        client_for(server).report_state("on", START)


# --- changes in (API-D10 (a)) --------------------------------------------------------

def test_send_changes_posts_rows_and_reads_results(server):
    intake = FakeIntake(server)
    rows = [wire(1), wire(2, "move", rid="n-1", parent=None),
            wire(3, "private", rid="n-1", private=True), wire(4, "delete", rid="n-1")]
    answer = client_for(server).send_changes(rows)
    assert answer == ChangesAnswer(results=tuple(ChangeResult(n, "applied") for n in range(1, 5)),
                                   applied_through=4)
    (seen,) = server.requests
    assert (seen.method, seen.path, seen.body) == ("POST", CHANGES, {"rows": rows})
    assert intake.applied == rows


def test_send_changes_reports_held_and_refused_with_reasons(server):
    intake = FakeIntake(server)
    intake.refuse[1] = "wolfnotes/thing is not a registered type of wolfnotes"
    answer = client_for(server).send_changes([wire(1), wire(2)])
    assert answer.results == (
        ChangeResult(1, "refused", "wolfnotes/thing is not a registered type of wolfnotes"),
        ChangeResult(2, "held"))
    assert answer.applied_through == 0


def test_a_replayed_row_is_answered_with_its_stored_result(server):
    intake = FakeIntake(server)
    client = client_for(server)
    client.send_changes([wire(1)])
    assert client.send_changes([wire(1)]).results == (ChangeResult(1, "applied"),)
    assert len(intake.applied) == 1


@pytest.mark.parametrize("rows", [[], [wire(1)] * 501, "rows", None])
def test_send_changes_takes_1_to_500_rows(server, rows):
    with pytest.raises(ValueError):
        client_for(server).send_changes(rows)
    assert server.requests == []


@pytest.mark.parametrize("row", [
    {"change_id": "c", "action": "create"},
    {"sequence": 0, "change_id": "c", "action": "create"},
    {"sequence": True, "change_id": "c", "action": "create"},
    {"sequence": 1, "change_id": "", "action": "create"},
    {"sequence": 1, "change_id": "c"},
    "row",
])
def test_send_changes_refuses_a_row_without_sequence_change_id_and_action(server, row):
    with pytest.raises(ValueError):
        client_for(server).send_changes([row])
    assert server.requests == []


@pytest.mark.parametrize("answer", [
    {"results": [], "applied_through": 1},                                 # missing result
    {"results": [{"sequence": 2, "status": "applied"}], "applied_through": 2},  # wrong row
    {"results": [{"sequence": 1, "status": "done"}], "applied_through": 1},     # unknown status
    {"results": [{"sequence": 1, "status": "held", "reason": 5}], "applied_through": 0},
    {"results": [{"sequence": 1, "status": "applied"}]},                   # no applied_through
    {"results": [{"sequence": 1, "status": "applied"}], "applied_through": -1},
    {"results": [{"sequence": 1, "status": "applied"}], "applied_through": True},
    {"results": "x", "applied_through": 1},
    [],
])
def test_send_changes_malformed_answer_is_a_response_error(server, answer):
    server.queue("POST", CHANGES, Reply(body=answer))
    with pytest.raises(WolfAccessResponseError):
        client_for(server).send_changes([wire(1)])


def test_a_resolved_row_counts_as_done(server):
    """CUT-D1 (1): a refused row can later become `resolved` (reconcile)."""
    server.queue("POST", CHANGES, Reply(body={
        "results": [{"sequence": 1, "status": "resolved"}], "applied_through": 1}))
    assert client_for(server).send_changes([wire(1)]).results == (ChangeResult(1, "resolved"),)


@pytest.mark.parametrize("status", [400, 401, 403, 422])
def test_send_changes_refusal_is_a_problem_not_retryable(server, status):
    server.queue("POST", CHANGES, problem("bad_request" if status == 400 else "forbidden",
                                          status))
    with pytest.raises(ProblemError) as exc:
        client_for(server).send_changes([wire(1)])
    assert exc.value.status == status and exc.value.retryable is False


@pytest.mark.parametrize("status", [408, 429, 500, 503])
def test_send_changes_transient_failure_is_retryable(server, status):
    server.queue("POST", CHANGES, Reply(status=status, raw=b"busy", content_type="text/plain",
                                        headers={"Retry-After": "7"}))
    with pytest.raises(WolfAccessHTTPError) as exc:
        client_for(server).send_changes([wire(1)])
    assert exc.value.retryable is True and exc.value.retry_after == 7


def test_send_changes_unreachable_is_retryable():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        client = WolfAccessClient(f"http://127.0.0.1:{s.getsockname()[1]}", CRED, timeout=1,
                                  service="wolfnotes")
        with pytest.raises(WolfAccessUnavailable) as exc:
            client.send_changes([wire(1)])
    assert exc.value.retryable is True


def test_service_name_is_percent_encoded_in_the_path(server):
    server.reply = Reply(body={"results": [{"sequence": 1, "status": "applied"}],
                               "applied_through": 1})
    client_for(server, service="wolf.notes~1").send_changes([wire(1)])
    assert server.requests[0].path == "/v1/services/wolf.notes~1/changes"


# --- changes out (API-D10 (b)) -------------------------------------------------------

def test_changes_page_lists_rows_after_n(server):
    intake = FakeIntake(server)
    intake.refuse[3] = "refused for a reason"
    client = client_for(server)
    client.send_changes([wire(1), wire(2), wire(3), wire(4)])
    page = client.changes_page(1)
    assert page == ChangesAnswer(results=(ChangeResult(2, "applied"),
                                          ChangeResult(3, "refused", "refused for a reason"),
                                          ChangeResult(4, "held")),
                                 applied_through=2)
    assert server.requests[-1].method == "GET"
    assert server.requests[-1].path == CHANGES + "?after=1"


@pytest.mark.parametrize("after", [-1, True, "1", None, 1.5])
def test_changes_page_after_is_a_sequence_number(server, after):
    with pytest.raises(ValueError):
        client_for(server).changes_page(after)


@pytest.mark.parametrize("answer", [
    {"results": [{"sequence": 1, "status": "applied"}], "applied_through": 1},  # not after 1
    {"results": [{"sequence": 3, "status": "applied"}, {"sequence": 2, "status": "applied"}],
     "applied_through": 3},                                                   # not in order
    {"results": [{"sequence": 2, "status": "applied"}] * 2, "applied_through": 2},
    {"results": [{"sequence": n, "status": "held"} for n in range(2, 1003)],
     "applied_through": 1},                                                   # over 1000
    {"results": []},
])
def test_changes_page_malformed_answer(server, answer):
    server.queue("GET", CHANGES, Reply(body=answer))
    with pytest.raises(WolfAccessResponseError):
        client_for(server).changes_page(1)


def test_changes_since_follows_every_page_oldest_first(server):
    page1 = [{"sequence": n, "status": "applied"} for n in range(1, 1001)]
    page2 = [{"sequence": 1001, "status": "held"}]
    server.queue("GET", CHANGES, Reply(body={"results": page1, "applied_through": 1000}),
                 Reply(body={"results": page2, "applied_through": 1000}))
    got = list(client_for(server).changes_since(0))
    assert [r.sequence for r in got] == list(range(1, 1002))
    assert got[-1] == ChangeResult(1001, "held")
    assert [r.path for r in server.requests] == [CHANGES + "?after=0",
                                                 CHANGES + "?after=1000"]


def test_changes_since_stops_on_a_short_page(server):
    server.queue("GET", CHANGES, Reply(body={"results": [{"sequence": 6, "status": "applied"}],
                                             "applied_through": 6}))
    assert list(client_for(server).changes_since(5)) == [ChangeResult(6, "applied")]
    assert len(server.requests) == 1


def test_changes_since_is_lazy_and_checks_arguments_first(server):
    with pytest.raises(ValueError):
        client_for(server).changes_since(-1)
    it = client_for(server).changes_since(0)
    assert server.requests == []
    server.queue("GET", CHANGES, Reply(body={"results": [], "applied_through": 0}))
    assert list(it) == []


def test_changes_since_failure_raises_from_the_iterator(server):
    server.queue("GET", CHANGES, Reply(status=503, raw=b"", content_type="text/plain"))
    with pytest.raises(WolfAccessHTTPError) as exc:
        list(client_for(server).changes_since(0))
    assert exc.value.retryable is True


# --- the seed gate on decisions (API-D10 (d)) -----------------------------------------

SEED_TEXT = b"decisions are answered once the seed is verified (CUT-D1)"


@pytest.mark.parametrize("call", ["evaluation", "evaluations", "search"])
def test_409_on_a_decision_is_seed_not_verified(server, call):
    """No decision until the service's seed is verified: a `DecisionRefused`
    (so an `AccessUnavailable`, treated as deny) of its own kind."""
    server.reply = Reply(status=409, raw=SEED_TEXT, content_type="text/plain")
    client = client_for(server)
    with pytest.raises(SeedNotVerified) as exc:
        if call == "evaluation":
            client.evaluation(user_id="u", client_id="c", action="view",
                              resource_type="wolfnotes/note", resource_id="n-1")
        elif call == "evaluations":
            from wolf_access_client import EvaluationItem
            client.evaluations(user_id="u", client_id="c",
                               items=[EvaluationItem("view", "wolfnotes/note", "n-1")])
        else:
            list(client.search_resources(user_id="u", client_id="c", action="view",
                                         resource_type="wolfnotes/note"))
    err = exc.value
    assert isinstance(err, DecisionRefused) and isinstance(err, AccessUnavailable)
    assert err.status == 409 and err.retryable is False
    assert SEED_TEXT.decode() not in str(err) and SEED_TEXT.decode() not in repr(err)


def test_other_decision_refusals_are_not_seed_not_verified(server):
    server.reply = Reply(status=403, raw=b"no", content_type="text/plain")
    with pytest.raises(DecisionRefused) as exc:
        client_for(server).evaluation(user_id="u", client_id="c", action="view",
                                      resource_type="wolfnotes/note", resource_id="n-1")
    assert not isinstance(exc.value, SeedNotVerified)


# --- use_outbox on direct writes (API-D10 (c)) -----------------------------------------

@pytest.mark.parametrize("write", ["create", "update", "delete"])
def test_direct_write_from_a_service_with_a_mode_is_use_outbox(server, write):
    server.reply = problem("use_outbox", 409, "this service has a mode")
    client = client_for(server)
    with pytest.raises(UseOutboxError) as exc:
        if write == "create":
            client.create_resource("wolfnotes/note", "n-1", owner=PrincipalRef.user("u"),
                                   author="u")
        elif write == "update":
            client.update_resource("wolfnotes/note", "n-1", private=True)
        else:
            client.delete_resource("wolfnotes/note", "n-1")
    assert (exc.value.status, exc.value.name, exc.value.retryable) == (409, "use_outbox",
                                                                       False)


def test_bad_request_on_changes_is_typed(server):
    server.queue("POST", CHANGES, problem("bad_request", 400, "rows"))
    with pytest.raises(BadRequestError):
        client_for(server).send_changes([wire(1)])
