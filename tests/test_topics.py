"""Topics and hints (wolf-access M7: WN-2..WN-8, WN-D3, SCP-D2, API-D3, API-D5,
CUT-D1 (2); decisions Q-T7, Q-T17..Q-T24).

- `set_topic_level`: `PUT /v1/resources/{type}/{id}/topics/{topic}` with
  `{level, reason, source, category}` (+ `user_id`, `client_id` for an owner
  answer). 200 `Written`, 202 `Pending`, 202 `Proposed` (an AI loosening, or
  an AI level above the ceiling, waiting for the owner). `needs_input` is never
  a level (WN-6); a reason is never empty (WN-2).
- `Change.create_topic`: the topic child is created through the outbox (Q-T7),
  parent = the note.
- `search_resources_with_hints`: the resources plus `context.hints[]`, each a
  person, a topic and a handle only (WN-8); never a score (WN-P2).
- `topic_examples`: the owner answers wolf-access keeps (WN-7).
- `AccessGate.hints`: no hint while any outbox row is unapplied, before the
  restart gate opens, or in `off` / `shadow` (CUT-D1 (2))."""
from __future__ import annotations

import pytest

from tests.fake_server import FakeWolfAccess, Reply, problem
from wolf_access_client import (
    AccessGate,
    Change,
    ChangesAnswer,
    Hint,
    Pending,
    PrincipalRef,
    ProblemError,
    Proposed,
    ResourceRef,
    ResourceSearch,
    TopicExample,
    WolfAccessClient,
    WolfAccessResponseError,
    Written,
)

CRED = "svc-credential-not-a-secret"
NOTE, TOPIC = "wolfnotes/note", "wolfnotes/topic"
PUT_PATH = "/v1/resources/wolfnotes/note/n-1/topics/t-1"
RES = "/access/v1/search/resource"
EXAMPLES = "/v1/services/wolfnotes/topic-examples"


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        yield fake


def client(server):
    return WolfAccessClient(server.url, CRED, service="wolfnotes")


def put(c, **overrides):
    args = dict(level="hidden", reason="names a person's diagnosis", source="ai",
                category="health")
    args.update(overrides)
    return c.set_topic_level(NOTE, "n-1", "t-1", **args)


# --- PUT .../topics/{topic} ---------------------------------------------------------

def test_a61_ai_proposal_request_shape(server):
    server.reply = Reply(body={"zedtoken": "zt-9"})
    c = client(server)
    assert put(c) == Written("zt-9")
    (seen,) = server.requests
    assert (seen.method, seen.path) == ("PUT", PUT_PATH)
    assert seen.body == {"level": "hidden", "reason": "names a person's diagnosis",
                         "source": "ai", "category": "health"}
    assert c.zedtoken == "zt-9"


@pytest.mark.parametrize("level", ["readable", "hinted", "hidden"])
def test_a61_every_level_is_accepted(server, level):
    server.reply = Reply(body={"zedtoken": "zt"})
    assert put(client(server), level=level, category="other") == Written("zt")


@pytest.mark.parametrize("reason", ["", "   ", None, 3])
def test_a61_a_level_without_a_reason_is_refused_before_sending(server, reason):
    with pytest.raises(ValueError):
        put(client(server), reason=reason)
    assert server.requests == []


def test_a65_needs_input_is_never_a_level(server):
    with pytest.raises(ValueError, match="needs_input"):
        put(client(server), level="needs_input")
    with pytest.raises(ValueError):
        put(client(server), level="secret")
    assert server.requests == []


@pytest.mark.parametrize("category", ["people", "money", "health", "legal", "other"])
def test_category_values(server, category):
    server.reply = Reply(body={"zedtoken": "zt"})
    put(client(server), category=category)
    assert server.requests[-1].body["category"] == category


def test_unknown_category_or_source_is_refused(server):
    with pytest.raises(ValueError):
        put(client(server), category="gossip")
    with pytest.raises(ValueError):
        put(client(server), source="robot")
    assert server.requests == []


def test_a64_ai_loosening_comes_back_proposed(server):
    server.reply = Reply(status=202, body={"status": "proposed", "proposal": "p-7"})
    assert put(client(server), level="readable", category="other") == Proposed("p-7")


def test_pending_answer(server):
    server.reply = Reply(status=202, body={"status": "pending"})
    assert put(client(server)) == Pending()


def test_a_proposed_answer_without_a_handle_is_a_response_error(server):
    server.reply = Reply(status=202, body={"status": "proposed"})
    with pytest.raises(WolfAccessResponseError):
        put(client(server))


def test_owner_answer_carries_the_callers_ids(server):
    server.reply = Reply(body={"zedtoken": "zt"})
    put(client(server), source="owner", level="readable", category="other",
        user_id="user-1", client_id="client-1")
    assert server.requests[-1].body == {
        "level": "readable", "reason": "names a person's diagnosis", "source": "owner",
        "category": "other", "user_id": "user-1", "client_id": "client-1"}


def test_owner_answer_needs_both_ids_and_ai_takes_neither(server):
    with pytest.raises(ValueError):
        put(client(server), source="owner", user_id="user-1")
    with pytest.raises(ValueError):
        put(client(server), source="owner", client_id="client-1")
    with pytest.raises(ValueError):
        put(client(server), source="ai", user_id="user-1", client_id="client-1")
    assert server.requests == []


def test_a62_owner_above_ceiling_is_a_typed_problem(server):
    server.reply = problem("above_ceiling", 422)
    with pytest.raises(ProblemError) as err:
        put(client(server), source="owner", level="readable", category="people",
            user_id="user-1", client_id="client-1")
    assert err.value.name == "above_ceiling" and err.value.status == 422


def test_topic_path_is_quoted(server):
    server.reply = Reply(body={"zedtoken": "zt"})
    client(server).set_topic_level(NOTE, "n/1", "t 1", level="hidden", reason="r",
                                   source="ai", category="legal")
    assert server.requests[-1].path == "/v1/resources/wolfnotes/note/n%2F1/topics/t%201"


# --- the topic child, through the outbox (Q-T7) --------------------------------------

def test_create_topic_is_a_create_under_the_note():
    note = ResourceRef(NOTE, "n-1")
    change = Change.create_topic(ResourceRef(TOPIC, "t-1"), note=note,
                                 owner=PrincipalRef.user("user-1"), author="user-2")
    assert change == Change.create(ResourceRef(TOPIC, "t-1"), parent=note,
                                   owner=PrincipalRef.user("user-1"), author="user-2")
    assert change.wire()["parent"] == {"type": NOTE, "id": "n-1"}


def test_create_topic_needs_a_note_parent():
    with pytest.raises(ValueError):
        Change.create_topic(ResourceRef(TOPIC, "t-1"), note=None,
                            owner=PrincipalRef.user("user-1"), author="user-1")


# --- hints in search context (API-D5, WN-8, WN-P2) ------------------------------------

def page(results, hints=None, next_token="", **context):
    body = {"results": results, "page": {"next_token": next_token, "count": len(results)}}
    if hints is not None or context:
        body["context"] = {**({"hints": hints} if hints is not None else {}), **context}
    return Reply(body=body)


def search(c):
    return c.search_resources_with_hints(user_id="user-1", client_id="client-1",
                                         action="view", resource_type=NOTE)


H1 = {"person": "user-9", "topic": "t-1", "hint": "h-1"}
H2 = {"person": "user-8", "topic": "t-2", "hint": "h-2"}


def test_hints_come_back_with_the_resources(server):
    server.queue("POST", RES, page([{"type": NOTE, "id": "n-1"}], [H1], "tok"),
                 page([{"type": NOTE, "id": "n-2"}], [H2]))
    found = search(client(server))
    assert found == ResourceSearch(
        resources=(ResourceRef(NOTE, "n-1"), ResourceRef(NOTE, "n-2")),
        hints=(Hint("user-9", "t-1", "h-1"), Hint("user-8", "t-2", "h-2")))


def test_no_hints_key_is_no_hints(server):
    server.queue("POST", RES, page([{"type": NOTE, "id": "n-1"}]))
    assert search(client(server)).hints == ()


@pytest.mark.parametrize("extra", [{"title": "Q3 layoffs"}, {"content": "..."},
                                   {"count": 3}, {"score": 0.9}])
def test_a67_a_hint_carrying_anything_but_person_topic_handle_is_dropped(server, extra):
    server.queue("POST", RES, page([], [{**H1, **extra}, H2]))
    assert search(client(server)).hints == (Hint("user-8", "t-2", "h-2"),)


@pytest.mark.parametrize("bad", [{"person": "", "topic": "t", "hint": "h"},
                                 {"person": "u", "topic": 3, "hint": "h"},
                                 {"person": "u", "topic": "t"}, "h-1", None])
def test_a_malformed_hint_is_dropped(server, bad):
    server.queue("POST", RES, page([], [bad, H2]))
    assert search(client(server)).hints == (Hint("user-8", "t-2", "h-2"),)


def test_hints_that_are_not_a_list_are_a_response_error(server):
    server.queue("POST", RES, page([], {"person": "u"}))
    with pytest.raises(WolfAccessResponseError):
        search(client(server))


def test_a146_no_score_reaches_the_caller(server):
    server.queue("POST", RES, page([{"type": NOTE, "id": "n-1"}], [H1], score=0.7,
                                   scores=[1]))
    found = search(client(server))
    assert "score" not in repr(found)
    assert set(Hint.__dataclass_fields__) == {"person", "topic", "hint"}


def test_a_hint_request_names_the_handle(server):
    server.reply = Reply(status=201, body={"request": "r-1", "continue": "c"})
    client(server).request_access(user_id="user-1", client_id="client-1", role="Viewer",
                                  hint="h-1")
    assert server.requests[-1].body["target"] == {"hint": "h-1"}


# --- owner answers kept as examples (WN-7) ---------------------------------------------

EX = {"topic": "t-1", "category": "health", "level": "hidden", "reason": "r", "by": "user-1",
      "at": "2026-10-08T10:00:00Z"}


def test_a66_topic_examples_pages_through_the_cursor(server):
    server.queue("GET", EXAMPLES, Reply(body={"examples": [EX], "next": "c-1"}))
    server.queue("GET", EXAMPLES, Reply(body={"examples": [
        {**EX, "topic": "t-2"}], "next": ""}))
    got = list(client(server).topic_examples())
    assert [e.topic for e in got] == ["t-1", "t-2"]
    assert got[0] == TopicExample("t-1", "health", "hidden", "r", "user-1",
                                  "2026-10-08T10:00:00Z")
    assert [s.path for s in server.requests] == [EXAMPLES, EXAMPLES + "?after=c-1"]


def test_topic_examples_limit(server):
    server.queue("GET", EXAMPLES, Reply(body={"examples": [], "next": ""}))
    assert list(client(server).topic_examples(limit=5)) == []
    assert server.requests[-1].path == EXAMPLES + "?limit=5"
    with pytest.raises(ValueError):
        list(client(server).topic_examples(limit=0))


def test_a_malformed_example_page_is_a_response_error(server):
    server.queue("GET", EXAMPLES, Reply(body={"examples": [{"topic": "t"}], "next": ""}))
    with pytest.raises(WolfAccessResponseError):
        list(client(server).topic_examples())


# --- AccessGate.hints (CUT-D1 (2)) -----------------------------------------------------

HINTS = (Hint("user-9", "t-1", "h-1"),)


def gate(mode, server, store):
    return AccessGate(mode, client(server), outbox=store, ancestors=lambda ref: ())


def test_on_passes_hints_when_every_row_is_applied(server, sqlite_backend):
    assert gate("on", server, sqlite_backend.store).hints(HINTS) == list(HINTS)


def test_on_drops_every_hint_while_any_row_is_unapplied(server, sqlite_backend):
    g = gate("on", server, sqlite_backend.store)
    sqlite_backend.append(Change.create(ResourceRef(NOTE, "n-5"),
                                        owner=PrincipalRef.user("user-1"), author="user-1"))
    assert g.hints(HINTS) == []
    sqlite_backend.store.record(ChangesAnswer(results=(), applied_through=1))
    assert g.hints(HINTS) == list(HINTS)


def test_on_drops_hints_until_the_restart_gate_opens(server, sqlite_backend):
    sqlite_backend.append(Change.create(ResourceRef(NOTE, "n-5"),
                                        owner=PrincipalRef.user("user-1"), author="user-1"))
    g = gate("on", server, sqlite_backend.store)
    assert g.hints(HINTS) == []


def test_off_and_shadow_show_no_hints(server, sqlite_backend):
    assert AccessGate("off").hints(HINTS) == []
    assert gate("shadow", server, sqlite_backend.store).hints(HINTS) == []


def test_on_drops_hints_when_the_outbox_cannot_be_read(server):
    class Broken:
        def progress(self):
            raise OSError("disk")

        def unapplied(self, refs):
            raise OSError("disk")
    g = AccessGate("on", client(server), outbox=Broken(), ancestors=lambda r: ())
    assert g.hints(HINTS) == []
