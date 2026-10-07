"""`AccessGate` at cut-over (CUT-D1 (2), the seed gate, #28):

- No answer from stale data: in `shadow` and `on`, while a resource, or any
  resource above it in the service's own parent chain, has an outbox row
  wolf-access has not applied, a check on it denies in `on` (logged as
  `shadow_deny` in `shadow`) and the list-filter leaves it out.
- Restart gate: in `on`, after start-up, every check denies and every
  filter is empty until every row written before start-up is applied and
  none is dead-lettered.
- A 409 from the seed gate is no answer: `shadow` allows, `on` denies.
- `health` is degraded while the gate cannot answer."""
from __future__ import annotations

import logging
import socket

import pytest

from tests.fake_server import FakeWolfAccess, Reply
from wolf_access_client import (
    AccessGate,
    Change,
    ChangeResult,
    ChangesAnswer,
    GateHealth,
    PrincipalRef,
    ResourceRef,
    WolfAccessClient,
)

CRED = "svc-credential-not-a-secret"
EVAL, BATCH = "/access/v1/evaluation", "/access/v1/evaluations"
LOGGER = "wolf_access_client"
NOTE, FOLDER = "wolfnotes/note", "wolfnotes/folder"
SEED_409 = Reply(status=409, raw=b"decisions are answered once the seed is verified (CUT-D1)",
                 content_type="text/plain")

#: The service's own parent chain: n-1 and n-2 sit in f-1, n-3 in f-2.
TREE = {ResourceRef(NOTE, "n-1"): [ResourceRef(FOLDER, "f-1")],
        ResourceRef(NOTE, "n-2"): [ResourceRef(FOLDER, "f-1")],
        ResourceRef(NOTE, "n-3"): [ResourceRef(FOLDER, "f-2")]}


def ancestors(ref):
    return TREE.get(ref, [])


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        fake.reply = Reply(body={"decision": True})
        yield fake


@pytest.fixture
def store(sqlite_backend):
    return sqlite_backend.store


def gate_for(mode, server, store, **kw):
    kw.setdefault("ancestors", ancestors)
    return AccessGate(mode, WolfAccessClient(server.url, CRED, service="wolfnotes"),
                      outbox=store, **kw)


def check(gate, rid="n-1", rtype=NOTE, **kw):
    return gate.check(user_id="user-1", client_id="client-1", action="view",
                      resource_type=rtype, resource_id=rid, **kw)


def keep(gate, ids):
    return gate.filter(ids, user_id="user-1", client_id="client-1", action="view",
                       resource_type=NOTE)


def events(caplog, name):
    return [r for r in caplog.records if r.name == LOGGER and getattr(r, "event", None) == name]


def append(backend, *changes):
    return backend.append(*changes)


def move(rid, folder="f-2"):
    return Change.move(ResourceRef(NOTE, rid), parent=ResourceRef(FOLDER, folder))


def create_folder(fid):
    return Change.create(ResourceRef(FOLDER, fid), owner=PrincipalRef.user("user-1"),
                         author="user-1")


def applied_through(store, n):
    store.record(ChangesAnswer(results=(), applied_through=n))


# --- construction -------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["shadow", "on"])
def test_shadow_and_on_need_the_outbox_and_the_parent_chain(server, store, mode):
    client = WolfAccessClient(server.url, CRED, service="wolfnotes")
    with pytest.raises(ValueError):
        AccessGate(mode, client)
    with pytest.raises(ValueError):
        AccessGate(mode, client, outbox=store)
    with pytest.raises(ValueError):
        AccessGate(mode, client, outbox=store, ancestors="not callable")
    with pytest.raises(ValueError):
        AccessGate(mode, client, outbox=object(), ancestors=ancestors)
    assert AccessGate(mode, client, outbox=store, ancestors=ancestors).mode.value == mode


def test_off_needs_neither_and_never_reads_the_outbox(server):
    class Untouchable:
        def __getattr__(self, name):
            raise AssertionError(f"off read the outbox ({name})")
    gate = AccessGate("off", outbox=Untouchable(), ancestors=ancestors)
    assert check(gate) is True and keep(gate, ["n-1"]) == ["n-1"]
    assert gate.withheld([ResourceRef(NOTE, "n-1")]) == set()
    assert gate.health == GateHealth("ok")
    assert AccessGate("off").health.status == "ok"


# --- no answer from stale data ----------------------------------------------------------

def test_on_denies_a_resource_with_an_unapplied_row_without_asking(server, store,
                                                                   sqlite_backend):
    gate = gate_for("on", server, store)               # started with an empty outbox
    append(sqlite_backend, move("n-1"))
    assert check(gate, "n-1") is False
    assert check(gate, "n-3") is True                  # another resource is answered
    assert [r.path for r in server.requests] == [EVAL]
    assert server.requests[0].body["resource"]["id"] == "n-3"
    applied_through(store, 1)
    assert check(gate, "n-1") is True


def test_on_denies_under_a_parent_with_an_unapplied_row(server, store, sqlite_backend):
    gate = gate_for("on", server, store)
    append(sqlite_backend, create_folder("f-1"))
    assert check(gate, "n-1") is False and check(gate, "n-2") is False
    assert check(gate, "f-1", rtype=FOLDER) is False
    assert check(gate, "n-3") is True


def test_pending_held_and_dead_lettered_rows_all_count(server, store, sqlite_backend):
    gate = gate_for("on", server, store)
    append(sqlite_backend, move("n-1"), move("n-2"), move("n-3"))
    store.record(ChangesAnswer(results=(ChangeResult(1, "refused", "why"),
                                        ChangeResult(2, "held")), applied_through=0))
    assert [check(gate, r) for r in ("n-1", "n-2", "n-3")] == [False, False, False]
    assert server.requests == []


def test_shadow_logs_a_stale_resource_as_shadow_deny_and_allows(server, store,
                                                                sqlite_backend, caplog):
    caplog.set_level(logging.INFO, LOGGER)
    gate = gate_for("shadow", server, store)
    append(sqlite_backend, move("n-1"))
    assert check(gate, "n-1") is True
    (record,) = events(caplog, "shadow_deny")
    assert (record.resource_id, record.reason) == ("n-1", "outbox_unapplied")
    assert server.requests == []


def test_on_filter_leaves_stale_resources_out_and_asks_about_the_rest(server, store,
                                                                     sqlite_backend):
    gate = gate_for("on", server, store)
    append(sqlite_backend, create_folder("f-1"))
    server.reply = Reply(body={"evaluations": [{"decision": True}, {"decision": False}]})
    assert keep(gate, ["n-3", "n-1", "n-9", "n-2"]) == ["n-3"]
    (seen,) = server.requests
    assert [e["resource"]["id"] for e in seen.body["evaluations"]] == ["n-3", "n-9"]


def test_on_filter_of_only_stale_resources_sends_nothing(server, store, sqlite_backend):
    gate = gate_for("on", server, store)
    append(sqlite_backend, create_folder("f-1"))
    assert keep(gate, ["n-1", "n-2"]) == []
    assert server.requests == []


def test_shadow_filter_keeps_everything_and_logs_stale_and_denied(server, store,
                                                                  sqlite_backend, caplog):
    caplog.set_level(logging.INFO, LOGGER)
    gate = gate_for("shadow", server, store)
    append(sqlite_backend, move("n-1"))
    server.reply = Reply(body={"evaluations": [{"decision": False}, {"decision": True}]})
    assert keep(gate, ["n-1", "n-2", "n-3"]) == ["n-1", "n-2", "n-3"]
    denies = [(r.resource_id, getattr(r, "reason", None))
              for r in events(caplog, "shadow_deny")]
    assert sorted(denies) == [("n-1", "outbox_unapplied"), ("n-2", "decision")]


def test_withheld_names_the_stale_resources(server, store, sqlite_backend):
    """For a service with a gate of its own: which of these resources must not
    be answered now (drop them from a search in `on`, log them in `shadow`)."""
    for mode in ("shadow", "on"):
        gate = gate_for(mode, server, store)
        refs = [ResourceRef(NOTE, i) for i in ("n-1", "n-2", "n-3")]
        assert gate.withheld(refs) == set()
        append(sqlite_backend, create_folder("f-1"))
        assert gate.withheld(refs) == {refs[0], refs[1]}
        applied_through(store, store.progress().last_sequence)


def test_the_parent_chain_is_not_read_while_nothing_is_unapplied(server, store):
    calls = []

    def chain(ref):
        calls.append(ref)
        return []
    gate = gate_for("on", server, store, ancestors=chain)
    check(gate, "n-1")
    keep(gate, ["n-1", "n-2"])
    assert calls == []


def test_an_unreadable_outbox_is_no_answer(server, caplog):
    caplog.set_level(logging.INFO, LOGGER)

    class Down:
        service = "wolfnotes"

        def progress(self):
            raise OSError("database is down")

        def unapplied(self, refs):
            raise OSError("database is down")
    for mode, expected in (("on", False), ("shadow", True)):
        gate = AccessGate(mode, WolfAccessClient(server.url, CRED), outbox=Down(),
                          ancestors=ancestors)
        assert check(gate) is expected
        assert keep(gate, ["n-1"]) == (["n-1"] if expected else [])
        assert gate.health == GateHealth("degraded", "outbox_error")
    assert server.requests == []
    assert events(caplog, "outbox_error")


def test_a_failing_parent_chain_is_no_answer(server, store, sqlite_backend):
    def chain(ref):
        raise LookupError("the service's own database is down")
    gate = gate_for("on", server, store, ancestors=chain)
    append(sqlite_backend, move("n-1"))
    assert check(gate, "n-3") is False
    assert gate.health == GateHealth("degraded", "outbox_error")


# --- the restart gate (on only) -----------------------------------------------------------

def test_on_after_a_restart_denies_everything_until_earlier_rows_are_applied(
        server, store, sqlite_backend):
    append(sqlite_backend, move("n-1"), move("n-2"))          # written before start-up
    gate = gate_for("on", server, store)
    assert check(gate, "n-3") is False
    assert keep(gate, ["n-3"]) == []
    assert gate.withheld([ResourceRef(NOTE, "n-3")]) == {ResourceRef(NOTE, "n-3")}
    assert gate.health == GateHealth("degraded", "restart_gate")
    assert server.requests == []
    applied_through(store, 1)
    assert check(gate, "n-3") is False                        # row 2 still unapplied
    append(sqlite_backend, move("n-3"))                       # after start-up: not waited for
    applied_through(store, 2)
    assert check(gate, "n-9") is True
    assert check(gate, "n-3") is False                        # its own row is unapplied
    assert gate.health == GateHealth("ok")


def test_the_restart_gate_also_waits_for_a_dead_letter(server, store, sqlite_backend):
    append(sqlite_backend, move("n-1"))
    gate_store_row = store.unapplied_rows(1)[0]
    store.record(ChangesAnswer(results=(ChangeResult(gate_store_row.sequence, "refused", "x"),),
                               applied_through=0))
    gate = gate_for("on", server, store)
    assert check(gate, "n-9") is False
    store.record(ChangesAnswer(results=(ChangeResult(1, "resolved"),), applied_through=1))
    assert check(gate, "n-9") is True


def test_the_restart_gate_stays_open_once_open(server, store, sqlite_backend):
    gate = gate_for("on", server, store)
    assert check(gate, "n-9") is True
    append(sqlite_backend, move("n-1"))
    store.record(ChangesAnswer(results=(ChangeResult(1, "refused", "x"),), applied_through=0))
    assert check(gate, "n-9") is True                          # only n-1 is withheld
    assert check(gate, "n-1") is False


def test_shadow_has_no_restart_gate(server, store, sqlite_backend):
    append(sqlite_backend, move("n-1"))
    gate = gate_for("shadow", server, store)
    assert check(gate, "n-3") is True
    assert [r.path for r in server.requests] == [EVAL]
    assert gate.health == GateHealth("ok")


def test_a_restart_gate_with_an_unreadable_outbox_at_start_up_waits(server, sqlite_backend):
    """If the outbox cannot be read at start-up, the first read that works
    sets the point to wait for."""
    store = sqlite_backend.store
    reads = {"n": 0}

    class Flaky:
        service = "wolfnotes"

        def progress(self):
            reads["n"] += 1
            if reads["n"] == 1:
                raise OSError("not yet")
            return store.progress()

        def unapplied(self, refs):
            return store.unapplied(refs)
    append(sqlite_backend, move("n-1"))
    gate = AccessGate("on", WolfAccessClient(server.url, CRED), outbox=Flaky(),
                      ancestors=ancestors)
    assert check(gate, "n-9") is False
    applied_through(store, 1)
    assert check(gate, "n-9") is True


# --- the seed gate: a 409 is no answer --------------------------------------------------

def test_seed_not_verified_denies_in_on_and_allows_in_shadow(server, store, caplog):
    caplog.set_level(logging.INFO, LOGGER)
    server.reply = SEED_409
    on, shadow = gate_for("on", server, store), gate_for("shadow", server, store)
    assert check(on) is False and keep(on, ["n-1"]) == []
    assert check(shadow) is True and keep(shadow, ["n-1"]) == ["n-1"]
    assert len(events(caplog, "seed_not_verified")) == 4
    assert events(caplog, "shadow_deny") == []
    assert on.health == GateHealth("degraded", "seed_not_verified")
    assert shadow.health == GateHealth("degraded", "seed_not_verified")
    server.reply = Reply(body={"decision": True})
    assert check(on) is True
    assert on.health == GateHealth("ok")


# --- health (#28) ---------------------------------------------------------------------------

@pytest.fixture
def dead_client():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        yield WolfAccessClient(f"http://127.0.0.1:{s.getsockname()[1]}", CRED, timeout=1)


@pytest.mark.parametrize("mode", ["shadow", "on"])
def test_health_is_degraded_while_wolf_access_is_unreachable(dead_client, store, mode):
    gate = AccessGate(mode, dead_client, outbox=store, ancestors=ancestors)
    assert gate.health == GateHealth("ok")
    check(gate)
    assert gate.health == GateHealth("degraded", "unavailable")
    assert gate.health.as_dict() == {"status": "degraded", "reason": "unavailable"}


def test_health_recovers_after_an_answer(server, store):
    gate = gate_for("on", server, store)
    server.reply = Reply(status=503, raw=b"", content_type="text/plain")
    check(gate)
    assert gate.health.status == "degraded"
    server.reply = Reply(body={"decision": False})
    assert check(gate) is False
    assert gate.health == GateHealth("ok") and gate.health.as_dict() == {"status": "ok"}


def test_a_caller_mistake_does_not_degrade_health(server, store):
    gate = gate_for("on", server, store)
    assert gate.check(user_id=None, client_id="c", action="view", resource_type=NOTE,
                      resource_id="n-1") is False
    assert gate.health == GateHealth("ok")


# --- log lines cannot be forged (#29) -----------------------------------------------------

def test_shadow_deny_log_has_no_line_break(server, store, caplog):
    caplog.set_level(logging.INFO, LOGGER)
    server.reply = Reply(body={"decision": False})
    gate = gate_for("shadow", server, store)
    assert check(gate, "n-1\nshadow_deny user_id=admin forged") is True
    (record,) = [r for r in caplog.records if r.name == LOGGER]
    assert "\n" not in record.getMessage() and "\r" not in record.getMessage()
    assert record.resource_id == "n-1\nshadow_deny user_id=admin forged"   # kept, as data


def test_no_answer_log_has_no_line_break(dead_client, store, caplog):
    caplog.set_level(logging.INFO, LOGGER)
    gate = AccessGate("on", dead_client, outbox=store, ancestors=ancestors)
    gate.check(user_id="u", client_id="c", action="view\r\nforged", resource_type=NOTE,
               resource_id="n-1")
    (record,) = [r for r in caplog.records if r.name == LOGGER]
    assert "\n" not in record.getMessage() and "\r" not in record.getMessage()
