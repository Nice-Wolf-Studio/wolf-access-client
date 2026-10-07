"""The enforcement-mode helper (CUT-D1, CUT-S1): `off` never calls the
decision API; `shadow` calls, logs `shadow_deny`, and allows; `on` enforces
and fails closed. An unknown mode is refused when the helper is built."""
import logging
import socket

import pytest

from tests.fake_server import FakeWolfAccess, Reply
from wolf_access_client import AccessGate, AccessMode, OutboxProgress, WolfAccessClient

CRED = "svc-credential-not-a-secret"


class EmptyOutbox:
    """An outbox with every row applied: these tests are about decisions."""
    service = "wolfnotes"

    def progress(self):
        return OutboxProgress(last_sequence=0, applied_through=0, dead_letter=None)

    def unapplied(self, resources):
        return set()


#: `shadow` and `on` need the outbox and the service's parent chain (CUT-D1 (2)).
CUT = {"outbox": EmptyOutbox(), "ancestors": lambda ref: ()}
EVAL, BATCH = "/access/v1/evaluation", "/access/v1/evaluations"
LOGGER = "wolf_access_client"


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        yield fake


@pytest.fixture
def dead_client():
    """A client whose wolf-access refuses every connection."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        yield WolfAccessClient(f"http://127.0.0.1:{s.getsockname()[1]}", CRED, timeout=1)


def check(gate, **overrides):
    args = dict(user_id="user-1", client_id="client-1", action="view",
                resource_type="wolfnotes/note", resource_id="n-1")
    args.update(overrides)
    return gate.check(**args)


def keep(gate, ids, **overrides):
    args = dict(user_id="user-1", client_id="client-1", action="view",
                resource_type="wolfnotes/note")
    args.update(overrides)
    return gate.filter(ids, **args)


def events(caplog, name):
    return [r for r in caplog.records if r.name == LOGGER and getattr(r, "event", None) == name]


# --- AccessMode -------------------------------------------------------------------

def test_modes():
    assert [m.value for m in AccessMode] == ["off", "shadow", "on"]
    assert AccessMode.parse("shadow") is AccessMode.SHADOW
    assert AccessMode.parse(AccessMode.ON) is AccessMode.ON


@pytest.mark.parametrize("value", ["", "OFF", "On", " on", "on ", "enforce", "true", None, 1,
                                   True])
def test_unknown_mode_is_refused(value):
    with pytest.raises(ValueError):
        AccessMode.parse(value)


def test_from_env_reads_service_access_mode():
    assert AccessMode.from_env("wolfnotes", {"WOLFNOTES_ACCESS_MODE": "shadow"}) \
        is AccessMode.SHADOW
    assert AccessMode.from_env("finops", {"FINOPS_ACCESS_MODE": "on"}) is AccessMode.ON


def test_from_env_unset_or_empty_is_off():
    """CUT-S1: the default enforcement mode is `off`. Empty counts as unset,
    as it already does in finOps and WolfNotes."""
    assert AccessMode.from_env("wolfnotes", {}) is AccessMode.OFF
    assert AccessMode.from_env("wolfnotes", {"WOLFNOTES_ACCESS_MODE": ""}) is AccessMode.OFF


@pytest.mark.parametrize("value", [" ", "ON", " on", "maybe"])
def test_from_env_set_to_an_unknown_value_is_refused(value):
    with pytest.raises(ValueError) as exc:
        AccessMode.from_env("wolfnotes", {"WOLFNOTES_ACCESS_MODE": value})
    assert "WOLFNOTES_ACCESS_MODE" in str(exc.value)


def test_from_env_defaults_to_the_process_environment(monkeypatch):
    monkeypatch.setenv("FINOPS_ACCESS_MODE", "shadow")
    assert AccessMode.from_env("finops") is AccessMode.SHADOW


@pytest.mark.parametrize("service", ["", None, "wolf notes", "a=b"])
def test_from_env_needs_a_service_name(service):
    with pytest.raises(ValueError):
        AccessMode.from_env(service, {})


# --- AccessGate: construction --------------------------------------------------------

@pytest.mark.parametrize("mode", ["", "OFF", "enforce", None, 0])
def test_gate_refuses_an_unknown_mode_at_construction(server, mode):
    with pytest.raises(ValueError):
        AccessGate(mode, WolfAccessClient(server.url, CRED))


@pytest.mark.parametrize("mode", ["shadow", "on"])
def test_shadow_and_on_need_a_client(mode):
    with pytest.raises(ValueError):
        AccessGate(mode, None)


def test_gate_accepts_a_mode_or_its_name(server):
    client = WolfAccessClient(server.url, CRED)
    assert AccessGate("shadow", client, **CUT).mode is AccessMode.SHADOW
    assert AccessGate(AccessMode.ON, client, **CUT).mode is AccessMode.ON
    assert AccessGate("off").mode is AccessMode.OFF


# --- off ------------------------------------------------------------------------------

def test_off_never_calls_the_decision_api(server, caplog):
    caplog.set_level(logging.DEBUG, LOGGER)
    gate = AccessGate("off", WolfAccessClient(server.url, CRED))
    server.reply = Reply(body={"decision": False})
    assert check(gate) is True
    assert keep(gate, ["n-1", "n-2"]) == ["n-1", "n-2"]
    assert server.requests == []
    assert events(caplog, "shadow_deny") == []


def test_off_keeps_today_s_behaviour_even_without_a_user_id():
    gate = AccessGate("off")
    assert check(gate, user_id=None, client_id=None) is True


# --- shadow ---------------------------------------------------------------------------

def test_shadow_deny_is_logged_and_allowed(server, caplog):
    caplog.set_level(logging.INFO, LOGGER)
    server.reply = Reply(body={"decision": False})
    assert check(AccessGate("shadow", WolfAccessClient(server.url, CRED), **CUT)) is True
    assert len(server.requests) == 1
    (record,) = events(caplog, "shadow_deny")
    assert record.levelno == logging.WARNING
    assert (record.user_id, record.client_id, record.action, record.resource_type,
            record.resource_id) == ("user-1", "client-1", "view", "wolfnotes/note", "n-1")
    assert CRED not in record.getMessage()


def test_shadow_allow_is_not_logged(server, caplog):
    caplog.set_level(logging.DEBUG, LOGGER)
    server.reply = Reply(body={"decision": True})
    assert check(AccessGate("shadow", WolfAccessClient(server.url, CRED), **CUT)) is True
    assert events(caplog, "shadow_deny") == []


def test_shadow_with_wolf_access_unreachable_proceeds(dead_client, caplog):
    """CUT-D1: in shadow, an unreachable wolf-access does not block the call."""
    caplog.set_level(logging.INFO, LOGGER)
    gate = AccessGate("shadow", dead_client, **CUT)
    assert check(gate) is True
    assert keep(gate, ["n-1"]) == ["n-1"]
    assert len(events(caplog, "access_unavailable")) == 2


def test_shadow_filter_logs_each_deny_and_keeps_everything(server, caplog):
    caplog.set_level(logging.INFO, LOGGER)
    server.reply = Reply(body={"evaluations": [{"decision": True}, {"decision": False},
                                               {"decision": False}]})
    gate = AccessGate("shadow", WolfAccessClient(server.url, CRED), **CUT)
    assert keep(gate, ["n-1", "n-2", "n-3"]) == ["n-1", "n-2", "n-3"]
    assert [r.resource_id for r in events(caplog, "shadow_deny")] == ["n-2", "n-3"]
    assert server.requests[0].path == BATCH


# --- on -------------------------------------------------------------------------------

def test_on_enforces(server):
    gate = AccessGate("on", WolfAccessClient(server.url, CRED), **CUT)
    server.reply = Reply(body={"decision": True})
    assert check(gate) is True
    server.reply = Reply(body={"decision": False})
    assert check(gate) is False
    assert [r.path for r in server.requests] == [EVAL, EVAL]


def test_on_fails_closed_when_wolf_access_is_unreachable(dead_client, caplog):
    caplog.set_level(logging.INFO, LOGGER)
    gate = AccessGate("on", dead_client, **CUT)
    assert check(gate) is False
    assert keep(gate, ["n-1", "n-2"]) == []
    assert len(events(caplog, "access_unavailable")) == 2


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_on_fails_closed_on_any_refusal(server, status):
    server.reply = Reply(status=status, raw=b"no", content_type="text/plain")
    gate = AccessGate("on", WolfAccessClient(server.url, CRED), **CUT)
    assert check(gate) is False
    assert keep(gate, ["n-1"]) == []


@pytest.mark.parametrize("missing", ["user_id", "client_id"])
def test_on_denies_a_call_without_a_user_id_or_client_id(server, missing, caplog):
    """A frame without a `user_id` fails closed; nothing is sent."""
    caplog.set_level(logging.INFO, LOGGER)
    gate = AccessGate("on", WolfAccessClient(server.url, CRED), **CUT)
    assert check(gate, **{missing: None}) is False
    assert keep(gate, ["n-1"], **{missing: None}) == []
    assert server.requests == []
    assert len(events(caplog, "invalid_request")) == 2


def test_shadow_allows_a_call_without_a_user_id_and_logs_it(server, caplog):
    caplog.set_level(logging.INFO, LOGGER)
    gate = AccessGate("shadow", WolfAccessClient(server.url, CRED), **CUT)
    assert check(gate, user_id=None) is True
    assert server.requests == []
    assert len(events(caplog, "invalid_request")) == 1


def test_on_filter_keeps_only_allowed_in_order(server):
    server.reply = Reply(body={"evaluations": [{"decision": False}, {"decision": True},
                                               {"decision": True}]})
    gate = AccessGate("on", WolfAccessClient(server.url, CRED), **CUT)
    assert keep(gate, ["n-3", "n-1", "n-2"]) == ["n-1", "n-2"]
    assert [e["resource"]["id"] for e in server.requests[0].body["evaluations"]] == [
        "n-3", "n-1", "n-2"]
    assert server.requests[0].body["options"] == {"evaluations_semantic": "execute_all"}


def test_on_filter_of_nothing_sends_nothing(server):
    assert keep(AccessGate("on", WolfAccessClient(server.url, CRED), **CUT), []) == []
    assert server.requests == []


def test_filter_splits_more_than_1000_ids_into_batches(server):
    server.queue("POST", BATCH, Reply(body={"evaluations": [{"decision": True}] * 1000}),
                 Reply(body={"evaluations": [{"decision": False}] * 499 +
                             [{"decision": True}]}))
    ids = [str(i) for i in range(1500)]
    assert keep(AccessGate("on", WolfAccessClient(server.url, CRED), **CUT), ids) == \
        ids[:1000] + ["1499"]
    assert [len(r.body["evaluations"]) for r in server.requests] == [1000, 500]


def test_filter_fails_closed_if_any_batch_fails(server):
    server.queue("POST", BATCH, Reply(body={"evaluations": [{"decision": True}] * 1000}),
                 Reply(status=503, raw=b"no", content_type="text/plain"))
    gate = AccessGate("on", WolfAccessClient(server.url, CRED), **CUT)
    assert keep(gate, [str(i) for i in range(1001)]) == []


def test_check_passes_extra_context(server):
    server.reply = Reply(body={"decision": True})
    check(AccessGate("on", WolfAccessClient(server.url, CRED), **CUT),
          context={"review_case": "case-1"})
    assert server.requests[0].body["context"] == {"client_id": "client-1",
                                                  "review_case": "case-1"}
