"""The outbox relay (CUT-D1 (1), API-D10): it reports the service's state at
start-up, then sends the outbox in sequence, in batches of at most 500, and
records every row's result. It backs off on 408, 429 (honouring
`Retry-After`), 5xx and network errors, across restarts; a refused row stays
at the head, alerted, until `retry_refused()`; held rows are sent again
later. `state` is ok, behind, refused or unavailable for the service's
`/health`."""
from __future__ import annotations

import logging
import socket
import threading
import time

import pytest

from tests.fake_server import SEED_WAIT, FakeIntake, FakeWolfAccess, Reply, problem
from wolf_access_client import (
    Change,
    OutboxRelay,
    PrincipalRef,
    RelayState,
    ResourceRef,
    WolfAccessClient,
)

CRED = "svc-credential-not-a-secret"
CHANGES = "/v1/services/wolfnotes/changes"
STATE = "/v1/services/wolfnotes/state"
LOGGER = "wolf_access_client"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def server():
    with FakeWolfAccess() as fake:
        yield fake


@pytest.fixture
def intake(server):
    return FakeIntake(server)


@pytest.fixture
def clock():
    return Clock()


def create(i):
    return Change.create(ResourceRef("wolfnotes/note", i), owner=PrincipalRef.user("u-1"),
                         author="u-1")


def relay_for(server, store, clock, **kw):
    kw.setdefault("mode", "off")
    client = WolfAccessClient(server.url, CRED, service="wolfnotes")
    return OutboxRelay(client, store, clock=clock, **kw)


def posts(server):
    return [[row["sequence"] for row in r.body["rows"]] for r in server.sent("POST", CHANGES)]


def events(caplog, name):
    return [r for r in caplog.records if r.name == LOGGER and getattr(r, "event", None) == name]


@pytest.fixture
def dead_url():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        yield f"http://127.0.0.1:{s.getsockname()[1]}"


# --- delivery in sequence --------------------------------------------------------------

def test_reports_state_then_delivers_in_sequence(server, intake, backend, clock):
    backend.append(create("n-1"), create("n-2"))
    backend.append(create("n-3"))
    relay = relay_for(server, backend.store, clock, mode="shadow")
    assert relay.state is RelayState.BEHIND
    assert relay.run_once() == 0
    assert [(r.method, r.path.split("?")[0]) for r in server.requests] == [
        ("PUT", STATE), ("POST", CHANGES)]
    assert intake.states[0]["mode"] == "shadow"
    assert intake.states[0]["registration_start"] == \
        backend.store.registration_start().isoformat()
    assert posts(server) == [[1, 2, 3]]
    assert [row["resource"]["id"] for row in intake.applied] == ["n-1", "n-2", "n-3"]
    assert relay.state is RelayState.OK
    assert backend.store.progress().applied_through == 3
    assert relay.run_once() == relay.idle_interval
    assert len(server.requests) == 2                  # nothing new: nothing sent


def test_state_is_reported_once_per_relay(server, intake, sqlite_backend, clock):
    relay = relay_for(server, sqlite_backend.store, clock)
    relay.run_once()
    sqlite_backend.append(create("n-1"))
    relay.run_once()
    assert len(intake.states) == 1


def test_nothing_to_send_is_ok_once_the_state_is_reported(server, intake, sqlite_backend,
                                                          clock):
    relay = relay_for(server, sqlite_backend.store, clock)
    assert relay.state is RelayState.BEHIND           # the state report is not made yet
    relay.run_once()
    assert relay.state is RelayState.OK
    assert server.sent("POST", CHANGES) == []


def test_batches_are_at_most_500_rows(server, intake, sqlite_backend, clock):
    sqlite_backend.append(*[create(f"n-{i}") for i in range(501)])
    relay = relay_for(server, sqlite_backend.store, clock)
    assert relay.run_once() == 0
    assert relay.run_once() == 0
    assert [len(p) for p in posts(server)] == [500, 1]
    assert posts(server)[1] == [501]
    assert relay.state is RelayState.OK


@pytest.mark.parametrize("size", [0, 501, True, 2.5])
def test_batch_size_is_1_to_500(server, sqlite_backend, clock, size):
    with pytest.raises(ValueError):
        relay_for(server, sqlite_backend.store, clock, batch_size=size)


def test_a_smaller_batch_size(server, intake, sqlite_backend, clock):
    sqlite_backend.append(*[create(f"n-{i}") for i in range(5)])
    relay = relay_for(server, sqlite_backend.store, clock, batch_size=2)
    while relay.run_once() == 0:
        pass
    assert posts(server) == [[1, 2], [3, 4], [5]]


def test_relay_needs_the_store_s_service(server, sqlite_backend, clock):
    with pytest.raises(ValueError):
        OutboxRelay(WolfAccessClient(server.url, CRED), sqlite_backend.store, mode="off")
    with pytest.raises(ValueError):
        OutboxRelay(WolfAccessClient(server.url, CRED, service="finops"),
                    sqlite_backend.store, mode="off")


@pytest.mark.parametrize("mode", ["", "OFF", None])
def test_relay_needs_a_mode(server, sqlite_backend, clock, mode):
    with pytest.raises(ValueError):
        relay_for(server, sqlite_backend.store, clock, mode=mode)


# --- retries and backoff --------------------------------------------------------------

def test_unreachable_wolf_access_keeps_rows_and_delivers_after_a_restart(
        server, intake, backend, clock, dead_url):
    """A change queued while wolf-access is unreachable is delivered after it
    returns, also across a service restart (criterion 181)."""
    backend.append(create("n-1"))
    down = OutboxRelay(WolfAccessClient(dead_url, CRED, timeout=1, service="wolfnotes"),
                       backend.store, mode="on", clock=clock)
    delay = down.run_once()
    assert delay > 0 and down.state is RelayState.UNAVAILABLE
    assert backend.store.progress().applied_through == 0
    restarted = relay_for(server, backend.store, clock, mode="on")      # a new process
    assert restarted.run_once() == 0
    assert posts(server) == [[1]] and restarted.state is RelayState.OK


def test_backoff_grows_on_each_failure_and_resets_on_success(server, intake, sqlite_backend,
                                                             clock):
    sqlite_backend.append(create("n-1"))
    for _ in range(4):
        server.queue("POST", CHANGES, Reply(status=503, raw=b"", content_type="text/plain"))
    relay = relay_for(server, sqlite_backend.store, clock, min_backoff=1.0, max_backoff=6.0)
    delays = []
    for _ in range(4):
        delays.append(relay.run_once())
        assert relay.state is RelayState.UNAVAILABLE
        assert relay.run_once() == pytest.approx(delays[-1])      # not before the delay
        clock.advance(delays[-1])
    for n, delay in enumerate(delays):
        ceiling = min(6.0, 2.0 ** n)
        assert ceiling / 2 <= delay <= ceiling
    assert relay.run_once() == 0
    assert relay.state is RelayState.OK
    assert len(server.sent("POST", CHANGES)) == 5


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
def test_retryable_statuses_are_retried(server, intake, sqlite_backend, clock, status):
    sqlite_backend.append(create("n-1"))
    server.queue("POST", CHANGES, Reply(status=status, raw=b"", content_type="text/plain"))
    relay = relay_for(server, sqlite_backend.store, clock)
    clock.advance(relay.run_once())
    assert relay.run_once() == 0
    assert intake.applied_through == 1


def test_retry_after_is_honoured(server, intake, sqlite_backend, clock):
    sqlite_backend.append(create("n-1"))
    server.queue("POST", CHANGES, problem("rate_limited", 429, Retry_After="40"))
    relay = relay_for(server, sqlite_backend.store, clock, min_backoff=1.0, max_backoff=5.0)
    assert relay.run_once() >= 40
    clock.advance(39)
    relay.wake()
    assert relay.run_once() == pytest.approx(1, abs=0.5)        # still waiting
    assert len(server.sent("POST", CHANGES)) == 1
    clock.advance(1)
    assert relay.run_once() == 0
    assert intake.applied_through == 1


def test_a_failed_state_report_is_retried_before_any_row(server, intake, sqlite_backend,
                                                         clock):
    sqlite_backend.append(create("n-1"))
    server.queue("PUT", STATE, Reply(status=503, raw=b"", content_type="text/plain"))
    relay = relay_for(server, sqlite_backend.store, clock)
    clock.advance(relay.run_once())
    assert server.sent("POST", CHANGES) == []
    assert relay.state is RelayState.UNAVAILABLE
    assert relay.run_once() == 0
    assert len(intake.states) == 1 and posts(server) == [[1]]


def test_a_refusal_of_the_whole_batch_backs_off_long_and_logs(server, intake, sqlite_backend,
                                                              clock, caplog):
    """A 4xx is not retryable as such (a wrong credential, the wrong
    service): the relay keeps the rows, waits the longest backoff, logs an
    error, and tries again, so fixing the configuration needs no restart."""
    caplog.set_level(logging.INFO, LOGGER)
    sqlite_backend.append(create("n-1"))
    server.queue("POST", CHANGES, problem("forbidden", 403, "only the service's own"))
    relay = relay_for(server, sqlite_backend.store, clock, max_backoff=120.0)
    assert relay.run_once() == pytest.approx(120.0)
    assert relay.state is RelayState.UNAVAILABLE
    (record,) = events(caplog, "outbox_send_failed")
    assert record.levelno == logging.ERROR and record.status == 403
    clock.advance(120)
    assert relay.run_once() == 0 and relay.state is RelayState.OK


def test_a_malformed_answer_is_retried(server, intake, sqlite_backend, clock):
    sqlite_backend.append(create("n-1"))
    server.queue("POST", CHANGES, Reply(body={"results": []}))
    relay = relay_for(server, sqlite_backend.store, clock)
    clock.advance(relay.run_once())
    assert relay.state is RelayState.UNAVAILABLE
    assert relay.run_once() == 0 and intake.applied_through == 1


def test_an_unreadable_store_is_unavailable_and_retried(server, intake, clock, caplog):
    caplog.set_level(logging.INFO, LOGGER)

    class Broken:
        service = "wolfnotes"

        def __getattr__(self, name):
            def fail(*a, **k):
                raise OSError("database is down")
            return fail

    relay = relay_for(server, Broken(), clock)
    assert relay.run_once() > 0
    assert relay.state is RelayState.UNAVAILABLE
    assert events(caplog, "outbox_store_failed")


# --- a refused row: dead-lettered at the head --------------------------------------------

def test_a_refused_row_stays_at_the_head_until_retry_refused(server, intake, backend, clock,
                                                             caplog):
    caplog.set_level(logging.INFO, LOGGER)
    intake.refuse[2] = "wolfnotes/thing is not a registered type of wolfnotes"
    backend.append(create("n-1"), create("n-2"), create("n-3"))
    relay = relay_for(server, backend.store, clock, refused_interval=60.0)
    assert relay.run_once() == pytest.approx(60.0)
    assert relay.state is RelayState.REFUSED
    progress = backend.store.progress()
    assert progress.applied_through == 1
    assert (progress.dead_letter.sequence, progress.dead_letter.reason) == (
        2, "wolfnotes/thing is not a registered type of wolfnotes")
    (alert,) = events(caplog, "outbox_refused")
    assert alert.levelno == logging.ERROR and alert.sequence == 2

    backend.append(create("n-4"))                     # later rows wait behind it
    clock.advance(1)
    relay.wake()
    relay.run_once()
    clock.advance(600)
    relay.run_once()
    assert posts(server) == [[1, 2, 3]]               # never re-sent on its own
    assert len(events(caplog, "outbox_refused")) == 1  # alerted once
    assert relay.state is RelayState.REFUSED

    del intake.refuse[2]                              # the cause is fixed
    relay.retry_refused()
    assert relay.run_once() == 0
    assert posts(server)[-1] == [2, 3, 4]
    assert relay.state is RelayState.OK
    assert backend.store.progress().applied_through == 4


def test_retry_refused_that_is_refused_again_stays_refused(server, intake, sqlite_backend,
                                                           clock, caplog):
    caplog.set_level(logging.INFO, LOGGER)
    intake.refuse[1] = "still wrong"
    sqlite_backend.append(create("n-1"))
    relay = relay_for(server, sqlite_backend.store, clock)
    relay.run_once()
    relay.retry_refused()
    relay.run_once()
    assert posts(server) == [[1], [1]]
    assert relay.state is RelayState.REFUSED
    assert len(events(caplog, "outbox_refused")) == 2  # each refusal of a delivery alerts
    clock.advance(10_000)
    relay.run_once()
    assert len(posts(server)) == 2                    # one retry per request


def test_retry_refused_without_a_refused_row_does_nothing(server, intake, sqlite_backend,
                                                          clock):
    sqlite_backend.append(create("n-1"))
    relay = relay_for(server, sqlite_backend.store, clock)
    relay.retry_refused()
    relay.run_once()
    assert posts(server) == [[1]] and relay.state is RelayState.OK


def test_a_dead_letter_resolved_by_reconcile_is_learned_from_the_feed(server, intake,
                                                                      sqlite_backend, clock):
    """CUT-D1 (1): the library learns later results from `GET …/changes`."""
    intake.refuse[1] = "refused"
    sqlite_backend.append(create("n-1"), create("n-2"))
    relay = relay_for(server, sqlite_backend.store, clock, refused_interval=30.0)
    relay.run_once()
    assert relay.state is RelayState.REFUSED
    server.queue("GET", CHANGES, Reply(body={"results": [
        {"sequence": 1, "status": "resolved"}, {"sequence": 2, "status": "applied"}],
        "applied_through": 2}))
    clock.advance(30)
    relay.run_once()
    assert server.sent("GET", CHANGES)[0].path == CHANGES + "?after=0"
    assert relay.state is RelayState.OK
    assert sqlite_backend.store.progress().applied_through == 2


def test_dead_letter_polls_are_spaced(server, intake, sqlite_backend, clock):
    intake.refuse[1] = "refused"
    sqlite_backend.append(create("n-1"))
    relay = relay_for(server, sqlite_backend.store, clock, refused_interval=30.0)
    relay.run_once()
    for _ in range(3):
        relay.run_once()
    assert server.sent("GET", CHANGES) == []
    clock.advance(30)
    relay.run_once()
    relay.run_once()
    assert len(server.sent("GET", CHANGES)) == 1


# --- held rows: sent again later -------------------------------------------------------------

def test_held_rows_are_sent_again_later(server, intake, sqlite_backend, clock):
    """A change for a seed resource sent before the seed import is applied
    after the import (criterion 181)."""
    intake.unknown.add("n-2")
    sqlite_backend.append(create("n-1"), Change.delete(ResourceRef("wolfnotes/note", "n-2")))
    relay = relay_for(server, sqlite_backend.store, clock, held_interval=30.0)
    assert relay.run_once() == pytest.approx(30.0)
    assert relay.state is RelayState.BEHIND
    (row,) = sqlite_backend.store.unapplied_rows(10)
    assert (row.sequence, row.status, row.reason) == (2, "held", SEED_WAIT)
    relay.wake()
    relay.run_once()
    assert posts(server) == [[1, 2]]                  # not before held_interval
    intake.unknown.clear()                            # the seed is imported
    clock.advance(30)
    assert relay.run_once() == 0
    assert posts(server) == [[1, 2], [2]]
    assert relay.state is RelayState.OK


# --- running it -------------------------------------------------------------------------------

def test_background_thread_delivers_on_wake_and_stops(server, intake, sqlite_backend):
    relay = OutboxRelay(WolfAccessClient(server.url, CRED, service="wolfnotes"),
                        sqlite_backend.store, mode="off", idle_interval=60.0)
    thread = relay.start()
    try:
        assert thread.daemon is True
        deadline = time.monotonic() + 5
        while not intake.states and time.monotonic() < deadline:
            time.sleep(0.01)
        sqlite_backend.append(create("n-1"))
        relay.wake()                                  # no 60 s wait
        while intake.applied_through < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert intake.applied_through == 1
    finally:
        relay.stop(timeout=5)
    assert not thread.is_alive()


def test_start_twice_is_refused(server, intake, sqlite_backend):
    relay = OutboxRelay(WolfAccessClient(server.url, CRED, service="wolfnotes"),
                        sqlite_backend.store, mode="off")
    relay.start()
    try:
        with pytest.raises(RuntimeError):
            relay.start()
    finally:
        relay.stop(timeout=5)


def test_run_forever_on_the_caller_s_thread_until_stop(server, intake, sqlite_backend):
    relay = OutboxRelay(WolfAccessClient(server.url, CRED, service="wolfnotes"),
                        sqlite_backend.store, mode="off", idle_interval=60.0)
    sqlite_backend.append(create("n-1"))
    runner = threading.Thread(target=relay.run_forever)
    runner.start()
    deadline = time.monotonic() + 5
    while intake.applied_through < 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    relay.stop()
    runner.join(5)
    assert not runner.is_alive() and intake.applied_through == 1
