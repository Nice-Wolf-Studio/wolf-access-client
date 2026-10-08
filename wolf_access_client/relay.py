"""`OutboxRelay`: delivers a service's lifecycle outbox to wolf-access
(CUT-D1 (1), API-D10), in every mode, `off` included.

Each step (`run_once`):

1. At start-up, the state report (`report_state`: the mode and the store's
   registration start), until it succeeds.
2. The unapplied rows from the head of the sequence, at most `batch_size`
   (500), sent in one `POST …/changes`; every row's result is recorded in
   the store. A fully applied batch is followed at once by the next.
3. Held rows (waiting for the seed import, or in sequence) are sent again
   after `held_interval`.
4. A refused row at the head is dead-lettered: it is alerted (an ERROR log,
   `event=outbox_refused`, and `state` `refused`) and never sent again on
   its own, so every later row waits behind it. `retry_refused()` sends it
   again once its cause is fixed. Meanwhile the relay polls
   `GET …/changes` every `refused_interval` to learn whether reconcile
   resolved it.
5. On 408, 429, 5xx, a network error or a malformed answer the relay backs
   off exponentially (with jitter, `min_backoff` to `max_backoff`), and
   never retries before a `Retry-After` (capped at one hour,
   `MAX_RETRY_AFTER`). Any other refusal (a wrong
   credential or service name) waits `max_backoff` and is logged as an
   error; the rows are kept, so fixing the configuration needs no restart.
   Rows live in the service's own database, so nothing is lost across
   restarts: a new relay starts from the head.

`state` is `ok` (everything delivered), `behind` (rows or the state report
still to deliver), `refused` (a dead-lettered row) or `unavailable`
(wolf-access or the store cannot be reached): what the service puts on its
`/health`, whose HTTP status stays 200.

Run it with `start()` (a daemon thread) and `stop()`, or call
`run_forever()` on a thread of your own (`asyncio.to_thread(relay.run_forever)`
in an asyncio service). Call `wake()` after committing a change so it goes
out at once instead of at the next `idle_interval`.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from enum import Enum
from typing import Any, Callable

from .client import MAX_CHANGE_ROWS, WolfAccessClient
from .errors import WolfAccessError, WolfAccessHTTPError, WolfAccessResponseError
from .mode import AccessMode, safe
from .models import ChangesAnswer, OutboxRow

log = logging.getLogger("wolf_access_client")

#: The longest a `Retry-After` is waited (one hour, #33): a longer one is
#: capped, so a broken or hostile header cannot stall the relay or overflow
#: the thread's wait.
MAX_RETRY_AFTER = 3600.0


class RelayState(str, Enum):
    OK = "ok"
    BEHIND = "behind"
    REFUSED = "refused"
    UNAVAILABLE = "unavailable"


def _seconds(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value < 1e6:
        raise ValueError(f"{name} must be a positive number of seconds")
    return float(value)


class OutboxRelay:
    def __init__(self, client: WolfAccessClient, store: Any, *, mode: AccessMode | str,
                 batch_size: int = MAX_CHANGE_ROWS, idle_interval: float = 2.0,
                 held_interval: float = 30.0, refused_interval: float = 60.0,
                 min_backoff: float = 1.0, max_backoff: float = 300.0,
                 logger: logging.Logger | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        """`client` must be made with `service=` equal to `store.service`.
        `mode` is the service's enforcement mode, reported at start-up.
        `clock` is for tests."""
        if not isinstance(client, WolfAccessClient):
            raise ValueError("client must be a WolfAccessClient")
        if client.service is None or client.service != getattr(store, "service", None):
            raise ValueError("the client's service= must be the store's service")
        self._mode = AccessMode.parse(mode)
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) \
                or not 1 <= batch_size <= MAX_CHANGE_ROWS:
            raise ValueError(f"batch_size must be an integer from 1 to {MAX_CHANGE_ROWS}")
        self._client, self._store, self._batch = client, store, batch_size
        self.idle_interval = _seconds(idle_interval, "idle_interval")
        self.held_interval = _seconds(held_interval, "held_interval")
        self.refused_interval = _seconds(refused_interval, "refused_interval")
        self.min_backoff = _seconds(min_backoff, "min_backoff")
        self.max_backoff = max(_seconds(max_backoff, "max_backoff"), self.min_backoff)
        self._log = logger or log
        self._clock = clock
        self._reported = False
        self._failures = 0
        self._failing = False
        self._not_before = 0.0          # backoff: nothing is sent before this
        self._held_until = 0.0          # a held head is not re-sent before this
        self._next_poll = 0.0           # a dead letter's result is not polled before this
        self._retry = False             # retry_refused() was asked for
        self._alerted: int | None = None
        self._step = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __repr__(self) -> str:
        return f"OutboxRelay(service={self._client.service!r})"

    # --- for /health -----------------------------------------------------------------------

    @property
    def state(self) -> RelayState:
        """ok, behind, refused or unavailable. Never raises."""
        try:
            progress = self._store.progress()
        except Exception:  # noqa: BLE001  (an unreadable store is reported, not raised)
            return RelayState.UNAVAILABLE
        if progress.dead_letter is not None:
            return RelayState.REFUSED
        if self._failing:
            return RelayState.UNAVAILABLE
        if not self._reported or progress.applied_through < progress.last_sequence:
            return RelayState.BEHIND
        return RelayState.OK

    # --- control ---------------------------------------------------------------------------

    def wake(self) -> None:
        """Run the next step now (a backoff or `Retry-After` still holds)."""
        self._wake.set()

    def retry_refused(self) -> None:
        """Send the dead-lettered head row again (its cause fixed): once."""
        self._retry = True
        self._wake.set()

    def start(self) -> threading.Thread:
        """Run `run_forever` on a daemon thread."""
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("the relay is already running")
        self._stop.clear()
        self._thread = threading.Thread(target=self.run_forever, daemon=True,
                                        name=f"wolf-access-outbox-{self._client.service}")
        self._thread.start()
        return self._thread

    def stop(self, timeout: float | None = None) -> None:
        """Stop `run_forever` after its current step; join the thread `start`
        made, waiting at most `timeout` seconds."""
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def run_forever(self) -> None:
        """Run steps until `stop()`, waiting between them as each one says."""
        while not self._stop.is_set():
            try:
                delay = self.run_once()
            except Exception:  # noqa: BLE001  (the loop must outlive any one step)
                self._log.exception("outbox relay step failed", extra={"event": "outbox_error"})
                delay = self.max_backoff
            self._wake.wait(delay)
            self._wake.clear()

    # --- one step --------------------------------------------------------------------------

    def run_once(self) -> float:
        """Do what is due now; return the seconds until the next step is due."""
        with self._step:
            now = self._clock()
            if now < self._not_before:
                return self._not_before - now
            retrying = self._retry
            try:
                return self._step_once(now)
            except WolfAccessError as exc:
                self._retry = retrying
                return self._failed(now, exc)
            except Exception as exc:  # noqa: BLE001  (the service's own database)
                self._retry = retrying
                return self._store_failed(now, exc)

    def _step_once(self, now: float) -> float:
        if not self._reported:
            self._client.report_state(self._mode, self._store.registration_start())
            self._reported = True
        rows = self._store.unapplied_rows(self._batch)
        if not rows:
            self._succeeded()
            return self.idle_interval
        head = rows[0]
        if head.status == "refused" and not self._retry:
            self._alert(head.sequence, head.reason, again=False)
            if now < self._next_poll:
                return self._next_poll - now
            self._next_poll = now + self.refused_interval
            self._store.record(self._client.changes_page(head.sequence - 1))
            self._succeeded()
            return 0.0 if self._store.progress().dead_letter is None else self.refused_interval
        if head.status == "held" and now < self._held_until and not self._retry:
            return self._held_until - now
        self._retry = False
        answer = self._client.send_changes([row.wire() for row in rows])
        self._store.record(answer)
        self._succeeded()
        return self._after(now, rows, answer)

    def _after(self, now: float, rows: list[OutboxRow], answer: ChangesAnswer) -> float:
        through = answer.applied_through
        head = next((r for r in answer.results if r.sequence > through), None)
        if head is None:
            return 0.0                          # the whole batch is applied: the next one
        if head.status == "refused":
            self._alert(head.sequence, head.reason, again=True)
            self._next_poll = now + self.refused_interval
            return self.refused_interval
        self._held_until = now + self.held_interval
        return self.held_interval

    # --- outcomes --------------------------------------------------------------------------

    def _succeeded(self) -> None:
        self._failures = 0
        self._failing = False

    def _alert(self, sequence: int, reason: str | None, *, again: bool) -> None:
        if not again and self._alerted == sequence:
            return
        self._alerted = sequence
        self._log.error(
            "outbox_refused service=%s sequence=%d reason=%s: every later row waits until it "
            "is delivered again (retry_refused) or reconcile resolves it",
            self._client.service, sequence, safe(reason),
            extra={"event": "outbox_refused", "service": self._client.service,
                   "sequence": sequence, "reason": reason})

    def _backoff(self) -> float:
        base = min(self.max_backoff, self.min_backoff * 2 ** (self._failures - 1))
        return base * (0.5 + random.random() / 2)

    def _failed(self, now: float, exc: WolfAccessError) -> float:
        self._failures += 1
        self._failing = True
        status = exc.status if isinstance(exc, WolfAccessHTTPError) else None
        if exc.retryable or isinstance(exc, WolfAccessResponseError):
            delay = self._backoff()
            retry_after = getattr(exc, "retry_after", None)
            if retry_after is not None:
                delay = max(delay, min(float(retry_after), MAX_RETRY_AFTER))
            level = logging.WARNING
        else:
            delay, level = self.max_backoff, logging.ERROR
        self._not_before = now + delay
        name = getattr(exc, "name", None)
        self._log.log(level, "outbox_send_failed service=%s error=%s status=%s problem=%s "
                      "retry_in=%.1fs", self._client.service, type(exc).__name__, status,
                      safe(name), delay,
                      extra={"event": "outbox_send_failed", "service": self._client.service,
                             "error": type(exc).__name__, "status": status, "problem": name,
                             "retry_in": delay})
        return delay

    def _store_failed(self, now: float, exc: Exception) -> float:
        self._failures += 1
        self._failing = True
        delay = self._backoff()
        self._not_before = now + delay
        self._log.warning("outbox_store_failed service=%s error=%s retry_in=%.1fs",
                          self._client.service, type(exc).__name__, delay,
                          extra={"event": "outbox_store_failed", "service": self._client.service,
                                 "error": type(exc).__name__, "retry_in": delay})
        return delay

