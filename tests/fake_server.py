"""A loopback HTTP server standing in for wolf-access in tests.

It records every request (method, path with query, lower-cased headers,
parsed JSON body) so tests can check request shapes, and answers each one
with the next `Reply` queued for that method and path, else the route
handler installed for it (`route`), else the default `reply`.

`FakeIntake` is wolf-access's cut-over intake (API-D10, CUT-D1 (1)) as the
M1c-1 server applies it (wolf-access `development` @ bc17d17,
`wolf_access/cutover.py`): rows applied in sequence, a gap held, a replay
answered with its stored result, a refused row dead-lettered at the head
and retried only when delivered again, an unknown resource held for the
seed import."""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

PROBLEM = "urn:wolfaccess:problem:"
SEED_WAIT = "waits for the service's seed import (CUT-D1)"


@dataclass
class Reply:
    status: int = 200
    body: Any = field(default_factory=lambda: {"decision": True})
    headers: dict[str, str] = field(default_factory=dict)
    delay: float = 0.0
    raw: bytes | None = None
    content_type: str = "application/json"


def problem(name: str, status: int, detail: str = "refused", **headers: str) -> Reply:
    """An RFC 9457 answer the way wolf-access's `/v1` renders one."""
    return Reply(status=status, content_type="application/problem+json",
                 headers={k.replace("_", "-"): v for k, v in headers.items()},
                 body={"type": PROBLEM + name, "title": name.replace("_", " "),
                       "status": status, "detail": detail})


@dataclass
class Seen:
    method: str
    path: str
    headers: dict[str, str]
    body: Any


class _Server(ThreadingHTTPServer):
    request_queue_size = 256  # concurrency tests open many connections at once
    daemon_threads = True


class FakeWolfAccess:
    def __init__(self, tls: tuple[str, str] | None = None) -> None:
        self.reply = Reply()
        self.requests: list[Seen] = []
        self._queued: dict[tuple[str, str], list[Reply]] = {}
        self._routes: dict[tuple[str, str], Callable[[Seen], Reply]] = {}
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length)
                body: Any = None
                if raw:
                    try:
                        body = json.loads(raw)
                    except ValueError:
                        body = raw
                with outer._lock:
                    seen = Seen(self.command, self.path,
                                {k.lower(): v for k, v in self.headers.items()}, body)
                    outer.requests.append(seen)
                    key = (self.command, self.path.split("?")[0])
                    queue = outer._queued.get(key)
                    route = outer._routes.get(key)
                    reply = queue.pop(0) if queue else route(seen) if route else outer.reply
                if reply.delay:
                    time.sleep(reply.delay)
                data = reply.raw if reply.raw is not None else json.dumps(reply.body).encode()
                self.send_response(reply.status)
                self.send_header("Content-Type", reply.content_type)
                for k, v in reply.headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

        self._server = _Server(("127.0.0.1", 0), Handler)
        if tls is not None:
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls)
            self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        kwargs={"poll_interval": 0.02}, daemon=True)

    def queue(self, method: str, path: str, *replies: Reply) -> None:
        """Answer the next requests to `method path` with `replies`, in order."""
        with self._lock:
            self._queued.setdefault((method, path), []).extend(replies)

    def route(self, method: str, path: str, handler: Callable[[Seen], Reply]) -> None:
        """Answer `method path` with `handler(seen)` when nothing is queued."""
        with self._lock:
            self._routes[(method, path)] = handler

    def sent(self, method: str, path: str) -> list[Seen]:
        with self._lock:
            return [r for r in self.requests
                    if r.method == method and r.path.split("?")[0] == path]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self) -> "FakeWolfAccess":
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()


class RawServer:
    """A loopback TCP server that answers every connection with `chunks`
    (raw bytes, sent `gap` seconds apart), then closes: for broken HTTP."""

    def __init__(self, *chunks: bytes, gap: float = 0.0) -> None:
        import socket as _socket
        self._chunks = chunks
        self._gap = gap
        self._sock = _socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._sock.getsockname()[1]}"

    def _run(self) -> None:
        self._sock.settimeout(0.05)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(2)
                try:
                    conn.recv(65536)
                    for chunk in self._chunks:
                        if self._stop.is_set():
                            break
                        conn.sendall(chunk)
                        if self._gap:
                            time.sleep(self._gap)
                except OSError:
                    pass

    def __enter__(self) -> "RawServer":
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._stop.set()
        self._thread.join(5)
        self._sock.close()


MAX_ROWS, LIST_LIMIT = 500, 1000
ACTIONS = ("create", "move", "private", "delete", "ack_ownership")


class FakeIntake:
    """wolf-access's cut-over intake for one service (API-D10, CUT-D1 (1)),
    following `wolf_access/cutover.py` at bc17d17:

    - `POST …/changes` stores each new row `held`, re-stores a re-delivered
      one (a refused row so re-delivered may be retried), then applies rows
      from `applied_through + 1` while they apply; a row already applied is
      answered with its stored result and changes nothing.
    - A row in `refuse` (sequence -> reason) is refused while it is listed:
      it dead-letters the sequence until it is delivered again with its
      cause fixed (removed from `refuse`).
    - A row whose resource id is in `unknown` is held (`SEED_WAIT`).
    - `GET …/changes?after=n` lists the stored rows after n, at most 1000.
    - `PUT …/state` records `{mode, registration_start}` and answers `{}`.
    """

    def __init__(self, fake: FakeWolfAccess, service: str = "wolfnotes") -> None:
        self.service = service
        self.applied_through = 0
        self.rows: dict[int, dict[str, Any]] = {}
        self.applied: list[dict[str, Any]] = []
        self.refuse: dict[int, str] = {}
        self.unknown: set[str] = set()
        self.states: list[dict[str, Any]] = []
        self.changes_path = f"/v1/services/{service}/changes"
        self.state_path = f"/v1/services/{service}/state"
        fake.route("POST", self.changes_path, self._post)
        fake.route("GET", self.changes_path, self._get)
        fake.route("PUT", self.state_path, self._put_state)

    def _put_state(self, seen: Seen) -> Reply:
        body = seen.body
        if not isinstance(body, dict) or set(body) != {"mode", "registration_start"} \
                or body["mode"] not in ("off", "shadow", "on"):
            return problem("bad_request", 400, "a state is {mode, registration_start}")
        self.states.append(body)
        return Reply(body={})

    def _post(self, seen: Seen) -> Reply:
        body = seen.body
        rows = body.get("rows") if isinstance(body, dict) and set(body) == {"rows"} else None
        if not isinstance(rows, list) or not rows or len(rows) > MAX_ROWS:
            return problem("bad_request", 400, "the body is {rows: [...]}")
        for row in rows:
            if not isinstance(row, dict) or isinstance(row.get("sequence"), bool) \
                    or not isinstance(row.get("sequence"), int) or row["sequence"] < 1 \
                    or not isinstance(row.get("change_id"), str) or not row["change_id"] \
                    or not isinstance(row.get("action"), str):
                return problem("bad_request", 400, "each row has a sequence, a change_id "
                                                   "and an action")
        through = self.applied_through
        again: set[int] = set()
        for row in rows:
            seq = row["sequence"]
            if seq <= through:
                continue
            stored = self.rows.get(seq)
            if stored is None:
                self.rows[seq] = {"body": row, "status": "held", "reason": None}
            else:
                stored["body"] = row
                if stored["status"] == "refused":
                    again.add(seq)
        while True:
            seq = through + 1
            stored = self.rows.get(seq)
            if stored is None or (stored["status"] == "refused" and seq not in again):
                break
            stored["status"], stored["reason"] = self._apply(stored["body"])
            if stored["status"] != "applied":
                break
            self.applied.append(stored["body"])
            through = seq
        self.applied_through = through
        return Reply(body={"results": [self._result(r["sequence"]) for r in rows],
                           "applied_through": through})

    def _apply(self, body: dict[str, Any]) -> tuple[str, str | None]:
        if body["action"] not in ACTIONS:
            return "refused", "action is create, move, private, delete or ack_ownership"
        if body["sequence"] in self.refuse:
            return "refused", self.refuse[body["sequence"]]
        if body.get("resource", {}).get("id") in self.unknown:
            return "held", SEED_WAIT
        return "applied", None

    def _result(self, seq: int) -> dict[str, Any]:
        stored = self.rows.get(seq)
        if stored is None:
            return {"sequence": seq, "status": "applied"}
        out = {"sequence": seq, "status": stored["status"]}
        if stored["reason"]:
            out["reason"] = stored["reason"]
        return out

    def _get(self, seen: Seen) -> Reply:
        query = parse_qs(urlsplit(seen.path).query)
        try:
            after = int(query.get("after", ["0"])[0])
        except ValueError:
            return problem("bad_request", 400, "after is a sequence number")
        seqs = sorted(s for s in self.rows if s > after)[:LIST_LIMIT]
        return Reply(body={"results": [self._result(s) for s in seqs],
                           "applied_through": self.applied_through})
