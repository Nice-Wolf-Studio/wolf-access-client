"""A loopback HTTP server standing in for wolf-access in tests.

It records every request (method, path with query, lower-cased headers,
parsed JSON body) so tests can check request shapes, and answers each one
with the next `Reply` queued for that method and path, or else the default
`reply`."""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PROBLEM = "urn:wolfaccess:problem:"


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
                    outer.requests.append(Seen(self.command, self.path,
                                               {k.lower(): v for k, v in self.headers.items()},
                                               body))
                    queue = outer._queued.get((self.command, self.path.split("?")[0]))
                    reply = queue.pop(0) if queue else outer.reply
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
