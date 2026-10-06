"""A loopback HTTP server standing in for wolf-access in tests."""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


@dataclass
class Reply:
    status: int = 200
    body: Any = field(default_factory=lambda: {"decision": True})
    headers: dict[str, str] = field(default_factory=dict)
    delay: float = 0.0
    raw: bytes | None = None


@dataclass
class Seen:
    method: str
    path: str
    headers: dict[str, str]
    body: Any


class FakeWolfAccess:
    def __init__(self) -> None:
        self.reply = Reply()
        self.requests: list[Seen] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length)
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = raw
                outer.requests.append(Seen("POST", self.path,
                                           {k.lower(): v for k, v in self.headers.items()},
                                           body))
                reply = outer.reply
                if reply.delay:
                    time.sleep(reply.delay)
                data = reply.raw if reply.raw is not None else json.dumps(reply.body).encode()
                self.send_response(reply.status)
                self.send_header("Content-Type", "application/json")
                for k, v in reply.headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        kwargs={"poll_interval": 0.02}, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self) -> "FakeWolfAccess":
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()
