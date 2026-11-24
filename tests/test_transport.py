"""Whole-call deadline timeouts (#2) and HTTP/1.1 keep-alive connection reuse (#11)."""
from __future__ import annotations

import concurrent.futures
import gc
import json
import socket
import struct
import subprocess
import threading
import time

import pytest

from tests.fake_server import FakeWolfAccess, RawServer, Reply
from tests.helpers import APP, CRED, LIST, ORG, TASK, USER, make
from wolf_access_client import EvaluationItem, SchemaType, WolfAccessUnavailable


def evaluate(client, **overrides):
    return client.evaluation(**dict(
        subject=USER, action="tasks.task.read", resource=TASK, client_wrn=APP, **overrides))


def _timed_out_fast(url: str, timeout: float = 0.5) -> float:
    start = time.monotonic()
    with pytest.raises(WolfAccessUnavailable):
        evaluate(make(url, CRED, timeout=timeout))
    return time.monotonic() - start


# --- #2: whole-call deadline timeout --------------------------------------------------

def test_slow_headers_and_100_continue_cannot_outlast_timeout():
    with RawServer(b"HTTP/1.1 200 OK\r\n", *[b"X-Pad: x\r\n"] * 30, gap=0.1) as srv:
        assert _timed_out_fast(srv.url) < 0.75
    with RawServer(*[b"HTTP/1.1 100 Continue\r\n\r\n"] * 15, gap=0.2) as srv:
        assert _timed_out_fast(srv.url) < 0.75


def test_slow_chunked_framing_cannot_outlast_timeout():
    chunks = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
              b"11\r\n", b'{"decision":true}\r\n', b"0\r\n", b"X-Trailer: a\r\n", b"\r\n")
    with RawServer(*chunks, gap=0.2) as srv:
        assert _timed_out_fast(srv.url) < 0.75


def test_stalled_tls_handshake_cannot_outlast_timeout():
    sock, stop, conns = socket.socket(), threading.Event(), []
    sock.bind(("127.0.0.1", 0))
    sock.listen()

    def drip_tls() -> None:
        sock.settimeout(0.05)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except OSError:
                continue
            conns.append(conn)
            try:
                conn.recv(4096)
                for chunk in (b"\x16\x03\x03\x00\x30", b"\x02", b"\x00", b"\x00", b"\x2c"):
                    if stop.is_set():
                        break
                    conn.sendall(chunk)
                    time.sleep(0.15)
            except OSError:
                pass

    t = threading.Thread(target=drip_tls, daemon=True)
    t.start()
    try:
        assert _timed_out_fast(f"https://127.0.0.1:{sock.getsockname()[1]}") < 0.75
    finally:
        stop.set()
        t.join(2)
        for c in conns:
            c.close()
        sock.close()


def test_evaluation_starts_no_threads():
    with FakeWolfAccess(keep_alive=True) as srv, make(srv.url, CRED) as client:
        assert evaluate(client).allowed
        before = threading.active_count()
        for _ in range(50):
            assert evaluate(client).allowed
        assert threading.active_count() == before


# --- #11: keep-alive connection reuse and idempotent retry ----------------------------

def test_consecutive_calls_reuse_one_connection(tmp_path, monkeypatch):
    with FakeWolfAccess(keep_alive=True) as srv:
        with make(srv.url, CRED) as client:
            assert evaluate(client).allowed and evaluate(client).allowed
            assert srv.accepts == 1 and len(srv.requests) == 2
        assert evaluate(make(srv.url, CRED)).allowed
        gc.collect()  # idle pooled socket closes on GC with zero ResourceWarning

    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                   check=True, capture_output=True)
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    with FakeWolfAccess(tls=(str(cert), str(key)), keep_alive=True) as srv:
        with make(srv.url.replace("http://127.0.0.1", "https://localhost"), CRED) as client:
            assert evaluate(client).allowed and evaluate(client).allowed
            assert srv.accepts == 1


def test_concurrent_threads_do_not_share_in_flight_connections():
    with FakeWolfAccess(keep_alive=True) as srv:
        srv.reply = Reply(delay=0.1)
        with make(srv.url, CRED, timeout=2) as client:
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                results = list(pool.map(lambda _: evaluate(client), range(24)))
        assert all(r.allowed for r in results) and len(srv.requests) == 24


class _DropSecondReuseServer:
    def __init__(self, first: dict, second: dict, *, drop_second: bool = False, rst: bool = False):
        self.first, self.second, self.drop_second, self.rst = first, second, drop_second, rst
        self.accepts, self.seen_requests = 0, []
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self.url = f"http://127.0.0.1:{self._sock.getsockname()[1]}"

    def _read_one(self, conn: socket.socket) -> bytes | None:
        buf = bytearray()
        while b"\r\n\r\n" not in buf and (p := conn.recv(65536)):
            buf.extend(p)
        if b"\r\n\r\n" not in buf:
            return None
        end = buf.index(b"\r\n\r\n") + 4
        length = next((int(v) for ln in bytes(buf[:end]).split(b"\r\n")[1:] if b":" in ln
                       for k, v in [ln.split(b":", 1)] if k.strip().lower() == b"content-length"), 0)
        while len(buf) - end < length and (p := conn.recv(65536)):
            buf.extend(p)
        return bytes(buf) if len(buf) - end >= length else None

    def _run(self) -> None:
        self._sock.settimeout(0.05)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                continue
            self.accepts += 1
            num = self.accepts
            with conn:
                conn.settimeout(2)
                try:
                    if (req := self._read_one(conn)) is None:
                        continue
                    self.seen_requests.append(req)
                    if num == 1:
                        raw = json.dumps(self.first).encode()
                        conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(raw)}\r\n\r\n".encode() + raw)
                        if (req2 := self._read_one(conn)) is not None:
                            self.seen_requests.append(req2)
                            if self.rst:
                                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    elif not self.drop_second:
                        raw = json.dumps(self.second).encode()
                        conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(raw)}\r\n\r\n".encode() + raw)
                except OSError:
                    pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(5)
        self._sock.close()


@pytest.mark.parametrize("rst", [False, True])
@pytest.mark.parametrize("call_name, second_body", [
    ("evaluation", {"decision": True}),
    ("evaluations", {"evaluations": [{"decision": True}]}),
    ("search_resources", {"results": [], "page": {"next_token": "", "count": 0}}),
    ("get_resource", {"parent_wrn": str(LIST)}),
    ("exchange_token", {"access_token": "tok.a.b", "token_type": "Bearer",
                        "issued_token_type": "urn:ietf:params:oauth:token-type:jwt", "expires_in": 60}),
    ("register_schema", {"zedtoken": "zt-1"}),
])
def test_idempotent_calls_retry_once_when_pooled_conn_drops(rst, call_name, second_body):
    with _DropSecondReuseServer({"decision": True}, second_body, rst=rst) as srv, \
            make(srv.url, CRED, timeout=2) as client:
        assert evaluate(client).allowed
        calls = {
            "evaluation": lambda: evaluate(client).allowed,
            "evaluations": lambda: client.evaluations(
                subject=USER, client_wrn=APP, items=[EvaluationItem("tasks.task.read", TASK)])[0].allowed,
            "search_resources": lambda: list(client.search_resources(
                subject=USER, action="tasks.task.read", resource_type="tasks.task", client_wrn=APP)) == [],
            "get_resource": lambda: client.get_resource(TASK).parent_wrn == LIST,
            "exchange_token": lambda: client.exchange_token(USER, "access").access_token == "tok.a.b",
            "register_schema": lambda: client.register_schema(types=[SchemaType("tasks.task")]).zedtoken == "zt-1",
        }
        assert calls[call_name]() and srv.accepts == 2


def test_idempotent_retry_fails_closed_if_fresh_connection_also_drops():
    with _DropSecondReuseServer({"decision": True}, {"decision": True}, drop_second=True) as srv, \
            make(srv.url, CRED, timeout=2) as client:
        assert evaluate(client).allowed
        with pytest.raises(WolfAccessUnavailable):
            evaluate(client)
        assert srv.accepts == 2


@pytest.mark.parametrize("write_fn", [
    lambda c: c.create_resource(ORG, name="Home"),
    lambda c: c.move_resource(TASK, LIST, version=1),
    lambda c: c.delete_resource(TASK, version=1),
    lambda c: c.reconcile([(TASK, LIST)]),
])
def test_non_idempotent_writes_never_retry_when_pooled_conn_drops(write_fn):
    with _DropSecondReuseServer({"decision": True},
                                {"added": [], "changes": [], "zedtoken": "zt", "version": 1}) as srv, \
            make(srv.url, CRED, timeout=2) as client:
        assert evaluate(client).allowed
        with pytest.raises(WolfAccessUnavailable):
            write_fn(client)
        assert srv.accepts == 1 and len(srv.seen_requests) == 2
