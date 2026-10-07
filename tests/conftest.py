"""Shared fixtures: an outbox store on each reference backend.

`backend` runs a test once on SQLite (a file in `tmp_path`) and once on
Postgres. Postgres needs `TEST_DATABASE_URL` (an owner URL on a scratch
server, e.g. `postgresql://postgres@127.0.0.1:5432/postgres`) and the
`psycopg2` driver; each test gets its own database, dropped after. Locally
an unset variable skips the Postgres runs. CI sets `WAC_REQUIRE_POSTGRES=1`,
which turns that skip into a failure, so CI can never go green without them.
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from dataclasses import dataclass
from typing import Any, Callable

import pytest

from wolf_access_client import PostgresOutboxStore, SQLiteOutboxStore

REQUIRE_POSTGRES = os.environ.get("WAC_REQUIRE_POSTGRES") == "1"
SERVICE = "wolfnotes"


@dataclass
class Backend:
    kind: str
    connect: Callable[[], Any]
    store: Any

    def make(self, service: str = SERVICE) -> Any:
        cls = SQLiteOutboxStore if self.kind == "sqlite" else PostgresOutboxStore
        return cls(self.connect, service)

    def append(self, *changes: Any, store: Any = None, commit: bool = True) -> list:
        """Append `changes` in one transaction of the consumer's own."""
        store = store or self.store
        conn = self.connect()
        try:
            rows = [store.append(conn, change) for change in changes]
            if commit:
                conn.commit()
            else:
                conn.rollback()
            return rows
        finally:
            conn.close()


def _skip_or_fail(reason: str) -> None:
    if REQUIRE_POSTGRES:
        pytest.fail(f"{reason} (WAC_REQUIRE_POSTGRES=1)")
    pytest.skip(reason)


@pytest.fixture
def pg_connect():
    url = (os.environ.get("TEST_DATABASE_URL") or "").strip()
    if not url:
        _skip_or_fail("TEST_DATABASE_URL is not set")
    try:
        import psycopg2
        from psycopg2.extensions import make_dsn
    except ImportError:
        _skip_or_fail("psycopg2 is not installed")
    name = "wac_" + uuid.uuid4().hex[:16]
    admin = psycopg2.connect(url)
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(f'CREATE DATABASE "{name}"')
    dsn = make_dsn(url, dbname=name)
    try:
        yield lambda: psycopg2.connect(dsn)
    finally:
        with admin.cursor() as cur:
            cur.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        admin.close()


@pytest.fixture
def sqlite_connect(tmp_path):
    path = tmp_path / "outbox.db"
    return lambda: sqlite3.connect(path, timeout=10)


@pytest.fixture(params=["sqlite", "postgres"])
def backend(request) -> Backend:
    connect = request.getfixturevalue(f"{request.param}_connect" if request.param == "sqlite"
                                      else "pg_connect")
    cls = SQLiteOutboxStore if request.param == "sqlite" else PostgresOutboxStore
    store = cls(connect, SERVICE)
    store.create_schema()
    return Backend(request.param, connect, store)


@pytest.fixture
def sqlite_backend(sqlite_connect) -> Backend:
    store = SQLiteOutboxStore(sqlite_connect, SERVICE)
    store.create_schema()
    return Backend("sqlite", sqlite_connect, store)
