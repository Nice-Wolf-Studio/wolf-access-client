"""Shared fixtures: a throwaway Postgres database.

`pg_connect` needs `TEST_DATABASE_URL` (an owner URL on a scratch server,
e.g. `postgresql://postgres@127.0.0.1:5432/postgres`) and the `psycopg2`
driver; each test gets its own database, dropped after. It runs the SQL
`canonical_wrn` function over the WRN conformance table. Locally an unset
variable skips those tests. CI sets `WAC_REQUIRE_POSTGRES=1`, which turns
that skip into a failure, so CI can never go green without them.
"""
from __future__ import annotations

import os
import uuid

import pytest

REQUIRE_POSTGRES = os.environ.get("WAC_REQUIRE_POSTGRES") == "1"


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
        # UTF8 whatever the server's default: the WRN cases hold non-ASCII text.
        cur.execute(f'CREATE DATABASE "{name}" ENCODING \'UTF8\' TEMPLATE template0')
    dsn = make_dsn(url, dbname=name)
    try:
        yield lambda: psycopg2.connect(dsn)
    finally:
        with admin.cursor() as cur:
            cur.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        admin.close()
