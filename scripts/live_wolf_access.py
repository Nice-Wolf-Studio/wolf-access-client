"""Run a real wolf-access server, seeded, for `tests/test_live.py`.

Not part of the library and not run by CI (wolf-access is a private repo and
CI installs nothing with credentials). It needs a wolf-access checkout
(`development`) on `PYTHONPATH` with its requirements installed, a scratch
Postgres owner URL and a SpiceDB endpoint (`spicedb serve-testing`):

    PYTHONPATH=/path/to/wolf-access \\
    /path/to/wolf-access-venv/bin/python scripts/live_wolf_access.py \\
        --database-url postgresql://postgres@127.0.0.1:5432/postgres \\
        --spicedb 127.0.0.1:50051 --port 8471 --out /tmp/live.json

then, with this package's own environment:

    WAC_LIVE=/tmp/live.json python -m pytest tests/test_live.py

It creates a new database (dropped on exit), migrates it, and seeds what
wolf-access has no HTTP call for (services and their credentials,
principals, the first grants), using wolf-access's own code: the services
`tasks` and `access`; the operator `op`; the org `o1`; `builder`, who may
create lists and tasks under it; `reader`, who may read them; `stranger`,
who holds nothing. `--out` receives the URL, the `tasks` credential and the
WRNs as JSON. The process serves until it is interrupted.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import secrets
import signal
import uuid

import asyncpg
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from wolf_access import db, migrate, tokens
from wolf_access.api import build_routes
from wolf_access.app import build_app
from wolf_access.core import Core
from wolf_access.settings import async_url
from wolf_access.spicedb import SpiceDB

TASKS_SCHEMA = {
    "types": [
        {"type": "tasks.list", "registered": True, "allowed_parents": ["access.org", "tasks.list"]},
        {"type": "tasks.task", "registered": True, "allowed_parents": ["tasks.list"]},
    ],
    "permissions": [{"name": "tasks.list.create"}, {"name": "tasks.task.create"},
                    {"name": "tasks.list.read"}, {"name": "tasks.task.read"},
                    {"name": "tasks.task.secret", "requires_end_to_end": True}],
    "roles": [
        {"name": "maker", "rank": 1,
         "permissions": ["tasks.list.create", "tasks.task.create", "tasks.use"]},
        {"name": "reader", "rank": 10,
         "permissions": ["tasks.list.read", "tasks.task.read", "tasks.task.secret",
                         "tasks.use"]},
    ],
}
# A role that bundles `access.use`: a principal must hold it for a token
# with audience `access` (AC-21).
ACCESS_SCHEMA = {"roles": [{"name": "access_user", "rank": 1, "permissions": ["access.use"]}]}


def principal(name: str) -> str:
    return "wrn:access:user/" + name  # wrn-ok: wolf-access's own seeding text


async def owner_execute(url: str, sql: str, **params) -> None:
    engine = db.create_engine(url)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params)
    finally:
        await engine.dispose()


async def settled(core: Core) -> None:
    from wolf_access import relay
    for _ in range(200):
        core.relay.poke()
        async with core.engine.connect() as conn:
            if not await relay.pending(conn):
                return
        await asyncio.sleep(0.05)
    raise RuntimeError("the relay did not apply the pending rows")


async def main(args: argparse.Namespace) -> None:
    admin = async_url(args.database_url)
    name = "wac_live_" + uuid.uuid4().hex[:10]
    conn = await asyncpg.connect(args.database_url)
    await conn.execute(f'CREATE DATABASE "{name}"')
    await conn.close()
    owner = migrate.with_database(admin, name)
    password = secrets.token_hex(16)
    try:
        await asyncio.to_thread(migrate.upgrade, owner)
        await migrate.sync_service_role(owner, password)
        from sqlalchemy.engine import make_url
        service_url = make_url(owner).set(username="wolf_access_service", password=password
                                          ).render_as_string(hide_password=False)
        creds = {"tasks": secrets.token_urlsafe(24), "access": secrets.token_urlsafe(24)}
        for service, token in creds.items():
            await owner_execute(owner, "INSERT INTO services (name) VALUES (:s) "
                                       "ON CONFLICT DO NOTHING", s=service)
            await owner_execute(owner, "INSERT INTO service_credentials (hash, service) "
                                       "VALUES (:h, :s)",
                                h=hashlib.sha256(token.encode()).hexdigest(), s=service)
        engine = db.create_engine(service_url)
        spice = SpiceDB(args.spicedb, "live-" + secrets.token_hex(8), engine)
        key = Ed25519PrivateKey.generate()
        # wolf-access PR #339 (#333, #334) replaces the one key with a key set.
        signing = ({"token_keys": tokens.SigningKeys([key])}
                   if hasattr(tokens, "SigningKeys") else {"token_signing_key": key})
        core = Core(engine, spice, operator_user_ids={"op"}, **signing)
        await core.start()
        people = {n: principal(n) for n in ("op", "builder", "reader", "stranger")}
        for wrn in people.values():
            async with core.engine.begin() as c:
                await c.execute(text("INSERT INTO principals (wrn, kind, person_wrn) "
                                     "VALUES (:w, 'user', :p)"),
                                {"w": wrn, "p": "wrn:people:person/" + wrn.rsplit("/", 1)[1]})  # wrn-ok
            await settled(core)
        org = "wrn:access:org/o1"  # wrn-ok: wolf-access's own seeding text
        await core.register_schema("tasks", TASKS_SCHEMA)
        await core.register_schema("access", ACCESS_SCHEMA)
        await core.create_resource("access", org, None, "Home")
        for who, role in (("builder", "maker"), ("builder", "access_user"),
                          ("reader", "reader"), ("reader", "access_user"),
                          ("op", "access_user")):
            async with core.engine.begin() as c:
                change = await core._add_grant(c, people[who], role, org, None)
            await core.relay.wait(change, 10)
        app = build_app({}, routes=build_routes(core))
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=args.port,
                                               log_level="warning"))
        info = {"url": f"http://127.0.0.1:{args.port}", "tasks_credential": creds["tasks"],
                "org": org, **{n: w for n, w in people.items()}}
        with open(args.out, "w") as f:
            json.dump(info, f)
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: setattr(server, "should_exit", True))
        print(f"wolf-access serving on {info['url']}; config in {args.out}", flush=True)
        await server.serve()
        await core.stop()
        await spice.close()
        await engine.dispose()
    finally:
        conn = await asyncpg.connect(args.database_url)
        await conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--database-url", required=True, help="scratch Postgres owner URL")
    parser.add_argument("--spicedb", required=True, help="SpiceDB gRPC endpoint")
    parser.add_argument("--port", type=int, default=8471)
    parser.add_argument("--out", required=True, help="where to write the JSON config")
    asyncio.run(main(parser.parse_args()))
