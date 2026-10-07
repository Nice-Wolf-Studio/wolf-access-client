"""The lifecycle outbox (CUT-D1 (1)): the only way a service with an
enforcement mode tells wolf-access that a resource was created, moved, made
private or public, or deleted.

The service writes each change to its own database **in the same
transaction as the change itself**, with the next number of a gapless
per-service sequence (`OutboxStore.append(conn, change)`). `OutboxRelay`
(`relay.py`) sends the rows to wolf-access in sequence and records each
row's result here; `AccessGate` asks the store which resources still have a
row wolf-access has not applied (CUT-D1 (2)).

`OutboxStore` is the small protocol a store implements. Two reference
stores ship with the library, both over plain DB-API 2.0 connections (no
driver is a dependency of this package):

- `PostgresOutboxStore`, for finOps (psycopg2 or psycopg 3; `%s` parameters);
- `SQLiteOutboxStore`, for WolfNotes (the standard `sqlite3` module).

Each takes `connect`, a zero-argument callable returning a new connection,
which the store closes after each operation of its own (`append` uses the
caller's connection and never commits). The tables are in `DDL`;
`create_schema()` creates them if they are missing.

Gapless: `append` takes the next number by incrementing the service's row in
`wolf_access_outbox_state` inside the caller's transaction. That row stays
locked until the transaction ends, so concurrent appenders queue behind each
other, a rolled-back append gives its number back, and rows commit in
sequence order (a relay never sees row n + 1 before row n).
"""

from __future__ import annotations

import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Collection, Iterator, Protocol, runtime_checkable

from ._checks import nonblank, resource_type, service_name
from .models import Change, ChangesAnswer, OutboxProgress, OutboxRow, ResourceRef

__all__ = ["OutboxStore", "PostgresOutboxStore", "SQLiteOutboxStore"]


@runtime_checkable
class OutboxStore(Protocol):
    """Where a service keeps its lifecycle outbox. `service` is its service
    name (`wolfnotes`, `finops`); every row is one of its own resources."""

    service: str

    def append(self, conn: Any, change: Change, *,
               change_id: str | None = None) -> OutboxRow:
        """Write `change` as the next row of the sequence, through the
        caller's own connection (or cursor), inside the caller's open
        transaction; never commits. A rollback removes the row and gives its
        number back. `change_id` defaults to a new UUID."""
        ...

    def unapplied_rows(self, limit: int) -> list[OutboxRow]:
        """Up to `limit` rows wolf-access has not applied, oldest first,
        starting at the head of the sequence."""
        ...

    def record(self, answer: ChangesAnswer) -> None:
        """Keep wolf-access's results: each row's status and reason, and
        `applied_through` (every row up to it is applied). Never moves
        `applied_through` back, nor past the newest row written."""
        ...

    def unapplied(self, resources: Collection[ResourceRef]) -> set[ResourceRef]:
        """Those of `resources` that have a row wolf-access has not applied
        (pending, held or dead-lettered)."""
        ...

    def progress(self) -> OutboxProgress:
        """The newest row written, `applied_through`, and the dead-lettered
        head row if there is one."""
        ...

    def registration_start(self) -> datetime:
        """The service's registration start (CUT-D1): when it first ran the
        library, recorded once and the same ever after (UTC)."""
        ...


class _SQLOutboxStore:
    """The shared SQL. Statements are written with `?` placeholders; a
    dialect sets its own placeholder and JSON column."""

    DDL = ""
    _PLACEHOLDER = "?"
    _BODY_PARAM = "?"
    _LOCK = ""

    def __init__(self, connect: Callable[[], Any], service: str) -> None:
        if not callable(connect):
            raise ValueError("connect must be a callable returning a new DB-API connection")
        self._connect = connect
        self.service = service_name(service)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(service={self.service!r})"

    # --- plumbing ----------------------------------------------------------------------

    def _sql(self, statement: str) -> str:
        return statement.replace("?", self._PLACEHOLDER)

    @contextmanager
    def _tx(self) -> Iterator[Any]:
        conn = self._connect()
        try:
            cur = conn.cursor()
            try:
                yield cur
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
            finally:
                cur.close()
        finally:
            conn.close()

    def _ensure_state(self, cur: Any) -> None:
        # A write first, so SQLite takes its write lock before any read.
        cur.execute(self._sql("INSERT INTO wolf_access_outbox_state (service) VALUES (?) "
                              "ON CONFLICT (service) DO NOTHING"), (self.service,))

    def create_schema(self) -> None:
        """Create the outbox tables if they are missing (`DDL`)."""
        with self._tx() as cur:
            for statement in self.DDL.split(";"):
                if statement.strip():
                    cur.execute(statement)

    # --- the protocol --------------------------------------------------------------------

    def append(self, conn: Any, change: Change, *,
               change_id: str | None = None) -> OutboxRow:
        if not isinstance(change, Change):
            raise ValueError("change must be a Change (Change.create, .move, .set_private, "
                             ".delete)")
        for ref in (change.resource, change.parent):
            if ref is not None and resource_type(ref.type)[0] != self.service:
                raise ValueError(f"{ref.type} is not a type of {self.service}: a service's "
                                 "outbox holds only its own resources")
        if change_id is None:
            change_id = str(uuid.uuid4())
        elif not nonblank(change_id):
            raise ValueError("change_id must be a non-empty string")
        own_cursor = callable(getattr(conn, "cursor", None))
        cur = conn.cursor() if own_cursor else conn
        try:
            self._ensure_state(cur)
            cur.execute(self._sql("UPDATE wolf_access_outbox_state SET last_sequence = "
                                  "last_sequence + 1 WHERE service = ?"), (self.service,))
            cur.execute(self._sql("SELECT last_sequence FROM wolf_access_outbox_state "
                                  "WHERE service = ?"), (self.service,))
            row = OutboxRow(int(cur.fetchone()[0]), change_id, change)
            cur.execute(self._sql(
                "INSERT INTO wolf_access_outbox (service, sequence, change_id, action, "
                "resource_type, resource_id, body) VALUES (?, ?, ?, ?, ?, ?, "
                + self._BODY_PARAM + ")"),
                (self.service, row.sequence, change_id, change.action, change.resource.type,
                 change.resource.id, json.dumps(row.wire())))
        finally:
            if own_cursor:
                cur.close()
        return row

    def unapplied_rows(self, limit: int) -> list[OutboxRow]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        with self._tx() as cur:
            cur.execute(self._sql(
                "SELECT o.sequence, o.change_id, o.body, o.status, o.reason "
                "FROM wolf_access_outbox o JOIN wolf_access_outbox_state s "
                "ON s.service = o.service WHERE o.service = ? AND o.sequence > s.applied_through "
                "ORDER BY o.sequence LIMIT ?"), (self.service, limit))
            return [_row(r) for r in cur.fetchall()]

    def record(self, answer: ChangesAnswer) -> None:
        if not isinstance(answer, ChangesAnswer):
            raise ValueError("answer must be a ChangesAnswer")
        with self._tx() as cur:
            self._ensure_state(cur)
            cur.execute(self._sql("SELECT last_sequence, applied_through FROM "
                                  "wolf_access_outbox_state WHERE service = ?" + self._LOCK),
                        (self.service,))
            last, stored = (int(v) for v in cur.fetchone())
            through = max(stored, min(answer.applied_through, last))
            for result in answer.results:
                if result.sequence > through:
                    status, reason = result.status, result.reason
                elif result.status == "resolved":
                    status, reason = "resolved", None
                else:
                    continue
                cur.execute(self._sql(
                    "UPDATE wolf_access_outbox SET status = ?, reason = ?, "
                    "answered_at = CURRENT_TIMESTAMP WHERE service = ? AND sequence = ?"),
                    (status, reason, self.service, result.sequence))
            cur.execute(self._sql(
                "UPDATE wolf_access_outbox SET status = 'applied', reason = NULL, "
                "answered_at = CURRENT_TIMESTAMP WHERE service = ? AND sequence > ? "
                "AND sequence <= ? AND status NOT IN ('applied', 'resolved')"),
                (self.service, stored, through))
            cur.execute(self._sql("UPDATE wolf_access_outbox_state SET applied_through = ? "
                                  "WHERE service = ?"), (through, self.service))

    def unapplied(self, resources: Collection[ResourceRef]) -> set[ResourceRef]:
        wanted = set(resources)
        if not wanted:
            return set()
        with self._tx() as cur:
            cur.execute(self._sql(
                "SELECT DISTINCT o.resource_type, o.resource_id FROM wolf_access_outbox o "
                "JOIN wolf_access_outbox_state s ON s.service = o.service "
                "WHERE o.service = ? AND o.sequence > s.applied_through"), (self.service,))
            return {ResourceRef(t, i) for t, i in cur.fetchall()} & wanted

    def progress(self) -> OutboxProgress:
        with self._tx() as cur:
            cur.execute(self._sql("SELECT last_sequence, applied_through FROM "
                                  "wolf_access_outbox_state WHERE service = ?"), (self.service,))
            found = cur.fetchone()
            if found is None:
                return OutboxProgress(0, 0, None)
            last, through = int(found[0]), int(found[1])
            cur.execute(self._sql(
                "SELECT sequence, change_id, body, status, reason FROM wolf_access_outbox "
                "WHERE service = ? AND sequence = ? AND status = 'refused'"),
                (self.service, through + 1))
            head = cur.fetchone()
            return OutboxProgress(last, through, None if head is None else _row(head))

    def registration_start(self) -> datetime:
        with self._tx() as cur:
            self._ensure_state(cur)
            cur.execute(self._sql("SELECT registration_start FROM wolf_access_outbox_state "
                                  "WHERE service = ?"), (self.service,))
            return _utc(cur.fetchone()[0])


def _row(found: Any) -> OutboxRow:
    sequence, change_id, body, status, reason = found
    data = json.loads(body) if isinstance(body, (str, bytes)) else body
    return OutboxRow(int(sequence), change_id, Change.from_wire(data), status, reason)


def _utc(value: Any) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if not isinstance(value, datetime):
        raise ValueError("registration_start is not a time")
    if value.tzinfo is None:            # SQLite's CURRENT_TIMESTAMP is UTC, without a zone
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class PostgresOutboxStore(_SQLOutboxStore):
    """The reference store on Postgres (finOps), over psycopg2 or psycopg 3:
    `PostgresOutboxStore(lambda: psycopg2.connect(dsn), "finops")`. The tables
    (`DDL`) can go in the service's own migrations instead of
    `create_schema()`."""

    _PLACEHOLDER = "%s"
    _BODY_PARAM = "CAST(? AS jsonb)"
    _LOCK = " FOR UPDATE"

    #: The outbox tables. One `wolf_access_outbox_state` row per service holds
    #: the sequence counter (locked by each append until its transaction
    #: ends), `applied_through` and the registration start.
    DDL = """
CREATE TABLE IF NOT EXISTS wolf_access_outbox_state (
    service            text        PRIMARY KEY,
    last_sequence      bigint      NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    applied_through    bigint      NOT NULL DEFAULT 0 CHECK (applied_through >= 0),
    registration_start timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS wolf_access_outbox (
    service       text        NOT NULL REFERENCES wolf_access_outbox_state (service),
    sequence      bigint      NOT NULL CHECK (sequence >= 1),
    change_id     text        NOT NULL,
    action        text        NOT NULL,
    resource_type text        NOT NULL,
    resource_id   text        NOT NULL,
    body          jsonb       NOT NULL,
    status        text        NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'held', 'refused', 'applied', 'resolved')),
    reason        text,
    created_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    answered_at   timestamptz,
    PRIMARY KEY (service, sequence),
    UNIQUE (service, change_id)
);
CREATE INDEX IF NOT EXISTS wolf_access_outbox_resource
    ON wolf_access_outbox (service, resource_type, resource_id)
"""


class SQLiteOutboxStore(_SQLOutboxStore):
    """The reference store on SQLite (WolfNotes), over the standard `sqlite3`
    module: `SQLiteOutboxStore(lambda: sqlite3.connect(path, timeout=30),
    "wolfnotes")`. Use a file database (each operation opens its own
    connection), and give `connect` a busy timeout."""

    #: The outbox tables (see `PostgresOutboxStore.DDL`).
    DDL = """
CREATE TABLE IF NOT EXISTS wolf_access_outbox_state (
    service            TEXT    PRIMARY KEY,
    last_sequence      INTEGER NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    applied_through    INTEGER NOT NULL DEFAULT 0 CHECK (applied_through >= 0),
    registration_start TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS wolf_access_outbox (
    service       TEXT    NOT NULL REFERENCES wolf_access_outbox_state (service),
    sequence      INTEGER NOT NULL CHECK (sequence >= 1),
    change_id     TEXT    NOT NULL,
    action        TEXT    NOT NULL,
    resource_type TEXT    NOT NULL,
    resource_id   TEXT    NOT NULL,
    body          TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'held', 'refused', 'applied', 'resolved')),
    reason        TEXT,
    created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    answered_at   TEXT,
    PRIMARY KEY (service, sequence),
    UNIQUE (service, change_id)
);
CREATE INDEX IF NOT EXISTS wolf_access_outbox_resource
    ON wolf_access_outbox (service, resource_type, resource_id)
"""
