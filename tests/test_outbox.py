"""The lifecycle outbox (CUT-D1 (1)): a `Change` is checked when it is built;
a store appends it inside the consumer's own transaction with the next
number of a gapless per-service sequence, keeps each row's result, and
answers which resources still have a row wolf-access has not applied.

Every store test runs on the SQLite and the Postgres reference store."""
from __future__ import annotations

import datetime as dt
import threading

import pytest

from tests.conftest import SERVICE
from wolf_access_client import (
    Change,
    ChangeResult,
    ChangesAnswer,
    OutboxProgress,
    OutboxRow,
    OutboxStore,
    PostgresOutboxStore,
    PrincipalRef,
    ResourceRef,
    SQLiteOutboxStore,
)

NOTE = "wolfnotes/note"
FOLDER = "wolfnotes/folder"
OWNER = PrincipalRef.user("u-1")


def note(i="n-1"):
    return ResourceRef(NOTE, i)


def folder(i="f-1"):
    return ResourceRef(FOLDER, i)


def create(i="n-1", **kw):
    kw.setdefault("owner", OWNER)
    kw.setdefault("author", "u-1")
    return Change.create(note(i), **kw)


def answer(*results, through):
    return ChangesAnswer(results=tuple(ChangeResult(*r) for r in results),
                         applied_through=through)


# --- Change: built and checked once ---------------------------------------------------

def test_create_wire_shape():
    change = Change.create(note(), owner=OWNER, author="u-1", parent=folder(), private=False)
    assert change.wire() == {"action": "create", "resource": {"type": NOTE, "id": "n-1"},
                             "owner": {"type": "user", "id": "u-1"}, "author": "u-1",
                             "parent": {"type": FOLDER, "id": "f-1"}, "private": False}


def test_create_sends_parent_and_private_only_when_given():
    assert Change.create(note(), owner=PrincipalRef("org", "o-1"), author="u-1").wire() == {
        "action": "create", "resource": {"type": NOTE, "id": "n-1"},
        "owner": {"type": "org", "id": "o-1"}, "author": "u-1"}


def test_move_wire_shape_and_null_parent_is_the_root():
    assert Change.move(note(), parent=folder("f-2")).wire() == {
        "action": "move", "resource": {"type": NOTE, "id": "n-1"},
        "parent": {"type": FOLDER, "id": "f-2"}}
    assert Change.move(note(), parent=None).wire() == {
        "action": "move", "resource": {"type": NOTE, "id": "n-1"}, "parent": None}


def test_private_and_delete_wire_shapes():
    assert Change.set_private(note(), True).wire() == {
        "action": "private", "resource": {"type": NOTE, "id": "n-1"}, "private": True}
    assert Change.delete(note()).wire() == {
        "action": "delete", "resource": {"type": NOTE, "id": "n-1"}}


def test_intent_token_is_carried_on_move_private_and_delete():
    """The M1c-2 seam: the row carries the intent token granted for it."""
    assert Change.move(note(), parent=None, intent="tok-1").wire()["intent"] == "tok-1"
    assert Change.set_private(note(), False, intent="tok-2").wire()["intent"] == "tok-2"
    assert Change.delete(note(), intent="tok-3").wire()["intent"] == "tok-3"


@pytest.mark.parametrize("build", [
    lambda: Change.create(note(), owner=None, author="u-1"),
    lambda: Change.create(note(), owner="u-1", author="u-1"),
    lambda: Change.create(note(), owner=PrincipalRef("team", "t"), author="u-1"),
    lambda: Change.create(note(), owner=PrincipalRef("user", ""), author="u-1"),
    lambda: Change.create(note(), owner=OWNER, author=""),
    lambda: Change.create(note(), owner=OWNER, author=None),
    lambda: Change.create(note(), owner=OWNER, author="u-1", private="yes"),
    lambda: Change.create(note(), owner=OWNER, author="u-1", parent=("wolfnotes/f", "f")),
    lambda: Change(action="create", resource=note(), owner=OWNER, author="u-1", intent="t"),
    lambda: Change.move(note(), parent="f-1"),
    lambda: Change.set_private(note(), None),
    lambda: Change.set_private(note(), 1),
    lambda: Change.delete(ResourceRef("note", "n-1")),
    lambda: Change.delete(ResourceRef(NOTE, "")),
    lambda: Change.delete(("wolfnotes/note", "n-1")),
    lambda: Change.delete(note(), intent=""),
    lambda: Change(action="delete", resource=note(), owner=OWNER),
    lambda: Change(action="move", resource=note(), parent=None, private=True),
    lambda: Change(action="ack_ownership", resource=note()),   # M1c-3
    lambda: Change(action="rename", resource=note()),
])
def test_a_malformed_change_is_refused_when_built(build):
    with pytest.raises(ValueError):
        build()


@pytest.mark.parametrize("change", [
    create(parent=folder(), private=True),
    create(owner=PrincipalRef("project", "p-1")),
    Change.move(note(), parent=None),
    Change.move(note(), parent=folder(), intent="t"),
    Change.set_private(note(), False),
    Change.delete(note()),
])
def test_change_round_trips_through_its_wire_shape(change):
    assert Change.from_wire(change.wire()) == change


def test_outbox_row_wire_adds_sequence_and_change_id():
    row = OutboxRow(sequence=7, change_id="c-7", change=Change.delete(note()))
    assert row.wire() == {"sequence": 7, "change_id": "c-7", "action": "delete",
                          "resource": {"type": NOTE, "id": "n-1"}}
    assert (row.status, row.reason, row.resource) == ("pending", None, note())


# --- stores: append, in the consumer's transaction --------------------------------------

def test_stores_are_outbox_stores(backend):
    assert isinstance(backend.store, OutboxStore)
    assert backend.store.service == SERVICE


def test_append_assigns_the_next_sequence_number(backend):
    rows = backend.append(create("n-1"), Change.move(note("n-1"), parent=folder()))
    rows += backend.append(Change.delete(note("n-1")))
    assert [r.sequence for r in rows] == [1, 2, 3]
    assert all(r.status == "pending" and r.change_id for r in rows)
    assert len({r.change_id for r in rows}) == 3
    stored = backend.store.unapplied_rows(10)
    assert stored == rows
    assert [r.change for r in stored] == [create("n-1"), Change.move(note("n-1"),
                                                                     parent=folder()),
                                          Change.delete(note("n-1"))]


def test_a_rolled_back_append_leaves_no_gap(backend):
    backend.append(create("n-1"))
    backend.append(create("n-2"), commit=False)
    (row,) = backend.append(create("n-3"))
    assert row.sequence == 2
    assert [r.change.resource.id for r in backend.store.unapplied_rows(10)] == ["n-1", "n-3"]


def test_the_row_commits_or_rolls_back_with_the_consumer_s_own_change(backend):
    conn = backend.connect()
    cur = conn.cursor()
    cur.execute("CREATE TABLE notes (id TEXT PRIMARY KEY)")
    conn.commit()
    for keep in (False, True):
        cur.execute("INSERT INTO notes (id) VALUES ('n-1')")
        backend.store.append(conn, create("n-1"))
        conn.commit() if keep else conn.rollback()
        cur.execute("SELECT count(*) FROM notes")
        assert cur.fetchone()[0] == int(keep)
        assert len(backend.store.unapplied_rows(10)) == int(keep)
    conn.close()


def test_append_takes_a_cursor_too(backend):
    conn = backend.connect()
    row = backend.store.append(conn.cursor(), create())
    conn.commit()
    conn.close()
    assert row.sequence == 1 and backend.store.unapplied_rows(1) == [row]


def test_append_keeps_a_given_change_id(backend):
    conn = backend.connect()
    row = backend.store.append(conn, create(), change_id="note-n-1-created")
    conn.commit()
    conn.close()
    assert row.change_id == "note-n-1-created"
    assert backend.store.unapplied_rows(1)[0].change_id == "note-n-1-created"


@pytest.mark.parametrize("change", [
    Change.delete(ResourceRef("finops/account", "a-1")),
    Change.move(note(), parent=ResourceRef("finops/account", "a-1")),
])
def test_append_refuses_another_service_s_type(backend, change):
    with pytest.raises(ValueError):
        backend.append(change)
    assert backend.store.unapplied_rows(10) == []
    assert backend.store.progress().last_sequence == 0


@pytest.mark.parametrize("change_id", ["", " ", 5])
def test_append_refuses_a_blank_change_id(backend, change_id):
    conn = backend.connect()
    with pytest.raises(ValueError):
        backend.store.append(conn, create(), change_id=change_id)
    conn.close()


def test_append_refuses_what_is_not_a_change(backend):
    with pytest.raises(ValueError):
        backend.append({"action": "delete"})


def test_concurrent_appends_get_a_gapless_sequence(backend):
    errors: list[BaseException] = []

    def worker(n: int) -> None:
        try:
            for i in range(5):
                backend.append(create(f"n-{n}-{i}"), commit=(i != 2))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert errors == []
    rows = backend.store.unapplied_rows(100)
    assert [r.sequence for r in rows] == list(range(1, 17))      # 4 workers x 4 commits
    assert backend.store.progress().last_sequence == 16


def test_each_service_has_its_own_sequence(backend):
    other = backend.make("finops")
    backend.append(create("n-1"))
    (row,) = backend.append(Change.delete(ResourceRef("finops/account", "a-1")), store=other)
    assert row.sequence == 1
    assert [r.sequence for r in backend.store.unapplied_rows(10)] == [1]
    assert other.unapplied_rows(10)[0].resource == ResourceRef("finops/account", "a-1")


def test_create_schema_is_idempotent(backend):
    backend.append(create())
    backend.store.create_schema()
    assert len(backend.store.unapplied_rows(10)) == 1


def test_a_store_needs_a_service_name(backend):
    cls = type(backend.store)
    for bad in ("", "wolf/notes", None):
        with pytest.raises(ValueError):
            cls(backend.connect, bad)


# --- stores: results, progress, what is still unapplied ------------------------------------

def test_record_keeps_each_result_and_applied_through(backend):
    backend.append(create("n-1"), create("n-2"), create("n-3"))
    backend.store.record(answer((1, "applied"), (2, "refused", "type not registered"),
                                (3, "held"), through=1))
    rows = backend.store.unapplied_rows(10)
    assert [(r.sequence, r.status, r.reason) for r in rows] == [
        (2, "refused", "type not registered"), (3, "held", None)]
    assert backend.store.progress() == OutboxProgress(last_sequence=3, applied_through=1,
                                                      dead_letter=rows[0])


def test_rows_up_to_applied_through_are_applied(backend):
    backend.append(create("n-1"), create("n-2"), create("n-3"))
    backend.store.record(answer((1, "held"), through=0))
    backend.store.record(answer(through=2))
    assert [r.sequence for r in backend.store.unapplied_rows(10)] == [3]
    progress = backend.store.progress()
    assert (progress.applied_through, progress.dead_letter) == (2, None)


def test_record_never_moves_applied_through_back(backend):
    backend.append(create("n-1"), create("n-2"))
    backend.store.record(answer((1, "applied"), (2, "applied"), through=2))
    backend.store.record(answer((2, "held"), through=1))           # a stale answer
    assert backend.store.progress().applied_through == 2
    assert backend.store.unapplied_rows(10) == []


def test_record_never_counts_rows_this_outbox_has_not_written(backend):
    backend.append(create("n-1"))
    backend.store.record(answer((1, "applied"), through=5))
    assert backend.store.progress().applied_through == 1
    (row,) = backend.append(create("n-2"))
    assert backend.store.unapplied_rows(10) == [row]


def test_resolved_counts_as_done(backend):
    backend.append(create("n-1"), create("n-2"))
    backend.store.record(answer((1, "refused", "why"), (2, "held"), through=0))
    backend.store.record(answer((1, "resolved"), (2, "applied"), through=2))
    assert backend.store.unapplied_rows(10) == []
    assert backend.store.progress().dead_letter is None


def test_unapplied_rows_are_oldest_first_and_limited(backend):
    backend.append(*[create(f"n-{i}") for i in range(7)])
    assert [r.sequence for r in backend.store.unapplied_rows(3)] == [1, 2, 3]
    backend.store.record(answer((1, "applied"), (2, "applied"), through=2))
    assert [r.sequence for r in backend.store.unapplied_rows(3)] == [3, 4, 5]


def test_unapplied_answers_which_resources_still_have_a_row(backend):
    backend.append(create("n-1"), create("n-2"), Change.move(note("n-1"), parent=folder()))
    backend.store.record(answer((1, "applied"), (2, "applied"), through=2))
    asked = {note("n-1"), note("n-2"), note("n-3"), folder()}
    assert backend.store.unapplied(asked) == {note("n-1")}
    backend.store.record(answer((3, "applied"), through=3))
    assert backend.store.unapplied(asked) == set()


def test_unapplied_of_nothing_is_nothing(backend):
    backend.append(create("n-1"))
    assert backend.store.unapplied(set()) == set()


def test_progress_of_an_empty_outbox(backend):
    assert backend.store.progress() == OutboxProgress(last_sequence=0, applied_through=0,
                                                      dead_letter=None)


def test_registration_start_is_recorded_once(backend):
    before = dt.datetime.now(dt.timezone.utc)
    first = backend.store.registration_start()
    assert first.tzinfo is not None
    assert before - dt.timedelta(seconds=5) <= first <= dt.datetime.now(dt.timezone.utc) + \
        dt.timedelta(seconds=5)
    assert backend.make().registration_start() == first


def test_registration_start_is_the_first_append_when_that_came_first(backend):
    backend.append(create())
    first = backend.store.registration_start()
    assert backend.store.registration_start() == first


def test_reference_store_classes():
    assert {SQLiteOutboxStore.DDL.count("CREATE TABLE"),
            PostgresOutboxStore.DDL.count("CREATE TABLE")} == {2}
