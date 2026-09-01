"""Tests for the event store.

The important one is the concurrency test: it reproduces exactly the scenario
that used to corrupt the data — the sensor thread writing while the MCP tool
thread reads.
"""

import json
import threading

from edr.eventstore import EventStore


def test_seq_is_monotonic_and_starts_at_1(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")

    assert store.append("execve", pid=1) == 1
    assert store.append("execve", pid=2) == 2
    assert store.append("module_load", pid=3) == 3


def test_events_carry_a_sortable_utc_timestamp(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")
    store.append("execve", pid=1)
    store.append("execve", pid=2)

    events = store.query()
    # ISO-8601 UTC: lexicographically sortable and correlatable with Supabase.
    assert events[0]["ts"] <= events[1]["ts"]
    assert "+00:00" in events[0]["ts"]


# ── concurrency: the bug that motivated this module ────────────

def test_concurrent_reads_and_writes(tmp_path):
    """20 threads writing while others read: no exception, no duplicate seq.

    The sensor thread used to rewrite the whole JSON file while the main thread
    parsed it, producing intermittent JSONDecodeErrors that reached the LLM as
    error text.
    """
    store = EventStore(tmp_path / "e.jsonl", cap=20000)
    errors = []
    seqs = []
    seqs_lock = threading.Lock()

    def writer(n):
        try:
            mine = [store.append("execve", pid=n, i=i) for i in range(500)]
            with seqs_lock:
                seqs.extend(mine)
        except Exception as e:  # noqa: BLE001 — the test exists to catch anything
            errors.append(e)

    def reader():
        try:
            for _ in range(200):
                store.query(kind="execve", limit=50)
                store.pending(limit=50)
                store.stats()
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = ([threading.Thread(target=writer, args=(n,)) for n in range(20)]
               + [threading.Thread(target=reader) for _ in range(5)])
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len(seqs) == 10000
    assert len(set(seqs)) == 10000, "duplicate sequence numbers"


def test_the_jsonl_parses_line_by_line(tmp_path):
    """Each line is independent: one corrupt line does not void the whole file."""
    path = tmp_path / "e.jsonl"
    store = EventStore(path, cap=100)

    threads = [threading.Thread(target=lambda n=n: [store.append("execve", pid=n, i=i)
                                                    for i in range(50)])
               for n in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = path.read_text().strip().split("\n")
    assert len(lines) == 500
    seqs = {json.loads(line)["seq"] for line in lines}
    assert len(seqs) == 500


# ── capacity ───────────────────────────────────────────────────

def test_memory_is_bounded_and_losses_are_counted(tmp_path):
    store = EventStore(tmp_path / "e.jsonl", cap=10)
    for i in range(25):
        store.append("execve", pid=i)

    stats = store.stats()
    assert stats["in_memory"] == 10
    # Dropping silently would turn lost telemetry into something invisible.
    assert stats["dropped"] == 15
    # The most recent ones are kept.
    assert [e["pid"] for e in store.query(limit=100)] == list(range(15, 25))


def test_the_jsonl_keeps_the_full_history(tmp_path):
    """Memory is bounded; the on-disk forensic record is not."""
    path = tmp_path / "e.jsonl"
    store = EventStore(path, cap=5)
    for i in range(30):
        store.append("execve", pid=i)

    assert len(path.read_text().strip().split("\n")) == 30


# ── filters ────────────────────────────────────────────────────

def test_filters_by_kind_and_by_pid(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")
    store.append("execve", pid=100)
    store.append("execve", pid=200)
    store.append("module_load", pid=100)

    assert len(store.query(kind="execve")) == 2
    assert len(store.query(pid=100)) == 2
    assert len(store.query(kind="module_load", pid=100)) == 1
    assert store.query(pid=999) == []


def test_since_seq_returns_only_what_is_new(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(5):
        store.append("execve", pid=i)

    assert [e["pid"] for e in store.query(since_seq=3)] == [3, 4]


def test_query_returns_the_most_recent_on_overflow(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(10):
        store.append("execve", pid=i)

    assert [e["pid"] for e in store.query(limit=3)] == [7, 8, 9]


# ── event acknowledgement ──────────────────────────────────────

def test_ack_stops_alerts_being_re_analysed_forever(tmp_path):
    """The original bug: kernel_events.json was never emptied nor marked."""
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(5):
        store.append("module_load", pid=i)

    pending = store.pending("module_load")
    assert len(pending) == 5

    store.ack(max(e["seq"] for e in pending))
    assert store.pending("module_load") == []

    store.append("module_load", pid=99)
    assert [e["pid"] for e in store.pending("module_load")] == [99]


def test_pending_returns_the_oldest_first(tmp_path):
    """The opposite of query: acknowledgement must advance without gaps."""
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(10):
        store.append("module_load", pid=i)

    assert [e["pid"] for e in store.pending(limit=3)] == [0, 1, 2]


def test_the_predicate_is_applied_before_the_limit(tmp_path):
    """Regression: filtering after the limit would make the trigger useless.

    `pending` returns the OLDEST events, and the real ratio is thousands of
    irrelevant ones for every interesting one. Trimming first would fill the
    window with noise and drop the flagged event — which is the last one — so
    the system would never escalate anything.
    """
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(100):
        store.append("execve", pid=i, interesting=(i == 99))

    pending = store.pending(limit=5, predicate=lambda e: e["interesting"])

    assert [e["pid"] for e in pending] == [99]


def test_without_a_predicate_it_behaves_as_before(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(5):
        store.append("module_load", pid=i)

    assert len(store.pending(limit=5)) == 5


def test_the_predicate_coexists_with_the_kind_filter(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")
    store.append("module_load", pid=1, bad=True)
    store.append("execve", pid=2, bad=True)
    store.append("execve", pid=3, bad=False)

    pending = store.pending("execve", predicate=lambda e: e["bad"])

    assert [e["pid"] for e in pending] == [2]


def test_ack_is_monotonic(tmp_path):
    """A late or retried ack cannot move the pointer backwards."""
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(5):
        store.append("module_load", pid=i)

    assert store.ack(5) == 5
    assert store.ack(2) == 0
    assert store.pending("module_load") == []


def test_partial_ack(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(5):
        store.append("module_load", pid=i)

    assert store.ack(3) == 3
    assert [e["pid"] for e in store.pending("module_load")] == [3, 4]


def test_ack_affects_pending_only_not_query(tmp_path):
    """The forensic evidence stays queryable after acknowledgement."""
    store = EventStore(tmp_path / "e.jsonl")
    store.append("module_load", pid=1)
    store.ack(1)

    assert store.pending("module_load") == []
    assert len(store.query(kind="module_load")) == 1


# ── degradation ────────────────────────────────────────────────

def test_it_works_without_a_file(tmp_path):
    """Memory-only mode: useful in tests and if the disk is unavailable."""
    store = EventStore(None)
    assert store.append("execve", pid=1) == 1
    assert len(store.query()) == 1


def test_a_failing_disk_does_not_stop_detection(tmp_path, monkeypatch):
    """Detecting without a trace is bad; not detecting at all is worse."""
    store = EventStore(tmp_path / "does" / "not" / "exist" / "e.jsonl")

    assert store.append("execve", pid=1) == 1
    assert len(store.query()) == 1
    assert store.stats()["jsonl"] is None
