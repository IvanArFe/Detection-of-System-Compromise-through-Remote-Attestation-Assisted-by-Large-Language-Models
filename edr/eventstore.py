"""Event store shared by the sensor threads and the MCP tools.

Sensors and MCP server live in the same process but different threads. They used
to talk through a JSON file that the sensor rewrote whole on every event while
the tools read it back, which produced intermittent JSONDecodeErrors that reached
the LLM as telemetry. The fix is not to lock the file but to take it out of the
data path: events live in memory under a lock, and the file becomes an
append-only forensic record.
"""

import json
import threading
from collections import deque
from datetime import datetime, timezone


def utc_now():
    """ISO-8601 UTC timestamp.

    Lexicographically sortable and with a zone, so it correlates with the
    TIMESTAMPTZ values Supabase stores.
    """
    return datetime.now(timezone.utc).isoformat()


class EventStore:
    """Bounded, thread-safe event queue with explicit acknowledgement."""

    def __init__(self, jsonl_path=None, cap=2000):
        self._lock = threading.Lock()
        self._events = deque(maxlen=cap)
        self._next_seq = 1
        self._acked = 0
        self._dropped = 0
        self._jsonl_path = str(jsonl_path) if jsonl_path else None
        self._fh = None

    # ── writing ────────────────────────────────────────────────

    def append(self, kind, **fields):
        """Record an event and return its sequence number.

        Stored in memory BEFORE touching the disk: if the disk fails we lose the
        forensic record but not the detection.
        """
        with self._lock:
            event = {"seq": self._next_seq, "ts": utc_now(), "kind": kind}
            event.update(fields)
            self._next_seq += 1

            # A maxlen deque discards silently; counting it turns an invisible
            # loss into a metric.
            if len(self._events) == self._events.maxlen:
                self._dropped += 1
            self._events.append(event)

            self._write_line(event)
            return event["seq"]

    def _write_line(self, event):
        """Append one line to the JSONL. Called with the lock held."""
        if not self._jsonl_path:
            return
        try:
            if self._fh is None:
                self._fh = open(self._jsonl_path, "a", encoding="utf-8")
            self._fh.write(json.dumps(event, ensure_ascii=False) + "\n")
            self._fh.flush()
        except OSError:
            # Degrade to memory-only rather than propagate into the sensor thread.
            self._jsonl_path = None
            self._fh = None

    # ── reading ────────────────────────────────────────────────

    def query(self, kind=None, pid=None, since_seq=0, limit=50):
        """Matching events in chronological order.

        On overflow the MOST RECENT are returned: what just happened is more
        informative than what happened first.
        """
        with self._lock:
            matches = [
                e for e in self._events
                if e["seq"] > since_seq
                and (kind is None or e["kind"] == kind)
                and (pid is None or e.get("pid") == pid)
            ]
        return matches[-limit:] if limit and limit > 0 else matches

    def pending(self, kind=None, limit=50, predicate=None):
        """Unacknowledged events, oldest first.

        Oldest-first so acknowledgement advances contiguously and leaves no
        unprocessed gaps behind.

        `predicate` decides whether an event counts and is applied **before** the
        limit. That ordering matters: with thousands of irrelevant events ahead —
        the real proportion of execve traffic — filtering after the cut would
        return a window of pure noise and drop exactly the flagged event.
        """
        with self._lock:
            matches = [
                e for e in self._events
                if e["seq"] > self._acked
                and (kind is None or e["kind"] == kind)
                and (predicate is None or predicate(e))
            ]
        return matches[:limit] if limit and limit > 0 else matches

    # ── acknowledgement ────────────────────────────────────────

    def ack(self, up_to_seq):
        """Mark every event with `seq <= up_to_seq` as consumed.

        Monotonic: a late acknowledgement cannot move the pointer backwards and
        cause resolved alerts to be re-analysed.
        """
        with self._lock:
            up_to_seq = int(up_to_seq)
            if up_to_seq <= self._acked:
                return 0
            newly = sum(
                1 for e in self._events if self._acked < e["seq"] <= up_to_seq
            )
            self._acked = up_to_seq
            return newly

    # ── introspection ──────────────────────────────────────────

    def stats(self):
        """Counters for diagnosis and for the performance chapter."""
        with self._lock:
            return {
                "in_memory": len(self._events),
                "next_seq": self._next_seq,
                "acked": self._acked,
                "dropped": self._dropped,
                "jsonl": self._jsonl_path,
            }

    def close(self):
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.close()
                except OSError:
                    pass
                self._fh = None
