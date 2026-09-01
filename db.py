"""Detection and evidence persistence in Supabase.

**Persistence is telemetry, not a dependency of detection.** A remote database
being down must not stop the EDR: every operation degrades to a local JSONL and
the decision loop carries on.

This is not a theoretical precaution. This module brought the whole orchestrator
down twice in one day — a transient connection error and a Cloudflare 521 from a
free-tier project that had auto-paused — neither of which has anything to do with
the ability to detect threats.
"""

import json
import logging
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone

from supabase import create_client

from edr import config

log = logging.getLogger("edr.db")

_client = None
_client_failed = False
_fallback_lock = threading.Lock()


def get_client():
    global _client
    if _client is None:
        url = os.environ["SUPABASE_URL"]
        key = os.environ["SUPABASE_KEY"]
        _client = create_client(url, key)
    return _client


def _fallback(operation, payload):
    """Record locally whatever could not be sent to Supabase.

    Append-only JSONL, like the event log: if what happened during an outage
    ever has to be reconstructed, it is here.
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "payload": payload,
    }
    try:
        with _fallback_lock:
            with open(config.DB_FALLBACK_JSONL, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except OSError as e:
        log.error("could not write the local fallback either: %s", e)


def _journal(operation, payload):
    """Mirror a detection locally when the run is tagged with a run_id.

    Unconditional, unlike `_fallback`: the lab report reads from here, so it must
    not depend on whether the remote insert happened to succeed.
    """
    if not config.RUN_ID:
        return
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "run_id": config.RUN_ID,
        "scenario": config.SCENARIO or None,
        "operation": operation,
        "payload": payload,
    }
    try:
        path = config.RESULTS_DIR / config.RUN_ID
        path.mkdir(parents=True, exist_ok=True)
        with _fallback_lock:
            with open(path / "detections.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except OSError as e:
        log.error("could not write the run journal: %s", e)


def _warn_once(e):
    """Warn in detail on the first failure and tersely afterwards.

    The loop polls every 20 s: without this, a prolonged outage fills the output
    with identical tracebacks and buries what matters.
    """
    global _client_failed
    if not _client_failed:
        _client_failed = True
        log.warning("Supabase unavailable (%s: %s). Continuing with the local fallback at %s. "
                    "On a free project, check it is not paused: "
                    "https://supabase.com/dashboard",
                    type(e).__name__, e, config.DB_FALLBACK_JSONL)
    else:
        log.debug("Supabase still unavailable: %s", type(e).__name__)


def log_detection(pid, process, decision, action, llm_round1,
                  llm_round2=None, remediation=None, **extra):
    """Insert a detection. Returns its UUID, or None if it could not be stored.

    `extra` carries the phase 5-7 columns (`model`, `latency_ms`, `tokens_in`,
    `severity`, `mitre_technique`…) as kwargs, so adding a metric does not mean
    changing this signature.

    `pid` and `process` may be None: a NOTHING verdict is recorded too, because
    the false-negative rate is computed from exactly those rows.
    """
    row = {
        "pid": pid,
        "process": process,
        "decision": decision,
        "action": action,
        "llm_round1": llm_round1,
        "llm_round2": llm_round2,
        "remediation": remediation,
        **extra,
    }
    try:
        res = get_client().table("detections").insert(row).execute()
        detection_id = res.data[0]["id"]
    except Exception as e:  # noqa: BLE001 — any failure must degrade, not propagate
        _warn_once(e)
        _fallback("log_detection", row)
        # In the lab a local id is synthesised so the rest of the cycle still
        # correlates in the journal. Outside it, None keeps the old behaviour.
        detection_id = f"local-{uuid.uuid4()}" if config.RUN_ID else None

    _journal("log_detection", {"id": detection_id, **row})
    return detection_id


def update_detection(detection_id, **fields):
    if not detection_id:
        return False
    _journal("update_detection", {"id": detection_id, **fields})
    try:
        get_client().table("detections").update(fields).eq("id", detection_id).execute()
        return True
    except Exception as e:  # noqa: BLE001
        _warn_once(e)
        _fallback("update_detection", {"id": detection_id, **fields})
        return False


def log_evidence(detection_id, tool, result):
    if not detection_id:
        return False
    row = {"detection_id": detection_id, "tool": tool, "result": result}
    _journal("log_evidence", row)
    try:
        get_client().table("evidence").insert(row).execute()
        return True
    except Exception as e:  # noqa: BLE001
        _warn_once(e)
        _fallback("log_evidence", row)
        return False


def was_recently_investigated(pid, process, window_seconds=300):
    """True if the same (pid, process) was already analysed within the window.

    **Fails open.** The alternative — assuming it was investigated and skipping
    it — would turn a database outage into total blindness. Analysing an
    incident twice is waste; not analysing it is a security failure.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    try:
        res = (
            get_client().table("detections")
            .select("id")
            .eq("pid", pid)
            .eq("process", process)
            .gte("created_at", cutoff)
            .limit(1)
            .execute()
        )
        return len(res.data) > 0
    except Exception as e:  # noqa: BLE001
        _warn_once(e)
        return False
