import os
from datetime import datetime, timedelta, timezone
from supabase import create_client

_client = None

def get_client():
    global _client
    if _client is None:
        url = os.environ["SUPABASE_URL"]
        key = os.environ["SUPABASE_KEY"]
        _client = create_client(url, key)
    return _client

def log_detection(pid, process, decision, action, llm_round1, llm_round2=None, remediation=None) -> str:
    # Insert new detected incident
    row = {
        "pid": pid,
        "process": process,
        "decision": decision,
        "action": action,
        "llm_round1": llm_round1,
        "llm_round2": llm_round2,
        "remediation": remediation
    }

    res = get_client().table("detections").insert(row).execute()
    return res.data[0]["id"]

def update_detection(detection_id: str, **fields):
    # Updates column values for existing detection.
    get_client().table("detections").update(fields).eq("id", detection_id).execute()

def log_evidence(detection_id: str, tool: str, result: str):
    get_client().table("evidence").insert({
        "detection_id": detection_id,
        "tool": tool,
        "result": result,
    }).execute()

# Check if detection was already investigated to avoid duplications.
def was_recently_investigated(pid: int, process: str, window_seconds: int = 300) -> bool:
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()

    res = (
        get_client().table("detections").select("id").eq("pid", pid).eq("process", process).gte("created_at", cutoff).limit(1).execute()
    )
    return len(res.data) > 0

