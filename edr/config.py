"""Central configuration. Every knob is read from the environment with a safe
default, so the system starts unconfigured but can be tuned without touching code.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Loaded here, before reading any variable. The entrypoints also call load_dotenv,
# but after their imports, by which point this module has already been evaluated.
# load_dotenv does not override the environment, so an explicit variable wins.
load_dotenv(BASE_DIR / ".env")

# ──────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────

# Append-only forensic record. Never rewritten, unlike the old kernel_events.json.
EVENTS_JSONL = Path(os.environ.get("EDR_EVENTS_FILE", BASE_DIR / "events.jsonl"))

# Local fallback when Supabase is unreachable: a database outage must not stop
# detection.
DB_FALLBACK_JSONL = Path(os.environ.get("EDR_DB_FALLBACK", BASE_DIR / "detections_fallback.jsonl"))

# Where the lab harness writes its results.
RESULTS_DIR = Path(os.environ.get("EDR_RESULTS_DIR", BASE_DIR / "results"))

# ──────────────────────────────────────────────
# Lab run tagging
# ──────────────────────────────────────────────

# Empty outside the lab. When set, every detection is tagged with them AND
# mirrored to results/<run_id>/detections.jsonl, so the report does not depend on
# Supabase being reachable — a free project auto-pauses after ~7 days idle.
RUN_ID = os.environ.get("EDR_RUN_ID", "").strip()
SCENARIO = os.environ.get("EDR_SCENARIO", "").strip()

# Deduplication window for was_recently_investigated. Sensible in production,
# ruinous for repeated lab runs of the same scenario: the harness sets it to 0.
DEDUP_WINDOW_S = int(os.environ.get("EDR_DEDUP_WINDOW", "300"))

# ──────────────────────────────────────────────
# Operating mode
# ──────────────────────────────────────────────

MODE_DRY_RUN = "dry-run"
MODE_AUTONOMOUS = "autonomous"
VALID_MODES = (MODE_DRY_RUN, MODE_AUTONOMOUS)

# Default is not to signal. Acting for real must be an explicit choice, not a
# configuration slip.
EDR_MODE = os.environ.get("EDR_MODE", MODE_DRY_RUN).strip().lower()
if EDR_MODE not in VALID_MODES:
    EDR_MODE = MODE_DRY_RUN

# ──────────────────────────────────────────────
# Remediation safeguards
# ──────────────────────────────────────────────

VALID_ACTIONS = ("freeze", "kill")

# Not a list of "important processes": the minimum whose death leaves the machine
# unusable or cuts off remote access to whoever is investigating.
_DEFAULT_PROTECTED = (
    "systemd", "init", "kthreadd", "sshd", "dockerd",
    "containerd", "dbus-daemon", "agetty", "login",
)
PROTECTED_COMMS = frozenset(
    c.strip() for c in os.environ.get(
        "EDR_PROTECTED_COMMS", ",".join(_DEFAULT_PROTECTED)
    ).split(",") if c.strip()
)

# Bounds the damage of a hallucination loop.
RATE_LIMIT_MAX = int(os.environ.get("EDR_RATE_LIMIT_MAX", "3"))
RATE_LIMIT_WINDOW_S = float(os.environ.get("EDR_RATE_LIMIT_WINDOW", "300"))

# ──────────────────────────────────────────────
# Model and Ollama client
# ──────────────────────────────────────────────

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("EDR_MODEL", "llama3.1:8b")

# (connect, read). The read timeout is generous because a cold first inference
# loads ~5 GB into VRAM.
LLM_CONNECT_TIMEOUT = float(os.environ.get("EDR_LLM_CONNECT_TIMEOUT", "5"))
LLM_READ_TIMEOUT = float(os.environ.get("EDR_LLM_READ_TIMEOUT", "180"))

# Ollama's default is 4096 and a round-2 prompt already spends ~2563 tokens on
# execve events alone. Raised here, and still budgeted explicitly in prompts.py.
LLM_NUM_CTX = int(os.environ.get("EDR_LLM_NUM_CTX", "8192"))
LLM_NUM_PREDICT = int(os.environ.get("EDR_LLM_NUM_PREDICT", "512"))

# Low temperature: an unreproducible decision is worthless for the lab comparison.
LLM_TEMPERATURE = float(os.environ.get("EDR_LLM_TEMPERATURE", "0.1"))
LLM_TOP_P = float(os.environ.get("EDR_LLM_TOP_P", "0.9"))

# Without this the model is evicted from VRAM between 20 s polls.
LLM_KEEP_ALIVE = os.environ.get("EDR_LLM_KEEP_ALIVE", "30m")

# ──────────────────────────────────────────────
# Context budget (edr/prompts.py)
# ──────────────────────────────────────────────

MAX_ALERTS = int(os.environ.get("EDR_MAX_ALERTS", "10"))
MAX_EXECVE = int(os.environ.get("EDR_MAX_EXECVE", "20"))
MAX_FDS = int(os.environ.get("EDR_MAX_FDS", "30"))
MAX_CONNECTIONS = int(os.environ.get("EDR_MAX_CONNECTIONS", "15"))
MAX_FIELD_CHARS = int(os.environ.get("EDR_MAX_FIELD_CHARS", "256"))
MAX_SECTION_CHARS = int(os.environ.get("EDR_MAX_SECTION_CHARS", "4000"))

# ──────────────────────────────────────────────
# Event store
# ──────────────────────────────────────────────

# Events kept in memory. The JSONL keeps the full history.
EVENT_CAP = int(os.environ.get("EDR_EVENT_CAP", "2000"))

KIND_MODULE_LOAD = "module_load"
KIND_EXECVE = "execve"

# ──────────────────────────────────────────────
# Triage (edr/triage.py)
# ──────────────────────────────────────────────

# Score above which a process is escalated to the model. With the current
# weights one weak signal is not enough and two are.
TRIAGE_THRESHOLD = int(os.environ.get("EDR_TRIAGE_THRESHOLD", "50"))
