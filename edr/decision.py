"""Reading the model's verdict.

Two layers. The primary one is Ollama's native structured output: a JSON Schema
in the `format` parameter, with fields bounded by `enum`. The fallback is an
anchored parser for when structured output is unavailable or does not parse.

`INVALID` is deliberately not `NOTHING`: "the model could not answer" and "the
model chose not to act" are different things when computing false negatives.
"""

import logging
import re
from dataclasses import dataclass

log = logging.getLogger("edr.decision")

INVESTIGATE = "INVESTIGATE"
MITIGATE = "MITIGATE"
NOTHING = "NOTHING"
INVALID = "INVALID"

VALID_ACTIONS = (INVESTIGATE, MITIGATE, NOTHING)
VALID_REMEDIATIONS = ("freeze", "kill")


@dataclass
class Decision:
    action: str
    pid: int | None = None
    remediation: str | None = None
    source: str = "none"     # structured | parsed | none
    detail: str = ""

    @property
    def is_actionable(self):
        return self.action in (INVESTIGATE, MITIGATE) and self.pid is not None


# ──────────────────────────────────────────────
# Layer 1: structured output
# ──────────────────────────────────────────────

def schema(allow_investigate=True, allowed_pids=None):
    """JSON Schema for Ollama's `format` parameter.

    **Every field is required.** An optional field is a field the model will
    omit: with only `reasoning` and `action` required it answered
    `{"action": "INVESTIGATE"}` with no pid, twice, while naming the pids in its
    own reasoning. `pid` and `remediation` accept null so it can say "not
    applicable" without breaking the schema, but it must emit them.

    **`pid` is constrained by enum to the pids actually shown.** The model
    otherwise confuses `pid` with the adjacent `ppid` field systematically. The
    grammar Ollama derives from the schema cannot emit any other value, which
    makes the mistake impossible rather than merely detectable.
    """
    actions = list(VALID_ACTIONS) if allow_investigate else [MITIGATE, NOTHING]

    if allowed_pids:
        # null stays allowed: that is what a NOTHING verdict carries.
        pid_field = {"enum": sorted(allowed_pids) + [None],
                     "description": "must be one of the PIDs listed in the telemetry"}
    else:
        pid_field = {"type": ["integer", "null"],
                     "description": "PID from the telemetry; null only for NOTHING"}

    return {
        "type": "object",
        "properties": {
            "reasoning": {"type": "string"},
            "action": {"type": "string", "enum": actions},
            "pid": pid_field,
            "remediation": {"type": ["string", "null"],
                            "enum": list(VALID_REMEDIATIONS) + [None],
                            "description": "only meaningful when action is MITIGATE"},
        },
        "required": ["reasoning", "action", "pid", "remediation"],
    }


def from_structured(data, allowed_pids):
    """Validate the structured response. None if it is unusable.

    The schema bounds each field independently but not their mutual coherence —
    the model has returned `"action": "NOTHING"` alongside
    `"remediation": "freeze"` — so `remediation` is ignored unless the action is
    MITIGATE.
    """
    if not isinstance(data, dict):
        return None

    action = data.get("action")
    if action not in VALID_ACTIONS:
        return None

    if action == NOTHING:
        return Decision(NOTHING, source="structured")

    pid = data.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool):
        return Decision(INVALID, source="structured",
                        detail=f"action {action} without a valid pid (pid={pid!r})")

    if allowed_pids is not None and pid not in allowed_pids:
        return Decision(INVALID, source="structured",
                        detail=f"pid {pid} absent from the telemetry shown "
                               f"{sorted(allowed_pids)}: hallucination or injection")

    if action == INVESTIGATE:
        return Decision(INVESTIGATE, pid=pid, source="structured")

    remediation = data.get("remediation")
    if remediation not in VALID_REMEDIATIONS:
        # Default to the reversible action: freezing a legitimate process can be
        # undone, killing it cannot.
        remediation = "freeze"
    return Decision(MITIGATE, pid=pid, remediation=remediation, source="structured")


# ──────────────────────────────────────────────
# Layer 2: anchored parser
# ──────────────────────────────────────────────

_MITIGATE_RE = re.compile(
    r"DECISION:\s*MITIGATE\s+pid=(\d+)\s+action=(freeze|kill)\.?", re.IGNORECASE)
_INVESTIGATE_RE = re.compile(
    r"DECISION:\s*INVESTIGATE\s+pid=(\d+)\.?", re.IGNORECASE)
_NOTHING_RE = re.compile(r"DECISION:\s*NOTHING\.?", re.IGNORECASE)

# Decorations models constantly add around the line.
_DECORATION_RE = re.compile(r"^[\s>#\-*`_]+|[\s*`_]+$")


def _clean(line):
    return _DECORATION_RE.sub("", line.strip())


def parse_decision(text, allowed_pids=None):
    """Extract the verdict by scanning lines bottom-up.

    `fullmatch` is the key: the WHOLE line must be the verdict, so a sentence
    that merely mentions one — or negates it — does not count. Scanning from the
    end makes the last decision win, which is the one emitted after reasoning.
    """
    if not text:
        return Decision(INVALID, detail="empty response")

    for raw in reversed(text.splitlines()):
        line = _clean(raw)
        if not line:
            continue

        match = _MITIGATE_RE.fullmatch(line)
        if match:
            pid = int(match.group(1))
            bad = _reject_pid(pid, allowed_pids)
            return bad or Decision(MITIGATE, pid=pid,
                                   remediation=match.group(2).lower(),
                                   source="parsed")

        match = _INVESTIGATE_RE.fullmatch(line)
        if match:
            pid = int(match.group(1))
            bad = _reject_pid(pid, allowed_pids)
            return bad or Decision(INVESTIGATE, pid=pid, source="parsed")

        if _NOTHING_RE.fullmatch(line):
            return Decision(NOTHING, source="parsed")

    return Decision(INVALID, detail="no valid DECISION: line in the response")


def _reject_pid(pid, allowed_pids):
    """A pid that was not in the telemetry is hallucination or injection."""
    if allowed_pids is None or pid in allowed_pids:
        return None
    return Decision(INVALID, source="parsed",
                    detail=f"pid {pid} absent from the telemetry shown "
                           f"{sorted(allowed_pids)}: hallucination or injection")


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def decide(result, allowed_pids=None):
    """Interpret an LLMResult through the best available path."""
    if result is None or not result.ok:
        detail = "no response from the model" if result is None else result.error
        return Decision(INVALID, detail=detail)

    if result.data is not None:
        structured = from_structured(result.data, allowed_pids)
        if structured is not None:
            return structured
        log.warning("structured output unusable; falling back to the parser")

    return parse_decision(result.text, allowed_pids)
