"""Remediation safeguards: what the EDR is not allowed to do.

The deterministic layer that bounds the probabilistic one. The LLM proposes,
these rules dispose. **Every attempt is recorded, denials included**: without
that trace there is no way to show the safeguards fired, and "the model asked to
kill systemd and the safety layer refused" is a result, not an incident.
"""

import logging
import os
import signal as signal_module
import threading
import time
from collections import deque, namedtuple

from . import config
from . import procinfo

log = logging.getLogger("edr.safety")

Verdict = namedtuple("Verdict", ["allowed", "reason", "detail"])

# Bounded diagnostic trace, not the evidence store — that is the database.
_ATTEMPTS = deque(maxlen=200)
_ATTEMPTS_LOCK = threading.Lock()


class RateLimiter:
    """Sliding window over approved remediations.

    Bounds the damage of a hallucination loop. The clock is injectable so the
    window can be tested without real waits.
    """

    def __init__(self, max_n=None, window_s=None, clock=time.monotonic):
        self.max_n = config.RATE_LIMIT_MAX if max_n is None else max_n
        self.window_s = config.RATE_LIMIT_WINDOW_S if window_s is None else window_s
        self._clock = clock
        self._hits = deque()
        self._lock = threading.Lock()

    def _prune(self, now):
        while self._hits and now - self._hits[0] > self.window_s:
            self._hits.popleft()

    def would_allow(self):
        with self._lock:
            now = self._clock()
            self._prune(now)
            return len(self._hits) < self.max_n

    def record(self):
        with self._lock:
            now = self._clock()
            self._prune(now)
            self._hits.append(now)

    def reset(self):
        with self._lock:
            self._hits.clear()


# Process-wide default. Tests build their own.
_DEFAULT_LIMITER = RateLimiter()


def validate_remediation(pid, action, expected_starttime=None,
                         self_pid=None, limiter=None):
    """Decide whether a remediation may run. Executes nothing.

    Returns a `Verdict(allowed, reason, detail)`. `reason` is a stable slug meant
    to be aggregated in the lab statistics, not a message for humans.
    """
    limiter = _DEFAULT_LIMITER if limiter is None else limiter
    self_pid = os.getpid() if self_pid is None else self_pid

    # os.kill(0, sig) signals the EDR's WHOLE process group, negatives signal
    # arbitrary groups, and 1 is systemd.
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return Verdict(False, "invalid_pid", f"pid={pid!r} is not a remediable process")

    if action not in config.VALID_ACTIONS:
        return Verdict(False, "invalid_action",
                       f"action {action!r}; allowed: {list(config.VALID_ACTIONS)}")

    stat = procinfo.read_stat(pid)
    if stat is None:
        return Verdict(False, "no_such_process", f"pid {pid} no longer exists")

    # Self-protection. The MCP server is a child of the orchestrator, so walking
    # the ancestor chain covers both.
    if pid == self_pid:
        return Verdict(False, "self_protection", "the pid is the EDR's own process")
    chain = procinfo.ancestors(self_pid)
    if pid in chain:
        return Verdict(False, "self_protection",
                       f"pid {pid} is an ancestor of the EDR (chain: {chain})")

    if stat["flags"] & procinfo.PF_KTHREAD:
        return Verdict(False, "kernel_thread",
                       f"{stat['comm']} is a kernel thread, it has no userspace")

    if stat["comm"] in config.PROTECTED_COMMS:
        return Verdict(False, "protected_process",
                       f"{stat['comm']} is on the protected process list")

    # Tens of seconds pass between capturing the event and this point: ample time
    # for the kernel to recycle the pid onto an innocent process.
    #
    # Without a starttime there is NO remediation. Skipping the check would leave
    # open exactly the door it exists to close — half an identity check is worth
    # nothing — so it fails closed.
    if expected_starttime is None:
        return Verdict(False, "identity_unknown",
                       f"identity of pid {pid} was never captured: cannot verify "
                       f"it is still the same process")

    if stat["starttime"] != expected_starttime:
        return Verdict(False, "pid_reused",
                       f"expected starttime {expected_starttime}, actual {stat['starttime']}: "
                       f"pid {pid} now belongs to another process ({stat['comm']})")

    # Checked last on purpose: a rejected proposal must not consume budget.
    if not limiter.would_allow():
        return Verdict(False, "rate_limited",
                       f"more than {limiter.max_n} remediations in {limiter.window_s:.0f}s")

    return Verdict(True, "ok", f"{stat['comm']} (pid={pid}, starttime={stat['starttime']})")


def remediate(pid, action, expected_starttime=None, reason="",
              mode=None, signal_fn=None, limiter=None, self_pid=None):
    """Validate and, if allowed and the mode permits, signal the process.

    dry-run walks exactly the same path minus the signal, so its lab metrics stay
    comparable with autonomous ones: same decisions, same rate-limit budget.
    """
    mode = config.EDR_MODE if mode is None else mode
    signal_fn = os.kill if signal_fn is None else signal_fn
    limiter = _DEFAULT_LIMITER if limiter is None else limiter

    verdict = validate_remediation(pid, action, expected_starttime,
                                   self_pid=self_pid, limiter=limiter)

    record = {
        "ts": time.time(),
        "pid": pid,
        "action": action,
        "reason": reason,
        "mode": mode,
        "allowed": verdict.allowed,
        "verdict": verdict.reason,
        "detail": verdict.detail,
    }

    if not verdict.allowed:
        record["outcome"] = "denied"
        _remember(record)
        log.warning("REMEDIATION DENIED pid=%s action=%s reason=%s (%s)",
                    pid, action, verdict.reason, verdict.detail)
        return record

    limiter.record()

    if mode == config.MODE_DRY_RUN:
        record["outcome"] = "dry_run"
        _remember(record)
        log.info("[DRY-RUN] would have sent %s to %s — no signal was sent",
                 action.upper(), verdict.detail)
        return record

    sig = signal_module.SIGSTOP if action == "freeze" else signal_module.SIGKILL
    try:
        signal_fn(pid, sig)
        record["outcome"] = "executed"
        log.warning("REMEDIATION EXECUTED %s on %s", action.upper(), verdict.detail)
    except ProcessLookupError:
        record["outcome"] = "vanished"
        record["detail"] = f"pid {pid} died between validation and the signal"
    except PermissionError:
        record["outcome"] = "permission_denied"
        record["detail"] = f"not allowed to signal pid {pid}: running as root?"
    except OSError as e:
        record["outcome"] = "error"
        record["detail"] = str(e)

    _remember(record)
    return record


def _remember(record):
    with _ATTEMPTS_LOCK:
        _ATTEMPTS.append(record)


def attempts():
    """Every recorded attempt, approved and denied."""
    with _ATTEMPTS_LOCK:
        return list(_ATTEMPTS)


def describe(record):
    """Turn an attempt record into one line for the operator and the LLM."""
    if record["outcome"] == "denied":
        return f"[BLOCKED] {record['verdict']}: {record['detail']}"
    if record["outcome"] == "dry_run":
        return (f"[DRY-RUN] validated ({record['detail']}). No signal was sent. "
                f"To act for real: EDR_MODE=autonomous")
    if record["outcome"] == "executed":
        verb = "frozen (SIGSTOP)" if record["action"] == "freeze" else "killed (SIGKILL)"
        return f"[EXECUTED] process {verb}: {record['detail']}"
    return f"[{record['outcome'].upper()}] {record['detail']}"
