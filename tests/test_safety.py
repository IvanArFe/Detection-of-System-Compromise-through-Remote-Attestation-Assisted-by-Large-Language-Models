"""Tests for the remediation safeguards.

The most important suite of the phase: each test corresponds to a concrete way
the EDR could cause collateral damage. None of them sends a real signal — the
signalling function is injected.
"""

import os

import pytest

from edr import config, procinfo, safety


@pytest.fixture
def limiter():
    """Isolated limiter with a manual clock, to avoid depending on global state."""
    clock = {"t": 1000.0}
    lim = safety.RateLimiter(max_n=3, window_s=300, clock=lambda: clock["t"])
    lim.clock = clock
    return lim


@pytest.fixture
def never_signals():
    """Capture the signals instead of sending them."""
    sent = []
    return sent, lambda pid, sig: sent.append((pid, sig))


# ── 1. Pids that do not designate one process ──────────────────

@pytest.mark.parametrize("pid,reason", [
    (0, "invalid_pid"),     # os.kill(0, sig) signals the EDR's WHOLE group
    (1, "invalid_pid"),     # systemd
    (-1, "invalid_pid"),    # every process of the user
    (-100, "invalid_pid"),  # an arbitrary process group
])
def test_non_remediable_pids(pid, reason, limiter):
    v = safety.validate_remediation(pid, "kill", limiter=limiter)
    assert not v.allowed
    assert v.reason == reason


def test_a_non_integer_pid_is_rejected(limiter):
    assert not safety.validate_remediation("123", "kill", limiter=limiter).allowed
    assert not safety.validate_remediation(None, "kill", limiter=limiter).allowed


# ── 2. Actions ─────────────────────────────────────────────────

@pytest.mark.parametrize("action", ["nuke", "delete", "", "KILL", "isolate"])
def test_invalid_actions(action, live_process, limiter):
    v = safety.validate_remediation(live_process.pid, action, limiter=limiter)
    assert not v.allowed
    assert v.reason == "invalid_action"


@pytest.mark.parametrize("action", ["freeze", "kill"])
def test_valid_actions(action, live_process, limiter):
    st = procinfo.starttime(live_process.pid)
    v = safety.validate_remediation(live_process.pid, action, st, limiter=limiter)
    assert v.allowed


# ── 3. Self-protection ─────────────────────────────────────────

def test_it_cannot_kill_itself(limiter):
    v = safety.validate_remediation(os.getpid(), "kill", limiter=limiter)
    assert not v.allowed
    assert v.reason == "self_protection"


def test_it_cannot_kill_its_parent(limiter):
    """In production the MCP server is a child of the orchestrator."""
    v = safety.validate_remediation(os.getppid(), "kill", limiter=limiter)
    assert not v.allowed
    assert v.reason == "self_protection"


def test_it_cannot_kill_a_distant_ancestor(limiter):
    chain = procinfo.ancestors(os.getpid())
    # The last ancestor before pid 1, to exercise the whole chain.
    distant = [p for p in chain if p > 1]
    if len(distant) < 2:
        pytest.skip("ancestor chain too short in this environment")

    v = safety.validate_remediation(distant[-1], "kill", limiter=limiter)
    assert not v.allowed
    assert v.reason == "self_protection"


# ── 4 and 5. Kernel threads and protected processes ────────────

def test_it_cannot_kill_a_kernel_thread(fake_proc, limiter, monkeypatch):
    fake_proc(pid=5000, comm="kworker/0:1", kthread=True, starttime=10)
    monkeypatch.setattr(procinfo, "ancestors", lambda pid: [])

    v = safety.validate_remediation(5000, "kill", limiter=limiter)
    assert not v.allowed
    assert v.reason == "kernel_thread"


@pytest.mark.parametrize("comm", ["systemd", "sshd", "dockerd", "init"])
def test_it_cannot_kill_critical_processes(comm, fake_proc, limiter, monkeypatch):
    """Killing sshd during an incident locks you out of the machine you are
    investigating."""
    fake_proc(pid=6000, comm=comm, starttime=10)
    monkeypatch.setattr(procinfo, "ancestors", lambda pid: [])

    v = safety.validate_remediation(6000, "kill", limiter=limiter)
    assert not v.allowed
    assert v.reason == "protected_process"


def test_an_ordinary_process_is_remediable(fake_proc, limiter, monkeypatch):
    fake_proc(pid=6001, comm="curl", starttime=10)
    monkeypatch.setattr(procinfo, "ancestors", lambda pid: [])

    assert safety.validate_remediation(6001, "kill", 10, limiter=limiter).allowed


# ── 6. Pid reuse ───────────────────────────────────────────────

def test_the_right_starttime_allows_remediation(live_process, limiter):
    st = procinfo.starttime(live_process.pid)
    v = safety.validate_remediation(live_process.pid, "kill", st, limiter=limiter)
    assert v.allowed


def test_a_different_starttime_blocks_remediation(live_process, limiter):
    """The heart of the phase: the pid matches but it is no longer the same
    process."""
    st = procinfo.starttime(live_process.pid)
    v = safety.validate_remediation(live_process.pid, "kill", st + 1, limiter=limiter)

    assert not v.allowed
    assert v.reason == "pid_reused"


def test_a_nonexistent_process(limiter):
    v = safety.validate_remediation(999999, "kill", 123, limiter=limiter)
    assert not v.allowed
    assert v.reason == "no_such_process"


def test_without_identity_there_is_no_remediation(live_process, limiter):
    """Half an identity check is worth nothing, so it fails closed.

    Found in the phase 1 verification: 100 % of module-load events arrived
    without a starttime, because modprobe dies before the userspace callback can
    read its /proc. Skipping the check in that case left open exactly the door
    the check exists to close.
    """
    v = safety.validate_remediation(live_process.pid, "kill", None, limiter=limiter)

    assert not v.allowed
    assert v.reason == "identity_unknown"


def test_without_identity_autonomous_mode_does_not_act_either(live_process, limiter,
                                                              never_signals):
    sent, fn = never_signals
    r = safety.remediate(live_process.pid, "kill", None,
                         mode=config.MODE_AUTONOMOUS, signal_fn=fn, limiter=limiter)

    assert r["outcome"] == "denied"
    assert sent == []
    assert live_process.poll() is None


# ── 7. Rate limit ──────────────────────────────────────────────

def test_the_rate_limit_cuts_a_hallucination_loop(fake_proc, limiter, monkeypatch):
    fake_proc(pid=7000, comm="curl", starttime=10)
    monkeypatch.setattr(procinfo, "ancestors", lambda pid: [])

    for _ in range(3):
        assert safety.validate_remediation(7000, "kill", 10, limiter=limiter).allowed
        limiter.record()

    v = safety.validate_remediation(7000, "kill", 10, limiter=limiter)
    assert not v.allowed
    assert v.reason == "rate_limited"


def test_the_limit_is_released_once_the_window_passes(fake_proc, limiter, monkeypatch):
    fake_proc(pid=7001, comm="curl", starttime=10)
    monkeypatch.setattr(procinfo, "ancestors", lambda pid: [])

    for _ in range(3):
        limiter.record()
    assert not safety.validate_remediation(7001, "kill", 10, limiter=limiter).allowed

    limiter.clock["t"] += 301  # the window is 300 s
    assert safety.validate_remediation(7001, "kill", 10, limiter=limiter).allowed


def test_an_invalid_proposal_does_not_consume_budget(limiter):
    """The limit is checked last on purpose: a rejection must not spend quota."""
    for _ in range(10):
        safety.validate_remediation(1, "kill", limiter=limiter)
    assert limiter.would_allow()


# ── Operating modes ────────────────────────────────────────────

def test_dry_run_sends_no_signal(live_process, limiter, never_signals):
    sent, fn = never_signals
    st = procinfo.starttime(live_process.pid)

    r = safety.remediate(live_process.pid, "kill", st,
                         mode=config.MODE_DRY_RUN, signal_fn=fn, limiter=limiter)

    assert r["outcome"] == "dry_run"
    assert sent == []
    assert live_process.poll() is None, "the process should still be alive"


def test_autonomous_does_send_the_signal(live_process, limiter, never_signals):
    sent, fn = never_signals
    st = procinfo.starttime(live_process.pid)

    r = safety.remediate(live_process.pid, "kill", st,
                         mode=config.MODE_AUTONOMOUS, signal_fn=fn, limiter=limiter)

    assert r["outcome"] == "executed"
    assert sent == [(live_process.pid, 9)]


def test_freeze_sends_sigstop(live_process, limiter, never_signals):
    sent, fn = never_signals
    st = procinfo.starttime(live_process.pid)

    safety.remediate(live_process.pid, "freeze", st,
                     mode=config.MODE_AUTONOMOUS, signal_fn=fn, limiter=limiter)

    assert sent == [(live_process.pid, 19)]  # SIGSTOP


def test_both_modes_consume_the_same_budget(live_process, limiter, never_signals):
    """So that dry-run metrics stay comparable with autonomous ones."""
    _, fn = never_signals
    st = procinfo.starttime(live_process.pid)

    for _ in range(3):
        safety.remediate(live_process.pid, "kill", st,
                         mode=config.MODE_DRY_RUN, signal_fn=fn, limiter=limiter)

    r = safety.remediate(live_process.pid, "kill", st,
                         mode=config.MODE_DRY_RUN, signal_fn=fn, limiter=limiter)
    assert r["verdict"] == "rate_limited"


def test_a_denial_sends_no_signal_even_in_autonomous(limiter, never_signals):
    sent, fn = never_signals

    r = safety.remediate(1, "kill", mode=config.MODE_AUTONOMOUS,
                         signal_fn=fn, limiter=limiter)

    assert r["outcome"] == "denied"
    assert sent == []


# ── Audit trail ────────────────────────────────────────────────

def test_denied_attempts_are_recorded(limiter, never_signals):
    """Without this trace there is no way to show the safeguards fired."""
    _, fn = never_signals
    safety.remediate(1, "kill", reason="audit check",
                     mode=config.MODE_AUTONOMOUS, signal_fn=fn, limiter=limiter)

    last = safety.attempts()[-1]
    assert last["allowed"] is False
    assert last["verdict"] == "invalid_pid"
    assert last["reason"] == "audit check"
    assert last["pid"] == 1


def test_describe_is_readable(limiter, never_signals):
    _, fn = never_signals
    r = safety.remediate(1, "kill", mode=config.MODE_AUTONOMOUS,
                         signal_fn=fn, limiter=limiter)

    text = safety.describe(r)
    assert "BLOCKED" in text
    assert "invalid_pid" in text
