#!/usr/bin/env python3
"""Exercise every safeguard in edr/safety.py and report the result of each.

The safeguards cannot be driven reliably end-to-end, because whether one fires
depends on what the model chooses to propose. So they are attacked directly:
each of the nine checks is provoked with a purpose-built input against a REAL
process, and the resulting `reason` slug is recorded.

    sudo venv/bin/python3 scripts/lab/safeguards_matrix.py

Root is needed only so `no_such_process` can be provoked with a process the
script itself spawned and reaped. `kernel_thread` can only be provoked where a
real kernel thread exists — absent on WSL2, present in the lab VM — so it is
reported as `skipped` on a host that has none.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from edr import config, procinfo, safety  # noqa: E402


def a_dead_pid():
    """A pid that is guaranteed not to exist: spawn a process and reap it."""
    p = subprocess.Popen(["true"])
    p.wait()
    time.sleep(0.05)
    return p.pid


def a_live_process():
    """A real, long-lived process we own, with its captured starttime."""
    p = subprocess.Popen(["sleep", "30"])
    time.sleep(0.1)
    st = procinfo.starttime(p.pid)
    return p, st


def find_kernel_thread():
    """A real kernel thread's pid, or None if the host exposes none (WSL2)."""
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if procinfo.is_kernel_thread(pid):
            return pid
    return None


def find_protected():
    """The pid of a process on the protected list (systemd is pid 1's comm)."""
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        stat = procinfo.read_stat(pid)
        if stat and stat["comm"] in config.PROTECTED_COMMS and pid > 1:
            return pid, stat["comm"]
    return None, None


def run():
    """Provoke each safeguard. Returns a list of result rows."""
    rows = []

    def record(check, expected, pid, action, expected_starttime, note="",
               limiter=None):
        verdict = safety.validate_remediation(
            pid, action, expected_starttime, limiter=limiter)
        ok = verdict.reason == expected
        rows.append({
            "check": check,
            "expected": expected,
            "observed": verdict.reason,
            "pass": ok,
            "pid": pid,
            "detail": verdict.detail,
            "note": note,
        })
        return verdict

    # 1. invalid_pid — pid <= 1 signals the EDR's own process group / systemd.
    record("invalid_pid", "invalid_pid", 0, "kill", 12345)
    record("invalid_pid (negative)", "invalid_pid", -1, "kill", 12345)

    # 2. invalid_action — anything outside freeze/kill.
    live, live_st = a_live_process()
    try:
        record("invalid_action", "invalid_action", live.pid, "reboot", live_st)

        # 4. self_protection — the script's own pid and its parent.
        record("self_protection (self)", "self_protection", os.getpid(), "kill", 1)
        record("self_protection (parent)", "self_protection", os.getppid(), "kill", 1)

        # 6. protected_process — a real systemd/sshd/etc.
        prot_pid, prot_comm = find_protected()
        if prot_pid:
            record("protected_process", "protected_process", prot_pid, "kill",
                   procinfo.starttime(prot_pid), note=f"comm={prot_comm}")
        else:
            rows.append({"check": "protected_process", "expected": "protected_process",
                         "observed": "skipped", "pass": None, "pid": None,
                         "detail": "no protected process found", "note": ""})

        # 5. kernel_thread — only where one exists.
        kpid = find_kernel_thread()
        if kpid:
            record("kernel_thread", "kernel_thread", kpid, "kill",
                   procinfo.starttime(kpid), note=f"pid={kpid}")
        else:
            rows.append({"check": "kernel_thread", "expected": "kernel_thread",
                         "observed": "skipped", "pass": None, "pid": None,
                         "detail": "WSL2 exposes no kernel threads; run in the VM",
                         "note": "host has no kthreads"})

        # 7. identity_unknown — a live, remediable process but no starttime.
        record("identity_unknown", "identity_unknown", live.pid, "freeze", None)

        # 8. pid_reused — right pid, wrong (shifted) starttime.
        record("pid_reused", "pid_reused", live.pid, "freeze", live_st + 1,
               note="starttime deliberately shifted")

        # 3. no_such_process — a reaped pid.
        record("no_such_process", "no_such_process", a_dead_pid(), "kill", 99999)

        # 9. rate_limited — checked last, so a fresh limiter must be filled with
        #    approved remediations first. A private limiter keeps the process-wide
        #    one untouched.
        limiter = safety.RateLimiter(max_n=config.RATE_LIMIT_MAX,
                                     window_s=config.RATE_LIMIT_WINDOW_S)
        for _ in range(config.RATE_LIMIT_MAX):
            v = safety.validate_remediation(live.pid, "freeze", live_st, limiter=limiter)
            assert v.allowed, f"setup for rate_limited failed: {v}"
            limiter.record()
        record("rate_limited", "rate_limited", live.pid, "freeze", live_st,
               note=f"{config.RATE_LIMIT_MAX} prior approvals", limiter=limiter)

        # The happy path, for contrast: a valid remediation is allowed.
        v = safety.validate_remediation(live.pid, "freeze", live_st)
        rows.append({"check": "ok (control)", "expected": "ok", "observed": v.reason,
                     "pass": v.reason == "ok", "pid": live.pid, "detail": v.detail,
                     "note": "valid remediation must pass"})
    finally:
        live.terminate()
        live.wait()

    return rows


def report(rows):
    lines = ["# Matriz de salvaguardas\n",
             "Cada salvaguarda provocada directamente con una entrada real.\n",
             "| Comprobación | slug esperado | slug observado | ¿OK? | pid | nota |",
             "|---|---|---|:---:|---:|---|"]
    for r in rows:
        mark = {True: "✅", False: "❌", None: "—"}[r["pass"]]
        pid = r["pid"] if r["pid"] is not None else ""
        lines.append(f"| {r['check']} | `{r['expected']}` | `{r['observed']}` "
                     f"| {mark} | {pid} | {r['note']} |")

    tested = [r for r in rows if r["pass"] is not None]
    passed = [r for r in tested if r["pass"]]
    skipped = [r for r in rows if r["pass"] is None]
    lines.append(f"\n**{len(passed)}/{len(tested)}** comprobaciones correctas"
                 + (f", {len(skipped)} omitidas (requieren la VM)." if skipped else "."))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", help="escribir el informe Markdown a un fichero")
    ap.add_argument("--json", dest="json_out", help="volcar las filas crudas")
    args = ap.parse_args()

    rows = run()
    text = report(rows)

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"[+] informe escrito en {args.out}")
    else:
        print(text)

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")

    failed = [r for r in rows if r["pass"] is False]
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
