#!/usr/bin/env python3
"""Synthetic workload: what an ordinary Linux host does when nobody is watching.

The false-positive rate of the triage only means something if it is measured
over activity that resembles the activity the system is meant to run on. A
development workstation does not supply that on its own: left alone it produces
an editor polling version control and almost nothing else, so a rate measured
there says more about that editor than about the rule set.

This generator exists for two reasons, and both are worth stating plainly
because the thesis reports the number it produces.

**It is reproducible.** Objective O5 asks for results a third party could
repeat, and a human working for three hours is not repeatable by anyone,
including the same human. A seeded generator is.

**It is closer to the target.** The system is aimed at servers, containers and
cloud workloads, which spend their time on periodic administration: monitoring,
package queries, log handling, scheduled jobs, container inspection. That is
what this reproduces.

What it is NOT: a claim that real hosts execute exactly these commands in
exactly these proportions. It is a documented stand-in, and the thesis says so.

    venv/bin/python3 scripts/lab/workload.py --minutes 20
    venv/bin/python3 scripts/lab/workload.py --minutes 5 --seed 7 --no-borderline
    venv/bin/python3 scripts/lab/workload.py --list

Needs no root, installs nothing, writes only inside its own scratch directory
and removes it on the way out.
"""

import argparse
import collections
import json
import random
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]


# ──────────────────────────────────────────────
# The catalogue
# ──────────────────────────────────────────────

# `weight` is how often a task is picked relative to the others, chosen so the
# mix looks like a host under light administrative load rather than a uniform
# sweep: monitoring runs constantly, package queries occasionally, archiving
# rarely.
#
# Every command here is benign AND is meant to score zero. The ones that
# deliberately approach a rule without crossing it live in BORDERLINE below.
TASKS = [
    # ── Monitoring: the bread and butter of any agent or cron job ──
    {"name": "process list", "category": "monitoring", "weight": 10,
     "cmd": "ps aux --sort=-%mem | head -15"},
    {"name": "process tree", "category": "monitoring", "weight": 5,
     "cmd": "ps -eo pid,ppid,comm --no-headers | sort -n | head -20"},
    {"name": "memory", "category": "monitoring", "weight": 8,
     "cmd": "free -m; cat /proc/meminfo | head -5"},
    {"name": "disk usage", "category": "monitoring", "weight": 6,
     "cmd": "df -h; (du -sh /var/log 2>/dev/null || true)"},
    {"name": "load and uptime", "category": "monitoring", "weight": 8,
     "cmd": "uptime; cat /proc/loadavg; vmstat 1 2 | tail -1"},
    {"name": "open sockets", "category": "monitoring", "weight": 6,
     "cmd": "ss -tuln | head -10; ss -s | head -3"},
    {"name": "who is logged in", "category": "monitoring", "weight": 3,
     "cmd": "who; users; id; (last -n 3 2>/dev/null || true)"},
    {"name": "kernel modules", "category": "monitoring", "weight": 4,
     "cmd": "lsmod | head -10; lsmod | wc -l"},
    {"name": "interfaces", "category": "monitoring", "weight": 4,
     "cmd": "ip -brief addr; ip route | head -3"},

    # ── Package management: what unattended-upgrades and inventory do ──
    {"name": "package inventory", "category": "packages", "weight": 5,
     "cmd": "dpkg-query -W -f='${Package} ${Version}\\n' | head -20; dpkg -l | wc -l"},
    {"name": "package policy", "category": "packages", "weight": 3,
     "cmd": "apt-cache policy python3 bash coreutils | head -12"},
    {"name": "package contents", "category": "packages", "weight": 2,
     "cmd": "dpkg -L coreutils | head -15"},

    # ── Version control: the CI polling pattern ──
    {"name": "repo status", "category": "vcs", "weight": 6,
     "cmd": "git status --short; git rev-parse --abbrev-ref HEAD"},
    {"name": "repo history", "category": "vcs", "weight": 4,
     "cmd": "git log --oneline -10; git count-objects -v | head -3"},
    {"name": "repo diff", "category": "vcs", "weight": 3,
     "cmd": "git diff --stat; git ls-files | wc -l"},

    # ── Containers ──
    {"name": "container list", "category": "containers", "weight": 5,
     "cmd": "docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null || echo 'no docker'"},
    {"name": "container images", "category": "containers", "weight": 2,
     "cmd": "docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | head -5 "
            "|| echo 'no docker'"},

    # ── Log handling: find, compress, rotate, count ──
    {"name": "log sweep", "category": "logs", "weight": 5,
     "cmd": "find /var/log -type f -name '*.log' 2>/dev/null | head -10 | wc -l"},
    {"name": "log rotation", "category": "logs", "weight": 3,
     "cmd": "cd {work} && seq 1 500 > app.log && gzip -k app.log && "
            "tar czf logs.tar.gz app.log.gz && ls -la logs.tar.gz && "
            "rm -f app.log app.log.gz logs.tar.gz"},
    {"name": "log analysis", "category": "logs", "weight": 4,
     "cmd": "cd {work} && seq 1 300 > access.log && "
            "grep -c '1' access.log && awk '{s+=$1} END {print s}' access.log && "
            "sort -rn access.log | head -3 && uniq access.log | wc -l && "
            "cut -c1-2 access.log | tail -3 && rm -f access.log"},

    # ── Scheduled maintenance ──
    {"name": "temp cleanup scan", "category": "maintenance", "weight": 3,
     "cmd": "find /tmp -maxdepth 1 -type f -mmin +60 2>/dev/null | wc -l; "
            "ls -la /tmp | head -5"},
    {"name": "checksum audit", "category": "maintenance", "weight": 3,
     "cmd": "cd {work} && seq 1 100 > data.bin && md5sum data.bin && "
            "sha256sum data.bin && cksum data.bin && rm -f data.bin"},
    {"name": "backup rehearsal", "category": "maintenance", "weight": 2,
     "cmd": "cd {work} && mkdir -p src && seq 1 50 > src/a.txt && seq 1 50 > src/b.txt && "
            "tar cf backup.tar src && ls -la backup.tar && tar tf backup.tar | wc -l && "
            "rm -rf src backup.tar"},

    # ── Build and test: what a CI runner does ──
    {"name": "test suite", "category": "build", "weight": 2,
     "cmd": "cd {repo} && venv/bin/python3 -m pytest -q --no-header 2>&1 | tail -2"},
    {"name": "syntax check", "category": "build", "weight": 3,
     "cmd": "cd {repo} && venv/bin/python3 -m py_compile edr/triage.py edr/safety.py "
            "&& echo compiled"},
    {"name": "dependency audit", "category": "build", "weight": 3,
     "cmd": "cd {repo} && venv/bin/pip list 2>/dev/null | head -12 && venv/bin/pip check"},
    {"name": "code metrics", "category": "build", "weight": 3,
     "cmd": "cd {repo} && find . -name '*.py' -not -path './venv/*' | wc -l && "
            "grep -rc 'def ' edr/*.py | head -5"},
]


# Legitimate activity that lands close to a rule without crossing the threshold.
# This is the part that actually exercises the calibration: a sample where
# nothing ever scores above zero cannot distinguish a well-tuned rule set from
# one that never fires.
BORDERLINE = [
    # Installers do exactly this: unpack into a world-writable directory and run
    # from there. Scores 40 on exec_from_world_writable, one step below the
    # threshold of 50, which is the boundary the weights were calibrated on.
    {"name": "installer from /tmp", "category": "borderline", "weight": 3,
     "cmd": "printf '#!/bin/sh\\necho setup done\\n' > /tmp/edr-wl-setup.sh && "
            "chmod +x /tmp/edr-wl-setup.sh && /tmp/edr-wl-setup.sh && "
            "rm -f /tmp/edr-wl-setup.sh",
     "note": "expected severity 40, must NOT escalate"},

    # A download to a domain name, not a literal address: download_from_public_ip
    # requires a routable literal, so this must score zero. It is the rule's
    # exclusion working on real traffic.
    {"name": "fetch over https", "category": "borderline", "weight": 2,
     "cmd": "curl -s --max-time 5 -o /dev/null -w '%{http_code}\\n' "
            "https://deb.debian.org/debian/dists/stable/Release || echo offline",
     "note": "domain, not literal IP: expected severity 0"},

    # A pipe into an interpreter that is not a shell. pipe_to_shell matches sh,
    # bash, zsh, ksh, dash and ash only, so feeding awk or python must not fire.
    {"name": "pipe into awk", "category": "borderline", "weight": 3,
     "cmd": "cd {work} && seq 1 200 > f.txt && cat f.txt | awk '{n++} END {print n}' && "
            "cat f.txt | python3 -c 'import sys; print(len(sys.stdin.readlines()))' && "
            "rm -f f.txt",
     "note": "interpreter but not a shell: expected severity 0"},

    # Requests to the model itself, over loopback. is_global excludes 127.0.0.0/8,
    # which is what stops the system alerting on its own traffic.
    {"name": "local model query", "category": "borderline", "weight": 2,
     "cmd": "curl -s --max-time 5 http://127.0.0.1:11434/api/tags -o /dev/null "
            "-w '%{http_code}\\n' || echo offline",
     "note": "loopback literal: expected severity 0"},
]


# ──────────────────────────────────────────────
# Execution
# ──────────────────────────────────────────────

def run_task(task, work_dir, timeout=60):
    """Run one task through a shell and report whether it succeeded.

    Through a shell on purpose, and not with a bare argv: a scheduled job on a
    real host is `sh -c "..."`, and that is the shape the sensor records in the
    command line. Running the binaries directly would produce cleaner telemetry
    than any real machine ever emits.

    Placeholders are substituted rather than formatted, because these commands
    are full of literal braces — `${Package}`, `%{http_code}`, Docker's
    `{{.Names}}` — and str.format would either eat them or raise.
    """
    cmd = (task["cmd"]
           .replace("{work}", str(work_dir))
           .replace("{repo}", str(BASE_DIR)))
    try:
        proc = subprocess.run(cmd, shell=True, executable="/bin/bash",
                              capture_output=True, text=True, timeout=timeout)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except OSError:
        return False


def pick(tasks, rng):
    """Weighted choice, so the mix stays lopsided the way a real host is."""
    total = sum(t["weight"] for t in tasks)
    r = rng.uniform(0, total)
    upto = 0
    for t in tasks:
        upto += t["weight"]
        if upto >= r:
            return t
    return tasks[-1]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--minutes", type=float, default=15,
                    help="duración de la generación")
    ap.add_argument("--seed", type=int, default=1,
                    help="semilla, para que la mezcla sea reproducible")
    ap.add_argument("--min-gap", type=float, default=0.4,
                    help="pausa mínima entre tareas, en segundos")
    ap.add_argument("--max-gap", type=float, default=2.5,
                    help="pausa máxima entre tareas, en segundos")
    ap.add_argument("--no-borderline", action="store_true",
                    help="omitir los casos límite legítimos")
    ap.add_argument("--list", action="store_true",
                    help="listar el catálogo y salir")
    ap.add_argument("--json", dest="json_out", help="volcar el resumen")
    args = ap.parse_args()

    catalogue = TASKS + ([] if args.no_borderline else BORDERLINE)

    if args.list:
        for t in catalogue:
            note = f"  ({t['note']})" if t.get("note") else ""
            print(f"[{t['category']:11s}] w={t['weight']:2d}  {t['name']}{note}")
        return

    rng = random.Random(args.seed)
    work_dir = Path(tempfile.mkdtemp(prefix="edr-workload-", dir=Path.home()))

    # Under $HOME rather than /tmp on purpose: /tmp is world-writable, and
    # anything executed from there scores 40. The scratch directory must not
    # accidentally become a finding of its own — the only task that runs from
    # /tmp is the borderline one, and it does so deliberately.

    counts = collections.Counter()
    failures = collections.Counter()
    deadline = time.monotonic() + args.minutes * 60
    executed = 0

    print(f"[*] carga sintética: {args.minutes} min, semilla {args.seed}, "
          f"{len(catalogue)} tareas en el catálogo")
    print(f"[*] directorio de trabajo: {work_dir}")

    try:
        while time.monotonic() < deadline:
            task = pick(catalogue, rng)
            ok = run_task(task, work_dir)
            counts[task["category"]] += 1
            executed += 1
            if not ok:
                failures[task["name"]] += 1
            if executed % 25 == 0:
                remaining = max(0, deadline - time.monotonic())
                print(f"    {executed} tareas, quedan {remaining/60:.1f} min",
                      flush=True)
            time.sleep(rng.uniform(args.min_gap, args.max_gap))
    except KeyboardInterrupt:
        print("\n[!] interrumpido")
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    print(f"\n[+] {executed} tareas ejecutadas")
    for category, n in counts.most_common():
        print(f"      {category:12s} {n:4d}  ({n/executed*100:.1f} %)")
    if failures:
        # Not an error: docker may be absent, the network may be down, a tool may
        # not be installed. Reported because a task that ended badly may have
        # contributed less telemetry than the catalogue suggests.
        print("\n[!] tareas terminadas con error (telemetría posiblemente parcial):")
        for name, n in failures.most_common():
            print(f"      {name}: {n}")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps({
            "minutes": args.minutes,
            "seed": args.seed,
            "executed": executed,
            "by_category": dict(counts),
            "failures": dict(failures),
            "catalogue_size": len(catalogue),
            "borderline_included": not args.no_borderline,
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n[+] resumen en {args.json_out}")


if __name__ == "__main__":
    main()
