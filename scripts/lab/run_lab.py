#!/usr/bin/env python3
"""Run the scenario catalogue and collect metrics.

One orchestrator process per (scenario, repetition), each with `--once`, so every
execution is an independent experiment: the in-memory rate-limit budget resets,
and repetitions of a mitigation scenario do not poison each other with
`rate_limited`.

    sudo venv/bin/python3 scripts/lab/run_lab.py                       # everything, 5x
    sudo venv/bin/python3 scripts/lab/run_lab.py --scenarios hidden_tmp_binary --repeat 1
    sudo EDR_MODEL=qwen2.5:7b venv/bin/python3 scripts/lab/run_lab.py  # a second model

Results land in results/<run_id>/:
    detections.jsonl  — journalled by db.py, the authoritative decision + metrics
    runs.jsonl        — one line per (scenario, rep): expected vs. observed, timings
    <slug>.<rep>.log  — the orchestrator console for that execution

Needs root (eBPF and /proc) and a reachable Ollama. It is unattended: a full 5x
campaign over 11 scenarios takes a while but needs no supervision.
"""

import argparse
import datetime as dt
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import scenarios  # noqa: E402
from edr import config  # noqa: E402

BASE_DIR = Path(__file__).resolve().parents[2]
ORCHESTRATOR = BASE_DIR / "orchestrator.py"

CONNECT_MARKER = "Connected to the MCP forensic server"


def make_run_id(model):
    host = socket.gethostname()
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_model = model.replace(":", "_").replace("/", "_")
    return f"{stamp}-{safe_model}-{host}"


def wait_for_marker(proc, log_fh, marker, timeout):
    """Block until the child prints `marker`, tee-ing its output to the log.

    Returns True if seen, False on timeout or early exit. The child's stdout is
    line-buffered (it calls reconfigure), so this does not deadlock.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if line == "" and proc.poll() is not None:
            return False
        if line:
            log_fh.write(line)
            log_fh.flush()
            if marker in line:
                return True
    return False


def drain(proc, log_fh, timeout):
    """Read the child to completion (or timeout), tee-ing to the log."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if line == "" and proc.poll() is not None:
            return True
        if line:
            log_fh.write(line)
            log_fh.flush()
    return False


def read_journal(path):
    """Merge journal lines into id -> detection, applying updates in order.

    The record's timestamp sits outside its payload, so it has to be copied in
    under reserved names. Without it there is no way to say when the verdict was
    reached, and every time_to_verdict_s comes out as zero.

    `_ts_first` is when the system first reacted, `_ts_last` when it settled on
    a final verdict. They differ whenever a round of investigation happened.
    """
    if not path.exists():
        return {}
    merged = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        payload = rec.get("payload", {})
        det_id = payload.get("id")
        if det_id is None:
            continue
        entry = merged.setdefault(det_id, {})
        entry.update({k: v for k, v in payload.items() if v is not None})
        ts = rec.get("ts")
        if ts:
            entry.setdefault("_ts_first", ts)
            entry["_ts_last"] = ts
    return merged


def read_sensor_stats(log_path):
    """Last [sensor-stats] line the orchestrator wrote, as a dict.

    Objective O1 asks the sensor to account for its own coverage and its own
    losses. The orchestrator prints them; this carries them into the summary row
    so the report does not have to reopen every log.
    """
    marker = "[sensor-stats] "
    found = None
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        idx = line.find(marker)
        if idx >= 0:
            found = line[idx + len(marker):].strip()
    if not found:
        return None
    try:
        return json.loads(found)
    except json.JSONDecodeError:
        return None


def proc_stat(pid):
    """The STAT column from ps, or '' if the process is gone."""
    if not pid:
        return ""
    try:
        out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                             capture_output=True, text=True)
        return out.stdout.strip()
    except OSError:
        return ""


def run_scenario(scenario, rep, run_id, model, mode, results_dir, timeout):
    """Run one scenario once. Returns the summary row."""
    slug = scenario["slug"]
    log_path = results_dir / f"{slug}.{rep}.log"
    journal = results_dir / "detections.jsonl"

    env = os.environ.copy()
    env["EDR_RUN_ID"] = run_id
    env["EDR_SCENARIO"] = slug
    env["EDR_MODE"] = mode
    env["EDR_MODEL"] = model
    env["EDR_DEDUP_WINDOW"] = "0"          # no dedup between repetitions
    env["EDR_RESULTS_DIR"] = str(results_dir.parent)

    row = {
        "run_id": run_id, "scenario": slug, "rep": rep, "model": model, "mode": mode,
        "category": scenario["category"], "mitre": scenario.get("mitre"),
        "expect_escalate": scenario["expect_escalate"],
        "expect_verdict": scenario["expect_verdict"],
        "expect_severity": scenario["expect_severity"],
        "long_lived": scenario["long_lived"],
        "needs_attacker": scenario["needs_attacker"],
        "injection_guard": scenario.get("injection_guard", False),
    }

    ids_before = set(read_journal(journal))

    with open(log_path, "w", encoding="utf-8") as log_fh:
        proc = subprocess.Popen(
            [sys.executable, str(ORCHESTRATOR), "--once"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=env, cwd=str(BASE_DIR))

        if not wait_for_marker(proc, log_fh, CONNECT_MARKER, timeout=60):
            proc.kill()
            row.update(error="orchestrator did not connect", observed_verdict="ERROR")
            return row

        # Fire the scenario. The sensor is already attached; the next 20 s poll
        # will pick it up.
        time.sleep(1.0)
        t_event = time.time()
        # Detached from this terminal, and bounded in time. The reverse-shell
        # scenarios leave an interactive bash running in the background; if it
        # inherits this terminal it competes for control of it and the harness
        # blocks here forever, since this was the one call of the three without
        # a timeout to rescue it.
        try:
            subprocess.run(scenario["cmd"], shell=True, executable="/bin/bash",
                           env=env, cwd=str(BASE_DIR),
                           stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,
                           start_new_session=True,
                           timeout=30)
        except subprocess.TimeoutExpired:
            row["scenario_cmd_timeout"] = True

        finished = drain(proc, log_fh, timeout=timeout)
        if not finished:
            proc.send_signal(signal.SIGINT)
            drain(proc, log_fh, timeout=10)
            proc.kill()
            row["timed_out"] = True

    # Coverage actually achieved and events lost, for objective O1. Absent if
    # the orchestrator died before it could report them, hence the guard.
    stats = read_sensor_stats(log_path)
    if stats:
        row["probes_attached"] = stats.get("probes_attached")
        row["probes_failed"] = stats.get("probes_failed")
        row["ringbuf_dropped"] = stats.get("ringbuf_dropped")
        row["store_dropped"] = stats.get("dropped")
        row["events_captured"] = stats.get("next_seq")

    # Authoritative decision from the journal delta.
    merged = read_journal(journal)
    new = [d for i, d in merged.items() if i not in ids_before]
    detection = new[-1] if new else None

    if detection:
        row.update(
            observed_verdict=detection.get("decision"),
            observed_action=detection.get("action"),
            observed_pid=detection.get("pid"),
            observed_severity=detection.get("severity"),
            rules_fired=detection.get("rules_fired"),
            remediation=detection.get("remediation"),
            latency_ms=detection.get("latency_ms"),
            tokens_in=detection.get("tokens_in"),
            tokens_out=detection.get("tokens_out"),
            detection_ts=detection.get("_ts_last"),
        )
        # Two different questions: how long until the system reacted at all
        # (dominated by the 20 s poll) and how long until it settled on a final
        # verdict (which additionally pays for a round of investigation).
        row["time_to_first_reaction_s"] = round(
            _ts_delta(detection.get("_ts_first"), t_event), 2)
        row["time_to_verdict_s"] = round(
            _ts_delta(detection.get("_ts_last"), t_event), 2)
    else:
        # No detection row = the triage never escalated. Correct for benign.
        row["observed_verdict"] = "NONE"
        row["time_to_verdict_s"] = None

    # Verified on the process the system actually signalled, taken from the
    # journal. An earlier version guessed it with pgrep and matched the wrapper
    # shell instead of the decoy, so the column reported the state of a process
    # nothing had been done to.
    acted_pid = row.get("observed_pid")
    if scenario["long_lived"] and acted_pid:
        row["decoy_pid"] = acted_pid
        row["decoy_stat_after"] = proc_stat(acted_pid)
        row["signal_landed"] = _interpret_stat(row["decoy_stat_after"])

    cleanup = scenario.get("cleanup")
    if cleanup:
        subprocess.run(cleanup, shell=True, executable="/bin/bash")

    return row


def _ts_delta(iso_ts, t_event):
    if not iso_ts:
        return 0.0
    try:
        detected = dt.datetime.fromisoformat(iso_ts).timestamp()
        return max(0.0, detected - t_event)
    except (ValueError, TypeError):
        return 0.0


def _interpret_stat(stat):
    """What ps STAT says happened to the decoy."""
    if not stat:
        return "gone"          # killed, or exited on its own
    if "T" in stat:
        return "frozen"        # SIGSTOP landed
    return "alive"             # still running: NOTHING, or a safeguard denied


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scenarios", nargs="*", help="slugs a ejecutar (por defecto todos)")
    ap.add_argument("--repeat", type=int, default=5)
    ap.add_argument("--mode", default=config.EDR_MODE,
                    choices=[config.MODE_DRY_RUN, config.MODE_AUTONOMOUS])
    ap.add_argument("--model", default=config.MODEL)
    ap.add_argument("--timeout", type=int, default=120,
                    help="segundos máximos por ejecución")
    ap.add_argument("--no-attacker", action="store_true",
                    help="omitir escenarios que necesitan la VM atacante")
    ap.add_argument("--run-id", help="reutilizar un run_id (por defecto se genera)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[!] needs root (eBPF and /proc). Run with sudo.")

    chosen = scenarios.select(args.scenarios, include_attacker=not args.no_attacker)
    if not chosen:
        sys.exit("[!] no scenarios selected")

    run_id = args.run_id or make_run_id(args.model)
    results_dir = config.RESULTS_DIR / run_id
    results_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "run_id": run_id, "model": args.model, "mode": args.mode,
        "repeat": args.repeat, "host": platform.node(),
        "kernel": platform.release(),
        "threshold": config.TRIAGE_THRESHOLD,
        "scenarios": [s["slug"] for s in chosen],
        "started_at": dt.datetime.now().isoformat(timespec="seconds"),
    }
    (results_dir / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))

    print(f"[*] run_id={run_id}  model={args.model}  mode={args.mode}  "
          f"{len(chosen)} escenarios × {args.repeat}")

    runs_path = results_dir / "runs.jsonl"
    total = len(chosen) * args.repeat
    done = 0
    with open(runs_path, "a", encoding="utf-8") as runs_fh:
        for scenario in chosen:
            for rep in range(1, args.repeat + 1):
                done += 1
                print(f"[{done}/{total}] {scenario['slug']} #{rep} …", flush=True)
                row = run_scenario(scenario, rep, run_id, args.model, args.mode,
                                   results_dir, args.timeout)
                runs_fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                runs_fh.flush()
                verdict = row.get("observed_verdict")
                landed = row.get("signal_landed", "")
                print(f"      → {verdict}"
                      + (f"  decoy:{landed}" if landed else "")
                      + (f"  {row['time_to_verdict_s']}s"
                         if row.get("time_to_verdict_s") is not None else ""))

    print(f"\n[+] hecho. Resultados en {results_dir}")
    print(f"    informe: venv/bin/python3 scripts/lab/lab_report.py --run-id {run_id}")


if __name__ == "__main__":
    main()
