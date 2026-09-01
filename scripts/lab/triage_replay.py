#!/usr/bin/env python3
"""Replay the triage rules over recorded telemetry.

`triage.assess()` is pure, so thousands of real events can be re-scored without
root, without BCC and without starting anything. That gives the false-positive
rate of the deterministic layer over genuine desktop activity — the number that
justifies the hybrid design.

    venv/bin/python3 scripts/lab/triage_replay.py events.jsonl

The severity stored in the event is ignored and recomputed: the point is to
evaluate the CURRENT rule set, including over telemetry captured before a rule
existed.
"""

import argparse
import collections
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from edr import config, triage  # noqa: E402


def load(path):
    """Yield events, skipping unreadable lines.

    A truncated last line is the normal case: the file is appended to by a
    running sensor.
    """
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                print(f"[!] line {n} is not valid JSON, skipped", file=sys.stderr)


def replay(events, threshold):
    stats = {
        "total": 0,
        "by_kind": collections.Counter(),
        "scored": 0,          # execve with severity > 0
        "escalated": 0,       # execve at or above the threshold
        "module_loads": 0,    # always escalated, by design
        "foreign_ns": 0,
        "severities": collections.Counter(),
        "rules": collections.Counter(),
        # What the sample is actually made of. A false-positive rate over
        # thousands of events means little if they are all the same command, so
        # the variety has to be reported alongside the volume.
        "programs": collections.Counter(),
        "escalated_events": [],
        "first_ts": None,
        "last_ts": None,
    }

    for event in events:
        stats["total"] += 1
        kind = event.get("kind")
        stats["by_kind"][kind] += 1

        ts = event.get("ts")
        if ts:
            if stats["first_ts"] is None or ts < stats["first_ts"]:
                stats["first_ts"] = ts
            if stats["last_ts"] is None or ts > stats["last_ts"]:
                stats["last_ts"] = ts

        if event.get("foreign_ns"):
            stats["foreign_ns"] += 1

        if kind == config.KIND_MODULE_LOAD:
            stats["module_loads"] += 1
            continue
        if kind != config.KIND_EXECVE:
            continue

        program = os.path.basename(event.get("filename") or "") or "(sin nombre)"
        stats["programs"][program] += 1

        severity, rules = triage.assess(event)
        if severity > 0:
            stats["scored"] += 1
            stats["severities"][severity] += 1
            for rule in rules:
                stats["rules"][rule] += 1

        if severity >= threshold:
            stats["escalated"] += 1
            stats["escalated_events"].append({
                "seq": event.get("seq"),
                "ts": ts,
                "pid": event.get("pid"),
                "severity": severity,
                "rules_fired": ",".join(rules),
                "filename": event.get("filename"),
                "cmdline": (event.get("cmdline") or "")[:120],
            })

    return stats


def pct(n, total):
    """Percentage with a Spanish decimal comma: the tables go into the thesis."""
    value = (100.0 * n / total) if total else 0.0
    return f"{value:.2f}".replace(".", ",")


def report(stats, threshold, path):
    execve = stats["by_kind"].get(config.KIND_EXECVE, 0)
    lines = []
    add = lines.append

    add(f"# Reproducción del triaje sobre `{path}`\n")
    add(f"Umbral de escalado: **{threshold}** "
        f"(`EDR_TRIAGE_THRESHOLD`)\n")
    if stats["first_ts"]:
        add(f"Ventana temporal: {stats['first_ts']} → {stats['last_ts']}\n")

    add("\n## Volumen\n")
    add("| Métrica | Valor | % del total |")
    add("|---|---:|---:|")
    add(f"| Eventos totales | {stats['total']} | 100,00 % |")
    for kind, n in stats["by_kind"].most_common():
        add(f"| — de tipo `{kind}` | {n} | {pct(n, stats['total'])} % |")
    add(f"| Desde otro namespace de PID (nunca escalan) | {stats['foreign_ns']} "
        f"| {pct(stats['foreign_ns'], stats['total'])} % |")

    add("\n## Capa determinista sobre `execve`\n")
    add("| Métrica | Valor | % de los execve |")
    add("|---|---:|---:|")
    add(f"| Evaluados | {execve} | 100,00 % |")
    add(f"| Con alguna regla activada (severidad > 0) | {stats['scored']} "
        f"| {pct(stats['scored'], execve)} % |")
    add(f"| **Escalados al modelo (severidad ≥ {threshold})** | **{stats['escalated']}** "
        f"| **{pct(stats['escalated'], execve)} %** |")
    add(f"| Descartados sin consultar al modelo | {execve - stats['escalated']} "
        f"| {pct(execve - stats['escalated'], execve)} % |")

    add("\n## Composición de la muestra\n")
    distinct = len(stats["programs"])
    add(f"{distinct} programas distintos entre los {execve} `execve` evaluados. "
        f"Los quince más frecuentes:\n")
    add("| Programa | Ejecuciones | % de los execve |")
    add("|---|---:|---:|")
    for program, n in stats["programs"].most_common(15):
        add(f"| `{program}` | {n} | {pct(n, execve)} % |")

    add("\n## Distribución de severidades (solo execve con severidad > 0)\n")
    if stats["severities"]:
        add("| Severidad | Eventos | ¿Escala? |")
        add("|---:|---:|---|")
        for severity, n in sorted(stats["severities"].items()):
            add(f"| {severity} | {n} | {'sí' if severity >= threshold else 'no'} |")
    else:
        add("_Ninguna regla se activó._")

    add("\n## Reglas activadas\n")
    if stats["rules"]:
        add("| Regla | Peso | Veces |")
        add("|---|---:|---:|")
        for rule, n in stats["rules"].most_common():
            add(f"| `{rule}` | {triage.WEIGHTS.get(rule, '?')} | {n} |")
    else:
        add("_Ninguna._")

    add("\n## Eventos escalados\n")
    if stats["escalated_events"]:
        add("| seq | pid | sev | reglas | fichero |")
        add("|---:|---:|---:|---|---|")
        for e in stats["escalated_events"]:
            add(f"| {e['seq']} | {e['pid']} | {e['severity']} "
                f"| `{e['rules_fired']}` | `{e['filename']}` |")
    else:
        add("_Ninguno._")

    add(f"\n## Nota sobre `module_load`\n")
    add(f"{stats['module_loads']} cargas de módulo. Escalan **siempre**, sin pasar por el "
        f"triaje: son intrínsecamente privilegiadas y raras. Es la fuente conocida de falsos "
        f"positivos del sistema y se mide aparte por eso.\n")

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("jsonl", nargs="?", default=str(config.EVENTS_JSONL),
                    help="fichero de eventos (por defecto el del sistema)")
    ap.add_argument("--threshold", type=int, default=config.TRIAGE_THRESHOLD)
    ap.add_argument("--out", help="escribir el informe Markdown a un fichero")
    ap.add_argument("--json", dest="json_out", help="volcar las estadísticas crudas")
    args = ap.parse_args()

    path = Path(args.jsonl)
    if not path.exists():
        sys.exit(f"[!] {path} does not exist")

    stats = replay(load(path), args.threshold)
    text = report(stats, args.threshold, path.name)

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"[+] informe escrito en {args.out}")
    else:
        print(text)

    if args.json_out:
        payload = dict(stats)
        payload["by_kind"] = dict(stats["by_kind"])
        payload["severities"] = {str(k): v for k, v in stats["severities"].items()}
        payload["rules"] = dict(stats["rules"])
        payload["programs"] = dict(stats["programs"])
        payload["generated_at"] = datetime.now().isoformat(timespec="seconds")
        Path(args.json_out).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[+] estadísticas en {args.json_out}")


if __name__ == "__main__":
    main()
