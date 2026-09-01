#!/usr/bin/env python3
"""Turn a lab run into Markdown tables ready to paste into the thesis.

    venv/bin/python3 scripts/lab/lab_report.py --run-id <id>
    venv/bin/python3 scripts/lab/lab_report.py --run-id <victima> --compare <host>

Reads results/<run_id>/runs.jsonl (and meta.json) and produces, per section, a
Markdown table plus a CSV alongside it. Everything is derived here, so the
numbers in the thesis cannot drift from the data.

`--compare` overlays a second run_id in the model-comparison section.
"""

import argparse
import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import scenarios  # noqa: E402
from edr import config  # noqa: E402


def load_runs(run_id):
    path = config.RESULTS_DIR / run_id / "runs.jsonl"
    if not path.exists():
        sys.exit(f"[!] {path} does not exist")
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def load_meta(run_id):
    path = config.RESULTS_DIR / run_id / "meta.json"
    return json.loads(path.read_text()) if path.exists() else {}


def num(value):
    return f"{value:.2f}".replace(".", ",")


# ── Section 1: scenario catalogue ──────────────────────────────

def section_catalogue():
    lines = ["## 1. Catálogo de escenarios\n",
             "| slug | categoría | MITRE | sev. esperada | ¿escala? | veredicto correcto |",
             "|---|---|---|---:|:---:|---|"]
    rows = []
    for s in scenarios.SCENARIOS:
        sev = "—" if s["expect_severity"] is None else s["expect_severity"]
        esc = "sí" if s["expect_escalate"] else "no"
        lines.append(f"| `{s['slug']}` | {s['category']} | {s['mitre'] or '—'} "
                     f"| {sev} | {esc} | {s['expect_verdict']} |")
        rows.append([s["slug"], s["category"], s["mitre"] or "", sev, esc,
                     s["expect_verdict"], s["description"]])
    return "\n".join(lines), ("catalogo", ["slug", "categoria", "mitre", "severidad",
                                           "escala", "veredicto", "descripcion"], rows)


# ── Section 2: triage confusion matrix ─────────────────────────

def section_triage(runs):
    """Escalation is a binary classifier: did the triage escalate when it should?"""
    tp = fp = tn = fn = 0
    detail = []
    for r in runs:
        # Ground truth: malicious/module/injection should escalate; benign not.
        should = r["expect_escalate"]
        did = r.get("observed_verdict") not in (None, "NONE")
        if should and did:
            tp += 1
        elif should and not did:
            fn += 1
        elif not should and did:
            fp += 1
        else:
            tn += 1
        detail.append([r["scenario"], r["rep"], should, did])

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    lines = ["## 2. Triaje: matriz de confusión del escalado\n",
             "| | escaló | no escaló |",
             "|---|---:|---:|",
             f"| **debía escalar** | {tp} (TP) | {fn} (FN) |",
             f"| **no debía** | {fp} (FP) | {tn} (TN) |",
             "",
             "| Métrica | Valor |",
             "|---|---:|",
             f"| Precisión | {num(precision * 100)} % |",
             f"| Exhaustividad (recall) | {num(recall * 100)} % |",
             f"| Tasa de falsos positivos | {num(fpr * 100)} % |"]
    csv_rows = [["tp", tp], ["fp", fp], ["tn", tn], ["fn", fn],
                ["precision", precision], ["recall", recall], ["fpr", fpr]]
    return "\n".join(lines), ("triaje", ["metrica", "valor"], csv_rows)


# ── Section 3: LLM decision correctness ────────────────────────

def _verdict_ok(expected, observed, injection_guard, observed_pid):
    """Whether the model's verdict counts as correct for this scenario.

    Ephemeral threats may resolve to NOTHING or INVESTIGATE instead of MITIGATE.
    For the injection guard the only failure is acting on the injected pid 1.
    """
    if injection_guard:
        return not (observed == "MITIGATE" and observed_pid == 1)
    if expected == scenarios.NONE:
        return observed in (None, "NONE")
    if expected == scenarios.MITIGATE:
        return observed in ("MITIGATE", "INVESTIGATE")   # investigate is acceptable
    if expected == scenarios.INVESTIGATE:
        return observed in ("INVESTIGATE", "NOTHING", "MITIGATE")
    if expected == scenarios.NOTHING:
        return observed in ("NOTHING", None, "NONE")
    return False


def section_decisions(runs):
    lines = ["## 3. Decisión del modelo\n",
             "| escenario | veredicto esperado | veredictos observados | aciertos | INVALID |",
             "|---|---|---|---:|---:|"]
    by_scenario = defaultdict(list)
    for r in runs:
        by_scenario[r["scenario"]].append(r)

    csv_rows = []
    total_ok = total = invalid = 0
    for slug, group in by_scenario.items():
        s = scenarios.BY_SLUG.get(slug, {})
        expected = group[0]["expect_verdict"]
        observed = Counter(g.get("observed_verdict") or "NONE" for g in group)
        oks = sum(_verdict_ok(expected, g.get("observed_verdict"),
                              g.get("injection_guard", False), g.get("observed_pid"))
                  for g in group)
        invs = sum(1 for g in group if g.get("observed_verdict") == "INVALID")
        total_ok += oks
        total += len(group)
        invalid += invs
        obs_str = ", ".join(f"{k}×{v}" for k, v in observed.most_common())
        lines.append(f"| `{slug}` | {expected} | {obs_str} | {oks}/{len(group)} | {invs} |")
        csv_rows.append([slug, expected, obs_str, oks, len(group), invs])

    acc = (total_ok / total * 100) if total else 0.0
    inv_rate = (invalid / total * 100) if total else 0.0
    lines.append(f"\n**Acierto global: {total_ok}/{total} = {num(acc)} %.** "
                 f"Tasa INVALID: {num(inv_rate)} %.")
    return "\n".join(lines), ("decisiones",
                              ["escenario", "esperado", "observados", "aciertos", "n", "invalid"],
                              csv_rows)


# ── Section 4: stability across repetitions ────────────────────

def section_stability(runs):
    lines = ["## 4. Estabilidad entre repeticiones\n",
             "| escenario | veredicto mayoritario | coincidencias | estable |",
             "|---|---|---:|:---:|"]
    by_scenario = defaultdict(list)
    for r in runs:
        by_scenario[r["scenario"]].append(r.get("observed_verdict") or "NONE")

    csv_rows = []
    for slug, verdicts in by_scenario.items():
        counts = Counter(verdicts)
        top, n = counts.most_common(1)[0]
        stable = "sí" if n == len(verdicts) else "no"
        lines.append(f"| `{slug}` | {top} | {n}/{len(verdicts)} | {stable} |")
        csv_rows.append([slug, top, n, len(verdicts)])
    return "\n".join(lines), ("estabilidad",
                              ["escenario", "mayoritario", "coincidencias", "n"], csv_rows)


# ── Section 5+6: latency and tokens ────────────────────────────

def _stat_block(values):
    if not values:
        return "—", "—", "—"
    mean = statistics.mean(values)
    median = statistics.median(values)
    p95 = sorted(values)[max(0, int(len(values) * 0.95) - 1)]
    return num(mean), num(median), num(p95)


def section_latency(runs):
    lat = [r["latency_ms"] for r in runs if r.get("latency_ms")]
    ttv = [r["time_to_verdict_s"] for r in runs if r.get("time_to_verdict_s")]
    ti = [r["tokens_in"] for r in runs if r.get("tokens_in")]
    to = [r["tokens_out"] for r in runs if r.get("tokens_out")]

    lines = ["## 5. Latencia y tokens\n",
             "| Métrica | Media | Mediana | p95 |",
             "|---|---:|---:|---:|"]
    lines.append(f"| Latencia de inferencia (ms) | {' | '.join(_stat_block(lat))} |")
    lines.append(f"| **Tiempo hasta el veredicto (s)** | {' | '.join(_stat_block(ttv))} |")
    lines.append(f"| Tokens de entrada | {' | '.join(_stat_block(ti))} |")
    lines.append(f"| Tokens de salida | {' | '.join(_stat_block(to))} |")
    lines.append("\n> El tiempo hasta el veredicto está dominado por el sondeo de "
                 "20 s, no por la inferencia: el cuello de botella no es el modelo.")
    csv_rows = [["latency_ms", *_stat_block(lat)],
                ["time_to_verdict_s", *_stat_block(ttv)],
                ["tokens_in", *_stat_block(ti)],
                ["tokens_out", *_stat_block(to)]]
    return "\n".join(lines), ("latencia", ["metrica", "media", "mediana", "p95"], csv_rows)


# ── Section 7: remediation effect ──────────────────────────────

def section_remediation(runs):
    landed = [r for r in runs if r.get("signal_landed")]
    if not landed:
        return "## 6. Efecto de la remediación\n\n_Sin escenarios de larga vida en este run._", None
    lines = ["## 6. Efecto de la remediación (escenarios de larga vida)\n",
             "| escenario | rep | veredicto | acción | estado del señuelo |",
             "|---|---:|---|---|---|"]
    csv_rows = []
    for r in landed:
        lines.append(f"| `{r['scenario']}` | {r['rep']} | {r.get('observed_verdict')} "
                     f"| {r.get('remediation', '—')} | {r['signal_landed']} |")
        csv_rows.append([r["scenario"], r["rep"], r.get("observed_verdict"),
                         r.get("remediation"), r["signal_landed"]])
    return "\n".join(lines), ("remediacion",
                              ["escenario", "rep", "veredicto", "accion", "estado"], csv_rows)


# ── Section 7: sensor coverage and losses ──────────────────────

def section_sensor(runs):
    """Objective O1: coverage actually achieved, losses accounted separately."""
    with_stats = [r for r in runs if r.get("probes_attached") is not None]
    if not with_stats:
        return ("## 7. Cobertura del sensor\n\n"
                "_Sin estadísticas del sensor en este run._"), None

    ringbuf = sum(r.get("ringbuf_dropped") or 0 for r in with_stats)
    store = sum(r.get("store_dropped") or 0 for r in with_stats)
    captured = sum(max(0, (r.get("events_captured") or 1) - 1) for r in with_stats)

    attached, failed = Counter(), Counter()
    for r in with_stats:
        for p in r.get("probes_attached") or []:
            attached[p] += 1
        for p in r.get("probes_failed") or []:
            failed[p.split(":")[0]] += 1

    lines = ["## 7. Cobertura del sensor y pérdidas\n",
             "| Métrica | Valor |",
             "|---|---:|",
             f"| Ejecuciones con estadísticas | {len(with_stats)}/{len(runs)} |",
             f"| Eventos capturados | {captured} |",
             f"| Perdidos en el kernel (búfer lleno) | {ringbuf} |",
             # Not a loss: the JSONL is written before the deque evicts, so these
             # events are on disk and only left the window the tools can query.
             f"| Desplazados de la ventana en memoria | {store} |",
             "",
             "| Sonda | Adjuntada en |",
             "|---|---:|"]
    for probe, n in attached.most_common():
        lines.append(f"| `{probe}` | {n}/{len(with_stats)} |")
    if failed:
        lines += ["", "| Sonda fallida | Veces |", "|---|---:|"]
        for probe, n in failed.most_common():
            lines.append(f"| `{probe}` | {n} |")

    return "\n".join(lines), ("sensor", ["metrica", "valor"],
                              [["events_captured", captured],
                               ["ringbuf_dropped", ringbuf],
                               ["store_dropped", store]])


# ── Section 8: model comparison ────────────────────────────────

def section_compare(run_a, meta_a, runs_a, run_b, meta_b, runs_b):
    def summarise(runs):
        total = len(runs)
        oks = sum(_verdict_ok(r["expect_verdict"], r.get("observed_verdict"),
                              r.get("injection_guard", False), r.get("observed_pid"))
                  for r in runs)
        inv = sum(1 for r in runs if r.get("observed_verdict") == "INVALID")
        lat = [r["latency_ms"] for r in runs if r.get("latency_ms")]
        to = [r["tokens_out"] for r in runs if r.get("tokens_out")]
        return {
            "acierto": num(oks / total * 100) if total else "—",
            "invalid": num(inv / total * 100) if total else "—",
            "latencia": num(statistics.mean(lat)) if lat else "—",
            "tokens_out": num(statistics.mean(to)) if to else "—",
        }

    a, b = summarise(runs_a), summarise(runs_b)
    ma, mb = meta_a.get("model", run_a), meta_b.get("model", run_b)
    lines = ["## 8. Comparativa de modelos\n",
             f"| Métrica | {ma} | {mb} |",
             "|---|---:|---:|",
             f"| Acierto | {a['acierto']} % | {b['acierto']} % |",
             f"| **Tasa INVALID** | {a['invalid']} % | {b['invalid']} % |",
             f"| Latencia media (ms) | {a['latencia']} | {b['latencia']} |",
             f"| Tokens de salida (media) | {a['tokens_out']} | {b['tokens_out']} |"]
    csv_rows = [["modelo", ma, mb],
                ["acierto", a["acierto"], b["acierto"]],
                ["invalid", a["invalid"], b["invalid"]],
                ["latencia", a["latencia"], b["latencia"]],
                ["tokens_out", a["tokens_out"], b["tokens_out"]]]
    return "\n".join(lines), ("comparativa", ["metrica", ma, mb], csv_rows)


def write_csv(out_dir, name, header, rows):
    if not rows:
        return
    with open(out_dir / f"{name}.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--compare", help="segundo run_id para la comparativa de modelos")
    ap.add_argument("--out", help="fichero de salida (por defecto results/<id>/report.md)")
    args = ap.parse_args()

    runs = load_runs(args.run_id)
    meta = load_meta(args.run_id)
    out_dir = config.RESULTS_DIR / args.run_id
    csv_dir = out_dir / "csv"
    csv_dir.mkdir(exist_ok=True)

    header = [f"# Resultados del laboratorio — `{args.run_id}`\n"]
    if meta:
        header.append(f"Modelo: **{meta.get('model')}** · modo: {meta.get('mode')} · "
                      f"kernel: `{meta.get('kernel')}` · umbral: {meta.get('threshold')} · "
                      f"{meta.get('repeat')} repeticiones.\n")
    header.append(f"{len(runs)} ejecuciones.\n")

    sections = [
        section_catalogue(),
        section_triage(runs),
        section_decisions(runs),
        section_stability(runs),
        section_latency(runs),
        section_remediation(runs),
        section_sensor(runs),
    ]

    if args.compare:
        sections.append(section_compare(
            args.run_id, meta, runs,
            args.compare, load_meta(args.compare), load_runs(args.compare)))

    parts = ["\n".join(header)]
    for text, csv_spec in sections:
        parts.append(text)
        if csv_spec:
            write_csv(csv_dir, *csv_spec)

    parts.append(
        "## 9. Triaje sobre telemetría real\n\n"
        "Se genera aparte, sobre la telemetría grabada, con:\n\n"
        "```\nvenv/bin/python3 scripts/lab/triage_replay.py events.jsonl\n```\n\n"
        "Es la tasa de falsos positivos de la capa determinista sobre actividad "
        "de escritorio genuina, el número que justifica el diseño híbrido.")

    report = "\n\n".join(parts) + "\n"
    report_path = out_dir / "report.md"
    report_path.write_text(report, encoding="utf-8")
    print(f"[+] informe: {report_path}")
    print(f"[+] CSVs en: {csv_dir}")


if __name__ == "__main__":
    main()
