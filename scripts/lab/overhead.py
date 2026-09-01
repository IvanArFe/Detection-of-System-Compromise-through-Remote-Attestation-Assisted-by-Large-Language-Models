#!/usr/bin/env python3
"""Measure what the sensor costs the host it protects.

The design argues that a kernel-resident witness is usable in production
because a defect there costs visibility instead of bringing the machine down.
That is an argument about safety, not about price, and the price has to be
measured on its own.

Three questions are answered separately, because they have different causes and
different remedies:

1. **Per-execve cost.** The tracepoint sits on the entry of the execution system
   call, so every process the host creates pays for it whether it is interesting
   or not. Timed over a fixed number of spawn/wait cycles with the probes
   attached and again with nothing loaded, alternating the two so that drift in
   background load cancels instead of accumulating in one of them.
2. **Consumer cost.** What the user-space side spends per event it decodes,
   scores and appends to the log, in processor time and in resident memory.
3. **Saturation.** The rate at which the kernel starts refusing to write into
   the ring buffer, which is the point where the sensor begins losing events.
   Read from the same counter `sensor_stats` reports, so the number here and the
   number the running system publishes are the same number.

    sudo venv/bin/python3 scripts/lab/overhead.py
    sudo venv/bin/python3 scripts/lab/overhead.py --rounds 7 --execs 3000
    sudo venv/bin/python3 scripts/lab/overhead.py --out results/overhead.md \
        --json results/overhead.json

Needs root, because loading eBPF does. Needs no model, no database and no
network. The program measured is the one in `forensic_mcp.py`, imported rather
than copied, so this cannot drift from what the sensor actually runs.
"""

import argparse
import ctypes as ct
import json
import os
import platform
import resource
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# forensic_mcp builds its EventStore at import time, and that opens the real
# forensic log. Redirect it before importing: this script creates tens of
# thousands of synthetic executions and none of them belong in the telemetry the
# evaluation is based on.
os.environ["EDR_EVENTS_FILE"] = str(
    Path(tempfile.gettempdir()) / "edr-overhead-events.jsonl")

import forensic_mcp as fm  # noqa: E402


# ──────────────────────────────────────────────
# Load generation
# ──────────────────────────────────────────────

def spawn_cycles(n, binary="/bin/true"):
    """Run `n` spawn/wait cycles. Returns elapsed wall time in seconds.

    posix_spawn rather than fork followed by exec: while the sensor is attached
    this process is running a polling thread, and forking a threaded process to
    then exec in the child is the kind of thing that works until it does not.
    Each cycle is one real execution, which is exactly what the tracepoint fires
    on.
    """
    argv = [binary]
    env = {}
    start = time.perf_counter()
    for _ in range(n):
        pid = os.posix_spawn(binary, argv, env)
        os.waitpid(pid, 0)
    return time.perf_counter() - start


def _rss_kb():
    """Resident memory of this process in kB, straight from /proc."""
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


# ──────────────────────────────────────────────
# The sensor, under this script's control
# ──────────────────────────────────────────────

class Sensor:
    """The real eBPF program, attached and detachable.

    `forensic_mcp.start_sensors()` polls forever in a daemon thread, which is
    correct for the sensor and useless here, because measuring requires
    attaching, timing, detaching and timing again. The program text, the probes
    and the event handler are the real ones; only the loop belongs to us.
    """

    def __init__(self, handler=None):
        self.bpf = None
        self.thread = None
        self.handler = handler
        self.count = 0
        self.attached = []
        self.failed = []
        self._stop = threading.Event()

    def start(self):
        from bcc import BPF

        self.bpf = BPF(text=fm.ebpf_code)
        # BCC attaches the execve tracepoint on load, because of the macro.
        self.attached.append("tracepoint:syscalls:sys_enter_execve")

        for syscall in ("finit_module", "init_module"):
            try:
                fnname = self.bpf.get_syscall_fnname(syscall)
                self.bpf.attach_kprobe(event=fnname,
                                       fn_name="kprobe_module_load")
                self.attached.append(f"kprobe:{syscall}")
            except Exception as e:  # noqa: BLE001
                # Same tolerance as the sensor: one missing probe degrades the
                # evidence, it does not abort the run.
                self.failed.append(f"{syscall}: {e}")

        def on_event(ctx, data, size):
            self.count += 1
            if self.handler is not None:
                self.handler(data, size)

        self.bpf["events"].open_ring_buffer(on_event)

        def loop():
            while not self._stop.is_set():
                self.bpf.ring_buffer_poll(50)

        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()

    def dropped(self):
        """Events the kernel refused to write because the buffer was full."""
        if self.bpf is None:
            return 0
        try:
            return self.bpf["dropped"][ct.c_int(0)].value
        except Exception:  # noqa: BLE001
            return 0

    def stop(self):
        self._stop.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
            self.thread = None
        if self.bpf is not None:
            self.bpf.cleanup()
            self.bpf = None


# ──────────────────────────────────────────────
# Measurement 1: per-execve cost
# ──────────────────────────────────────────────

def measure_execve_cost(rounds, execs, warmup):
    """Cost of one execution with and without the probes, in microseconds.

    Rounds alternate rather than running all of one and then all of the other,
    because anything that drifts during the run (thermal throttling, another
    process waking up) would otherwise land entirely on whichever half came
    second and be read as overhead.
    """
    spawn_cycles(warmup)          # warm the page cache and the spawn path
    baseline, instrumented = [], []

    for _ in range(rounds):
        baseline.append(spawn_cycles(execs) / execs * 1e6)

        sensor = Sensor()
        sensor.start()
        time.sleep(0.3)           # let the probes settle before timing
        try:
            instrumented.append(spawn_cycles(execs) / execs * 1e6)
        finally:
            sensor.stop()

    return baseline, instrumented


# ──────────────────────────────────────────────
# Measurement 2: consumer cost
# ──────────────────────────────────────────────

def measure_consumer_cost(execs):
    """Processor time and memory the user-space side spends per event.

    RUSAGE_SELF excludes children, so running /bin/true does not land in the
    figure. What is left is decoding the structure, scoring it and appending it
    to the log, which is all the consumer actually does.
    """
    sensor = Sensor(handler=fm.handle_event)
    sensor.start()
    time.sleep(0.3)

    rss_before = _rss_kb()
    before = resource.getrusage(resource.RUSAGE_SELF)

    elapsed = spawn_cycles(execs)
    time.sleep(1.5)               # let the consumer drain what is still queued

    after = resource.getrusage(resource.RUSAGE_SELF)
    rss_after = _rss_kb()
    seen = sensor.count
    dropped = sensor.dropped()
    sensor.stop()

    cpu = ((after.ru_utime - before.ru_utime)
           + (after.ru_stime - before.ru_stime))

    return {
        "execs_generated": execs,
        "events_seen": seen,
        "ringbuf_dropped": dropped,
        "elapsed_s": round(elapsed, 3),
        "cpu_s": round(cpu, 4),
        "cpu_us_per_event": round(cpu / seen * 1e6, 2) if seen else None,
        "rss_before_kb": rss_before,
        "rss_after_kb": rss_after,
        "rss_delta_kb": rss_after - rss_before,
    }


# ──────────────────────────────────────────────
# Measurement 3: saturation
# ──────────────────────────────────────────────

def measure_saturation(levels, execs):
    """Push the execution rate up until the kernel starts refusing writes.

    Python cannot spawn fast enough on its own to fill a ring buffer, so the
    load is generated with xargs at increasing parallelism. What is watched is
    `dropped`, the counter the kernel bumps when the buffer has no room, which
    is the same one the sensor publishes through sensor_stats.
    """
    rows = []
    for workers in levels:
        sensor = Sensor()
        sensor.start()
        time.sleep(0.3)

        before = sensor.dropped()
        start = time.perf_counter()
        subprocess.run(
            f"seq 1 {execs} | xargs -P {workers} -n 1 -I@ /bin/true",
            shell=True, executable="/bin/bash",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elapsed = time.perf_counter() - start
        time.sleep(1.5)

        rows.append({
            "workers": workers,
            "execs_generated": execs,
            "elapsed_s": round(elapsed, 3),
            "rate_per_s": round(execs / elapsed, 1) if elapsed else 0,
            "events_seen": sensor.count,
            "ringbuf_dropped": sensor.dropped() - before,
        })
        sensor.stop()
    return rows


# ──────────────────────────────────────────────
# Report
# ──────────────────────────────────────────────

def num(value, digits=2):
    """Spanish decimal comma: these tables go straight into the thesis."""
    if value is None:
        return "—"
    return f"{value:.{digits}f}".replace(".", ",")


def _block(values):
    return (statistics.mean(values),
            statistics.median(values),
            min(values),
            max(values))


def report(meta, baseline, instrumented, consumer, saturation):
    lines = []
    add = lines.append

    add("# Coste operativo del sensor\n")
    add(f"Kernel `{meta['kernel']}` · {meta['rounds']} rondas × "
        f"{meta['execs']} ejecuciones por ronda.\n")
    add(f"Sondas adjuntadas: {', '.join(meta['probes_attached']) or '—'}.")
    if meta["probes_failed"]:
        add(f"Sondas fallidas: {'; '.join(meta['probes_failed'])}.")

    # ── 1 ──
    b_mean, b_med, b_min, b_max = _block(baseline)
    i_mean, i_med, i_min, i_max = _block(instrumented)
    delta = i_med - b_med
    pct = (delta / b_med * 100) if b_med else 0.0

    add("\n## 1. Coste por ejecución de proceso\n")
    add("| Escenario | Media (µs) | Mediana (µs) | Mín (µs) | Máx (µs) |")
    add("|---|---:|---:|---:|---:|")
    add(f"| Sin sensor | {num(b_mean)} | {num(b_med)} | {num(b_min)} | {num(b_max)} |")
    add(f"| Con el sensor adjuntado | {num(i_mean)} | {num(i_med)} | "
        f"{num(i_min)} | {num(i_max)} |")
    add(f"| **Sobrecoste** | | **{num(delta)}** | | |")
    add(f"\nSobre la mediana, el sensor añade **{num(delta)} µs** por ejecución, "
        f"un **{num(pct)} %** sobre el coste base. Las rondas se alternan, así que "
        f"una deriva de carga durante la medición se reparte entre las dos "
        f"columnas en vez de acumularse en una.")

    # ── 2 ──
    add("\n## 2. Coste del consumidor en espacio de usuario\n")
    add("| Métrica | Valor |")
    add("|---|---:|")
    add(f"| Ejecuciones generadas | {consumer['execs_generated']} |")
    add(f"| Eventos recibidos | {consumer['events_seen']} |")
    add(f"| Perdidos en el kernel | {consumer['ringbuf_dropped']} |")
    add(f"| Tiempo de CPU del proceso (s) | {num(consumer['cpu_s'], 4)} |")
    add(f"| **CPU por evento (µs)** | **{num(consumer['cpu_us_per_event'])}** |")
    add(f"| Memoria residente antes (kB) | {consumer['rss_before_kb']} |")
    add(f"| Memoria residente después (kB) | {consumer['rss_after_kb']} |")
    add(f"| Incremento (kB) | {consumer['rss_delta_kb']} |")
    add("\nEste bloque mide únicamente el lado de usuario, porque `RUSAGE_SELF` "
        "excluye a los procesos hijo: lo que queda es descodificar la estructura, "
        "puntuarla con el triaje y anexarla al registro.")

    # ── 3 ──
    add("\n## 3. Saturación del búfer circular\n")
    add("| Paralelismo | Ejecuciones | Duración (s) | Tasa (ejec/s) | "
        "Recibidos | Perdidos en kernel |")
    add("|---:|---:|---:|---:|---:|---:|")
    for r in saturation:
        add(f"| {r['workers']} | {r['execs_generated']} | {num(r['elapsed_s'], 3)} "
            f"| {num(r['rate_per_s'], 1)} | {r['events_seen']} "
            f"| {r['ringbuf_dropped']} |")

    lost = [r for r in saturation if r["ringbuf_dropped"] > 0]
    if lost:
        first = lost[0]
        add(f"\nEl kernel empieza a descartar a partir de **{num(first['rate_per_s'], 1)} "
            f"ejecuciones por segundo** ({first['workers']} procesos en paralelo). "
            f"Por debajo de esa tasa no se pierde ningún evento.")
    else:
        top = max(saturation, key=lambda r: r["rate_per_s"]) if saturation else None
        if top:
            add(f"\nNo se perdió ningún evento en ningún nivel. La tasa máxima que "
                f"el banco pudo generar fue de **{num(top['rate_per_s'], 1)} "
                f"ejecuciones por segundo**, así que el punto de saturación queda "
                f"por encima de lo que esta máquina es capaz de producir.")

    return "\n".join(lines)


# ──────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rounds", type=int, default=5,
                    help="rondas alternadas de la medida 1")
    ap.add_argument("--execs", type=int, default=2000,
                    help="ejecuciones por ronda")
    ap.add_argument("--warmup", type=int, default=200,
                    help="ejecuciones de calentamiento, no medidas")
    ap.add_argument("--sat-execs", type=int, default=4000,
                    help="ejecuciones por nivel de la medida 3")
    ap.add_argument("--sat-levels", type=int, nargs="*",
                    default=[1, 4, 16, 64],
                    help="niveles de paralelismo de la medida 3")
    ap.add_argument("--skip-saturation", action="store_true")
    ap.add_argument("--out", help="escribir el informe Markdown a un fichero")
    ap.add_argument("--json", dest="json_out", help="volcar las medidas crudas")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[!] necesita root (eBPF). Ejecuta con sudo.")

    print(f"[*] medida 1: {args.rounds} rondas × {args.execs} ejecuciones …",
          flush=True)
    baseline, instrumented = measure_execve_cost(
        args.rounds, args.execs, args.warmup)

    print("[*] medida 2: coste del consumidor …", flush=True)
    consumer = measure_consumer_cost(args.execs)

    saturation = []
    if not args.skip_saturation:
        print(f"[*] medida 3: saturación en {args.sat_levels} …", flush=True)
        saturation = measure_saturation(args.sat_levels, args.sat_execs)

    probe = Sensor()
    probe.start()
    meta = {
        "kernel": platform.release(),
        "host": platform.node(),
        "rounds": args.rounds,
        "execs": args.execs,
        "probes_attached": list(probe.attached),
        "probes_failed": list(probe.failed),
    }
    probe.stop()

    text = report(meta, baseline, instrumented, consumer, saturation)

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"[+] informe escrito en {args.out}")
    else:
        print("\n" + text)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps({
            "meta": meta,
            "execve_us_baseline": baseline,
            "execve_us_instrumented": instrumented,
            "consumer": consumer,
            "saturation": saturation,
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[+] medidas crudas en {args.json_out}")


if __name__ == "__main__":
    main()
