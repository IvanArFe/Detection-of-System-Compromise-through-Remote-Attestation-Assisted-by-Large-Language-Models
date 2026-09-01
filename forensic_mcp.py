"""MCP server exposing the forensic tools, plus the eBPF sensors.

Launched as a subprocess of the orchestrator, with its privileges, speaking
JSON-RPC over stdio.

**Nothing here may write to stdout**: that channel carries the MCP framing. All
logging goes to stderr through `log`.

The eBPF program is loaded inside `start_sensors()`, not at import time, so the
module can be imported without root for testing.
"""

import ctypes as ct
import json
import logging
import os
import sys
import threading

from mcp.server.fastmcp import FastMCP

from edr import config, netinfo, procinfo, safety, triage
from edr.eventstore import EventStore

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("forensic_mcp")

mcp = FastMCP("Kernel_Forensic")

# Shared between the sensor thread and the tool thread.
STORE = EventStore(config.EVENTS_JSONL, cap=config.EVENT_CAP)

# BPF handle and attachment state. Filled in by start_sensors().
_bpf = None
PROBES = {"attached": [], "failed": []}


# ──────────────────────────────────────────────
# MCP tools
# ──────────────────────────────────────────────

@mcp.tool()
def get_kernel_alerts() -> str:
    """Return the kernel alerts that have not been processed yet.

    Every module load, plus the processes the triage in `edr/triage.py` scored
    above the threshold. Only unacknowledged events are returned.
    """
    events = STORE.pending(limit=30, predicate=triage.is_alert)
    if not events:
        return "No security alerts for now."
    return json.dumps(_rank_alerts(events), indent=2, ensure_ascii=False)


def _rank_alerts(events):
    """Annotate each alert with `alive` and sort by actionability.

    Ascending on purpose — dead and low-severity first, alive and severe last —
    because two truncations pull the same way: `render_events` keeps the LAST
    events, and Ollama keeps the tail of the prompt. The most actionable alert
    is the one that survives both.

    Sorting is not filtering: dead alerts are still shown (forensic value, and
    NOTHING is a legitimate answer) and the model still chooses.
    """
    annotated = []
    for e in events:
        alert = dict(e)   # the stored event is not mutated
        # Same check safety.py relies on: the pid existing is not enough, it has
        # to still be THE SAME process.
        alert["alive"] = procinfo.is_alive(e.get("pid"), e.get("starttime"))
        annotated.append(alert)

    # `sorted` is stable, so within each group the chronological order that
    # pending() already provides is preserved.
    return sorted(annotated, key=lambda e: (e["alive"], e.get("severity") or 0))


@mcp.tool()
def ack_alerts(max_seq: int) -> str:
    """Mark every alert up to `max_seq` as processed.

    Explicit and monotonic rather than an implicit delete: there is a record of
    what was consumed, and a late acknowledgement cannot rewind the pointer.
    """
    n = STORE.ack(max_seq)
    return f"Acknowledged {n} events up to seq={max_seq}."


@mcp.tool()
def inspect_pid_resources(pid: int) -> str:
    """List the file descriptors opened by a pid via /proc/{pid}/fd."""
    path = f"/proc/{pid}/fd"
    if not os.path.exists(path):
        return f"[!] Error: PID {pid} does not exist or cannot be accessed."
    try:
        entries = os.listdir(path)
    except PermissionError:
        return f"[!] Insufficient permissions to inspect PID {pid}."
    except OSError as e:
        return f"[!] Unexpected error: {e}"

    files = []
    for fd in entries:
        try:
            files.append(os.readlink(os.path.join(path, fd)))
        except OSError:
            # A descriptor closing between listdir and readlink is the normal
            # case in /proc. This used to escape and discard the WHOLE result.
            continue

    if not files:
        return f"[!] Process {pid} has no detectable open files."
    return "Opened files for process:\n- " + "\n- ".join(files)


@mcp.tool()
def inspect_pid_network(pid: int) -> str:
    """List the active TCP connections of a pid by matching socket inodes."""
    fd_path = f"/proc/{pid}/fd"
    if not os.path.exists(fd_path):
        return f"[!] Error: PID {pid} does not exist or cannot be accessed."

    socket_inodes = set()
    try:
        for fd in os.listdir(fd_path):
            try:
                link = os.readlink(os.path.join(fd_path, fd))
            except OSError:
                continue
            if link.startswith("socket:["):
                socket_inodes.add(link[8:-1])
    except PermissionError:
        return f"[!] Insufficient permissions to inspect PID {pid}."
    except OSError as e:
        return f"[!] Unexpected error: {e}"

    if not socket_inodes:
        return f"[-] PID {pid} has no open sockets."

    connections = []
    for table in (f"/proc/{pid}/net/tcp", f"/proc/{pid}/net/tcp6"):
        try:
            with open(table) as f:
                next(f)  # header
                for line in f:
                    conn = netinfo.format_connection(line, socket_inodes)
                    if conn:
                        connections.append(conn)
        except (OSError, StopIteration):
            continue

    if not connections:
        return f"[-] No active TCP connections found for PID {pid}."
    return f"TCP connections for PID {pid}:\n" + "\n".join(f"  {c}" for c in connections)


@mcp.tool()
def get_execve_events(pid: int) -> str:
    """Return the executions of a pid or of its direct children."""
    events = [
        e for e in STORE.query(kind=config.KIND_EXECVE, limit=0)
        if e.get("pid") == pid or e.get("ppid") == pid
    ]
    if not events:
        return f"[-] No execve events found for PID {pid} or its children."
    return json.dumps(events[-50:], indent=2, ensure_ascii=False)


@mcp.tool()
def remediate_incident(pid: int, action: str = "kill",
                       expected_starttime: int | None = None,
                       reason: str = "") -> str:
    """Freeze (SIGSTOP) or kill (SIGKILL) a process, subject to the safeguards.

    `expected_starttime` is filled in by the orchestrator from the original
    event, never by the model, so the identity check cannot be bypassed.
    """
    record = safety.remediate(pid, action, expected_starttime, reason)
    return safety.describe(record)


@mcp.tool()
def sensor_stats() -> str:
    """Sensor state: events, drops and the real probe coverage of this run."""
    stats = STORE.stats()
    stats["probes_attached"] = PROBES["attached"]
    stats["probes_failed"] = PROBES["failed"]
    stats["ringbuf_dropped"] = _ringbuf_dropped()
    return json.dumps(stats, indent=2, ensure_ascii=False)


# ──────────────────────────────────────────────
# eBPF program
# ──────────────────────────────────────────────

# Event type ids. Must match _KIND_NAMES below.
KIND_MODULE_LOAD = 1
KIND_EXECVE = 2

_KIND_NAMES = {
    KIND_MODULE_LOAD: config.KIND_MODULE_LOAD,
    KIND_EXECVE: config.KIND_EXECVE,
}

# The EDR's own PID namespace, injected into the program at compile time: an
# eBPF program cannot stat, and this is information about the environment.
_PIDNS = os.stat("/proc/self/ns/pid")

_ebpf_template = """
#include <linux/sched.h>

#define EDR_PIDNS_DEV __PIDNS_DEV__
#define EDR_PIDNS_INO __PIDNS_INO__

#define KIND_MODULE_LOAD 1
#define KIND_EXECVE      2

/* Command-line budget. ARGS_BUF is a power of two so the write offset can be
 * bounded with a mask, which is how the verifier is convinced the write lands
 * inside the buffer. Whatever does not fit is flagged in args_truncated. */
#define ARGS_BUF   256   /* usable space for the command line */
#define ARG_LEN     64   /* per individual argument (ARG_MAX is already taken
                          * by linux/limits.h with another meaning) */
#define ARG_COUNT   16

/* The extra 64 bytes are not for data, they are for the verifier: it reasons
 * about the whole reserved object and demands that the WORST case fit. The mask
 * tells it only that the offset is 0..255, and the runtime check that makes the
 * worst case impossible is invisible to it. Never used at runtime. */
#define ARGS_ARRAY (ARGS_BUF + ARG_LEN)

/* Common header, embedded at the start of each concrete struct rather than
 * being a union: a union would spend the size of the largest event on every
 * event and waste ring-buffer space. */
struct ev_hdr {
    u64 ts_ns;
    u64 start_boottime;
    u64 cgroup_id;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 kind;
    u32 in_target_ns;   /* 1 if the pid is in the EDR's namespace */
    char comm[16];
};

struct module_event_t {
    struct ev_hdr hdr;
};

struct exec_event_t {
    struct ev_hdr hdr;
    char filename[128];
    /* Arguments are concatenated, separated by the '\\0' that
     * bpf_probe_read_user_str writes: no separator of our own is needed. */
    char args[ARGS_ARRAY];
    u32  args_len;        /* bytes written to args, separators included */
    u32  args_count;      /* arguments actually copied */
    u32  args_truncated;  /* 1 if the buffer or the argument limit ran out */
};

/* One ring buffer for all sensors: global ordering between event types, fewer
 * copies and less CPU than one buffer per sensor. */
BPF_RINGBUF_OUTPUT(events, 64);

/* The ring buffer drops when full. Without this counter the loss would be
 * invisible, which is what happened with the perf buffer's unused lost_cb. */
BPF_ARRAY(dropped, u64, 1);

static __always_inline void fill_hdr(struct ev_hdr *hdr, u32 kind) {
    /* Ring-buffer memory is NOT zeroed, unlike the stack `= {}` this replaced.
     * Any field that might not be written has to be initialised, or it would
     * carry garbage from a previous event. */
    hdr->ppid = 0;
    hdr->in_target_ns = 0;

    hdr->ts_ns = bpf_ktime_get_ns();
    hdr->uid = (u32)bpf_get_current_uid_gid();
    hdr->cgroup_id = bpf_get_current_cgroup_id();
    hdr->kind = kind;
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));

    /* The pid must be translated between namespaces.
     *
     * bpf_get_current_pid_tgid() always returns the pid in the INITIAL kernel
     * namespace, and WSL2 with systemd runs the session in a nested one, so
     * that number does not exist in the /proc the EDR reads. With the wrong pid
     * every safety check and every forensic tool silently reads another process
     * or none at all.
     *
     * bpf_get_ns_current_pid_tgid translates to the namespace identified by
     * (dev, ino). It returns non-zero for a process outside that namespace — a
     * container, say — and then the global pid is kept and the event flagged. */
    struct bpf_pidns_info ns = {};
    if (bpf_get_ns_current_pid_tgid(EDR_PIDNS_DEV, EDR_PIDNS_INO,
                                    &ns, sizeof(ns)) == 0) {
        hdr->pid = ns.tgid;
        hdr->in_target_ns = 1;
    } else {
        hdr->pid = bpf_get_current_pid_tgid() >> 32;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    /* ppid is deliberately not read here: the helper above only translates the
     * current task, and real_parent->tgid is the global pid. It is resolved in
     * userspace from /proc, which is already in the right numbering. */

    /* Identity has to be read HERE, inside the probe. The userspace callback
     * runs hundreds of milliseconds later, by which point short-lived processes
     * are gone — it captured 0 identities out of 2905 events.
     *
     * start_boottime, not start_time: since 5.5 the kernel derives /proc stat
     * field 22 from the former, and that is what this is compared against. */
    bpf_probe_read_kernel(&hdr->start_boottime, sizeof(hdr->start_boottime),
                          &task->start_boottime);
}

static __always_inline void count_drop() {
    u32 key = 0;
    u64 *slot = dropped.lookup(&key);
    if (slot) {
        __sync_fetch_and_add(slot, 1);
    }
}

int kprobe_module_load(struct pt_regs *ctx) {
    struct module_event_t ev = {};
    fill_hdr(&ev.hdr, KIND_MODULE_LOAD);
    if (events.ringbuf_output(&ev, sizeof(ev), 0) < 0) {
        count_drop();
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    /* Reserved in the ring buffer instead of built on the stack: an eBPF stack
     * is 512 bytes and this struct is 528, so it would not even fit. */
    struct exec_event_t *ev = events.ringbuf_reserve(sizeof(struct exec_event_t));
    if (!ev) {
        count_drop();
        return 0;
    }

    fill_hdr(&ev->hdr, KIND_EXECVE);

    ev->filename[0] = '\\0';
    bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), args->filename);

    ev->args_len = 0;
    ev->args_count = 0;
    ev->args_truncated = 0;

    /* argv is a vector of userspace pointers: read the pointer first, then the
     * string it points at. Starts at 1 because argv[0] is the program itself,
     * which already travels in filename. */
    const char *const *argv = (const char *const *)(args->argv);

    /* Runs to ARG_COUNT rather than ARG_COUNT-1: that last pass copies nothing
     * and only checks whether more arguments remained, so the truncation flag
     * is exact instead of over-reporting a command with exactly 15 arguments. */
    #pragma unroll
    for (int i = 1; i <= ARG_COUNT; i++) {
        const char *arg = NULL;
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) != 0 || !arg) {
            break;   /* end of the vector: argv is null-terminated */
        }

        if (i == ARG_COUNT) {
            ev->args_truncated = 1;
            break;
        }

        /* Cut by the USABLE space. Flagging it matters: a model that knows the
         * line is cut reasons differently from one that believes it saw the
         * whole command. This check is also what guarantees the mask below
         * never wraps around and overwrites what was already written. */
        if (ev->args_len >= ARGS_BUF) {
            ev->args_truncated = 1;
            break;
        }

        int n = bpf_probe_read_user_str(&ev->args[ev->args_len & (ARGS_BUF - 1)],
                                        ARG_LEN, arg);
        if (n <= 0) {
            break;
        }

        /* n includes the '\\0', which stays as the separator. */
        ev->args_len += n;
        ev->args_count++;
    }

    events.ringbuf_submit(ev, 0);
    return 0;
}
"""

ebpf_code = (_ebpf_template
             .replace("__PIDNS_DEV__", str(_PIDNS.st_dev))
             .replace("__PIDNS_INO__", str(_PIDNS.st_ino)))


# ──────────────────────────────────────────────
# ctypes mirror of the event schema
# ──────────────────────────────────────────────

class EvHdr(ct.Structure):
    """Must match `struct ev_hdr` field by field.

    Order matters: the u64s come first so there is no intermediate padding and
    the size is identical in C and in ctypes.
    """
    _fields_ = [
        ("ts_ns", ct.c_uint64),
        ("start_boottime", ct.c_uint64),
        ("cgroup_id", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("ppid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("kind", ct.c_uint32),
        ("in_target_ns", ct.c_uint32),
        ("comm", ct.c_char * 16),
    ]


class ModuleEvent(ct.Structure):
    _fields_ = [("hdr", EvHdr)]


# Must match the #defines in the C program. The test asserts the struct size,
# which is what would catch any divergence between the two.
ARGS_BUF = 256                      # usable space
ARG_LEN = 64                        # per argument
ARGS_ARRAY = ARGS_BUF + ARG_LEN     # declared size: the slack is the verifier's
ARG_COUNT = 16


class ExecEvent(ct.Structure):
    _fields_ = [
        ("hdr", EvHdr),
        ("filename", ct.c_char * 128),
        # c_ubyte, not c_char: a c_char array stops at the first '\0', and here
        # '\0' is the separator, so it would return only the first argument.
        ("args", ct.c_ubyte * ARGS_ARRAY),
        ("args_len", ct.c_uint32),
        ("args_count", ct.c_uint32),
        ("args_truncated", ct.c_uint32),
    ]


def _decode(raw):
    return raw.decode(errors="replace").strip("\x00")


def decode_cmdline(raw, args_len, truncated=False):
    """Rebuild the command line from the probe's raw buffer.

    Sliced by `args_len` rather than to the end of the buffer: ring-buffer
    memory is not zeroed, so reading further would show the model fragments of
    other commands.
    """
    args_len = max(0, min(int(args_len), len(raw)))
    if not args_len:
        return "…" if truncated else ""

    chunks = bytes(raw[:args_len]).split(b"\x00")
    parts = [c.decode(errors="replace") for c in chunks if c]
    if truncated:
        parts.append("…")
    return " ".join(parts)


def _hdr_fields(hdr):
    """Common fields stored for every event."""
    # ppid is resolved here, not in the probe: the probe can only give the
    # parent's global pid, which means nothing to /proc in a nested namespace.
    # Lost for very short-lived processes, which is acceptable: it is
    # informational and no decision depends on it.
    parent = procinfo.read_stat(hdr.pid) if hdr.in_target_ns else None

    return {
        "pid": hdr.pid,
        "ppid": parent["ppid"] if parent else None,
        "uid": hdr.uid,
        "comm": _decode(hdr.comm),
        # Converted to ticks here so the event keeps carrying `starttime` with
        # the same units as before: safety.py and procinfo.py need no changes.
        "starttime": procinfo.ns_to_ticks(hdr.start_boottime),
        "cgroup_id": hdr.cgroup_id,
        # Recorded for its forensic value, but its pid cannot be interpreted
        # here and it cannot be signalled, so it never becomes an alert.
        "foreign_ns": not hdr.in_target_ns,
    }


def handle_event(data, size):
    """Dispatch a ring-buffer event on its `kind` and re-cast the buffer."""
    hdr = ct.cast(data, ct.POINTER(EvHdr)).contents
    kind = _KIND_NAMES.get(hdr.kind)
    if kind is None:
        log.warning("unknown event kind: %s", hdr.kind)
        return

    fields = _hdr_fields(hdr)

    if hdr.kind == KIND_EXECVE:
        ev = ct.cast(data, ct.POINTER(ExecEvent)).contents
        fields["filename"] = _decode(ev.filename)
        fields["cmdline"] = decode_cmdline(ev.args, ev.args_len,
                                           bool(ev.args_truncated))

        # At sys_enter_execve the kernel has not renamed the process yet, so
        # `comm` is the CALLER's name, not the program being executed — the
        # telemetry read `comm=sh filename=/usr/bin/ollama`. Renamed so the
        # field cannot be mistaken for the program.
        fields["caller_comm"] = fields.pop("comm")

        # Scored once, on ingest, and the result travels with the event: the
        # alert filter would otherwise re-evaluate thousands of events per cycle.
        severity, rules = triage.assess(fields)
        if rules:
            fields["severity"] = severity
            fields["rules_fired"] = ",".join(rules)
    else:
        fields["detail"] = "Kernel module load detected"

    STORE.append(kind, **fields)


def _ringbuf_dropped():
    """Events the kernel dropped because the ring buffer was full."""
    if _bpf is None:
        return 0
    try:
        return _bpf["dropped"][ct.c_int(0)].value
    except Exception:  # noqa: BLE001
        return 0


# ──────────────────────────────────────────────
# Sensor startup
# ──────────────────────────────────────────────

def _attach(description, fn):
    """Attach a probe without letting its failure prevent the rest from starting.

    Some probes depend on symbols that may not exist on another kernel; losing
    all detection because one sensor is unavailable would be a bad trade.
    """
    try:
        fn()
        PROBES["attached"].append(description)
        return True
    except Exception as e:  # noqa: BLE001
        PROBES["failed"].append(f"{description}: {e}")
        log.warning("could not attach %s: %s", description, e)
        return False


def start_sensors():
    """Compile the eBPF program, attach the probes and start the polling thread.

    In a function rather than at module level on purpose: loading BPF at import
    time required root and attached real probes, which made the module
    impossible to test or even import.
    """
    global _bpf
    from bcc import BPF  # imported here so the module imports without BCC

    _bpf = BPF(text=ebpf_code)

    # BCC auto-attaches the execve tracepoint at load time because of the
    # TRACEPOINT_PROBE macro. The kprobes are attached one by one.
    PROBES["attached"].append("tracepoint:syscalls:sys_enter_execve")

    for syscall in ("finit_module", "init_module"):
        fnname = _bpf.get_syscall_fnname(syscall)
        _attach(
            f"kprobe:{syscall}",
            lambda f=fnname: _bpf.attach_kprobe(event=f, fn_name="kprobe_module_load"),
        )

    if not PROBES["attached"]:
        log.error("no probe attached: the sensor will capture nothing")

    log.info("Active probes: %s", ", ".join(PROBES["attached"]))
    if PROBES["failed"]:
        log.warning("Failed probes: %s", "; ".join(PROBES["failed"]))
    log.info("Remediation mode: %s", config.EDR_MODE)
    log.info("Event log: %s", config.EVENTS_JSONL)

    def run():
        _bpf["events"].open_ring_buffer(lambda ctx, data, size: handle_event(data, size))
        while True:
            _bpf.ring_buffer_poll(100)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    log.info("Sensor running. Waiting for events...")
    return thread


if __name__ == "__main__":
    start_sensors()
    mcp.run()
