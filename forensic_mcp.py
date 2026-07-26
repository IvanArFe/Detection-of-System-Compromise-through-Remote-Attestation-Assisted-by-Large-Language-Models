from bcc import BPF
import json
import logging
import os
import sys
import threading
from pathlib import Path
from mcp.server.fastmcp import FastMCP
from datetime import datetime
import signal

# El transporte stdio de MCP usa stdout para el framing JSON-RPC: cualquier
# escritura libre ahí corrompe el protocolo. Todo el logging va a stderr.
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("forensic_mcp")

mcp = FastMCP("Kernel_Forensic")

# Rutas absolutas derivadas del propio fichero: el servidor funciona
# independientemente del directorio desde el que se lance.
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "kernel_events.json"
EXECVE_LOG_FILE = BASE_DIR / "execve_events.json"

# ──────────────────────────────────────────────
# MCP Tools
# ──────────────────────────────────────────────

@mcp.tool()
def get_kernel_alerts() -> str:
    """Reads the last captured kernel module load events from the eBPF sensor."""
    if not os.path.exists(LOG_FILE):
        return "No security alerts for now."
    with open(LOG_FILE, "r") as f:
        try:
            events = json.load(f)
            if not events:
                return "Empty."
            return json.dumps(events, indent=2)
        except Exception as e:
            return f"[!] Error reading alerts file: {str(e)}"


@mcp.tool()
def inspect_pid_resources(pid: int) -> str:
    """Inspect the open file descriptors for a given PID via /proc/{pid}/fd."""
    path = f"/proc/{pid}/fd"
    if not os.path.exists(path):
        return f"[!] Error: PID {pid} does not exist or cannot be accessed."
    try:
        files = []
        for fd in os.listdir(path):
            full_path = os.readlink(os.path.join(path, fd))
            files.append(full_path)
        if not files:
            return f"[!] Process {pid} has no detectable open files."
        return "Opened files for process:\n- " + "\n- ".join(files)
    except PermissionError:
        return f"[!] Insufficient permissions to inspect PID {pid}."
    except Exception as e:
        return f"[!] Unexpected error: {str(e)}"


@mcp.tool()
def inspect_pid_network(pid: int) -> str:
    """List active TCP connections for a given PID by matching socket inodes."""
    fd_path = f"/proc/{pid}/fd"
    if not os.path.exists(fd_path):
        return f"[!] Error: PID {pid} does not exist or cannot be accessed."

    # Collect socket inodes owned by this PID from /proc/{pid}/fd
    socket_inodes = set()
    try:
        for fd in os.listdir(fd_path):
            try:
                link = os.readlink(os.path.join(fd_path, fd))
                if link.startswith("socket:["):
                    socket_inodes.add(link[8:-1])  # extract inode number
            except OSError:
                continue
    except PermissionError:
        return f"[!] Insufficient permissions to inspect PID {pid}."

    if not socket_inodes:
        return f"[-] PID {pid} has no open sockets."

    TCP_STATES = {
        "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
        "04": "FIN_WAIT1",   "05": "FIN_WAIT2", "06": "TIME_WAIT",
        "07": "CLOSE",       "08": "CLOSE_WAIT", "09": "LAST_ACK",
        "0A": "LISTEN",      "0B": "CLOSING",
    }

    def decode_ipv4(hex_str):
        # /proc/net/tcp stores IPs in little-endian hex: reverse byte order
        addr = int(hex_str, 16)
        return (f"{addr & 0xFF}.{(addr >> 8) & 0xFF}."
                f"{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}")

    def parse_tcp_file(path):
        conns = []
        if not os.path.exists(path):
            return conns
        try:
            with open(path) as f:
                next(f)  # skip header line
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    inode = parts[9]
                    if inode not in socket_inodes:
                        continue
                    local_ip, local_port = parts[1].split(":")
                    remote_ip, remote_port = parts[2].split(":")
                    state = TCP_STATES.get(parts[3].upper(), parts[3])
                    conns.append(
                        f"{decode_ipv4(local_ip)}:{int(local_port, 16)} → "
                        f"{decode_ipv4(remote_ip)}:{int(remote_port, 16)} [{state}]"
                    )
        except Exception as e:
            conns.append(f"[!] Error reading {path}: {e}")
        return conns

    connections = (
        parse_tcp_file(f"/proc/{pid}/net/tcp") +
        parse_tcp_file(f"/proc/{pid}/net/tcp6")
    )

    if not connections:
        return f"[-] No active TCP connections found for PID {pid}."

    return f"TCP connections for PID {pid}:\n" + "\n".join(f"  {c}" for c in connections)


@mcp.tool()
def get_execve_events(pid: int) -> str:
    """Return execve events (process executions) associated with a PID or any of its children."""
    if not os.path.exists(EXECVE_LOG_FILE):
        return "No execve events recorded yet."
    with open(EXECVE_LOG_FILE, "r") as f:
        try:
            events = json.load(f)
        except Exception as e:
            return f"[!] Error reading execve log: {e}"

    relevant = [e for e in events if e.get("pid") == pid or e.get("ppid") == pid]
    if not relevant:
        return f"[-] No execve events found for PID {pid} or its children."
    return json.dumps(relevant, indent=2)


@mcp.tool()
def remediate_incident(pid: int, action: str = "kill") -> str:
    """
    Terminate or pause a suspicious process.
    Actions: 'freeze' (SIGSTOP) or 'kill' (SIGKILL).
    """
    try:
        if action == "freeze":
            os.kill(pid, signal.SIGSTOP)
            return f"[!] Process {pid} frozen (SIGSTOP). Still in memory, cannot execute."
        elif action == "kill":
            os.kill(pid, signal.SIGKILL)
            return f"[!] Process {pid} terminated (SIGKILL)."
        else:
            return "[!] Unknown action. Use 'freeze' or 'kill'."
    except ProcessLookupError:
        return f"[!] PID {pid} does not exist."
    except PermissionError:
        return f"[!] Insufficient permissions to act on PID {pid}. Are you root?"
    except Exception as e:
        return f"[!] Error: {str(e)}"


# ──────────────────────────────────────────────
# eBPF programs
# ──────────────────────────────────────────────

ebpf_code = """
#include <linux/sched.h>

/* ── Module load tracing ── */

struct data_t {
    u32 pid;
    char command[16];
    char message[64];
};

BPF_PERF_OUTPUT(eventos);

int kprobe_monitor(void *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.command, sizeof(data.command));
    __builtin_memcpy(data.message, "Kernel module load detected", 27);
    eventos.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

/* ── execve tracing ── */

struct exec_data_t {
    u32 pid;
    u32 ppid;
    char command[16];
    char filename[128];
};

BPF_PERF_OUTPUT(exec_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&data.ppid, sizeof(data.ppid), &parent->tgid);

    bpf_get_current_comm(&data.command, sizeof(data.command));
    bpf_probe_read_user_str(data.filename, sizeof(data.filename), args->filename);

    exec_events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# ──────────────────────────────────────────────
# BPF init and kprobe attachment
# ──────────────────────────────────────────────

b = BPF(text=ebpf_code)

fnname_finit = b.get_syscall_fnname("finit_module")
fnname_init  = b.get_syscall_fnname("init_module")
b.attach_kprobe(event=fnname_finit, fn_name="kprobe_monitor")
b.attach_kprobe(event=fnname_init,  fn_name="kprobe_monitor")

log.info("Monitoring syscalls: %s, %s, syscalls:sys_enter_execve", fnname_finit, fnname_init)
log.info("Sensor active. Waiting for events...")


# ──────────────────────────────────────────────
# Event callbacks
# ──────────────────────────────────────────────

def append_to_log(log_file, entry, cap=30):
    records = []
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            try:
                records = json.load(f)
            except json.JSONDecodeError:
                records = []
    records.append(entry)
    if len(records) > cap:
        records = records[-cap:]
    with open(log_file, "w") as f:
        json.dump(records, f, indent=4)


def procesar_evento(cpu, data, size):
    evento = b["eventos"].event(data)
    entry = {
        "timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "pid":       evento.pid,
        "comando":   evento.command.decode(errors="replace").strip("\x00"),
        "evento":    evento.message.decode(errors="replace").strip("\x00"),
    }
    append_to_log(LOG_FILE, entry, cap=30)


def procesar_exec_evento(cpu, data, size):
    evento = b["exec_events"].event(data)
    entry = {
        "timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "pid":       evento.pid,
        "ppid":      evento.ppid,
        "command":   evento.command.decode(errors="replace").strip("\x00"),
        "filename":  evento.filename.decode(errors="replace").strip("\x00"),
    }
    append_to_log(EXECVE_LOG_FILE, entry, cap=200)


# ──────────────────────────────────────────────
# Sensor thread — polls both perf buffers
# ──────────────────────────────────────────────

def run_ebpf_sensor():
    b["eventos"].open_perf_buffer(procesar_evento)
    b["exec_events"].open_perf_buffer(procesar_exec_evento)
    while True:
        b.perf_buffer_poll()


if __name__ == "__main__":
    sensor_thread = threading.Thread(target=run_ebpf_sensor, daemon=True)
    sensor_thread.start()
    mcp.run()
