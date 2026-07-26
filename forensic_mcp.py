"""Servidor MCP con las herramientas forenses y los sensores eBPF.

Se lanza como subproceso del orquestador, con sus mismos privilegios, y habla
JSON-RPC por stdio.

**Nada de este fichero debe escribir en stdout**: ese es el canal de framing del
protocolo MCP. Todo el logging va a stderr a través de `log`.

La carga del programa eBPF ocurre dentro de `start_sensors()`, no al importar el
módulo. Es lo que permite `import forensic_mcp` sin root para poder testear.
"""

import json
import logging
import os
import sys
import threading

from mcp.server.fastmcp import FastMCP

from edr import config, procinfo, safety
from edr.eventstore import EventStore

# El transporte stdio de MCP usa stdout para el framing JSON-RPC: cualquier
# escritura libre ahí corrompe el protocolo. Todo el logging va a stderr.
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("forensic_mcp")

mcp = FastMCP("Kernel_Forensic")

# Almacén compartido entre el hilo de los sensores y el hilo de las herramientas.
# Sustituye a los dos ficheros JSON que se reescribían enteros sin sincronización.
STORE = EventStore(config.EVENTS_JSONL, cap=config.EVENT_CAP)

# Handle del programa BPF. Lo rellena start_sensors().
_bpf = None


# ──────────────────────────────────────────────
# MCP Tools
# ──────────────────────────────────────────────

@mcp.tool()
def get_kernel_alerts() -> str:
    """Devuelve las alertas de carga de módulos del kernel aún sin procesar.

    Solo entrega eventos no confirmados: una vez el orquestador llama a
    `ack_alerts`, dejan de aparecer. Antes no había forma de consumirlos y la
    misma alerta se reanalizaba indefinidamente.
    """
    eventos = STORE.pending(config.KIND_MODULE_LOAD, limit=30)
    if not eventos:
        return "No security alerts for now."
    return json.dumps(eventos, indent=2, ensure_ascii=False)


@mcp.tool()
def ack_alerts(max_seq: int) -> str:
    """Confirma como procesadas todas las alertas hasta `max_seq` inclusive.

    La confirmación es explícita y monótona en vez de un borrado implícito: queda
    registro de qué se procesó y cuándo, y una confirmación tardía no puede hacer
    retroceder el puntero.
    """
    n = STORE.ack(max_seq)
    return f"Confirmados {n} eventos hasta seq={max_seq}."


@mcp.tool()
def inspect_pid_resources(pid: int) -> str:
    """Lista los descriptores de fichero abiertos por un PID vía /proc/{pid}/fd."""
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
    """Lista las conexiones TCP activas de un PID cruzando inodos de socket."""
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
    """Devuelve las ejecuciones asociadas a un PID o a sus hijos directos."""
    eventos = [
        e for e in STORE.query(kind=config.KIND_EXECVE, limit=0)
        if e.get("pid") == pid or e.get("ppid") == pid
    ]
    if not eventos:
        return f"[-] No execve events found for PID {pid} or its children."
    return json.dumps(eventos[-50:], indent=2, ensure_ascii=False)


@mcp.tool()
def remediate_incident(pid: int, action: str = "kill",
                       expected_starttime: int | None = None,
                       reason: str = "") -> str:
    """Congela (SIGSTOP) o termina (SIGKILL) un proceso, con salvaguardas.

    La remediación pasa por siete comprobaciones antes de enviar nada: PID
    remediable, acción válida, autoprotección del EDR y sus ancestros, hilos de
    kernel, procesos críticos protegidos, coincidencia de identidad contra la
    reutilización de PID, y límite de tasa.

    `expected_starttime` lo rellena el orquestador a partir del evento original,
    nunca el modelo. Si no coincide con el valor actual, el PID pertenece ya a
    otro proceso y la remediación se aborta.
    """
    record = safety.remediate(pid, action, expected_starttime, reason)
    return safety.describe(record)


@mcp.tool()
def sensor_stats() -> str:
    """Contadores del almacén de eventos: útiles para diagnóstico y rendimiento."""
    return json.dumps(STORE.stats(), indent=2)


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
# Event callbacks
# ──────────────────────────────────────────────

def _decode(raw):
    return raw.decode(errors="replace").strip("\x00")


def procesar_evento(cpu, data, size):
    evento = _bpf["eventos"].event(data)
    pid = evento.pid
    STORE.append(
        config.KIND_MODULE_LOAD,
        pid=pid,
        comm=_decode(evento.command),
        # La identidad se captura AQUÍ, milisegundos después del evento, no
        # cuando el modelo decide actuar decenas de segundos más tarde. Es lo que
        # reduce la ventana de reutilización de PID de segundos a milisegundos.
        # Si el proceso ya murió queda a None y la remediación se denegará.
        starttime=procinfo.starttime(pid),
        detail=_decode(evento.message),
    )


def procesar_exec_evento(cpu, data, size):
    evento = _bpf["exec_events"].event(data)
    pid = evento.pid
    STORE.append(
        config.KIND_EXECVE,
        pid=pid,
        ppid=evento.ppid,
        comm=_decode(evento.command),
        filename=_decode(evento.filename),
        starttime=procinfo.starttime(pid),
    )


# ──────────────────────────────────────────────
# Sensor startup
# ──────────────────────────────────────────────

def start_sensors():
    """Compila el programa eBPF, engancha las sondas y arranca el hilo de sondeo.

    Está en una función y no en el nivel de módulo a propósito: cargar BPF al
    importar exigía root y enganchaba sondas reales, lo que hacía imposible
    testear o siquiera importar el módulo.
    """
    global _bpf
    from bcc import BPF  # importado aquí para que el módulo se pueda importar sin BCC

    _bpf = BPF(text=ebpf_code)

    fnname_finit = _bpf.get_syscall_fnname("finit_module")
    fnname_init = _bpf.get_syscall_fnname("init_module")
    _bpf.attach_kprobe(event=fnname_finit, fn_name="kprobe_monitor")
    _bpf.attach_kprobe(event=fnname_init, fn_name="kprobe_monitor")

    log.info("Monitorizando: %s, %s, syscalls:sys_enter_execve", fnname_finit, fnname_init)
    log.info("Modo de remediación: %s", config.EDR_MODE)
    log.info("Registro de eventos: %s", config.EVENTS_JSONL)

    def run():
        _bpf["eventos"].open_perf_buffer(procesar_evento)
        _bpf["exec_events"].open_perf_buffer(procesar_exec_evento)
        while True:
            _bpf.perf_buffer_poll()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    log.info("Sensor activo. Esperando eventos...")
    return thread


if __name__ == "__main__":
    start_sensors()
    mcp.run()
