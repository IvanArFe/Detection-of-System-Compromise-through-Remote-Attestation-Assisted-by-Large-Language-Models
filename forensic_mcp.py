"""Servidor MCP con las herramientas forenses y los sensores eBPF.

Se lanza como subproceso del orquestador, con sus mismos privilegios, y habla
JSON-RPC por stdio.

**Nada de este fichero debe escribir en stdout**: ese es el canal de framing del
protocolo MCP. Todo el logging va a stderr a través de `log`.

La carga del programa eBPF ocurre dentro de `start_sensors()`, no al importar el
módulo. Es lo que permite `import forensic_mcp` sin root para poder testear.
"""

import ctypes as ct
import json
import logging
import os
import sys
import threading

from mcp.server.fastmcp import FastMCP

from edr import config, netinfo, procinfo, safety
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

# Handle del programa BPF y estado del enganche. Los rellena start_sensors().
_bpf = None
PROBES = {"attached": [], "failed": []}


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
            # Un descriptor que se cierra entre el listdir y el readlink es lo
            # normal en /proc, no una anomalía. Antes esta excepción escapaba al
            # manejador exterior y se perdía el resultado ENTERO.
            continue

    if not files:
        return f"[!] Process {pid} has no detectable open files."
    return "Opened files for process:\n- " + "\n- ".join(files)


@mcp.tool()
def inspect_pid_network(pid: int) -> str:
    """Lista las conexiones TCP activas de un PID cruzando inodos de socket."""
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
                next(f)  # cabecera
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

    La remediación pasa por varias comprobaciones antes de enviar nada: PID
    remediable, acción válida, autoprotección del EDR y sus ancestros, hilos de
    kernel, procesos críticos protegidos, identidad conocida, coincidencia contra
    la reutilización de PID, y límite de tasa.

    `expected_starttime` lo rellena el orquestador a partir del evento original,
    nunca el modelo. Si no coincide con el valor actual, el PID pertenece ya a
    otro proceso y la remediación se aborta.
    """
    record = safety.remediate(pid, action, expected_starttime, reason)
    return safety.describe(record)


@mcp.tool()
def sensor_stats() -> str:
    """Estado de los sensores: eventos, descartes y cobertura real de sondas."""
    stats = STORE.stats()
    stats["probes_attached"] = PROBES["attached"]
    stats["probes_failed"] = PROBES["failed"]
    stats["ringbuf_dropped"] = _ringbuf_dropped()
    return json.dumps(stats, indent=2, ensure_ascii=False)


# ──────────────────────────────────────────────
# eBPF program
# ──────────────────────────────────────────────

# Identificadores de tipo de evento. Deben coincidir con _KIND_NAMES de abajo.
KIND_MODULE_LOAD = 1
KIND_EXECVE = 2

_KIND_NAMES = {
    KIND_MODULE_LOAD: config.KIND_MODULE_LOAD,
    KIND_EXECVE: config.KIND_EXECVE,
}

ebpf_code = """
#include <linux/sched.h>

#define KIND_MODULE_LOAD 1
#define KIND_EXECVE      2

/* Cabecera común a todos los eventos. Va embebida al principio de cada struct
 * concreta en vez de usarse una unión: una unión gastaría en CADA evento el
 * tamaño del mayor de todos, desperdiciando espacio del ring buffer. */
struct ev_hdr {
    u64 ts_ns;
    u64 start_boottime;
    u64 cgroup_id;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 kind;
    char comm[16];
};

struct module_event_t {
    struct ev_hdr hdr;
};

struct exec_event_t {
    struct ev_hdr hdr;
    char filename[128];
};

/* Un único ring buffer para todos los sensores: da ordenación global entre tipos
 * de evento, hace menos copias que un buffer por sensor y consume menos CPU. */
BPF_RINGBUF_OUTPUT(events, 64);

/* El ring buffer descarta cuando se llena. Sin este contador la pérdida sería
 * invisible, que es justo lo que pasaba antes al no usar el lost_cb del perf
 * buffer. */
BPF_ARRAY(dropped, u64, 1);

static __always_inline void fill_hdr(struct ev_hdr *hdr, u32 kind) {
    hdr->ts_ns = bpf_ktime_get_ns();
    hdr->pid = bpf_get_current_pid_tgid() >> 32;
    hdr->uid = (u32)bpf_get_current_uid_gid();
    hdr->cgroup_id = bpf_get_current_cgroup_id();
    hdr->kind = kind;
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
        bpf_probe_read_kernel(&hdr->ppid, sizeof(hdr->ppid), &parent->tgid);
    }

    /* LA razón de ser de esta fase. Leer la identidad AQUÍ, dentro de la sonda,
     * es la única forma de obtenerla: el callback de userspace corre cientos de
     * milisegundos después y para entonces los procesos de vida corta ya no
     * existen. Se midió 0 identidades capturadas de 2905 eventos.
     *
     * Es start_boottime, no start_time: desde la 5.5 el kernel calcula con el
     * primero el campo 22 de /proc/{pid}/stat, contra el que se compara luego. */
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
    struct exec_event_t ev = {};
    fill_hdr(&ev.hdr, KIND_EXECVE);
    bpf_probe_read_user_str(ev.filename, sizeof(ev.filename), args->filename);
    if (events.ringbuf_output(&ev, sizeof(ev), 0) < 0) {
        count_drop();
    }
    return 0;
}
"""


# ──────────────────────────────────────────────
# Espejo en ctypes del esquema de evento
# ──────────────────────────────────────────────

class EvHdr(ct.Structure):
    """Debe coincidir campo a campo con `struct ev_hdr` del programa eBPF.

    El orden importa: los u64 van primero para que la estructura quede alineada
    sin relleno, de modo que el tamaño en C y en ctypes coincida exactamente.
    """
    _fields_ = [
        ("ts_ns", ct.c_uint64),
        ("start_boottime", ct.c_uint64),
        ("cgroup_id", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("ppid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("kind", ct.c_uint32),
        ("comm", ct.c_char * 16),
    ]


class ModuleEvent(ct.Structure):
    _fields_ = [("hdr", EvHdr)]


class ExecEvent(ct.Structure):
    _fields_ = [("hdr", EvHdr), ("filename", ct.c_char * 128)]


def _decode(raw):
    return raw.decode(errors="replace").strip("\x00")


def _hdr_fields(hdr):
    """Campos comunes que se guardan en el almacén de eventos."""
    return {
        "pid": hdr.pid,
        "ppid": hdr.ppid,
        "uid": hdr.uid,
        "comm": _decode(hdr.comm),
        # Se convierte a ticks aquí, no en el kernel: el evento sigue llevando el
        # campo `starttime` con la misma semántica y unidades que antes, así que
        # ni safety.py ni procinfo.py necesitan cambiar.
        "starttime": procinfo.ns_to_ticks(hdr.start_boottime),
        "cgroup_id": hdr.cgroup_id,
    }


def handle_event(data, size):
    """Despacha un evento del ring buffer según su `kind`.

    Con un único buffer para todos los sensores, el tipo va en la cabecera y hay
    que reinterpretar el búfer en consecuencia.
    """
    hdr = ct.cast(data, ct.POINTER(EvHdr)).contents
    kind = _KIND_NAMES.get(hdr.kind)
    if kind is None:
        log.warning("evento de tipo desconocido: %s", hdr.kind)
        return

    fields = _hdr_fields(hdr)

    if hdr.kind == KIND_EXECVE:
        ev = ct.cast(data, ct.POINTER(ExecEvent)).contents
        fields["filename"] = _decode(ev.filename)
    else:
        fields["detail"] = "Kernel module load detected"

    STORE.append(kind, **fields)


def _ringbuf_dropped():
    """Eventos que el kernel descartó por ring buffer lleno."""
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
    """Engancha una sonda sin que su fallo impida arrancar el resto.

    Antes, un solo `attach_kprobe` fallido lanzaba excepción y el sensor no
    arrancaba en absoluto. Con más sondas por venir —algunas dependientes de
    símbolos que pueden no existir en otro kernel— eso significaría perder toda la
    detección por un sensor indisponible.
    """
    try:
        fn()
        PROBES["attached"].append(description)
        return True
    except Exception as e:  # noqa: BLE001
        PROBES["failed"].append(f"{description}: {e}")
        log.warning("no se pudo enganchar %s: %s", description, e)
        return False


def start_sensors():
    """Compila el programa eBPF, engancha las sondas y arranca el hilo de sondeo.

    Está en una función y no en el nivel de módulo a propósito: cargar BPF al
    importar exigía root y enganchaba sondas reales, lo que hacía imposible
    testear o siquiera importar el módulo.
    """
    global _bpf
    from bcc import BPF  # importado aquí para que el módulo se pueda importar sin BCC

    _bpf = BPF(text=ebpf_code)

    # El tracepoint de execve lo engancha BCC automáticamente al cargar, por usar
    # la macro TRACEPOINT_PROBE. Los kprobes se enganchan uno a uno.
    PROBES["attached"].append("tracepoint:syscalls:sys_enter_execve")

    for syscall in ("finit_module", "init_module"):
        fnname = _bpf.get_syscall_fnname(syscall)
        _attach(
            f"kprobe:{syscall}",
            lambda f=fnname: _bpf.attach_kprobe(event=f, fn_name="kprobe_module_load"),
        )

    if not PROBES["attached"]:
        log.error("ninguna sonda enganchada: el sensor no capturará nada")

    log.info("Sondas activas: %s", ", ".join(PROBES["attached"]))
    if PROBES["failed"]:
        log.warning("Sondas fallidas: %s", "; ".join(PROBES["failed"]))
    log.info("Modo de remediación: %s", config.EDR_MODE)
    log.info("Registro de eventos: %s", config.EVENTS_JSONL)

    def run():
        _bpf["events"].open_ring_buffer(lambda ctx, data, size: handle_event(data, size))
        while True:
            _bpf.ring_buffer_poll(100)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    log.info("Sensor activo. Esperando eventos...")
    return thread


if __name__ == "__main__":
    start_sensors()
    mcp.run()
