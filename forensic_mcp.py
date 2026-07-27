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

from edr import config, netinfo, procinfo, safety, triage
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
    """Devuelve las alertas del kernel aún sin procesar.

    Son las cargas de módulo —siempre— más los procesos que el triaje de
    `edr/triage.py` ha puntuado por encima del umbral. Antes solo devolvía cargas
    de módulo, de modo que un proceso malicioso podía ejecutarse sin que el
    sistema llegara a plantearse nada sobre él.

    Solo entrega eventos no confirmados: una vez el orquestador llama a
    `ack_alerts`, dejan de aparecer. Antes no había forma de consumirlos y la
    misma alerta se reanalizaba indefinidamente.

    Cada alerta se anota con `alive`, y el lote se ordena por accionabilidad. El
    motivo salió de la primera ejecución autónoma: los eventos más severos son los
    de la cadena de un dropper (`bash -c 'curl … | sh'`, severidad 150), que vive
    tres segundos, mientras el orquestador sondea cada veinte. El modelo gastaba
    sus dos rondas razonando sobre procesos ya muertos y pidiendo congelarlos.
    **La severidad no basta como criterio: un proceso muerto no se puede remediar
    por muy grave que fuese.**
    """
    eventos = STORE.pending(limit=30, predicate=triage.is_alert)
    if not eventos:
        return "No security alerts for now."
    return json.dumps(_rank_alerts(eventos), indent=2, ensure_ascii=False)


def _rank_alerts(eventos):
    """Anota cada alerta con `alive` y las ordena por accionabilidad.

    El orden es **ascendente**: primero lo muerto y menos severo, al final lo vivo
    y más severo. Parece del revés, y no lo es, por dos recortes que van en la
    misma dirección: `prompts.render_events` conserva los ÚLTIMOS eventos cuando
    hay más de los que caben, y Ollama descarta la cabeza del prompt conservando
    la cola. Lo más accionable es entonces lo que sobrevive a ambos.

    Ordenar no es filtrar ni decidir: las alertas muertas siguen presentándose
    —tienen valor forense y el modelo puede querer responder NOTHING— y la
    elección sigue siendo suya. La capa determinista prioriza e informa.
    """
    anotados = []
    for e in eventos:
        alerta = dict(e)   # no se muta lo que hay en el almacén
        # Misma comprobación en la que se apoya `safety.py`: no basta con que el
        # PID exista, tiene que seguir siendo EL MISMO proceso.
        alerta["alive"] = procinfo.is_alive(e.get("pid"), e.get("starttime"))
        anotados.append(alerta)

    # `sorted` es estable, así que dentro de cada grupo se mantiene el orden
    # cronológico que ya trae `pending()`.
    return sorted(anotados, key=lambda e: (e["alive"], e.get("severity") or 0))


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

# Identificadores del namespace de PIDs del propio EDR, inyectados en el programa
# al compilar. Se leen aquí y no en el C porque un programa eBPF no puede hacer
# stat: es información del entorno, no del kernel.
_PIDNS = os.stat("/proc/self/ns/pid")

_ebpf_template = """
#include <linux/sched.h>

#define EDR_PIDNS_DEV __PIDNS_DEV__
#define EDR_PIDNS_INO __PIDNS_INO__

#define KIND_MODULE_LOAD 1
#define KIND_EXECVE      2

/* Presupuesto para la línea de órdenes.
 *
 * ARGS_BUF es POTENCIA DE 2 a propósito: permite acotar el desplazamiento de
 * escritura con una máscara (& (ARGS_BUF - 1)), que es la forma de demostrarle al
 * verificador que la escritura cae dentro del búfer. Con una comparación normal no
 * siempre lo da por bueno.
 *
 * Los tres valores son un compromiso: entran las líneas de órdenes reales de un
 * atacante sin inflar cada evento del ring buffer ni el presupuesto de contexto
 * del modelo. Lo que no quepa se marca con args_truncated. */
#define ARGS_BUF   256   /* espacio útil para la línea de órdenes */
#define ARG_LEN     64   /* por argumento suelto (ARG_MAX ya lo define
                          * linux/limits.h con otro significado) */
#define ARG_COUNT   16   /* argumentos como mucho */

/* Los 64 bytes de más NO son para datos: son para el verificador.
 *
 * Éste razona sobre el objeto reservado ENTERO, no sobre el campo `args`. Al
 * acotar el desplazamiento con `& (ARGS_BUF - 1)` lo único que sabe es que vale
 * entre 0 y 255; la comprobación en tiempo de ejecución que impide llegar tan
 * lejos queda fuera de su alcance. Así que calcula el caso peor —escritura
 * empezando en el último byte útil y copiando ARG_LEN— y rechaza el programa si
 * ese caso se sale:
 *
 *   invalid access to memory, mem_size=456 off=439 size=64
 *
 * Reservar la holgura hace que el caso peor quepa. En ejecución no se usa: el
 * corte por ARGS_BUF garantiza que la máscara nunca llega a envolver. */
#define ARGS_ARRAY (ARGS_BUF + ARG_LEN)

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
    u32 in_target_ns;   /* 1 si el pid está en el namespace del EDR; ver abajo */
    char comm[16];
};

struct module_event_t {
    struct ev_hdr hdr;
};

struct exec_event_t {
    struct ev_hdr hdr;
    char filename[128];
    /* Los argumentos van concatenados y separados por el '\\0' que escribe
     * bpf_probe_read_user_str: no hace falta un separador propio. */
    char args[ARGS_ARRAY];
    u32  args_len;        /* bytes escritos en args, incluidos los separadores */
    u32  args_count;      /* argumentos que se llegaron a copiar */
    u32  args_truncated;  /* 1 si se agotó el búfer o el límite de argumentos */
};

/* Un único ring buffer para todos los sensores: da ordenación global entre tipos
 * de evento, hace menos copias que un buffer por sensor y consume menos CPU. */
BPF_RINGBUF_OUTPUT(events, 64);

/* El ring buffer descarta cuando se llena. Sin este contador la pérdida sería
 * invisible, que es justo lo que pasaba antes al no usar el lost_cb del perf
 * buffer. */
BPF_ARRAY(dropped, u64, 1);

static __always_inline void fill_hdr(struct ev_hdr *hdr, u32 kind) {
    /* Todo campo que pueda no escribirse se inicializa explícitamente. Antes daba
     * igual: el evento se construía en la pila con `= {}` y salía a cero. Al
     * reservar en el ring buffer la memoria NO viene limpia, así que sin esto un
     * campo ausente sería basura de un evento anterior, y el modelo razonaría
     * sobre un número inventado sin saberlo. */
    hdr->ppid = 0;
    hdr->in_target_ns = 0;

    hdr->ts_ns = bpf_ktime_get_ns();
    hdr->uid = (u32)bpf_get_current_uid_gid();
    hdr->cgroup_id = bpf_get_current_cgroup_id();
    hdr->kind = kind;
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));

    /* EL PID HAY QUE TRADUCIRLO DE NAMESPACE.
     *
     * bpf_get_current_pid_tgid() devuelve SIEMPRE el PID del namespace inicial
     * del kernel. WSL2 con systemd ejecuta la sesión dentro de un namespace de
     * PIDs anidado, así que ese número no existe en el /proc que ve el EDR: se
     * midió un desfase de unos 9800 (eBPF decía 45163 donde /proc no tenía nada,
     * con el último PID del namespace en 38684).
     *
     * Con el PID equivocado, TODA la capa de seguridad se cae en silencio:
     * comprobar que el proceso existe, que no es un hilo de kernel, que no está
     * protegido, que el starttime coincide... todo lee otro proceso o ninguno.
     * Y las herramientas forenses devuelven error siempre.
     *
     * bpf_get_ns_current_pid_tgid traduce al namespace identificado por
     * (dev, ino), que se inyectan al compilar desde /proc/self/ns/pid del propio
     * EDR. Devuelve != 0 cuando el proceso NO está en ese namespace —un
     * contenedor, por ejemplo—; en ese caso se conserva el PID global y se marca
     * el evento, porque su número no significa nada para nosotros y no se puede
     * remediar. */
    struct bpf_pidns_info ns = {};
    if (bpf_get_ns_current_pid_tgid(EDR_PIDNS_DEV, EDR_PIDNS_INO,
                                    &ns, sizeof(ns)) == 0) {
        hdr->pid = ns.tgid;
        hdr->in_target_ns = 1;
    } else {
        hdr->pid = bpf_get_current_pid_tgid() >> 32;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    /* El ppid NO se lee aquí. `real_parent->tgid` es el PID global, y traducirlo
     * al namespace del EDR requeriría recorrer `struct pid` a mano: el helper de
     * arriba solo sirve para el proceso actual. Se resuelve en userspace desde
     * /proc, que ya está en la numeración correcta. El precio es perderlo en los
     * procesos de vida muy corta, y es informativo: ninguna decisión depende de
     * él. Hacerlo en la sonda es trabajo para la otra mitad de la fase 3b. */

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
    /* Se reserva en el ring buffer en vez de construir el evento en la pila.
     * No es una preferencia de estilo: la pila de un programa eBPF son 512 bytes
     * y esta struct son 520, así que ni siquiera cabría. Reservar además ahorra
     * la copia que hacía ringbuf_output. */
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

    /* argv es un vector de punteros en espacio de usuario: hay que leer primero el
     * puntero y luego la cadena a la que apunta. Se empieza en 1 porque argv[0] es
     * por convención el propio programa, que ya viaja en filename. */
    const char *const *argv = (const char *const *)(args->argv);

    /* El bucle llega a ARG_COUNT en vez de quedarse en ARG_COUNT-1: esa última
     * vuelta no copia nada, solo mira si quedaban más argumentos, y así el aviso
     * de truncamiento es exacto. Cortando una vuelta antes, una orden con
     * exactamente ARG_COUNT-1 argumentos se marcaría como truncada sin serlo. */
    #pragma unroll
    for (int i = 1; i <= ARG_COUNT; i++) {
        const char *arg = NULL;
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) != 0 || !arg) {
            break;   /* fin del vector: argv termina en un puntero nulo */
        }

        if (i == ARG_COUNT) {
            ev->args_truncated = 1;
            break;
        }

        /* Corte por el espacio ÚTIL. Marcarlo importa: que el modelo sepa que la
         * línea está cortada es distinto de que crea que eso era todo lo que se
         * ejecutó. Esta condición es además la que garantiza que la máscara de
         * abajo nunca envuelve, así que no puede pisar lo ya escrito. */
        if (ev->args_len >= ARGS_BUF) {
            ev->args_truncated = 1;
            break;
        }

        int n = bpf_probe_read_user_str(&ev->args[ev->args_len & (ARGS_BUF - 1)],
                                        ARG_LEN, arg);
        if (n <= 0) {
            break;
        }

        /* n incluye el '\\0', que queda como separador entre argumentos. */
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
        ("in_target_ns", ct.c_uint32),
        ("comm", ct.c_char * 16),
    ]


class ModuleEvent(ct.Structure):
    _fields_ = [("hdr", EvHdr)]


# Deben coincidir con los #define del programa en C. El test comprueba el tamaño
# de la struct, que es lo que ataría cualquier divergencia entre ambos.
ARGS_BUF = 256                      # espacio útil
ARG_LEN = 64                        # por argumento
ARGS_ARRAY = ARGS_BUF + ARG_LEN     # lo que se declara: la holgura es del verificador
ARG_COUNT = 16


class ExecEvent(ct.Structure):
    _fields_ = [
        ("hdr", EvHdr),
        ("filename", ct.c_char * 128),
        # c_ubyte y no c_char: un array de c_char se lee hasta el primer '\0' y
        # aquí el '\0' es justamente el separador entre argumentos, así que
        # devolvería solo el primero de ellos.
        ("args", ct.c_ubyte * ARGS_ARRAY),
        ("args_len", ct.c_uint32),
        ("args_count", ct.c_uint32),
        ("args_truncated", ct.c_uint32),
    ]


def _decode(raw):
    return raw.decode(errors="replace").strip("\x00")


def decode_cmdline(raw, args_len, truncated=False):
    """Reconstruye la línea de órdenes a partir del búfer crudo de la sonda.

    Se corta por `args_len` en vez de por el final del búfer: la memoria que
    reserva el ring buffer no viene a cero, así que más allá de lo escrito hay
    basura de eventos anteriores. Leer de más significaría enseñarle al modelo
    fragmentos de otras órdenes como si fueran de ésta.
    """
    args_len = max(0, min(int(args_len), len(raw)))
    if not args_len:
        return "…" if truncated else ""

    trozos = bytes(raw[:args_len]).split(b"\x00")
    partes = [t.decode(errors="replace") for t in trozos if t]
    if truncated:
        partes.append("…")
    return " ".join(partes)


def _hdr_fields(hdr):
    """Campos comunes que se guardan en el almacén de eventos."""
    # El ppid se resuelve aquí, no en la sonda: la sonda solo puede dar el PID
    # global del padre, que en un namespace anidado no significa nada para /proc.
    # Se pierde en los procesos de vida muy corta, y se acepta: es informativo.
    padre = procinfo.read_stat(hdr.pid) if hdr.in_target_ns else None

    return {
        "pid": hdr.pid,
        "ppid": padre["ppid"] if padre else None,
        "uid": hdr.uid,
        "comm": _decode(hdr.comm),
        # Se convierte a ticks aquí, no en el kernel: el evento sigue llevando el
        # campo `starttime` con la misma semántica y unidades que antes, así que
        # ni safety.py ni procinfo.py necesitan cambiar.
        "starttime": procinfo.ns_to_ticks(hdr.start_boottime),
        "cgroup_id": hdr.cgroup_id,
        # Un proceso de otro namespace se registra —tiene valor forense— pero su
        # PID no es interpretable desde aquí y no se puede señalizar, así que no
        # puede convertirse en alerta.
        "foreign_ns": not hdr.in_target_ns,
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
        fields["cmdline"] = decode_cmdline(ev.args, ev.args_len,
                                           bool(ev.args_truncated))

        # En sys_enter_execve el kernel todavía no ha cambiado el nombre del
        # proceso, así que `comm` es el de QUIEN LLAMA, no el del programa que se
        # va a ejecutar: por eso en la telemetría aparecían cosas como
        # `comm=sh filename=/usr/bin/ollama`. El nombre real ya viaja en
        # `filename`; se renombra el campo para que el dato deje de mentir.
        # El arreglo de fondo es emitir el evento en sched_process_exec, que
        # corre cuando el cambio ya ha ocurrido.
        fields["caller_comm"] = fields.pop("comm")

        # El triaje se evalúa aquí, una sola vez por evento, y su resultado viaja
        # con él: así el filtrado de alertas no tiene que reevaluar miles de
        # eventos en cada vuelta del bucle de decisión.
        severidad, reglas = triage.assess(fields)
        if reglas:
            fields["severity"] = severidad
            fields["rules_fired"] = ",".join(reglas)
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
