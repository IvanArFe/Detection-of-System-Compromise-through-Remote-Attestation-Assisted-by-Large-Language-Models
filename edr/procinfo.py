"""Lectura de /proc: identidad estable de proceso.

Funciones puras, sin BCC y sin estado global, para que sean testeables sin root.
Ninguna lanza excepción: ante un proceso inexistente o inaccesible devuelven
`None` o un valor vacío. Un sensor no puede caerse porque un proceso muriera
entre dos lecturas — que es lo normal en /proc, no la excepción.

**La idea central:** el identificador real de un proceso no es el PID, sino el par
`(pid, starttime)`. El kernel recicla los PID; `starttime` (campo 22 de
/proc/{pid}/stat, en jiffies desde el arranque) es inmutable durante toda la vida
del proceso. Comparar ese par antes de señalizar es lo que impide matar a un
proceso inocente que heredó el PID de un malicioso.
"""

import os

# Raíz del pseudo-sistema de ficheros. Es una variable y no una constante literal
# para que los tests puedan apuntarla a un /proc sintético: WSL2 no expone hilos
# de kernel, así que casos como PF_KTHREAD no se pueden reproducir contra el /proc
# real de esta máquina. Con esto se testean de forma determinista y en cualquier
# entorno.
PROC = "/proc"

# Campos de /proc/{pid}/stat, indexados DESPUÉS del `comm` entre paréntesis.
# El fichero es: pid (comm) state ppid pgrp ... y la numeración oficial empieza
# en 1 para `pid`, así que el índice aquí es (número_de_campo - 3).
_STAT_STATE = 0       # campo 3
_STAT_PPID = 1        # campo 4
_STAT_FLAGS = 6       # campo 9
_STAT_STARTTIME = 19  # campo 22

# Un proceso del kernel no tiene espacio de usuario: señalizarlo no tiene sentido.
PF_KTHREAD = 0x00200000

# Cota de seguridad al recorrer la cadena de ancestros. /proc no debería contener
# ciclos, pero un bucle infinito dentro del EDR sería un fallo peor que el que
# intenta evitar.
_MAX_ANCESTRY_DEPTH = 64

# Nanosegundos por tick de reloj. El campo 22 de /proc/{pid}/stat viene en ticks
# (100 por segundo en este sistema), mientras que en eBPF la identidad se lee de
# `task->start_boottime`, que está en nanosegundos. Se calcula en vez de fijarlo:
# USER_HZ no es 100 en todos los kernels.
NS_PER_TICK = 1_000_000_000 // os.sysconf("SC_CLK_TCK")


def ns_to_ticks(ns):
    """Convierte `task->start_boottime` a las unidades del campo 22 de /proc.

    Es exactamente la misma operación que hace el kernel en `nsec_to_clock_t()`,
    una división entera, así que el resultado coincide al tick con lo que devuelve
    `/proc`. Verificado contra `/proc/uptime` con diferencia 0,00 s.

    Se usa `start_boottime` y no `start_time`: desde la 5.5 el kernel calcula el
    campo 22 a partir del primero, y difieren en el tiempo que la máquina pasa
    suspendida.
    """
    if ns is None:
        return None
    return int(ns) // NS_PER_TICK


def read_stat(pid):
    """Devuelve {comm, state, ppid, starttime, flags} o None si no se puede leer.

    El parseo es la parte delicada: `comm` puede contener espacios y paréntesis
    (en esta misma máquina existen procesos llamados `(sd-pam)` y `Relay(203)`),
    así que hay que cortar por el ÚLTIMO paréntesis de cierre. Cortar por el
    primero, o hacer un `split()` ingenuo, desplaza todos los campos y devuelve
    un `starttime` incorrecto SIN error — que es exactamente la clase de fallo
    silencioso que no puede permitirse algo de lo que dependen las decisiones de
    seguridad.
    """
    try:
        with open(f"{PROC}/{pid}/stat", "rb") as f:
            raw = f.read().decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return None

    open_paren = raw.find("(")
    close_paren = raw.rfind(")")
    if open_paren == -1 or close_paren == -1 or close_paren < open_paren:
        return None

    comm = raw[open_paren + 1:close_paren]
    rest = raw[close_paren + 1:].split()
    if len(rest) <= _STAT_STARTTIME:
        return None

    try:
        return {
            "comm": comm,
            "state": rest[_STAT_STATE],
            "ppid": int(rest[_STAT_PPID]),
            "flags": int(rest[_STAT_FLAGS]),
            "starttime": int(rest[_STAT_STARTTIME]),
        }
    except (ValueError, IndexError):
        return None


def starttime(pid):
    """Instante de arranque del proceso en jiffies, o None si no existe."""
    stat = read_stat(pid)
    return stat["starttime"] if stat else None


def comm(pid):
    """Nombre corto del proceso, o None."""
    stat = read_stat(pid)
    return stat["comm"] if stat else None


def proc_key(pid):
    """Identidad estable como cadena: "4711:195964". None si el proceso no existe."""
    st = starttime(pid)
    return None if st is None else f"{pid}:{st}"


def is_alive(pid, expected_starttime):
    """True si el PID sigue siendo EL MISMO proceso que cuando se capturó el evento.

    Un `expected_starttime` en None significa que no se pudo capturar la identidad
    (el proceso ya había muerto al procesar el evento). En ese caso no se puede
    afirmar la identidad, así que se devuelve False: ante la duda, no se actúa.
    """
    if expected_starttime is None:
        return False
    return starttime(pid) == expected_starttime


def is_kernel_thread(pid):
    """True si es un hilo de kernel.

    Se mira el flag PF_KTHREAD de la task, que es la señal autoritativa. Si no se
    puede leer el stat, se recurre a /proc/{pid}/exe: los hilos de kernel no
    tienen ejecutable que resolver.
    """
    stat = read_stat(pid)
    if stat is not None:
        return bool(stat["flags"] & PF_KTHREAD)
    try:
        os.readlink(f"{PROC}/{pid}/exe")
        return False
    except OSError:
        return True


def ancestors(pid):
    """Cadena de ancestros desde el padre de `pid` hasta PID 1, en orden ascendente.

    Se usa para la autoprotección: el EDR no puede señalizar a ninguno de sus
    propios ancestros. En este sistema el servidor MCP es hijo del orquestador,
    así que recorrer la cadena cubre ambos con una sola comprobación.
    """
    chain = []
    seen = set()
    current = pid
    for _ in range(_MAX_ANCESTRY_DEPTH):
        stat = read_stat(current)
        if stat is None:
            break
        parent = stat["ppid"]
        if parent <= 0 or parent in seen:
            break
        chain.append(parent)
        seen.add(parent)
        if parent == 1:
            break
        current = parent
    return chain


def _read_uid(pid):
    """UID real del proceso, leído de la línea `Uid:` de /proc/{pid}/status."""
    try:
        with open(f"{PROC}/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def cmdline(pid):
    """Línea de comandos completa. /proc la entrega separada por bytes nulos.

    Es lo que distingue `curl https://api.empresa.com/health` de
    `curl -s http://45.33.x.x/x.sh`, que para el `comm` son idénticos.
    """
    try:
        with open(f"{PROC}/{pid}/cmdline", "rb") as f:
            raw = f.read()
    except OSError:
        return None
    if not raw:
        return ""
    parts = raw.split(b"\x00")
    return " ".join(p.decode("utf-8", errors="replace") for p in parts if p)


def snapshot(pid):
    """Retrato del proceso en un instante, o None si ya no existe.

    `exe_deleted` merece atención: un ejecutable borrado mientras sigue corriendo
    es omnipresente en malware moderno, y detectarlo no cuesta nada porque el
    propio kernel añade el sufijo " (deleted)" al enlace.
    """
    stat = read_stat(pid)
    if stat is None:
        return None

    try:
        exe = os.readlink(f"{PROC}/{pid}/exe")
    except OSError:
        exe = None

    try:
        cwd = os.readlink(f"{PROC}/{pid}/cwd")
    except OSError:
        cwd = None

    return {
        "pid": pid,
        "comm": stat["comm"],
        "ppid": stat["ppid"],
        "state": stat["state"],
        "starttime": stat["starttime"],
        "proc_key": f"{pid}:{stat['starttime']}",
        "uid": _read_uid(pid),
        "exe": exe,
        "exe_deleted": bool(exe and exe.endswith(" (deleted)")),
        "cmdline": cmdline(pid),
        "cwd": cwd,
        "kernel_thread": bool(stat["flags"] & PF_KTHREAD),
    }
