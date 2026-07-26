"""Salvaguardas de remediación: lo que el EDR NO puede hacer.

Hasta ahora `remediate_incident` hacía `os.kill(pid, SIGKILL)` sin una sola
comprobación. Un modelo de 8B que alucina un PID, o un atacante que consigue
inyectar texto en el prompt, podía ordenar la muerte de PID 1, del propio
orquestador o del sensor.

Este módulo es la capa determinista que acota lo probabilístico. El LLM propone;
estas reglas disponen. Y **toda tentativa queda registrada, incluidas las
denegadas y su motivo**: sin esa traza no se puede demostrar que las salvaguardas
se activaron, y "el modelo propuso matar systemd y la capa de seguridad lo
bloqueó" es un resultado, no un incidente.
"""

import logging
import os
import signal as signal_module
import threading
import time
from collections import deque, namedtuple

from . import config
from . import procinfo

log = logging.getLogger("edr.safety")

Verdict = namedtuple("Verdict", ["allowed", "reason", "detail"])

# Registro de tentativas para auditoría. Acotado: es una traza de diagnóstico, no
# el almacén de evidencia (de eso se encarga la base de datos).
_ATTEMPTS = deque(maxlen=200)
_ATTEMPTS_LOCK = threading.Lock()


class RateLimiter:
    """Ventana deslizante sobre las remediaciones aprobadas.

    Existe para acotar el daño de un bucle de alucinación: si el modelo se
    engancha proponiendo matar procesos, el límite corta antes de que arrase la
    máquina. El reloj es inyectable para poder testear la ventana sin esperas
    reales.
    """

    def __init__(self, max_n=None, window_s=None, clock=time.monotonic):
        self.max_n = config.RATE_LIMIT_MAX if max_n is None else max_n
        self.window_s = config.RATE_LIMIT_WINDOW_S if window_s is None else window_s
        self._clock = clock
        self._hits = deque()
        self._lock = threading.Lock()

    def _prune(self, now):
        while self._hits and now - self._hits[0] > self.window_s:
            self._hits.popleft()

    def would_allow(self):
        with self._lock:
            now = self._clock()
            self._prune(now)
            return len(self._hits) < self.max_n

    def record(self):
        with self._lock:
            now = self._clock()
            self._prune(now)
            self._hits.append(now)

    def reset(self):
        with self._lock:
            self._hits.clear()


# Limitador por defecto del proceso. Los tests crean el suyo propio.
_DEFAULT_LIMITER = RateLimiter()


def validate_remediation(pid, action, expected_starttime=None,
                         self_pid=None, limiter=None):
    """Decide si una remediación puede ejecutarse. No ejecuta nada.

    Devuelve un `Verdict(allowed, reason, detail)`. El `reason` es un identificador
    estable pensado para agregarse en las estadísticas del laboratorio, no un
    mensaje para humanos.
    """
    limiter = _DEFAULT_LIMITER if limiter is None else limiter
    self_pid = os.getpid() if self_pid is None else self_pid

    # 1. PIDs que no designan un proceso concreto.
    #    Es la comprobación más importante de la lista: os.kill(0, sig) señaliza
    #    al GRUPO DE PROCESOS ENTERO del EDR, que corre como root; los negativos
    #    señalizan grupos arbitrarios; y 1 es systemd.
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return Verdict(False, "invalid_pid", f"pid={pid!r} no designa un proceso remediable")

    if action not in config.VALID_ACTIONS:
        return Verdict(False, "invalid_action",
                       f"acción {action!r}; permitidas: {list(config.VALID_ACTIONS)}")

    stat = procinfo.read_stat(pid)
    if stat is None:
        return Verdict(False, "no_such_process", f"el PID {pid} ya no existe")

    # 3. Autoprotección. El servidor MCP es hijo del orquestador, así que recorrer
    #    la cadena de ancestros cubre a ambos con una sola comprobación. Es el
    #    equivalente a las self-protection rules de un EDR comercial.
    if pid == self_pid:
        return Verdict(False, "self_protection", "el PID es el propio proceso del EDR")
    chain = procinfo.ancestors(self_pid)
    if pid in chain:
        return Verdict(False, "self_protection",
                       f"el PID {pid} es un ancestro del EDR (cadena: {chain})")

    if stat["flags"] & procinfo.PF_KTHREAD:
        return Verdict(False, "kernel_thread",
                       f"{stat['comm']} es un hilo de kernel, no tiene espacio de usuario")

    if stat["comm"] in config.PROTECTED_COMMS:
        return Verdict(False, "protected_process",
                       f"{stat['comm']} está en la lista de procesos protegidos")

    # 6. Anti-reutilización de PID. Entre la captura del evento y este instante han
    #    pasado decenas de segundos, tiempo de sobra para que el kernel reciclara
    #    el PID y se lo diera a un proceso inocente. El `starttime` viaja con la
    #    alerta desde la captura; si no coincide, no es el mismo proceso.
    #
    #    Sin `starttime` NO se remedia. Podría parecer excesivo, pero la alternativa
    #    es señalizar un PID cuya identidad no se ha podido establecer, que es
    #    precisamente el fallo que esta comprobación existe para evitar: media
    #    validación no vale de nada. Se descubrió en la verificación de la Fase 1,
    #    donde el 100% de los eventos de carga de módulo llegaban sin identidad
    #    porque `modprobe` muere antes de que el callback de userspace pueda leer
    #    su /proc. La solución de fondo —capturar la identidad dentro de la propia
    #    sonda eBPF— es de la Fase 3; hasta entonces, se falla en cerrado.
    if expected_starttime is None:
        return Verdict(False, "identity_unknown",
                       f"no se capturó la identidad del PID {pid}: no se puede "
                       f"verificar que siga siendo el mismo proceso")

    if stat["starttime"] != expected_starttime:
        return Verdict(False, "pid_reused",
                       f"starttime esperado {expected_starttime}, actual {stat['starttime']}: "
                       f"el PID {pid} pertenece ahora a otro proceso ({stat['comm']})")

    # 7. El límite de tasa va el último a propósito: una propuesta inválida no debe
    #    consumir presupuesto de remediación.
    if not limiter.would_allow():
        return Verdict(False, "rate_limited",
                       f"más de {limiter.max_n} remediaciones en {limiter.window_s:.0f}s")

    return Verdict(True, "ok", f"{stat['comm']} (pid={pid}, starttime={stat['starttime']})")


def remediate(pid, action, expected_starttime=None, reason="",
              mode=None, signal_fn=None, limiter=None, self_pid=None):
    """Valida y, si procede y el modo lo permite, señaliza el proceso.

    En `dry-run` se recorre exactamente el mismo camino salvo el envío de la señal.
    Eso es deliberado: para que las métricas del laboratorio en dry-run sean
    comparables con las de autonomous, ambos modos deben tomar las mismas
    decisiones y consumir el mismo presupuesto de remediación.
    """
    mode = config.EDR_MODE if mode is None else mode
    signal_fn = os.kill if signal_fn is None else signal_fn
    limiter = _DEFAULT_LIMITER if limiter is None else limiter

    verdict = validate_remediation(pid, action, expected_starttime,
                                   self_pid=self_pid, limiter=limiter)

    record = {
        "ts": time.time(),
        "pid": pid,
        "action": action,
        "reason": reason,
        "mode": mode,
        "allowed": verdict.allowed,
        "verdict": verdict.reason,
        "detail": verdict.detail,
    }

    if not verdict.allowed:
        record["outcome"] = "denied"
        _remember(record)
        log.warning("REMEDIACIÓN DENEGADA pid=%s action=%s motivo=%s (%s)",
                    pid, action, verdict.reason, verdict.detail)
        return record

    limiter.record()

    if mode == config.MODE_DRY_RUN:
        record["outcome"] = "dry_run"
        _remember(record)
        log.info("[DRY-RUN] se habría enviado %s a %s — NO se envió ninguna señal",
                 action.upper(), verdict.detail)
        return record

    sig = signal_module.SIGSTOP if action == "freeze" else signal_module.SIGKILL
    try:
        signal_fn(pid, sig)
        record["outcome"] = "executed"
        log.warning("REMEDIACIÓN EJECUTADA %s sobre %s", action.upper(), verdict.detail)
    except ProcessLookupError:
        record["outcome"] = "vanished"
        record["detail"] = f"el PID {pid} murió entre la validación y la señal"
    except PermissionError:
        record["outcome"] = "permission_denied"
        record["detail"] = f"sin permisos para señalizar el PID {pid}: ¿se ejecuta como root?"
    except OSError as e:
        record["outcome"] = "error"
        record["detail"] = str(e)

    _remember(record)
    return record


def _remember(record):
    with _ATTEMPTS_LOCK:
        _ATTEMPTS.append(record)


def attempts():
    """Todas las tentativas registradas, aprobadas y denegadas."""
    with _ATTEMPTS_LOCK:
        return list(_ATTEMPTS)


def describe(record):
    """Convierte el registro de una tentativa en una línea para el operador y el LLM."""
    if record["outcome"] == "denied":
        return f"[BLOQUEADO] {record['verdict']}: {record['detail']}"
    if record["outcome"] == "dry_run":
        return (f"[DRY-RUN] validado ({record['detail']}). No se envió ninguna señal. "
                f"Para actuar de verdad: EDR_MODE=autonomous")
    if record["outcome"] == "executed":
        verb = "congelado (SIGSTOP)" if record["action"] == "freeze" else "terminado (SIGKILL)"
        return f"[EJECUTADO] proceso {verb}: {record['detail']}"
    return f"[{record['outcome'].upper()}] {record['detail']}"
