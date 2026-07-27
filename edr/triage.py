"""Triaje determinista: decide qué eventos merecen molestar al modelo.

**El hueco que cierra.** Hasta ahora el bucle de decisión solo se disparaba con
cargas de módulo: `get_kernel_alerts()` devolvía únicamente eventos
`module_load`. El sensor de execve, que produce el 99 % de la telemetría, no
iniciaba nunca un ciclo — solo aportaba evidencia en la ronda 2 de una
investigación que ya estaba en marcha por otro motivo. Es decir, un proceso
malicioso podía ejecutarse delante del EDR sin que éste llegara a preguntarse
nada.

Lo evidente sería mandarle al modelo todos los execve. No sirve: en esta máquina
se midieron 3601 en una sesión corta, la inmensa mayoría de VS Code sondeando
`git` y de Docker lanzando `runc`. Ahogarían el prompt y el coste por ciclo, y
sobre todo diluirían la señal entre ruido.

De ahí este módulo: **reglas deterministas que puntúan, y un umbral que decide a
quién se le pregunta al modelo**. Es la forma que tendrá la Fase 5 completa
—reglas, ATT&CK y línea base del host—, aquí en su versión mínima. La división de
trabajo es deliberada y es el argumento central del diseño híbrido: lo barato y
objetivo lo resuelve una regla, y el razonamiento caro se reserva para lo que ya
ha demostrado ser sospechoso.

**Las ponderaciones están pensadas para que una sola señal débil no escale.**
Ejecutar desde `/tmp` es común y legítimo; ejecutar desde `/tmp` un binario cuyo
nombre empieza por punto, ya no. Dos señales débiles superan el umbral, una no.

Los slugs de las reglas son estables y legibles por máquina, igual que los de
`safety.py`: se agregan en las estadísticas del laboratorio y aparecen en la
columna `rules_fired`, así que renombrarlos rompería la comparación entre
ejecuciones.
"""

import ipaddress
import os
import re

from . import config

# ──────────────────────────────────────────────
# Ponderaciones
# ──────────────────────────────────────────────

# Directorios donde puede escribir cualquiera. Que un binario se ejecute desde
# aquí no es malo por sí solo, pero sí es donde aterriza casi todo lo que se
# descarga.
WORLD_WRITABLE = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")

DOWNLOADERS = frozenset({"curl", "wget"})
NETCATS = frozenset({"nc", "ncat", "netcat", "nc.traditional"})

# La tubería a un shell tal cual aparece en la línea de órdenes. Solo se ve cuando
# alguien invoca `sh -c "…"`, que es justamente como se ejecutan los droppers.
_PIPE_TO_SHELL = re.compile(r"\|\s*(?:/[\w/]*/)?(?:ba|da|z|k|a)?sh\b")

# Redirección de un shell a un socket: la forma canónica de una reverse shell en
# bash sin herramientas externas.
_NET_REDIRECT = re.compile(r"/dev/(?:tcp|udp)/")

_URL = re.compile(r"https?://([^/\s:]+)")

# Peso de cada regla. El umbral vive en config para poder moverlo sin tocar código.
WEIGHTS = {
    "exec_from_world_writable": 40,
    "hidden_binary": 30,
    "pipe_to_shell": 40,
    "downloader_to_shell": 60,
    "download_from_public_ip": 50,
    "shell_net_redirect": 60,
    "netcat_exec": 60,
}


# ──────────────────────────────────────────────
# Reglas
# ──────────────────────────────────────────────

def _is_public_ip(host):
    """True si `host` es una IP literal y además encaminable por internet.

    Que la URL apunte a una IP en crudo en vez de a un dominio es la señal: el
    software legítimo usa nombres. Pero hay que excluir loopback y redes privadas
    o la regla se dispararía con la propia infraestructura — en esta máquina,
    cualquier `curl http://127.0.0.1:11434/…` contra Ollama.
    """
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False   # es un dominio
    return ip.is_global


def assess(event):
    """Puntúa un evento execve. Devuelve `(severidad, [slugs de reglas])`.

    Función pura: no toca `/proc`, ni la red, ni el reloj. Eso la hace testeable
    sin root y determinista, que es lo que permite defender por qué escaló cada
    proceso en la memoria del trabajo.
    """
    filename = (event.get("filename") or "").strip()
    cmdline = (event.get("cmdline") or "").strip()

    if not filename and not cmdline:
        return 0, []

    base = os.path.basename(filename)
    reglas = []

    if filename.startswith(WORLD_WRITABLE):
        reglas.append("exec_from_world_writable")

    if base.startswith(".") and base not in (".", ".."):
        reglas.append("hidden_binary")

    hay_tuberia = bool(_PIPE_TO_SHELL.search(cmdline))
    if hay_tuberia:
        reglas.append("pipe_to_shell")

    # Un descargador puede aparecer como el propio binario ejecutado o citado
    # dentro de la orden de un `sh -c`, que es el caso habitual del dropper.
    menciona_descargador = base in DOWNLOADERS or any(
        re.search(rf"\b{d}\b", cmdline) for d in DOWNLOADERS)

    if menciona_descargador and hay_tuberia:
        reglas.append("downloader_to_shell")

    if menciona_descargador:
        for host in _URL.findall(cmdline):
            if _is_public_ip(host):
                reglas.append("download_from_public_ip")
                break

    if _NET_REDIRECT.search(cmdline):
        reglas.append("shell_net_redirect")

    if base in NETCATS and re.search(r"(?:^|\s)-\w*[ec]", cmdline):
        reglas.append("netcat_exec")

    return sum(WEIGHTS[r] for r in reglas), reglas


def should_escalate(event, threshold=None):
    """True si el evento merece consultarle al modelo."""
    threshold = config.TRIAGE_THRESHOLD if threshold is None else threshold
    severidad, _ = assess(event)
    return severidad >= threshold


def is_alert(event, threshold=None):
    """True si el evento debe entrar en `get_kernel_alerts()`.

    Las cargas de módulo escalan siempre: son intrínsecamente privilegiadas, hay
    pocas y son el caso que el sistema venía tratando desde el principio. Los
    execve pasan por el triaje.
    """
    # Un proceso de otro namespace de PIDs no es interpretable ni remediable desde
    # aquí: su número no corresponde a nada en nuestro /proc y no se le puede
    # enviar una señal. Se conserva en el registro forense, pero escalarlo sería
    # pedirle al modelo que decida sobre algo que el sistema no puede tocar.
    if event.get("foreign_ns"):
        return False

    if event.get("kind") == config.KIND_MODULE_LOAD:
        return True
    if event.get("kind") != config.KIND_EXECVE:
        return False

    threshold = config.TRIAGE_THRESHOLD if threshold is None else threshold

    # La severidad se calcula una sola vez, al recibir el evento, y viaja con él.
    # Recalcularla en cada consulta significaría reevaluar miles de eventos en
    # cada vuelta del bucle. El recálculo queda solo como red de seguridad para
    # eventos que no hayan pasado por el sensor (tests, reproducciones).
    severidad = event.get("severity")
    if severidad is None:
        severidad, _ = assess(event)
    return severidad >= threshold
