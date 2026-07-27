"""Tests del esquema de evento y del arranque de los sensores.

No se carga eBPF: lo que se comprueba es que el espejo en ctypes cuadra con la
estructura de C, que el despacho por tipo de evento funciona, y que el arranque
tolera una sonda indisponible.

La compilación real del programa en C **no se puede verificar sin root**: BCC
obtiene las cabeceras del kernel cargando el módulo `kheaders`, cosa que requiere
privilegios. Para eso está `scripts/check_sensor.py`.
"""

import ctypes as ct

import pytest

import forensic_mcp
from edr import config, procinfo
from edr.eventstore import EventStore


@pytest.fixture
def store(monkeypatch, tmp_path):
    s = EventStore(None, cap=100)
    monkeypatch.setattr(forensic_mcp, "STORE", s)
    # El sensor resuelve el ppid leyendo /proc. Se apunta a un árbol vacío para
    # que los PIDs de prueba no coincidan por casualidad con procesos reales de
    # la máquina y los tests dejen de ser deterministas.
    monkeypatch.setattr(procinfo, "PROC", str(tmp_path))
    return s


def _buffer(struct_obj):
    """Puntero al struct, como el que entrega el ring buffer."""
    return ct.cast(ct.pointer(struct_obj), ct.c_void_p)


def _hdr(kind, pid=100, ppid=1, uid=1000, comm=b"modprobe", start_boottime=0,
         cgroup_id=0, in_target_ns=1):
    return forensic_mcp.EvHdr(
        ts_ns=123456789, start_boottime=start_boottime, cgroup_id=cgroup_id,
        pid=pid, ppid=ppid, uid=uid, kind=kind, in_target_ns=in_target_ns,
        comm=comm,
    )


# ── Espejo de ctypes ───────────────────────────────────────────

def test_la_cabecera_cuadra_con_la_struct_de_c():
    """Si C y ctypes discrepan en tamaño, los campos se leerían desplazados.

    Los u64 van primero para que no haya relleno INTERMEDIO, que es el que
    desplazaría campos. Los 4 bytes de cola (3·8 + 5·4 + 16 = 60, redondeado a 64
    por la alineación a 8 que imponen los u64) los añaden igual C y ctypes, así
    que no rompen nada.
    """
    assert ct.sizeof(forensic_mcp.EvHdr) == 64


def test_el_evento_de_exec_cuadra_byte_a_byte_con_la_struct_de_c():
    """64 de cabecera + 128 de nombre + 320 de argumentos + 3 u32, alineado a 8.

    Se fija el número entero además de la suma: si alguien reordena los campos y
    aparece relleno intermedio, la suma podría seguir cuadrando y el tamaño no.
    """
    assert ct.sizeof(forensic_mcp.ExecEvent) == 528

    offsets = {n: getattr(forensic_mcp.ExecEvent, n).offset
               for n, _ in forensic_mcp.ExecEvent._fields_}
    assert offsets == {"hdr": 0, "filename": 64, "args": 192,
                       "args_len": 512, "args_count": 516, "args_truncated": 520}


def test_el_buffer_de_argumentos_deja_holgura_para_el_verificador():
    """Regresión: el verificador rechazó el programa por 47 bytes.

    Razona sobre el objeto reservado entero, no sobre el campo. Con la máscara
    `& (ARGS_BUF - 1)` sólo sabe que el desplazamiento va de 0 a 255, así que
    calcula el caso peor —empezar en el último byte útil y copiar ARG_MAX— y
    exige que quepa. El corte en tiempo de ejecución no lo ve.

        invalid access to memory, mem_size=456 off=439 size=64

    Esta comprobación es la misma cuenta que hace el verificador.
    """
    inicio = forensic_mcp.ExecEvent.args.offset
    peor_caso = inicio + (forensic_mcp.ARGS_BUF - 1) + forensic_mcp.ARG_LEN

    assert peor_caso <= ct.sizeof(forensic_mcp.ExecEvent)


def test_los_argumentos_no_se_leen_como_c_char():
    """Un array de c_char se corta en el primer '\\0', y aquí el '\\0' separa.

    Con c_char solo se recuperaría el primer argumento de la orden, en silencio.
    """
    tipo = dict(forensic_mcp.ExecEvent._fields_)["args"]
    assert tipo._type_ is ct.c_ubyte


def test_los_desplazamientos_son_los_esperados():
    offsets = {n: getattr(forensic_mcp.EvHdr, n).offset
               for n, _ in forensic_mcp.EvHdr._fields_}
    assert offsets == {"ts_ns": 0, "start_boottime": 8, "cgroup_id": 16,
                       "pid": 24, "ppid": 28, "uid": 32, "kind": 36,
                       "in_target_ns": 40, "comm": 44}


# ── Despacho por tipo de evento ────────────────────────────────

def test_un_evento_de_modulo_se_guarda_como_tal(store):
    ev = forensic_mcp.ModuleEvent(hdr=_hdr(forensic_mcp.KIND_MODULE_LOAD))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    guardado = store.query()[0]
    assert guardado["kind"] == config.KIND_MODULE_LOAD
    assert guardado["pid"] == 100
    assert guardado["comm"] == "modprobe"
    assert "detail" in guardado


def _args(*argumentos):
    """Construye el búfer tal y como lo deja `bpf_probe_read_user_str`.

    El relleno NO es a ceros a propósito: la memoria del ring buffer llega sucia y
    los tests deben ejercitar esa condición, no una versión idealizada.
    """
    crudo = b"".join(a + b"\x00" for a in argumentos)
    buf = (ct.c_ubyte * forensic_mcp.ARGS_ARRAY)(
        *([0x41] * forensic_mcp.ARGS_ARRAY))
    for i, b in enumerate(crudo):
        buf[i] = b
    return buf, len(crudo)


def _exec_event(filename=b"/bin/sh", argumentos=(), truncado=0, **hdr_kwargs):
    buf, longitud = _args(*argumentos)
    return forensic_mcp.ExecEvent(
        hdr=_hdr(forensic_mcp.KIND_EXECVE, **hdr_kwargs),
        filename=filename, args=buf, args_len=longitud,
        args_count=len(argumentos), args_truncated=truncado,
    )


def test_un_evento_de_exec_lleva_el_nombre_del_binario(store):
    ev = _exec_event(filename=b"/usr/sbin/modprobe", pid=200, comm=b"sudo")
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    guardado = store.query()[0]
    assert guardado["kind"] == config.KIND_EXECVE
    assert guardado["filename"] == "/usr/sbin/modprobe"


def test_en_un_exec_el_comm_es_el_de_quien_llama(store):
    """En sys_enter_execve el kernel aún no ha cambiado el nombre del proceso.

    Por eso en la telemetría aparecían líneas como `comm=sh filename=/usr/bin/ollama`:
    `sh` era el shell que lanzaba, no lo que se ejecutaba. Se renombra el campo para
    que el dato no se pueda confundir con el nombre del programa.
    """
    ev = _exec_event(filename=b"/usr/bin/ollama", comm=b"sh")
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    guardado = store.query()[0]
    assert guardado["caller_comm"] == "sh"
    assert "comm" not in guardado


def test_el_comm_de_una_carga_de_modulo_no_se_renombra(store):
    """Ahí `comm` sí ES el proceso: no hay exec de por medio."""
    ev = forensic_mcp.ModuleEvent(
        hdr=_hdr(forensic_mcp.KIND_MODULE_LOAD, comm=b"modprobe"))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["comm"] == "modprobe"


# ── Línea de órdenes ───────────────────────────────────────────

def test_la_linea_de_ordenes_llega_entera_y_en_orden(store):
    ev = _exec_event(filename=b"/usr/bin/curl",
                     argumentos=(b"-s", b"http://x/y.sh"))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["cmdline"] == "-s http://x/y.sh"


def test_no_se_lee_mas_alla_de_lo_que_escribio_la_sonda():
    """Regresión: la memoria del ring buffer no viene a cero.

    Si se leyera hasta el final del búfer en vez de hasta `args_len`, al modelo le
    llegarían restos de órdenes anteriores mezclados con la actual, presentados
    como si fueran del mismo proceso.
    """
    buf, longitud = _args(b"-s")
    assert forensic_mcp.decode_cmdline(buf, longitud) == "-s"
    assert "A" not in forensic_mcp.decode_cmdline(buf, longitud)


def test_un_args_len_imposible_no_desborda():
    """La longitud la escribe el kernel, pero leer de más no puede ser una opción."""
    buf, _ = _args(b"-s")
    assert forensic_mcp.decode_cmdline(buf, 10 ** 9)
    assert forensic_mcp.decode_cmdline(buf, -5) == ""


def test_una_orden_sin_argumentos_no_inventa_nada(store):
    ev = _exec_event(filename=b"/bin/sh")
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["cmdline"] == ""


def test_el_truncamiento_se_le_dice_al_modelo(store):
    """Que sepa que vio parte de la orden es distinto de que crea que la vio entera."""
    ev = _exec_event(filename=b"/bin/sh", argumentos=(b"-c", b"algo"), truncado=1)
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["cmdline"] == "-c algo …"


def test_un_argumento_vacio_no_rompe_la_linea():
    buf, longitud = _args(b"-c", b"", b"ls")
    assert forensic_mcp.decode_cmdline(buf, longitud) == "-c ls"


# ── Namespace de PIDs ──────────────────────────────────────────

def test_el_ppid_se_resuelve_desde_proc(store, fake_proc):
    """La sonda no puede darlo en la numeración correcta; /proc sí.

    `real_parent->tgid` es el PID del namespace inicial del kernel, y el helper
    que traduce solo funciona para el proceso actual, no para su padre.
    """
    fake_proc(pid=200, comm="sh", ppid=199)

    ev = _exec_event(filename=b"/usr/bin/curl", pid=200)
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["ppid"] == 199


def test_un_proceso_ya_muerto_deja_el_ppid_en_nulo(store):
    """Precio aceptado del arreglo: informativo, ninguna decisión depende de él.

    Preferible a un número de otra numeración, que el modelo interpretaría como
    válido — ya se vio en la fase 1 confabulando sobre un `starttime: null`.
    """
    ev = _exec_event(filename=b"/bin/sh", pid=999999)
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["ppid"] is None


def test_un_proceso_de_otro_namespace_se_marca(store):
    """Regresión: el sensor emitía PIDs del namespace inicial del kernel.

    WSL2 con systemd ejecuta la sesión en un namespace anidado, así que esos
    números no existen en el /proc que ve el EDR — se midió un desfase de unos
    9800. Con el PID equivocado, las siete salvaguardas leen otro proceso o
    ninguno, y las herramientas forenses fallan siempre.
    """
    ev = _exec_event(filename=b"/usr/bin/runc", pid=45163, in_target_ns=0)
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    guardado = store.query()[0]
    assert guardado["foreign_ns"] is True
    assert guardado["ppid"] is None      # ni se intenta leer /proc


def test_un_proceso_del_namespace_propio_no_se_marca(store):
    ev = _exec_event(filename=b"/bin/sh", pid=200, in_target_ns=1)
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["foreign_ns"] is False


def test_un_evento_de_otro_namespace_nunca_es_alerta():
    """No es interpretable ni remediable: escalarlo sería pedirle al modelo que
    decida sobre algo que el sistema no puede tocar."""
    from edr import triage

    ajeno = {"kind": config.KIND_EXECVE, "severity": 100, "foreign_ns": True}
    propio = {"kind": config.KIND_EXECVE, "severity": 100, "foreign_ns": False}

    assert not triage.is_alert(ajeno)
    assert triage.is_alert(propio)

    # Ni siquiera una carga de módulo, que por lo demás escala siempre.
    assert not triage.is_alert({"kind": config.KIND_MODULE_LOAD,
                                "foreign_ns": True})


def test_el_namespace_del_edr_se_inyecta_en_el_programa():
    """Un programa eBPF no puede hacer stat: es información del entorno."""
    import os
    st = os.stat("/proc/self/ns/pid")

    assert f"#define EDR_PIDNS_DEV {st.st_dev}" in forensic_mcp.ebpf_code
    assert f"#define EDR_PIDNS_INO {st.st_ino}" in forensic_mcp.ebpf_code
    assert "__PIDNS_DEV__" not in forensic_mcp.ebpf_code


# ── Triaje adjunto al evento ───────────────────────────────────

def test_un_exec_sospechoso_llega_puntuado(store):
    """La severidad se calcula una vez, en el sensor, y viaja con el evento."""
    ev = _exec_event(filename=b"/tmp/.systemd-update", argumentos=(b"600",))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    guardado = store.query()[0]
    assert guardado["severity"] == 70
    assert guardado["rules_fired"] == "exec_from_world_writable,hidden_binary"


def test_un_exec_corriente_no_arrastra_campos_de_triaje(store):
    """Sin reglas disparadas no se guarda nada: son el 99 % de los eventos."""
    ev = _exec_event(filename=b"/usr/bin/grep", argumentos=(b"-r", b"foo"))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    guardado = store.query()[0]
    assert "severity" not in guardado
    assert "rules_fired" not in guardado


def test_un_tipo_desconocido_no_revienta(store):
    """Un evento de un sensor futuro no debe tumbar el hilo del sensor."""
    ev = forensic_mcp.ModuleEvent(hdr=_hdr(999))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))
    assert store.query() == []


# ── Identidad: el objetivo de la fase ──────────────────────────

def test_el_evento_lleva_la_identidad_convertida_a_ticks(store):
    """La sonda entrega nanosegundos; el almacén guarda ticks, como /proc."""
    from edr.procinfo import NS_PER_TICK

    ev = forensic_mcp.ModuleEvent(
        hdr=_hdr(forensic_mcp.KIND_MODULE_LOAD, start_boottime=15_083_530_000_000))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["starttime"] == 15_083_530_000_000 // NS_PER_TICK


def test_la_identidad_ya_no_llega_vacia(store):
    """Antes de esta fase se midieron 0 identidades capturadas de 2905 eventos."""
    ev = _exec_event(filename=b"/bin/sh", start_boottime=1_000_000_000)
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["starttime"] is not None


def test_uid_y_cgroup_viajan_en_la_cabecera(store):
    ev = forensic_mcp.ModuleEvent(
        hdr=_hdr(forensic_mcp.KIND_MODULE_LOAD, uid=0, cgroup_id=4242))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    guardado = store.query()[0]
    assert guardado["uid"] == 0
    assert guardado["cgroup_id"] == 4242


def test_el_cgroup_no_se_le_muestra_al_modelo():
    """Es una etiqueta para el laboratorio, no información para razonar."""
    from edr import prompts
    linea = prompts.render_event({"pid": 1, "comm": "x", "cgroup_id": 4242, "uid": 0})
    assert "4242" not in linea
    assert "uid=0" in linea


# ── Resiliencia del enganche ───────────────────────────────────

def test_una_sonda_que_falla_no_impide_las_demas(monkeypatch):
    """Con siete sensores por venir, perder toda la detección por uno sería grave."""
    monkeypatch.setattr(forensic_mcp, "PROBES", {"attached": [], "failed": []})

    def falla():
        raise RuntimeError("símbolo inexistente")

    assert forensic_mcp._attach("kprobe:buena", lambda: None) is True
    assert forensic_mcp._attach("kprobe:mala", falla) is False

    assert forensic_mcp.PROBES["attached"] == ["kprobe:buena"]
    assert len(forensic_mcp.PROBES["failed"]) == 1
    assert "símbolo inexistente" in forensic_mcp.PROBES["failed"][0]


def test_sensor_stats_declara_la_cobertura_real(store, monkeypatch):
    """Hay que poder saber con qué sondas se está ejecutando de verdad."""
    monkeypatch.setattr(forensic_mcp, "PROBES",
                        {"attached": ["kprobe:init_module"], "failed": ["kprobe:x: no"]})
    import json
    stats = json.loads(forensic_mcp.sensor_stats())

    assert stats["probes_attached"] == ["kprobe:init_module"]
    assert stats["probes_failed"] == ["kprobe:x: no"]
    assert stats["ringbuf_dropped"] == 0     # sin BPF cargado, degrada a 0


def test_los_contadores_de_perdida_estan_separados(store):
    """Son dos pérdidas distintas: la del kernel y la del tope de memoria."""
    import json
    stats = json.loads(forensic_mcp.sensor_stats())
    assert "ringbuf_dropped" in stats    # el kernel descartó por buffer lleno
    assert "dropped" in stats            # el EventStore descartó por su cap
