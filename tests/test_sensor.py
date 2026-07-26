"""Tests del esquema de evento y del arranque de los sensores.

No se carga eBPF: lo que se comprueba es que el espejo en ctypes cuadra con la
estructura de C, que el despacho por tipo de evento funciona, y que el arranque
tolera una sonda indisponible.

La compilación real del programa en C **no se puede verificar sin root**: BCC
obtiene las cabeceras del kernel cargando el módulo `kheaders`, cosa que requiere
privilegios. Para eso está `scripts/check-bpf.py`.
"""

import ctypes as ct

import pytest

import forensic_mcp
from edr import config
from edr.eventstore import EventStore


@pytest.fixture
def store(monkeypatch):
    s = EventStore(None, cap=100)
    monkeypatch.setattr(forensic_mcp, "STORE", s)
    return s


def _buffer(struct_obj):
    """Puntero al struct, como el que entrega el ring buffer."""
    return ct.cast(ct.pointer(struct_obj), ct.c_void_p)


def _hdr(kind, pid=100, ppid=1, uid=1000, comm=b"modprobe", start_boottime=0,
         cgroup_id=0):
    return forensic_mcp.EvHdr(
        ts_ns=123456789, start_boottime=start_boottime, cgroup_id=cgroup_id,
        pid=pid, ppid=ppid, uid=uid, kind=kind, comm=comm,
    )


# ── Espejo de ctypes ───────────────────────────────────────────

def test_la_cabecera_no_lleva_relleno():
    """Si C y ctypes discrepan en tamaño, los campos se leerían desplazados.

    Los u64 van primero precisamente para que la estructura quede alineada sin
    que el compilador inserte relleno.
    """
    assert ct.sizeof(forensic_mcp.EvHdr) == 8 * 3 + 4 * 4 + 16


def test_el_evento_de_exec_es_la_cabecera_mas_el_nombre():
    assert ct.sizeof(forensic_mcp.ExecEvent) == ct.sizeof(forensic_mcp.EvHdr) + 128


def test_los_desplazamientos_son_los_esperados():
    offsets = {n: getattr(forensic_mcp.EvHdr, n).offset
               for n, _ in forensic_mcp.EvHdr._fields_}
    assert offsets == {"ts_ns": 0, "start_boottime": 8, "cgroup_id": 16,
                       "pid": 24, "ppid": 28, "uid": 32, "kind": 36, "comm": 40}


# ── Despacho por tipo de evento ────────────────────────────────

def test_un_evento_de_modulo_se_guarda_como_tal(store):
    ev = forensic_mcp.ModuleEvent(hdr=_hdr(forensic_mcp.KIND_MODULE_LOAD))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    guardado = store.query()[0]
    assert guardado["kind"] == config.KIND_MODULE_LOAD
    assert guardado["pid"] == 100
    assert guardado["comm"] == "modprobe"
    assert "detail" in guardado


def test_un_evento_de_exec_lleva_el_nombre_del_binario(store):
    ev = forensic_mcp.ExecEvent(
        hdr=_hdr(forensic_mcp.KIND_EXECVE, pid=200, comm=b"sudo"),
        filename=b"/usr/sbin/modprobe",
    )
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    guardado = store.query()[0]
    assert guardado["kind"] == config.KIND_EXECVE
    assert guardado["filename"] == "/usr/sbin/modprobe"
    assert guardado["comm"] == "sudo"


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
    ev = forensic_mcp.ExecEvent(
        hdr=_hdr(forensic_mcp.KIND_EXECVE, start_boottime=1_000_000_000),
        filename=b"/bin/sh")
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
