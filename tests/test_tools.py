"""Tests de las herramientas MCP y de la correlación evento↔PID del orquestador.

Que este fichero pueda importar `forensic_mcp` ya es, en sí mismo, una de las
comprobaciones de la fase: antes la carga del programa eBPF estaba en el nivel de
módulo, así que importarlo exigía root y enganchaba sondas reales.
"""

import json

import pytest

import forensic_mcp
import orchestrator
from edr import config
from edr.eventstore import EventStore


@pytest.fixture
def store(monkeypatch):
    """Almacén limpio y solo en memoria para cada test."""
    s = EventStore(None, cap=100)
    monkeypatch.setattr(forensic_mcp, "STORE", s)
    return s


# ── get_kernel_alerts / ack_alerts ─────────────────────────────

def test_sin_alertas_devuelve_el_mensaje_que_espera_el_orquestador(store):
    assert "No security alerts for now" in forensic_mcp.get_kernel_alerts()


def test_las_alertas_se_devuelven_como_json(store):
    store.append(config.KIND_MODULE_LOAD, pid=100, comm="modprobe", starttime=555)

    eventos = json.loads(forensic_mcp.get_kernel_alerts())
    assert len(eventos) == 1
    assert eventos[0]["pid"] == 100
    assert eventos[0]["comm"] == "modprobe"
    # El starttime viaja con la alerta: es lo que después impide actuar sobre un
    # PID reciclado.
    assert eventos[0]["starttime"] == 555
    assert eventos[0]["seq"] == 1


def test_una_alerta_confirmada_no_se_reanaliza(store):
    """El bug original: las mismas alertas volvían al modelo en cada vuelta."""
    store.append(config.KIND_MODULE_LOAD, pid=100, comm="modprobe")
    store.append(config.KIND_MODULE_LOAD, pid=101, comm="insmod")

    eventos = json.loads(forensic_mcp.get_kernel_alerts())
    max_seq = max(e["seq"] for e in eventos)
    forensic_mcp.ack_alerts(max_seq)

    assert "No security alerts for now" in forensic_mcp.get_kernel_alerts()


def test_las_alertas_nuevas_si_aparecen_tras_confirmar(store):
    store.append(config.KIND_MODULE_LOAD, pid=100, comm="modprobe")
    forensic_mcp.ack_alerts(1)

    store.append(config.KIND_MODULE_LOAD, pid=200, comm="insmod")
    eventos = json.loads(forensic_mcp.get_kernel_alerts())
    assert [e["pid"] for e in eventos] == [200]


def test_los_execve_no_contaminan_las_alertas_de_modulos(store):
    store.append(config.KIND_EXECVE, pid=1, comm="bash", filename="/bin/ls")
    assert "No security alerts for now" in forensic_mcp.get_kernel_alerts()


# ── get_execve_events ──────────────────────────────────────────

def test_execve_del_pid_y_de_sus_hijos(store):
    store.append(config.KIND_EXECVE, pid=100, ppid=1, comm="bash", filename="/bin/bash")
    store.append(config.KIND_EXECVE, pid=101, ppid=100, comm="curl", filename="/usr/bin/curl")
    store.append(config.KIND_EXECVE, pid=999, ppid=5, comm="otro", filename="/bin/otro")

    eventos = json.loads(forensic_mcp.get_execve_events(100))
    assert {e["pid"] for e in eventos} == {100, 101}


def test_execve_sin_resultados(store):
    assert "No execve events found" in forensic_mcp.get_execve_events(12345)


# ── remediate_incident a través de la herramienta MCP ──────────

def test_la_herramienta_bloquea_pid_1(store):
    salida = forensic_mcp.remediate_incident(1, "kill")
    assert "BLOQUEADO" in salida
    assert "invalid_pid" in salida


def test_la_herramienta_bloquea_un_pid_reciclado(store, live_process):
    from edr import procinfo
    st = procinfo.starttime(live_process.pid)

    salida = forensic_mcp.remediate_incident(live_process.pid, "kill",
                                             expected_starttime=st + 1)
    assert "BLOQUEADO" in salida
    assert "pid_reused" in salida
    assert live_process.poll() is None


# ── correlación evento ↔ PID en el orquestador ─────────────────

def test_correlaciona_el_evento_del_pid_decidido():
    """Antes se cogía events[0], sin relación con el PID elegido por el modelo."""
    eventos = [
        {"seq": 1, "pid": 100, "comm": "modprobe", "starttime": 111},
        {"seq": 2, "pid": 200, "comm": "insmod", "starttime": 222},
    ]
    encontrado = orchestrator.find_event_for_pid(eventos, 200)

    assert encontrado["comm"] == "insmod"
    assert encontrado["starttime"] == 222


def test_correlacion_devuelve_la_aparicion_mas_reciente():
    eventos = [
        {"seq": 1, "pid": 100, "comm": "modprobe", "starttime": 111},
        {"seq": 2, "pid": 100, "comm": "modprobe", "starttime": 333},
    ]
    assert orchestrator.find_event_for_pid(eventos, 100)["starttime"] == 333


def test_un_pid_alucinado_no_correlaciona():
    """Si el modelo inventa un PID, no hay evento y no se aporta starttime."""
    eventos = [{"seq": 1, "pid": 100, "comm": "modprobe", "starttime": 111}]
    assert orchestrator.find_event_for_pid(eventos, 4242) is None


def test_parse_alerts_tolera_texto_de_error():
    """Las herramientas MCP devuelven texto plano ante un fallo, no JSON."""
    assert orchestrator.parse_alerts("[!] Error reading alerts file") == []
    assert orchestrator.parse_alerts("No security alerts for now.") == []
    assert orchestrator.parse_alerts('{"no": "es una lista"}') == []
