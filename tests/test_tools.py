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


# ── Orden de las alertas por accionabilidad ────────────────────

def test_lo_vivo_va_al_final_aunque_sea_menos_severo(store, live_process):
    """Regresión de la primera ejecución autónoma.

    Los eventos más severos son los de la cadena de un dropper —severidad 150—
    que vive tres segundos, mientras el orquestador sondea cada veinte. El modelo
    gastaba sus dos rondas pidiendo congelar procesos ya muertos.

    El orden es ascendente a propósito: `render_events` conserva los ÚLTIMOS
    eventos al recortar, y Ollama descarta la cabeza del prompt conservando la
    cola. Lo accionable tiene que quedar al final para sobrevivir a ambos.
    """
    from edr import procinfo

    vivo = live_process.pid
    store.append(config.KIND_EXECVE, pid=999999, filename="/bin/bash",
                 starttime=1, severity=150, rules_fired="downloader_to_shell")
    store.append(config.KIND_EXECVE, pid=vivo, filename="/tmp/.x",
                 starttime=procinfo.starttime(vivo), severity=70,
                 rules_fired="hidden_binary")

    eventos = json.loads(forensic_mcp.get_kernel_alerts())

    assert [e["pid"] for e in eventos] == [999999, vivo]
    assert eventos[-1]["alive"] is True
    assert eventos[0]["alive"] is False


def test_un_proceso_muerto_se_sigue_presentando(store):
    """No se filtra: tiene valor forense y el modelo puede responder NOTHING."""
    store.append(config.KIND_EXECVE, pid=999999, filename="/bin/bash",
                 starttime=1, severity=150, rules_fired="downloader_to_shell")

    eventos = json.loads(forensic_mcp.get_kernel_alerts())
    assert len(eventos) == 1
    assert eventos[0]["alive"] is False


def test_entre_iguales_manda_la_severidad(store):
    store.append(config.KIND_EXECVE, pid=999998, filename="/tmp/.a",
                 starttime=1, severity=70, rules_fired="hidden_binary")
    store.append(config.KIND_EXECVE, pid=999999, filename="/bin/bash",
                 starttime=1, severity=150, rules_fired="downloader_to_shell")

    eventos = json.loads(forensic_mcp.get_kernel_alerts())
    assert [e["severity"] for e in eventos] == [70, 150]


def test_anotar_no_ensucia_el_almacen(store):
    """`alive` es del momento en que se sirve la alerta, no del evento."""
    store.append(config.KIND_MODULE_LOAD, pid=999999, comm="modprobe", starttime=1)
    forensic_mcp.get_kernel_alerts()

    assert "alive" not in store.query()[0]


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


# ── inspect_pid_resources: la carrera de descriptores ──────────

def test_un_descriptor_que_desaparece_no_pierde_el_resto(live_process, monkeypatch):
    """Antes, un solo readlink fallido descartaba el resultado ENTERO.

    Que un descriptor se cierre entre el listdir y el readlink es lo normal en
    /proc, no una anomalía.
    """
    real_readlink = forensic_mcp.os.readlink
    llamadas = {"n": 0}

    def readlink_inestable(path):
        llamadas["n"] += 1
        if llamadas["n"] == 2:          # el segundo descriptor "se cierra"
            raise FileNotFoundError(path)
        return real_readlink(path)

    monkeypatch.setattr(forensic_mcp.os, "readlink", readlink_inestable)

    salida = forensic_mcp.inspect_pid_resources(live_process.pid)
    assert "Opened files" in salida
    assert "Error" not in salida


def test_inspect_pid_resources_con_pid_inexistente():
    assert "does not exist" in forensic_mcp.inspect_pid_resources(999999)


def test_inspect_pid_network_con_pid_inexistente():
    assert "does not exist" in forensic_mcp.inspect_pid_network(999999)


def test_el_subproceso_mcp_hereda_el_entorno(monkeypatch):
    """Regresión: `EDR_MODE=autonomous` no llegaba a quien envía la señal.

    El SDK de MCP lanza el servidor con `get_default_environment()`, que solo
    propaga HOME, LOGNAME, PATH, SHELL, TERM y USER. `remediate_incident` vive en
    ese subproceso, así que el sistema anunciaba modo autónomo por el banner del
    orquestador mientras seguía en dry-run donde de verdad importaba.
    """
    monkeypatch.setenv("EDR_MODE", "autonomous")

    params = orchestrator.mcp_server_params()

    assert params.env is not None, "sin env explícito el SDK recorta el entorno"
    assert params.env.get("EDR_MODE") == "autonomous"


def test_el_subproceso_mcp_usa_el_mismo_interprete():
    """Anteponer sudo aquí rompía el canal stdio si pedía contraseña."""
    import sys

    params = orchestrator.mcp_server_params()
    assert params.command == sys.executable
    assert params.args[0].endswith("forensic_mcp.py")


def test_parse_json_list_tolera_texto_de_error():
    """Las herramientas MCP devuelven texto plano ante un fallo, no JSON."""
    assert orchestrator.parse_json_list("[!] Error reading alerts file") == []
    assert orchestrator.parse_json_list("[tool-error] get_kernel_alerts: timeout") == []
    assert orchestrator.parse_json_list("No security alerts for now.") == []
    assert orchestrator.parse_json_list('{"no": "es una lista"}') == []
    assert orchestrator.parse_json_list('[{"pid": 1}]') == [{"pid": 1}]
