"""Tests de las salvaguardas de remediación.

Es la suite más importante de la fase: cada test corresponde a una forma concreta
en que el EDR podría causar daño colateral. Ninguno envía señales de verdad — la
función de señalización se inyecta.
"""

import os

import pytest

from edr import config, procinfo, safety


@pytest.fixture
def limiter():
    """Limitador aislado con reloj manual, para no depender del estado global."""
    reloj = {"t": 1000.0}
    lim = safety.RateLimiter(max_n=3, window_s=300, clock=lambda: reloj["t"])
    lim.reloj = reloj
    return lim


@pytest.fixture
def nunca_senaliza():
    """Captura las señales en vez de enviarlas."""
    enviadas = []
    return enviadas, lambda pid, sig: enviadas.append((pid, sig))


# ── 1. PIDs que no designan un proceso concreto ────────────────

@pytest.mark.parametrize("pid,motivo", [
    (0, "invalid_pid"),    # os.kill(0, sig) señaliza el GRUPO ENTERO del EDR
    (1, "invalid_pid"),    # systemd
    (-1, "invalid_pid"),   # todos los procesos del usuario
    (-100, "invalid_pid"),  # un grupo de procesos arbitrario
])
def test_pids_no_remediables(pid, motivo, limiter):
    v = safety.validate_remediation(pid, "kill", limiter=limiter)
    assert not v.allowed
    assert v.reason == motivo


def test_pid_no_entero_rechazado(limiter):
    assert not safety.validate_remediation("123", "kill", limiter=limiter).allowed
    assert not safety.validate_remediation(None, "kill", limiter=limiter).allowed


# ── 2. Acciones ────────────────────────────────────────────────

@pytest.mark.parametrize("accion", ["nuke", "delete", "", "KILL", "isolate"])
def test_acciones_invalidas(accion, live_process, limiter):
    v = safety.validate_remediation(live_process.pid, accion, limiter=limiter)
    assert not v.allowed
    assert v.reason == "invalid_action"


@pytest.mark.parametrize("accion", ["freeze", "kill"])
def test_acciones_validas(accion, live_process, limiter):
    st = procinfo.starttime(live_process.pid)
    v = safety.validate_remediation(live_process.pid, accion, st, limiter=limiter)
    assert v.allowed


# ── 3. Autoprotección ──────────────────────────────────────────

def test_no_puede_matarse_a_si_mismo(limiter):
    v = safety.validate_remediation(os.getpid(), "kill", limiter=limiter)
    assert not v.allowed
    assert v.reason == "self_protection"


def test_no_puede_matar_a_su_padre(limiter):
    """En producción el servidor MCP es hijo del orquestador: esto lo protege."""
    v = safety.validate_remediation(os.getppid(), "kill", limiter=limiter)
    assert not v.allowed
    assert v.reason == "self_protection"


def test_no_puede_matar_a_un_ancestro_lejano(limiter):
    cadena = procinfo.ancestors(os.getpid())
    # El último ancestro antes de PID 1, para probar la cadena completa.
    lejano = [p for p in cadena if p > 1]
    if len(lejano) < 2:
        pytest.skip("cadena de ancestros demasiado corta en este entorno")

    v = safety.validate_remediation(lejano[-1], "kill", limiter=limiter)
    assert not v.allowed
    assert v.reason == "self_protection"


# ── 4 y 5. Hilos de kernel y procesos protegidos ───────────────

def test_no_puede_matar_un_hilo_de_kernel(fake_proc, limiter, monkeypatch):
    fake_proc(pid=5000, comm="kworker/0:1", kthread=True, starttime=10)
    monkeypatch.setattr(procinfo, "ancestors", lambda pid: [])

    v = safety.validate_remediation(5000, "kill", limiter=limiter)
    assert not v.allowed
    assert v.reason == "kernel_thread"


@pytest.mark.parametrize("comm", ["systemd", "sshd", "dockerd", "init"])
def test_no_puede_matar_procesos_criticos(comm, fake_proc, limiter, monkeypatch):
    """Matar sshd durante un incidente te deja fuera de la máquina que investigas."""
    fake_proc(pid=6000, comm=comm, starttime=10)
    monkeypatch.setattr(procinfo, "ancestors", lambda pid: [])

    v = safety.validate_remediation(6000, "kill", limiter=limiter)
    assert not v.allowed
    assert v.reason == "protected_process"


def test_un_proceso_normal_si_es_remediable(fake_proc, limiter, monkeypatch):
    fake_proc(pid=6001, comm="curl", starttime=10)
    monkeypatch.setattr(procinfo, "ancestors", lambda pid: [])

    assert safety.validate_remediation(6001, "kill", 10, limiter=limiter).allowed


# ── 6. Reutilización de PID ────────────────────────────────────

def test_starttime_correcto_permite_remediar(live_process, limiter):
    st = procinfo.starttime(live_process.pid)
    v = safety.validate_remediation(live_process.pid, "kill", st, limiter=limiter)
    assert v.allowed


def test_starttime_distinto_bloquea_la_remediacion(live_process, limiter):
    """El núcleo de la fase: el PID coincide, pero ya no es el mismo proceso."""
    st = procinfo.starttime(live_process.pid)
    v = safety.validate_remediation(live_process.pid, "kill", st + 1, limiter=limiter)

    assert not v.allowed
    assert v.reason == "pid_reused"


def test_proceso_inexistente(limiter):
    v = safety.validate_remediation(999999, "kill", 123, limiter=limiter)
    assert not v.allowed
    assert v.reason == "no_such_process"


def test_sin_identidad_no_se_remedia(live_process, limiter):
    """Media validación de identidad no vale de nada: se falla en cerrado.

    Descubierto en la verificación de la Fase 1: el 100% de los eventos de carga
    de módulo llegaban sin `starttime` porque `modprobe` muere antes de que el
    callback de userspace pueda leer su /proc. Saltarse la comprobación en ese
    caso dejaba abierta exactamente la puerta que la comprobación cierra.
    """
    v = safety.validate_remediation(live_process.pid, "kill", None, limiter=limiter)

    assert not v.allowed
    assert v.reason == "identity_unknown"


def test_sin_identidad_tampoco_se_remedia_en_autonomous(live_process, limiter,
                                                        nunca_senaliza):
    enviadas, fn = nunca_senaliza
    r = safety.remediate(live_process.pid, "kill", None,
                         mode=config.MODE_AUTONOMOUS, signal_fn=fn, limiter=limiter)

    assert r["outcome"] == "denied"
    assert enviadas == []
    assert live_process.poll() is None


# ── 7. Límite de tasa ──────────────────────────────────────────

def test_limite_de_tasa_corta_un_bucle_de_alucinacion(fake_proc, limiter, monkeypatch):
    fake_proc(pid=7000, comm="curl", starttime=10)
    monkeypatch.setattr(procinfo, "ancestors", lambda pid: [])

    for _ in range(3):
        assert safety.validate_remediation(7000, "kill", 10, limiter=limiter).allowed
        limiter.record()

    v = safety.validate_remediation(7000, "kill", 10, limiter=limiter)
    assert not v.allowed
    assert v.reason == "rate_limited"


def test_el_limite_se_libera_al_pasar_la_ventana(fake_proc, limiter, monkeypatch):
    fake_proc(pid=7001, comm="curl", starttime=10)
    monkeypatch.setattr(procinfo, "ancestors", lambda pid: [])

    for _ in range(3):
        limiter.record()
    assert not safety.validate_remediation(7001, "kill", 10, limiter=limiter).allowed

    limiter.reloj["t"] += 301  # la ventana son 300 s
    assert safety.validate_remediation(7001, "kill", 10, limiter=limiter).allowed


def test_una_propuesta_invalida_no_consume_presupuesto(limiter):
    """El límite va el último a propósito: rechazar no debe gastar cupo."""
    for _ in range(10):
        safety.validate_remediation(1, "kill", limiter=limiter)
    assert limiter.would_allow()


# ── Modos de operación ─────────────────────────────────────────

def test_dry_run_no_envia_ninguna_senal(live_process, limiter, nunca_senaliza):
    enviadas, fn = nunca_senaliza
    st = procinfo.starttime(live_process.pid)

    r = safety.remediate(live_process.pid, "kill", st,
                         mode=config.MODE_DRY_RUN, signal_fn=fn, limiter=limiter)

    assert r["outcome"] == "dry_run"
    assert enviadas == []
    assert live_process.poll() is None, "el proceso debería seguir vivo"


def test_autonomous_si_envia_la_senal(live_process, limiter, nunca_senaliza):
    enviadas, fn = nunca_senaliza
    st = procinfo.starttime(live_process.pid)

    r = safety.remediate(live_process.pid, "kill", st,
                         mode=config.MODE_AUTONOMOUS, signal_fn=fn, limiter=limiter)

    assert r["outcome"] == "executed"
    assert enviadas == [(live_process.pid, 9)]


def test_freeze_envia_sigstop(live_process, limiter, nunca_senaliza):
    enviadas, fn = nunca_senaliza
    st = procinfo.starttime(live_process.pid)

    safety.remediate(live_process.pid, "freeze", st,
                     mode=config.MODE_AUTONOMOUS, signal_fn=fn, limiter=limiter)

    assert enviadas == [(live_process.pid, 19)]  # SIGSTOP


def test_ambos_modos_consumen_el_mismo_presupuesto(live_process, limiter, nunca_senaliza):
    """Para que las métricas de dry-run sean comparables con las de autonomous."""
    _, fn = nunca_senaliza
    st = procinfo.starttime(live_process.pid)

    for _ in range(3):
        safety.remediate(live_process.pid, "kill", st,
                         mode=config.MODE_DRY_RUN, signal_fn=fn, limiter=limiter)

    r = safety.remediate(live_process.pid, "kill", st,
                         mode=config.MODE_DRY_RUN, signal_fn=fn, limiter=limiter)
    assert r["verdict"] == "rate_limited"


def test_una_denegacion_no_envia_senal_ni_en_autonomous(limiter, nunca_senaliza):
    enviadas, fn = nunca_senaliza

    r = safety.remediate(1, "kill", mode=config.MODE_AUTONOMOUS,
                         signal_fn=fn, limiter=limiter)

    assert r["outcome"] == "denied"
    assert enviadas == []


# ── Auditoría ──────────────────────────────────────────────────

def test_las_tentativas_denegadas_quedan_registradas(limiter, nunca_senaliza):
    """Sin esta traza no se puede demostrar que las salvaguardas se activaron."""
    _, fn = nunca_senaliza
    safety.remediate(1, "kill", reason="prueba de auditoría",
                     mode=config.MODE_AUTONOMOUS, signal_fn=fn, limiter=limiter)

    ultimo = safety.attempts()[-1]
    assert ultimo["allowed"] is False
    assert ultimo["verdict"] == "invalid_pid"
    assert ultimo["reason"] == "prueba de auditoría"
    assert ultimo["pid"] == 1


def test_describe_es_legible(limiter, nunca_senaliza):
    _, fn = nunca_senaliza
    r = safety.remediate(1, "kill", mode=config.MODE_AUTONOMOUS,
                         signal_fn=fn, limiter=limiter)

    texto = safety.describe(r)
    assert "BLOQUEADO" in texto
    assert "invalid_pid" in texto
