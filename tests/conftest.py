"""Fixtures compartidas.

Toda la suite corre sin root, sin BCC y sin red, y debe terminar en segundos: son
tests para ejecutar constantemente durante el desarrollo, no una batería nocturna.
"""

import subprocess
import time

import pytest

from edr import procinfo


@pytest.fixture
def live_process():
    """Un proceso real y de vida corta contra el que probar la lectura de /proc.

    Se usa un proceso de verdad, y no un /proc sintético, porque el formato real
    de `stat` es precisamente lo que se quiere verificar.
    """
    proc = subprocess.Popen(["sleep", "30"])
    # Margen para que /proc/{pid}/ esté poblado del todo.
    time.sleep(0.1)
    yield proc
    proc.kill()
    proc.wait()


@pytest.fixture
def fake_proc(tmp_path, monkeypatch):
    """Constructor de un /proc sintético.

    Necesario porque WSL2 no expone hilos de kernel: sin esto, la comprobación de
    PF_KTHREAD no se podría testear en esta máquina. También permite fabricar los
    `comm` patológicos exactos que se quieren cubrir.

        make(pid=42, comm="(sd-pam)", ppid=1, starttime=1234, kthread=True)
    """
    monkeypatch.setattr(procinfo, "PROC", str(tmp_path))

    def make(pid, comm="test", ppid=1, starttime=1000, flags=0, state="S",
             kthread=False, cmdline=None, uid=None):
        if kthread:
            flags |= procinfo.PF_KTHREAD

        # Campos posteriores al `comm`, por índice: 0=state, 1=ppid, 6=flags,
        # 19=starttime. El resto son relleno con la forma correcta.
        fields = ["0"] * 20
        fields[0] = state
        fields[1] = str(ppid)
        fields[6] = str(flags)
        fields[19] = str(starttime)

        d = tmp_path / str(pid)
        d.mkdir(exist_ok=True)
        (d / "stat").write_text(f"{pid} ({comm}) " + " ".join(fields) + "\n")

        if cmdline is not None:
            (d / "cmdline").write_bytes(b"\x00".join(c.encode() for c in cmdline) + b"\x00")
        if uid is not None:
            (d / "status").write_text(f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        return pid

    return make
