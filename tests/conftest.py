"""Shared fixtures.

The whole suite runs without root, without BCC and without network, and has to
finish in seconds: these are tests to run constantly while developing, not a
nightly batch.
"""

import subprocess
import time

import pytest

from edr import procinfo


@pytest.fixture
def live_process():
    """A real, short-lived process to read /proc against.

    A real process rather than a synthetic tree, because the real format of
    `stat` is precisely what is being verified.
    """
    proc = subprocess.Popen(["sleep", "30"])
    # Give /proc/{pid}/ time to be fully populated.
    time.sleep(0.1)
    yield proc
    proc.kill()
    proc.wait()


@pytest.fixture
def fake_proc(tmp_path, monkeypatch):
    """Builder for a synthetic /proc.

    Needed because WSL2 exposes no kernel threads, so PF_KTHREAD could not be
    tested on this machine. It also allows fabricating the exact pathological
    `comm` values worth covering.

        make(pid=42, comm="(sd-pam)", ppid=1, starttime=1234, kthread=True)
    """
    monkeypatch.setattr(procinfo, "PROC", str(tmp_path))

    def make(pid, comm="test", ppid=1, starttime=1000, flags=0, state="S",
             kthread=False, cmdline=None, uid=None):
        if kthread:
            flags |= procinfo.PF_KTHREAD

        # Fields after `comm`, by index: 0=state, 1=ppid, 6=flags,
        # 19=starttime. The rest is padding with the right shape.
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
