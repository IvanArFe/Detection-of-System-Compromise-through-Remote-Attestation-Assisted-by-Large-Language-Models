"""Tests for the event schema and the sensor startup.

No eBPF is loaded here: what is checked is that the ctypes mirror matches the C
struct, that dispatch by event kind works, and that startup tolerates an
unavailable probe.

Compiling the C program **cannot be verified without root** — BCC gets the
kernel headers by loading the `kheaders` module. That is what
`scripts/check_sensor.py` is for.
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
    # The sensor resolves ppid from /proc. Pointed at an empty tree so test pids
    # cannot collide by chance with real processes on the machine.
    monkeypatch.setattr(procinfo, "PROC", str(tmp_path))
    return s


def _buffer(struct_obj):
    """Pointer to the struct, like the one the ring buffer hands over."""
    return ct.cast(ct.pointer(struct_obj), ct.c_void_p)


def _hdr(kind, pid=100, ppid=1, uid=1000, comm=b"modprobe", start_boottime=0,
         cgroup_id=0, in_target_ns=1):
    return forensic_mcp.EvHdr(
        ts_ns=123456789, start_boottime=start_boottime, cgroup_id=cgroup_id,
        pid=pid, ppid=ppid, uid=uid, kind=kind, in_target_ns=in_target_ns,
        comm=comm,
    )


# ── ctypes mirror ──────────────────────────────────────────────

def test_header_matches_the_c_struct():
    """If C and ctypes disagree on size, every field would be read shifted.

    The u64s come first so there is no INTERMEDIATE padding, which is the kind
    that shifts fields. The 4 tail bytes are added identically by both.
    """
    assert ct.sizeof(forensic_mcp.EvHdr) == 64


def test_exec_event_matches_the_c_struct_byte_for_byte():
    """64 header + 128 filename + 320 args + 3 u32, aligned to 8.

    The absolute number is pinned as well as the sum: reordering fields could
    keep the sum right while the size changes.
    """
    assert ct.sizeof(forensic_mcp.ExecEvent) == 528

    offsets = {n: getattr(forensic_mcp.ExecEvent, n).offset
               for n, _ in forensic_mcp.ExecEvent._fields_}
    assert offsets == {"hdr": 0, "filename": 64, "args": 192,
                       "args_len": 512, "args_count": 516, "args_truncated": 520}


def test_args_buffer_leaves_slack_for_the_verifier():
    """Regression: the verifier rejected the program over 47 bytes.

    It reasons about the whole reserved object. With the `& (ARGS_BUF - 1)` mask
    it only knows the offset is 0..255, so it computes the worst case — start at
    the last usable byte and copy ARG_LEN — and demands that it fit:

        invalid access to memory, mem_size=456 off=439 size=64

    This assertion is the same arithmetic the verifier does.
    """
    start = forensic_mcp.ExecEvent.args.offset
    worst_case = start + (forensic_mcp.ARGS_BUF - 1) + forensic_mcp.ARG_LEN

    assert worst_case <= ct.sizeof(forensic_mcp.ExecEvent)


def test_args_are_not_read_as_c_char():
    """A c_char array stops at the first '\\0', and here '\\0' is the separator,
    so only the first argument would come back — silently."""
    field_type = dict(forensic_mcp.ExecEvent._fields_)["args"]
    assert field_type._type_ is ct.c_ubyte


def test_header_offsets_are_as_expected():
    offsets = {n: getattr(forensic_mcp.EvHdr, n).offset
               for n, _ in forensic_mcp.EvHdr._fields_}
    assert offsets == {"ts_ns": 0, "start_boottime": 8, "cgroup_id": 16,
                       "pid": 24, "ppid": 28, "uid": 32, "kind": 36,
                       "in_target_ns": 40, "comm": 44}


# ── Dispatch by event kind ─────────────────────────────────────

def test_a_module_event_is_stored_as_one(store):
    ev = forensic_mcp.ModuleEvent(hdr=_hdr(forensic_mcp.KIND_MODULE_LOAD))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    stored = store.query()[0]
    assert stored["kind"] == config.KIND_MODULE_LOAD
    assert stored["pid"] == 100
    assert stored["comm"] == "modprobe"
    assert "detail" in stored


def _args(*arguments):
    """Build the buffer exactly as `bpf_probe_read_user_str` leaves it.

    The padding is deliberately NOT zeros: ring-buffer memory arrives dirty and
    the tests must exercise that, not an idealised version of it.
    """
    raw = b"".join(a + b"\x00" for a in arguments)
    buf = (ct.c_ubyte * forensic_mcp.ARGS_ARRAY)(
        *([0x41] * forensic_mcp.ARGS_ARRAY))
    for i, b in enumerate(raw):
        buf[i] = b
    return buf, len(raw)


def _exec_event(filename=b"/bin/sh", arguments=(), truncated=0, **hdr_kwargs):
    buf, length = _args(*arguments)
    return forensic_mcp.ExecEvent(
        hdr=_hdr(forensic_mcp.KIND_EXECVE, **hdr_kwargs),
        filename=filename, args=buf, args_len=length,
        args_count=len(arguments), args_truncated=truncated,
    )


def test_an_exec_event_carries_the_binary_name(store):
    ev = _exec_event(filename=b"/usr/sbin/modprobe", pid=200, comm=b"sudo")
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    stored = store.query()[0]
    assert stored["kind"] == config.KIND_EXECVE
    assert stored["filename"] == "/usr/sbin/modprobe"


def test_on_an_exec_comm_is_the_caller(store):
    """At sys_enter_execve the kernel has not renamed the process yet, which is
    why the telemetry read `comm=sh filename=/usr/bin/ollama`: `sh` was the
    launching shell. The field is renamed so it cannot be misread."""
    ev = _exec_event(filename=b"/usr/bin/ollama", comm=b"sh")
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    stored = store.query()[0]
    assert stored["caller_comm"] == "sh"
    assert "comm" not in stored


def test_comm_on_a_module_load_is_not_renamed(store):
    """There `comm` IS the process: no exec is involved."""
    ev = forensic_mcp.ModuleEvent(
        hdr=_hdr(forensic_mcp.KIND_MODULE_LOAD, comm=b"modprobe"))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["comm"] == "modprobe"


# ── Command line ───────────────────────────────────────────────

def test_the_command_line_arrives_whole_and_in_order(store):
    ev = _exec_event(filename=b"/usr/bin/curl",
                     arguments=(b"-s", b"http://x/y.sh"))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["cmdline"] == "-s http://x/y.sh"


def test_nothing_is_read_past_what_the_probe_wrote():
    """Regression: ring-buffer memory is not zeroed. Reading to the end of the
    buffer instead of up to `args_len` would show the model fragments of earlier
    commands as if they belonged to this process."""
    buf, length = _args(b"-s")
    assert forensic_mcp.decode_cmdline(buf, length) == "-s"
    assert "A" not in forensic_mcp.decode_cmdline(buf, length)


def test_an_impossible_args_len_does_not_overflow():
    """The kernel writes the length, but over-reading cannot be an option."""
    buf, _ = _args(b"-s")
    assert forensic_mcp.decode_cmdline(buf, 10 ** 9)
    assert forensic_mcp.decode_cmdline(buf, -5) == ""


def test_a_command_without_arguments_invents_nothing(store):
    ev = _exec_event(filename=b"/bin/sh")
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["cmdline"] == ""


def test_truncation_is_reported_to_the_model(store):
    """Knowing it saw part of the command is different from believing it saw all."""
    ev = _exec_event(filename=b"/bin/sh", arguments=(b"-c", b"something"), truncated=1)
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["cmdline"] == "-c something …"


def test_an_empty_argument_does_not_break_the_line():
    buf, length = _args(b"-c", b"", b"ls")
    assert forensic_mcp.decode_cmdline(buf, length) == "-c ls"


# ── PID namespace ──────────────────────────────────────────────

def test_ppid_is_resolved_from_proc(store, fake_proc):
    """The probe cannot give it in the right numbering; /proc can.

    `real_parent->tgid` is the initial-namespace pid, and the translating helper
    only works for the current task, not for its parent.
    """
    fake_proc(pid=200, comm="sh", ppid=199)

    ev = _exec_event(filename=b"/usr/bin/curl", pid=200)
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["ppid"] == 199


def test_an_already_dead_process_leaves_ppid_null(store):
    """Accepted price of the fix: informational, no decision depends on it.

    Better than a number from another namespace, which the model would take as
    valid — it already confabulated a meaning for a `starttime: null`.
    """
    ev = _exec_event(filename=b"/bin/sh", pid=999999)
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["ppid"] is None


def test_a_process_from_another_namespace_is_flagged(store):
    """Regression: the sensor emitted initial-namespace pids.

    WSL2 with systemd runs the session in a nested namespace, so those numbers
    do not exist in the /proc the EDR reads — a measured offset of about 9800.
    With the wrong pid all nine safeguards read another process or none, and
    the forensic tools fail unconditionally.
    """
    ev = _exec_event(filename=b"/usr/bin/runc", pid=45163, in_target_ns=0)
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    stored = store.query()[0]
    assert stored["foreign_ns"] is True
    assert stored["ppid"] is None      # /proc is not even consulted


def test_a_process_from_our_own_namespace_is_not_flagged(store):
    ev = _exec_event(filename=b"/bin/sh", pid=200, in_target_ns=1)
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["foreign_ns"] is False


def test_a_foreign_namespace_event_is_never_an_alert():
    """It can neither be interpreted nor signalled, so escalating it would ask
    the model to decide about something the system cannot touch."""
    from edr import triage

    foreign = {"kind": config.KIND_EXECVE, "severity": 100, "foreign_ns": True}
    ours = {"kind": config.KIND_EXECVE, "severity": 100, "foreign_ns": False}

    assert not triage.is_alert(foreign)
    assert triage.is_alert(ours)

    # Not even a module load, which otherwise always escalates.
    assert not triage.is_alert({"kind": config.KIND_MODULE_LOAD,
                                "foreign_ns": True})


def test_the_edr_namespace_is_injected_into_the_program():
    """An eBPF program cannot stat: this is information about the environment."""
    import os
    st = os.stat("/proc/self/ns/pid")

    assert f"#define EDR_PIDNS_DEV {st.st_dev}" in forensic_mcp.ebpf_code
    assert f"#define EDR_PIDNS_INO {st.st_ino}" in forensic_mcp.ebpf_code
    assert "__PIDNS_DEV__" not in forensic_mcp.ebpf_code


# ── Triage attached to the event ───────────────────────────────

def test_a_suspicious_exec_arrives_already_scored(store):
    """Severity is computed once, in the sensor, and travels with the event."""
    ev = _exec_event(filename=b"/tmp/.systemd-update", arguments=(b"600",))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    stored = store.query()[0]
    assert stored["severity"] == 70
    assert stored["rules_fired"] == "exec_from_world_writable,hidden_binary"


def test_an_ordinary_exec_carries_no_triage_fields(store):
    """With no rule fired nothing is stored: that is 99 % of the events."""
    ev = _exec_event(filename=b"/usr/bin/grep", arguments=(b"-r", b"foo"))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    stored = store.query()[0]
    assert "severity" not in stored
    assert "rules_fired" not in stored


def test_an_unknown_kind_does_not_blow_up(store):
    """An event from a future sensor must not bring down the sensor thread."""
    ev = forensic_mcp.ModuleEvent(hdr=_hdr(999))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))
    assert store.query() == []


# ── Identity: the point of the phase ───────────────────────────

def test_the_event_carries_identity_converted_to_ticks(store):
    """The probe delivers nanoseconds; the store keeps ticks, like /proc."""
    from edr.procinfo import NS_PER_TICK

    ev = forensic_mcp.ModuleEvent(
        hdr=_hdr(forensic_mcp.KIND_MODULE_LOAD, start_boottime=15_083_530_000_000))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["starttime"] == 15_083_530_000_000 // NS_PER_TICK


def test_identity_no_longer_arrives_empty(store):
    """Before this phase, 0 identities were captured out of 2905 events."""
    ev = _exec_event(filename=b"/bin/sh", start_boottime=1_000_000_000)
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    assert store.query()[0]["starttime"] is not None


def test_uid_and_cgroup_travel_in_the_header(store):
    ev = forensic_mcp.ModuleEvent(
        hdr=_hdr(forensic_mcp.KIND_MODULE_LOAD, uid=0, cgroup_id=4242))
    forensic_mcp.handle_event(_buffer(ev), ct.sizeof(ev))

    stored = store.query()[0]
    assert stored["uid"] == 0
    assert stored["cgroup_id"] == 4242


def test_cgroup_is_not_shown_to_the_model():
    """It is a lab label, not information to reason with."""
    from edr import prompts
    line = prompts.render_event({"pid": 1, "comm": "x", "cgroup_id": 4242, "uid": 0})
    assert "4242" not in line
    assert "uid=0" in line


# ── Attachment resilience ──────────────────────────────────────

def test_one_failing_probe_does_not_stop_the_others(monkeypatch):
    """With seven more sensors coming, losing all detection to one would hurt."""
    monkeypatch.setattr(forensic_mcp, "PROBES", {"attached": [], "failed": []})

    def fails():
        raise RuntimeError("missing symbol")

    assert forensic_mcp._attach("kprobe:good", lambda: None) is True
    assert forensic_mcp._attach("kprobe:bad", fails) is False

    assert forensic_mcp.PROBES["attached"] == ["kprobe:good"]
    assert len(forensic_mcp.PROBES["failed"]) == 1
    assert "missing symbol" in forensic_mcp.PROBES["failed"][0]


def test_sensor_stats_reports_the_real_coverage(store, monkeypatch):
    """It has to be possible to know which probes a run actually had."""
    monkeypatch.setattr(forensic_mcp, "PROBES",
                        {"attached": ["kprobe:init_module"], "failed": ["kprobe:x: no"]})
    import json
    stats = json.loads(forensic_mcp.sensor_stats())

    assert stats["probes_attached"] == ["kprobe:init_module"]
    assert stats["probes_failed"] == ["kprobe:x: no"]
    assert stats["ringbuf_dropped"] == 0     # with no BPF loaded, degrades to 0


def test_the_two_loss_counters_are_separate(store):
    """Two different losses: the kernel's and the memory cap's."""
    import json
    stats = json.loads(forensic_mcp.sensor_stats())
    assert "ringbuf_dropped" in stats    # kernel dropped: buffer full
    assert "dropped" in stats            # EventStore dropped: cap reached
