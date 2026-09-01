"""Tests for the MCP tools and for the orchestrator's event↔pid correlation.

That this file can import `forensic_mcp` at all is itself one of the phase's
checks: loading the eBPF program used to happen at module level, so importing it
required root and attached real probes.
"""

import json

import pytest

import forensic_mcp
import orchestrator
from edr import config
from edr.eventstore import EventStore


@pytest.fixture
def store(monkeypatch):
    """A clean, memory-only store for each test."""
    s = EventStore(None, cap=100)
    monkeypatch.setattr(forensic_mcp, "STORE", s)
    return s


# ── get_kernel_alerts / ack_alerts ─────────────────────────────

def test_no_alerts_returns_the_message_the_orchestrator_expects(store):
    assert "No security alerts for now" in forensic_mcp.get_kernel_alerts()


def test_alerts_are_returned_as_json(store):
    store.append(config.KIND_MODULE_LOAD, pid=100, comm="modprobe", starttime=555)

    events = json.loads(forensic_mcp.get_kernel_alerts())
    assert len(events) == 1
    assert events[0]["pid"] == 100
    assert events[0]["comm"] == "modprobe"
    # The starttime travels with the alert: it is what later blocks acting on a
    # recycled pid.
    assert events[0]["starttime"] == 555
    assert events[0]["seq"] == 1


def test_an_acknowledged_alert_is_not_re_analysed(store):
    """The original bug: the same alerts went back to the model every cycle."""
    store.append(config.KIND_MODULE_LOAD, pid=100, comm="modprobe")
    store.append(config.KIND_MODULE_LOAD, pid=101, comm="insmod")

    events = json.loads(forensic_mcp.get_kernel_alerts())
    max_seq = max(e["seq"] for e in events)
    forensic_mcp.ack_alerts(max_seq)

    assert "No security alerts for now" in forensic_mcp.get_kernel_alerts()


def test_new_alerts_still_appear_after_acknowledging(store):
    store.append(config.KIND_MODULE_LOAD, pid=100, comm="modprobe")
    forensic_mcp.ack_alerts(1)

    store.append(config.KIND_MODULE_LOAD, pid=200, comm="insmod")
    events = json.loads(forensic_mcp.get_kernel_alerts())
    assert [e["pid"] for e in events] == [200]


def test_ordinary_execve_does_not_pollute_the_module_alerts(store):
    store.append(config.KIND_EXECVE, pid=1, comm="bash", filename="/bin/ls")
    assert "No security alerts for now" in forensic_mcp.get_kernel_alerts()


# ── Alert ranking by actionability ─────────────────────────────

def test_the_live_one_goes_last_even_if_less_severe(store, live_process):
    """Regression from the first autonomous run.

    The most severe events are a dropper chain — severity 150 — that lives three
    seconds, while the orchestrator polls every twenty. The model spent both of
    its rounds asking to freeze processes that had already exited.

    The order is ascending on purpose: `render_events` keeps the LAST events
    when trimming, and Ollama discards the head of the prompt and keeps the
    tail. The actionable alert has to be last to survive both.
    """
    from edr import procinfo

    alive = live_process.pid
    store.append(config.KIND_EXECVE, pid=999999, filename="/bin/bash",
                 starttime=1, severity=150, rules_fired="downloader_to_shell")
    store.append(config.KIND_EXECVE, pid=alive, filename="/tmp/.x",
                 starttime=procinfo.starttime(alive), severity=70,
                 rules_fired="hidden_binary")

    events = json.loads(forensic_mcp.get_kernel_alerts())

    assert [e["pid"] for e in events] == [999999, alive]
    assert events[-1]["alive"] is True
    assert events[0]["alive"] is False


def test_a_dead_process_is_still_presented(store):
    """Not filtered: it has forensic value and NOTHING is a valid answer."""
    store.append(config.KIND_EXECVE, pid=999999, filename="/bin/bash",
                 starttime=1, severity=150, rules_fired="downloader_to_shell")

    events = json.loads(forensic_mcp.get_kernel_alerts())
    assert len(events) == 1
    assert events[0]["alive"] is False


def test_among_equals_severity_decides(store):
    store.append(config.KIND_EXECVE, pid=999998, filename="/tmp/.a",
                 starttime=1, severity=70, rules_fired="hidden_binary")
    store.append(config.KIND_EXECVE, pid=999999, filename="/bin/bash",
                 starttime=1, severity=150, rules_fired="downloader_to_shell")

    events = json.loads(forensic_mcp.get_kernel_alerts())
    assert [e["severity"] for e in events] == [70, 150]


def test_annotating_does_not_dirty_the_store(store):
    """`alive` belongs to the moment the alert is served, not to the event."""
    store.append(config.KIND_MODULE_LOAD, pid=999999, comm="modprobe", starttime=1)
    forensic_mcp.get_kernel_alerts()

    assert "alive" not in store.query()[0]


# ── get_execve_events ──────────────────────────────────────────

def test_execve_of_the_pid_and_of_its_children(store):
    store.append(config.KIND_EXECVE, pid=100, ppid=1, comm="bash", filename="/bin/bash")
    store.append(config.KIND_EXECVE, pid=101, ppid=100, comm="curl", filename="/usr/bin/curl")
    store.append(config.KIND_EXECVE, pid=999, ppid=5, comm="other", filename="/bin/other")

    events = json.loads(forensic_mcp.get_execve_events(100))
    assert {e["pid"] for e in events} == {100, 101}


def test_execve_with_no_results(store):
    assert "No execve events found" in forensic_mcp.get_execve_events(12345)


# ── remediate_incident through the MCP tool ────────────────────

def test_the_tool_blocks_pid_1(store):
    output = forensic_mcp.remediate_incident(1, "kill")
    assert "BLOCKED" in output
    assert "invalid_pid" in output


def test_the_tool_blocks_a_recycled_pid(store, live_process):
    from edr import procinfo
    st = procinfo.starttime(live_process.pid)

    output = forensic_mcp.remediate_incident(live_process.pid, "kill",
                                             expected_starttime=st + 1)
    assert "BLOCKED" in output
    assert "pid_reused" in output
    assert live_process.poll() is None


# ── event ↔ pid correlation in the orchestrator ────────────────

def test_correlates_the_event_of_the_decided_pid():
    """This used to take events[0], unrelated to the pid the model chose."""
    events = [
        {"seq": 1, "pid": 100, "comm": "modprobe", "starttime": 111},
        {"seq": 2, "pid": 200, "comm": "insmod", "starttime": 222},
    ]
    found = orchestrator.find_event_for_pid(events, 200)

    assert found["comm"] == "insmod"
    assert found["starttime"] == 222


def test_correlation_returns_the_most_recent_occurrence():
    events = [
        {"seq": 1, "pid": 100, "comm": "modprobe", "starttime": 111},
        {"seq": 2, "pid": 100, "comm": "modprobe", "starttime": 333},
    ]
    assert orchestrator.find_event_for_pid(events, 100)["starttime"] == 333


def test_a_hallucinated_pid_does_not_correlate():
    """If the model invents a pid there is no event, and no starttime."""
    events = [{"seq": 1, "pid": 100, "comm": "modprobe", "starttime": 111}]
    assert orchestrator.find_event_for_pid(events, 4242) is None


# ── inspect_pid_resources: the descriptor race ─────────────────

def test_a_vanishing_descriptor_does_not_lose_the_rest(live_process, monkeypatch):
    """A single failed readlink used to discard the WHOLE result.

    A descriptor closing between listdir and readlink is the normal case in
    /proc, not an anomaly.
    """
    real_readlink = forensic_mcp.os.readlink
    calls = {"n": 0}

    def flaky_readlink(path):
        calls["n"] += 1
        if calls["n"] == 2:          # the second descriptor "closes"
            raise FileNotFoundError(path)
        return real_readlink(path)

    monkeypatch.setattr(forensic_mcp.os, "readlink", flaky_readlink)

    output = forensic_mcp.inspect_pid_resources(live_process.pid)
    assert "Opened files" in output
    assert "Error" not in output


def test_inspect_pid_resources_with_a_nonexistent_pid():
    assert "does not exist" in forensic_mcp.inspect_pid_resources(999999)


def test_inspect_pid_network_with_a_nonexistent_pid():
    assert "does not exist" in forensic_mcp.inspect_pid_network(999999)


def test_the_mcp_subprocess_inherits_the_environment(monkeypatch):
    """Regression: `EDR_MODE=autonomous` never reached the signalling process.

    The MCP SDK launches the server with `get_default_environment()`, which
    propagates only HOME, LOGNAME, PATH, SHELL, TERM and USER.
    `remediate_incident` lives in that subprocess, so the system announced
    autonomous mode in the orchestrator's banner while staying in dry-run where
    it actually mattered.
    """
    monkeypatch.setenv("EDR_MODE", "autonomous")

    params = orchestrator.mcp_server_params()

    assert params.env is not None, "without an explicit env the SDK trims it"
    assert params.env.get("EDR_MODE") == "autonomous"


def test_the_mcp_subprocess_uses_the_same_interpreter():
    """Prefixing sudo here broke the stdio channel if it asked for a password."""
    import sys

    params = orchestrator.mcp_server_params()
    assert params.command == sys.executable
    assert params.args[0].endswith("forensic_mcp.py")


def test_parse_json_list_tolerates_error_text():
    """MCP tools return plain text on failure, not JSON."""
    assert orchestrator.parse_json_list("[!] Error reading alerts file") == []
    assert orchestrator.parse_json_list("[tool-error] get_kernel_alerts: timeout") == []
    assert orchestrator.parse_json_list("No security alerts for now.") == []
    assert orchestrator.parse_json_list('{"not": "a list"}') == []
    assert orchestrator.parse_json_list('[{"pid": 1}]') == [{"pid": 1}]
