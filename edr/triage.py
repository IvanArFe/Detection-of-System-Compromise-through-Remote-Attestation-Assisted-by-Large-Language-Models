"""Deterministic triage: decides which events are worth asking the model about.

Cheap objective facts are settled by a rule; expensive reasoning is reserved for
what already looks suspicious. This is the minimal version of what phase 5 will
be (rules + ATT&CK + host baseline).

Rule slugs are stable and machine-readable, like the ones in safety.py: they are
aggregated in the lab statistics and stored in the `rules_fired` column, so
renaming one breaks the comparison between runs.
"""

import ipaddress
import os
import re

from . import config

# ──────────────────────────────────────────────
# Weights
# ──────────────────────────────────────────────

# Anyone can write here. Not malicious by itself, but it is where almost
# everything that gets downloaded lands.
WORLD_WRITABLE = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")

DOWNLOADERS = frozenset({"curl", "wget"})
NETCATS = frozenset({"nc", "ncat", "netcat", "nc.traditional"})

# A pipe into a shell only shows up under `sh -c "…"`, which is exactly how real
# droppers run: a normal shell consumes the `|` and never passes it in argv.
_PIPE_TO_SHELL = re.compile(r"\|\s*(?:/[\w/]*/)?(?:ba|da|z|k|a)?sh\b")

# Canonical reverse shell in bash without external tools.
_NET_REDIRECT = re.compile(r"/dev/(?:tcp|udp)/")

_URL = re.compile(r"https?://([^/\s:]+)")

# The threshold itself lives in config so it can be moved without touching code.
WEIGHTS = {
    "exec_from_world_writable": 40,
    "hidden_binary": 30,
    "pipe_to_shell": 40,
    "downloader_to_shell": 60,
    "download_from_public_ip": 50,
    "shell_net_redirect": 60,
    "netcat_exec": 60,
}


# ──────────────────────────────────────────────
# Rules
# ──────────────────────────────────────────────

def _is_public_ip(host):
    """True if `host` is a literal IP and globally routable.

    The routability check is what keeps the rule from firing on our own
    infrastructure — every `curl http://127.0.0.1:11434/…` to Ollama.
    """
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False   # it is a domain name
    return ip.is_global


def assess(event):
    """Score an execve event. Returns `(severity, [rule slugs])`.

    Pure: no /proc, no network, no clock. That is what makes it testable without
    root and what makes every escalation defensible after the fact.
    """
    filename = (event.get("filename") or "").strip()
    cmdline = (event.get("cmdline") or "").strip()

    if not filename and not cmdline:
        return 0, []

    base = os.path.basename(filename)
    rules = []

    if filename.startswith(WORLD_WRITABLE):
        rules.append("exec_from_world_writable")

    if base.startswith(".") and base not in (".", ".."):
        rules.append("hidden_binary")

    piped = bool(_PIPE_TO_SHELL.search(cmdline))
    if piped:
        rules.append("pipe_to_shell")

    # A downloader can be the executed binary itself or be quoted inside a
    # `sh -c` command, which is the usual dropper shape.
    downloader = base in DOWNLOADERS or any(
        re.search(rf"\b{d}\b", cmdline) for d in DOWNLOADERS)

    if downloader and piped:
        rules.append("downloader_to_shell")

    if downloader:
        for host in _URL.findall(cmdline):
            if _is_public_ip(host):
                rules.append("download_from_public_ip")
                break

    if _NET_REDIRECT.search(cmdline):
        rules.append("shell_net_redirect")

    if base in NETCATS and re.search(r"(?:^|\s)-\w*[ec]", cmdline):
        rules.append("netcat_exec")

    return sum(WEIGHTS[r] for r in rules), rules


def should_escalate(event, threshold=None):
    """True if the event is worth asking the model about."""
    threshold = config.TRIAGE_THRESHOLD if threshold is None else threshold
    severity, _ = assess(event)
    return severity >= threshold


def is_alert(event, threshold=None):
    """True if the event belongs in `get_kernel_alerts()`.

    Module loads always escalate: they are inherently privileged and rare.
    Execve events go through the triage.
    """
    # A process from another PID namespace cannot be interpreted or signalled
    # from here. It is kept in the forensic record but never escalated.
    if event.get("foreign_ns"):
        return False

    if event.get("kind") == config.KIND_MODULE_LOAD:
        return True
    if event.get("kind") != config.KIND_EXECVE:
        return False

    threshold = config.TRIAGE_THRESHOLD if threshold is None else threshold

    # Severity is computed once, on ingest, and travels with the event.
    # Recomputing here would re-evaluate thousands of events every cycle; the
    # fallback only covers events that never went through the sensor.
    severity = event.get("severity")
    if severity is None:
        severity, _ = assess(event)
    return severity >= threshold
