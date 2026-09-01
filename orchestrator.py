"""The EDR decision loop.

MCP client: polls the sensor for alerts, puts them to the model and acts on its
verdict. All the delicate logic lives in `edr/`; this file only choreographs.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import db
from edr import config, decision, llm, prompts

# Absolute paths derived from this file, so the system runs from any directory.
BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")

POLL_INTERVAL_S = 20
TOOL_TIMEOUT_S = 30

# Sensor coverage and losses are dumped every this many cycles in continuous
# mode. Objective O1 asks for them, and a long capture ended with Ctrl-C would
# otherwise leave no record of them at all.
STATS_EVERY_CYCLES = 10


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

async def safe_tool(session, name, **args):
    """Call an MCP tool without letting its failure bring down the loop.

    A tool can fail for perfectly normal reasons — the process died while being
    asked about — and the error is returned as text so it lands in the evidence.
    """
    try:
        result = await asyncio.wait_for(
            session.call_tool(name, arguments=args or None), timeout=TOOL_TIMEOUT_S)
        return result.content[0].text if result.content else ""
    except asyncio.TimeoutError:
        return f"[tool-error] {name} did not answer in {TOOL_TIMEOUT_S}s"
    except Exception as e:  # noqa: BLE001
        return f"[tool-error] {name}: {type(e).__name__}: {e}"


def parse_json_list(data):
    """Turn a tool response into a list. Empty if it is not JSON."""
    try:
        parsed = json.loads(data)
        return parsed if isinstance(parsed, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def find_event_for_pid(events, pid):
    """Locate the event matching the pid the model decided on.

    This used to take `events[0]`, unrelated to the chosen pid, so the stored
    `pid` and `process` could belong to different processes. It is also where
    the `starttime` that guards against pid reuse comes from.
    """
    for event in reversed(events):
        if event.get("pid") == pid:
            return event
    return None


def process_name(event):
    """Name of the process an event refers to.

    On a module load `comm` IS the process. On an execve it is not: the kernel
    has not renamed the process yet, so `comm` is the caller — it travels as
    `caller_comm` for that reason — and the real program is in `filename`.
    """
    if not event:
        return None
    if event.get("filename"):
        return os.path.basename(event["filename"])
    return event.get("comm")


async def log_sensor_stats(session):
    """Record the sensor's own probe coverage and event losses.

    Printed on a single line, behind a marker the lab harness looks for, because
    sensor_stats pretty-prints its JSON and the harness reads the log line by
    line.
    """
    raw = await safe_tool(session, "sensor_stats")
    try:
        compact = json.dumps(json.loads(raw), separators=(",", ":"),
                             ensure_ascii=False)
    except (json.JSONDecodeError, TypeError):
        compact = json.dumps({"error": str(raw)[:200]}, ensure_ascii=False)
    print(f"[sensor-stats] {compact}")


async def ask(prompt, allowed_pids, allow_investigate=True):
    """Query the model and return (Decision, LLMResult).

    An unusable reply gets one corrective retry: small models get the format
    wrong often enough that a single retry recovers most of those cases.
    """
    # The candidate pids go into the schema itself: the grammar cannot emit any
    # other value, so a wrong one is impossible rather than merely rejected.
    schema = decision.schema(allow_investigate=allow_investigate,
                             allowed_pids=allowed_pids)

    result = await llm.ask(prompt, schema=schema)
    verdict = decision.decide(result, allowed_pids)

    if verdict.action == decision.INVALID and result.ok:
        print(f"[!] Unusable verdict ({verdict.detail}). Retrying…")
        result = await llm.ask(prompt + prompts.RETRY_SUFFIX, schema=schema)
        verdict = decision.decide(result, allowed_pids)

    return verdict, result


def describe(verdict, result):
    metrics = ""
    if result and result.ok:
        metrics = (f" [{result.latency_ms} ms, "
                   f"{result.tokens_in}→{result.tokens_out} tokens, "
                   f"via {verdict.source}]")
    detail = f" — {verdict.detail}" if verdict.detail else ""
    return (f"{verdict.action} pid={verdict.pid} "
            f"action={verdict.remediation}{detail}{metrics}")


# ──────────────────────────────────────────────
# Decision cycle
# ──────────────────────────────────────────────

async def investigate(session, pid, alerts):
    """Gather forensic evidence and ask for a final verdict."""
    print(f"[*] Investigating PID {pid}…")

    resources = await safe_tool(session, "inspect_pid_resources", pid=pid)
    network = await safe_tool(session, "inspect_pid_network", pid=pid)
    execve_raw = await safe_tool(session, "get_execve_events", pid=pid)

    print(f"[*] Descriptors: {resources[:120]}")
    print(f"[*] Network:     {network[:120]}")

    prompt, allowed = prompts.round2(
        pid, alerts, resources, network, parse_json_list(execve_raw))

    verdict, result = await ask(prompt, allowed, allow_investigate=False)
    print(f"\n[AI round 2]: {result.text[:600]}")
    print(f"[*] Verdict: {describe(verdict, result)}")

    evidence = {
        "inspect_pid_resources": resources,
        "inspect_pid_network": network,
        "get_execve_events": execve_raw,
    }
    return verdict, result, evidence


async def handle_alerts(session, alerts):
    """Process a batch of alerts: reasoning, investigation and remediation."""
    print("[!] Alert detected, asking the AI (round 1)…")

    prompt, allowed = prompts.round1(alerts)
    verdict, result = await ask(prompt, allowed)

    if not result.ok:
        # No model, no decision. Logged, and the loop carries on: the sensor
        # does not stop.
        print(f"[!] The model did not answer: {result.error}")
        db.log_detection(pid=None, process=None, decision=decision.INVALID,
                         action=None, llm_round1=f"[error] {result.error}",
                         model=result.model,
                         run_id=config.RUN_ID or None,
                         scenario=config.SCENARIO or None)
        return

    print(f"\n[AI round 1]: {result.text[:600]}")
    print(f"[*] Verdict: {describe(verdict, result)}")

    # Correlate the decided pid with ITS event: that is where the process name
    # and the identity that blocks acting on a recycled pid come from.
    event = find_event_for_pid(alerts, verdict.pid) if verdict.pid else None
    process = process_name(event)
    expected_starttime = event.get("starttime") if event else None

    if (verdict.pid is not None and config.DEDUP_WINDOW_S > 0
            and db.was_recently_investigated(verdict.pid, process,
                                             window_seconds=config.DEDUP_WINDOW_S)):
        print(f"[DB] PID {verdict.pid} ({process}) analysed recently, skipping.")
        return

    # EVERY decision is logged, NOTHING verdicts without a pid included: the
    # false-negative rate is computed from exactly those rows.
    detection_id = db.log_detection(
        pid=verdict.pid,
        process=process,
        decision=verdict.action,
        action=verdict.remediation,
        llm_round1=result.text,
        model=result.model,
        latency_ms=result.latency_ms,
        tokens_in=result.tokens_in,
        tokens_out=result.tokens_out,
        # Why this event escalated, per the deterministic rules. Stored next to
        # the verdict so the model's decision can be compared with the triage's.
        severity=event.get("severity") if event else None,
        rules_fired=event.get("rules_fired") if event else None,
        # Empty outside the lab; set by scripts/lab/run_lab.py so every row can
        # be attributed to one scenario of one run.
        run_id=config.RUN_ID or None,
        scenario=config.SCENARIO or None,
    )

    if verdict.action == decision.INVESTIGATE:
        verdict, result2, evidence = await investigate(session, verdict.pid, alerts)
        if detection_id:
            for tool, value in evidence.items():
                db.log_evidence(detection_id, tool, value)
            db.update_detection(detection_id, llm_round2=result2.text,
                                decision=verdict.action, action=verdict.remediation)

    if verdict.action == decision.MITIGATE and verdict.pid is not None:
        print(f"[!] Remediating PID {verdict.pid} (action={verdict.remediation})…")
        # expected_starttime comes from the original event, never from the
        # model, so it cannot bypass the identity check.
        remediation = await safe_tool(
            session, "remediate_incident",
            pid=verdict.pid, action=verdict.remediation,
            expected_starttime=expected_starttime,
            reason=f"LLM verdict on {process}")
        print(f"[!] Result: {remediation}")
        if detection_id:
            db.update_detection(detection_id, remediation=remediation)

    elif verdict.action == decision.NOTHING:
        print("[-] No action.")
    elif verdict.action == decision.INVALID:
        print(f"[!] Verdict still unusable after the retry: {verdict.detail}")


def mcp_server_params():
    """Launch parameters for the MCP server.

    Same interpreter and same privileges as the orchestrator. Prefixing "sudo"
    here used to break the stdio channel whenever sudo asked for a password.

    **`env` must be passed explicitly.** Without it the MCP SDK uses
    `get_default_environment()`, which propagates only HOME, LOGNAME, PATH,
    SHELL, TERM and USER — so `EDR_MODE` never reached the subprocess where the
    signal is actually sent, and the orchestrator announced autonomous mode
    while the process that acts stayed in dry-run. Copying the environment
    grants nothing new: the subprocess already runs as the same user.
    """
    return StdioServerParameters(
        command=sys.executable,
        args=[str(BASE_DIR / "forensic_mcp.py")],
        env=os.environ.copy(),
    )


async def run_orchestrator(once=False):
    """Poll, decide, act. With `once`, exit after the first batch of alerts.

    `once` is what the lab harness uses: one process per scenario keeps every
    execution independent, including the in-memory rate-limit budget.
    """
    server_params = mcp_server_params()

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("[-] Connected to the MCP forensic server.")
            print(f"[-] Model: {config.MODEL} (num_ctx={config.LLM_NUM_CTX})")
            print(f"[-] Remediation mode: {config.EDR_MODE}")
            if config.RUN_ID:
                print(f"[-] Lab run: run_id={config.RUN_ID} scenario={config.SCENARIO}")

            cycles = 0
            while True:
                cycles += 1
                # Before anything else in the cycle: the "no alerts" path below
                # continues, and would otherwise skip this for hours on end.
                if cycles % STATS_EVERY_CYCLES == 0:
                    await log_sensor_stats(session)

                print("\n[*] Polling kernel alerts…")

                data = await safe_tool(session, "get_kernel_alerts")

                if "No security alerts for now" in data or data.startswith("[tool-error]"):
                    if data.startswith("[tool-error]"):
                        print(f"[!] {data}")
                    else:
                        print("[-] No alerts.")
                    await asyncio.sleep(POLL_INTERVAL_S)
                    continue

                alerts = parse_json_list(data)
                max_seq = max((e.get("seq", 0) for e in alerts), default=0)

                try:
                    await handle_alerts(session, alerts)
                finally:
                    # ALWAYS acknowledge, even if the cycle failed halfway. A
                    # transient error that prevented it would leave the same
                    # alerts being re-analysed forever. The evidence is not
                    # lost: it stays in the JSONL and in the database.
                    if max_seq:
                        await safe_tool(session, "ack_alerts", max_seq=max_seq)
                        print(f"[*] Alerts acknowledged up to seq={max_seq}.")

                if once:
                    print("[-] Single cycle requested; exiting.")
                    await log_sensor_stats(session)
                    return

                await asyncio.sleep(POLL_INTERVAL_S)


if __name__ == "__main__":
    # When the output is piped, Python switches stdout to block buffering: the
    # loop's trace stays in memory and a Ctrl-C loses all of it — precisely
    # when verifying the system, which is when it is most needed.
    sys.stdout.reconfigure(line_buffering=True)

    # eBPF and inspecting other processes' /proc need root. Failing here with a
    # clear message beats an opaque hang when the sensor starts.
    if os.geteuid() != 0:
        sys.exit(
            "[!] This program needs root (eBPF and /proc).\n"
            "    Run: sudo venv/bin/python3 orchestrator.py"
        )
    asyncio.run(run_orchestrator(once="--once" in sys.argv))
