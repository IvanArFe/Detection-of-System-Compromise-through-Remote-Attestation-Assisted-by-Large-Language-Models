import asyncio
import re
import requests
import os
import sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from dotenv import load_dotenv
import db
import json

# Rutas absolutas derivadas del propio fichero: el orquestador ya no depende
# del directorio desde el que se lance.
BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")

# Ollama configuration
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1:8b"

async def ask_ollama(prompt):
    """ Send forensic context to Ollama and obtain an answer """
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "system": (
            "You are a Senior Linux Security Analyst and Incident Responder. "
            "Your task is to analyze kernel telemetry and decide on the next steps. "
            "IMPORTANT: All your reasoning and decisions MUST be written in English. "
            "Be concise and technical."
        )
    }
    response = requests.post(OLLAMA_URL, json=payload)
    return response.json().get("response", "")


def parse_decision(text):
    """
    Extracts the structured DECISION line from the LLM response.
    Returns a tuple: (action, pid, action_param)
    """
    mitigate = re.search(r"DECISION:\s*MITIGATE\s+pid=(\d+)\s+action=(freeze|kill)", text)
    if mitigate:
        return ("MITIGATE", int(mitigate.group(1)), mitigate.group(2))

    investigate = re.search(r"DECISION:\s*INVESTIGATE\s+pid=(\d+)", text)
    if investigate:
        return ("INVESTIGATE", int(investigate.group(1)), None)

    if "DECISION: NOTHING" in text:
        return ("NOTHING", None, None)

    return ("NOTHING", None, None)


async def run_orchestrator():
    # El servidor MCP se lanza con el mismo intérprete y los mismos privilegios
    # que el orquestador. Antes se anteponía "sudo": si sudo pedía contraseña,
    # el prompt se mezclaba con el canal stdio JSON-RPC y la sesión MCP moría
    # sin ningún mensaje de error.
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(BASE_DIR / "forensic_mcp.py")],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("[-] Connecting to MCP forensic server...")

            while True:
                print("\n[*] Monitoring kernel alerts...")

                alerts_result = await session.call_tool("get_kernel_alerts")
                data = alerts_result.content[0].text

                if "No security alerts for now" in data or "Empty" in data:
                    print("[-] No alarms in kernel.")
                    await asyncio.sleep(20)
                    continue

                print("[!] Alert detected, consulting AI (round 1)...")

                prompt_round1 = f"""
KERNEL EVENTS DETECTED:
{data}

INSTRUCTIONS:
1. Analyze the PID and the command that loaded the kernel module.
2. Evaluate if the behavior is suspicious (e.g., unexpected module loading by an unknown process).
3. Choose one of the following actions:
   - INVESTIGATE: if you need more context before deciding (open files, network, etc.)
   - MITIGATE: if you are certain this is a threat and must act immediately
   - NOTHING: if the behavior appears to be a legitimate system action

Provide your reasoning first. Then end your response with EXACTLY one of these lines:
DECISION: INVESTIGATE pid=<pid>
DECISION: MITIGATE pid=<pid> action=freeze
DECISION: MITIGATE pid=<pid> action=kill
DECISION: NOTHING
"""
                llm_response = await ask_ollama(prompt_round1)
                print(f"\n[AI round 1]: {llm_response}")

                action, pid, action_param = parse_decision(llm_response)
                print(f"[*] Parsed decision: {action} | pid={pid} | action={action_param}")

                # Obtain process name from first alert event
                process = json.loads(data)[0].get("comando", "unknown") if data != "Empty." else "unknown"

                detection_id = None
                if pid is not None:
                    # Avoid re-investigating the same process within 5 minutes
                    if db.was_recently_investigated(pid, process):
                        print(f"[DB] PID {pid} ({process}) already investigated recently, avoiding.")
                        await asyncio.sleep(20)
                        continue
                    # Log detection (round 1)
                    detection_id = db.log_detection(
                        pid=pid,
                        process=process,
                        decision=action,
                        action=action_param,
                        llm_round1=llm_response
                    )

                if action == "INVESTIGATE":
                    print(f"[*] Investigating PID {pid}...")

                    resources_result = await session.call_tool(
                        "inspect_pid_resources", arguments={"pid": pid}
                    )
                    resources = resources_result.content[0].text

                    network_result = await session.call_tool(
                        "inspect_pid_network", arguments={"pid": pid}
                    )
                    network = network_result.content[0].text

                    execve_result = await session.call_tool(
                        "get_execve_events", arguments={"pid": pid}
                    )
                    execve = execve_result.content[0].text

                    print(f"[*] Files:   {resources}")
                    print(f"[*] Network: {network}")
                    print(f"[*] Execve:  {execve}")

                    prompt_round2 = f"""
KERNEL EVENTS DETECTED:
{data}

FORENSIC EVIDENCE FOR PID {pid}:

Open file descriptors:
{resources}

Active network connections:
{network}

Process executions (this PID and its children):
{execve}

Based on all evidence above, make a final decision:
- MITIGATE: if the process is confirmed malicious
- NOTHING: if the process appears legitimate

End your response with EXACTLY one of these lines:
DECISION: MITIGATE pid={pid} action=freeze
DECISION: MITIGATE pid={pid} action=kill
DECISION: NOTHING
"""
                    llm_response2 = await ask_ollama(prompt_round2)
                    print(f"\n[AI round 2]: {llm_response2}")
                    action, pid, action_param = parse_decision(llm_response2)
                    print(f"[*] Parsed decision: {action} | pid={pid} | action={action_param}")

                    # Log forensic evidence and update detection with round 2 verdict
                    if detection_id:
                        db.log_evidence(detection_id, "inspect_pid_resources", resources)
                        db.log_evidence(detection_id, "inspect_pid_network", network)
                        db.log_evidence(detection_id, "get_execve_events", execve)
                        db.update_detection(detection_id, llm_round2=llm_response2, decision=action, action=action_param)

                if action == "MITIGATE" and pid is not None:
                    print(f"[!] Executing remediation on PID {pid} (action={action_param})...")
                    remediation_result = await session.call_tool(
                        "remediate_incident", arguments={"pid": pid, "action": action_param}
                    )
                    print(f"[!] Remediation result: {remediation_result.content[0].text}")
                    if detection_id:
                        db.update_detection(detection_id, remediation=remediation_result.content[0].text)

                elif action == "NOTHING":
                    print("[-] No action taken.")

                await asyncio.sleep(20)

if __name__ == "__main__":
    # eBPF y la inspección de /proc de otros procesos requieren root. Fallar
    # aquí con un mensaje claro evita un cuelgue opaco al arrancar el sensor.
    if os.geteuid() != 0:
        sys.exit(
            "[!] Este programa necesita root (eBPF y /proc).\n"
            "    Ejecuta: sudo venv/bin/python3 orchestrator.py"
        )
    asyncio.run(run_orchestrator())
