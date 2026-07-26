import asyncio
import json
import os
import re
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import db
from edr import config

# Rutas absolutas derivadas del propio fichero: el orquestador ya no depende
# del directorio desde el que se lance.
BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")

# Ollama configuration
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1:8b"

POLL_INTERVAL_S = 20


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


def parse_alerts(data):
    """Convierte la respuesta de get_kernel_alerts en una lista de eventos."""
    try:
        events = json.loads(data)
        return events if isinstance(events, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def find_event_for_pid(events, pid):
    """Localiza el evento que corresponde al PID decidido por el modelo.

    Antes se cogía `events[0]`, es decir el PRIMER evento del lote, sin ninguna
    relación con el PID elegido: los campos `pid` y `process` que se guardaban en
    la base de datos podían pertenecer a procesos distintos. Además es de aquí de
    donde sale el `starttime` que protege contra la reutilización de PID, así que
    la correlación tiene que ser exacta.

    Se recorre de atrás hacia delante para quedarse con la aparición más reciente.
    """
    for event in reversed(events):
        if event.get("pid") == pid:
            return event
    return None


async def investigate(session, pid, data):
    """Recopila evidencia forense y pide al modelo un veredicto final."""
    print(f"[*] Investigating PID {pid}...")

    resources = (await session.call_tool(
        "inspect_pid_resources", arguments={"pid": pid})).content[0].text
    network = (await session.call_tool(
        "inspect_pid_network", arguments={"pid": pid})).content[0].text
    execve = (await session.call_tool(
        "get_execve_events", arguments={"pid": pid})).content[0].text

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

    return llm_response2, {
        "inspect_pid_resources": resources,
        "inspect_pid_network": network,
        "get_execve_events": execve,
    }


async def handle_alerts(session, data, events):
    """Procesa un lote de alertas: razonamiento, investigación y remediación."""
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

    # Correlacionar el PID decidido con SU evento: de ahí salen tanto el nombre
    # del proceso como la identidad que impide actuar sobre un PID reciclado.
    event = find_event_for_pid(events, pid) if pid is not None else None
    process = event.get("comm", "unknown") if event else "unknown"
    expected_starttime = event.get("starttime") if event else None

    if pid is not None and event is None:
        # El modelo ha devuelto un PID que no estaba en la telemetría que se le
        # dio: o lo ha alucinado, o procede de una inyección en el prompt.
        print(f"[!] AVISO: el PID {pid} no aparece en las alertas presentadas.")

    detection_id = None
    if pid is not None:
        if db.was_recently_investigated(pid, process):
            print(f"[DB] PID {pid} ({process}) already investigated recently, avoiding.")
            return
        detection_id = db.log_detection(
            pid=pid,
            process=process,
            decision=action,
            action=action_param,
            llm_round1=llm_response,
        )

    if action == "INVESTIGATE":
        llm_response2, evidence = await investigate(session, pid, data)
        action, pid, action_param = parse_decision(llm_response2)
        print(f"[*] Parsed decision: {action} | pid={pid} | action={action_param}")

        if detection_id:
            for tool, result in evidence.items():
                db.log_evidence(detection_id, tool, result)
            db.update_detection(detection_id, llm_round2=llm_response2,
                                decision=action, action=action_param)

    if action == "MITIGATE" and pid is not None:
        print(f"[!] Executing remediation on PID {pid} (action={action_param})...")
        # expected_starttime lo aporta el orquestador desde el evento original,
        # nunca el modelo: así no puede saltarse la validación de identidad.
        remediation = (await session.call_tool("remediate_incident", arguments={
            "pid": pid,
            "action": action_param,
            "expected_starttime": expected_starttime,
            "reason": f"LLM verdict on {process}",
        })).content[0].text
        print(f"[!] Remediation result: {remediation}")
        if detection_id:
            db.update_detection(detection_id, remediation=remediation)

    elif action == "NOTHING":
        print("[-] No action taken.")


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
            print(f"[-] Remediation mode: {config.EDR_MODE}")

            while True:
                print("\n[*] Monitoring kernel alerts...")

                alerts_result = await session.call_tool("get_kernel_alerts")
                data = alerts_result.content[0].text

                if "No security alerts for now" in data:
                    print("[-] No alarms in kernel.")
                    await asyncio.sleep(POLL_INTERVAL_S)
                    continue

                events = parse_alerts(data)
                max_seq = max((e.get("seq", 0) for e in events), default=0)

                try:
                    await handle_alerts(session, data, events)
                finally:
                    # Confirmar SIEMPRE, incluso si el ciclo falló a medias. Si un
                    # error transitorio impidiera confirmar, esas mismas alertas se
                    # reanalizarían en cada vuelta para siempre — que es justo el
                    # comportamiento que esta fase elimina. La evidencia no se
                    # pierde: sigue en el JSONL y en la base de datos.
                    if max_seq:
                        await session.call_tool(
                            "ack_alerts", arguments={"max_seq": max_seq})
                        print(f"[*] Alerts acknowledged up to seq={max_seq}.")

                await asyncio.sleep(POLL_INTERVAL_S)


if __name__ == "__main__":
    # Al canalizar la salida (`| tee`, `> fichero`), Python cambia stdout a buffer
    # de bloque: la traza del bucle se queda en memoria y un Ctrl-C la pierde
    # entera. Es justo lo que pasa al verificar el sistema, que es cuando más
    # falta hace verla.
    sys.stdout.reconfigure(line_buffering=True)

    # eBPF y la inspección de /proc de otros procesos requieren root. Fallar
    # aquí con un mensaje claro evita un cuelgue opaco al arrancar el sensor.
    if os.geteuid() != 0:
        sys.exit(
            "[!] Este programa necesita root (eBPF y /proc).\n"
            "    Ejecuta: sudo venv/bin/python3 orchestrator.py"
        )
    asyncio.run(run_orchestrator())
