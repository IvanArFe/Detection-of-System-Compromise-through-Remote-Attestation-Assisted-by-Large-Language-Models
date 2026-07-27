"""Bucle de decisión del EDR.

Cliente MCP que sondea las alertas del sensor, se las plantea al modelo y actúa
según su veredicto. Toda la lógica delicada vive en `edr/`: aquí solo queda la
coreografía.
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

# Rutas absolutas derivadas del propio fichero: el orquestador ya no depende
# del directorio desde el que se lance.
BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")

POLL_INTERVAL_S = 20
TOOL_TIMEOUT_S = 30


# ──────────────────────────────────────────────
# Utilidades
# ──────────────────────────────────────────────

async def safe_tool(session, name, **args):
    """Invoca una herramienta MCP sin que un fallo suyo tumbe el bucle.

    Una herramienta puede fallar por motivos perfectamente normales —el proceso
    murió mientras se le preguntaba— y eso no debe interrumpir el ciclo de
    decisión. El error se devuelve como texto para que quede en la evidencia.
    """
    try:
        result = await asyncio.wait_for(
            session.call_tool(name, arguments=args or None), timeout=TOOL_TIMEOUT_S)
        return result.content[0].text if result.content else ""
    except asyncio.TimeoutError:
        return f"[tool-error] {name} no respondió en {TOOL_TIMEOUT_S}s"
    except Exception as e:  # noqa: BLE001
        return f"[tool-error] {name}: {type(e).__name__}: {e}"


def parse_json_list(data):
    """Convierte la respuesta de una herramienta en lista. Vacía si no es JSON."""
    try:
        parsed = json.loads(data)
        return parsed if isinstance(parsed, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def find_event_for_pid(events, pid):
    """Localiza el evento que corresponde al PID decidido por el modelo.

    Antes se cogía `events[0]`, el primer evento del lote, sin ninguna relación con
    el PID elegido: los campos `pid` y `process` que se guardaban podían pertenecer
    a procesos distintos. Además es de aquí de donde sale el `starttime` que
    protege contra la reutilización de PID.
    """
    for event in reversed(events):
        if event.get("pid") == pid:
            return event
    return None


def process_name(event):
    """Nombre del proceso al que se refiere un evento.

    En una carga de módulo `comm` ES el proceso. En un execve todavía no: en ese
    punto el kernel aún no ha cambiado el nombre, así que `comm` es el de quien
    llama —viaja como `caller_comm` precisamente para no confundirlos— y el
    programa que se está ejecutando es el de `filename`.
    """
    if not event:
        return None
    if event.get("filename"):
        return os.path.basename(event["filename"])
    return event.get("comm")


async def ask(prompt, allowed_pids, allow_investigate=True):
    """Consulta al modelo y devuelve (Decision, LLMResult).

    Ante una respuesta ininteligible se reintenta una vez con un prompt correctivo.
    Los modelos pequeños fallan el formato con cierta frecuencia y un reintento
    recupera la mayoría de esos casos.
    """
    # Los PIDs candidatos entran en el propio esquema: la gramática impide que el
    # modelo emita otro valor, en vez de tener que rechazarlo después.
    schema = decision.schema(allow_investigate=allow_investigate,
                             allowed_pids=allowed_pids)

    result = await llm.ask(prompt, schema=schema)
    verdict = decision.decide(result, allowed_pids)

    if verdict.action == decision.INVALID and result.ok:
        print(f"[!] Veredicto no interpretable ({verdict.detail}). Reintentando…")
        result = await llm.ask(prompt + prompts.RETRY_SUFFIX, schema=schema)
        verdict = decision.decide(result, allowed_pids)

    return verdict, result


def describe(verdict, result):
    metrics = ""
    if result and result.ok:
        metrics = (f" [{result.latency_ms} ms, "
                   f"{result.tokens_in}→{result.tokens_out} tokens, "
                   f"vía {verdict.source}]")
    detail = f" — {verdict.detail}" if verdict.detail else ""
    return (f"{verdict.action} pid={verdict.pid} "
            f"action={verdict.remediation}{detail}{metrics}")


# ──────────────────────────────────────────────
# Ciclo de decisión
# ──────────────────────────────────────────────

async def investigate(session, pid, alerts):
    """Recopila evidencia forense y pide un veredicto final."""
    print(f"[*] Investigando PID {pid}…")

    resources = await safe_tool(session, "inspect_pid_resources", pid=pid)
    network = await safe_tool(session, "inspect_pid_network", pid=pid)
    execve_raw = await safe_tool(session, "get_execve_events", pid=pid)

    print(f"[*] Descriptores: {resources[:120]}")
    print(f"[*] Red:          {network[:120]}")

    prompt, allowed = prompts.round2(
        pid, alerts, resources, network, parse_json_list(execve_raw))

    verdict, result = await ask(prompt, allowed, allow_investigate=False)
    print(f"\n[IA ronda 2]: {result.text[:600]}")
    print(f"[*] Veredicto: {describe(verdict, result)}")

    evidence = {
        "inspect_pid_resources": resources,
        "inspect_pid_network": network,
        "get_execve_events": execve_raw,
    }
    return verdict, result, evidence


async def handle_alerts(session, alerts):
    """Procesa un lote de alertas: razonamiento, investigación y remediación."""
    print("[!] Alerta detectada, consultando a la IA (ronda 1)…")

    prompt, allowed = prompts.round1(alerts)
    verdict, result = await ask(prompt, allowed)

    if not result.ok:
        # Sin modelo no hay decisión. Se registra y se sigue: el sensor no para.
        print(f"[!] El modelo no respondió: {result.error}")
        db.log_detection(pid=None, process=None, decision=decision.INVALID,
                         action=None, llm_round1=f"[error] {result.error}",
                         model=result.model)
        return

    print(f"\n[IA ronda 1]: {result.text[:600]}")
    print(f"[*] Veredicto: {describe(verdict, result)}")

    # Correlacionar el PID decidido con SU evento: de ahí salen el nombre del
    # proceso y la identidad que impide actuar sobre un PID reciclado.
    event = find_event_for_pid(alerts, verdict.pid) if verdict.pid else None
    process = process_name(event)
    expected_starttime = event.get("starttime") if event else None

    if verdict.pid is not None and db.was_recently_investigated(verdict.pid, process):
        print(f"[DB] PID {verdict.pid} ({process}) ya analizado hace poco, se omite.")
        return

    # Se registra TODA decisión, incluidas las NOTHING sin PID. Sin esas filas no
    # se puede calcular la tasa de falsos negativos.
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
        # Por qué escaló este evento, según las reglas deterministas. Guardarlo
        # junto al veredicto es lo que permite comparar después qué decidió el
        # modelo frente a lo que ya decía el triaje.
        severity=event.get("severity") if event else None,
        rules_fired=event.get("rules_fired") if event else None,
    )

    if verdict.action == decision.INVESTIGATE:
        verdict, result2, evidence = await investigate(session, verdict.pid, alerts)
        if detection_id:
            for tool, value in evidence.items():
                db.log_evidence(detection_id, tool, value)
            db.update_detection(detection_id, llm_round2=result2.text,
                                decision=verdict.action, action=verdict.remediation)

    if verdict.action == decision.MITIGATE and verdict.pid is not None:
        print(f"[!] Remediando PID {verdict.pid} (acción={verdict.remediation})…")
        # expected_starttime lo aporta el orquestador desde el evento original,
        # nunca el modelo: así no puede saltarse la validación de identidad.
        remediation = await safe_tool(
            session, "remediate_incident",
            pid=verdict.pid, action=verdict.remediation,
            expected_starttime=expected_starttime,
            reason=f"veredicto del LLM sobre {process}")
        print(f"[!] Resultado: {remediation}")
        if detection_id:
            db.update_detection(detection_id, remediation=remediation)

    elif verdict.action == decision.NOTHING:
        print("[-] Sin acción.")
    elif verdict.action == decision.INVALID:
        print(f"[!] Veredicto inutilizable tras el reintento: {verdict.detail}")


def mcp_server_params():
    """Parámetros de lanzamiento del servidor MCP.

    El servidor se lanza con el mismo intérprete y los mismos privilegios que el
    orquestador. Antes se anteponía "sudo": si sudo pedía contraseña, el prompt se
    mezclaba con el canal stdio JSON-RPC y la sesión MCP moría sin ningún mensaje.

    **`env` hay que pasarlo explícitamente.** Sin él, el SDK de MCP lanza el
    servidor con `get_default_environment()`, que solo propaga HOME, LOGNAME,
    PATH, SHELL, TERM y USER. `EDR_MODE` no está en esa lista, así que
    `sudo EDR_MODE=autonomous ... orchestrator.py` dejaba al orquestador
    anunciando modo autónomo mientras el subproceso —que es donde vive
    `remediate_incident` y donde se envía la señal— seguía en dry-run. El sistema
    nunca llegó a actuar de verdad, y el banner del orquestador decía lo
    contrario.

    Copiar el entorno no concede nada nuevo: el subproceso ya corre con el mismo
    usuario y los mismos privilegios.
    """
    return StdioServerParameters(
        command=sys.executable,
        args=[str(BASE_DIR / "forensic_mcp.py")],
        env=os.environ.copy(),
    )


async def run_orchestrator():
    server_params = mcp_server_params()

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("[-] Conectado al servidor forense MCP.")
            print(f"[-] Modelo: {config.MODEL} (num_ctx={config.LLM_NUM_CTX})")
            print(f"[-] Modo de remediación: {config.EDR_MODE}")

            while True:
                print("\n[*] Consultando alertas del kernel…")

                data = await safe_tool(session, "get_kernel_alerts")

                if "No security alerts for now" in data or data.startswith("[tool-error]"):
                    if data.startswith("[tool-error]"):
                        print(f"[!] {data}")
                    else:
                        print("[-] Sin alertas.")
                    await asyncio.sleep(POLL_INTERVAL_S)
                    continue

                alerts = parse_json_list(data)
                max_seq = max((e.get("seq", 0) for e in alerts), default=0)

                try:
                    await handle_alerts(session, alerts)
                finally:
                    # Confirmar SIEMPRE, incluso si el ciclo falló a medias. Si un
                    # error transitorio impidiera confirmar, esas mismas alertas se
                    # reanalizarían en cada vuelta para siempre — que es justo el
                    # comportamiento que la fase 1 eliminó. La evidencia no se
                    # pierde: sigue en el JSONL y en la base de datos.
                    if max_seq:
                        await safe_tool(session, "ack_alerts", max_seq=max_seq)
                        print(f"[*] Alertas confirmadas hasta seq={max_seq}.")

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
