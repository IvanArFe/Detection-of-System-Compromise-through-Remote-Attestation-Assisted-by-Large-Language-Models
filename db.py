"""Persistencia de detecciones y evidencia en Supabase.

**Principio de diseño de este módulo: la persistencia es telemetría, no una
dependencia de la detección.** Que la base de datos remota esté caída no puede
detener el EDR.

No es una precaución teórica. El 26/07/2026, durante la verificación de la Fase 0,
este módulo tumbó el orquestador entero dos veces en el mismo día por dos causas
distintas: un `httpx.ConnectError` transitorio tras reconfigurarse la red al
instalar Docker, y un `521` de Cloudflare porque el proyecto gratuito de Supabase
se había auto-pausado tras meses inactivo. Ninguna de las dos tiene nada que ver
con la capacidad de detectar amenazas, y ambas dejaron el sistema muerto.

Ahora cada operación degrada a un JSONL local y el ciclo de decisión continúa.
"""

import json
import logging
import os
import threading
from datetime import datetime, timedelta, timezone

from supabase import create_client

from edr import config

log = logging.getLogger("edr.db")

_client = None
_client_failed = False
_fallback_lock = threading.Lock()


def get_client():
    global _client
    if _client is None:
        url = os.environ["SUPABASE_URL"]
        key = os.environ["SUPABASE_KEY"]
        _client = create_client(url, key)
    return _client


def _fallback(operation, payload):
    """Registra localmente lo que no se pudo enviar a Supabase.

    Es un JSONL append-only, igual que el registro de eventos: si más adelante hay
    que reconstruir lo ocurrido durante una caída, la información está aquí.
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "payload": payload,
    }
    try:
        with _fallback_lock:
            with open(config.DB_FALLBACK_JSONL, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except OSError as e:
        log.error("tampoco se pudo escribir el respaldo local: %s", e)


def _warn_once(e):
    """Avisa del primer fallo con detalle y de los siguientes de forma escueta.

    El bucle consulta cada 20 s: sin esto, una caída prolongada de Supabase llena
    la salida de trazas idénticas y esconde lo que sí importa.
    """
    global _client_failed
    if not _client_failed:
        _client_failed = True
        log.warning("Supabase no disponible (%s: %s). Se continúa con respaldo local en %s. "
                    "Si el proyecto es gratuito, comprueba que no esté pausado: "
                    "https://supabase.com/dashboard",
                    type(e).__name__, e, config.DB_FALLBACK_JSONL)
    else:
        log.debug("Supabase sigue no disponible: %s", type(e).__name__)


def log_detection(pid, process, decision, action, llm_round1,
                  llm_round2=None, remediation=None, **extra):
    """Inserta una detección. Devuelve su UUID, o None si no se pudo persistir.

    `extra` recoge las columnas añadidas para las fases 5-7 (`model`, `latency_ms`,
    `tokens_in`, `tokens_out`, `severity`, `mitre_technique`…). Se aceptan como
    kwargs para que añadir una métrica nueva no obligue a cambiar esta firma.

    `pid` y `process` pueden ser None: un veredicto NOTHING sin PID también se
    registra, porque sin esas filas no se puede calcular la tasa de falsos
    negativos.
    """
    row = {
        "pid": pid,
        "process": process,
        "decision": decision,
        "action": action,
        "llm_round1": llm_round1,
        "llm_round2": llm_round2,
        "remediation": remediation,
        **extra,
    }
    try:
        res = get_client().table("detections").insert(row).execute()
        return res.data[0]["id"]
    except Exception as e:  # noqa: BLE001 — cualquier fallo debe degradar, no propagar
        _warn_once(e)
        _fallback("log_detection", row)
        return None


def update_detection(detection_id, **fields):
    if not detection_id:
        return False
    try:
        get_client().table("detections").update(fields).eq("id", detection_id).execute()
        return True
    except Exception as e:  # noqa: BLE001
        _warn_once(e)
        _fallback("update_detection", {"id": detection_id, **fields})
        return False


def log_evidence(detection_id, tool, result):
    if not detection_id:
        return False
    row = {"detection_id": detection_id, "tool": tool, "result": result}
    try:
        get_client().table("evidence").insert(row).execute()
        return True
    except Exception as e:  # noqa: BLE001
        _warn_once(e)
        _fallback("log_evidence", row)
        return False


def was_recently_investigated(pid, process, window_seconds=300):
    """True si el mismo (pid, proceso) ya se analizó en la ventana indicada.

    **Ante un fallo devuelve False (fail-open).** La alternativa —asumir que ya se
    investigó y no analizar— convertiría una caída de la base de datos en una
    ceguera total del EDR. Analizar dos veces un incidente es un desperdicio;
    no analizarlo es un fallo de seguridad.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    try:
        res = (
            get_client().table("detections")
            .select("id")
            .eq("pid", pid)
            .eq("process", process)
            .gte("created_at", cutoff)
            .limit(1)
            .execute()
        )
        return len(res.data) > 0
    except Exception as e:  # noqa: BLE001
        _warn_once(e)
        return False
