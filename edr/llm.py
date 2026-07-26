"""Cliente de Ollama.

Sustituye a la función `ask_ollama` original, que tenía tres problemas en quince
líneas:

- **Sin `timeout`.** Si Ollama se colgaba, el EDR se colgaba con él, para siempre
  y sin ningún mensaje.
- **Era `async def` pero llamaba a `requests.post` síncrono**, bloqueando el event
  loop de asyncio durante toda la inferencia.
- **No pasaba `options`**, así que Ollama usaba su `num_ctx` por defecto (4096 en
  la 0.32). Medido: un prompt de ronda 2 con 50 eventos execve ocupa ya ~2563
  tokens solo en esa sección.

Sobre el desbordamiento de contexto conviene ser preciso, porque es contraintuitivo.
Medido contra Ollama 0.32.4 con `num_ctx=512` y un prompt de ~3400 tokens: una
instrucción colocada al FINAL se obedece, y la misma instrucción al PRINCIPIO se
ignora por completo. **Ollama descarta la cabeza del prompt y conserva la cola.**
Es decir, la línea `DECISION:` nunca se pierde — lo que desaparece, en silencio, es
la evidencia. El modelo responde entonces con total seguridad sobre datos que nunca
vio y cuya ausencia desconoce, que es un fallo bastante peor que una respuesta
truncada: ésta se detectaría al instante.

De ahí que el recorte se haga explícitamente en `edr/prompts.py` y no se delegue en
Ollama.

Nada de este módulo lanza excepciones: siempre devuelve un `LLMResult`.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field

import requests

from . import config

log = logging.getLogger("edr.llm")


@dataclass
class LLMResult:
    """Resultado de una consulta, incluidas las métricas que alimentan la Fase 7."""

    text: str = ""
    data: dict | None = None          # solo si se pidió salida estructurada
    latency_ms: int | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    model: str = ""
    error: str | None = None

    @property
    def ok(self):
        return self.error is None


SYSTEM_PROMPT = (
    "You are a Senior Linux Security Analyst and Incident Responder. "
    "Your task is to analyze kernel telemetry and decide on the next steps. "
    "IMPORTANT: All your reasoning and decisions MUST be written in English. "
    "Be concise and technical."
)


def _options():
    return {
        "temperature": config.LLM_TEMPERATURE,
        "top_p": config.LLM_TOP_P,
        "num_ctx": config.LLM_NUM_CTX,
        "num_predict": config.LLM_NUM_PREDICT,
    }


def ask_sync(prompt, system=None, schema=None, session=None):
    """Consulta bloqueante. `ask()` la envuelve para no bloquear el event loop.

    `schema` es un JSON Schema que se pasa en el parámetro `format` de Ollama.
    Verificado con llama3.1:8b: devuelve JSON válido y respeta los `enum`, lo que
    es órdenes de magnitud más fiable que aplicar una regex sobre prosa libre.
    """
    payload = {
        "model": config.MODEL,
        "prompt": prompt,
        "stream": False,
        "system": system or SYSTEM_PROMPT,
        "options": _options(),
        "keep_alive": config.LLM_KEEP_ALIVE,
    }
    if schema is not None:
        payload["format"] = schema

    post = (session or requests).post
    try:
        response = post(
            f"{config.OLLAMA_URL}/api/generate",
            json=payload,
            timeout=(config.LLM_CONNECT_TIMEOUT, config.LLM_READ_TIMEOUT),
        )
        response.raise_for_status()
        body = response.json()
    except requests.Timeout:
        return LLMResult(model=config.MODEL,
                         error=f"timeout tras {config.LLM_READ_TIMEOUT:.0f}s")
    except requests.RequestException as e:
        return LLMResult(model=config.MODEL, error=f"{type(e).__name__}: {e}")
    except ValueError as e:
        # Ollama devolvió algo que no es JSON (una página de error de un proxy,
        # por ejemplo). Es un fallo de infraestructura, no del modelo.
        return LLMResult(model=config.MODEL, error=f"respuesta no es JSON: {e}")

    text = (body.get("response") or "").strip()

    result = LLMResult(
        text=text,
        model=body.get("model", config.MODEL),
        tokens_in=body.get("prompt_eval_count"),
        tokens_out=body.get("eval_count"),
    )
    # total_duration viene en nanosegundos.
    if isinstance(body.get("total_duration"), (int, float)):
        result.latency_ms = int(body["total_duration"] / 1_000_000)

    if schema is not None:
        try:
            result.data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            # No se marca como error: el texto sigue ahí y la capa de decisión
            # puede recurrir al parser anclado.
            log.warning("se pidió salida estructurada pero la respuesta no parsea")

    if not text:
        result.error = "respuesta vacía"

    return result


async def ask(prompt, system=None, schema=None):
    """Versión asíncrona. La llamada HTTP va a un hilo aparte.

    `requests` es síncrono: invocarlo directamente desde una corrutina bloquea el
    event loop durante toda la inferencia, que son decenas de segundos.
    """
    return await asyncio.to_thread(ask_sync, prompt, system, schema)
