"""Ollama client. Nothing here raises: it always returns an `LLMResult`.

Context overflow is handled in edr/prompts.py rather than delegated to Ollama,
because Ollama discards the HEAD of the prompt and keeps the tail — so the
DECISION line always survives while the evidence disappears silently.
"""

import asyncio
import json
import logging
from dataclasses import dataclass

import requests

from . import config

log = logging.getLogger("edr.llm")


@dataclass
class LLMResult:
    """One query's result, including the metrics that feed the phase 7 tables."""

    text: str = ""
    data: dict | None = None          # only when structured output was requested
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
    """Blocking query. `ask()` wraps it so the event loop stays free.

    `schema` is a JSON Schema passed in Ollama's `format` parameter. Verified
    with llama3.1:8b: valid JSON, enums respected — far more reliable than a
    regex over free prose.
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
                         error=f"timed out after {config.LLM_READ_TIMEOUT:.0f}s")
    except requests.RequestException as e:
        return LLMResult(model=config.MODEL, error=f"{type(e).__name__}: {e}")
    except ValueError as e:
        # Ollama returned something that is not JSON — a proxy error page, say.
        # Infrastructure failure, not a model failure.
        return LLMResult(model=config.MODEL, error=f"response is not JSON: {e}")

    text = (body.get("response") or "").strip()

    result = LLMResult(
        text=text,
        model=body.get("model", config.MODEL),
        tokens_in=body.get("prompt_eval_count"),
        tokens_out=body.get("eval_count"),
    )
    # total_duration comes in nanoseconds.
    if isinstance(body.get("total_duration"), (int, float)):
        result.latency_ms = int(body["total_duration"] / 1_000_000)

    if schema is not None:
        try:
            result.data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            # Not flagged as an error: the text is still there and the decision
            # layer can fall back to the anchored parser.
            log.warning("structured output requested but the response does not parse")

    if not text:
        result.error = "empty response"

    return result


async def ask(prompt, system=None, schema=None):
    """Async wrapper. `requests` is synchronous, so the call goes to a thread:
    running it inline would block the event loop for the whole inference.
    """
    return await asyncio.to_thread(ask_sync, prompt, system, schema)
