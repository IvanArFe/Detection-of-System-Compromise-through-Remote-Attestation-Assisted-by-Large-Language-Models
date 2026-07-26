"""Tests del cliente de Ollama, sin red.

`requests.post` se sustituye por un doble. Lo que se comprueba es que ningún modo
de fallo escapa hacia el bucle de decisión: el cliente siempre devuelve un
LLMResult, nunca lanza.
"""

import json

import pytest
import requests

from edr import config, llm


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} Server Error")

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeSession:
    """Captura la petición y devuelve lo que se le indique."""

    def __init__(self, response):
        self._response = response
        self.last_json = None
        self.last_timeout = None

    def post(self, url, json=None, timeout=None):
        self.last_json = json
        self.last_timeout = timeout
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


OK_BODY = {
    "model": "llama3.1:8b",
    "response": "  DECISION: NOTHING  ",
    "prompt_eval_count": 361,
    "eval_count": 42,
    "total_duration": 3_500_000_000,   # 3,5 s en nanosegundos
}


# ── Camino feliz y métricas ────────────────────────────────────

def test_respuesta_correcta_y_metricas():
    s = FakeSession(FakeResponse(OK_BODY))
    r = llm.ask_sync("hola", session=s)

    assert r.ok
    assert r.text == "DECISION: NOTHING"     # se recorta el espacio sobrante
    assert (r.tokens_in, r.tokens_out) == (361, 42)
    assert r.latency_ms == 3500              # ns → ms, para la columna latency_ms
    assert r.model == "llama3.1:8b"


def test_se_envian_las_opciones_que_evitan_el_truncado():
    s = FakeSession(FakeResponse(OK_BODY))
    llm.ask_sync("hola", session=s)

    opciones = s.last_json["options"]
    assert opciones["num_ctx"] == config.LLM_NUM_CTX
    assert opciones["num_ctx"] > 4096, "el contexto por defecto de Ollama se queda corto"
    assert opciones["temperature"] == config.LLM_TEMPERATURE
    assert s.last_json["keep_alive"] == config.LLM_KEEP_ALIVE


def test_siempre_se_envia_timeout():
    """Sin timeout, un Ollama colgado cuelga el EDR para siempre."""
    s = FakeSession(FakeResponse(OK_BODY))
    llm.ask_sync("hola", session=s)
    assert s.last_timeout == (config.LLM_CONNECT_TIMEOUT, config.LLM_READ_TIMEOUT)


# ── Modos de fallo ─────────────────────────────────────────────

def test_timeout_no_lanza():
    r = llm.ask_sync("hola", session=FakeSession(requests.Timeout("agotado")))
    assert not r.ok
    assert "timeout" in r.error.lower()


def test_conexion_rechazada_no_lanza():
    r = llm.ask_sync("hola", session=FakeSession(
        requests.ConnectionError("connection refused")))
    assert not r.ok
    assert "ConnectionError" in r.error


def test_error_http_no_lanza():
    r = llm.ask_sync("hola", session=FakeSession(FakeResponse({}, status=500)))
    assert not r.ok


def test_respuesta_que_no_es_json_no_lanza():
    """Un proxy devolviendo HTML, por ejemplo. Es fallo de infraestructura."""
    s = FakeSession(FakeResponse(json.JSONDecodeError("no", "doc", 0)))
    r = llm.ask_sync("hola", session=s)
    assert not r.ok
    assert "JSON" in r.error


def test_respuesta_vacia_se_marca_como_error():
    s = FakeSession(FakeResponse({"response": "   "}))
    r = llm.ask_sync("hola", session=s)
    assert not r.ok


def test_sin_metricas_no_revienta():
    s = FakeSession(FakeResponse({"response": "algo"}))
    r = llm.ask_sync("hola", session=s)
    assert r.ok
    assert r.latency_ms is None and r.tokens_in is None


# ── Salida estructurada ────────────────────────────────────────

def test_el_esquema_viaja_en_format():
    s = FakeSession(FakeResponse(OK_BODY))
    esquema = {"type": "object"}
    llm.ask_sync("hola", schema=esquema, session=s)
    assert s.last_json["format"] == esquema


def test_sin_esquema_no_se_envia_format():
    s = FakeSession(FakeResponse(OK_BODY))
    llm.ask_sync("hola", session=s)
    assert "format" not in s.last_json


def test_se_parsea_la_salida_estructurada():
    body = dict(OK_BODY, response='{"action": "NOTHING", "reasoning": "ok"}')
    r = llm.ask_sync("hola", schema={"type": "object"}, session=FakeSession(
        FakeResponse(body)))
    assert r.data == {"action": "NOTHING", "reasoning": "ok"}


def test_estructura_ilegible_conserva_el_texto():
    """No es un error: la capa de decisión puede recurrir al parser anclado."""
    body = dict(OK_BODY, response="esto no es JSON")
    r = llm.ask_sync("hola", schema={"type": "object"}, session=FakeSession(
        FakeResponse(body)))
    assert r.ok
    assert r.data is None
    assert r.text == "esto no es JSON"


# ── Versión asíncrona ──────────────────────────────────────────

def test_ask_no_bloquea_el_event_loop(monkeypatch):
    """`requests` es síncrono: debe ejecutarse en un hilo aparte.

    Se comprueba que otra corrutina progresa mientras la llamada está en curso. Sin
    `asyncio.to_thread`, el event loop quedaría bloqueado toda la inferencia —
    decenas de segundos en los que el orquestador no puede hacer nada más.
    """
    import asyncio
    import time

    def lenta(*a, **k):
        time.sleep(0.2)
        return llm.LLMResult(text="DECISION: NOTHING")

    monkeypatch.setattr(llm, "ask_sync", lenta)

    async def escenario():
        latidos = 0

        async def latir():
            nonlocal latidos
            while True:
                latidos += 1
                await asyncio.sleep(0.01)

        tarea = asyncio.create_task(latir())
        resultado = await llm.ask("hola")
        tarea.cancel()
        return resultado, latidos

    resultado, latidos = asyncio.run(escenario())
    assert resultado.text == "DECISION: NOTHING"
    assert latidos > 5, "el event loop se quedó bloqueado durante la llamada"
