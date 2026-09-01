"""Tests for the Ollama client, without network.

`requests.post` is replaced by a double. What is checked is that no failure mode
escapes into the decision loop: the client always returns an LLMResult and never
raises.
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
    """Capture the request and return whatever it was given."""

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
    "total_duration": 3_500_000_000,   # 3.5 s in nanoseconds
}


# ── Happy path and metrics ─────────────────────────────────────

def test_a_correct_response_and_its_metrics():
    s = FakeSession(FakeResponse(OK_BODY))
    r = llm.ask_sync("hello", session=s)

    assert r.ok
    assert r.text == "DECISION: NOTHING"     # surrounding whitespace trimmed
    assert (r.tokens_in, r.tokens_out) == (361, 42)
    assert r.latency_ms == 3500              # ns → ms, for the latency_ms column
    assert r.model == "llama3.1:8b"


def test_the_options_that_prevent_truncation_are_sent():
    s = FakeSession(FakeResponse(OK_BODY))
    llm.ask_sync("hello", session=s)

    options = s.last_json["options"]
    assert options["num_ctx"] == config.LLM_NUM_CTX
    assert options["num_ctx"] > 4096, "Ollama's default context is too small"
    assert options["temperature"] == config.LLM_TEMPERATURE
    assert s.last_json["keep_alive"] == config.LLM_KEEP_ALIVE


def test_a_timeout_is_always_sent():
    """Without one, a hung Ollama hangs the EDR forever."""
    s = FakeSession(FakeResponse(OK_BODY))
    llm.ask_sync("hello", session=s)
    assert s.last_timeout == (config.LLM_CONNECT_TIMEOUT, config.LLM_READ_TIMEOUT)


# ── Failure modes ──────────────────────────────────────────────

def test_a_timeout_does_not_raise():
    r = llm.ask_sync("hello", session=FakeSession(requests.Timeout("expired")))
    assert not r.ok
    assert "timed out" in r.error.lower()


def test_a_refused_connection_does_not_raise():
    r = llm.ask_sync("hello", session=FakeSession(
        requests.ConnectionError("connection refused")))
    assert not r.ok
    assert "ConnectionError" in r.error


def test_an_http_error_does_not_raise():
    r = llm.ask_sync("hello", session=FakeSession(FakeResponse({}, status=500)))
    assert not r.ok


def test_a_non_json_response_does_not_raise():
    """A proxy returning HTML, say. That is an infrastructure failure."""
    s = FakeSession(FakeResponse(json.JSONDecodeError("no", "doc", 0)))
    r = llm.ask_sync("hello", session=s)
    assert not r.ok
    assert "JSON" in r.error


def test_an_empty_response_is_flagged_as_an_error():
    s = FakeSession(FakeResponse({"response": "   "}))
    r = llm.ask_sync("hello", session=s)
    assert not r.ok


def test_missing_metrics_do_not_blow_up():
    s = FakeSession(FakeResponse({"response": "something"}))
    r = llm.ask_sync("hello", session=s)
    assert r.ok
    assert r.latency_ms is None and r.tokens_in is None


# ── Structured output ──────────────────────────────────────────

def test_the_schema_travels_in_format():
    s = FakeSession(FakeResponse(OK_BODY))
    the_schema = {"type": "object"}
    llm.ask_sync("hello", schema=the_schema, session=s)
    assert s.last_json["format"] == the_schema


def test_without_a_schema_no_format_is_sent():
    s = FakeSession(FakeResponse(OK_BODY))
    llm.ask_sync("hello", session=s)
    assert "format" not in s.last_json


def test_structured_output_is_parsed():
    body = dict(OK_BODY, response='{"action": "NOTHING", "reasoning": "ok"}')
    r = llm.ask_sync("hello", schema={"type": "object"}, session=FakeSession(
        FakeResponse(body)))
    assert r.data == {"action": "NOTHING", "reasoning": "ok"}


def test_an_unreadable_structure_keeps_the_text():
    """Not an error: the decision layer can fall back to the anchored parser."""
    body = dict(OK_BODY, response="this is not JSON")
    r = llm.ask_sync("hello", schema={"type": "object"}, session=FakeSession(
        FakeResponse(body)))
    assert r.ok
    assert r.data is None
    assert r.text == "this is not JSON"


# ── Async version ──────────────────────────────────────────────

def test_ask_does_not_block_the_event_loop(monkeypatch):
    """`requests` is synchronous, so it must run in a separate thread.

    Verified by checking another coroutine makes progress while the call is in
    flight. Without `asyncio.to_thread` the event loop would be blocked for the
    whole inference — tens of seconds in which the orchestrator can do nothing.
    """
    import asyncio
    import time

    def slow(*a, **k):
        time.sleep(0.2)
        return llm.LLMResult(text="DECISION: NOTHING")

    monkeypatch.setattr(llm, "ask_sync", slow)

    async def scenario():
        beats = 0

        async def heartbeat():
            nonlocal beats
            while True:
                beats += 1
                await asyncio.sleep(0.01)

        task = asyncio.create_task(heartbeat())
        result = await llm.ask("hello")
        task.cancel()
        return result, beats

    result, beats = asyncio.run(scenario())
    assert result.text == "DECISION: NOTHING"
    assert beats > 5, "the event loop was blocked during the call"
