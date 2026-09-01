"""Tests for verdict interpretation.

The first four blocks are regressions: each reproduces an input that, against
the previous parser, produced a mitigation order nobody had decided. The strings
are the ones used to demonstrate the bugs.
"""

import pytest

from edr.decision import (INVALID, INVESTIGATE, MITIGATE, NOTHING, Decision,
                          decide, from_structured, parse_decision, schema)
from edr.llm import LLMResult


# ── Regression 1: a negated sentence ───────────────────────────

def test_a_sentence_negating_the_verdict_does_not_count():
    """The old parser returned MITIGATE pid=1 kill: it would have hit systemd."""
    text = (
        "We must NOT do DECISION: MITIGATE pid=1 action=kill because that would "
        "kill systemd.\nThe process looks legitimate.\n\nDECISION: NOTHING"
    )
    assert parse_decision(text, allowed_pids={1, 4711}).action == NOTHING


def test_the_last_decision_wins_not_the_first():
    """The model reasons and changes its mind: what it concludes is what counts."""
    text = "DECISION: MITIGATE pid=4711 action=kill\n\nOn reflection:\nDECISION: NOTHING"
    assert parse_decision(text, allowed_pids={4711}).action == NOTHING


# ── Regression 2: echoing the instructions ─────────────────────

def test_echoing_the_instructions_is_harmless():
    """No attacker needed: small models leak the instruction into the answer.

    The prompt used to interpolate the real pid into its examples, so the echo
    was a valid, actionable verdict. The examples now carry the literal <PID>.
    """
    text = (
        "Here is my analysis. The process seems fine.\n"
        "I was told to end with one of these lines:\n"
        "DECISION: MITIGATE pid=<PID> action=freeze\n"
        "DECISION: MITIGATE pid=<PID> action=kill\n"
        "DECISION: NOTHING\n"
        "So my answer is NOTHING."
    )
    assert parse_decision(text, allowed_pids={4711}).action == NOTHING


# ── Regression 3: hallucinated or injected pid ─────────────────

def test_a_pid_absent_from_the_telemetry_is_rejected():
    d = parse_decision("DECISION: MITIGATE pid=1 action=kill", allowed_pids={4711})
    assert d.action == INVALID
    assert "1" in d.detail


def test_a_pid_present_in_the_telemetry_is_accepted():
    d = parse_decision("DECISION: MITIGATE pid=4711 action=kill", allowed_pids={4711})
    assert (d.action, d.pid, d.remediation) == (MITIGATE, 4711, "kill")


def test_without_a_pid_list_nothing_is_filtered():
    """Lets the parser be used standalone, from a test or a tool."""
    assert parse_decision("DECISION: MITIGATE pid=999 action=kill").pid == 999


# ── Regression 4: INVALID is not NOTHING ───────────────────────

@pytest.mark.parametrize("text", [
    "",
    "I am not sure what to do with this.",
    "The process is suspicious but I cannot decide.",
    "DECISION: PROBABLY",
    "DECISION: MITIGATE pid=abc action=kill",
    "DECISION: MITIGATE pid=4711 action=destroy",
])
def test_an_unusable_response_is_invalid(text):
    """All of this used to collapse into NOTHING and skew the false-negative rate."""
    assert parse_decision(text, allowed_pids={4711}).action == INVALID


def test_invalid_explains_why():
    assert parse_decision("").detail
    assert parse_decision("blah blah").detail


# ── Decorations models add ─────────────────────────────────────

@pytest.mark.parametrize("line", [
    "DECISION: NOTHING",
    "**DECISION: NOTHING**",
    "- DECISION: NOTHING",
    "> DECISION: NOTHING",
    "`DECISION: NOTHING`",
    "DECISION: NOTHING.",
    "   decision: nothing   ",
    "DECISION:NOTHING",
])
def test_markdown_and_variants_are_tolerated(line):
    assert parse_decision(line).action == NOTHING


def test_decorations_on_a_mitigation_are_tolerated():
    d = parse_decision("**DECISION: MITIGATE pid=4711 action=freeze**",
                       allowed_pids={4711})
    assert (d.action, d.pid, d.remediation) == (MITIGATE, 4711, "freeze")


def test_investigate_parses():
    d = parse_decision("DECISION: INVESTIGATE pid=4711", allowed_pids={4711})
    assert (d.action, d.pid) == (INVESTIGATE, 4711)


# ── Structured output ──────────────────────────────────────────

def test_structured_basic():
    d = from_structured(
        {"reasoning": "…", "action": "MITIGATE", "pid": 4711, "remediation": "kill"},
        {4711})
    assert (d.action, d.pid, d.remediation, d.source) == (MITIGATE, 4711, "kill",
                                                          "structured")


def test_structured_ignores_remediation_unless_the_action_is_mitigate():
    """An incoherence observed for real: NOTHING alongside remediation=freeze.

    The schema bounds each field separately but does not force them to be
    coherent with each other.
    """
    d = from_structured({"action": "NOTHING", "pid": 4711, "remediation": "freeze"},
                        {4711})
    assert d.action == NOTHING
    assert d.remediation is None


def test_structured_without_a_pid_on_an_action_that_needs_one():
    d = from_structured({"action": "MITIGATE", "pid": None}, {4711})
    assert d.action == INVALID


def test_structured_rejects_a_hallucinated_pid():
    d = from_structured({"action": "MITIGATE", "pid": 1, "remediation": "kill"}, {4711})
    assert d.action == INVALID


def test_structured_without_remediation_picks_the_reversible_action():
    """Freezing can be undone; killing cannot. Same asymmetry as the safeguards."""
    d = from_structured({"action": "MITIGATE", "pid": 4711}, {4711})
    assert d.remediation == "freeze"


def test_structured_with_an_unknown_action_is_unusable():
    assert from_structured({"action": "PANIC", "pid": 4711}, {4711}) is None


def test_the_schema_can_forbid_investigate():
    """In round 2 there is nothing left to investigate."""
    assert INVESTIGATE not in schema(allow_investigate=False)["properties"]["action"]["enum"]
    assert INVESTIGATE in schema()["properties"]["action"]["enum"]


@pytest.mark.parametrize("field", ["reasoning", "action", "pid", "remediation"])
def test_the_schema_requires_every_field(field):
    """Regression: an optional field is a field the model will omit.

    With only `reasoning` and `action` required, the model answered
    `{"action": "INVESTIGATE"}` with no pid, twice in a row, while naming the
    pids in its own reasoning. It was valid against that schema and left the
    whole cycle INVALID.
    """
    assert field in schema()["required"]
    assert field in schema(allow_investigate=False)["required"]


def test_pid_accepts_null_so_not_applicable_can_be_expressed():
    """Required is not the same as non-null: a NOTHING verdict has no pid."""
    assert "null" in schema()["properties"]["pid"]["type"]


def test_the_schema_bounds_the_pid_to_the_ones_shown():
    """Regression: the model returned the `ppid` instead of the `pid`.

    The telemetry shows `pid=108630 ppid=108629` and it answered `108629`,
    systematically and on the retry too. Not a hallucination but a confusion
    between two adjacent numeric fields. Bounding the field with an enum makes
    it impossible: the derived grammar cannot generate any other value.
    """
    field = schema(allowed_pids={108630, 108640})["properties"]["pid"]

    assert field["enum"] == [108630, 108640, None]
    assert 108629 not in field["enum"], "the adjacent ppid must be excluded"


def test_without_a_pid_list_the_field_stays_open():
    """Lets the schema be used standalone, with no specific telemetry behind it."""
    assert "enum" not in schema()["properties"]["pid"]
    assert "enum" not in schema(allowed_pids=set())["properties"]["pid"]


def test_null_is_still_allowed_when_bounded():
    """A NOTHING verdict carries no pid, so the enum has to admit null."""
    assert None in schema(allowed_pids={1234})["properties"]["pid"]["enum"]


# ── decide(): choosing the path ────────────────────────────────

def test_decide_prefers_the_structured_path():
    r = LLMResult(text="DECISION: NOTHING",
                  data={"action": "MITIGATE", "pid": 4711, "remediation": "kill"})
    d = decide(r, {4711})
    assert (d.action, d.source) == (MITIGATE, "structured")


def test_decide_falls_back_to_the_parser_without_structure():
    d = decide(LLMResult(text="DECISION: NOTHING"), {4711})
    assert (d.action, d.source) == (NOTHING, "parsed")


def test_decide_falls_back_to_the_parser_if_the_structure_is_unusable():
    r = LLMResult(text="DECISION: NOTHING", data={"action": "PANIC"})
    assert decide(r, {4711}).source == "parsed"


def test_decide_with_a_model_error_is_invalid():
    d = decide(LLMResult(error="timed out after 180s"), {4711})
    assert d.action == INVALID
    assert "timed out" in d.detail


def test_decide_without_a_result_is_invalid():
    assert decide(None, {4711}).action == INVALID


def test_is_actionable():
    assert Decision(MITIGATE, pid=1).is_actionable
    assert Decision(INVESTIGATE, pid=1).is_actionable
    assert not Decision(NOTHING).is_actionable
    assert not Decision(INVALID).is_actionable
    assert not Decision(MITIGATE).is_actionable
