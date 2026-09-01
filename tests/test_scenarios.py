"""The scenario catalogue must not lie about what it triggers.

Each scenario declares the severity and rules it expects the triage to produce.
These tests re-derive them from `triage.assess()` — the real rule engine — so a
scenario whose `probe_event` no longer matches its `expect_*` fields fails here
rather than silently producing wrong numbers in the results chapter.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "lab"))

import scenarios  # noqa: E402
from edr import config, triage  # noqa: E402


ALL = scenarios.SCENARIOS
ESCALATING = [s for s in ALL if s["probe_event"] is not None]


def test_the_catalogue_is_not_empty():
    assert ALL


def test_slugs_are_unique():
    slugs = [s["slug"] for s in ALL]
    assert len(slugs) == len(set(slugs))


@pytest.mark.parametrize("s", ESCALATING, ids=lambda s: s["slug"])
def test_severity_and_rules_match_the_engine(s):
    """The declared severity/rules are exactly what assess() computes."""
    severity, rules = triage.assess(s["probe_event"])
    assert severity == s["expect_severity"], (
        f"{s['slug']}: catalogue says {s['expect_severity']}, engine says {severity}")
    assert sorted(rules) == sorted(s["expect_rules"]), (
        f"{s['slug']}: catalogue says {s['expect_rules']}, engine fired {rules}")


@pytest.mark.parametrize("s", ESCALATING, ids=lambda s: s["slug"])
def test_escalation_flag_agrees_with_the_threshold(s):
    """expect_escalate must be consistent with severity vs. the threshold."""
    over = s["expect_severity"] >= config.TRIAGE_THRESHOLD
    assert over == s["expect_escalate"], (
        f"{s['slug']}: severity {s['expect_severity']} vs threshold "
        f"{config.TRIAGE_THRESHOLD} disagrees with expect_escalate={s['expect_escalate']}")


def test_benign_scenarios_stay_below_the_threshold():
    """The whole point of the benign set: none of them may escalate."""
    for s in ALL:
        if s["category"] == "benign":
            assert not s["expect_escalate"], f"{s['slug']} should not escalate"
            if s["probe_event"] is not None:
                severity, _ = triage.assess(s["probe_event"])
                assert severity < config.TRIAGE_THRESHOLD


def test_module_scenario_has_no_probe_event():
    """Module loads bypass assess(): they escalate unconditionally."""
    module = scenarios.BY_SLUG["kernel_module_load"]
    assert module["probe_event"] is None
    assert module["expect_escalate"] is True


def test_required_fields_are_present():
    required = {"slug", "category", "description", "cmd", "expect_escalate",
                "expect_verdict", "long_lived", "needs_attacker", "needs_root"}
    for s in ALL:
        missing = required - set(s)
        assert not missing, f"{s['slug']} is missing {missing}"


def test_verdict_values_are_valid():
    valid = {scenarios.NONE, scenarios.NOTHING, scenarios.INVESTIGATE, scenarios.MITIGATE}
    for s in ALL:
        assert s["expect_verdict"] in valid


def test_select_filters_attacker_and_root():
    no_attacker = scenarios.select(include_attacker=False)
    assert all(not s["needs_attacker"] for s in no_attacker)
    no_root = scenarios.select(include_root=False)
    assert all(not s["needs_root"] for s in no_root)


def test_select_by_slug():
    picked = scenarios.select(["hidden_tmp_binary"])
    assert len(picked) == 1 and picked[0]["slug"] == "hidden_tmp_binary"
