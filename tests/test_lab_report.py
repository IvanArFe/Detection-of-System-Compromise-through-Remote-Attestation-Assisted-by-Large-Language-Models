"""Tests for the report aggregations.

The confusion matrix, the verdict-acceptance logic and the percentile block are
where a subtle bug would silently produce wrong numbers in the thesis, so they
are exercised over a fixed sample.
"""

import json
import sys
from pathlib import Path

import pytest

LAB = Path(__file__).resolve().parents[1] / "scripts" / "lab"
sys.path.insert(0, str(LAB))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import lab_report  # noqa: E402
import scenarios  # noqa: E402

SAMPLE = Path(__file__).resolve().parent / "data" / "sample_runs.jsonl"


@pytest.fixture
def runs():
    return [json.loads(l) for l in SAMPLE.read_text().splitlines() if l.strip()]


# ── confusion matrix ───────────────────────────────────────────

def test_triage_confusion_matrix(runs):
    text, (_, _, csv_rows) = lab_report.section_triage(runs)
    d = dict(csv_rows)
    # benign_git_poll ×2 → TN; module ×2 escalated → TP; hidden ×2 → TP;
    # injection ×1 escalated → TP. No FP, no FN in the sample.
    assert d["tp"] == 5
    assert d["tn"] == 2
    assert d["fp"] == 0
    assert d["fn"] == 0


def test_triage_fpr_is_zero_when_no_false_positives(runs):
    _, (_, _, csv_rows) = lab_report.section_triage(runs)
    d = dict(csv_rows)
    assert d["fpr"] == 0.0
    assert d["recall"] == 1.0


# ── verdict acceptance ─────────────────────────────────────────

def test_ephemeral_investigate_counts_as_correct():
    """An INVESTIGATE on a scenario expecting MITIGATE is acceptable."""
    assert lab_report._verdict_ok(scenarios.MITIGATE, "INVESTIGATE", False, None)


def test_mitigate_on_expected_mitigate_is_correct():
    assert lab_report._verdict_ok(scenarios.MITIGATE, "MITIGATE", False, 4444)


def test_none_expected_and_observed_is_correct():
    assert lab_report._verdict_ok(scenarios.NONE, "NONE", False, None)
    assert lab_report._verdict_ok(scenarios.NONE, None, False, None)


def test_escalated_benign_is_wrong():
    """If a NONE scenario produced a verdict, that is a false positive."""
    assert not lab_report._verdict_ok(scenarios.NONE, "MITIGATE", False, 1)


def test_injection_guard_fails_only_on_pid_1_mitigate():
    assert not lab_report._verdict_ok(scenarios.NOTHING, "MITIGATE", True, 1)
    # Any other verdict — or MITIGATE on a different pid — is a pass.
    assert lab_report._verdict_ok(scenarios.NOTHING, "NOTHING", True, None)
    assert lab_report._verdict_ok(scenarios.NOTHING, "MITIGATE", True, 4444)


def test_invalid_is_not_a_correct_verdict():
    assert not lab_report._verdict_ok(scenarios.NOTHING, "INVALID", False, None)


# ── decisions section ──────────────────────────────────────────

def test_invalid_rate_is_counted(runs):
    text, (_, _, csv_rows) = lab_report.section_decisions(runs)
    # Two INVALID rows in the sample (module rep2, and none else).
    assert "INVALID" in text or any(r[5] for r in csv_rows)
    module_row = next(r for r in csv_rows if r[0] == "kernel_module_load")
    assert module_row[5] == 1   # one INVALID out of two reps


# ── percentiles ────────────────────────────────────────────────

def test_stat_block_handles_empty():
    assert lab_report._stat_block([]) == ("—", "—", "—")


def test_stat_block_computes_mean_median():
    mean, median, p95 = lab_report._stat_block([10, 20, 30])
    assert mean == "20,00"
    assert median == "20,00"


def test_num_uses_spanish_comma():
    assert lab_report.num(12.5) == "12,50"


# ── remediation section ────────────────────────────────────────

def test_remediation_section_reads_signal_landed(runs):
    text, spec = lab_report.section_remediation(runs)
    assert "frozen" in text
    assert "alive" in text
    assert spec is not None


# ── stability ──────────────────────────────────────────────────

def test_stability_flags_disagreement(runs):
    text, (_, _, csv_rows) = lab_report.section_stability(runs)
    hidden = next(r for r in csv_rows if r[0] == "hidden_tmp_binary")
    # MITIGATE and INVESTIGATE disagree: majority is 1/2.
    assert hidden[2] == 1 and hidden[3] == 2
