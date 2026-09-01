"""The lab-tagging config must come from the environment.

config is evaluated once at import, so these reload it under a patched
environment rather than trusting the value captured at collection time.
"""

import importlib

import pytest


@pytest.fixture(autouse=True)
def _restore_config():
    """Reloading config mutates the module in place; restore it afterwards so a
    leftover RUN_ID does not leak into other test files."""
    yield
    import edr.config as cfg
    importlib.reload(cfg)


def _reload_config(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import edr.config as cfg
    return importlib.reload(cfg)


def test_run_id_and_scenario_default_empty(monkeypatch):
    monkeypatch.delenv("EDR_RUN_ID", raising=False)
    monkeypatch.delenv("EDR_SCENARIO", raising=False)
    cfg = _reload_config(monkeypatch)
    assert cfg.RUN_ID == ""
    assert cfg.SCENARIO == ""


def test_run_id_and_scenario_read_from_env(monkeypatch):
    cfg = _reload_config(monkeypatch, EDR_RUN_ID="run-42", EDR_SCENARIO="hidden_tmp_binary")
    assert cfg.RUN_ID == "run-42"
    assert cfg.SCENARIO == "hidden_tmp_binary"


def test_dedup_window_default(monkeypatch):
    monkeypatch.delenv("EDR_DEDUP_WINDOW", raising=False)
    cfg = _reload_config(monkeypatch)
    assert cfg.DEDUP_WINDOW_S == 300


def test_dedup_window_can_be_zeroed(monkeypatch):
    """The harness sets it to 0 so repetitions are not deduplicated away."""
    cfg = _reload_config(monkeypatch, EDR_DEDUP_WINDOW="0")
    assert cfg.DEDUP_WINDOW_S == 0


def test_results_dir_is_a_path(monkeypatch):
    cfg = _reload_config(monkeypatch, EDR_RESULTS_DIR="/tmp/edr-results")
    assert str(cfg.RESULTS_DIR) == "/tmp/edr-results"


def test_run_id_is_stripped(monkeypatch):
    cfg = _reload_config(monkeypatch, EDR_RUN_ID="  spaced  ")
    assert cfg.RUN_ID == "spaced"
