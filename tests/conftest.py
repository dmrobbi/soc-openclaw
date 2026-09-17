"""Shared fixtures for the soc-openclaw test suite.

Adds the repo root to sys.path so `services.*` and `lib.*` import
without an install step, and provides isolated tmpdir fixtures for
the modules that read/write state files.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
for sub in ("services", "lib"):
    p = str(REPO_ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture()
def tmp_tasks_log(monkeypatch, tmp_path):
    """Point soc_tasklog.TASKS_LOG at a per-test tmp file.

    soc_tasklog reads the env var at import time, so patching the
    module attribute (not the env) is the reliable knob.
    """
    import soc_tasklog

    log = tmp_path / "tasks.jsonl"
    monkeypatch.setattr(soc_tasklog, "TASKS_LOG", log)
    return log


@pytest.fixture()
def stig_catalogue_dir(monkeypatch, tmp_path):
    """Build a tiny synthetic stig-rules catalogue and point the
    classifier at it via SOC_STIG_RULES_DIR, then reload the index.

    Two files, alphabetic order matters (and names must match the
    loader's `catalogue-*.yaml` glob): catalogue-01-ubuntu.yaml
    defines rule 53503 -> UBTU-22-232010 (ubuntu benchmark);
    catalogue-02-rhel.yaml defines rule 53503 -> RHEL-08-010010 (rhel
    benchmark) as the override that should win when the host hint
    says rhel, while 01 wins for ubuntu hosts (it is the
    first-loaded primary).
    """

    def write_catalogue(files: dict) -> Path:
        d = tmp_path / "stig-rules"
        d.mkdir()
        for name, text in files.items():
            (d / f"catalogue-{name}.yaml").write_text(text, encoding="utf-8")
        monkeypatch.setenv("SOC_STIG_RULES_DIR", str(d))
        import soc_stig_classifier as clf
        clf.reload_catalogue()
        return d

    return write_catalogue


CATALOGUE_TEMPLATE = """\
version: 1
benchmark: {benchmark}
stig_release: V1R1
last_updated: 2026-01-01

entries:
  - wazuh_rules: [53503, 53104]
    stig_id: {stig_id}
    control_id: {control_id}
    title: {title}
    severity: {severity}
    nist_family: {family}
"""