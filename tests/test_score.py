"""Unit tests for services/soc_score.py `_compute` (pure math)."""
from __future__ import annotations

import pytest

from soc_score import ScoreError, _compute


def _control(cid, family="AC", severity="medium", baselines=("low",)):
    return {"id": cid, "family": family, "severity": severity,
            "baselines": list(baselines)}


def test_score_math_basic():
    controls = [_control("AC-1"), _control("AC-2"), _control("AU-1", "AU"),
                _control("IA-1", "IA")]
    statuses = {"AC-1": "pass", "AC-2": "fail", "AU-1": "pass"}
    r = _compute(controls, statuses)
    # IA-1 has no status -> manual_review; total excludes n/a
    assert r["total"] == 4
    assert r["pass"] == 2
    assert r["fail"] == 1
    assert r["manual_review"] == 1
    assert r["score"] == 50.0
    assert r["by_family"]["AC"] == {"pass": 1, "fail": 1}
    assert r["by_family"]["AU"] == {"pass": 1}
    assert r["by_family"]["IA"] == {"manual_review": 1}
    assert r["by_baseline"]["low"]["pass"] == 2


def test_not_applicable_excluded():
    controls = [_control("AC-1"), _control("AC-2")]
    statuses = {"AC-1": "pass", "AC-2": "not_applicable"}
    r = _compute(controls, statuses)
    # Current behavior: n/a controls are excluded from the score
    # entirely (`continue` before counting) — so the reported
    # "not_applicable" count key stays 0. It looks vestigial; flagged
    # to the owner. What matters here: exclusion from total/score.
    assert r["not_applicable"] == 0
    assert r["total"] == 1
    assert r["score"] == 100.0


def test_empty_inputs_zero_score():
    r = _compute([], {})
    assert r["total"] == 0
    assert r["score"] == 0.0
    assert r["not_applicable"] == 0


def test_all_na_zero_score_no_div():
    controls = [_control("AC-1")]
    r = _compute(controls, {"AC-1": "not_applicable"})
    assert r["total"] == 0
    assert r["score"] == 0.0


def test_baseline_grouping_counts_each_baseline():
    controls = [_control("AC-1", baselines=("low", "moderate")),
                _control("AU-1", "AU", "high", ("moderate",))]
    statuses = {"AC-1": "pass", "AU-1": "manual_review"}
    r = _compute(controls, statuses)
    assert r["by_baseline"]["moderate"] == {"pass": 1, "manual_review": 1}
    assert r["by_severity"]["high"] == {"manual_review": 1}


def test_score_rounding():
    # 1 pass / 3 total = 33.333... -> 33.3
    controls = [_control("AC-1"), _control("AC-2"), _control("AC-3")]
    r = _compute(controls, {"AC-1": "pass"})
    assert r["score"] == 33.3