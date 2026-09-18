"""Unit tests for services/scanner/soc_scan_diff.py (synthetic results)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services"
                       / "scanner"))
import soc_scan_diff as sd


def _write_results(path: Path, graded: dict) -> None:
    rows = "\n".join(
        f'<rule-result idref="xccdf_org.ssgproject.content_rule_{rid}">'
        f'<result>{res}</result></rule-result>' for rid, res in graded.items())
    path.write_text(
        f'<TestResult id="r"><{rows}</TestResult>', encoding="utf-8")


@pytest.fixture()
def scans(tmp_path):
    base = tmp_path / "scans"
    (base / "d1").mkdir(parents=True)
    (base / "d2").mkdir(parents=True)
    return base


def _w(base, day, host, graded):
    (base / day / f"results-{host}.xml").write_text(
        '<rule-result idref="xccdf_org.ssgproject.content_rule_'
        + rid + '"><result>' + res + '</result></rule-result>'
        for rid, res in graded.items()) if False else None


def _res(base, day, host, graded: dict):
    p = base / day / f"results-{host}.xml"
    body = "".join(
        f'<rule-result idref="xccdf_org.ssgproject.content_rule_{rid}">'
        f'<result>{res}</result></rule-result>' for rid, res in graded.items())
    p.write_text(f"<results>{body}</results>", encoding="utf-8")


def test_parse_results_extracts_graded_only(scans):
    _res(scans, "d1", "h1", {"a": "pass", "b": "fail",
                             "c": "notapplicable", "d": "notchecked"})
    r = sd.parse_results(scans / "d1" / "results-h1.xml")
    assert r == {"a": "pass", "b": "fail"}


def test_missing_or_empty_results_are_empty(scans):
    assert sd.parse_results(scans / "d1" / "results-nope.xml") == {}
    (scans / "d1" / "results-broken.xml").write_text("", encoding="utf-8")
    assert sd.parse_results(scans / "d1" / "results-broken.xml") == {}


def test_diff_categories(scans):
    _res(scans, "d1", "h1", {
        "fixed_rule": "fail",        # -> pass in d2
        "regressed_rule": "pass",    # -> fail in d2
        "new_fail_rule": None,       # absent in d1 (no entry at all)
        "still_rule": "fail",        # fail both days
        "dropped_rule": "fail",      # gone in d2
        "quiet_rule": "pass",        # pass both days
    })
    _res(scans, "d2", "h1", {
        "fixed_rule": "pass", "regressed_rule": "fail",
        "new_fail_rule": "fail", "still_rule": "fail",
        "quiet_rule": "pass",
    })
    d = sd.diff_host("d1", "d2", "h1", scans)
    assert d["fixed"] == ["fixed_rule"]
    assert d["regressed"] == ["regressed_rule"]
    assert d["new_fail"] == ["new_fail_rule"]
    assert d["still_bad"] == ["still_rule"]
    assert d["dropped"] == ["dropped_rule"]


def test_fail_to_fixed_counts_as_fixed(scans):
    _res(scans, "d1", "h1", {"r": "fail"})
    _res(scans, "d2", "h1", {"r": "fixed"})
    d = sd.diff_host("d1", "d2", "h1", scans)
    assert d["fixed"] == ["r"]


def test_no_change_host_omitted(scans):
    # all-pass both days → truly nothing to report
    _res(scans, "d1", "h1", {"b": "pass"})
    _res(scans, "d2", "h1", {"b": "pass"})
    d = sd.diff_host("d1", "d2", "h1", scans)
    assert d is None
    assert sd.diff_days("d1", "d2", scans) == []


def test_still_failing_host_reported(scans):
    _res(scans, "d1", "h1", {"a": "fail"})
    _res(scans, "d2", "h1", {"a": "fail"})
    diffs = sd.diff_days("d1", "d2", scans)
    assert [d["host"] for d in diffs] == ["h1"]
    assert diffs[0]["still_bad"] == ["a"]


def test_diff_days_hosts_union_and_missing(scans):
    _res(scans, "d1", "h1", {"a": "fail"})
    _res(scans, "d2", "h2", {"a": "fail"})  # only in d2
    diffs = sd.diff_days("d1", "d2", scans)
    hosts = {d["host"] for d in diffs}
    assert hosts == {"h1", "h2"}


def test_render_markdown_shape(scans):
    _res(scans, "d1", "h1", {"fixme": "fail", "same": "fail"})
    _res(scans, "d2", "h1", {"fixme": "pass", "same": "fail",
                             "brand": "fail"})
    diffs = sd.diff_days("d1", "d2", scans)
    md = sd.render_markdown("d1", "d2", diffs)
    assert "### Scan diff d1 → d2" in md
    assert "**fixed (1):**" in md
    assert "new-fail (1): `brand`" in md
    assert "still failing (1): `same`" in md


def test_render_empty_diff(scans):
    md = sd.render_markdown("d1", "d2", [])
    assert "No graded rule changes" in md