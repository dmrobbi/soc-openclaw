"""Unit tests for services/soc_stig_classifier.py.

Pure helpers run directly; catalogue-driven classification runs
against a synthetic SOC_STIG_RULES_DIR (isolated from the live
config/stig-rules directory).
"""
from __future__ import annotations

import pytest

import soc_stig_classifier as clf
from conftest import CATALOGUE_TEMPLATE


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("blob,expected", [
    ("Ubuntu 22.04 LTS", "ubuntu"),
    ("Ubuntu", "ubuntu"),
    ("Red Hat Enterprise Linux 9", "rhel"),
    ("RHEL 8", "rhel"),
    ("Rocky Linux 8", "rhel"),
    ("AlmaLinux 8", "rhel"),
    ("CentOS 7", "rhel"),
    ("Debian 12", "debian"),
    ("FreeBSD 14", ""),
    ("", ""),
    (None, ""),
])
def test_family_from_blob(blob, expected):
    assert clf._family_from_blob(blob) == expected


@pytest.mark.parametrize("benchmark,hint,expected", [
    ("RHEL 9", "rhel", True),
    ("Red Hat Enterprise Linux 8", "rhel", True),
    ("Rocky Linux", "rhel", True),
    ("Ubuntu 22.04 LTS", "rhel", False),
    ("Ubuntu 22.04", "ubuntu", True),
    ("Debian 12", "debian", True),
    ("RHEL 9", "debian", False),
    ("Anything", "", True),          # no hint accepts all
    ("Windows Server 2022", "freebsd", False),
])
def test_family_matches(benchmark, hint, expected):
    assert clf._family_matches(benchmark, hint) is expected


# ---------------------------------------------------------------------------
# classify_stig_finding against a synthetic catalogue
# ---------------------------------------------------------------------------
def _alert(rule_id, agent_name="", host_os=None):
    alert = {"rule": {"id": rule_id},
             "agent": {"name": agent_name}}
    if host_os is not None:
        alert["data"] = {"host": {"os": {"name": host_os}}}
    return alert


def test_classify_uses_synthetic_catalogue(stig_catalogue_dir):
    stig_catalogue_dir({
        "01-ubuntu": CATALOGUE_TEMPLATE.format(
            benchmark="Ubuntu 22.04", stig_id="UBTU-22-232010",
            control_id="IA-2", title="sudo users", severity="high",
            family="IA"),
    })
    r = clf.classify_stig_finding(_alert(53503, "somehost"))
    assert r is not None
    assert r["stig_id"] == "UBTU-22-232010"
    assert r["control_id"] == "IA-2"


def test_classify_no_match_returns_none(stig_catalogue_dir):
    stig_catalogue_dir({
        "01-ubuntu": CATALOGUE_TEMPLATE.format(
            benchmark="Ubuntu 22.04", stig_id="UBTU-22-232010",
            control_id="IA-2", title="t", severity="high", family="IA"),
    })
    assert clf.classify_stig_finding(_alert(99999, "somehost")) is None


def test_classify_malformed_alerts(stig_catalogue_dir):
    stig_catalogue_dir({
        "01-ubuntu": CATALOGUE_TEMPLATE.format(
            benchmark="Ubuntu 22.04", stig_id="UBTU-22-232010",
            control_id="IA-2", title="t", severity="high", family="IA"),
    })
    assert clf.classify_stig_finding(None) is None
    assert clf.classify_stig_finding("not-a-dict") is None
    assert clf.classify_stig_finding({}) is None           # no rule id
    assert clf.classify_stig_finding({"rule": {}}) is None


def test_classify_reads_data_rule_id_fallback(stig_catalogue_dir):
    stig_catalogue_dir({
        "01-ubuntu": CATALOGUE_TEMPLATE.format(
            benchmark="Ubuntu 22.04", stig_id="UBTU-22-232010",
            control_id="IA-2", title="t", severity="high", family="IA"),
    })
    r = clf.classify_stig_finding({"data": {"rule_id": "53503"}})
    assert r is not None and r["stig_id"] == "UBTU-22-232010"


def test_host_family_override_rhel_wins_on_rhel_host(stig_catalogue_dir):
    """Rule 53503 is defined in both files; the rhel benchmark file
    must win when the host hint says rhel (override behaviour)."""
    stig_catalogue_dir({
        "01-ubuntu": CATALOGUE_TEMPLATE.format(
            benchmark="Ubuntu 22.04", stig_id="UBTU-22-232010",
            control_id="IA-2", title="t", severity="high", family="IA"),
        "02-rhel": CATALOGUE_TEMPLATE.format(
            benchmark="RHEL 8", stig_id="RHEL-08-010010",
            control_id="IA-2", title="t", severity="high", family="IA"),
    })
    # agent name carries an ubuntu-ish hint -> primary (ubuntu file)
    r = clf.classify_stig_finding(_alert(53503, "ubuntu-box"))
    assert r["stig_id"] == "UBTU-22-232010"
    # data.host.os.name says RHEL -> the rhel entry must win
    r = clf.classify_stig_finding(
        _alert(53503, "weirdname", host_os="RHEL 8"))
    assert r["stig_id"] == "RHEL-08-010010"