"""Unit tests for the scan ignore_list.yml feature (loader + tailoring
builder in services/scanner/soc_scanner.py)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services"
                       / "scanner"))
import soc_scanner as sc


# A tiny synthetic datastream-ish file with full xccdf rule ids.
SYN_DS = """<?xml version="1.0"?>
<ds:data-stream-collection xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2">
 <ds:component id="c1">
  <Benchmark id="b1" xmlns="http://checklists.nist.gov/xccdf/1.2">
   <Rule id="xccdf_org.ssgproject.content_rule_aide_build_database"/>
   <Rule id="xccdf_org.ssgproject.content_rule_aide_check_audit_tools"/>
   <Rule id="xccdf_org.ssgproject.content_rule_package_aide_installed"/>
  </Benchmark>
 </ds:component>
</ds:data-stream-collection>
"""


@pytest.fixture()
def syn_ds(tmp_path):
    p = tmp_path / "ds.xml"
    p.write_text(SYN_DS, encoding="utf-8")
    return str(p)


def test_load_ignore_list_missing_file(tmp_path):
    r = sc.load_ignore_list(str(tmp_path / "nope.yml"))
    assert r == {"global": [], "hosts": {}}


def test_load_ignore_list_full_schema(tmp_path):
    p = tmp_path / "ignore_list.yml"
    p.write_text("""
version: 1
global:
  - rule: aide_build_database
    reason: "churn"
hosts:
  thing1:
    - rule: is_fips_mode_enabled
      reason: "breaks containers"
""", encoding="utf-8")
    r = sc.load_ignore_list(str(p))
    assert r["global"] == [{"rule": "aide_build_database", "reason": "churn"}]
    assert r["hosts"]["thing1"] == [{"rule": "is_fips_mode_enabled",
                                     "reason": "breaks containers"}]


def test_load_ignore_list_malformed_fails_open(tmp_path, capsys):
    p = tmp_path / "bad.yml"
    p.write_text("!!not-a-map: [", encoding="utf-8")
    r = sc.load_ignore_list(str(p))
    assert r == {"global": [], "hosts": {}}


def test_ds_rule_ids(syn_ds):
    ids = sc._ds_rule_ids(syn_ds)
    assert "xccdf_org.ssgproject.content_rule_aide_build_database" in ids
    assert len(ids) == 3


def test_build_tailoring_resolves_and_writes(syn_ds, tmp_path):
    out = tmp_path / "tailoring.xml"
    r = sc.build_tailoring(
        syn_ds, "xccdf_org.ssgproject.content_profile_cis_level1_server",
        [{"rule": "aide_build_database", "reason": "x"},
         {"rule": "xccdf_org.ssgproject.content_rule_package_aide_installed",
          "reason": "full id"}],
        str(out))
    assert r["ok"] is True
    assert r["resolved"] == [
        "xccdf_org.ssgproject.content_rule_aide_build_database",
        "xccdf_org.ssgproject.content_rule_package_aide_installed"]
    assert r["unmatched"] == []
    assert r["profile_id"].endswith("_soc_ignore")
    body = out.read_text(encoding="utf-8")
    assert '<Profile id="' + r["profile_id"] + '" extends="xccdf_org.ssgproject.content_profile_cis_level1_server">' in body
    assert '<select idref="xccdf_org.ssgproject.content_rule_aide_build_database" selected="false"/>' in body
    assert '<version time="' in body
    assert "<status>incomplete</status>" in body


def test_build_tailoring_unmatched_entries(syn_ds, tmp_path):
    out = tmp_path / "t2.xml"
    r = sc.build_tailoring(
        syn_ds, "prof_id",
        [{"rule": "no_such_rule", "reason": ""}],
        str(out))
    assert r["ok"] is False
    assert r["resolved"] == []
    assert r["unmatched"] == ["no_such_rule"]
    assert not out.exists()


def test_effective_ignore_entries():
    ignore = {"global": [{"rule": "g1", "reason": ""}],
              "hosts": {"thing1": [{"rule": "h1", "reason": ""}]}}
    assert [e["rule"] for e in sc.effective_ignore_entries(ignore, "thing1")] == ["g1", "h1"]
    assert [e["rule"] for e in sc.effective_ignore_entries(ignore, "other")] == ["g1"]


def test_tailoring_xml_is_wellformed_and_shaped(syn_ds, tmp_path):
    """The generated tailoring must parse and carry the verified live
    shape (2026-09-18, thing1): an oscap-loaded tailoring whose Profile
    extends the scan profile with select=false entries — full-profile
    eval returns the deselected rules as notselected."""
    from xml.etree import ElementTree as ET
    out = tmp_path / "tailoring.xml"
    r = sc.build_tailoring(
        syn_ds, "xccdf_org.ssgproject.content_profile_cis_level1_server",
        [{"rule": "aide_build_database", "reason": "x"}], str(out))
    assert r["ok"] is True
    root = ET.parse(str(out)).getroot()
    assert root.tag == "{http://checklists.nist.gov/xccdf/1.2}Tailoring"
    ns = {"x": "http://checklists.nist.gov/xccdf/1.2"}
    assert root.find("x:status", ns) is not None
    assert root.find("x:version", ns) is not None
    assert (root.find("x:version", ns).get("time") or "") != ""
    prof = root.find("x:Profile", ns)
    assert prof is not None
    assert prof.get("extends") == "xccdf_org.ssgproject.content_profile_cis_level1_server"
    selects = prof.findall("x:select", ns)
    assert len(selects) == 1
    assert selects[0].get("idref") == "xccdf_org.ssgproject.content_rule_aide_build_database"
    assert selects[0].get("selected") == "false"