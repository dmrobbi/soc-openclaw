"""Unit tests for services/soc_stig.py parse_xccdf() with a synthetic
DISA-style XCCDF (namespace 1.1, the namespace-flexible path)."""
from __future__ import annotations

from pathlib import Path

import pytest

from soc_stig import STIGError, parse_xccdf

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.1"

# Wrapped in BenchmarkCollection to exercise the unwrap path; Profile
# selects only V-260001 (rule 1 gets a high baseline; rule 2 falls
# back to ["low"]). Rule 2 has no severity attribute (default medium)
# and an explicit NIST ident; rule 1 has a CCI ident + automated fix.
BENCHMARK = f"""<?xml version="1.0" encoding="UTF-8"?>
<ns0:BenchmarkCollection xmlns:ns0="{XCCDF_NS}"
                         xmlns:xhtml="http://www.w3.org/1999/xhtml">
 <ns0:Benchmark id="test-stig">
  <ns0:title>Test STIG Benchmark</ns0:title>
  <ns0:Profile id="MAC-1_Public">
    <ns0:select idref="V-260001" selected="true"/>
    <ns0:select/>
  </ns0:Profile>
  <ns0:Group id="V-260001">
    <ns0:title>SRG-OS-000001-GPOS-00001</ns0:title>
    <ns0:Rule id="SV-260001r889_rule" severity="high">
      <ns0:title>Audit log files must be owned by root</ns0:title>
      <ns0:description>The audit system must be proper.&lt;br/&gt;Keep it owned by root.</ns0:description>
      <ns0:check>
        <ns0:check-content>Verify ownership with stat.</ns0:check-content>
      </ns0:check>
      <ns0:fixtext fixref="f1">chmod 0640 /var/log/audit/audit.log</ns0:fixtext>
      <ns0:ident system="http://iase.disa.mil/cci">CCI-000139</ns0:ident>
    </ns0:Rule>
  </ns0:Group>
  <ns0:Group id="V-260002">
    <ns0:title>SRG-OS-000999</ns0:title>
    <ns0:Rule id="SV-260002r889_rule">
      <ns0:title>Time data must be synchronized</ns0:title>
      <ns0:fixtext fixref="f2">Enable time sync</ns0:fixtext>
      <ns0:ident system="http://csrc.nist.gov/ns/800-53">AU-3</ns0:ident>
    </ns0:Rule>
  </ns0:Group>
 </ns0:Benchmark>
</ns0:BenchmarkCollection>
"""


@pytest.fixture()
def xccdf_file(tmp_path) -> Path:
    p = tmp_path / "test-stig-xccdf.xml"
    p.write_text(BENCHMARK, encoding="utf-8")
    return p


def test_parse_returns_catalogue_shape(xccdf_file):
    out = parse_xccdf(str(xccdf_file))
    assert "_meta" in out and "controls" in out
    ids = [c["id"] for c in out["controls"]]
    assert ids == ["SV-260001r889_rule", "SV-260002r889_rule"]


def test_rule1_fields(xccdf_file):
    c = parse_xccdf(str(xccdf_file))["controls"][0]
    assert c["family"] == "AU"          # "audit" keyword in title
    assert c["title"] == "Audit log files must be owned by root"
    assert c["severity"] == "high"
    assert c["baselines"] == ["high"]   # Profile MAC-1_Public -> high
    assert "unknown-family" not in c["tags"]
    assert "au" in c["tags"]            # family tag lowercased
    assert "srg-backed" in c["tags"]    # Group title SRG-...
    assert c["check"] == "Verify ownership with stat."
    assert c["automated"] is True       # fixtext has chmod


def test_rule1_description_html_stripped(xccdf_file):
    c = parse_xccdf(str(xccdf_file))["controls"][0]
    assert "<br/>" not in c["description"]
    assert "The audit system must be proper." in c["description"]
    assert "owned by root" in c["description"]


def test_rule1_references(xccdf_file):
    refs = parse_xccdf(str(xccdf_file))["controls"][0]["references"]
    assert refs["disa_vuln_id"] == "V-260001"
    assert refs["disa_cci"] == "CCI-000139"


def test_rule2_defaults_and_ident(xccdf_file):
    c = parse_xccdf(str(xccdf_file))["controls"][1]
    assert c["severity"] == "medium"            # no severity attr
    assert c["baselines"] == ["low"]            # no select match
    assert c["family"] == "AC"                  # no family keyword
    assert "unknown-family" in c["tags"]
    assert c["references"]["nist_800_53"] == "AU-3"
    assert c["automated"] is False


def test_missing_file_raises(tmp_path):
    with pytest.raises(STIGError, match="not found"):
        parse_xccdf(str(tmp_path / "nope.xml"))


def test_scap_datastream_wrapped_benchmark(tmp_path):
    """SSG/DISA SCAP datastreams nest the Benchmark inside
    ds:data-stream-collection → ds:data-stream → ds:checklists →
    ds:component, with non-checklist (OVAL) components alongside.
    parse_xccdf must find the checklist Benchmark."""
    doc = (
        '<ds:data-stream-collection xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2"'
        ' xmlns:ns0="' + XCCDF_NS + '">'
        '<ds:data-stream id="ds1">'
        '<ds:checklists><ds:component-ref id="cl0" xlink:href="#xccdf0"'
        ' xmlns:xlink="http://www.w3.org/1999/xlink"/></ds:checklists>'
        '</ds:data-stream>'
        '<ds:component id="oval0"><oval-def:oval_definitions'
        ' xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5"/>'
        '</ds:component>'
        '<ds:component id="xccdf0">'
        '<ns0:Benchmark id="test-stig"><ns0:title>DS Wrapped</ns0:title>'
        '<ns0:Profile id="MAC-1_Public"><ns0:select idref="V-260001"'
        ' selected="true"/></ns0:Profile>'
        '<ns0:Group id="V-260001"><ns0:title>SRG-OS-000001</ns0:title>'
        '<ns0:Rule id="SV-260001r1_rule" severity="high">'
        '<ns0:title>Audit log files must be owned by root</ns0:title>'
        '<ns0:fixtext fixref="f1">chmod 0640 /var/log/audit/audit.log</ns0:fixtext>'
        '</ns0:Rule></ns0:Group></ns0:Benchmark>'
        '</ds:component></ds:data-stream-collection>')
    p = tmp_path / "wrapped.xml"
    p.write_text(doc, encoding="utf-8")
    out = parse_xccdf(str(p))
    assert [c["id"] for c in out["controls"]] == ["SV-260001r1_rule"]
    c = out["controls"][0]
    assert c["family"] == "AU"
    assert c["baselines"] == ["high"]
    assert c["references"]["disa_vuln_id"] == "V-260001"


def test_malformed_xml_raises(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("<not-closed>", encoding="utf-8")
    with pytest.raises(STIGError, match="parse error"):
        parse_xccdf(str(p))


def test_no_rules_raises(tmp_path):
    doc = (f'<ns0:Benchmark xmlns:ns0="{XCCDF_NS}">'
           f'<ns0:title>Empty</ns0:title></ns0:Benchmark>')
    p = tmp_path / "empty.xml"
    p.write_text(doc, encoding="utf-8")
    with pytest.raises(STIGError):
        parse_xccdf(str(p))


def test_nested_groups(tmp_path):
    """A Rule two levels deep inherits the inner Group's id/title."""
    doc = (f'<ns0:Benchmark xmlns:ns0="{XCCDF_NS}">'
           f'<ns0:title>Nested</ns0:title>'
           f'<ns0:Group id="V-300001"><ns0:title>SRG-OS-000100</ns0:title>'
           f'<ns0:Group id="V-300002"><ns0:title>SRG-OS-000200</ns0:title>'
           f'<ns0:Rule id="SV-300001r1_rule">'
           f'<ns0:title>Time data must be synchronized</ns0:title>'
           f'</ns0:Rule></ns0:Group></ns0:Group></ns0:Benchmark>')
    p = tmp_path / "nested.xml"
    p.write_text(doc, encoding="utf-8")
    out = parse_xccdf(str(p))
    assert [c["id"] for c in out["controls"]] == ["SV-300001r1_rule"]
    c = out["controls"][0]
    assert c["references"]["disa_vuln_id"] == "V-300002"
    assert "srg-backed" in c["tags"]


def test_duplicate_rule_ids_deduped(tmp_path):
    doc = (f'<ns0:Benchmark xmlns:ns0="{XCCDF_NS}">'
           f'<ns0:title>Dup</ns0:title>'
           f'<ns0:Group id="V-1"><ns0:title>SRG-A</ns0:title>'
           f'<ns0:Rule id="SV-1"><ns0:title>Time sync</ns0:title></ns0:Rule>'
           f'<ns0:Rule id="SV-1"><ns0:title>Time sync</ns0:title>'
           f'</ns0:Rule></ns0:Group></ns0:Benchmark>')
    p = tmp_path / "dup.xml"
    p.write_text(doc, encoding="utf-8")
    out = parse_xccdf(str(p))
    assert len(out["controls"]) == 1


def test_invalid_severity_defaults_medium(tmp_path):
    doc = (f'<ns0:Benchmark xmlns:ns0="{XCCDF_NS}">'
           f'<ns0:title>Sev</ns0:title>'
           f'<ns0:Group id="V-1"><ns0:title>SRG-A</ns0:title>'
           f'<ns0:Rule id="SV-1" severity="critical">'
           f'<ns0:title>Time sync</ns0:title>'
           f'</ns0:Rule></ns0:Group></ns0:Benchmark>')
    p = tmp_path / "sev.xml"
    p.write_text(doc, encoding="utf-8")
    out = parse_xccdf(str(p))
    assert out["controls"][0]["severity"] == "medium"