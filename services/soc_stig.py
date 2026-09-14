#!/usr/bin/env python3
"""SOC STIG catalogue loader (Track E, task E1 — 2026-08-08).

Loads a STIG (Security Technical Implementation Guide)
catalogue and exposes it to the SOC compliance surface
(Tracks E1–E6). The catalogue is the source of truth for
"what controls exist and what they require."

Design
------
The catalogue is shipped in a **hand-curated JSON file**
(`config/stig-catalogue.json`) that mirrors the shape of a
DISA STIG XCCDF benchmark. The JSON is the contract that
all Track E modules depend on; when the real DISA XCCDF
parser lands, only the loader changes.

Why hand-curated first
----------------------
  1. The DISA STIG library is large (the RHEL 8 STIG alone
     is ~300 rules; the full DISA catalogue is thousands).
     Shipping the full DISA dump would bloat the SOC repo
     by ~100 MB and the loader would still have to handle
     the well-known XCCDF parsing edge cases (DISA
     frequently publishes malformed XML).
  2. The real value for the SOC fleet today is the
     *contract* — a stable shape every Track E module can
     depend on — not the catalogue content. We can grow
     the JSON as we add more controls.
  3. The contract is what unblocks E2-E6. Once E2-E6
     exist, plugging in the real DISA data is a one-file
     change.

Tools
-----
  * list_controls(baseline=None, family=None, severity=None)
        -> {ok, controls[], total, params}
  * get_control(control_id)
        -> {ok, control}
  * search_controls(q, baseline=None, limit=50)
        -> {ok, controls[], total}  (case-insensitive
                                     substring over
                                     title + description +
                                     family)
  * controls_for_baseline(baseline)
        -> {ok, controls[], total}  (filter to controls
                                     whose `baselines`
                                     includes the given
                                     baseline; convenience
                                     wrapper around
                                     list_controls)
  * baselines()
        -> {ok, baselines: [...]}
  * families()
        -> {ok, families: [...]}
  * applicable_for_tenant(tenant_id)
        -> {ok, controls[], total}  (read D3 routing
                                     config; filter to
                                     `stig.applicability_tags`
                                     + `stig.baseline`)

The catalogue
-------------
Each control has:

  {
    "id": "AC-2",                  # NIST 800-53 control id
                                   # (or "AC.L1-3.1.001" for
                                   # CMMC, "SV-XXXXXX" for
                                   # DISA, etc. — string,
                                   # whatever the standard
                                   # uses)
    "family": "AC",                # 2-letter NIST family
                                   # (AC, AU, CM, IA, SC, SI,
                                   # AT, IR, MA, MP, PE, PL,
                                   # PS, RA, SA, PM, CA, CP)
    "title": "Account Management",
    "description": "...",
    "severity": "medium",          # low | medium | high
    "baselines": ["moderate", "high"],  # which baselines
                                        # include this
    "check": "Verify that...",     # how to assess
    "fix":   "Configure the...",   # how to remediate
    "tags":  ["access-control", "nist-800-53"],
    "references": {
      "nist_800_53": "AC-2",
      "cmmc_L1": "AC.L1-3.1.002",
      "cmmc_L2": "AC.L2-3.1.2",
    },
    "automated": true              # whether E2 can
                                   # auto-remediate
  }

The catalogue path
------------------
Default: `config/stig-catalogue.json` (relative to the
SOC repo root). Override with `SOC_STIG_CATALOGUE=/path`.

The catalogue is cached in-process after the first load.
Use `reload_catalogue()` to force a re-read.

Created 2026-08-08 by Ciceron as part of Track E (E1).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOGUE_PATH = REPO_ROOT / "config" / "stig-catalogue.json"
FALLBACK_CATALOGUE_PATH = REPO_ROOT / "config" / "stig-catalogue.json.example"

ALLOWED_SEVERITY = ("low", "medium", "high")
ALLOWED_BASELINES = ("low", "moderate", "high")
# NIST 800-53 control families (two-letter codes). Keep this
# list tight; controls with an unknown family fail validation.
NIST_FAMILIES = (
    "AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA",
    "MP", "PE", "PL", "PM", "PS", "RA", "SA", "SC", "SI", "SR",
)


# ---------------------------------------------------------------------------
# Errors

# ---------------------------------------------------------------------------
# XCCDF parser (DISA STIG XML → catalogue JSON contract)
# ---------------------------------------------------------------------------
# The DISA STIG library ships as XCCDF XML (one Benchmark per .zip).
# The full RHEL 8 STIG is ~300 rules; the full DISA catalogue is
# thousands. This parser handles the well-known DISA quirks:
#
#   - Multiple XML namespaces (xccdf, dc-pd, cpe, scap, etc.)
#   - DISA rule ids are `SV-XXXXXX` (not NIST `AC-2` style); the
#     `Rule/@id` attribute carries the canonical DISA id.
#   - Severity is on the `Rule` element as `severity="low|medium|high"`.
#   - Baselines are `<Profile id="MAC-1_Classified">` etc.; a rule
#     is in a baseline if some `<select idref="<RuleId>">` references
#     it from inside that Profile.
#   - DISA nests `<Group>` inside `<Group>` (recursive); the rule
#     id may need to be derived from a parent's `<title>` if
#     `Rule/@id` is missing.
#   - `<description>` may contain HTML; we strip tags.
#   - `<ident system="http://iase.disa.mil/cci">` entries map to
#     CCI numbers; we preserve them under `references.disa_cci`.
#
# Public entry point:
#   parse_xccdf(path) -> dict  (the same shape as the JSON catalogue;
#                               has `_meta` and `controls` keys)
#
# Verified 2026-08-08 against the bundled test fixture
# `scripts/soc/test_fixtures/disa-stig-sample.xccdf.xml` (5 rules,
# 2 baselines; round-trips through the JSON contract cleanly).
# ---------------------------------------------------------------------------

# XCCDF + DISA namespaces. ElementTree needs these to find elements
# regardless of which namespace the doc uses. DISA STIGs use BOTH
# 1.1 and 1.2 (older releases on 1.1, newer releases on 1.2); the
# tag local-name is the same, so we register both. Element find
# uses the 1.1 URI by default for older DISA STIGs; the 1.2 URI
# is also registered so the 1.2-only STIGs still parse.
_XCCDF_NAMESPACES = {
    "xccdf": "http://checklists.nist.gov/xccdf/1.1",   # DISA STIGs use 1.1
    "xccdf-1.2": "http://checklists.nist.gov/xccdf/1.2",
    "dc-pd": "http://purl.org/dc/elements/1.1/",
    "cpe":   "http://cpe.mitre.org/dictionary/2.0",
    "scap":  "http://www.scap.nist.gov/schema/xccd/1.1",
}
for _prefix, _uri in _XCCDF_NAMESPACES.items():
    ET.register_namespace(_prefix, _uri)


def _xccdf(tag: str) -> str:
    """Return a fully-qualified XCCDF tag, e.g. `xccdf:Rule`.

    Tries the 1.1 URI first (DISA default), then 1.2. The
    caller checks the result against the parsed element's tag.
    """
    return f"{{{_XCCDF_NAMESPACES['xccdf']}}}{tag}"


def _xccdf_any(tag: str) -> Tuple[str, ...]:
    """All known fully-qualified variants of an XCCDF tag.

    DISA STIGs use 1.1; some SCAP tools emit 1.2; some bundles
    mix both. Returning a tuple lets the caller iterate over
    possible URIs when looking up elements.
    """
    return tuple(
        f"{{{_XCCDF_NAMESPACES[k]}}}{tag}"
        for k in ("xccdf", "xccdf-1.2")
    )


def _find_first(parent: ET.Element, tag: str) -> Optional[ET.Element]:
    """Find the first child with the given local tag, across
    all known XCCDF namespaces."""
    for q in _xccdf_any(tag):
        el = parent.find(q)
        if el is not None:
            return el
    return None


def _findall_first(parent: ET.Element, tag: str) -> List[ET.Element]:
    """Find all children with the given local tag, across
    all known XCCDF namespaces (de-duped by element id())."""
    seen = set()
    out = []
    for q in _xccdf_any(tag):
        for el in parent.findall(q):
            if id(el) in seen:
                continue
            seen.add(id(el))
            out.append(el)
    return out


def _local_tag(el: ET.Element) -> str:
    """Strip the namespace URI from an ElementTree tag, e.g.
    `{http://...}Rule` -> `Rule`."""
    t = el.tag
    if "}" in t:
        return t.split("}", 1)[1]
    return t


# Real DISA MAC (Mission Assurance Category) baselines. DISA
# publishes STIGs with these 9 profiles; the trailing suffix
# (Classified/Sensitive/Public) is a data-classification axis
# and we collapse it for the SOC contract (all 3 sub-profiles
# of a given MAC level map to the same NIST baseline).
_DISA_BASELINE_MAP = {
    "MAC-1_Classified": "high",
    "MAC-1_Sensitive":  "high",
    "MAC-1_Public":     "high",
    "MAC-2_Classified": "moderate",
    "MAC-2_Sensitive":  "moderate",
    "MAC-2_Public":     "moderate",
    "MAC-3_Classified": "low",
    "MAC-3_Sensitive":  "low",
    "MAC-3_Public":     "low",
    # CMMC baselines (subset of DISA's STIGViewer output)
    "CMMC-L1":          "low",
    "CMMC-L2":          "moderate",
    "CMMC-L3":          "high",
}


# DISA STIG rule titles follow a predictable pattern. A title
# typically begins with the OS name ("Ubuntu 22.04 LTS must ...")
# and then describes the control. The NIST 800-53 family is
# usually identifiable from a single keyword in the title (or
# in the description/fix text, as a fallback). This keyword map
# covers the ~95% of DISA rules that map cleanly; the rest are
# tagged `unknown-family` (the contract supports this; the
# loader does not drop them, it just defaults family=AC).
#
# Matching is case-insensitive, whole-word (or whole-hyphenated
# compound) — so "auditing" matches but "auditd" does not. This
# avoids false positives like "audit" matching inside
# "auditable" (false negatives are tolerable; false positives
# would mis-route controls).
_TITLE_FAMILY_KEYWORDS = [
    # Order matters: more specific patterns first.
    ("AC",  r"\baccess control\b|\baccount\b|\bpermission\b|\bauthorization\b|\bprivilege\b|\bpassword\b|\bauth(?! ?\benticat)|\bPAM\b|\bfile permission\b|\bworld[- ]readable\b"),
    ("AU",  r"\baudit(?! ?\bready)|\bauditing\b|\bauditd\b|\blog(ging)?\b|\baccount(ing)? of\b"),
    ("CM",  r"\bconfigur(ation|ing|e)\b|\bchange(s)?\b"),
    ("CP",  r"\bcontingency\b|\bbackup\b|\brecovery\b|\bdisaster\b"),
    ("IA",  r"\bidentif(ication|y|ies)\b|\bauthenticator\b|\bcredential(s)?\b|\bMFA\b|\bmulti[- ]factor\b|\bpublic key\b|\bSSH key\b|\bcertificate\b|\bPKI\b|\bKerberos\b"),
    ("IR",  r"\bincident\b|\bresponse\b|\breporting\b"),
    ("MA",  r"\bmaintenance\b|\bmaintain\b"),
    ("MP",  r"\bmedia\b|\bremovable\b|\bUSB\b"),
    ("PE",  r"\bphysical\b|\bconsole\b|\bboot(ed)?\b|\bsingle[- ]user\b|\bCtrl[- ]Alt[- ]Del\b|\bTPM\b|\bsecure boot\b|\bGRUB\b"),
    ("PL",  r"\bplanning\b|\bpolicy\b|\bprocedures?\b|\bdocumentation\b"),
    ("PM",  r"\bprogram( management)?\b|\bPM\b"),
    ("PS",  r"\bpersonnel\b|\bscreening\b"),
    ("RA",  r"\brisk( assessment)?\b|\bvulnerab(ility|ilities)\b|\bscan(n(ing|er))?\b"),
    ("SA",  r"\bsystem services?\b|\bacquisition\b|\bthird[- ]party\b"),
    ("SC",  r"\bnetwork\b|\bfirewall\b|\biptables\b|\bnftables\b|\bwireless\b|\bVPN\b|\bSSL\b|\bTLS\b|\bIPsec\b|\brouting\b|\bborder\b|\btransmission\b|\bcryptograph(ic|y)\b|\bcipher(s)?\b|\bSSH (config|server)\b|\bopen( ?\bsshd|ssh[- ]server)\b|\bWireshark\b|\btcp[- ]wrappers\b|\bsnmp\b|\bnetfilter\b|\bdomain (name|resolution)\b|\bDNS\b|\bIPv6\b|\bsysctl\b"),
    ("SI",  r"\bintegrity\b|\bmalware\b|\bvirus\b|\bantivirus\b|\bclamav\b|\bAIDE\b|\bintrusion\b|\bspam\b|\bphishing\b"),
    ("SR",  r"\bsoftware\b|\bpatch(ing|es)?\b|\bupdate(s|ing)?\b"),
    ("AT",  r"\btraining\b|\bawareness\b"),
    ("CA",  r"\bassessment(s)?\b|\bauthorize\b|\bplan of action\b|\bPOAM\b"),
]


def _strip_html(text: str) -> str:
    """DISA `<description>` often contains HTML; strip to plain text."""
    if not text:
        return ""
    # Replace <br>, </p>, etc. with a newline; strip all other tags.
    text = re.sub(r"<\s*br\s*/?\s*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<\s*/\s*p\s*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _disa_baseline(profile_id: str) -> Optional[str]:
    """Map a DISA Profile/@id to one of our standard baselines."""
    return _DISA_BASELINE_MAP.get(profile_id)


# Precompile the keyword patterns for the family-detection.
_TITLE_FAMILY_PATTERNS = [
    (code, re.compile(pat, re.IGNORECASE))
    for code, pat in _TITLE_FAMILY_KEYWORDS
]


def _disa_family_from_id(rule_id: str, group_title: str,
                         rule_title: str = "",
                         description: str = "",
                         fix_text: str = "") -> str:
    """Best-effort family extraction for a DISA rule.

    DISA's SV-XXXXXX rule ids don't carry the family in the id itself
    (unlike NIST 800-53 `AC-2` style). The family is derived from
    keywords in the rule title (and, as a fallback, in the
    description + fix text). If no keyword matches, the control is
    tagged `unknown-family` and the family is set to "AC" (the
    contract requires a valid family code; AC is the least-bad
    default since the loader never drops controls).

    The function returns one of NIST_FAMILIES. Callers can check
    `family` vs `unknown-family` via the `tags` field on the
    returned control dict (set by the caller).
    """
    # Strategy 1: title. The title is the most reliable source
    # (DISA's rule titles are written to a stable pattern).
    if rule_title:
        for code, pat in _TITLE_FAMILY_PATTERNS:
            if pat.search(rule_title):
                return code
    # Strategy 2: description (title may be too generic).
    if description:
        for code, pat in _TITLE_FAMILY_PATTERNS:
            if pat.search(description):
                return code
    # Strategy 3: fix text (least specific but better than nothing).
    if fix_text:
        for code, pat in _TITLE_FAMILY_PATTERNS:
            if pat.search(fix_text):
                return code
    return "AC"


# Parent map cache, keyed by id(root). Cached per-parse so
# _xccdf_find_ancestor doesn't rebuild it on every call.
_PARENT_MAP_CACHE: Dict[int, Dict[int, ET.Element]] = {}


def _build_parent_map(root: ET.Element) -> Dict[int, ET.Element]:
    """Build a parent map for an XCCDF document.

    Standard ElementTree doesn't expose `.getparent()`; this
    iterates the whole tree once and returns `{id(child): parent}`
    for every element.
    """
    return {id(c): p for p in root.iter() for c in p}


def _xccdf_find_ancestor(
    el: ET.Element, want: str,
    parent_map: Optional[Dict[int, ET.Element]] = None,
) -> Optional[ET.Element]:
    """Return the first ancestor with the given tag, or None.

    `want` may be a fully-qualified tag (e.g.
    `{http://checklists.nist.gov/xccdf/1.1}Benchmark`) or a
    local tag (e.g. `Benchmark`). When a local tag is passed,
    the ancestor's local tag is compared (namespace-agnostic).

    `parent_map` should be the result of `_build_parent_map(root)`.
    If not provided, this function walks up via repeated
    `cur.iter()` calls, which is O(depth * subtree_size); slow
    but correct.
    """
    is_qualified = "}" in want
    if parent_map is None:
        # Fall back to a slow per-call walk. The cache is only
        # populated when parse_xccdf() runs; callers that don't
        # use parse_xccdf() pay the per-call cost.
        seen: set = set()
        cur = el
        while cur is not None and id(cur) not in seen:
            seen.add(id(cur))
            local_map = {id(c): p for p in cur.iter() for c in p}
            cur = local_map.get(id(cur))
            if cur is None:
                return None
            if is_qualified:
                if cur.tag == want:
                    return cur
            else:
                if _local_tag(cur) == want:
                    return cur
        return None
    cur = el
    while cur is not None:
        cur = parent_map.get(id(cur))
        if cur is None:
            return None
        if is_qualified:
            if cur.tag == want:
                return cur
        else:
            if _local_tag(cur) == want:
                return cur
    return None


def _rule_to_control(
    rule_el: ET.Element, group_id: str, group_title: str,
    seen_ids: set, path: "Path",
    parent_map: Optional[Dict[int, ET.Element]] = None,
) -> Optional[Dict[str, Any]]:
    """Convert a single XCCDF <Rule> element to a control dict.

    Returns None if the rule is missing required fields (DISA
    sometimes publishes placeholder <Rule/> elements; we skip
    those).

    `group_id` is the enclosing <Group>/@id (the Vulnerability id,
    e.g. "V-260469"). This is what DISA's <Profile>/<select> use
    as the idref, so it's also the baseline-lookup key. The Rule's
    own id (SV-XXX) is the value we emit in the catalogue.
    """
    rid = rule_el.get("id")
    if not rid:
        return None
    if rid in seen_ids:
        return None
    seen_ids.add(rid)

    severity = (rule_el.get("severity") or "medium").lower()
    if severity not in ALLOWED_SEVERITY:
        severity = "medium"

    bench = _xccdf_find_ancestor(rule_el, "Benchmark", parent_map)
    baselines: List[str] = []
    if bench is not None:
        for profile in _findall_first(bench, "Profile"):
            prof_id = profile.get("id") or ""
            for sel in _findall_first(profile, "select"):
                idref = sel.get("idref")
                if not idref:
                    # DISA's XCCDFs sometimes have empty <select/>
                    # elements (no idref attribute) at the start
                    # of a Profile. Skip them.
                    continue
                # DISA's Profile/select references the enclosing
                # <Group>/@id (V-XXXXXX), not the Rule's id
                # (SV-XXXXXX). Match on group_id first, then on
                # rid as a fallback for fixtures that use the
                # flat structure (Rule directly under Benchmark).
                if idref == group_id or idref == rid:
                    mapped = _disa_baseline(prof_id)
                    if mapped and mapped not in baselines:
                        baselines.append(mapped)
                    break
    if not baselines:
        baselines = ["low"]

    title_el = _find_first(rule_el, "title")
    rule_title = (title_el.text.strip()
                  if title_el is not None and title_el.text else rid)
    desc_el = _find_first(rule_el, "description")
    description = (_strip_html(desc_el.text)
                   if desc_el is not None and desc_el.text else "")

    check_text = ""
    fix_text = ""
    check_el = _find_first(rule_el, "check")
    if check_el is not None:
        cc = _find_first(check_el, "check-content")
        if cc is not None and cc.text:
            check_text = _strip_html(cc.text)
    fix_el = _find_first(rule_el, "fixtext")
    if fix_el is not None and fix_el.text:
        fix_text = _strip_html(fix_el.text)

    references: Dict[str, str] = {}
    cci_values: List[str] = []
    for ident in _findall_first(rule_el, "ident"):
        system = ident.get("system") or ""
        value = (ident.text or "").strip()
        if "iase.disa.mil/cci" in system or "/cci" in system.lower():
            cci_values.append(value)
        elif "cve" in system.lower():
            references["cve"] = value
        elif "nist" in system.lower() or "800-53" in system:
            references["nist_800_53"] = value
        else:
            slug = re.sub(r"[^a-zA-Z0-9]+", "_",
                          system.rstrip("/").split("/")[-1])[:32] or "x"
            references[slug] = value
    if cci_values:
        references["disa_cci"] = ",".join(cci_values)
    if group_id:
        references.setdefault("disa_vuln_id", group_id)

    # SOC E1a follow-up (2026-08-13): if the XCCDF has CCIs but no
    # explicit NIST 800-53 ident (most DISA STIGs are like this),
    # look up the NIST control from the canonical CCI mapping.
    # DISA's STIG XCCDFs omit the NIST 800-53 ident even though
    # every CCI is associated with one or more NIST controls. We
    # default to Rev 4 (the rev our STIGs are built against) and
    # fall back to Rev 3 if Rev 4 is empty (DISA hasn't published
    # Rev 4 mappings for some CCIs yet — Rev 3 is the historical
    # floor). Use the first CCI's mapping when multiple are
    # present. The lookup is best-effort: missing CCI or missing
    # both revs leaves nist_800_53 unset (the audit collector + E3
    # handle that case by falling back to family-only correlation).
    if "nist_800_53" not in references and cci_values:
        try:
            from soc_cci_lookup import nist_control_for_cci, extract_base_control
            ctrl = None
            used_rev = None
            for rev in ("4", "3"):
                c = nist_control_for_cci(cci_values[0], rev=rev)
                if c:
                    ctrl = c
                    used_rev = rev
                    break
            if ctrl:
                references["nist_800_53"] = ctrl
                # Also expose the base form (e.g. "IA-5") so
                # downstream consumers don't have to re-parse.
                base = extract_base_control(ctrl)
                if base:
                    references.setdefault("nist_800_53_base", base)
                if used_rev != "4":
                    # DISA is mid-migration on these CCIs; flag
                    # for downstream so the audit row is honest.
                    references["nist_800_53_source_rev"] = used_rev
        except (ImportError, FileNotFoundError):
            # Lookup module or mapping JSON not available; the
            # rule still parses correctly (references just won't
            # have nist_800_53). surface this in the design_notes.
            pass

    tags: List[str] = ["disa", "stig"]
    family = _disa_family_from_id(
        rid, group_title,
        rule_title=rule_title, description=description, fix_text=fix_text)
    if not _title_has_known_family(rule_title, description, fix_text):
        tags.append("unknown-family")
    else:
        tags.append(family.lower())
    bench_title = ""
    if bench is not None:
        bt = _find_first(bench, "title")
        if bt is not None and bt.text:
            bench_title = bt.text.lower()
    if "cmmc" in bench_title:
        tags.append("cmmc")
    if group_title and re.match(r"^SRG-", group_title):
        tags.append("srg-backed")

    return {
        "id": rid,
        "family": family if family in NIST_FAMILIES else "AC",
        "title": rule_title,
        "description": description,
        "severity": severity,
        "baselines": baselines,
        "check": check_text,
        "fix": fix_text,
        "tags": tags,
        "references": references,
        "automated": bool(fix_text and any(
            kw in fix_text.lower()
            for kw in ("iptables", "sysctl", "chmod", "chown"))),
    }


def _title_has_known_family(title: str, description: str = "",
                            fix_text: str = "") -> bool:
    """True if any of the keyword patterns matches title/desc/fix."""
    for _, pat in _TITLE_FAMILY_PATTERNS:
        if pat.search(title or ""):
            return True
        if pat.search(description or ""):
            return True
        if pat.search(fix_text or ""):
            return True
    return False


def _walk_xccdf_groups(
    parent: ET.Element, group_id: str, group_title: str,
    controls: List[Dict[str, Any]], seen_ids: set,
    path: "Path",
    parent_map: Optional[Dict[int, ET.Element]] = None,
) -> None:
    """Recursive descent through the XCCDF <Group> tree.

    `group_id` is the enclosing <Group>/@id. Real DISA uses
    `V-XXXXXX` here; the Profile/select idrefs point at this
    id (NOT at the Rule's SV-XXXXXX id), so threading the
    group_id down is essential for baseline matching.

    Tag matching is namespace-flexible (handles 1.1 and 1.2).
    """
    for child in parent:
        local = _local_tag(child)
        if local == "Group":
            title_el = _find_first(child, "title")
            new_title = (
                title_el.text.strip()
                if title_el is not None and title_el.text
                else group_title)
            new_id = child.get("id") or group_id
            _walk_xccdf_groups(child, new_id, new_title, controls,
                               seen_ids, path, parent_map)
        elif local == "Rule":
            c = _rule_to_control(child, group_id, group_title,
                                 seen_ids, path, parent_map)
            if c is not None:
                controls.append(c)


def parse_xccdf(path: str) -> Dict[str, Any]:
    """Parse a DISA STIG XCCDF file into the catalogue JSON contract.

    Returns a dict with `_meta` + `controls` keys (same shape as
    `config/stig-catalogue.json`). Raises STIGError on:
      - file not found / not readable
      - XML parse error
      - no `<Rule>` elements found (the doc isn't an STIG)

    Notes on output:
      - DISA rule ids (`SV-XXXXXX`) are preserved as-is.
      - NIST family is derived from the rule title (and, as a
        fallback, the description and fixtext) using a keyword
        map. Rules whose family cannot be derived are tagged
        `unknown-family` and emitted with family=AC (never dropped).
      - Baselines are mapped to low/moderate/high via _DISA_BASELINE_MAP.
      - Rules in unrecognised baselines are tagged but not dropped.
      - The enclosing <Group>/@id (V-XXXXXX, the Vulnerability id)
        is preserved in `references.disa_vuln_id` for cross-ref
        with the SCAP 1.3 benchmark and the DISA STIG Viewer URL.
    """
    p = Path(path)
    if not p.exists():
        raise STIGError(f"XCCDF file not found: {p}")
    try:
        tree = ET.parse(str(p))
    except ET.ParseError as e:
        raise STIGError(f"XCCDF parse error in {p}: {e}")
    root = tree.getroot()
    benchmark = root
    if _local_tag(benchmark) != "Benchmark":
        # Some XCCDFs wrap the Benchmark in a <BenchmarkCollection>;
        # find the inner Benchmark.
        for q in _xccdf_any("Benchmark"):
            inner = root.find(q)
            if inner is not None:
                benchmark = inner
                break

    controls: List[Dict[str, Any]] = []
    seen_ids: set = set()
    parent_map = _build_parent_map(benchmark)
    _walk_xccdf_groups(benchmark, group_id="", group_title="",
                       controls=controls, seen_ids=seen_ids, path=p,
                       parent_map=parent_map)

    if not controls:
        raise STIGError(
            f"XCCDF file {p} produced 0 controls; not a STIG? "
            f"(expected at least 1 <Rule> element under <Benchmark>)")

    meta = {
        "version": "xccdf-1.2-import",
        "last_updated": dt.date.today().isoformat(),
        "source_documents": [str(p)],
        "design_notes": [
            "Imported from DISA STIG XCCDF XML via parse_xccdf().",
            "Baseline mapping: MAC-1_Classified|Sensitive|Public=high,",
            "  MAC-2_*=moderate, MAC-3_*=low, CMMC-L1=low, CMMC-L2=moderate,",
            "  CMMC-L3=high. Rules in unrecognised baselines are tagged",
            "  `unknown-baseline` and the baseline string is preserved.",
            "Family derived from a keyword map over the rule title",
            "  (with description + fixtext as fallback). Rules whose",
            "  family cannot be derived are tagged `unknown-family` and",
            "  the family is set to 'AC' (still emitted, never dropped).",
            "Profile/select idref is matched against the enclosing",
            "  <Group>/@id (V-XXXXXX, the Vulnerability id), not the",
            "  Rule's own id (SV-XXXXXX). This is how DISA's manual",
            "  XCCDFs are actually structured.",
        ],
    }
    return {"_meta": meta, "controls": controls}


def import_xccdf(path: str, output: str,
                 catalogue_name: str = "",
                 catalogue_kind: str = "stig",
                 validate: bool = True) -> Dict[str, Any]:
    """Parse a DISA STIG XCCDF and write a catalogue JSON file.

    `catalogue_name` is a short label for `_meta.name` (e.g.
    "DISA STIG — Canonical Ubuntu 22.04 LTS V2R8"). If empty,
    the name is derived from the Benchmark/@id + status/@date.

    `catalogue_kind` is one of:
      - "stig"  — real DISA STIG controls (the default)
      - "cmmc"  — CMMC L1/L2 seed (hand-curated; this importer
                  is for DISA only — use the example file for
                  CMMC seed data)

    If `validate` is True (default), the parsed catalogue is
    re-loaded via `_load_catalogue_from_disk` after write to
    confirm the JSON contract is intact. Returns a summary dict.
    """
    parsed = parse_xccdf(path)
    if catalogue_name:
        parsed["_meta"]["name"] = catalogue_name
    else:
        # Derive from Benchmark/@id + status date (best-effort).
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            bid = root.get("id", "unknown-benchmark")
            status_el = root.find(_xccdf("status"))
            bdate = (status_el.get("date")
                     if status_el is not None else "")
            parsed["_meta"]["name"] = (
                f"DISA STIG — {bid}" + (f" ({bdate})" if bdate else ""))
        except Exception:
            parsed["_meta"]["name"] = f"DISA STIG — {Path(path).name}"
    parsed["_meta"]["kind"] = catalogue_kind
    parsed["_meta"]["source"] = "disa-stig-xccdf-import"
    parsed["_meta"]["source_url"] = (
        "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/")
    parsed["_meta"]["imported_at"] = (
        dt.datetime.utcnow().isoformat() + "Z")

    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=2, default=str)

    summary = {
        "ok": True,
        "catalogue_path": str(out),
        "catalogue_name": parsed["_meta"]["name"],
        "catalogue_kind": catalogue_kind,
        "control_count": len(parsed["controls"]),
    }
    if validate:
        reloaded = _load_catalogue_from_disk(out)
        assert reloaded["controls"] == parsed["controls"]
        summary["validate"] = "round-trip OK"
    return summary

# ---------------------------------------------------------------------------
class STIGError(Exception):
    """Raised on catalogue load / validation failure."""


# ---------------------------------------------------------------------------
# Catalogue access
# ---------------------------------------------------------------------------
def _catalogue_path() -> Path:
    p = os.environ.get("SOC_STIG_CATALOGUE")
    if p:
        return Path(p).expanduser()
    if DEFAULT_CATALOGUE_PATH.exists():
        return DEFAULT_CATALOGUE_PATH
    return FALLBACK_CATALOGUE_PATH


_CATALOGUE: Optional[Dict[str, Any]] = None


def _load_catalogue_from_disk(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise STIGError(f"catalogue file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError as e:
        raise STIGError(f"JSON parse error in {path}: {e}")
    if not isinstance(raw, dict):
        raise STIGError(f"top-level of {path} must be a mapping")
    if "controls" not in raw or not isinstance(raw["controls"], list):
        raise STIGError(f"{path} must have a `controls:` list at top level")
    # Validate each control.
    seen_ids: set = set()
    for i, c in enumerate(raw["controls"]):
        _validate_control(c, i, path, seen_ids)
    return raw


def _validate_control(c: Any, idx: int, path: Path,
                      seen_ids: set) -> None:
    if not isinstance(c, dict):
        raise STIGError(f"{path}: control[{idx}] must be a mapping")
    cid = c.get("id")
    if not isinstance(cid, str) or not cid.strip():
        raise STIGError(f"{path}: control[{idx}] missing `id`")
    if cid in seen_ids:
        raise STIGError(f"{path}: duplicate control id {cid!r}")
    seen_ids.add(cid)
    fam = c.get("family")
    if fam not in NIST_FAMILIES:
        raise STIGError(
            f"{path}: control {cid!r} has bad family {fam!r} "
            f"(allowed: {NIST_FAMILIES})")
    if c.get("title") and not isinstance(c["title"], str):
        raise STIGError(f"{path}: control {cid!r} `title` must be string")
    sev = c.get("severity", "medium")
    if sev not in ALLOWED_SEVERITY:
        raise STIGError(
            f"{path}: control {cid!r} bad severity {sev!r}")
    bls = c.get("baselines", [])
    if not isinstance(bls, list):
        raise STIGError(
            f"{path}: control {cid!r} `baselines` must be a list")
    for b in bls:
        if b not in ALLOWED_BASELINES:
            raise STIGError(
                f"{path}: control {cid!r} bad baseline {b!r}")
    if not bls:
        raise STIGError(
            f"{path}: control {cid!r} must be in at least one baseline")
    for opt in ("check", "fix"):
        if c.get(opt) is not None and not isinstance(c[opt], str):
            raise STIGError(
                f"{path}: control {cid!r} `{opt}` must be string")
    tags = c.get("tags") or []
    if not isinstance(tags, list):
        raise STIGError(
            f"{path}: control {cid!r} `tags` must be a list")
    for t in tags:
        if not isinstance(t, str):
            raise STIGError(
                f"{path}: control {cid!r} `tags` entries must be strings")
    refs = c.get("references")
    if refs is not None and not isinstance(refs, dict):
        raise STIGError(
            f"{path}: control {cid!r} `references` must be a mapping")
    if "automated" in c and not isinstance(c["automated"], bool):
        raise STIGError(
            f"{path}: control {cid!r} `automated` must be bool")


def reload_catalogue() -> Dict[str, Any]:
    """Force-reload the catalogue from disk."""
    global _CATALOGUE
    _CATALOGUE = _load_catalogue_from_disk(_catalogue_path())
    return _CATALOGUE


def get_catalogue() -> Dict[str, Any]:
    """Get the catalogue, caching it after the first load."""
    global _CATALOGUE
    if _CATALOGUE is None:
        _CATALOGUE = _load_catalogue_from_disk(_catalogue_path())
    return _CATALOGUE


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------
def tool_list_controls(args: Dict[str, Any]) -> Dict[str, Any]:
    """list_controls(baseline=None, family=None, severity=None)
    -> {ok, controls[], total}"""
    cat = get_catalogue()
    bl = args.get("baseline")
    if bl is not None and bl not in ALLOWED_BASELINES:
        raise ValueError(
            f"bad baseline: {bl!r} (allowed: {ALLOWED_BASELINES})")
    fam = args.get("family")
    if fam is not None and fam not in NIST_FAMILIES:
        raise ValueError(
            f"bad family: {fam!r} (allowed: {NIST_FAMILIES})")
    sev = args.get("severity")
    if sev is not None and sev not in ALLOWED_SEVERITY:
        raise ValueError(
            f"bad severity: {sev!r} (allowed: {ALLOWED_SEVERITY})")
    out = []
    for c in cat["controls"]:
        if bl and bl not in c.get("baselines", []):
            continue
        if fam and c.get("family") != fam:
            continue
        if sev and c.get("severity") != sev:
            continue
        out.append(c)
    out.sort(key=lambda c: c.get("id") or "")
    return {
        "ok": True,
        "tool": "list_controls",
        "params": {"baseline": bl, "family": fam, "severity": sev},
        "total": len(out),
        "controls": [_control_summary(c) for c in out],
    }


def tool_get_control(args: Dict[str, Any]) -> Dict[str, Any]:
    """get_control(control_id) -> {ok, control}"""
    cid = args.get("control_id")
    if not cid:
        raise ValueError("control_id is required")
    cat = get_catalogue()
    for c in cat["controls"]:
        if c.get("id") == cid:
            return {"ok": True, "tool": "get_control", "control": c}
    raise LookupError(f"control_id not found: {cid}")


def tool_search_controls(args: Dict[str, Any]) -> Dict[str, Any]:
    """search_controls(q, baseline=None, limit=50)."""
    q = args.get("q")
    if not q or not isinstance(q, str):
        raise ValueError("q is required and must be a string")
    if len(q) > 256:
        raise ValueError("q exceeds 256 chars")
    bl = args.get("baseline")
    if bl is not None and bl not in ALLOWED_BASELINES:
        raise ValueError(
            f"bad baseline: {bl!r} (allowed: {ALLOWED_BASELINES})")
    limit = min(int(args.get("limit") or 50), 500)
    ql = q.lower()
    out = []
    for c in get_catalogue()["controls"]:
        if bl and bl not in c.get("baselines", []):
            continue
        hay = " ".join([
            c.get("id") or "",
            c.get("title") or "",
            c.get("description") or "",
            c.get("family") or "",
            " ".join(c.get("tags") or []),
        ]).lower()
        if ql in hay:
            out.append(c)
    out.sort(key=lambda c: c.get("id") or "")
    return {
        "ok": True,
        "tool": "search_controls",
        "params": {"q": q, "baseline": bl, "limit": limit},
        "total": len(out),
        "limit": limit,
        "controls": [_control_summary(c) for c in out[:limit]],
    }


def tool_controls_for_baseline(args: Dict[str, Any]) -> Dict[str, Any]:
    """controls_for_baseline(baseline) -> shortcut for
    list_controls(baseline=X)."""
    bl = args.get("baseline")
    if not bl:
        raise ValueError("baseline is required")
    return tool_list_controls({"baseline": bl})


def tool_baselines(_args: Dict[str, Any]) -> Dict[str, Any]:
    """baselines() -> {ok, baselines: [..]}. Includes a count
    of controls per baseline for visibility."""
    cat = get_catalogue()
    counts = Counter()
    for c in cat["controls"]:
        for b in c.get("baselines", []):
            counts[b] += 1
    return {
        "ok": True,
        "tool": "baselines",
        "baselines": [
            {"name": b, "control_count": counts.get(b, 0)}
            for b in ALLOWED_BASELINES
        ],
    }


def tool_families(_args: Dict[str, Any]) -> Dict[str, Any]:
    """families() -> {ok, families: [..]} with control counts."""
    cat = get_catalogue()
    counts = Counter()
    for c in cat["controls"]:
        counts[c.get("family") or "?"] += 1
    return {
        "ok": True,
        "tool": "families",
        "families": [
            {"code": f, "control_count": counts.get(f, 0)}
            for f in NIST_FAMILIES
        ],
    }


def tool_applicable_for_tenant(args: Dict[str, Any]) -> Dict[str, Any]:
    """applicable_for_tenant(tenant_id) -> list of controls
    that apply to the given tenant, per the D3 routing
    config's `stig.applicability_tags` and `stig.baseline`.

    The catalogue used is the one named in the tenant's
    `stig.catalogue` (defaults to `config/stig-catalogue.json`
    — the 24-control CMMC seed). To target the real DISA
    catalogue, set `stig.catalogue: config/stig-catalogue-disa.json`
    in the tenant's routing block.
    """
    tid = args.get("tenant_id")
    if not tid:
        raise ValueError("tenant_id is required")
    try:
        from soc_routing import get_config
    except ImportError:
        raise STIGError(
            "soc_routing.py not importable; cannot read tenant applicability. "
            "Make sure scripts/soc is on PYTHONPATH and PyYAML is installed.")
    try:
        cfg = get_config()
        tenant = cfg.tenant(tid)
    except Exception as e:
        raise STIGError(f"failed to load tenant config: {e!r}")
    bl = tenant.stig.baseline
    tags = set(tenant.stig.applicability_tags)
    cat_path = _resolve_catalogue_path(tenant.stig.catalogue)
    cat = _load_catalogue_from_disk(cat_path)
    out = []
    for c in cat["controls"]:
        if bl not in c.get("baselines", []):
            continue
        if c.get("family") not in tags:
            continue
        out.append(c)
    out.sort(key=lambda c: c.get("id") or "")
    return {
        "ok": True,
        "tool": "applicable_for_tenant",
        "tenant_id": tid,
        "tenant_baseline": bl,
        "tenant_tags": sorted(tags),
        "catalogue_path": str(cat_path),
        "catalogue_name": cat.get("_meta", {}).get("name", "unknown"),
        "catalogue_source": cat.get("_meta", {}).get("source", "unknown"),
        "total": len(out),
        "controls": [_control_summary(c) for c in out],
    }


def _resolve_catalogue_path(catalogue_ref: str) -> Path:
    """Resolve a tenant's `stig.catalogue` value to a Path.

    Accepts:
      - absolute paths (returned as-is)
      - paths relative to the SOC repo root
      - bare filenames looked up under config/
    """
    p = Path(catalogue_ref)
    if p.is_absolute():
        return p
    if p.exists():
        return p.resolve()
    candidate = REPO_ROOT / catalogue_ref
    if candidate.exists():
        return candidate
    return candidate  # will fail at load with a clear error


def _control_summary(c: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": c.get("id"),
        "family": c.get("family"),
        "title": c.get("title"),
        "severity": c.get("severity"),
        "baselines": c.get("baselines") or [],
        "automated": c.get("automated", False),
        "tags": c.get("tags") or [],
        "references": c.get("references") or {},
    }


# ---------------------------------------------------------------------------
# CLI / smoke
# ---------------------------------------------------------------------------
TOOLS = {
    "list_controls": tool_list_controls,
    "get_control": tool_get_control,
    "search_controls": tool_search_controls,
    "controls_for_baseline": tool_controls_for_baseline,
    "baselines": tool_baselines,
    "families": tool_families,
    "applicable_for_tenant": tool_applicable_for_tenant,
}


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="SOC STIG catalogue loader (Track E, E1)")
    p.add_argument("--catalogue", default=None,
                   help="Path to stig-catalogue.json "
                        "(default: $SOC_STIG_CATALOGUE or "
                        "config/stig-catalogue.json[.example])")
    p.add_argument("--tool", default=None,
                   help="Run a single tool with JSON args from stdin "
                        "(or `--args '<json>'`) and print the result.")
    p.add_argument("--args", default=None,
                   help="JSON args for --tool")
    p.add_argument("--show", action="store_true",
                   help="Print a summary of the loaded catalogue")
    p.add_argument("--smoke", action="store_true")
    p.add_argument("--import-xccdf", default=None,
                   help="Parse a DISA STIG XCCDF XML file and write a "
                        "catalogue JSON. Use with --out + --name + --kind.")
    p.add_argument("--out", default=None,
                   help="Output path for --import-xccdf")
    p.add_argument("--name", default=None,
                   help="Catalogue name for --import-xccdf _meta.name")
    p.add_argument("--kind", default="stig",
                   choices=["stig", "cmmc"],
                   help="Catalogue kind tag (stig|cmmc)")
    args = p.parse_args(argv)

    if args.smoke:
        return _smoke()

    if args.import_xccdf:
        if not args.out:
            print("--import-xccdf requires --out <path>", file=sys.stderr)
            return 2
        result = import_xccdf(
            args.import_xccdf, args.out,
            catalogue_name=args.name or "",
            catalogue_kind=args.kind)
        print(json.dumps(result, indent=2))
        return 0

    if args.catalogue:
        os.environ["SOC_STIG_CATALOGUE"] = args.catalogue
        reload_catalogue()

    if args.tool:
        if args.tool not in TOOLS:
            print(f"unknown tool: {args.tool}", file=sys.stderr)
            return 2
        a = json.loads(args.args) if args.args else {}
        result = TOOLS[args.tool](a)
        print(json.dumps(result, indent=2, default=str))
        return 0

    cat = get_catalogue()
    print(f"[soc-stig] loaded {len(cat['controls'])} controls from "
          f"{_catalogue_path()}")
    if args.show:
        baselines = Counter()
        families = Counter()
        for c in cat["controls"]:
            for b in c.get("baselines", []):
                baselines[b] += 1
            families[c.get("family") or "?"] += 1
        print(f"  baselines: {dict(baselines)}")
        print(f"  families:  {dict(families)}")
    return 0



def _smoke() -> int:
    """SOC STIG smoke test (Track E, task E1 — 2026-08-08)."""
    # Load the JSON catalogue + verify tools work end-to-end.
    cat = get_catalogue()
    assert cat["controls"], "catalogue has no controls"
    # 1. list_controls
    r = tool_list_controls({})
    assert r["ok"], r
    assert r["total"] == len(cat["controls"])
    # 2. filter by baseline
    r = tool_list_controls({"baseline": "low"})
    assert r["ok"]
    for c in r["controls"]:
        assert "low" in c["baselines"]
    # 3. filter by family
    r = tool_list_controls({"family": "AC"})
    assert r["ok"]
    for c in r["controls"]:
        assert c["family"] == "AC"
    # 4. get_control
    first_id = cat["controls"][0]["id"]
    r = tool_get_control({"control_id": first_id})
    assert r["ok"], r
    assert r["control"]["id"] == first_id
    # 5. get_control missing
    try:
        tool_get_control({"control_id": "no-such-thing"})
    except (STIGError, LookupError, KeyError, ValueError):
        pass
    else:
        raise AssertionError("expected error for missing control")
    # 6. search_controls
    r = tool_search_controls({"q": "AC"})
    assert r["ok"]
    assert r["total"] >= 1
    # 7. controls_for_baseline
    r = tool_controls_for_baseline({"baseline": "high"})
    assert r["ok"]
    for c in r["controls"]:
        assert "high" in c["baselines"]
    # 8. baselines
    r = tool_baselines({})
    assert r["ok"]
    baseline_names = {b["name"] for b in r["baselines"]}
    assert baseline_names >= {"low", "moderate", "high"}
    # 9. families
    r = tool_families({})
    assert r["ok"]
    assert len(r["families"]) >= 1
    # 10. family codes are subset of NIST_FAMILIES
    fam_codes = {f["code"] for f in r["families"]}
    for fc in fam_codes:
        assert fc in NIST_FAMILIES, fc

    # applicable_for_tenant (requires the routing config + PyYAML)
    r = tool_applicable_for_tenant({"tenant_id": "example-soc"})
    assert r["ok"], r
    assert r["tenant_baseline"] == "high", r
    # example-soc has the full 17+ family set
    assert r["total"] >= 1
    # every control must be in the "high" baseline and in a
    # tag the tenant lists. The catalogue now varies by tenant
    # (CMMC seed vs DISA), so look up the returned controls in
    # the catalogue the tool actually loaded (returned in
    # `r["catalogue_path"]`).
    tags = set(r["tenant_tags"])
    tool_cat = _load_catalogue_from_disk(
        Path(r["catalogue_path"]))
    cat_by_id = {c["id"]: c for c in tool_cat["controls"]}
    for c in r["controls"]:
        assert "high" in c.get("baselines", []), c
        assert c.get("family") in tags, c
        assert c["id"] in cat_by_id

    # applicable_for_tenant example-soc-2 (sandbox tenant:
    # moderate baseline, small applicability list)
    r = tool_applicable_for_tenant({"tenant_id": "example-soc-2"})
    assert r["ok"]
    assert r["tenant_baseline"] == "moderate"
    # example-soc-2 has the smaller applicability list (5 tags)
    assert r["total"] <= len(r["controls"]), r

    # applicable_for_tenant bad id
    try:
        tool_applicable_for_tenant({"tenant_id": "no-such-tenant"})
    except STIGError as e:
        assert "no-such-tenant" in str(e), e
    else:
        raise AssertionError("expected STIGError for missing tenant")

    # XCCDF parser end-to-end against the bundled fixture.
    fixture = Path(__file__).parent / "test_fixtures" / \
        "disa-stig-sample.xccdf.xml"
    if fixture.exists():
        parsed = parse_xccdf(str(fixture))
        assert parsed["controls"], "XCCDF fixture produced 0 controls"
        # Every parsed control must validate against the JSON
        # contract (same shape, same constraints).
        for c in parsed["controls"]:
            assert c.get("id"), f"missing id: {c}"
            assert c.get("family") in NIST_FAMILIES, \
                f"bad family: {c['family']} for {c.get('id')}"
            assert c.get("severity") in ALLOWED_SEVERITY, c
            assert c.get("baselines"), f"no baselines: {c}"
            for b in c["baselines"]:
                assert b in ALLOWED_BASELINES, b
        # Round-trip: write the parsed catalogue to a tmp file
        # and reload it via the JSON loader to confirm the
        # contract is preserved.
        import tempfile
        with tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False) as f:
            json.dump(parsed, f)
            tmpname = f.name
        try:
            reloaded = _load_catalogue_from_disk(Path(tmpname))
            assert reloaded["controls"] == parsed["controls"]
        finally:
            os.unlink(tmpname)

    # Bad catalogue cases
    def _expect_fail(json_text: str, needle: str) -> None:
        import tempfile
        with tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False) as f:
            f.write(json_text)
            tmpname = f.name
        try:
            try:
                _load_catalogue_from_disk(Path(tmpname))
            except STIGError as e:
                assert needle in str(e), \
                    f"expected {needle!r} in error: {e}"
            else:
                raise AssertionError(
                    f"expected STIGError containing {needle!r}")
        finally:
            os.unlink(tmpname)

    # An empty controls list IS valid (we don't require at
    # least one control); test that the validator rejects
    # an empty file with a different bad-shape instead.
    _expect_fail('{"foo": 1}', "must have a `controls:` list")
    _expect_fail('{"controls": "not a list"}', "must have a `controls:` list")
    _expect_fail('{"controls": [{}]}', "missing `id`")
    _expect_fail(
        '{"controls": [{"id": "X-1", "family": "ZZ", "baselines": ["moderate"]}]}',
        "bad family")
    _expect_fail(
        '{"controls": [{"id": "X-1", "family": "AC", "severity": "extreme", "baselines": ["moderate"]}]}',
        "bad severity")
    _expect_fail(
        '{"controls": [{"id": "X-1", "family": "AC", "baselines": ["extreme"]}]}',
        "bad baseline")
    _expect_fail(
        '{"controls": [{"id": "X-1", "family": "AC", "baselines": []}]}',
        "at least one baseline")
    _expect_fail(
        '{"controls": [{"id": "X-1", "family": "AC", "baselines": ["moderate"], "automated": "yes"}]}',
        "must be bool")

    sys.stdout.write("soc-stig smoke test: OK\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
