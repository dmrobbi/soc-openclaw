#!/usr/bin/env python3
"""SOC STIG finding classifier (Track E, task E1b — 2026-08-11).

Given a Wazuh alert, returns the matched STIG control + Vuln
id, or None if no rule mapping exists.

The mapping is data, not code: per-STIG YAML files at
`config/stig-rules/catalogue-<benchmark>-<version>.yaml` (one
file per STIG release). The classifier loads all matching YAML
files at startup and indexes them by Wazuh rule id. At alert
time, it does a single dict lookup.

Why a separate file per STIG release
------------------------------------
- Different OSes (RHEL 9 vs Ubuntu 22.04) have different Vuln
  ids (RHEL-08-010010 vs UBTU-22-232010 for the same Wazuh
  rule). One file per release keeps the mapping obvious.
- DISA releases ~quarterly; adding a new release is a new
  YAML, no code change.
- The classifier doesn't care which OS — it just looks up
  the Wazuh rule id and returns whichever mapping fires
  first (ordered by file glob, so deterministic).

What `classify_stig_finding(alert)` returns
--------------------------------------------
    {
        "stig_id":         "RHEL-08-010010",   # DISA Vuln id
        "control_id":      "AU-2",             # NIST 800-53 control
        "nist_family":     "AU",
        "title":           "Audit SUID binary execution",
        "severity":        "medium",
        "evidence_required": ["audit_log_lines", "file_stat"],
        "remediate_hint":  "The auditd rule for SUID...",
        "catalogue":       "config/stig-rules/catalogue-rhel-9-v2r9.yaml",
        "benchmark":       "RHEL 9",
        "stig_release":    "V2R9",
    }

Or None if no mapping exists. The `agentic-soc-send.py`
integration is responsible for setting `alert["stig_evidence"]`
to this dict (and `alert["stig_id"]` to the short form) before
posting to `/ingest` so the JSONL record carries the
classification and the realtime_soc_server audit row includes
`extra.stig_evidence` for the E3 collector to find.

CLI
---
    # Classify an alert JSON from stdin.
    python3 scripts/soc/soc_stig_classifier.py \\
        --alert-json path/to/alert.json
    echo '<json>' | python3 scripts/soc/soc_stig_classifier.py

    # Show the loaded catalogue summary.
    python3 scripts/soc/soc_stig_classifier.py --show

    # Self-test (hermetic; uses the bundled test fixture).
    python3 scripts/soc/soc_stig_classifier.py --smoke

Schema
------
Each YAML has the shape:
    version: 1
    benchmark: <str>
    stig_release: <str>
    entries:
      - wazuh_rules: [list of int/str]
        stig_id: <str>
        control_id: <str>
        title: <str>
        severity: <str>      # low|medium|high
        nist_family: <str>   # 2-letter code
        evidence_required: [list of str]
        remediate_hint: <str> (multi-line ok)
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# services/ layout: parents[1] = repo root (fixed for soc-openclaw)
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOGUE_DIR = REPO_ROOT / "config" / "stig-rules"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class STIGClassifierError(Exception):
    """Raised on catalogue load / classification failure."""


# ---------------------------------------------------------------------------
# Catalogue loading
# ---------------------------------------------------------------------------
_INDEX: Dict[str, Dict[str, Any]] = {}   # wazuh_rule_id (str) -> entry
_LOADED_FILES: List[Path] = []


def _catalogue_dir() -> Path:
    """Return the directory holding the per-STIG YAML files."""
    p = os.environ.get("SOC_STIG_RULES_DIR")
    if p:
        return Path(p).expanduser()
    return DEFAULT_CATALOGUE_DIR


def _entry_key(wazuh_rule_id: Any) -> str:
    """Normalize a Wazuh rule id to a string key for the index."""
    return str(wazuh_rule_id).strip()


def _parse_yaml(path: Path) -> Dict[str, Any]:
    """Parse one STIG catalogue YAML file. We avoid a hard
    PyYAML dependency by doing a small hand-rolled parser for
    the limited schema we ship; if PyYAML is available, we
    prefer it for correctness on edge cases (block scalars,
    anchors, etc.)."""
    try:
        import yaml  # type: ignore
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        pass
    return _parse_yaml_minimal(path)


def _parse_yaml_minimal(path: Path) -> Dict[str, Any]:
    """Minimal YAML reader for our catalogue schema.

    Supports:
      - top-level `key: value` mappings
      - list items under `entries:` as `- ...` blocks where
        each block is `key: value` lines, possibly with
        multi-line `>` folded scalars
      - comments (`#`)

    Does NOT support anchors, tags, or block sequences of
    mappings with nested mappings. If we ever need that, we
    pull in PyYAML.
    """
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    # Strip comments
    text = re.sub(r"(?m)^\s*#.*$", "", text)
    lines = [l.rstrip() for l in text.splitlines() if l.strip()]

    out: Dict[str, Any] = {}
    i = 0
    top_scalar = ("benchmark", "version", "stig_release", "last_updated")
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", line)
        if not m:
            i += 1
            continue
        key, val = m.group(1), m.group(2).strip()
        if key in top_scalar and val:
            out[key] = val
            i += 1
            continue
        if key == "entries" and val == "":
            # Parse list of entries
            entries: List[Dict[str, Any]] = []
            i += 1
            while i < len(lines) and lines[i].startswith("  -"):
                entry: Dict[str, Any] = {}
                # First line after the dash may carry a key: value
                m2 = re.match(r"^\s*-\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$",
                              lines[i])
                if m2:
                    k2, v2 = m2.group(1), m2.group(2).strip()
                    if v2.startswith("[") and v2.endswith("]"):
                        # inline list
                        inner = v2[1:-1]
                        entry[k2] = [
                            x.strip().strip("'\"")
                            for x in inner.split(",") if x.strip()
                        ]
                    else:
                        entry[k2] = v2
                i += 1
                # Continuation lines (indented with 4+ spaces, not
                # starting with "- ")
                while (i < len(lines)
                       and lines[i].startswith("    ")
                       and not lines[i].lstrip().startswith("- ")):
                    m3 = re.match(
                        r"^\s{4,}([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$",
                        lines[i])
                    if not m3:
                        break
                    k3, v3 = m3.group(1), m3.group(2).strip()
                    if v3.startswith("[") and v3.endswith("]"):
                        inner = v3[1:-1]
                        entry[k3] = [
                            x.strip().strip("'\"")
                            for x in inner.split(",") if x.strip()
                        ]
                    elif v3 in ("", ">"):
                        # Folded scalar — collect following
                        # indented lines until dedent.
                        if v3 == ">":
                            parts: List[str] = []
                            i += 1
                            while (i < len(lines)
                                   and lines[i].startswith("      ")):
                                parts.append(lines[i].strip())
                                i += 1
                            entry[k3] = " ".join(parts)
                        else:
                            entry[k3] = ""
                            i += 1
                    else:
                        entry[k3] = v3
                    i += 1
                entries.append(entry)
            out["entries"] = entries
            continue
        # Unknown top-level key — skip
        i += 1
    return out


def _validate_entry(entry: Dict[str, Any], path: Path) -> None:
    """Raise STIGClassifierError if `entry` is missing required
    fields or has the wrong shape."""
    required = ("wazuh_rules", "stig_id", "control_id", "title",
                "severity", "nist_family")
    for k in required:
        if k not in entry:
            raise STIGClassifierError(
                f"{path}: entry missing required field {k!r}: {entry}")
    if not isinstance(entry["wazuh_rules"], list):
        raise STIGClassifierError(
            f"{path}: entry.wazuh_rules must be a list: {entry}")
    for rid in entry["wazuh_rules"]:
        if not isinstance(rid, (int, str)):
            raise STIGClassifierError(
                f"{path}: wazuh_rules entries must be int or str: {rid!r}")
    if entry["severity"] not in ("low", "medium", "high"):
        raise STIGClassifierError(
            f"{path}: bad severity {entry['severity']!r}: {entry}")


def reload_catalogue() -> Dict[str, Dict[str, Any]]:
    """Force-reload the per-STIG YAML catalogues from disk.
    Returns the in-memory index (wazuh_rule_id -> entry)."""
    global _INDEX, _LOADED_FILES
    new_index: Dict[str, Dict[str, Any]] = {}
    files_loaded: List[Path] = []
    cat_dir = _catalogue_dir()
    if not cat_dir.exists():
        raise STIGClassifierError(
            f"catalogue directory not found: {cat_dir}")
    for path in sorted(cat_dir.glob("catalogue-*.yaml")):
        data = _parse_yaml(path)
        if not isinstance(data, dict) or "entries" not in data:
            raise STIGClassifierError(
                f"{path}: missing `entries:` top-level list")
        meta = {
            "catalogue": str(path),
            "benchmark": data.get("benchmark", "unknown"),
            "stig_release": data.get("stig_release", "unknown"),
        }
        for entry in data["entries"]:
            _validate_entry(entry, path)
            enriched = dict(entry)
            enriched.update(meta)
            for rid in entry["wazuh_rules"]:
                k = _entry_key(rid)
                if k in new_index:
                    # Multiple STIGs map the same Wazuh rule.
                    # We KEEP the first match (alphabetic
                    # filename order) and stash the others
                    # under `_overrides` so the host-aware
                    # classify_stig_finding() can pick the
                    # right one based on the host's OS. No
                    # log noise at load time.
                    new_index.setdefault(
                        "_overrides", {}).setdefault(k, []).append(enriched)
                    continue
                new_index[k] = enriched
        files_loaded.append(path)
    _INDEX = new_index
    _LOADED_FILES = files_loaded
    return new_index


def _ensure_loaded() -> Dict[str, Dict[str, Any]]:
    if not _INDEX:
        reload_catalogue()
    return _INDEX


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def classify_stig_finding(alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Classify a Wazuh alert as a STIG finding.

    Reads the alert's Wazuh rule id (tries `rule.id`, then
    `rule_name`, then `data.rule_id` in that order) and looks
    it up in the loaded catalogue index. Returns the matching
    entry (with catalogue provenance metadata) or None.

    Host-aware catalogue selection
    ------------------------------
    The index is built by walking every YAML file in
    `config/stig-rules/` and keeping the FIRST mapping for a
    given Wazuh rule (deterministic, alphabetic filename
    order). But the *first* match is rarely right for a
    multi-OS fleet — e.g. Wazuh rule 53503 maps to both
    `RHEL-08-010010` (RHEL) and `UBTU-22-232010` (Ubuntu),
    and we want the one that matches the host. So this
    function:

    1. Builds a host-family hint from `agent.name`
       (e.g. "darth" → "rhel", "ubuntu" → "ubuntu", or
       matched via the host's `os` field if present).
    2. For each loaded catalogue file (alphabetical order),
       checks whether its `benchmark` matches the host family
       hint. If so, the index entry from THAT file wins.
    3. If no file matches the hint, falls back to the
       first-loaded mapping (the existing behaviour).

    Does NOT mutate the alert. The caller (typically
    `agentic-soc-send.py`) is responsible for setting
    `alert["stig_evidence"]` and `alert["stig_id"]` based on
    the returned dict.
    """
    if not isinstance(alert, dict):
        return None
    rule = alert.get("rule") or {}
    rule_id = rule.get("id") or alert.get("rule_name")
    if rule_id is None:
        data = alert.get("data") or {}
        rule_id = data.get("rule_id")
    if rule_id is None:
        return None
    index = _ensure_loaded()
    key = _entry_key(rule_id)
    primary = index.get(key)
    if primary is None:
        return None
    family = _host_family_hint(alert)
    if not family:
        # No host hint at all; use the primary (first-loaded)
        # mapping. Don't wander into the overrides — they're
        # only consulted when the hint says the primary is
        # wrong.
        return _format_result(primary, rule_id)
    if _family_matches(primary.get("benchmark", ""), family):
        return _format_result(primary, rule_id)
    # Primary doesn't match the host family hint; look for
    # an override that does.
    overrides = (index.get("_overrides") or {}).get(key) or []
    for entry in overrides:
        if _family_matches(entry.get("benchmark", ""), family):
            return _format_result(entry, rule_id)
    return _format_result(primary, rule_id)


def _format_result(entry: Dict[str, Any], rule_id: Any) -> Dict[str, Any]:
    return {
        "stig_id": entry["stig_id"],
        "control_id": entry["control_id"],
        "nist_family": entry["nist_family"],
        "title": entry["title"],
        "severity": entry["severity"],
        "evidence_required": list(entry.get("evidence_required") or []),
        "remediate_hint": (entry.get("remediate_hint") or "").strip(),
        "catalogue": entry["catalogue"],
        "benchmark": entry["benchmark"],
        "stig_release": entry["stig_release"],
        "wazuh_rule_id": str(rule_id),
        "classified_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Fleet OS lookup (2026-09-13): agent names don't encode the OS and most
# Wazuh alerts carry no `os` block, so resolve the family from the C2
# manager's fleet status (SOC_MANAGER_MCP_URL /tools/list_agents). Cached
# 5 min per agent; degrades to "" on any error so classification never
# blocks on the manager.
_FLEET_CACHE: Dict[str, Tuple[str, float]] = {}
_FLEET_TTL = 300.0


def _family_from_blob(blob: str) -> str:
    b = (blob or "").lower()
    if "ubuntu" in b:
        return "ubuntu"
    if any(s in b for s in ("rhel", "red hat", "redhat", "centos",
                            "rocky", "fedora", "almalinux")):
        return "rhel"
    if "debian" in b:
        return "debian"
    return ""


def _fleet_family(agent_name: str) -> str:
    """OS family for an agent name. Tries the C2 manager MCP first
    (SOC_MANAGER_MCP_URL /tools/list_agents), then the C1 indexer MCP
    (SOC_WAZUH_MCP_URL /tools/list_agent_os — reachable from inside
    the Wazuh container where the loopback manager is not). Cached
    5 min per agent; degrades to "" on any error."""
    import time as _t
    now = _t.time()
    hit = _FLEET_CACHE.get(agent_name)
    if hit and now - hit[1] < _FLEET_TTL:
        return hit[0]
    fam = ""
    attempts = []
    m2 = (os.environ.get("SOC_MANAGER_MCP_URL") or "").rstrip("/")
    if m2:
        attempts.append((m2 + "/tools/list_agents", "manager"))
    c1 = (os.environ.get("SOC_WAZUH_MCP_URL") or "").rstrip("/")
    if c1:
        attempts.append((c1 + "/tools/list_agent_os", "indexer"))
    for url, _kind in attempts:
        if not url or not agent_name:
            continue
        try:
            import urllib.request as _ur
            req = _ur.Request(
                url,
                data=json.dumps({"limit": 200} if _kind == "manager"
                                else {}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with _ur.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8")) or {}
            rows = data.get("agents") or []
            for row in rows:
                if str(row.get("name") or "") != agent_name:
                    continue
                osinfo = row.get("os")
                if isinstance(osinfo, dict):
                    blob = " ".join([
                        str(osinfo.get("platform") or ""),
                        str(osinfo.get("name") or ""),
                        str(row.get("os_name") or ""),
                    ]).lower()
                else:
                    # manager-mcp flattens os to a string ("ubuntu")
                    blob = " ".join([
                        str(osinfo or ""),
                        str(row.get("os_name") or ""),
                    ]).lower()
                if _kind == "indexer":
                    blob = " ".join([
                        str(row.get("os_platform") or ""),
                        str(row.get("os_name") or ""),
                    ]).lower()
                fam = _family_from_blob(blob)
                break
            if fam:
                break
        except Exception:
            continue
    _FLEET_CACHE[agent_name] = (fam, now)
    return fam


def _host_family_hint(alert: Dict[str, Any]) -> str:
    """Best-effort OS family hint from the alert.

    Looks at `agent.name`, then `data.agent_name`, then
    `data.host.os.name`, then `data.os.name`. Returns one of
    "rhel", "ubuntu", "centos", "fedora", "debian" or "".
    """
    candidates = []
    agent = alert.get("agent") or {}
    if isinstance(agent, dict):
        candidates.append(str(agent.get("name", "")))
    data = alert.get("data") or {}
    if isinstance(data, dict):
        candidates.append(str(data.get("agent_name", "")))
        host_block = data.get("host") or {}
        if isinstance(host_block, dict):
            os_block = host_block.get("os") or {}
            if isinstance(os_block, dict):
                candidates.append(str(os_block.get("name", "")))
        candidates.append(str(data.get("os", "")))
        candidates.append(str(data.get("os_name", "")))
    blob = " ".join(candidates).lower()
    if "ubuntu" in blob:
        return "ubuntu"
    if "rhel" in blob or "redhat" in blob or "red hat" in blob:
        return "rhel"
    if "centos" in blob:
        return "rhel"   # treat centos as rhel-family for STIG mapping
    if "fedora" in blob:
        return "rhel"
    if "debian" in blob:
        return "debian"
    if "rocky" in blob:
        return "rhel"
    # Names/os-blocks gave nothing — ask the C2 manager what OS the
    # agent actually runs (Wazuh fleet status carries os.platform).
    agent_name = candidates[0] if candidates else ""
    return _fleet_family(agent_name)


def _family_matches(benchmark: str, family_hint: str) -> bool:
    """True if the catalogue's `benchmark:` label matches the
    host-family hint. `benchmark` is free text ("RHEL 9",
    "Ubuntu 22.04 LTS", etc.)."""
    b = (benchmark or "").lower()
    f = (family_hint or "").lower()
    if not f:
        return True    # no hint means we accept any benchmark
    if f == "rhel":
        return any(s in b for s in ("rhel", "redhat", "red hat",
                                    "centos", "rocky", "fedora"))
    if f == "ubuntu":
        return "ubuntu" in b
    if f == "debian":
        return "debian" in b
    return f in b


def catalogue_summary() -> Dict[str, Any]:
    """Summary of the loaded catalogue: file count, rule count,
    per-file entry counts. Used by --show and the smoke test."""
    index = _ensure_loaded()
    by_file: Dict[str, int] = {}
    for k, entry in index.items():
        if k == "_overrides":
            continue
        cat = entry.get("catalogue", "?")
        by_file[cat] = by_file.get(cat, 0) + 1
    return {
        "catalogue_dir": str(_catalogue_dir()),
        "files_loaded": [str(p) for p in _LOADED_FILES],
        "total_wazuh_rules_indexed": sum(
            1 for k in index if k != "_overrides"),
        "entries_per_file": by_file,
    }


# ---------------------------------------------------------------------------
# CLI / smoke
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="SOC STIG finding classifier (Track E, E1b)")
    p.add_argument("--alert-json", default=None,
                   help="Path to a Wazuh alert JSON file. The "
                        "matched STIG finding (or None) is "
                        "printed to stdout as JSON.")
    p.add_argument("--show", action="store_true",
                   help="Print the loaded catalogue summary.")
    p.add_argument("--smoke", action="store_true")
    args = p.parse_args(argv)

    if args.smoke:
        return _smoke()

    if args.show:
        print(json.dumps(catalogue_summary(), indent=2))
        return 0

    if args.alert_json:
        with open(args.alert_json, "r", encoding="utf-8") as f:
            alert = json.load(f)
        result = classify_stig_finding(alert)
        print(json.dumps(result, indent=2, default=str))
        return 0

    p.error("specify --alert-json, --show, or --smoke")
    return 2


def _smoke() -> int:
    """Hermetic self-test.

    Loads the bundled YAML catalogues, exercises
    classify_stig_finding on known + unknown rule ids, and
    verifies the metadata round-trips.
    """
    # 1. Catalogue loads
    summary = catalogue_summary()
    assert summary["total_wazuh_rules_indexed"] >= 5, summary
    assert len(summary["files_loaded"]) >= 2, summary

    # 2. Known mapping: 53503 -> AU-2 (audit SUID)
    alert = {
        "rule": {"id": "53503", "level": 8, "description": "..."},
        "agent": {"name": "darth"},
        "data": {"srcip": "10.0.0.99"},
    }
    result = classify_stig_finding(alert)
    assert result is not None, "53503 should classify"
    assert result["stig_id"] in ("RHEL-08-010010", "UBTU-22-232010"), result
    assert result["control_id"] == "AU-2", result
    assert result["severity"] == "medium", result
    assert "audit" in result["title"].lower(), result
    assert "auditd" in result["remediate_hint"].lower(), result

    # 3. Same alert, accessed via rule_name (the JSONL shape)
    alert2 = {"rule_name": "53503", "affected_asset": "darth"}
    result2 = classify_stig_finding(alert2)
    assert result2 is not None, "53503 via rule_name should classify"
    assert result2["stig_id"] == result["stig_id"]

    # 4. Unknown rule -> None
    alert3 = {"rule": {"id": "99999999"}}
    assert classify_stig_finding(alert3) is None

    # 5. No rule id at all -> None
    assert classify_stig_finding({}) is None
    assert classify_stig_finding({"rule": {}}) is None
    assert classify_stig_finding({"data": {}}) is None

    # 6. SSH brute-force (5763) -> high
    alert4 = {"rule": {"id": "5763"}, "data": {"srcip": "9.9.9.9"}}
    result4 = classify_stig_finding(alert4)
    assert result4 is not None
    assert result4["severity"] == "high", result4
    assert result4["control_id"] == "AC-7", result4

    # 7. SSH brute-force-then-success (40112) -> high, AC-2
    alert5 = {"rule": {"id": "40112"}, "data": {"srcip": "10.9.8.7"}}
    result5 = classify_stig_finding(alert5)
    assert result5 is not None
    assert result5["severity"] == "high", result5
    assert result5["control_id"] == "AC-2", result5
    assert "credential" in result5["remediate_hint"].lower(), result5

    # 8. Host-aware mapping: rule 53503 from a "darth" agent
    # should pick the RHEL Vuln id (RHEL-08-010010), not the
    # Ubuntu one (UBTU-22-232010), because darth runs RHEL 9.
    alert6 = {
        "rule": {"id": "53503"},
        "agent": {"name": "darth", "ip": "10.0.0.114"},
        "data": {"srcip": "10.0.0.99"},
    }
    result6 = classify_stig_finding(alert6)
    assert result6 is not None, result6
    assert result6["stig_id"] == "RHEL-08-010010", result6
    assert "RHEL" in result6["benchmark"], result6

    # 9. Same rule, Ubuntu host -> Ubuntu Vuln id
    alert7 = {
        "rule": {"id": "53503"},
        "agent": {"name": "ubuntu-host-1", "ip": "10.0.0.50"},
        "data": {},
    }
    result7 = classify_stig_finding(alert7)
    assert result7 is not None, result7
    assert result7["stig_id"] == "UBTU-22-232010", result7
    assert "Ubuntu" in result7["benchmark"], result7

    # 10. Same rule, no host hint -> falls back to primary
    # (RHEL, because RHEL catalogue sorts first)
    alert8 = {"rule": {"id": "53503"}}
    result8 = classify_stig_finding(alert8)
    assert result8 is not None
    assert result8["stig_id"] == "RHEL-08-010010", result8

    sys.stdout.write("soc-stig-classifier smoke test: OK\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
