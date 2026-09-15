#!/usr/bin/env python3
"""SOC OpenSCAP compliance scanner (soc-openclaw).

Rewritten 2026-09-13 (the 02:56 draft was unwired and broken on every
path — see audits/2026-09-13-stig-scanner-audit.md B9-B17).

Orchestrates OpenSCAP scans of managed hosts via oscap-ssh:

    oscap-ssh <user>@<host> <port> xccdf eval --profile <profile> \
        --results <results.xml> --report <report.html> <ssg datastream>

  - individual: scan_host(agent) — one host
  - fleet: scan_fleet(agents) — every reachable managed host, parallel

Requires on the TARGET host: the `oscap` binary (deploy/openscap-setup.sh
installs openscap-scanner + SSG). The datastream file is read LOCALLY
and pushed to the target by oscap-ssh; it must exist on the SOC host.

Results are parsed per-rule, mapped to CMMC controls through the SSG
rules' NIST 800-53 references (plus the 800-53 -> CMMC alias table in
soc_evidence), and written to the evidence store so soc_score scores
them:

    compliance/evidence/<tenant>/<control_id>/<day>.jsonl

Usage:
    python3 soc_scanner.py --host vader --dry-run
    python3 soc_scanner.py --host thing1 --host-ip 127.0.0.1 \
        --family ubuntu --profile cis_level1_server --tenant bedimsecurity
    python3 soc_scanner.py --fleet
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # services/ (soc_evidence, soc_stig, soc_routing)

# ---- configuration (env-overridable) ---------------------------------------
SCAN_USER = os.environ.get("SOC_SCAN_SSH_USER", "wez")
SSH_PORT = os.environ.get("SOC_SCAN_SSH_PORT", "22")
SCAN_TIMEOUT = int(os.environ.get("SOC_SCAN_TIMEOUT", "3600"))
PARALLEL = int(os.environ.get("SOC_SCAN_PARALLEL", "8"))
SCAN_RESULTS_DIR = Path(os.environ.get(
    "SOC_SCAN_RESULTS_DIR", os.path.expanduser("~/.openclaw/soc/scans")))
SSG_DIR = Path(os.environ.get(
    "SOC_SSG_DIR", "/usr/share/xml/scap/ssg/content"))
C2_URL = os.environ.get("SOC_MANAGER_MCP_URL",
                        "http://127.0.0.1:8767").rstrip("/")
C1_URL = os.environ.get("SOC_WAZUH_MCP_URL",
                        "http://127.0.0.1:8766").rstrip("/")

# family -> (datastream filename, profile id). Ubuntu ships CIS
# profiles only (no DISA STIG profile in the SSG ubuntu DS); RHEL ships
# the DISA STIG profile.
SSG_PROFILES = {
    "ubuntu": ("ssg-ubuntu2204-ds.xml",
               "xccdf_org.ssgproject.content_profile_cis_level2_server"),
    "debian": ("ssg-debian12-ds.xml",
               "xccdf_org.ssgproject.content_profile_cis_level2_server"),
    "rhel":   ("ssg-rhel9-ds.xml",
               "xccdf_org.ssgproject.content_profile_stig"),
    "fedora": ("ssg-fedora-ds.xml",
               "xccdf_org.ssgproject.content_profile_cis_server_l2"),
    "centos": ("ssg-centos8-ds.xml",
               "xccdf_org.ssgproject.content_profile_cis_server_l2"),
}

_NS = {"c": "http://checklists.nist.gov/xccdf/1.2"}
_NIST_RE = re.compile(r"^([A-Z]{2})-\d+")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _post_json(url: str, payload: Dict[str, Any],
               timeout: float = 15.0) -> Optional[Dict[str, Any]]:
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def fleet_agents() -> List[Dict[str, Any]]:
    """Resolve managed hosts: C2 manager first (id/name/ip/os), C1
    indexer (monitoring index; ip added 2026-09-13) as fallback.
    Returns [{id, name, ip, platform}] for non-manager agents."""
    rows: List[Dict[str, Any]] = []
    data = _post_json(C2_URL + "/tools/list_agents", {"limit": 200})
    for r in ((data or {}).get("agents") or []):
        aid = str(r.get("id") or "")
        if not aid or aid == "000":
            continue
        osinfo = r.get("os")
        if isinstance(osinfo, dict):
            platform = str(osinfo.get("platform") or "")
        else:  # manager-mcp flattens os to a string ("ubuntu")
            platform = str(osinfo or "")
        rows.append({"id": aid, "name": str(r.get("name") or aid),
                     "ip": str(r.get("ip") or ""),
                     "platform": platform.lower(), "os_version": ""})
    if not rows:
        data = _post_json(C1_URL + "/tools/list_agent_os", {})
        for r in ((data or {}).get("agents") or []):
            aid = str(r.get("id") or "")
            if not aid or aid == "000":
                continue
            rows.append({"id": aid, "name": str(r.get("name") or aid),
                         "ip": str(r.get("ip") or ""),
                         "platform": str(r.get("os_platform") or "").lower(),
                         "os_version": str(r.get("os_version") or "")})
    else:
        # enrich ubuntu rows with the OS version from C1 (the manager
        # flattens os and carries no version) for datastream selection.
        c1 = _post_json(C1_URL + "/tools/list_agent_os", {})
        by_name = {str(r.get("name") or ""): str(r.get("os_version") or "")
                   for r in ((c1 or {}).get("agents") or [])}
        for row in rows:
            if row["platform"] == "ubuntu":
                row["os_version"] = by_name.get(row["name"], "")
    return rows


def _family(platform: str) -> Optional[str]:
    for fam in SSG_PROFILES:
        if fam in (platform or "").lower():
            return fam
    return None


def scan_host(agent: Dict[str, Any], day: str,
              profile: Optional[str] = None,
              dry_run: bool = False) -> Dict[str, Any]:
    """Run one OpenSCAP XCCDF eval on `agent` via oscap-ssh."""
    name = agent.get("name") or agent.get("id") or "?"
    ip = agent.get("ip") or ""
    family = _family(agent.get("platform") or "")
    if family not in SSG_PROFILES:
        return {"ok": False, "host": name,
                "error": f"no SSG profile for OS family {family!r}"}
    ds_name, default_profile = SSG_PROFILES[family]
    # version-aware ubuntu pick: 24.04 hosts must use the 2404 datastream
    # (the 2204 DS CPE-checks fail on 24.04 → every rule notapplicable).
    # The 2404 DS (SSG 0.1.82+) ships a DISA stig profile; 2204 does not.
    if family == "ubuntu":
        ver = str(agent.get("os_version") or "")
        maj = re.match(r"\s*(\d+)", ver).group(1) if re.match(r"\s*(\d+)", ver) else ""
        if maj == "24" and (SSG_DIR / "ssg-ubuntu2404-ds.xml").exists():
            ds_name = "ssg-ubuntu2404-ds.xml"
            default_profile = "xccdf_org.ssgproject.content_profile_stig"
    ds = SSG_DIR / ds_name
    if not ds.exists():
        return {"ok": False, "host": name,
                "error": f"datastream missing on SOC host: {ds}"}
    prof = profile or default_profile
    results_dir = SCAN_RESULTS_DIR / day
    results_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    results_xml = results_dir / f"results-{safe}.xml"
    report_html = results_dir / f"report-{safe}.html"
    ds_path = str(ds)
    cmd = [
        "oscap-ssh", f"{SCAN_USER}@{ip}" if ip else SCAN_USER, SSH_PORT,
        "xccdf", "eval",
        "--profile", prof,
        "--results", str(results_xml),
        "--report", str(report_html),
        str(ds),
    ]
    if dry_run:
        return {"ok": True, "host": name, "dry_run": True,
                "family": family, "profile": prof, "ds_path": ds_path,
                "command": " ".join(cmd)}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=SCAN_TIMEOUT)
        rc = proc.returncode
        ok = rc in (0, 1, 2)  # 0 pass, 1/2 = findings found (still fine)
    except subprocess.TimeoutExpired:
        return {"ok": False, "host": name,
                "error": f"scan timed out after {SCAN_TIMEOUT}s"}
    return {"ok": ok, "host": name, "agent_id": agent.get("id"),
            "returncode": rc, "ds_path": ds_path,
            "results_path": str(results_xml) if results_xml.exists() else None,
            "report_path": str(report_html) if report_html.exists() else None,
            "stdout_tail": (proc.stdout or "")[-800:],
            "stderr_tail": (proc.stderr or "")[-400:]}


def parse_rule_results(results_xml: str) -> List[Dict[str, Any]]:
    """Parse an XCCDF results file into per-rule rows."""
    root = ET.parse(results_xml).getroot()
    out = []
    for rr in root.findall(".//c:rule-result", _NS):
        out.append({
            "rule": rr.get("idref") or "",
            "result": (rr.findtext("c:result", default="",
                                   namespaces=_NS) or "").strip(),
        })
    return out


def parse_ds_rule_nist(ds_path: str) -> Dict[str, List[str]]:
    """Extract rule_id -> [NIST 800-53 refs] from an SSG datastream."""
    root = ET.parse(ds_path).getroot()
    out: Dict[str, List[str]] = {}
    for rule in root.findall(".//c:Rule", _NS):
        rid = rule.get("id") or ""
        refs = []
        for ref in rule.findall("c:reference", _NS):
            t = (ref.text or "").strip()
            m = _NIST_RE.match(t)
            if m:
                # normalize: "AU-9(3)" / "AU-9(3).1" -> "AU-9"
                refs.append(m.group(0))
        if refs:
            out[rid] = refs
    return out


# ---- fleet collect: merge results -> ONE evidence write -------------------

_PASS_RESULTS = {"pass", "fixed"}

# results files record the benchmark id they evaluated, e.g.
# xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04 (verified on the
# 2026-09-13 archive). Longest-prefix match — UBUNTU_24-04 before
# UBUNTU_24, DEBIAN-12 before DEBIAN.
_BENCH_DS_MAP = {
    "UBUNTU_24-04": "ssg-ubuntu2404-ds.xml",
    "UBUNTU_22-04": "ssg-ubuntu2204-ds.xml",
    "DEBIAN-12": "ssg-debian12-ds.xml",
    "DEBIAN-11": "ssg-debian11-ds.xml",
    "RHEL-9": "ssg-rhel9-ds.xml",
    "RHEL-8": "ssg-rhel8-ds.xml",
    "CENTOS-9": "ssg-centos9-ds.xml",
    "FEDORA": "ssg-fedora-ds.xml",
}


def _benchmark_to_ds(results_xml: str) -> Optional[str]:
    """Guess the SSG datastream filename from a results file's
    Benchmark id, so a day's scans can be re-collected without the
    original manifest. Returns "" when nothing matches."""
    try:
        with open(results_xml, "r", encoding="utf-8", errors="replace") as f:
            head = f.read(262144)
    except OSError:
        return None
    m = re.search(r"xccdf_org\.ssgproject\.content_benchmark_([A-Za-z0-9_.-]+)",
                  head)
    if not m:
        return None
    bench = m.group(1)
    for key in sorted(_BENCH_DS_MAP, key=len, reverse=True):
        if bench == key or bench.startswith(key):
            cand = SSG_DIR / _BENCH_DS_MAP[key]
            if cand.exists():
                return str(cand)
    return None


def _specs_from_day(day: str, manifest_path: Optional[str] = None
                    ) -> List[Dict[str, str]]:
    """Build scan specs for `day`: the recorded manifest.json if present,
    else synthesized from results-*.xml on disk. Missing ds paths are
    backfilled from each results file's Benchmark id. Specs whose ds
    cannot be resolved are dropped (they cannot be mapped to controls)."""
    day_dir = SCAN_RESULTS_DIR / day
    if manifest_path is None:
        manifest_path = str(day_dir / "manifest.json")
    specs: List[Dict[str, str]] = []
    p = Path(manifest_path)
    if p.exists():
        try:
            for row in json.loads(p.read_text()):
                rp = Path(row.get("results") or "")
                if not rp.exists():
                    continue
                specs.append({"host": str(row.get("host") or rp.stem),
                              "results": str(rp),
                              "ds": str(row.get("ds") or ""),
                              "tenant": str(row.get("tenant") or "")})
        except Exception:
            specs = []
    if not specs:
        for rp in sorted(day_dir.glob("results-*.xml")):
            specs.append({"host": rp.stem[len("results-"):],
                          "results": str(rp), "ds": "", "tenant": ""})
    out = []
    for spec in specs:
        if not spec["ds"] or not Path(spec["ds"]).exists():
            spec["ds"] = _benchmark_to_ds(spec["results"]) or ""
        if spec["ds"]:
            out.append(spec)
    return out


def merge_results(specs: List[Dict[str, str]], tenant_id: str, day: str,
                  dry_run: bool = False) -> Dict[str, Any]:
    """Worst-result merge of multiple hosts' scan results into ONE
    evidence write per control/day (canonical implementation of the
    collect_fleet_day.py merge rule):
      any host "fail"      -> fail
      all "pass"/"fixed"   -> pass
      otherwise            -> rule dropped (neutral)
    With dry_run=True nothing is written; counts are still computed."""
    per_host: Dict[str, Any] = {}
    occ: Dict[str, List] = {}
    refs: Dict[str, List[str]] = {}
    skipped: List[Dict[str, str]] = []
    for spec in specs:
        host, rp, ds = spec["host"], spec["results"], spec["ds"]
        if not ds or not Path(ds).exists():
            skipped.append({"host": host, "reason": "datastream unresolved"})
            continue
        try:
            rows = parse_rule_results(rp)
        except Exception as exc:
            skipped.append({"host": host, "reason": repr(exc)})
            continue
        per_host[host] = {
            "rules": len(rows),
            "pass": sum(1 for r in rows if r["result"] in _PASS_RESULTS),
            "fail": sum(1 for r in rows if r["result"] == "fail"),
        }
        for r in rows:
            occ.setdefault(r["rule"], []).append((host, r["result"]))
        for rule, rl in parse_ds_rule_nist(ds).items():
            lst = refs.setdefault(rule, [])
            for ref in rl:
                if ref not in lst:
                    lst.append(ref)
    merged_rows = []
    for rule, o in occ.items():
        results = {x[1] for x in o}
        if "fail" in results:
            w = "fail"
        elif results and results <= _PASS_RESULTS:
            w = "pass"
        else:
            continue  # notchecked/notselected/mixed-neutral -> drop
        merged_rows.append({"rule": rule, "result": w,
                            "hosts": sorted({h for h, _ in o}),
                            "source": "oscap"})
    counts: Dict[str, int] = {}
    if merged_rows and not dry_run:
        counts = write_evidence(tenant_id, merged_rows, refs, day,
                                "fleet:" + ",".join(sorted(per_host)))
    return {"per_host": per_host, "merged_rules": len(merged_rows),
            "evidence_counts": counts, "skipped": skipped}


def host_control_status(day: str, tenant_id: Optional[str] = None,
                        manifest_path: Optional[str] = None
                        ) -> Dict[str, Any]:
    """Per-host per-control attribution from the day's scan results.
    The merged evidence loses which host failed what — this re-derives
    it (Phase 1.4 prerequisite): for each host with archived results,
    roll its rule rows up to controls and report per-control status.
    Fleet-scale remediation keys on the failing (host, control) pairs.
    Read-only."""
    specs = _specs_from_day(day, manifest_path)
    if not specs:
        return {"ok": False,
                "error": f"no scan results found for day {day} under "
                         f"{SCAN_RESULTS_DIR / day}"}
    if tenant_id is None:
        for s in specs:
            if s.get("tenant"):
                tenant_id = s["tenant"]
                break
    if tenant_id is None:
        tenant_id = _default_tenant()
    if tenant_id is None:
        return {"ok": False, "error": "no tenant resolved"}
    from soc_stig import tool_applicable_for_tenant
    applicable = {c["id"] for c in
                  tool_applicable_for_tenant({"tenant_id": tenant_id})
                  ["controls"]}
    hosts: Dict[str, Any] = {}
    for spec in specs:
        if not spec["ds"] or not Path(spec["ds"]).exists():
            continue
        try:
            rows = parse_rule_results(spec["results"])
        except Exception:
            continue
        refs = parse_ds_rule_nist(spec["ds"])
        rollup = _control_rollup(rows, refs, applicable)
        controls = {cid: s["status"] for cid, s in
                    sorted(rollup.items())}
        hosts[spec["host"]] = {
            "controls": controls,
            "failed": [cid for cid, s in controls.items()
                       if s == "fail"],
        }
    return {"ok": True, "day": day, "tenant": tenant_id, "hosts": hosts}


def collect_day(day: str, tenant_id: Optional[str] = None,
                manifest_path: Optional[str] = None,
                score: bool = False, dry_run: bool = False
                ) -> Dict[str, Any]:
    """Collect + merge every scan recorded for `day` into the evidence
    store (single write per control), optionally recompute the score.
    Tenant resolution: explicit argument > manifest-recorded tenant >
    SOC_OSCAP_TENANT > first known tenant."""
    specs = _specs_from_day(day, manifest_path)
    if not specs:
        return {"ok": False,
                "error": f"no scan results found for day {day} under "
                         f"{SCAN_RESULTS_DIR / day}"}
    if tenant_id is None:
        for s in specs:
            if s.get("tenant"):
                tenant_id = s["tenant"]
                break
    if tenant_id is None:
        tenant_id = _default_tenant()
    if tenant_id is None:
        return {"ok": False, "error": "no tenant resolved (pass --tenant "
                "or set SOC_OSCAP_TENANT)"}
    out: Dict[str, Any] = {"ok": True, "day": day, "tenant": tenant_id,
                           "hosts": len(specs)}
    out.update(merge_results(specs, tenant_id, day, dry_run=dry_run))
    if not dry_run:
        # record the day's manifest (host/ds/tenant) for later re-collects
        day_dir = SCAN_RESULTS_DIR / day
        day_dir.mkdir(parents=True, exist_ok=True)
        mp = day_dir / "manifest.json"
        rows: List[Dict[str, Any]] = []
        seen = set()
        if mp.exists():
            try:
                for row in json.loads(mp.read_text()):
                    h = row.get("host")
                    if h in seen:
                        continue
                    seen.add(h)
                    # attribute pre-existing entries to the resolved
                    # tenant too, so re-collects inherit it
                    row["tenant"] = tenant_id
                    rows.append(row)
            except Exception:
                pass
        for s in specs:
            if s["host"] in seen:
                continue
            seen.add(s["host"])
            rows.append({"host": s["host"], "results": s["results"],
                         "ds": s["ds"], "tenant": tenant_id})
        mp.write_text(json.dumps(rows, indent=1))
    if score and not dry_run:
        try:
            from soc_score import tool_compute_score
            out["score"] = tool_compute_score({"tenant_id": tenant_id,
                                               "day": day})
        except Exception as exc:
            out["score_error"] = repr(exc)
    return out


def _control_rollup(rule_rows: List[Dict[str, Any]],
                    rule_refs: Dict[str, List[str]],
                    applicable: set) -> Dict[str, Dict[str, Any]]:
    """Map rule results -> CMMC controls (800-53 refs + aliases).
    Shared by write_evidence and host_control_status (per-host
    attribution) — one source of truth for the rollup. A control fails
    when any mapped rule fails; passes only when it has mapped rules
    and every one passes; partial coverage stays manual_review."""
    from soc_evidence import _CONTROL_ALIASES
    by_control: Dict[str, Dict[str, Any]] = {}
    for row in rule_rows:
        refs = []
        for ref in rule_refs.get(row["rule"], []):
            m = _NIST_RE.match(ref)
            if m:
                refs.append(ref)
        if not refs:
            continue
        for nist in refs:
            for cid in [nist] + _CONTROL_ALIASES.get(nist, []):
                if cid not in applicable:
                    continue
                slot = by_control.setdefault(
                    cid, {"fails": 0, "passes": 0, "rules": []})
                slot["rules"].append(row["rule"])
                if row["result"] == "fail":
                    slot["fails"] += 1
                elif row["result"] in ("pass", "fixed"):
                    slot["passes"] += 1
    for cid, slot in by_control.items():
        slot["status"] = ("fail" if slot["fails"] else
                          ("pass" if slot["passes"] else "manual_review"))
    return by_control


def write_evidence(tenant_id: str, rule_rows: List[Dict[str, Any]],
                   rule_refs: Dict[str, List[str]], day: str,
                   host: str) -> Dict[str, int]:
    """Map rule results -> CMMC controls -> evidence store. A control
    fails when any mapped rule fails; passes only when it has mapped
    rules and every one passes (partial coverage stays manual_review
    unless a failing rule exists). Returns per-control status counts.
    """
    from soc_evidence import (_evidence_path, _write_evidence)
    from soc_stig import tool_applicable_for_tenant
    applicable = {c["id"] for c in
                  tool_applicable_for_tenant({"tenant_id": tenant_id})
                  ["controls"]}

    by_control = _control_rollup(rule_rows, rule_refs, applicable)

    counts = {"pass": 0, "fail": 0, "neutral": 0}
    for cid, slot in sorted(by_control.items()):
        status = slot["status"]
        items = [{
            "source": "oscap",
            "kind": "oscap_rule_result",
            "ts": _now(),
            "summary": f"{host}: {len(slot['rules'])} rule(s) checked, "
                       f"{slot['fails']} fail",
            "outcome": status,
            "status": "fail" if status == "fail" else (
                "ok" if status == "pass" else None),
            "payload": {"host": host, "rules": slot["rules"][:20],
                        "fails": slot["fails"], "passes": slot["passes"]},
        }]
        _write_evidence(_evidence_path(tenant_id, cid, day),
                        items, status)
        counts[status if status in counts else "neutral"] += 1
    return counts


def scan_and_record(agent: Dict[str, Any], tenant_id: str, day: str,
                    profile: Optional[str] = None,
                    dry_run: bool = False) -> Dict[str, Any]:
    out = scan_host(agent, day, profile=profile, dry_run=dry_run)
    if dry_run or not out.get("ok"):
        return out
    results_xml = out.get("results_path")
    if not results_xml:
        return dict(out, evidence={"error": "no results file produced"})
    try:
        rows = parse_rule_results(results_xml)
        refs = parse_ds_rule_nist(str(
            out.get("ds_path") or _ds_path_for(agent)))
        counts = write_evidence(tenant_id, rows, refs, day,
                                str(out.get("host")))
        return dict(out, evidence=counts)
    except Exception as exc:
        return dict(out, evidence={"error": repr(exc)})


def _ds_path_for(agent: Dict[str, Any]) -> Optional[str]:
    family = _family(agent.get("platform") or "")
    if family in SSG_PROFILES:
        return str(SSG_DIR / SSG_PROFILES[family][0])
    return None


def scan_fleet(agents: List[Dict[str, Any]], tenant_id: str, day: str,
               profile: Optional[str] = None,
               dry_run: bool = False) -> Dict[str, Any]:
    """Scan every reachable managed host, then merge ALL hosts' results
    into ONE evidence write (worst-result per rule, see merge_results).
    Per-host immediate writes would thrash the evidence store: each
    control/day file is replaced whole, so the last host scanned would
    wipe every other host's findings (the 2026-09-13 lesson)."""
    started = _now()
    out: Dict[str, Any] = {"started": started, "scans": [], "errors": []}

    def _scan(a):
        return scan_host(a, day, profile=profile, dry_run=dry_run)

    specs: List[Dict[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=PARALLEL) as pool:
        futs = {pool.submit(_scan, a): a for a in agents}
        for fut in concurrent.futures.as_completed(futs):
            a = futs[fut]
            try:
                res = fut.result()
            except Exception as exc:
                out["errors"].append({"host": a.get("name"),
                                      "error": repr(exc)})
                continue
            out["scans"].append(res)
            if res.get("ok") and res.get("results_path"):
                specs.append({"host": str(res.get("host")),
                              "results": str(res["results_path"]),
                              "ds": str(res.get("ds_path") or ""),
                              "tenant": tenant_id})
    if dry_run:
        out["counts"] = {"scanned": len(out["scans"]),
                         "errors": len(out["errors"]),
                         "would_merge_hosts": len(
                             [s for s in out["scans"] if s.get("ok")])}
        return out
    out["completed"] = _now()
    if specs:
        merged = merge_results(specs, tenant_id, day)
        out["merge"] = merged
        out["evidence"] = merged.get("evidence_counts")
    out["counts"] = {"scanned": len(out["scans"]),
                     "errors": len(out["errors"]),
                     "merged_hosts": len(specs)}
    return out


def _default_tenant() -> Optional[str]:
    env = os.environ.get("SOC_OSCAP_TENANT")
    if env:
        return env
    try:
        from soc_routing import get_config
        known = get_config().known_tenants()
        return known[0] if known else None
    except Exception:
        return None


def _local_agent_row() -> Optional[Dict[str, Any]]:
    """Synthetic agent row for the SOC host itself (the manager is
    agent 000 and fleet_agents() excludes it by design — but the SOC
    host is the most important asset to scan). Platform detected from
    /etc/os-release."""
    import socket as _socket
    platform = ""
    version = ""
    try:
        for line in open("/etc/os-release"):
            k, _, v = line.partition("=")
            v = v.strip().strip('"')
            if k == "ID":
                platform = v
            elif k == "VERSION_ID":
                version = v
    except OSError:
        return None
    if not platform:
        return None
    return {"id": "000", "name": _socket.gethostname(),
            "ip": "127.0.0.1", "platform": platform.lower(),
            "os_version": version}


def _tasklog():
    """Lazy services/soc_tasklog (best-effort; None when unavailable)."""
    try:
        import soc_tasklog
        return soc_tasklog
    except Exception:
        return None


def _tasklog_run(run_id_target: str, fn, *args, **kwargs) -> Any:
    """Run a scan entrypoint with tasklog running→done/failed rows so
    /tasks shows automated runs with real state (2026-09-14: the CLI
    was invisible to the task pane)."""
    tl = _tasklog()
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    if tl:
        try:
            tl.record_task("stig_scan", run_id_target, "running", started)
        except Exception:
            pass
    try:
        res = fn(*args, **kwargs)
    except Exception as exc:
        if tl:
            try:
                tl.record_task("stig_scan", run_id_target, "failed", started,
                               ended=dt.datetime.now(
                                   dt.timezone.utc).isoformat(),
                               details={"error": repr(exc)})
            except Exception:
                pass
        raise
    if tl:
        try:
            counts = (res or {}).get("counts") if isinstance(res, dict) else None
            tl.record_task("stig_scan", run_id_target, "done", started,
                           ended=dt.datetime.now(
                               dt.timezone.utc).isoformat(),
                           details={"counts": counts or {}})
        except Exception:
            pass
    return res


def _smoke() -> int:
    """Hermetic self-test: synthetic XCCDF results + DS mapping →
    parse → worst-result merge (dry_run: no evidence writes)."""
    import tempfile

    tmp = tempfile.mkdtemp(prefix="soc-scanner-smoke-")
    globals()["SCAN_RESULTS_DIR"] = Path(tmp) / "scans"
    day = "2026-01-01"
    daydir = Path(tmp) / "scans" / day
    daydir.mkdir(parents=True)

    xccdf = (
        '<?xml version="1.0"?>\n'
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" '
        'id="xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04">\n'
        '  <TestResult>\n'
        '    <rule-result idref="xccdf_org.ssgproject.content_rule_a">'
        '<result>{}</result></rule-result>\n'
        '    <rule-result idref="xccdf_org.ssgproject.content_rule_b">'
        '<result>pass</result></rule-result>\n'
        '    <rule-result idref="xccdf_org.ssgproject.content_rule_c">'
        '<result>notchecked</result></rule-result>\n'
        '  </TestResult>\n'
        '</Benchmark>\n')
    (daydir / "results-host1.xml").write_text(xccdf.format("fail"))
    (daydir / "results-host2.xml").write_text(xccdf.format("pass"))

    specs = _specs_from_day(day)
    assert len(specs) == 2, specs
    assert specs[0]["ds"].endswith("ssg-ubuntu2404-ds.xml"), specs

    merged = merge_results(specs, "example-soc", day, dry_run=True)
    assert merged["per_host"]["host1"]["fail"] == 1, merged
    assert merged["merged_rules"] == 2, merged  # c dropped (neutral)
    assert merged["evidence_counts"] == {}, merged  # dry_run: no writes

    shutil.rmtree(tmp, ignore_errors=True)
    sys.stdout.write("soc-scanner smoke test: OK\n")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="SOC OpenSCAP compliance scanner")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--host", help="agent name or id (fleet-resolved), "
                   "or any name if --host-ip is given")
    g.add_argument("--fleet", action="store_true",
                   help="scan every reachable managed host")
    g.add_argument("--collect", metavar="DAY",
                   help="merge + collect existing scan results for DAY "
                        "(e.g. 2026-09-13) into evidence; combine with "
                        "--score. Replaces the manual scp/parse/merge "
                        "dance after detached scans")
    ap.add_argument("--manifest", help="collect mode: manifest.json path "
                    "(default: <scans-dir>/<day>/manifest.json; when "
                    "absent, results-*.xml are discovered and the "
                    "datastream is inferred from each results file)")
    ap.add_argument("--score", action="store_true",
                    help="collect mode: recompute the tenant score after "
                    "collecting")
    ap.add_argument("--host-ip", help="target IP (skips fleet resolution; "
                    "requires --family when the host is not in the fleet)")
    ap.add_argument("--family", help="OS family override "
                    "(ubuntu|rhel|debian|...)")
    ap.add_argument("--os-version", help="OS version hint for datastream "
                    "selection, e.g. 24.04 (default: fleet-resolved or "
                    "newest local SSG file)")
    ap.add_argument("--profile", help="XCCDF profile id override")
    ap.add_argument("--tenant", help="evidence tenant "
                    "(default: SOC_OSCAP_TENANT or first known tenant)")
    ap.add_argument("--day", help="evidence day (default: today, UTC)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the resolved command and exit")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output")
    ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args(argv)
    if args.smoke:
        return _smoke()
    if not (args.host or args.fleet or args.collect):
        ap.error("one of --host / --fleet / --collect is required")
    day = args.day or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    tenant = args.tenant or _default_tenant()

    def emit(res: Dict[str, Any]) -> int:
        if args.json:
            print(json.dumps(res, indent=2, default=str))
            return 0 if res.get("ok", True) else 1
        if args.dry_run and isinstance(res, dict) and res.get("command"):
            print("DRY-RUN:", res["command"])
            return 0
        print(json.dumps(res, indent=2, default=str))
        return 0 if res.get("ok", True) else 1

    if args.collect:
        return emit(collect_day(args.collect, tenant,
                                manifest_path=args.manifest,
                                score=args.score,
                                dry_run=args.dry_run))

    if args.fleet:
        agents = [a for a in fleet_agents() if _family(a["platform"])]
        # include the SOC host itself (agent 000 is excluded from the
        # fleet list; scan it locally via ssh loopback)
        local = _local_agent_row()
        if local and _family(local["platform"]) and \
                not any(a.get("name") == local["name"] for a in agents):
            agents.append(local)
        if not agents:
            print(json.dumps({"ok": False,
                              "error": "no scannable agents (family resolved)"}))
            return 1
        return emit(_tasklog_run("fleet", scan_fleet, agents, tenant,
                                 day, args.profile, args.dry_run))

    # single host
    agents = fleet_agents()
    row = None
    for a in agents:
        if args.host in (a["name"], a["id"]):
            row = dict(a)
            break
    if row is None and args.host_ip:
        row = {"id": "", "name": args.host, "ip": args.host_ip,
               "platform": args.family or "",
               "os_version": args.os_version or ""}
    if row is None:
        # the SOC host itself is agent 000 (excluded from the fleet
        # list) — resolve the local host by hostname
        local = _local_agent_row()
        if local and args.host in (local["name"], local["id"], "local"):
            row = local
    if row is None:
        return emit({"ok": False,
                     "error": f"host {args.host!r} not in fleet; "
                              "pass --host-ip + --family for out-of-band targets"})
    if args.family:
        row["platform"] = args.family
    if args.os_version:
        row["os_version"] = args.os_version
    if not row.get("os_version") and (row.get("platform") or "").startswith("ubuntu"):
        # out-of-band target without a version: prefer the newest local
        # ubuntu datastream (2404 over 2204) so CPE checks match.
        if (SSG_DIR / "ssg-ubuntu2404-ds.xml").exists():
            row["os_version"] = "24.04"
    return emit(_tasklog_run(args.host, scan_and_record, row, tenant,
                             day, args.profile, args.dry_run))


if __name__ == "__main__":
    sys.exit(main())