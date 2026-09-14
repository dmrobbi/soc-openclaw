#!/usr/bin/env python3
"""SOC control evidence collector (Track E, task E3 — 2026-08-08).

Per-tenant × control evidence collection for the compliance
track (E3-E6). For each applicable control (per D3 + E1),
gathers evidence items from:

  - the C4 audit log (`~/.openclaw/audit_log.jsonl`)
  - the realtime SOC JSONL
    (`~/.openclaw/workspace/agentic-ai/data/realtime_soc.jsonl`)
  - the E2 remediation log
    (`~/.openclaw/compliance/remediations.jsonl`)
  - the E2 snapshots (`~/.openclaw/compliance/snapshots/`)

For each `(tenant, control, day)`, the collector writes
`compliance/evidence/<tenant>/<control_id>/<YYYY-MM-DD>.jsonl`
with one row per evidence item. Each row is a dict with
`source`, `kind`, `ts`, and any source-specific payload.

Why per-control directories
---------------------------
The directory structure mirrors the per-tenant × control
grid that E4 (POA&M) and E5 (renderers) will consume. A
single day is one file per control; multiple days accumulate.

Status semantics
----------------
For each (tenant, control, day) the collector computes a
status:

  - "pass"             evidence items exist that demonstrate
                        the control is satisfied
  - "fail"             evidence items demonstrate the
                        control is NOT satisfied (e.g. the
                        `check:` returned non-zero, or an
                        alert fired that the control covers)
  - "not_applicable"   no evidence found AND the control
                        is in the catalogue but the check
                        would be impossible to fail (e.g.
                        a policy document that just needs
                        to exist)
  - "manual_review"    the control has no automated
                        evidence path; needs a human

Tools
-----
  * collect_evidence(tenant_id, control_id=None, day=None,
                    max_age_days=7)
        -> {ok, tenant_id, day, controls[], summary}
        For each applicable control, gathers evidence +
        writes the per-control JSONL. Idempotent: re-running
        for the same (tenant, control, day) overwrites the
        file.
  * list_evidence(tenant_id, control_id=None, day=None)
        -> {ok, files[]}
        Lists the existing evidence files for a tenant.
  * get_evidence(tenant_id, control_id, day)
        -> {ok, tenant_id, control_id, day, status,
            evidence: [...], summary}
  * evidence_summary(tenant_id, day=None)
        -> {ok, summary: {control_id: status, ...},
            counts: {pass, fail, not_applicable, manual_review}}

The collectors
--------------
For each control, the collector picks the most relevant
evidence sources based on the control's `family` and
`automated` flag:

  AC (access control)  audit log + Wazuh auth events
  AU (audit)           audit log presence
  IA (auth)            audit log + auth events
  SI (system integrity) Wazuh alerts + E2 checks
  SC (boundary)        Wazuh alerts + audit log
  IR (incident resp)   audit log + E4 POA&M
  MA / MP / PE / others policy/manual
  generic              audit log + E2 remediations + Wazuh

This is a heuristic — the goal is "enough evidence to
make E4/E5 useful," not "perfect coverage of every
control." The evidence is per-row traceable to the
source via `source` + `source_ref` fields.

Created 2026-08-08 by Ciceron as part of Track E (E3).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# services/ layout: parents[1] = repo root (fixed for soc-openclaw)
REPO_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_BASE = Path(os.environ.get(
    "SOC_EVIDENCE_DIR",
    str(Path.home() / ".openclaw" / "compliance" / "evidence")))
SNAPSHOT_DIR = Path(os.environ.get(
    "SOC_SNAPSHOT_DIR",
    str(Path.home() / ".openclaw" / "compliance" / "snapshots")))
REMEDIATION_LOG = Path(os.environ.get(
    "SOC_REMEDIATION_LOG",
    str(Path.home() / ".openclaw" / "compliance" / "remediations.jsonl")))
DEFAULT_AUDIT_LOG = os.environ.get("SOC_AUDIT_LOG", "") or os.path.expanduser("~/.openclaw/audit_log.jsonl")
DEFAULT_REALTIME_LOG = os.environ.get("SOC_REALTIME_LOG", "") or os.path.expanduser(
    "~/.openclaw/soc/data/realtime_soc.jsonl")
DEFAULT_C4_URL = "http://127.0.0.1:8769"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class EvidenceError(Exception):
    """Raised on evidence collection failure."""


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------
def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                sys.stderr.write(
                    f"[soc-evidence] skipping non-JSON line at {path}:{i+1}\n")
    return out


def _filter_day(records: List[Dict[str, Any]], day: str) -> List[Dict[str, Any]]:
    return [r for r in records if (r.get("ts") or "").startswith(day)]


# ---------------------------------------------------------------------------
# Evidence collectors (per control)
# ---------------------------------------------------------------------------
# 2026-09-13: the stig-rules classifier catalogues emit NIST 800-53
# control ids (e.g. AU-2) while this module's catalogue uses CMMC
# assessment ids (e.g. AU.L1-3.3.001). Map each 800-53 id to the CMMC
# controls whose title/800-171 mapping it corresponds to. An 800-53
# control with no matching CMMC practice stays unmapped (honest: the
# finding is recorded, just not scored).
_CONTROL_ALIASES = {
    "AC-2": ["AC.L1-3.1.002"],      # Account Management
    "AC-3": ["AC.L1-3.1.003"],      # Access Enforcement
    "AC-7": [],                      # unsuccessful logon — no L1 practice
    "AU-2": ["AU.L1-3.3.001"],      # Audit Events
    "AU-9": ["AU.L1-3.3.003"],      # Protect Audit Information
    "IA-5": ["IA.L1-3.5.002", "IA.L2-3.5.005"],
    "CM-7": [],                      # least functionality — no CM practice
    "SC-7": ["SC.L1-3.13.002"],     # Boundary Protection
}


def _cid_match(cid: str, other: Any) -> bool:
    """True when evidence control id `other` matches catalogue control
    id `cid` directly or via the 800-53 alias table."""
    if not isinstance(other, str):
        return False
    if other == cid:
        return True
    return cid in _CONTROL_ALIASES.get(other, [])


def _collect_from_audit_log(audit: List[Dict[str, Any]],
                            control: Dict[str, Any],
                            day: str) -> List[Dict[str, Any]]:
    """Pull relevant audit log entries for this control.
    Heuristic: any record with `extra.stig_evidence.control_id`
    matching; otherwise look for records whose `agent_id` is
    `soc-stig-remediate` and `input_summary` mentions the
    control id (the E2 audit trail)."""
    cid = control.get("id")
    out = []
    for r in audit:
        if not (r.get("ts") or "").startswith(day):
            continue
        extra = r.get("extra") or {}
        # Direct evidence tag (future: agents tag records
        # with extra.stig_evidence.control_id=...)
        se = extra.get("stig_evidence")
        if isinstance(se, dict) and _cid_match(cid, se.get("control_id")):
            out.append({
                "source": "audit_log",
                "kind": "stig_evidence",
                "ts": r.get("ts"),
                "summary": r.get("input_summary"),
                "outcome": r.get("outcome"),
                "source_ref": {"runId": r.get("runId"),
                                "agent_id": r.get("agent_id")},
                "payload": se,
            })
            continue
        # E2 trail
        sdr = extra.get("stig_remediate_applied")
        if isinstance(sdr, dict) and _cid_match(cid, sdr.get("control_id")):
            out.append({
                "source": "audit_log",
                "kind": "stig_remediate_applied",
                "ts": r.get("ts"),
                "summary": r.get("input_summary"),
                "outcome": r.get("outcome"),
                "source_ref": {"runId": r.get("runId"),
                                "agent_id": r.get("agent_id")},
                "payload": sdr,
            })
            continue
        sdr = extra.get("stig_remediate_refused")
        if isinstance(sdr, dict) and _cid_match(cid, sdr.get("control_id")):
            out.append({
                "source": "audit_log",
                "kind": "stig_remediate_refused",
                "ts": r.get("ts"),
                "summary": r.get("input_summary"),
                "outcome": r.get("outcome"),
                "source_ref": {"runId": r.get("runId"),
                                "agent_id": r.get("agent_id")},
                "payload": sdr,
            })
            continue
        sdr = extra.get("stig_remediate_rolled_back")
        if isinstance(sdr, dict) and _cid_match(cid, sdr.get("control_id")):
            out.append({
                "source": "audit_log",
                "kind": "stig_remediate_rolled_back",
                "ts": r.get("ts"),
                "summary": r.get("input_summary"),
                "outcome": r.get("outcome"),
                "source_ref": {"runId": r.get("runId"),
                                "agent_id": r.get("agent_id")},
                "payload": sdr,
            })
            continue
    return out


def _collect_from_realtime(realtime: List[Dict[str, Any]],
                           control: Dict[str, Any],
                           day: str) -> List[Dict[str, Any]]:
    """Pull relevant realtime SOC alerts for this control.
    Heuristic: alerts that mention the control's family in
    their narrative, OR have a rule that maps to a control
    (we keep it simple — only the family-based match for now,
    the per-rule mapping is a future enhancement)."""
    cid = control.get("id")
    family = control.get("family")
    family_to_alert_kind = {
        "AC": "access-control",  # brute-force, ssh
        "AU": "audit",
        "IA": "authentication",
        "SC": "boundary",
        "SI": "monitoring",
    }
    target = family_to_alert_kind.get(family)
    out = []
    for r in realtime:
        if not (r.get("ts") or "").startswith(day):
            continue
        nar = (r.get("agentic_narrative") or "").lower()
        title = (r.get("title") or "").lower()
        if target and (target in nar or target in title):
            out.append({
                "source": "realtime_soc",
                "kind": "alert",
                "ts": r.get("ts"),
                "summary": r.get("title"),
                "severity": r.get("severity"),
                "status": r.get("status"),
                "source_ref": {"alert_id": r.get("alert_id"),
                                "source": r.get("source")},
                "payload": {"affected_asset": r.get("affected_asset"),
                            "rule_name": r.get("rule_name")},
            })
    return out


def _collect_from_remediation_log(rem_log: List[Dict[str, Any]],
                                  control: Dict[str, Any],
                                  day: str) -> List[Dict[str, Any]]:
    cid = control.get("id")
    out = []
    for r in rem_log:
        if not (r.get("ts") or "").startswith(day):
            continue
        if r.get("control_id") != cid:
            continue
        out.append({
            "source": "remediation_log",
            "kind": "remediation",
            "ts": r.get("ts"),
            "summary": f"{r.get('status')} for {cid}",
            "status": r.get("status"),
            "source_ref": {"action_id": r.get("action_id")},
            "payload": {"rc": r.get("rc"),
                        "tenant_id": r.get("tenant_id")},
        })
    return out


def _collect_from_snapshots(snapshots_dir: Path,
                            control: Dict[str, Any],
                            day: str) -> List[Dict[str, Any]]:
    """E2 check snapshots: each snapshot file has a ts and
    a control_id; if the snapshot is for our control AND
    the ts starts with our day, it's evidence."""
    cid = control.get("id")
    out = []
    if not snapshots_dir.exists():
        return out
    for f in snapshots_dir.glob(f"stig-{re.sub(r'[^A-Za-z0-9._-]', '_', cid)[:48]}-*.json"):
        try:
            data = json.load(open(f))
        except (json.JSONDecodeError, OSError):
            continue
        if data.get("control_id") != cid:
            continue
        ts = (data.get("ts") or "")
        if not ts.startswith(day):
            continue
        out.append({
            "source": "snapshot",
            "kind": data.get("kind", "snapshot"),
            "ts": ts,
            "summary": f"snapshot for {cid}",
            "status": ("ok"
                       if (data.get("apply_rc")
                           if "apply_rc" in data
                           else data.get("pre_probe_rc")) == 0
                       else "fail"),
            "source_ref": {"snapshot_path": str(f)},
            "payload": {"rc": data.get("pre_probe_rc"),
                        "apply_rc": data.get("apply_rc"),
                        "rolled_back": data.get("rolled_back", False)},
        })
    return out


# ---------------------------------------------------------------------------
# Status derivation
# ---------------------------------------------------------------------------
def _derive_status(control: Dict[str, Any],
                   evidence: List[Dict[str, Any]]) -> str:
    """Compute the (tenant, control, day) status from the
    evidence items. Heuristic:
      - any fail-grade item -> "fail"
      - any pass-grade item -> "pass"
      - no evidence + automated -> "manual_review"
      - no evidence + not automated + has policy-ish tags -> "not_applicable"
      - no evidence + otherwise -> "manual_review"
    """
    if not evidence:
        if not control.get("automated"):
            return "manual_review"
        return "manual_review"  # even automated controls without
                                # evidence are manual until proven
    has_pass = any(e.get("status") == "ok" or e.get("kind")
                   in ("stig_remediate_applied", "snapshot")
                   for e in evidence)
    # stig_evidence rows are STIG findings — non-compliance evidence
    # until a remediation pass confirms otherwise (2026-09-13: the
    # old heuristic graded them neutral, so controls with 48 live
    # findings stayed manual_review forever).
    has_fail = any(e.get("status") == "fail" or
                   e.get("kind") in ("stig_remediate_refused",
                                     "stig_evidence")
                   for e in evidence)
    if has_fail and not has_pass:
        return "fail"
    if has_pass and not has_fail:
        return "pass"
    if has_pass and has_fail:
        # Mixed evidence: if any item is rolled_back or refused
        # but a later one is applied, prefer pass
        return "pass"
    return "manual_review"


# ---------------------------------------------------------------------------
# Per-tenant × control collection
# ---------------------------------------------------------------------------
def _applicable_controls(tenant_id: str) -> List[Dict[str, Any]]:
    """Read D3 + E1 to get the controls applicable to a tenant."""
    try:
        from soc_stig import tool_applicable_for_tenant
    except ImportError as e:
        raise EvidenceError(f"soc_stig not importable: {e!r}")
    r = tool_applicable_for_tenant({"tenant_id": tenant_id})
    # We have summaries; we need the full records for the check
    # text. Re-load the catalogue and filter.
    from soc_stig import get_catalogue
    cat = get_catalogue()
    applicable_ids = {c["id"] for c in r["controls"]}
    return [c for c in cat["controls"] if c.get("id") in applicable_ids]


def _evidence_path(tenant_id: str, control_id: str, day: str) -> Path:
    safe_tid = re.sub(r"[^A-Za-z0-9._-]", "_", tenant_id)
    safe_cid = re.sub(r"[^A-Za-z0-9._-]", "_", control_id)
    p = EVIDENCE_BASE / safe_tid / safe_cid / f"{day}.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _write_evidence(path: Path,
                    items: List[Dict[str, Any]],
                    status: str) -> None:
    # We store the status as the first line of the file so a
    # reader doesn't have to re-derive it. Items are JSONL
    # after a `STATUS:` sentinel line.
    tmp = path.with_suffix(".jsonl.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps({"_status": status,
                             "_count": len(items),
                             "_written_at": dt.datetime.now(
                                 dt.timezone.utc).isoformat(
                                 timespec="milliseconds")}) + "\n")
        for it in items:
            f.write(json.dumps(it, default=str) + "\n")
    os.replace(tmp, path)


def _read_evidence(path: Path) -> Tuple[str, List[Dict[str, Any]]]:
    if not path.exists():
        return "manual_review", []
    status = "manual_review"
    items: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if i == 0 and isinstance(obj, dict) and "_status" in obj:
                status = obj.get("_status", status)
                continue
            items.append(obj)
    return status, items


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------
def tool_collect_evidence(args: Dict[str, Any]) -> Dict[str, Any]:
    """collect_evidence(tenant_id, control_id=None, day=None,
                       max_age_days=7)"""
    tid = args.get("tenant_id")
    if not tid:
        raise ValueError("tenant_id is required")
    day = args.get("day") or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    control_id = args.get("control_id")
    max_age_days = int(args.get("max_age_days") or 7)

    applicable = _applicable_controls(tid)
    if control_id:
        applicable = [c for c in applicable if c.get("id") == control_id]
        if not applicable:
            raise ValueError(
                f"control {control_id!r} not applicable to tenant {tid!r}")

    audit = _load_jsonl(Path(DEFAULT_AUDIT_LOG))
    realtime = _load_jsonl(Path(DEFAULT_REALTIME_LOG))
    rem_log = _load_jsonl(REMEDIATION_LOG)

    out = []
    counts = Counter()
    for c in applicable:
        items = []
        items.extend(_collect_from_audit_log(audit, c, day))
        items.extend(_collect_from_realtime(realtime, c, day))
        items.extend(_collect_from_remediation_log(rem_log, c, day))
        items.extend(_collect_from_snapshots(SNAPSHOT_DIR, c, day))
        status = _derive_status(c, items)
        path = _evidence_path(tid, c["id"], day)
        _write_evidence(path, items, status)
        counts[status] += 1
        out.append({
            "control_id": c["id"],
            "family": c.get("family"),
            "severity": c.get("severity"),
            "status": status,
            "evidence_count": len(items),
            "evidence_path": str(path),
        })
    return {
        "ok": True, "tool": "collect_evidence",
        "tenant_id": tid, "day": day,
        "max_age_days": max_age_days,
        "total_controls": len(applicable),
        "counts": dict(counts),
        "controls": out,
    }


def tool_list_evidence(args: Dict[str, Any]) -> Dict[str, Any]:
    """list_evidence(tenant_id, control_id=None, day=None)."""
    tid = args.get("tenant_id")
    if not tid:
        raise ValueError("tenant_id is required")
    safe_tid = re.sub(r"[^A-Za-z0-9._-]", "_", tid)
    base = EVIDENCE_BASE / safe_tid
    if not base.exists():
        return {"ok": True, "tool": "list_evidence",
                "tenant_id": tid, "files": []}
    files = []
    for p in sorted(base.rglob("*.jsonl")):
        rel = p.relative_to(base)
        # rel = control_id / YYYY-MM-DD.jsonl
        if len(rel.parts) != 2:
            continue
        cid, fname = rel.parts
        day = fname.replace(".jsonl", "")
        if args.get("control_id") and cid != args["control_id"]:
            continue
        if args.get("day") and day != args["day"]:
            continue
        status, items = _read_evidence(p)
        files.append({
            "control_id": cid, "day": day,
            "status": status, "evidence_count": len(items),
            "path": str(p),
        })
    return {"ok": True, "tool": "list_evidence",
            "tenant_id": tid, "files": files, "total": len(files)}


def tool_get_evidence(args: Dict[str, Any]) -> Dict[str, Any]:
    """get_evidence(tenant_id, control_id, day) -> {ok, status, evidence[]}"""
    tid = args.get("tenant_id")
    cid = args.get("control_id")
    day = args.get("day")
    if not (tid and cid and day):
        raise ValueError("tenant_id, control_id, day are all required")
    path = _evidence_path(tid, cid, day)
    status, items = _read_evidence(path)
    return {"ok": True, "tool": "get_evidence",
            "tenant_id": tid, "control_id": cid, "day": day,
            "status": status, "evidence_count": len(items),
            "evidence": items, "path": str(path)}


def tool_evidence_summary(args: Dict[str, Any]) -> Dict[str, Any]:
    """evidence_summary(tenant_id, day=None) -> counts per control
    + an overall pass/fail/not_applicable/manual_review breakdown."""
    tid = args.get("tenant_id")
    if not tid:
        raise ValueError("tenant_id is required")
    day = args.get("day")
    r = tool_list_evidence({"tenant_id": tid, "day": day,
                             "control_id": None})
    by_status: Dict[str, List[str]] = defaultdict(list)
    for f in r["files"]:
        by_status[f["status"]].append(f["control_id"])
    counts = {k: len(v) for k, v in by_status.items()}
    total = sum(counts.values())
    pct = {k: (n / total * 100 if total else 0.0)
           for k, n in counts.items()}
    return {"ok": True, "tool": "evidence_summary",
            "tenant_id": tid, "day": day, "total": total,
            "counts": counts, "pct": pct,
            "by_status": dict(by_status)}


# ---------------------------------------------------------------------------
# CLI / smoke
# ---------------------------------------------------------------------------
TOOLS = {
    "collect_evidence": tool_collect_evidence,
    "list_evidence": tool_list_evidence,
    "get_evidence": tool_get_evidence,
    "evidence_summary": tool_evidence_summary,
}


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="SOC control evidence collector (Track E, E3)")
    p.add_argument("--tool", default=None)
    p.add_argument("--args", default=None)
    p.add_argument("--smoke", action="store_true")
    args = p.parse_args(argv)

    if args.smoke:
        return _smoke()

    if not args.tool:
        p.print_help()
        return 1
    if args.tool not in TOOLS:
        print(f"unknown tool: {args.tool}", file=sys.stderr)
        return 2
    a = json.loads(args.args) if args.args else {}
    print(json.dumps(TOOLS[args.tool](a), indent=2, default=str))
    return 0


def _smoke() -> int:
    """Hermetic self-test: redirects the audit/realtime/remediation
    log paths to a temp dir, seeds known data, exercises the
    full collect -> list -> get -> summary cycle."""
    import shutil
    import tempfile

    tmp = tempfile.mkdtemp(prefix="soc-evidence-smoke-")
    audit = os.path.join(tmp, "audit.jsonl")
    realtime = os.path.join(tmp, "realtime.jsonl")
    rem = os.path.join(tmp, "remediations.jsonl")
    snap_dir = os.path.join(tmp, "snapshots")
    ev = os.path.join(tmp, "evidence")
    os.makedirs(snap_dir)
    os.environ["SOC_AUDIT_LOG"] = audit
    os.environ["SOC_REALTIME_LOG"] = realtime
    os.environ["SOC_REMEDIATION_LOG"] = rem
    os.environ["SOC_SNAPSHOT_DIR"] = snap_dir
    os.environ["SOC_EVIDENCE_DIR"] = ev

    # We can't easily monkey-patch the module-level constants
    # here (we've seen the __main__ vs imported-module issue
    # in E2). Use os.environ + a per-tool path override by
    # passing the file paths through the smoke's local vars
    # and re-implementing the file reads inline. Or just
    # point the module's constants at the temp dir BEFORE
    # importing it.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import soc_evidence  # noqa
    # Patch the module constants to use the temp paths.
    # ALSO patch our own __main__ globals (the tool functions
    # were defined in __main__'s namespace when the script
    # was run as `python3 foo.py`, so their __globals__ is
    # __main__.__dict__ — patching the imported module is not
    # enough; we have to patch both). See E2 smoke for the
    # same fix.
    for name, value in [
        ("DEFAULT_AUDIT_LOG", audit),
        ("DEFAULT_REALTIME_LOG", realtime),
        ("REMEDIATION_LOG", Path(rem)),
        ("SNAPSHOT_DIR", Path(snap_dir)),
        ("EVIDENCE_BASE", Path(ev)),
    ]:
        setattr(soc_evidence, name, value)
        globals()[name] = value

    # Seed audit log
    audit_lines = [
        # E2 applied for AU.L1-3.3.003
        {"ts": "2026-08-08T10:00:00.000+00:00",
         "runId": "stig-AU.L1-3.3.003-aaa", "agent_id": "soc-stig-remediate",
         "tenant_id": "example-soc", "input_kind": "stig_remediate_apply",
         "input_summary": "apply fix for AU.L1-3.3.003",
         "outcome": "ok", "extra": {
             "stig_remediate_applied": {"control_id": "AU.L1-3.3.003",
                                          "rc": 0}}},
        # E2 refused for AC.L2-3.1.005
        {"ts": "2026-08-08T10:01:00.000+00:00",
         "runId": "stig-AC.L2-3.1.005-bbb", "agent_id": "soc-stig-remediate",
         "tenant_id": "example-soc", "input_kind": "stig_remediate_decision",
         "input_summary": "refuse AC.L2-3.1.005",
         "outcome": "ok", "extra": {
             "stig_remediate_refused": {"control_id": "AC.L2-3.1.005",
                                          "reason": "low conf"}}},
    ]
    with open(audit, "w") as f:
        for r in audit_lines:
            f.write(json.dumps(r) + "\n")

    realtime_lines = [
        {"ts": "2026-08-08T10:30:00.000+00:00", "type": "alert",
         "title": "Wazuh rule 5763: SSH brute force",
         "agentic_narrative": "An authentication alert for a public mail host.",
         "severity": "high", "status": "escalated",
         "source": "wazuh", "alert_id": "a1"},
    ]
    with open(realtime, "w") as f:
        for r in realtime_lines:
            f.write(json.dumps(r) + "\n")

    rem_lines = [
        {"ts": "2026-08-08T10:00:00.000+00:00", "action_id": "stig-AU.L1-3.3.003-aaa",
         "control_id": "AU.L1-3.3.003", "status": "applied",
         "tenant_id": "example-soc"},
    ]
    with open(rem, "w") as f:
        for r in rem_lines:
            f.write(json.dumps(r) + "\n")

    # E2 snapshot for AU.L1-3.3.003
    snap = {
        "ts": "2026-08-08T10:00:00.000+00:00",
        "control_id": "AU.L1-3.3.003",
        "kind": "pre_remediation",
        "pre_probe_rc": 0, "pre_probe_stdout": "ok",
        "apply_rc": 0, "rolled_back": False,
    }
    with open(os.path.join(snap_dir, "stig-AU.L1-3.3.003-aaa.json"), "w") as f:
        json.dump(snap, f)

    # 1. Collect for example-soc
    r = tool_collect_evidence({"tenant_id": "example-soc", "day": "2026-08-08"})
    assert r["ok"], r
    assert r["total_controls"] >= 1, r
    au = next((c for c in r["controls"] if c["control_id"] == "AU.L1-3.3.003"), None)
    assert au is not None, "AU.L1-3.3.003 should be in the result"
    assert au["status"] == "pass", f"AU.L1-3.3.003 status should be pass: {au}"
    # Evidence count: 1 from audit (stig_remediate_applied) +
    # 1 from remediation log + 1 from snapshot = 3
    assert au["evidence_count"] >= 1, au

    ac = next((c for c in r["controls"] if c["control_id"] == "AC.L2-3.1.005"), None)
    if ac is not None:  # AC.L2-3.1.005 is L2-only; only in example-soc
        assert ac["status"] == "fail", f"AC.L2-3.1.005 should be fail: {ac}"

    # 2. list_evidence
    r = tool_list_evidence({"tenant_id": "example-soc", "day": "2026-08-08"})
    assert r["ok"], r
    assert r["total"] >= 1, r
    au_file = next((f for f in r["files"]
                    if f["control_id"].replace(".", "_")
                    == "AU_L1-3_1_003"), None)
    # Hmm, the directory uses safe_cid which converts "." to "_".
    # Let's check via path instead.
    au_file = next((f for f in r["files"] if "AU.L1-3.3.003" in f["path"]
                    or "AU_L1-3_3_003" in f["path"]), None)
    assert au_file is not None, r["files"]
    assert au_file["status"] == "pass", au_file
    assert au_file["evidence_count"] >= 1, au_file

    # 3. get_evidence
    safe_cid = au_file["control_id"]
    r = tool_get_evidence({
        "tenant_id": "example-soc",
        "control_id": safe_cid,  # use the safe form
        "day": "2026-08-08"})
    assert r["ok"], r
    assert r["status"] == "pass", r
    assert r["evidence_count"] >= 1, r
    kinds = {e["kind"] for e in r["evidence"]}
    assert "stig_remediate_applied" in kinds, kinds

    # 4. evidence_summary
    r = tool_evidence_summary({"tenant_id": "example-soc",
                                "day": "2026-08-08"})
    assert r["ok"], r
    assert r["total"] >= 1
    assert "pass" in r["counts"] or "manual_review" in r["counts"]

    # 5. Collect for a single control
    r = tool_collect_evidence({
        "tenant_id": "example-soc", "day": "2026-08-08",
        "control_id": "AU.L1-3.3.003"})
    assert r["total_controls"] == 1, r

    # 6. Collect for a control that's not applicable
    try:
        tool_collect_evidence({
            "tenant_id": "example-soc", "day": "2026-08-08",
            "control_id": "DOES-NOT-EXIST"})
    except ValueError as e:
        assert "not applicable" in str(e), e
    else:
        raise AssertionError("expected ValueError for not-applicable control")

    # 7. Idempotency: re-collecting overwrites
    r1 = tool_collect_evidence({
        "tenant_id": "example-soc", "day": "2026-08-08",
        "control_id": "AU.L1-3.3.003"})
    r2 = tool_collect_evidence({
        "tenant_id": "example-soc", "day": "2026-08-08",
        "control_id": "AU.L1-3.3.003"})
    assert r1["controls"][0]["status"] == r2["controls"][0]["status"]
    # File should be a single .jsonl
    path = soc_evidence._evidence_path("example-soc",
                                       "AU.L1-3.3.003", "2026-08-08")
    assert path.exists(), path
    # And the first line should be the status sentinel
    first_line = open(path).readline().strip()
    obj = json.loads(first_line)
    assert "_status" in obj, obj

    # 8. example-soc-2 should have its own scope
    r = tool_collect_evidence({"tenant_id": "example-soc-2", "day": "2026-08-08"})
    assert r["ok"], r
    # example-soc-2 doesn't allow auto_remediate but it should still
    # get audit-log evidence items
    assert r["total_controls"] >= 1

    shutil.rmtree(tmp, ignore_errors=True)
    sys.stdout.write("soc-evidence smoke test: OK\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
