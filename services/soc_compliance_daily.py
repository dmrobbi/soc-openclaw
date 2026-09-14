#!/usr/bin/env python3
"""soc_compliance_daily.py — nightly compliance refresh.

Designed for soc-compliance-daily.timer (06:30 UTC daily, after the
06:00 daily-decisions report). Idempotent: safe to re-run, and it only
reads audit/realtime/remediation logs + archived scan results — it never
touches Wazuh (no agent restarts).

Steps:
  1. Collect evidence for every known tenant from the audit /
     realtime / remediation logs (soc_evidence.tool_collect_evidence).
  2. If OpenSCAP results exist for the day under
     ~/.openclaw/soc/scans/<day>/, merge them (worst result across
     hosts) and write ONE evidence pass per tenant (soc_scanner
     .merge_results). Scan evidence supersedes alert-derived evidence
     for the controls it covers — the scan is the measured state.
  3. Recompute scores for all tenants (soc_score.tool_score_all_tenants)
     so the dashboard trend stays real without manual runs.

Env expected (set by the systemd unit — the module defaults differ):
  SOC_ROUTING_CONFIG  live tenant config (~/.openclaw/soc/soc-routing.yaml)
  SOC_EVIDENCE_DIR    compliance evidence store (~/.openclaw/soc/compliance/evidence)
  SOC_AUDIT_LOG       canonical audit log (~/.openclaw-wazuh/audit_log.jsonl)

Usage:
  python3 soc_compliance_daily.py [--day 2026-09-13] [--dry-run] [--json]
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "scanner"))


def _today() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")


def _smoke() -> int:
    """Hermetic self-test: isolated config + temp state dirs, full
    orchestration in dry-run mode (no writes)."""
    import shutil
    import tempfile

    tmp = tempfile.mkdtemp(prefix="soc-compliance-daily-smoke-")
    os.environ["SOC_ROUTING_CONFIG"] = str(
        HERE.parent / "config" / "soc-routing.yaml.example")
    os.environ["SOC_EVIDENCE_DIR"] = os.path.join(tmp, "evidence")
    os.environ["SOC_SNAPSHOT_DIR"] = os.path.join(tmp, "snapshots")
    os.environ["SOC_REMEDIATION_LOG"] = os.path.join(tmp, "remediations.jsonl")
    os.environ["SOC_AUDIT_LOG"] = os.path.join(tmp, "audit.jsonl")
    try:
        rc = main(["--dry-run", "--json"])
        assert rc == 0, rc
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    sys.stdout.write("soc-compliance-daily smoke test: OK\n")
    return 0


# ---------------------------------------------------------------------------
# auto-remediation pass (Phase 1.3, 2026-09-14)
# ---------------------------------------------------------------------------
def _remediate_control_via_sudo(control_id: str, tenant_id: str) -> Dict[str, Any]:
    """Run one E2 remediation as ROOT (fixes need root), with the same
    state envs as this process. Artifacts the root run creates are
    re-owned to 999:999 immediately (the container state contract —
    healthcheck asserts no root-owned files)."""
    args_json = json.dumps({"control_id": control_id, "tenant_id": tenant_id,
                            "confidence": 0.95, "timeout": 300})
    envs = [f"SOC_ROUTING_CONFIG={os.environ.get('SOC_ROUTING_CONFIG', '')}",
            f"SOC_SNAPSHOT_DIR={os.environ.get('SOC_SNAPSHOT_DIR', str(Path.home() / '.openclaw' / 'compliance' / 'snapshots'))}",
            f"SOC_REMEDIATION_LOG={os.environ.get('SOC_REMEDIATION_LOG', str(Path.home() / '.openclaw' / 'compliance' / 'remediations.jsonl'))}",
            f"SOC_AUDIT_LOG={os.environ.get('SOC_AUDIT_LOG', str(Path.home() / '.openclaw-wazuh' / 'audit_log.jsonl'))}"]
    cmd = ["sudo", "-n", "env"] + envs + [
        "/usr/bin/python3", str(HERE / "soc_stig_remediate.py"),
        "--tool", "remediate_control", "--args", args_json]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=420)
    except subprocess.TimeoutExpired as e:
        return {"ok": False, "status": "timeout", "error": repr(e)}
    except Exception as e:
        return {"ok": False, "status": "error", "error": repr(e)}
    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {"ok": False, "status": "unparseable",
                "stdout": (proc.stdout or "")[:400],
                "stderr": (proc.stderr or "")[:400]}


def _auto_remediate_pass(tenants: List[str], day: str,
                         collect_results: Dict[str, Any],
                         dry_run: bool) -> Dict[str, Any]:
    """Apply safe shell fixes for controls that are not pass today.

    Layered gates (all must pass):
      1. operator opt-in: SOC_AUTO_REMEDIATE=1 or --remediate
      2. only controls with automated=true + a pure-shell fix (the
         2026-09-14 catalogue cleanup guarantees shell fixes are safe
         and idempotent)
      3. the tenant routing gate (can_auto_remediate: allowed_actions,
         threshold, severity eligibility) — enforced inside
         soc_stig_remediate.remedieate_control
      4. not already pass in today's evidence
    """
    from soc_stig import get_catalogue
    from soc_stig_remediate import looks_like_command
    out: Dict[str, Any] = {}
    catalogue = {c["id"]: c for c in get_catalogue()["controls"]}
    for t in tenants:
        res = collect_results.get(t)
        if not isinstance(res, dict) or not res.get("ok"):
            continue
        candidates = []
        for c in res.get("controls", []):
            cid = c.get("control_id")
            if c.get("status") == "pass" or not cid:
                continue
            cat = catalogue.get(cid)
            if not cat or not cat.get("automated"):
                continue
            if not looks_like_command((cat.get("fix") or "").strip()):
                continue
            candidates.append(cid)
        if not candidates:
            continue
        entry: Dict[str, Any] = {"candidates": candidates}
        if dry_run:
            entry["note"] = "would remediate via sudo (tenant gate checked at apply time)"
            out[t] = entry
            continue
        entry["results"] = {}
        for cid in candidates:
            r = _remediate_control_via_sudo(cid, t)
            entry["results"][cid] = {"status": r.get("status"),
                                     "reason": r.get("reason")}
        out[t] = entry
    return out


def main(argv: List[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="SOC nightly compliance refresh")
    ap.add_argument("--day", default=_today(), help="evidence day (UTC date)")
    ap.add_argument("--dry-run", action="store_true",
                    help="resolve tenants + list what would run; no writes")
    ap.add_argument("--remediate", action="store_true",
                    help="auto-remediation pass: for controls that are not "
                         "pass today and have a safe shell fix, apply it "
                         "(tenant-gated; requires SOC_AUTO_REMEDIATE=1 or "
                         "this flag). Fixes needing root run via "
                         "sudo -n env (wez must have NOPASSWD sudo)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args(argv)

    if args.smoke:
        return _smoke()

    from soc_routing import get_config
    from soc_evidence import tool_collect_evidence
    from soc_score import tool_score_all_tenants

    tenants = list(get_config().known_tenants())
    out: Dict[str, Any] = {"day": args.day, "dry_run": args.dry_run,
                           "tenants": tenants, "collect": {}, "oscap": {}}
    raw_collect: Dict[str, Any] = {}

    # 1. audit/realtime/remediation evidence per tenant
    for t in tenants:
        if args.dry_run:
            out["collect"][t] = "would collect"
            continue
        try:
            r = tool_collect_evidence({"tenant_id": t, "day": args.day})
            raw_collect[t] = r
            out["collect"][t] = {"ok": bool(r.get("ok")),
                                 "total_controls": r.get("total_controls"),
                                 "counts": r.get("counts")}
        except Exception as exc:
            out["collect"][t] = {"error": repr(exc)}

    # 2. OpenSCAP results for the day, if any were archived
    from soc_scanner import _specs_from_day, collect_day
    specs = _specs_from_day(args.day)
    if specs:
        default_tenant = tenants[0] if tenants else None
        by_tenant: Dict[str, List[Dict[str, str]]] = {}
        for s in specs:
            t = s.get("tenant") or default_tenant
            if not t:
                continue
            by_tenant.setdefault(t, []).append(s)
        if args.dry_run:
            out["oscap"] = {"hosts": sorted(s["host"] for s in specs),
                            "tenants": sorted(by_tenant),
                            "note": "would merge+write per tenant"}
        else:
            out["oscap"] = {}
            for t, tspecs in sorted(by_tenant.items()):
                try:
                    out["oscap"][t] = collect_day(
                        args.day, tenant_id=t, dry_run=False)
                except Exception as exc:
                    out["oscap"][t] = {"error": repr(exc)}
    else:
        out["oscap"] = {"hosts": [], "note": "no scans archived for the day"}

    # 2b. auto-remediation pass (opt-in: SOC_AUTO_REMEDIATE=1 or --remediate)
    enabled = args.remediate or \
        os.environ.get("SOC_AUTO_REMEDIATE", "0") == "1"
    out["remediate"] = {"enabled": enabled}
    applied_any = False
    if enabled:
        out["remediate"].update(_auto_remediate_pass(
            tenants, args.day, raw_collect, args.dry_run))
        if not args.dry_run:
            for v in out["remediate"].values():
                if isinstance(v, dict) and any(
                        (r or {}).get("status") == "applied"
                        for r in v.get("results", {}).values()):
                    applied_any = True
        if applied_any:
            # re-collect so the new remediation evidence is graded
            out["recollect"] = {}
            for t in tenants:
                try:
                    r = tool_collect_evidence({"tenant_id": t, "day": args.day})
                    out["recollect"][t] = {"ok": bool(r.get("ok")),
                                           "counts": r.get("counts")}
                except Exception as exc:
                    out["recollect"][t] = {"error": repr(exc)}

    # 3. scores for all tenants
    if args.dry_run:
        out["scores"] = "would recompute all tenant scores"
    else:
        try:
            r = tool_score_all_tenants({"day": args.day})
            out["scores"] = {t["tenant_id"]: {"score": t.get("score"),
                                              "pass": t.get("pass"),
                                              "fail": t.get("fail"),
                                              "manual_review":
                                                  t.get("manual_review")}
                             for t in r.get("tenants", [])}
        except Exception as exc:
            out["scores"] = {"error": repr(exc)}

    errors = sum(1 for v in out["collect"].values()
                 if isinstance(v, dict) and "error" in v)
    failed = bool(errors) or (
        isinstance(out.get("scores"), dict) and "error" in out["scores"])
    out["ok"] = not failed
    print(json.dumps(out, indent=1, default=str))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())