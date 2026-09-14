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
import sys
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "scanner"))


def _today() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")


def main(argv: List[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="SOC nightly compliance refresh")
    ap.add_argument("--day", default=_today(), help="evidence day (UTC date)")
    ap.add_argument("--dry-run", action="store_true",
                    help="resolve tenants + list what would run; no writes")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args(argv)

    from soc_routing import get_config
    from soc_evidence import tool_collect_evidence
    from soc_score import tool_score_all_tenants

    tenants = list(get_config().known_tenants())
    out: Dict[str, Any] = {"day": args.day, "dry_run": args.dry_run,
                           "tenants": tenants, "collect": {}, "oscap": {}}

    # 1. audit/realtime/remediation evidence per tenant
    for t in tenants:
        if args.dry_run:
            out["collect"][t] = "would collect"
            continue
        try:
            r = tool_collect_evidence({"tenant_id": t, "day": args.day})
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