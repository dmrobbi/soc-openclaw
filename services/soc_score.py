#!/usr/bin/env python3
"""SOC continuous compliance scoring (Track E, task E6 — 2026-08-08).

Aggregates E3 evidence across controls to produce per-tenant
compliance scores. A score is:

    pass_count / applicable_count * 100

where `applicable` is the set of controls that the tenant's
D3 routing config + E1 catalogue agree on. A control with
status `not_applicable` is excluded from the denominator.

Tools
-----
  * compute_score(tenant_id, day=None)
        -> {ok, tenant_id, day, total, pass, fail,
            manual_review, not_applicable, score,
            by_family: {family: {pass, fail, ...}},
            by_baseline: {baseline: {pass, fail, ...}},
            controls: [{control_id, status, ...}]}
  * score_history(tenant_id, days=7)
        -> {ok, tenant_id, scores: [{day, score, pass, ...}]}
        Walks the E3 evidence dirs for the last N days and
        computes a score per day.
  * score_trend(tenant_id, since_day=None, until_day=None)
        -> like score_history but with explicit date range
  * score_all_tenants(day=None)
        -> {ok, day, scores: [{tenant_id, score, ...}]}
  * dashboard_score(tenant_id)
        -> the data shape consumed by the D2 dashboard
           (similar to compute_score, but with extra
           fields for the dashboard's visual elements)

The scoring model
-----------------
- A control is `applicable` if it passes the D3 filter
  (baselines + applicability_tags).
- A control's status comes from E3 evidence for the day.
- A control with no E3 evidence is `manual_review`
  (honest "we don't know").
- `not_applicable` controls are excluded from the score
  denominator AND numerator.

Score = 100 * pass / (pass + fail + manual_review)

Trend: a 7-day rolling score. Each day's score is
independent (a control that's `pass` today but `fail`
tomorrow is counted in each day's pass/fail count
separately). The trend is a list of {day, score, ...}
dicts, oldest first.

Created 2026-08-08 by Ciceron as part of Track E (E6).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_BASE = Path(os.environ.get(
    "SOC_EVIDENCE_DIR",
    str(Path.home() / ".openclaw" / "compliance" / "evidence")))
SCORE_DIR = Path(os.environ.get(
    "SOC_SCORE_DIR",
    str(Path.home() / ".openclaw" / "compliance" / "scores")))


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class ScoreError(Exception):
    pass


# ---------------------------------------------------------------------------
# Evidence + catalogue reading
# ---------------------------------------------------------------------------
def _read_evidence_status(tenant_id: str, control_id: str,
                          day: str) -> Tuple[str, List[Dict[str, Any]]]:
    safe_cid = re.sub(r"[^A-Za-z0-9._-]", "_", control_id)
    safe_tid = re.sub(r"[^A-Za-z0-9._-]", "_", tenant_id)
    p = EVIDENCE_BASE / safe_tid / safe_cid / f"{day}.jsonl"
    if not p.exists():
        return "manual_review", []
    status = "manual_review"
    items: List[Dict[str, Any]] = []
    with open(p, "r", encoding="utf-8") as f:
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


def _applicable_controls(tenant_id: str) -> List[Dict[str, Any]]:
    try:
        from soc_stig import tool_applicable_for_tenant, get_catalogue
    except ImportError as e:
        raise ScoreError(f"soc_stig not importable: {e!r}")
    r = tool_applicable_for_tenant({"tenant_id": tenant_id})
    applicable_ids = {c["id"] for c in r["controls"]}
    cat = get_catalogue()
    return [c for c in cat["controls"] if c.get("id") in applicable_ids]


def _compute(controls: List[Dict[str, Any]],
             statuses: Dict[str, str]) -> Dict[str, Any]:
    """Compute the score for a tenant's applicable controls.
    `statuses` maps control_id -> E3 status (or
    'manual_review' for missing evidence)."""
    by_family: Dict[str, Counter] = defaultdict(Counter)
    by_baseline: Dict[str, Counter] = defaultdict(Counter)
    by_severity: Dict[str, Counter] = defaultdict(Counter)
    counts: Counter = Counter()
    for c in controls:
        cid = c["id"]
        st = statuses.get(cid, "manual_review")
        if st == "not_applicable":
            continue  # excluded from score
        counts[st] += 1
        by_family[c.get("family") or "?"][st] += 1
        for b in c.get("baselines", []):
            by_baseline[b][st] += 1
        by_severity[c.get("severity") or "?"][st] += 1
    total = counts["pass"] + counts["fail"] + counts["manual_review"]
    score = (counts["pass"] / total * 100) if total else 0.0
    return {
        "total": total,
        "pass": counts["pass"],
        "fail": counts["fail"],
        "manual_review": counts["manual_review"],
        "not_applicable": counts.get("not_applicable", 0),
        "score": round(score, 1),
        "by_family": {k: dict(v) for k, v in by_family.items()},
        "by_baseline": {k: dict(v) for k, v in by_baseline.items()},
        "by_severity": {k: dict(v) for k, v in by_severity.items()},
    }


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------
def tool_compute_score(args: Dict[str, Any]) -> Dict[str, Any]:
    """compute_score(tenant_id, day=None)."""
    tid = args.get("tenant_id")
    if not tid:
        raise ValueError("tenant_id is required")
    day = args.get("day") or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    controls = _applicable_controls(tid)
    statuses = {c["id"]: _read_evidence_status(tid, c["id"], day)[0]
                for c in controls}
    score = _compute(controls, statuses)
    return {
        "ok": True, "tool": "compute_score",
        "tenant_id": tid, "day": day,
        **score,
    }


def tool_score_history(args: Dict[str, Any]) -> Dict[str, Any]:
    """score_history(tenant_id, days=7)."""
    tid = args.get("tenant_id")
    if not tid:
        raise ValueError("tenant_id is required")
    n = int(args.get("days") or 7)
    today = dt.datetime.now(dt.timezone.utc).date()
    days = [(today - dt.timedelta(days=i)).strftime("%Y-%m-%d")
            for i in range(n - 1, -1, -1)]
    return tool_score_trend({"tenant_id": tid, "since_day": days[0],
                              "until_day": days[-1]})


def tool_score_trend(args: Dict[str, Any]) -> Dict[str, Any]:
    """score_trend(tenant_id, since_day=None, until_day=None)."""
    tid = args.get("tenant_id")
    if not tid:
        raise ValueError("tenant_id is required")
    today = dt.datetime.now(dt.timezone.utc).date()
    since = args.get("since_day") or (today - dt.timedelta(days=7)).strftime("%Y-%m-%d")
    until = args.get("until_day") or today.strftime("%Y-%m-%d")
    # Iterate days
    sd = dt.date.fromisoformat(since)
    ud = dt.date.fromisoformat(until)
    days = []
    d = sd
    while d <= ud:
        days.append(d.isoformat())
        d += dt.timedelta(days=1)
    controls = _applicable_controls(tid)
    out = []
    for day in days:
        statuses = {c["id"]: _read_evidence_status(tid, c["id"], day)[0]
                    for c in controls}
        s = _compute(controls, statuses)
        out.append({"day": day, **s})
    return {
        "ok": True, "tool": "score_trend",
        "tenant_id": tid, "since_day": since, "until_day": until,
        "scores": out,
    }


def tool_score_all_tenants(args: Dict[str, Any]) -> Dict[str, Any]:
    """score_all_tenants(day=None) — fleet-wide scores."""
    day = args.get("day") or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    try:
        from soc_routing import get_config
    except ImportError as e:
        raise ScoreError(f"soc_routing not importable: {e!r}")
    cfg = get_config()
    out = []
    for tid in cfg.known_tenants():
        s = tool_compute_score({"tenant_id": tid, "day": day})
        out.append({
            "tenant_id": tid,
            "score": s["score"],
            "pass": s["pass"],
            "fail": s["fail"],
            "manual_review": s["manual_review"],
            "total": s["total"],
        })
    out.sort(key=lambda x: -x["score"])
    fleet_pass = sum(x["pass"] for x in out)
    fleet_total = sum(x["total"] for x in out)
    fleet_score = (fleet_pass / fleet_total * 100) if fleet_total else 0.0
    return {
        "ok": True, "tool": "score_all_tenants",
        "day": day,
        "fleet_score": round(fleet_score, 1),
        "fleet_total": fleet_total,
        "fleet_pass": fleet_pass,
        "tenants": out,
    }


def tool_dashboard_score(args: Dict[str, Any]) -> Dict[str, Any]:
    """dashboard_score(tenant_id) — the data shape consumed
    by the D2 dashboard. Similar to compute_score but
    includes a few extra fields the dashboard uses."""
    tid = args.get("tenant_id")
    if not tid:
        raise ValueError("tenant_id is required")
    base = tool_compute_score({"tenant_id": tid})
    # Trend: last 7 days
    hist = tool_score_history({"tenant_id": tid, "days": 7})
    return {
        "ok": True, "tool": "dashboard_score",
        "tenant_id": tid,
        "current": {
            "day": base["day"],
            "score": base["score"],
            "pass": base["pass"],
            "fail": base["fail"],
            "manual_review": base["manual_review"],
            "total": base["total"],
        },
        "trend": hist["scores"],
        "by_family": base["by_family"],
        "by_baseline": base["by_baseline"],
        "by_severity": base["by_severity"],
    }


# ---------------------------------------------------------------------------
# CLI / smoke
# ---------------------------------------------------------------------------
TOOLS = {
    "compute_score": tool_compute_score,
    "score_history": tool_score_history,
    "score_trend": tool_score_trend,
    "score_all_tenants": tool_score_all_tenants,
    "dashboard_score": tool_dashboard_score,
}


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="SOC continuous compliance scoring (Track E, E6)")
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
    """Hermetic self-test: redirects EVIDENCE_BASE to a temp
    dir, seeds evidence for one tenant across 3 days, runs
    all 5 tools, validates score math."""
    import shutil
    import tempfile

    tmp = tempfile.mkdtemp(prefix="soc-score-smoke-")
    ev = os.path.join(tmp, "evidence")
    os.makedirs(ev)
    os.environ["SOC_EVIDENCE_DIR"] = ev

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import soc_score  # noqa
    for name, value in [("EVIDENCE_BASE", Path(ev))]:
        setattr(soc_score, name, value)
        globals()[name] = value

    safe_tid = "bedimsecurity"
    # Seed evidence for 3 controls across 3 days.
    # AU.L1-3.3.003: pass on all 3 days
    # AU.L1-3.3.001: fail on day 1, fail on day 2, pass on day 3
    # AC.L1-3.1.001: manual_review on all 3 days
    days = ["2026-08-06", "2026-08-07", "2026-08-08"]
    seed = {
        "AU.L1-3.3.003": {d: "pass" for d in days},
        "AU.L1-3.3.001": {"2026-08-06": "fail",
                          "2026-08-07": "fail",
                          "2026-08-08": "pass"},
        "AC.L1-3.1.001": {d: "manual_review" for d in days},
    }
    for cid, by_day in seed.items():
        safe_cid = re.sub(r"[^A-Za-z0-9._-]", "_", cid)
        d_dir = Path(ev) / safe_tid / safe_cid
        d_dir.mkdir(parents=True, exist_ok=True)
        for day, status in by_day.items():
            with open(d_dir / f"{day}.jsonl", "w") as f:
                f.write(json.dumps({"_status": status, "_count": 0,
                                     "_written_at": "now"}) + "\n")

    # 1. compute_score for 2026-08-08
    r = tool_compute_score({"tenant_id": safe_tid, "day": "2026-08-08"})
    assert r["ok"], r
    # 24 applicable controls, 2 pass (AU.L1-3.3.001 + 003), 22 manual_review
    assert r["total"] == 24, r
    assert r["pass"] == 2, r
    assert r["fail"] == 0, r
    assert r["manual_review"] == 22, r
    # score = 2 / 24 * 100 = 8.33%
    assert abs(r["score"] - 8.33) < 0.1, r["score"]
    # by_family has the families
    assert "AC" in r["by_family"]
    assert "AU" in r["by_family"]
    # by_baseline has the baselines
    assert "high" in r["by_baseline"]
    assert "moderate" in r["by_baseline"]
    assert "low" in r["by_baseline"]

    # 2. compute_score for 2026-08-06 (where AU.L1-3.3.001 was fail)
    r = tool_compute_score({"tenant_id": safe_tid, "day": "2026-08-06"})
    assert r["pass"] == 1, r  # only AU.L1-3.3.003
    assert r["fail"] == 1, r  # AU.L1-3.3.001
    assert r["manual_review"] == 22
    # 1 / 24 = 4.17%
    assert abs(r["score"] - 4.17) < 0.1, r["score"]

    # 3. score_trend over 3 days
    r = tool_score_trend({"tenant_id": safe_tid,
                           "since_day": "2026-08-06",
                           "until_day": "2026-08-08"})
    assert r["ok"], r
    assert len(r["scores"]) == 3
    # Day 0 (08-06): 1 pass / 1 fail / 22 manual_review = 1/24 = 4.17%
    # Day 1 (08-07): same (we seeded 2026-08-07 with the same data)
    # Day 2 (08-08): 2 pass = 8.33%
    assert r["scores"][0]["day"] == "2026-08-06"
    assert r["scores"][0]["pass"] == 1
    assert r["scores"][2]["day"] == "2026-08-08"
    assert r["scores"][2]["pass"] == 2

    # 4. score_history (last 7 days)
    r = tool_score_history({"tenant_id": safe_tid, "days": 7})
    assert r["ok"], r
    assert len(r["scores"]) == 7, r["scores"]

    # 5. score_all_tenants
    r = tool_score_all_tenants({"day": "2026-08-08"})
    assert r["ok"], r
    assert "bedimsecurity" in [t["tenant_id"] for t in r["tenants"]]
    assert "stsgym" in [t["tenant_id"] for t in r["tenants"]]
    assert r["fleet_total"] > 0

    # 6. dashboard_score
    r = tool_dashboard_score({"tenant_id": safe_tid})
    assert r["ok"], r
    assert "current" in r
    assert "trend" in r
    assert len(r["trend"]) == 7
    assert "by_family" in r
    assert "by_baseline" in r

    # 7. Empty: tenant with no evidence
    r = tool_compute_score({"tenant_id": safe_tid, "day": "1999-01-01"})
    assert r["pass"] == 0
    assert r["fail"] == 0
    assert r["manual_review"] == 24
    assert r["score"] == 0.0

    shutil.rmtree(tmp, ignore_errors=True)
    sys.stdout.write("soc-score smoke test: OK\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
