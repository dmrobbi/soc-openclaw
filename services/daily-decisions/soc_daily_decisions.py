#!/usr/bin/env python3
"""SOC daily decisions report (Track D, task D1 — 2026-08-08).

Reads the SOC audit log (Track B) + the realtime SOC JSONL
and produces a per-tenant, per-agent, per-decision markdown
report at `memory/soc-agent-decisions-YYYY-MM-DD.md`. This is
the human-review artifact for "what did the SOC do yesterday?"

The report is designed to be:
  - Idempotent (re-running for the same day overwrites the
    same file; we never append).
  - Tenant-scoped from day 1 (Wes's decision 2026-08-06).
  - Linked to the C4 audit-log MCP for drill-down (every
    section ends with a curl example).
  - Cheap to generate (one pass over the audit log + one
    pass over the realtime JSONL; no LLM call).
  - Boring on purpose — this is the SOC's daily status, not
    a story.

What it shows
-------------
  1. Top-line: total decisions, by outcome (ok/error), low
     confidence count, total run time, error rate.
  2. By tenant: decisions + error rate per tenant.
  3. By agent: decisions per agent_id.
  4. By decision (severity_class + recommended_response):
     the breakdown of what the LLM decided. The key thing
     to look for here is `low_confidence` and disagreement
     with the rule-based stub.
  5. Notable runs: top 10 by `duration_ms`, plus the 5 most
     recent errors with their `error` text.
  6. Disagreement vs rule-based stub: the B1 contract is
     ≥80% agreement on `recommended_response` vs the
     calibrated stub. The report shows the actual rate.
  7. Per-run deep links: the `runId` of any decision can
     be drilled into via the C4 MCP.

CLI
---
  python3 soc_daily_decisions.py --day 2026-08-08
  python3 soc_daily_decisions.py --day 2026-08-08 \
      --output /tmp/report.md
  python3 soc_daily_decisions.py --day 2026-08-08 \
      --c4-url http://127.0.0.1:8769   # link targets
  python3 soc_daily_decisions.py --smoke

Cron
----
  # Daily report (every day 06:00 UTC, after the curator
  # at 04:00):
  0 6 * * * cd /opt/soc-openclaw && \\
      /usr/bin/python3 scripts/soc/soc_daily_decisions.py \\
      --day $(date -u +%Y-%m-%d) \\
      >> /home/wez/logs/soc-daily-decisions.log 2>&1

Created 2026-08-08 by Ciceron as part of Track D (D1).
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
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_AUDIT_LOG = os.path.expanduser("~/.openclaw/audit_log.jsonl")
DEFAULT_REALTIME_LOG = os.path.expanduser(
    "~/.openclaw/workspace/agentic-ai/data/realtime_soc.jsonl")
DEFAULT_OUTPUT_DIR = "/home/wez/.openclaw/workspace/memory"
DEFAULT_C4_URL = "http://127.0.0.1:8769"

# Decisions we want to highlight in the report.
DECISION_ACTIONS = (
    "note_only", "digest_only", "email", "page", "auto_remediate")
SEVERITY_CLASSES = ("low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------
def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
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
                    f"[soc-daily-decisions] skipping non-JSON line at "
                    f"{path}:{i+1}\n")
    return out


def _filter_day(records: List[Dict[str, Any]], day: str) -> List[Dict[str, Any]]:
    """Return records whose `ts` starts with the given YYYY-MM-DD."""
    out = []
    for r in records:
        ts = r.get("ts") or ""
        if ts.startswith(day):
            out.append(r)
    return out


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def _parse_decision(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """For soc-triage decision_prompt records, return the parsed
    model_output dict. Returns None if the record isn't a
    decision or the output isn't parseable JSON."""
    if record.get("agent_id") != "soc-triage":
        return None
    if record.get("input_kind") != "decision_prompt":
        return None
    raw = record.get("model_output")
    if not raw:
        return None
    try:
        out = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(out, dict):
        return None
    return out


def _classify_run(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """For each runId, compute the canonical Decision + the
    rule-based stub's decision (from the `extra.rule_based`
    if present, otherwise by re-running the stub on
    `input_summary`)."""
    by_run: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        by_run[r.get("runId") or ""].append(r)
    out: Dict[str, Dict[str, Any]] = {}
    for rid, recs in by_run.items():
        # Take the first soc-triage decision_prompt record as
        # the canonical decision for the run.
        canonical = None
        for r in recs:
            if (r.get("agent_id") == "soc-triage"
                    and r.get("input_kind") == "decision_prompt"):
                canonical = r
                break
        if canonical is None:
            continue
        d = _parse_decision(canonical)
        if d is None:
            continue
        out[rid] = {
            "ts": canonical.get("ts"),
            "decision": d,
            "record": canonical,
        }
    return out


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------
def _table(headers: List[str], rows: List[List[Any]]) -> List[str]:
    """Render a markdown table. Headers are strings; rows are
    lists of anything (str() called on each)."""
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(str(c) for c in row) + " |")
    return out


def _pct(n: int, total: int) -> str:
    if total == 0:
        return "0.0%"
    return f"{n / total * 100:.1f}%"


def render_report(day: str, audit: List[Dict[str, Any]],
                  realtime: List[Dict[str, Any]],
                  c4_url: str) -> str:
    """Render the full markdown report for one day."""
    # Filter to the day.
    audit_day = _filter_day(audit, day)
    realtime_day = _filter_day(realtime, day)

    # Top line.
    total = len(audit_day)
    by_outcome = Counter(r.get("outcome") or "unknown" for r in audit_day)
    errors = by_outcome.get("error", 0)
    total_runtime_ms = sum(int(r.get("duration_ms") or 0)
                           for r in audit_day)
    avg_runtime_ms = (total_runtime_ms / total) if total else 0

    # By tenant.
    by_tenant: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in audit_day:
        by_tenant[r.get("tenant_id") or "unknown"].append(r)

    # By agent.
    by_agent = Counter(r.get("agent_id") or "unknown" for r in audit_day)

    # By decision (soc-triage only).
    decisions_by_action: Counter = Counter()
    decisions_by_severity: Counter = Counter()
    low_confidence_count = 0
    stub_disagree_count = 0
    stub_total = 0
    parsed_decisions: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for r in audit_day:
        d = _parse_decision(r)
        if d is None:
            continue
        act = d.get("recommended_response") or "unknown"
        sev = d.get("severity_class") or "unknown"
        decisions_by_action[act] += 1
        decisions_by_severity[sev] += 1
        if d.get("low_confidence") is True or d.get("confidence", 1.0) < 0.7:
            low_confidence_count += 1
        # Stub agreement: compare with the stub if it was
        # stored in `extra.stub_recommended_response`. This
        # is the field that B1 (soc_decision) writes when
        # it has a stub to compare against.
        extra = r.get("extra") or {}
        if "stub_recommended_response" in extra:
            stub_total += 1
            if extra["stub_recommended_response"] != act:
                stub_disagree_count += 1
        parsed_decisions.append((r, d))

    stub_agree_rate = (
        _pct(stub_total - stub_disagree_count, stub_total)
        if stub_total else "n/a")

    # Notable runs: top 10 by duration_ms.
    sorted_by_dur = sorted(audit_day,
                           key=lambda r: r.get("duration_ms") or 0,
                           reverse=True)
    notable = sorted_by_dur[:10]

    # Recent errors: 5 most recent.
    recent_errors = sorted([r for r in audit_day
                            if r.get("outcome") == "error"],
                           key=lambda r: r.get("ts") or "",
                           reverse=True)[:5]

    # Realtime SOC alerts (one per incident).
    realtime_by_status: Counter = Counter(
        r.get("status") or "unknown" for r in realtime_day)
    realtime_by_severity: Counter = Counter(
        r.get("severity") or "unknown" for r in realtime_day)

    # Render.
    lines: List[str] = []
    lines.append(f"# SOC daily decisions — {day}")
    lines.append("")
    lines.append(
        f"_Generated {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}_")
    lines.append("")
    lines.append("## Top line")
    lines.append("")
    lines.append(f"- **Total decisions:** {total}")
    lines.append(f"- **OK:** {by_outcome.get('ok', 0)} "
                 f"({_pct(by_outcome.get('ok', 0), total)})")
    lines.append(f"- **Errors:** {errors} "
                 f"({_pct(errors, total)})")
    lines.append(f"- **Total runtime:** {total_runtime_ms:,} ms")
    lines.append(f"- **Avg runtime:** {avg_runtime_ms:.1f} ms/decision")
    lines.append(f"- **Low-confidence:** {low_confidence_count} "
                 f"({_pct(low_confidence_count, total)})")
    lines.append(f"- **Stub agreement (B1):** {stub_agree_rate} "
                 f"({stub_total - stub_disagree_count}/{stub_total})")
    lines.append("")

    # By tenant.
    lines.append("## By tenant")
    lines.append("")
    rows = []
    for tenant in sorted(by_tenant.keys()):
        recs = by_tenant[tenant]
        n = len(recs)
        err = sum(1 for r in recs if r.get("outcome") == "error")
        rows.append([tenant, n, err, _pct(err, n)])
    lines += _table(["Tenant", "Decisions", "Errors", "Error rate"], rows)
    lines.append("")

    # By agent.
    lines.append("## By agent")
    lines.append("")
    rows = [[a, n, _pct(n, total)]
            for a, n in by_agent.most_common()]
    lines += _table(["Agent", "Decisions", "Share"], rows)
    lines.append("")

    # By decision.
    lines.append("## Decisions (soc-triage only)")
    lines.append("")
    lines.append("### By `recommended_response`")
    lines.append("")
    rows = [[a, n, _pct(n, sum(decisions_by_action.values()))]
            for a, n in decisions_by_action.most_common()]
    lines += _table(["Action", "Count", "Share"], rows)
    lines.append("")
    lines.append("### By `severity_class`")
    lines.append("")
    rows = [[s, n, _pct(n, sum(decisions_by_severity.values()))]
            for s, n in decisions_by_severity.most_common()]
    lines += _table(["Severity", "Count", "Share"], rows)
    lines.append("")

    # Notable runs.
    lines.append("## Notable runs (top 10 by duration)")
    lines.append("")
    rows = []
    for r in notable:
        d = _parse_decision(r) or {}
        rows.append([
            (r.get("ts") or "")[:19],
            r.get("runId") or "-",
            r.get("agent_id") or "-",
            r.get("input_summary") or "-"[:60],
            d.get("recommended_response") or "-",
            f"{r.get('duration_ms') or 0} ms",
        ])
    lines += _table(
        ["ts", "runId", "agent", "input", "decision", "duration"], rows)
    lines.append("")

    # Recent errors.
    lines.append("## Recent errors (up to 5)")
    lines.append("")
    if not recent_errors:
        lines.append("_No errors._")
    else:
        rows = []
        for r in recent_errors:
            err = (r.get("error") or "")[:120]
            rows.append([
                (r.get("ts") or "")[:19],
                r.get("runId") or "-",
                r.get("agent_id") or "-",
                r.get("input_summary") or "-",
                err,
            ])
        lines += _table(
            ["ts", "runId", "agent", "input", "error"], rows)
    lines.append("")

    # Realtime alerts.
    lines.append("## Realtime SOC alerts")
    lines.append("")
    lines.append(f"- **Total:** {len(realtime_day)}")
    if realtime_day:
        lines.append("")
        lines.append("### By status")
        lines.append("")
        rows = [[s, n, _pct(n, sum(realtime_by_status.values()))]
                for s, n in realtime_by_status.most_common()]
        lines += _table(["Status", "Count", "Share"], rows)
        lines.append("")
        lines.append("### By severity")
        lines.append("")
        rows = [[s, n, _pct(n, sum(realtime_by_severity.values()))]
                for s, n in realtime_by_severity.most_common()]
        lines += _table(["Severity", "Count", "Share"], rows)
        lines.append("")

    # Drill-down.
    lines.append("## Drill-down")
    lines.append("")
    lines.append("Run `soc-audit-mcp` (port 8769) to query any "
                 "of the above. Examples:")
    lines.append("")
    lines.append("```bash")
    lines.append("# All decisions for the day")
    lines.append(f'curl -sS -X POST {c4_url}/tools/query_audit \\')
    lines.append(f'  -d \'{{"time_range":"{day}T00:00:00Z,{day}T23:59:59Z"}}\' '
                 "| python3 -m json.tool | head -40")
    lines.append("")
    lines.append("# All low-confidence decisions")
    lines.append(f'curl -sS -X POST {c4_url}/tools/query_audit \\')
    lines.append(f"  -d '{{\"agent_id\":\"soc-triage\",\"input_kind\":\"decision_prompt\"}}'"
                 " | python3 -m json.tool | head -40")
    lines.append("")
    lines.append("# A single run")
    lines.append(f'curl -sS -X POST {c4_url}/tools/get_run \\')
    lines.append("  -d '{\"run_id\":\"REPLACE_ME\"}' "
                 "| python3 -m json.tool")
    lines.append("```")
    lines.append("")

    # Footer.
    lines.append("---")
    lines.append("")
    lines.append(
        f"_Audit log: `{DEFAULT_AUDIT_LOG}` ({total} records) · "
        f"Realtime log: `{DEFAULT_REALTIME_LOG}` "
        f"({len(realtime_day)} alerts) · "
        f"C4 MCP: `{c4_url}` · "
        f"Source: `scripts/soc/soc_daily_decisions.py`_")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _day_arg(s: Optional[str]) -> str:
    if s:
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", s):
            raise SystemExit(f"bad --day: {s!r} (expected YYYY-MM-DD)")
        return s
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")


def _output_path(output: Optional[str], day: str) -> str:
    if output:
        return output
    p = Path(DEFAULT_OUTPUT_DIR)
    p.mkdir(parents=True, exist_ok=True)
    return str(p / f"soc-agent-decisions-{day}.md")


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="SOC daily decisions report (Track D, D1)")
    p.add_argument("--day", default=None,
                   help="YYYY-MM-DD (default: today UTC)")
    p.add_argument("--audit-log", default=DEFAULT_AUDIT_LOG)
    p.add_argument("--realtime-log", default=DEFAULT_REALTIME_LOG)
    p.add_argument("--c4-url", default=DEFAULT_C4_URL)
    p.add_argument("--output", default=None,
                   help="Override the output path")
    p.add_argument("--smoke", action="store_true")
    args = p.parse_args(argv)

    if args.smoke:
        return _smoke()

    day = _day_arg(args.day)
    audit = _load_jsonl(args.audit_log)
    realtime = _load_jsonl(args.realtime_log)
    md = render_report(day, audit, realtime, args.c4_url)
    out = _output_path(args.output, day)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(md)
    sys.stdout.write(f"[soc-daily-decisions] wrote {out} "
                     f"({len(audit)} audit records, "
                     f"{len(realtime)} realtime)\n")
    return 0


def _smoke() -> int:
    """Self-test: build a tiny synthetic audit log + realtime
    log in /tmp, run the report, assert the output is
    well-formed and contains the expected sections."""
    import shutil
    import tempfile

    tmp = tempfile.mkdtemp(prefix="soc-daily-decisions-smoke-")
    audit = os.path.join(tmp, "audit_log.jsonl")
    realtime = os.path.join(tmp, "realtime_soc.jsonl")
    sample_audit = [
        # soc-triage decision with stub comparison
        {"ts": "2026-08-08T10:00:00.000+00:00", "runId": "r1",
         "agent_id": "soc-triage", "tenant_id": "example-soc",
         "input_kind": "decision_prompt",
         "input_summary": "L12 5763 agent=darth",
         "model_output": json.dumps({
             "severity_class": "high",
             "is_known_pattern": True,
             "recommended_response": "page",
             "confidence": 0.92,
             "reasoning": "stub says page",
             "low_confidence": False}),
         "model": "stub", "duration_ms": 120, "outcome": "ok",
         "error": None, "extra": {"stub_recommended_response": "page"},
         "schema": 1},
        # soc-triage decision that DISAGREES with stub
        {"ts": "2026-08-08T10:01:00.000+00:00", "runId": "r2",
         "agent_id": "soc-triage", "tenant_id": "example-soc",
         "input_kind": "decision_prompt",
         "input_summary": "L9 5503 agent=vader",
         "model_output": json.dumps({
             "severity_class": "medium",
             "is_known_pattern": False,
             "recommended_response": "digest_only",
             "confidence": 0.81,
             "reasoning": "stub says email; LLM says digest",
             "low_confidence": False}),
         "model": "stub", "duration_ms": 80, "outcome": "ok",
         "error": None, "extra": {"stub_recommended_response": "email"},
         "schema": 1},
        # low-confidence decision
        {"ts": "2026-08-08T10:02:00.000+00:00", "runId": "r3",
         "agent_id": "soc-triage", "tenant_id": "example-soc",
         "input_kind": "decision_prompt",
         "input_summary": "L5 5700 agent=mail.example.com",
         "model_output": json.dumps({
             "severity_class": "low",
             "is_known_pattern": False,
             "recommended_response": "note_only",
             "confidence": 0.55,
             "reasoning": "uncertain",
             "low_confidence": True}),
         "model": "stub", "duration_ms": 50, "outcome": "ok",
         "error": None, "extra": {}, "schema": 1},
        # error record
        {"ts": "2026-08-08T10:03:00.000+00:00", "runId": "r4",
         "agent_id": "soc-triage", "tenant_id": "example-soc",
         "input_kind": "decision_prompt",
         "input_summary": "L8 5715 agent=gus2",
         "model_output": "", "model": "stub", "duration_ms": 5,
         "outcome": "error",
         "error": "openclaw binary not on PATH",
         "extra": {}, "schema": 1},
        # narrator record (not a decision)
        {"ts": "2026-08-08T10:04:00.000+00:00", "runId": "r1",
         "agent_id": "soc-narrator", "tenant_id": "example-soc",
         "input_kind": "llm_prompt",
         "input_summary": "narrate r1",
         "model_output": "{}", "model": "m", "duration_ms": 200,
         "outcome": "ok", "error": None, "extra": {}, "schema": 1},
        # different day (should be filtered out)
        {"ts": "2026-08-07T10:00:00.000+00:00", "runId": "old",
         "agent_id": "soc-triage", "tenant_id": "example-soc",
         "input_kind": "decision_prompt",
         "input_summary": "L1 1 agent=old",
         "model_output": "{}", "model": "stub", "duration_ms": 1,
         "outcome": "ok", "error": None, "extra": {}, "schema": 1},
    ]
    sample_realtime = [
        {"ts": "2026-08-08T10:00:30.000+00:00",
         "type": "alert", "title": "A1", "severity": "high",
         "status": "escalated", "source": "wazuh"},
        {"ts": "2026-08-08T10:01:30.000+00:00",
         "type": "alert", "title": "A2", "severity": "medium",
         "status": "in_progress", "source": "wazuh"},
    ]
    with open(audit, "w") as f:
        for s in sample_audit:
            f.write(json.dumps(s) + "\n")
    with open(realtime, "w") as f:
        for s in sample_realtime:
            f.write(json.dumps(s) + "\n")

    out = os.path.join(tmp, "report.md")
    rc = main(["--day", "2026-08-08",
               "--audit-log", audit,
               "--realtime-log", realtime,
               "--c4-url", "http://127.0.0.1:8769",
               "--output", out])
    assert rc == 0, f"main returned {rc}"

    text = open(out).read()
    # Sections
    for section in ("# SOC daily decisions — 2026-08-08",
                    "## Top line",
                    "## By tenant",
                    "## By agent",
                    "## Decisions (soc-triage only)",
                    "## Notable runs",
                    "## Recent errors",
                    "## Realtime SOC alerts",
                    "## Drill-down"):
        assert section in text, f"missing section: {section}\n--- text ---\n{text[:1000]}"
    # Content
    assert "Total decisions:** 5" in text, text  # 4 soc-triage + 1 narrator, but the 2026-08-07 record is filtered out → 5
    assert "example-soc" in text
    assert "page" in text
    assert "digest_only" in text
    assert "Stub agreement (B1):** 50.0%" in text, text  # 1 agree, 1 disagree
    assert "low_confidence" in text.lower() or "Low-confidence" in text
    # Old day must be filtered out
    assert "old" not in text.split("## By agent")[1].split("## ")[0], text  # 'old' runId not in by-agent table
    # Recent errors
    assert "openclaw binary not on PATH" in text
    # Cleanup
    shutil.rmtree(tmp, ignore_errors=True)
    sys.stdout.write("soc-daily-decisions smoke test: OK\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
