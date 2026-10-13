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
# 2026-09-14: env-overridable, same contract as soc_evidence.py — the
# systemd unit pins the CANONICAL fleet audit log
# (~/.openclaw-wazuh/audit_log.jsonl); the legacy host-side default
# below only had ~5 rows, which is why the daily reports were nearly
# empty ("Total decisions: 1"). Realtime default moved from the stale
# workspace/agentic-ai path (0-byte) to the live ingest path.
DEFAULT_AUDIT_LOG = os.environ.get(
    "SOC_AUDIT_LOG", "") or os.path.expanduser("~/.openclaw/audit_log.jsonl")
DEFAULT_REALTIME_LOG = os.environ.get(
    "SOC_REALTIME_LOG", "") or os.path.expanduser(
    "~/.openclaw/soc/data/realtime_soc.jsonl")
DEFAULT_OUTPUT_DIR = "/home/wez/.openclaw/workspace/memory"
DEFAULT_C4_URL = "http://127.0.0.1:8769"
SCAN_RESULTS_DIR_DEFAULT = os.environ.get(
    "SOC_SCAN_RESULTS_DIR",
    os.environ.get("SOC_SCANS_DIR",
                   os.path.expanduser("~/.openclaw/soc/scans")))

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

    # Detection report (v3 contract) - deterministic section built from
    # the day's realtime rows; the module block above carries the rules.
    lines += render_detection_report(day, realtime_day, realtime)
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
# Detection report (v3 contract - wired 2026-10-12, owner-approved)
#
# Source contract: agentic-ai docs/PROMPT_EXERCISE_DETECTION_REPORTS.md
# (the tuned v3 prompt). The daily SOC report gains a deterministic
# detection-report section built from the day's realtime-soc rows:
#
#   - Executive summary: 3 bullets maximum (derived; an empty day says so)
#   - Detection inventory: one row per detection group
#   - Top sources: the 3 loudest entries
#   - Affected accounts and services
#   - Recommended actions: ticket + blocking candidates only
#
# Rules enforced by construction: every group row cites its source
# (realtime-soc/<rule family>), unknown values render as "unknown"
# instead of guesses, no IP/count/timestamp is ever invented, no
# exploit/countermeasure detail, and an unreachable/quiet source is said
# in the summary rather than guessed around. No extra LLM turn; the
# section is idempotent like the rest of the report.

_GROUP_TO_SERVICE = {
    "sshd": "ssh",
    "authentication_failures": "ssh",
    "authentication_failed": "ssh",
    "firewall": "edge/ufw",
    "ufw": "edge/ufw",
    "web": "http",
    "apache": "http",
}


def _rule_fields(r: Dict[str, Any]) -> Tuple[str, List[str]]:
    """(description, groups) for one realtime row. The embedded
    full_alert.rule fills gaps; a numeric-only flat rule_description
    (a rule id) swaps for the embedded prose. Missing stays honest."""
    full = r.get("full_alert")
    rule = full.get("rule") if isinstance(full, dict) else None
    rule = rule if isinstance(rule, dict) else {}
    desc = str(r.get("rule_description") or "").strip()
    if desc.isdigit() and rule.get("description"):
        desc = str(rule.get("description")).strip()
    groups = rule.get("groups") if isinstance(rule.get("groups"), list) \
        else []
    return desc, [str(g) for g in groups]


def _category_cite(desc: str, groups: List[str]) -> Tuple[str, str]:
    """(category, citation) per the v3 vocabulary. The label rides the
    record's own rule-group family - never the prose, never guessed:
    a rule whose TEXT merely mentions sshd (e.g. the AIDE monitored-
    surfaces list) keeps its aide/fim label."""
    text = (desc + " " + " ".join(groups)).lower()
    gl = [g.lower() for g in groups]
    if any(h in text for h in ("invalid user", "invalid_user",
                               "non-existent user", "nonexistent user")):
        return "logon-attempt", "realtime-soc/sshd"
    if any("auth_fail" in g or g in ("sshd", "authentication",
                                     "authentication_failures",
                                     "authentication_failed")
           for g in gl):
        return "brute-force", "realtime-soc/sshd"
    if any(g in ("firewall", "ufw") for g in gl):
        return "service scan", "realtime-soc/ufw"
    if gl:
        return "other: " + gl[0], "realtime-soc/" + gl[0]
    return "other", "realtime-soc/unknown"


def _detection_rows(realtime_day: List[Dict[str, Any]]
                    ) -> List[Dict[str, Any]]:
    """Collapse the day's realtime rows into detection groups, loudest
    first: host/category/target with counts, first/last seen + citations."""
    groups: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for r in realtime_day:
        desc, gl = _rule_fields(r)
        full = r.get("full_alert") if isinstance(r.get("full_alert"), dict) \
            else {}
        agent = full.get("agent") if isinstance(full.get("agent"), dict) \
            else {}
        host = str(r.get("agent_name") or agent.get("name") or "unknown")
        src = str(r.get("src_ip") or "").strip() or "unknown"
        sev = str(r.get("severity") or "").strip()
        cat, cite = _category_cite(desc, gl)
        target = desc[:80]
        if not target:
            target = "rule " + str(r.get("rule_id") or "unknown")
        if gl:
            target += " (" + ", ".join(gl[:3]) + ")"
        key = (host, cat, target)
        g = groups.setdefault(key, {"count": 0, "first": "", "last": "",
                                    "sev": "", "rank": 0,
                                    "src": src, "cite": cite})
        ts = str(r.get("ts") or "")
        mm = ts[11:16]
        g["count"] += 1
        if mm:
            if not g["first"]:
                g["first"] = mm
            g["last"] = mm
        if sev:
            rank = {"low": 1, "medium": 2, "high": 3,
                    "critical": 4}.get(sev, 0)
            if rank >= g["rank"]:
                g["sev"], g["rank"] = sev, rank
    rows: List[Dict[str, Any]] = []
    for (host, cat, target), g in groups.items():
        rows.append({"host": host, "cat": cat, "cite": g["cite"],
                     "target": target, "count": g["count"],
                     "first": g["first"], "last": g["last"],
                     "sev": g["sev"] or "unknown", "src": g["src"]})
    rows.sort(key=lambda x: (-x["count"], x["host"], x["cat"]))
    return rows


def render_detection_report(day: str,
                            realtime_day: List[Dict[str, Any]],
                            realtime_all: List[Dict[str, Any]],
                            ) -> List[str]:
    """The v3 detection-report section for one day's rows."""
    rows = _detection_rows(realtime_day)
    out: List[str] = []
    out.append("## Detection report (" + day + ")")
    out.append("")
    out.append("_Follows the v3 output contract in agentic-ai "
               "docs/PROMPT_EXERCISE_DETECTION_REPORTS.md: per-row source "
               "citations, unknowns marked, nothing invented._")
    out.append("")

    out.append("### Executive summary")
    out.append("")
    bullets: List[str] = []
    if rows:
        for r in rows[:2]:
            span = f", {r['first']}-{r['last']}" if r["first"] else ""
            bullets.append(
                f"- {r['cat']} on {r['host']} ({r['target']}): "
                f"{r['count']} alerts{span}; severity {r['sev']}; "
                f"source: {r['cite']}.")
        sevs = sorted({r["sev"] for r in rows if r["sev"] != "unknown"})
        bullets.append(
            f"- Window: {len(realtime_day)} alerts in {len(rows)} groups; "
            f"severities {', '.join(sevs) or 'unknown'}.")
    elif realtime_all:
        last_ts = str(realtime_all[-1].get("ts") or "")
        bullets.append("- No detections in the window.")
        bullets.append(
            "- Scope note: the realtime-soc store shows no alerts for "
            f"{day}; its last stored alert is {last_ts[:19]} - the store "
            "is treated as unreachable for the window, not guessed.")
    else:
        bullets.append(
            "- No detections in the window; the realtime-soc store is "
            "empty or missing - sources unreachable, nothing guessed.")
    out += bullets[:3]
    out.append("")

    out.append("### Detection inventory")
    out.append("")
    if rows:
        irows = [[
            (f"{r['first']}-{r['last']}" if r["first"] else "unknown"),
            r["host"], r["cat"], r["src"], r["target"], r["count"],
            r["sev"], r["cite"],
        ] for r in rows]
        out += _table(["time range", "host", "category", "source ip",
                       "target", "count", "severity", "source"], irows)
    else:
        out.append("_No detection groups in the window._")
    out.append("")

    out.append("### Top sources")
    out.append("")
    if rows:
        stat: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            name = r["src"] if r["src"] != "unknown" \
                else "unknown (host " + r["host"] + ")"
            h = stat.setdefault(name, {"hits": 0, "cats": Counter()})
            h["hits"] += r["count"]
            h["cats"][r["cat"]] += r["count"]
        top = sorted(stat.items(),
                     key=lambda kv: (-kv[1]["hits"], kv[0]))[:3]
        srows = [[name, h["hits"],
                  ", ".join(c for c, _ in h["cats"].most_common(2))]
                 for name, h in top]
        out += _table(["origin", "hits", "pattern"], srows)
    else:
        out.append("_No origins in the window._")
    out.append("")

    out.append("### Affected accounts and services")
    out.append("")
    users: Counter = Counter()
    services: Counter = Counter()
    for r in realtime_day:
        full = r.get("full_alert") if isinstance(r.get("full_alert"), dict) \
            else {}
        data = full.get("data") if isinstance(full.get("data"), dict) \
            else {}
        u = str(data.get("dstuser") or data.get("srcuser")
                or data.get("user") or "").strip()
        if u:
            users[u] += 1
        _, gl = _rule_fields(r)
        for g in gl:
            svc = _GROUP_TO_SERVICE.get(g.lower())
            if svc:
                services[svc] += 1
    bits = []
    if users:
        bits.append("accounts: "
                    + ", ".join(u for u, _ in users.most_common(6)))
    elif realtime_day:
        bits.append("accounts: unknown (no dstuser fields in the "
                    "window's rows)")
    if services:
        bits.append("services: "
                    + ", ".join(s for s, _ in services.most_common(6)))
    out.append("- " + ("; ".join(bits) + "." if bits else
                       "unknown (the window's rows carry no account/"
                       "service fields)."))
    out.append("")

    out.append("### Recommended actions")
    out.append("")
    acts: List[str] = []
    for r in rows:
        if r["sev"] in ("high", "critical"):
            acts.append(f"Ticket candidate: {r['cat']} on {r['host']} "
                        f"({r['count']} alerts; evidence rows above).")
        if len(acts) >= 4:
            break
    blocks = sorted({r["src"] for r in rows if r["src"] != "unknown"})
    if blocks:
        acts.append("Blocking candidates: " + ", ".join(blocks[:5])
                    + " (verify before applying).")
    else:
        acts.append("Blocking candidates: unknown (the store carries no "
                    "origin IPs).")
    policy = ("Policy: this report stops at tickets and network blocks; "
              "no exploit or countermeasure detail.")
    acts.append(policy)
    for i, a in enumerate(acts[:5], 1):
        out.append(f"{i}. {a}")
    if len(acts) > 5:
        out.append(f"6. {policy}")
    out.append("")
    return out


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


# --- G8 delivery (2026-09-18): the report file alone is invisible to
# the operator. After render, send a compact summary via the OpenClaw
# agent turn (lands in the operator's main chat); fall back to SMTP
# (self-addressed via the reports mailbox) when the CLI is missing or
# stalls. Mirrors deploy/notify-healthcheck-failure.sh delivery order.
DEFAULT_MAILBOX_ENV = ("/home/wez/.openclaw/workspace/secrets/"
                       "reports-bedimsecurity-mailbox.env")
DELIVERY_TIMEOUT_S = 45


def _scan_diff_section(base: Optional[Path] = None) -> str:
    """Diff the two latest scan days, or empty string when <2 days.
    Errors are swallowed: a diff section must never fail the report."""
    try:
        import sys
        scanner_dir = str(Path(__file__).resolve().parent.parent / "scanner")
        if scanner_dir not in sys.path:
            sys.path.insert(0, scanner_dir)
        from soc_scan_diff import diff_days, render_markdown
        base = Path(base) if base else Path(SCAN_RESULTS_DIR_DEFAULT)
        days = sorted({d.name for d in base.iterdir()
                       if d.is_dir() and len(d.name) == 10
                       and d.name[4] == d.name[7] == "-"})
        if len(days) < 2:
            return ""
        return render_markdown(days[-2], days[-1], diff_days(days[-2], days[-1], base))
    except Exception:
        return ""


def _deliver_report(out: str, md: str, day: str) -> str:
    """G8: make the report visible. 1) OpenClaw agent turn (main chat);
    2) SMTP fallback (self-addressed via the reports mailbox). Returns
    a short delivery note for the journal/stdout log."""
    import smtplib
    import subprocess

    # compact summary for the chat subject/first lines
    first_head = ""
    for line in md.splitlines():
        if line.strip() and not line.startswith("#"):
            first_head = line.strip()
            break
    diff_md = _scan_diff_section()
    summary = (f"SOC daily decisions report for {day} → {out}\n"
               f"{first_head}\n")
    if diff_md:
        summary += "\n" + diff_md[:3000]

    oc = os.environ.get("OPENCLAW_BIN", "openclaw")
    if os.path.exists(oc) or os.environ.get("OPENCLAW_BIN"):
        try:
            r = subprocess.run(
                ["timeout", "-k", "5", "60", oc, "agent",
                 "--agent", "main", "--deliver", "-m", summary,
                 "--timeout", "45"],
                capture_output=True, text=True,
                timeout=DELIVERY_TIMEOUT_S)
            if r.returncode == 0:
                return "delivered via openclaw agent turn"
        except Exception:
            pass

    env_file = os.environ.get("SOC_MAILBOX_ENV", DEFAULT_MAILBOX_ENV)
    if not os.path.isfile(env_file):
        return "not delivered (no mailbox env + no openclaw)"
    cfg = {}
    for line in open(env_file, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            cfg[k.strip()] = v.strip()
    host = cfg.get("SMTP_HOST")
    port = int(cfg.get("SMTP_PORT", "587"))
    mailbox = cfg.get("REPORTS_MAILBOX")
    pw = cfg.get("REPORTS_MAILBOX_PW")
    if not (host and mailbox and pw):
        return "not delivered (mailbox env incomplete)"
    try:
        s = smtplib.SMTP(host, port, timeout=20)
        try:
            s.starttls()
            s.login(mailbox, pw)
            s.sendmail(
                mailbox, [mailbox],
                "Subject: [SOC] daily decisions report " + day
                + "\r\n\r\n" + summary)
        finally:
            s.quit()
        return "delivered via SMTP (reports mailbox)"
    except Exception as e:
        return f"not delivered (SMTP error: {e!r})"


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
    note = ""
    if os.environ.get("SOC_DAILY_DELIVER", "1") != "0":
        try:
            note = " | " + _deliver_report(out, md, day)
        except Exception as e:
            note = f" | delivery error: {e!r}"
    sys.stdout.write(f"[soc-daily-decisions] wrote {out} "
                     f"({len(audit)} audit records, "
                     f"{len(realtime)} realtime){note}\n")
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
        {"ts": "2026-08-08T10:05:00.000+00:00", "type": "alert",
         "alert_id": "ALERT-S-1", "level": 12, "severity": "high",
         "rule_id": "5710",
         "rule_description": "SSHD: brute force trying to get access to "
         "the system.",
         "agent_name": "lab-web", "src_ip": "",
         "full_alert": {
             "rule": {"level": 12,
                      "description": "SSHD: brute force trying to get "
                      "access to the system.",
                      "id": "5710", "firedtimes": 3, "mail": False,
                      "groups": ["syslog", "sshd",
                                 "authentication_failures"]},
             "agent": {"id": "025", "name": "lab-web",
                       "ip": "203.0.113.9"},
             "data": {"dstuser": "root"}},
         "schema": 1},
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
                    "## Detection report (2026-08-08)",
                    "### Executive summary",
                    "### Detection inventory",
                    "### Top sources",
                    "### Affected accounts and services",
                    "### Recommended actions",
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
    # Detection report (v3 contract)
    ss = text.split("### Executive summary")[1].split("### ")[0]
    nbul = sum(1 for ln in ss.splitlines() if ln.startswith("- "))
    assert nbul <= 3, f"summary bullets {nbul}"
    assert "realtime-soc/sshd" in text
    assert "brute-force" in text
    assert "source ip" in text
    assert "unknown (host" in text
    assert "accounts: root" in text
    assert "services: ssh." in text
    # Cleanup
    shutil.rmtree(tmp, ignore_errors=True)
    sys.stdout.write("soc-daily-decisions smoke test: OK\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
