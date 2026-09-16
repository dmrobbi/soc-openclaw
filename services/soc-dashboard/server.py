#!/usr/bin/env python3
"""SOC web dashboard (Track D, task D2 — 2026-08-08).

A stdlib HTTP server that serves a static SOC dashboard on
`:8770/soc/`. The dashboard is the operator's read-only view
of the SOC fleet:

  /                - overview: last 24h, by tenant, by agent,
                     by decision, alerts, queue size
  /tenants/<id>    - per-tenant: routing config + last 24h
                     activity for that tenant
  /agents/<id>     - per-agent: last 24h activity for that
                     agent + low-confidence / error rate
  /runs/<id>       - per-run: drill-down via the C4 audit MCP
  /healthz         - liveness (also tests the C4 and C3
                     backends)
  /tools.json      - the tool inventory (so the dashboard's
                     own tools surface is discoverable)

The dashboard is a thin shim: it doesn't have its own data
store. Every page calls one of the existing MCP servers
(C4 audit-log, C3 tickets, C2 manager, C1 indexer) over
loopback HTTP and renders the result. This means the
dashboard is automatically consistent with the rest of the
SOC — there is no dashboard DB to get out of sync.

Transport
---------
Same shape as the rest of the SOC MCP servers: stdlib
HTTP, loopback-only by default, no third-party deps. PUT and
DELETE on any path return 405 (the dashboard is read-only).

Routing
-------
The dashboard loads `config/soc-routing.yaml` (D3) on startup
to know which tenants exist and what their display_name +
STIG baseline is. The routing config is the single source of
truth — no tenant list is hard-coded in the dashboard.

Run
---
    # foreground
    python3 scripts/soc/soc-dashboard/server.py

    # systemd
    sudo cp scripts/soc/soc-dashboard/soc-dashboard.service \
            /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now soc-dashboard

    # smoke
    python3 scripts/soc/soc-dashboard/server.py --smoke

Created 2026-08-08 by Ciceron as part of Track D (D2).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 8770
DEFAULT_C4_URL = "http://127.0.0.1:8769"   # soc-audit-mcp
DEFAULT_C3_URL = "http://127.0.0.1:8768"   # soc-tickets-mcp
DEFAULT_C2_URL = "http://127.0.0.1:8767"   # soc-manager-mcp
DEFAULT_C1_URL = "http://127.0.0.1:8766"   # soc-wazuh-mcp
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "static")
MAX_RESPONSE_BYTES = 5 * 1024 * 1024

DASHBOARD_TOOLS = (
    "overview", "tenant_view", "agent_view", "run_view",
    "audit_stats_proxy", "tickets_list_proxy",
    "compliance_score", "compliance_scores_all",
    "fleet_status", "fleet_summary",
    "stig_overview", "stig_findings",
    "stig_host_view",
    "host_control_status",
    "fleet_host_view", "run_scan",
    "run_host_compliance_scan",
    "remediate_control",
    "tasks_list", "task_get",
    "compliance_report", "stig_report", "run_fleet_scan",
    "agent_logs",
    "vulnerability_findings", "fleet_cve_overview",
    "packages_search", "package_diff",
)


# ---------------------------------------------------------------------------
# Backend clients (call C4/C3/C2/C1 over loopback HTTP)
# ---------------------------------------------------------------------------
def _http_post(url: str, body: Dict[str, Any],
               timeout: float = 5.0) -> Tuple[int, Any]:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw)
            except json.JSONDecodeError:
                return r.status, raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        return 0, f"unreachable: {e!r}"


def _http_get(url: str, timeout: float = 3.0) -> Tuple[int, Any]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw)
            except json.JSONDecodeError:
                return r.status, raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        return 0, f"unreachable: {e!r}"


# Routing config is loaded lazily so the dashboard can still
# start if PyYAML is missing (the dashboard then falls back
# to a tenant list derived from the C4 audit log).
def _load_routing_tenants() -> Optional[Dict[str, Any]]:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return None
    # Honor SOC_ROUTING_CONFIG first — the same live routing config every
    # other component reads (the systemd unit sets it). Then repo-relative
    # fallbacks: __file__ is soc-dashboard/server.py, so the repo root is
    # 3 levels up: soc-dashboard/ -> services/ -> REPO.
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    env_path = os.environ.get("SOC_ROUTING_CONFIG")
    candidates = ([env_path] if env_path else []) + [
        os.path.join(repo_root, "config", "soc-routing.yaml"),
        os.path.join(repo_root, "config", "soc-routing.yaml.example"),
    ]
    for path in candidates:
        if not path or not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                raw = yaml.safe_load(f)
            tenants = raw.get("tenants") or {}
            return {tid: (t.get("display_name", tid)
                          if isinstance(t, dict) else tid)
                    for tid, t in tenants.items()}
        except Exception as e:
            sys.stderr.write(
                f"[soc-dashboard] routing config load failed ({path}): {e}\n")
            continue
    return None


# ---------------------------------------------------------------------------
# Tools (the dashboard's own MCP-style tool surface)
# ---------------------------------------------------------------------------
def tool_overview(args: Dict[str, Any]) -> Dict[str, Any]:
    """overview() -> aggregated last-24h stats from C4 + C3."""
    c4 = os.environ.get("SOC_DASHBOARD_C4_URL", DEFAULT_C4_URL)
    c3 = os.environ.get("SOC_DASHBOARD_C3_URL", DEFAULT_C3_URL)
    # C4 audit_stats for the last 24h
    _, stats = _http_post(f"{c4}/tools/audit_stats",
                          {"time_range": "24h"})
    # C3 ticket list (any status)
    _, tix = _http_post(f"{c3}/tools/list_tickets",
                        {"limit": 50})
    return {
        "ok": True,
        "tool": "overview",
        "audit_24h": stats if isinstance(stats, dict) else {},
        "tickets_recent": (tix.get("tickets", [])
                           if isinstance(tix, dict) else []),
        "ticket_total": (tix.get("total", 0)
                         if isinstance(tix, dict) else 0),
    }


def tool_tenant_view(args: Dict[str, Any]) -> Dict[str, Any]:
    """tenant_view(tenant_id) -> audit + tickets + routing for one tenant."""
    tid = args.get("tenant_id")
    if not tid:
        raise ValueError("tenant_id is required")
    c4 = os.environ.get("SOC_DASHBOARD_C4_URL", DEFAULT_C4_URL)
    c3 = os.environ.get("SOC_DASHBOARD_C3_URL", DEFAULT_C3_URL)
    # Audit query
    _, audit = _http_post(f"{c4}/tools/query_audit",
                          {"tenant_id": tid, "limit": 50,
                           "time_range": "24h"})
    # Ticket list filtered by tenant_id is not yet a tool
    # (C3 doesn't have a tenant filter on list_tickets; the
    # tenant_id is in the source_run_id or has to be
    # client-side). For the dashboard we do client-side
    # filtering on the most recent 100 tickets.
    _, tix = _http_post(f"{c3}/tools/list_tickets", {"limit": 100})
    tickets = []
    if isinstance(tix, dict):
        # The C3 ticket model doesn't have a tenant_id field
        # today; the dashboard shows all recent tickets and
        # lets the operator filter. (Adding tenant_id to C3
        # is a follow-up; not in this PR.)
        tickets = tix.get("tickets", [])[:20]
    return {
        "ok": True,
        "tool": "tenant_view",
        "tenant_id": tid,
        "audit_24h": (audit.get("hits", [])
                      if isinstance(audit, dict) else []),
        "audit_total": (audit.get("total", 0)
                        if isinstance(audit, dict) else 0),
        "tickets_recent": tickets,
    }


def tool_agent_view(args: Dict[str, Any]) -> Dict[str, Any]:
    """agent_view(agent_id) -> audit + low-conf / error counts for one agent."""
    aid = args.get("agent_id")
    if not aid:
        raise ValueError("agent_id is required")
    c4 = os.environ.get("SOC_DASHBOARD_C4_URL", DEFAULT_C4_URL)
    _, audit = _http_post(f"{c4}/tools/query_audit",
                          {"agent_id": aid, "limit": 50,
                           "time_range": "24h"})
    hits = audit.get("hits", []) if isinstance(audit, dict) else []
    total = audit.get("total", 0) if isinstance(audit, dict) else 0
    err = sum(1 for h in hits if h.get("outcome") == "error")
    return {
        "ok": True,
        "tool": "agent_view",
        "agent_id": aid,
        "audit_24h": hits,
        "audit_total": total,
        "error_count": err,
    }


def tool_run_view(args: Dict[str, Any]) -> Dict[str, Any]:
    """run_view(run_id) -> full record(s) for one runId via C4."""
    rid = args.get("run_id")
    if not rid:
        raise ValueError("run_id is required")
    c4 = os.environ.get("SOC_DASHBOARD_C4_URL", DEFAULT_C4_URL)
    _, body = _http_post(f"{c4}/tools/get_run", {"run_id": rid})
    return body if isinstance(body, dict) else {
        "ok": False, "error": f"unexpected C4 response: {body!r}"}


def tool_compliance_score(args: Dict[str, Any]) -> Dict[str, Any]:
    """compliance_score(tenant_id) -> E6 dashboard_score shape.

    Wraps the E6 soc_score module (Track E, task E6 — 2026-08-08).
    The score module is on the same host and lives in
    scripts/soc/soc_score.py; we import it in-process rather
    than shelling out, since this is a stdlib-only service and
    soc_score is too. Returns the same shape as soc_score's
    tool_dashboard_score: current score + 7-day trend + by-family
    + by-baseline + by-severity scores.
    """
    tid = args.get("tenant_id")
    if not tid:
        raise ValueError("tenant_id is required")
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(
            os.path.abspath(__file__)), os.pardir))
        from soc_score import tool_dashboard_score  # noqa: E402
        return tool_dashboard_score({"tenant_id": tid})
    except ImportError as e:
        return {"ok": False, "error": f"soc_score import failed: {e!r}",
                "tool": "compliance_score", "tenant_id": tid}
    except Exception as e:
        return {"ok": False, "error": f"score compute failed: {e!r}",
                "tool": "compliance_score", "tenant_id": tid}


def tool_compliance_scores_all(args: Dict[str, Any]) -> Dict[str, Any]:
    """compliance_scores_all() -> fleet-wide score summary.

    Wraps soc_score tool_score_all_tenants. Returns one
    score entry per tenant (NOT a per-tenant drill-down;
    for that use compliance_score). Used by the /scores
    landing page.
    """
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(
            os.path.abspath(__file__)), os.pardir))
        from soc_score import tool_score_all_tenants  # noqa: E402
        return tool_score_all_tenants({})
    except ImportError as e:
        return {"ok": False, "error": f"soc_score import failed: {e!r}",
                "tool": "compliance_scores_all"}
    except Exception as e:
        return {"ok": False, "error": f"score compute failed: {e!r}",
                "tool": "compliance_scores_all"}


def tool_audit_stats_proxy(args: Dict[str, Any]) -> Dict[str, Any]:
    """audit_stats_proxy(time_range='24h') -> raw pass-through to C4."""
    c4 = os.environ.get("SOC_DASHBOARD_C4_URL", DEFAULT_C4_URL)
    _, body = _http_post(f"{c4}/tools/audit_stats",
                         {"time_range": args.get("time_range", "24h")})
    return body if isinstance(body, dict) else {
        "ok": False, "error": f"unexpected C4 response: {body!r}"}


def tool_stig_overview(args: Dict[str, Any]) -> Dict[str, Any]:
    """stig_overview(time_range='24h') -> KPIs + breakdowns for the
    STIG section of the overview page.

    Wraps the C4 `query_stig_findings` tool. The dashboard's
    overview page calls this and surfaces the four KPIs
    (total findings, unique stig_ids, unique controls, unique
    hosts) plus the by_severity / by_nist_family breakdowns.

    Intentionally small payload — this is meant to be cheap
    to call on every page render.
    """
    c4 = os.environ.get("SOC_DASHBOARD_C4_URL", DEFAULT_C4_URL)
    tr = args.get("time_range", "24h")
    _, body = _http_post(f"{c4}/tools/query_stig_findings",
                         {"time_range": tr, "limit": 1})
    if not isinstance(body, dict):
        return {"ok": False, "error": f"unexpected C4 response: {body!r}"}
    # Pull just the summary fields; don't ship the full findings
    # list on the overview (the /stig page does that).
    return {
        "ok": True,
        "tool": "stig_overview",
        "time_range": body.get("time_range"),
        "total": body.get("total", 0),
        "unique_stig_ids": body.get("unique_stig_ids", 0),
        "unique_controls": body.get("unique_controls", 0),
        "unique_hosts": len(body.get("by_host", {}) or {}),
        "monitored_hosts": body.get("monitored_hosts", []),
        "monitored_hosts_status": body.get("monitored_hosts_status", {}),
        "by_severity": body.get("by_severity", {}),
        "by_nist_family": body.get("by_nist_family", {}),
        "by_tenant": body.get("by_tenant", {}),
    }


def tool_stig_findings(args: Dict[str, Any]) -> Dict[str, Any]:
    """stig_findings(time_range='7d', tenant_id=None, severity=None,
    limit=100) -> full STIG findings + aggregates.

    Thin pass-through to C4 `query_stig_findings`. The
    dashboard's /stig page calls this; the result includes
    the full findings array (capped at `limit`, default 100)
    plus the same aggregates as stig_overview.
    """
    c4 = os.environ.get("SOC_DASHBOARD_C4_URL", DEFAULT_C4_URL)
    payload: Dict[str, Any] = {
        "time_range": args.get("time_range", "7d"),
        "limit": args.get("limit", 100),
    }
    if args.get("tenant_id"):
        payload["tenant_id"] = args["tenant_id"]
    if args.get("severity"):
        payload["severity"] = args["severity"]
    _, body = _http_post(f"{c4}/tools/query_stig_findings", payload)
    return body if isinstance(body, dict) else {
        "ok": False, "error": f"unexpected C4 response: {body!r}"}


def tool_stig_host_view(args: Dict[str, Any]) -> Dict[str, Any]:
    """stig_host_view(host, time_range='30d', limit=200) -> findings
    + aggregates for one monitored host, plus the agent's
    current Wazuh status.

    Used by the dashboard's /stig/host/<host> drilldown page.
    Filters C4 `query_stig_findings` by `host` (= wazuh_alert.agent)
    and augments with the host's current status from C2
    manager-mcp. The 16-family seed stays in the response
    (consistency with /stig); by_host is suppressed (it would
    just be `{host: N}`).

    Default window is 30d (vs the /stig page's 7d) because
    per-host findings are sparse — a 7d window often shows
    zero for hosts that just had one bad week, which makes
    the drilldown look broken. Override with time_range.

    `host` must match `[A-Za-z0-9_.-]{1,64}`. Returns ok=False
    on invalid input rather than calling C4.
    """
    host = (args.get("host") or "").strip()
    if not host:
        return {"ok": False, "tool": "stig_host_view",
                "error": "host is required"}
    if not re.match(r"^[A-Za-z0-9_.-]{1,64}$", host):
        return {"ok": False, "tool": "stig_host_view",
                "host": host,
                "error": "host must match [A-Za-z0-9_.-]{1,64}"}
    c4 = os.environ.get("SOC_DASHBOARD_C4_URL", DEFAULT_C4_URL)
    payload: Dict[str, Any] = {
        "host": host,
        "time_range": args.get("time_range", "30d"),
        "limit": min(int(args.get("limit") or 200), 1000),
    }
    if args.get("tenant_id"):
        payload["tenant_id"] = args["tenant_id"]
    if args.get("severity"):
        payload["severity"] = args["severity"]
    code, body = _http_post(f"{c4}/tools/query_stig_findings", payload)
    if not isinstance(body, dict):
        return {"ok": False, "tool": "stig_host_view",
                "host": host,
                "error": f"unexpected C4 response: {body!r}"}
    # Suppress by_host on per-host views (would just be
    # {host: total}); the dashboard renders findings directly.
    body.pop("by_host", None)
    body["drilldown"] = "host"
    body["host"] = host
    # Augment with the host's current Wazuh status from C2.
    # Fail-soft — if C2 is unreachable we still return the
    # audit-derived findings; the dashboard renders a
    # "(status unknown)" badge instead of crashing.
    c2 = os.environ.get("SOC_DASHBOARD_C2_URL", DEFAULT_C2_URL)
    try:
        _, agents_body = _http_post(f"{c2}/tools/list_agents",
                                    {"limit": 200})
        agent_status = "unknown"
        for a in (agents_body.get("agents") or []):
            if a.get("name") == host:
                agent_status = a.get("status") or "unknown"
                break
        body["host_status"] = agent_status
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        sys.stderr.write(
            f"[soc-dashboard] C2 probe failed for host={host}: {e}\n")
        body["host_status"] = "unknown"
    return body


def tool_tickets_list_proxy(args: Dict[str, Any]) -> Dict[str, Any]:
    """tickets_list_proxy(...) -> raw pass-through to C3."""
    c3 = os.environ.get("SOC_DASHBOARD_C3_URL", DEFAULT_C3_URL)
    _, body = _http_post(f"{c3}/tools/list_tickets", args or {})
    return body if isinstance(body, dict) else {
        "ok": False, "error": f"unexpected C3 response: {body!r}"}


def tool_host_control_status(args: Dict[str, Any]) -> Dict[str, Any]:
    """host_control_status(day=None, tenant_id=None, host=None)
    -> per-host per-control attribution from the day's archived
    OpenSCAP scan results.

    Read-only wrapper over services/scanner/soc_scanner
    .host_control_status(). `day` defaults to the most recent day
    (today, stepping back up to 7 days) with archived results.
    Failing controls are enriched with catalogue metadata (title,
    severity, automated) so the UI can render Remediate buttons —
    fleet remediation keys on the failing (host, control) pairs."""
    soc_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    scanner_dir = os.path.join(soc_dir, "scanner")
    for p in (soc_dir, scanner_dir):
        if p not in sys.path:
            sys.path.insert(0, p)
    from soc_scanner import host_control_status as _hcs
    import datetime as _dt
    day_arg = args.get("day")
    res = None
    last_err = None
    if day_arg:
        res = _hcs(str(day_arg), tenant_id=args.get("tenant_id"),
                   host=args.get("host"))
    else:
        today = _dt.datetime.now(_dt.timezone.utc).date()
        for back in range(7):
            cand = str(today - _dt.timedelta(days=back))
            res = _hcs(cand, tenant_id=args.get("tenant_id"),
                       host=args.get("host"))
            if res.get("ok") and res.get("hosts"):
                break
            last_err = res.get("error") or f"no results for {cand}"
            res = None
    if not res or not res.get("ok"):
        return {"ok": False, "tool": "host_control_status",
                "error": (res or {}).get("error")
                or f"no scan results in the last 7 days (last: {last_err})"}
    # Enrich failing controls with catalogue metadata so the UI can
    # label rows and disable buttons for non-automated controls.
    meta: Dict[str, Any] = {}
    try:
        from soc_stig import tool_applicable_for_tenant
        for c in tool_applicable_for_tenant(
                {"tenant_id": res.get("tenant")}).get("controls", []):
            meta[c.get("id")] = c
    except Exception:
        pass  # unknown tenant / catalogue hiccup — ship ids without meta
    for h in (res.get("hosts") or {}).values():
        h["failed_meta"] = [
            {"control_id": cid,
             "title": (meta.get(cid) or {}).get("title"),
             "severity": (meta.get(cid) or {}).get("severity"),
             "automated": bool((meta.get(cid) or {}).get("automated"))}
            for cid in (h.get("failed") or [])]
    res["tool"] = "host_control_status"
    return res


def tool_fleet_host_view(args: Dict[str, Any]) -> Dict[str, Any]:
    """fleet_host_view(agent_id) -> drill-down for one managed host.

    Combines: current Wazuh state (C2 get_agent), recent alerts for the
    host (realtime ingest /alerts filtered by agent name), STIG findings
    (stig_host_view), and whether the C2 manager allows mutations (which
    gates the Run Scan button).
    """
    aid = str(args.get("agent_id") or "").strip()
    if not aid:
        raise ValueError("agent_id is required")
    c2 = os.environ.get("SOC_DASHBOARD_C2_URL", DEFAULT_C2_URL)
    code, agent = _http_post(f"{c2}/tools/get_agent",
                             {"agent_id": aid}, timeout=8.0)
    if code != 200 or not isinstance(agent, dict) or not agent.get("ok"):
        return {"ok": False, "tool": "fleet_host_view",
                "error": f"C2 get_agent failed ({code})", "agent_id": aid}
    row = agent.get("agent", {})
    name = str(row.get("name") or aid)

    rt = os.environ.get("SOC_REALTIME_URL", "http://127.0.0.1:8765")
    alerts: List[Dict[str, Any]] = []
    rc, rb = _http_get(f"{rt}/alerts", timeout=3.0)
    if rc == 200 and isinstance(rb, dict):
        want = name.lower()
        for a in rb.get("alerts", []):
            an = str(a.get("agent_name") or
                     (a.get("full_alert") or {}).get("agent_name", "")).lower()
            if an and an == want:
                alerts.append(a)
    alerts.sort(key=lambda a: str(a.get("ts", "")), reverse=True)
    alerts = alerts[:50]

    stig = tool_stig_host_view({"host": name})

    # OpenSCAP control attribution for this host from the latest
    # archived scan day (read-only; feeds the Remediate buttons).
    host_controls = None
    try:
        hcs = tool_host_control_status({"host": name})
        if hcs.get("ok"):
            hc = (hcs.get("hosts") or {}).get(name)
            if hc:
                host_controls = {
                    "day": hcs.get("day"),
                    "tenant": hcs.get("tenant"),
                    "failed": hc.get("failed") or [],
                    "failed_meta": hc.get("failed_meta") or [],
                    "total": len(hc.get("controls") or {})}
    except Exception as e:
        host_controls = {"error": repr(e)}

    # mutations gate: read the manager's /healthz, which reports the
    # SOC_MANAGER_MCP_ALLOW_MUTATIONS state directly. (2026-09-13 fix:
    # get_manager_info returns raw Wazuh /manager/info data, which has
    # no mutations key — the Run Scan button was permanently disabled.)
    mcode, mbody = _http_get(f"{c2}/healthz", timeout=5.0)
    mutations = bool((mbody or {}).get("mutations_enabled")) \
        if mcode == 200 and isinstance(mbody, dict) else False

    return {
        "ok": True,
        "tool": "fleet_host_view",
        "agent": row,
        "alerts": alerts,
        "alerts_total": len(alerts),
        "stig": stig,
        "controls": host_controls,
        "mutations_enabled": mutations,
    }


def tool_run_scan_proxy(args: Dict[str, Any]) -> Dict[str, Any]:
    """run_scan(agent_id) -> proxy to the C2 manager-mcp run_scan tool
    (mutating: restarts the agent to trigger a fresh scan)."""
    aid = str(args.get("agent_id") or "").strip()
    if not aid:
        raise ValueError("agent_id is required")
    c2 = os.environ.get("SOC_DASHBOARD_C2_URL", DEFAULT_C2_URL)
    code, body = _http_post(f"{c2}/tools/run_scan", {"agent_id": aid},
                            timeout=15.0)
    if code != 200:
        err = body.get("error") if isinstance(body, dict) else repr(body)
        return {"ok": False, "tool": "run_scan",
                "error": f"C2 manager returned {code}: {err}"}
    return body


def tool_agent_logs(args: Dict[str, Any]) -> Dict[str, Any]:
    """agent_logs(agent, hours=24, min_level=0, size=200) -> recent Wazuh
    alerts for one agent. Proxies C1 soc-wazuh-mcp search_alerts (which
    handles the agent.name.keyword match for tokenized names)."""
    agent = (args or {}).get("agent")
    if not agent:
        raise ValueError("agent is required")
    c1 = os.environ.get("SOC_DASHBOARD_C1_URL", "http://127.0.0.1:8766")
    hours = max(1, min(int((args or {}).get("hours") or 24), 24 * 30))
    payload = {
        "agent": str(agent),
        "time_range": f"{hours}h",
        "min_level": max(0, int((args or {}).get("min_level") or 0)),
        "size": max(1, min(int((args or {}).get("size") or 200), 500)),
    }
    code, body = _http_post(f"{c1}/tools/search_alerts", payload,
                            timeout=20.0)
    if code != 200 or not body.get("ok"):
        raise ValueError(f"C1 search_alerts failed: HTTP {code}, "
                         f"{str(body)[:200]}")
    return {
        "ok": True, "tool": "agent_logs", "agent": str(agent),
        "range": body.get("range"), "total": body.get("total"),
        "hits": body.get("hits", []),
    }


def tool_vulnerability_findings(args: Dict[str, Any]) -> Dict[str, Any]:
    """vulnerability_findings(agent=None, package=None, cve=None,
    severity=None, size=200) -> CVE findings from the Vulnerability
    Detector state index (proxy to C1 search_vulnerabilities)."""
    c1 = os.environ.get("SOC_DASHBOARD_C1_URL", "http://127.0.0.1:8766")
    args = args or {}
    payload = {k: v for k, v in args.items()
               if k in ("agent", "package", "cve", "severity") and v}
    payload["size"] = max(1, min(int(args.get("size") or 200), 500))
    code, body = _http_post(f"{c1}/tools/search_vulnerabilities", payload,
                            timeout=20.0)
    if code != 200 or not body.get("ok"):
        raise ValueError(f"C1 search_vulnerabilities failed: HTTP {code}, "
                         f"{str(body)[:200]}")
    return {"ok": True, "tool": "vulnerability_findings", **body}


def tool_fleet_cve_overview(args: Dict[str, Any]) -> Dict[str, Any]:
    """fleet_cve_overview() -> per-host CVE severity rollup (C1 proxy)."""
    c1 = os.environ.get("SOC_DASHBOARD_C1_URL", "http://127.0.0.1:8766")
    code, body = _http_post(f"{c1}/tools/fleet_cve_overview", {},
                            timeout=20.0)
    if code != 200 or not body.get("ok"):
        raise ValueError(f"C1 fleet_cve_overview failed: HTTP {code}, "
                         f"{str(body)[:200]}")
    return {"ok": True, "tool": "fleet_cve_overview",
            "by_host": body.get("by_host", {}),
            "totals": body.get("totals", {})}


def tool_packages_search(args: Dict[str, Any]) -> Dict[str, Any]:
    """packages_search(name=None, q=None, size=500) -> package inventory
    rows with CVE-count annotation (proxy to C1 search_packages)."""
    c1 = os.environ.get("SOC_DASHBOARD_C1_URL", "http://127.0.0.1:8766")
    args = args or {}
    payload = {k: args[k] for k in ("name", "q", "size") if args.get(k)}
    code, body = _http_post(f"{c1}/tools/search_packages", payload,
                            timeout=30.0)
    if code != 200 or not body.get("ok"):
        raise ValueError(f"C1 search_packages failed: HTTP {code}, "
                         f"{str(body)[:200]}")
    return {"ok": True, "tool": "packages_search", **body}


def tool_package_diff(args: Dict[str, Any]) -> Dict[str, Any]:
    """package_diff(agent_a, agent_b) -> installed-package comparison
    (proxy to C1 package_diff)."""
    c1 = os.environ.get("SOC_DASHBOARD_C1_URL", "http://127.0.0.1:8766")
    args = args or {}
    payload = {k: args.get(k) for k in ("agent_a", "agent_b")}
    code, body = _http_post(f"{c1}/tools/package_diff", payload,
                            timeout=45.0)
    if code != 200 or not body.get("ok"):
        raise ValueError(f"C1 package_diff failed: HTTP {code}, "
                         f"{str(body)[:200]}")
    return {"ok": True, "tool": "package_diff", **body}


def tool_compliance_report(args: Dict[str, Any]) -> Dict[str, Any]:
    """compliance_report(day=None) -> full per-tenant, per-control
    compliance report: scores + evidence status + applicable controls,
    plus the STIG findings overview for the same window."""
    day = args.get("day") or __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc).strftime("%Y-%m-%d")
    soc_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # soc_dir is the services/ dir (server.py sits one level below it).
    sys.path.insert(0, soc_dir)
    from soc_score import tool_score_all_tenants, tool_dashboard_score
    try:
        from soc_evidence import tool_evidence_summary
    except ImportError:
        # soc_evidence lives in stsgym-work; not ported yet — degrade
        # instead of crashing the whole report.
        tool_evidence_summary = None
    routing_cfg = os.environ.get("SOC_ROUTING_CONFIG") or None
    tenants: List[str] = []
    try:
        if routing_cfg:
            sys.path.insert(0, soc_dir)
            from soc_routing import get_config
            tenants = list(get_config().known_tenants())
    except Exception:
        tenants = []
    detail = []
    for tid in tenants:
        try:
            detail.append(tool_dashboard_score({"tenant_id": tid}))
        except Exception as e:
            detail.append({"tenant_id": tid, "error": repr(e)})
    ev_rows: Dict[str, Any] = {}
    for tid in tenants:
        if tool_evidence_summary is None:
            ev_rows[tid] = {"note": "soc_evidence module not available in this deployment"}
            continue
        try:
            ev_rows[tid] = tool_evidence_summary({"tenant_id": tid, "day": day})
        except Exception as e:
            ev_rows[tid] = {"error": repr(e)}
    code4 = os.environ.get("SOC_DASHBOARD_C4_URL", DEFAULT_C4_URL)
    try:
        _, stig = _http_post(f"{code4}/tools/stig_findings", {})
    except Exception as e:
        stig = {"error": repr(e)}
    return {
        "ok": True,
        "tool": "compliance_report",
        "day": day,
        "tenants": detail,
        "evidence_summary": ev_rows,
        "stig_findings": stig if isinstance(stig, dict) else {"raw": stig},
    }


def tool_stig_report(args: Dict[str, Any]) -> Dict[str, Any]:
    """stig_report() -> full STIG findings list + catalogue summary."""
    code4 = os.environ.get("SOC_DASHBOARD_C4_URL", DEFAULT_C4_URL)
    _, findings = _http_post(f"{code4}/tools/query_stig_findings", {}, timeout=15.0)
    cat_path = os.environ.get(
        "SOC_STIG_CATALOGUE",
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))),
            "config", "stig-catalogue.json"))
    cat_summary: Dict[str, Any] = {}
    try:
        with open(cat_path, "r", encoding="utf-8") as f:
            cat = json.load(f)
        controls = cat.get("controls", [])
        fams = {}
        for c in controls:
            fam = str(c.get("family") or "misc")
            fams[fam] = fams.get(fam, 0) + 1
        cat_summary = {"catalogue": cat_path, "controls": len(controls),
                       "families": fams}
    except Exception as e:
        cat_summary = {"error": repr(e)}
    return {
        "ok": True,
        "tool": "stig_report",
        "catalogue_summary": cat_summary,
        "findings": findings if isinstance(findings, (dict, list)) else {"raw": findings},
    }


def tool_run_fleet_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """run_fleet_scan() -> MUTATING + heavy.

    1. Fleet-wide Wazuh agent restart (every reachable agent re-runs its
       syscheck/FIM scan and the vulnerability detector re-runs).
    2. Compliance evidence collection for every known tenant for today.
    3. Fleet-wide compliance score recompute.

    Gated behind SOC_MANAGER_MCP_ALLOW_MUTATIONS=1 on the C2 manager.
    """
    c2 = os.environ.get("SOC_DASHBOARD_C2_URL", DEFAULT_C2_URL)
    soc_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    steps: List[Dict[str, Any]] = []
    day = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc).strftime("%Y-%m-%d")

    # 1. fleet-wide agent restart (bulk: all reachable)
    code, body = _http_post(f"{c2}/tools/restart_fleet", {}, timeout=20.0)
    steps.append({"step": "fleet agent restart", "code": code,
                  "body": body if isinstance(body, dict) else {"raw": str(body)}})
    if code != 200:
        return {"ok": False, "tool": "run_fleet_scan",
                "error": f"fleet restart failed: {body!r}"}

    # 2. compliance evidence harvest for every known tenant
    ev_summary = {}
    try:
        sys.path.insert(0, soc_dir)  # services/ dir — see note in tool_compliance_report
        from soc_evidence import tool_collect_evidence, tool_evidence_summary
        from soc_routing import get_config
        for tid in get_config().known_tenants():
            try:
                ev = tool_collect_evidence({"tenant_id": tid})
                ev_summary = tool_evidence_summary({"tenant_id": tid})
                steps.append({"step": f"evidence {tid}", "ok": True,
                              "summary": ev_summary})
            except Exception as e:
                steps.append({"step": f"evidence {tid}", "ok": False,
                              "error": repr(e)})
    except Exception as e:
        steps.append({"step": "evidence", "ok": False, "error": repr(e)})

    # 3. fleet-wide score recompute
    scores = {}
    try:
        sys.path.insert(0, soc_dir)  # services/ dir — see note in tool_compliance_report
        from soc_score import tool_score_all_tenants
        scores = tool_score_all_tenants({})
    except Exception as e:
        steps.append({"step": "scores", "ok": False, "error": repr(e)})

    return {
        "ok": True,
        "tool": "run_fleet_scan",
        "steps": steps,
        "scores": scores,
        "ts": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(),
    }


def tool_run_host_compliance_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """run_host_compliance_scan(agent_id) -> MUTATING + moderate.

    Per-host re-run of the compliance pipeline (2026-09-13):
      1. Scoped Wazuh agent restart (fresh syscheck/FIM + vuln detector
         for that host only).
      2. Evidence re-collect for every known tenant (today).
      3. Fleet-wide compliance score recompute.
    Gated on SOC_MANAGER_MCP_ALLOW_MUTATIONS, read from C2 /healthz.
    """
    aid = str(args.get("agent_id") or "").strip()
    if not aid:
        raise ValueError("agent_id is required")
    c2 = os.environ.get("SOC_DASHBOARD_C2_URL", DEFAULT_C2_URL)
    soc_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    steps: List[Dict[str, Any]] = []
    day = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc).strftime("%Y-%m-%d")

    mcode, mbody = _http_get(f"{c2}/healthz", timeout=5.0)
    if mcode != 200 or not isinstance(mbody, dict) \
            or not mbody.get("mutations_enabled"):
        return {"ok": False, "tool": "run_host_compliance_scan",
                "error": "mutations disabled on C2 manager "
                         "(SOC_MANAGER_MCP_ALLOW_MUTATIONS)"}

    code, body = _http_post(f"{c2}/tools/run_scan", {"agent_id": aid},
                            timeout=15.0)
    steps.append({"step": "scoped agent restart", "code": code,
                  "ok": code == 200})
    if code != 200:
        return {"ok": False, "tool": "run_host_compliance_scan",
                "error": f"run_scan failed (HTTP {code})",
                "steps": steps}

    # 2. evidence re-collect for every known tenant
    tenants: List[str] = []
    try:
        sys.path.insert(0, soc_dir)  # services/ dir
        from soc_routing import get_config
        tenants = list(get_config().known_tenants())
    except Exception as e:
        steps.append({"step": "tenant resolution", "ok": False,
                      "error": repr(e)})

    ev: Dict[str, Any] = {}
    try:
        from soc_evidence import tool_collect_evidence
        for tid in tenants:
            try:
                r = tool_collect_evidence({"tenant_id": tid, "day": day})
                ev[tid] = {"counts": r.get("counts"),
                           "total_controls": r.get("total_controls")}
            except Exception as e:
                ev[tid] = {"error": repr(e)}
        steps.append({"step": "evidence re-collect", "ok": True,
                      "tenants": ev})
    except Exception as e:
        steps.append({"step": "evidence re-collect", "ok": False,
                      "error": repr(e)})

    # 3. score recompute
    scores: Dict[str, Any] = {}
    try:
        from soc_score import tool_score_all_tenants
        scores = tool_score_all_tenants({})
    except Exception as e:
        scores = {"error": repr(e)}
    steps.append({"step": "score recompute",
                  "ok": "error" not in scores})

    return {"ok": True, "tool": "run_host_compliance_scan",
            "agent_id": aid, "steps": steps, "scores": scores,
            "tenants_scanned": tenants}


def tool_remediate_control(args: Dict[str, Any]) -> Dict[str, Any]:
    """remediate_control(control_id, tenant_id, confidence, dry_run)
    -> MUTATING.

    E2 STIG auto-remediation for one control (ported 2026-09-14):
    snapshot current state (read-only check) -> confidence/tenant
    gate -> apply the catalogue fix command -> verify with the check
    command. Then re-collect evidence for the tenant (today) and
    recompute its score so the pass grades immediately.

    Layers of gating, in order:
      1. C2 /healthz mutations_enabled (SOC_MANAGER_MCP_ALLOW_MUTATIONS)
         — the same gate as the scan triggers. SKIPPED for dry_run
         (2026-09-16): a dry run changes nothing (read-only check),
         so it may validate the gates while real applies stay
         mutation-gated.
      2. The tenant routing config: `auto_remediate` must be in
         allowed_actions AND auto_remediation_threshold met AND the
         severity eligible.
      3. dry_run (arg or SOC_REMEDIATION_DRY_RUN=1) — no system change.
    Commands run as the dashboard service user; root-needing fixes
    fail honestly (rc recorded) — use the CLI under sudo for those.
    Every apply/rollback writes a snapshot + audit row + remediation
    log entry (the rows soc_evidence grades into PASS evidence)."""
    cid = str(args.get("control_id") or "").strip()
    tid = str(args.get("tenant_id") or "").strip()
    if not cid or not tid:
        raise ValueError("control_id and tenant_id are required")
    dry = bool(args.get("dry_run"))
    c2 = os.environ.get("SOC_DASHBOARD_C2_URL", DEFAULT_C2_URL)
    soc_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    mcode, mbody = _http_get(f"{c2}/healthz", timeout=5.0)
    mutations = bool(mcode == 200 and isinstance(mbody, dict)
                     and mbody.get("mutations_enabled"))
    if not mutations and not dry:
        return {"ok": False, "tool": "remediate_control",
                "error": "mutations disabled on C2 manager "
                         "(SOC_MANAGER_MCP_ALLOW_MUTATIONS)",
                "mutations_enabled": False}
    if soc_dir not in sys.path:
        sys.path.insert(0, soc_dir)
    from soc_stig_remediate import tool_remediate_control as _remediate
    res = _remediate({"control_id": cid, "tenant_id": tid,
                      "confidence": args.get("confidence"),
                      "dry_run": dry,
                      "host": args.get("host"),
                      "host_ip": args.get("host_ip")})
    out: Dict[str, Any] = {"ok": True, "tool": "remediate_control",
                           "remediation": res,
                           "mutations_enabled": mutations}
    if res.get("status") == "applied":
        import datetime as _dt
        day = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
        try:
            from soc_evidence import tool_collect_evidence
            ev = tool_collect_evidence({"tenant_id": tid, "day": day})
            out["evidence"] = {"total_controls": ev.get("total_controls"),
                               "counts": ev.get("counts")}
        except Exception as e:
            out["evidence"] = {"error": repr(e)}
        try:
            from soc_score import tool_compute_score
            out["score"] = tool_compute_score({"tenant_id": tid,
                                               "day": day})
        except Exception as e:
            out["score"] = {"error": repr(e)}
    return out


def _tasklog():
    """Lazy services/soc_tasklog module (services/ on sys.path)."""
    soc_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if soc_dir not in sys.path:
        sys.path.insert(0, soc_dir)
    import soc_tasklog
    return soc_tasklog


# Tasks recorded into the task log (vCenter-style pane): every
# mutating/compliance trigger gets a running + done/failed row.
_TASK_LOGGED_TOOLS = {
    "run_scan": "wazuh_scan",
    "run_host_compliance_scan": "compliance_scan",
    "run_fleet_scan": "compliance_scan",
    "remediate_control": "stig_remediate",
}


def _scan_dir_rows() -> List[Dict[str, Any]]:
    """Synthesize task rows for historic OpenSCAP scans on disk."""
    import hashlib
    base = os.environ.get(
        "SOC_SCAN_RESULTS_DIR",
        os.path.expanduser("~/.openclaw/soc/scans"))
    out: List[Dict[str, Any]] = []
    if not os.path.isdir(base):
        return out
    for day in sorted(os.listdir(base)):
        daydir = os.path.join(base, day)
        if not os.path.isdir(daydir) or not re.match(
                r"^\d{4}-\d{2}-\d{2}$", day):
            continue
        for res in sorted(os.listdir(daydir)):
            if not res.startswith("results-") or not res.endswith(".xml"):
                continue
            host = res[len("results-"):-len(".xml")]
            full = os.path.join(daydir, res)
            try:
                mtime = os.stat(full).st_mtime
            except OSError:
                continue
            ts = __import__("datetime").datetime.fromtimestamp(
                mtime, __import__("datetime").timezone.utc).isoformat()
            report = os.path.join(daydir, f"report-{host}.html")
            out.append({
                "id": hashlib.sha1(
                    f"{ts}|stig_scan|{host}".encode()).hexdigest()[:12],
                "ts": ts, "kind": "stig_scan", "target": host,
                "status": "done", "ended": ts,
                "details": {
                    "results_path": full,
                    "report_url": f"/scans/{day}/report-{host}.html"
                    if os.path.exists(report) else None,
                },
            })
    return out


def tool_tasks_list(args: Dict[str, Any]) -> Dict[str, Any]:
    """tasks_list(limit=100) -> vCenter-style task history: every
    recorded SOC task (compliance scans, agent-restart triggers)
    newest-first, merged with historic OpenSCAP scans on disk."""
    limit = min(int(args.get("limit") or 100), 500)
    rows = list(_tasklog().load_tasks(limit * 2)) + _scan_dir_rows()
    rows.sort(key=lambda r: r.get("ts") or "", reverse=True)
    # a "running" row older than 2h is almost certainly a dead process
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc)
    out = []
    for r in rows[:limit]:
        if r.get("status") == "running":
            try:
                started = _dt.datetime.fromisoformat(
                    (r.get("ts") or "").replace("Z", "+00:00"))
                if now - started > _dt.timedelta(hours=2):
                    r = dict(r, status="timeout")
            except Exception:
                pass
        out.append(r)
    return {"ok": True, "tool": "tasks_list", "tasks": out,
            "total": len(rows)}


def tool_task_get(args: Dict[str, Any]) -> Dict[str, Any]:
    """task_get(id) -> one task row + its history (drill-down)."""
    tid = str(args.get("id") or "").strip()
    if not tid:
        raise ValueError("id is required")
    row = _tasklog().get_task(tid)
    if row is None:
        for r in _scan_dir_rows():
            if r.get("id") == tid:
                row = dict(r, history=[r])
                break
    if row is None:
        return {"ok": False, "tool": "task_get",
                "error": f"unknown task id {tid!r}"}
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    rp = details.get("report_path") or details.get("results_path")
    return {"ok": True, "tool": "task_get",
            "task": dict(row, report_available=bool(rp and os.path.exists(rp)))}


def tool_fleet_status(args: Dict[str, Any]) -> Dict[str, Any]:
    """fleet_status() -> one row per Wazuh agent, plus summary counts.

    Proxies to the C2 manager-mcp `list_agents` for the canonical
    Wazuh-side state (id, name, status, ip, lastKeepAlive, version, os,
    group). Augments each row with:
      - `staleness_seconds`: lastKeepAlive delta (negative means the
        last keepalive is in the future, which means a clock skew
        issue — flagged in the response).
      - `healthy`: True if status == 'active' AND staleness < 300s.

    The dashboard fetches this on /fleet and the JS renders a table.
    The endpoint is intentionally cheap (single C2 call) so the page
    can poll every 30s without putting load on the manager API.

    Falls back to a one-line 'manager unreachable' response on C2 error,
    so the dashboard page still renders and shows 'backend offline'.
    """
    c2 = os.environ.get("SOC_DASHBOARD_C2_URL", DEFAULT_C2_URL)
    code, body = _http_post(f"{c2}/tools/list_agents",
                            {"limit": int(args.get("limit", 100))})
    if code != 200 or not isinstance(body, dict) or not body.get("ok"):
        return {
            "ok": False,
            "tool": "fleet_status",
            "error": f"C2 manager-mcp unreachable: code={code}",
            "manager_url": c2,
            "agents": [],
            "summary": {"total": 0, "active": 0, "stale": 0,
                        "down": 0, "unknown_status": 0,
                        "clock_skew": 0},
        }

    raw_agents = body.get("agents", []) or []
    now = dt.datetime.now(dt.timezone.utc)
    rows: List[Dict[str, Any]] = []
    summary = {"total": len(raw_agents), "active": 0, "stale": 0,
               "down": 0, "unknown_status": 0, "clock_skew": 0}
    for a in raw_agents:
        last_ka = a.get("lastKeepAlive")
        staleness_s: Optional[int] = None
        healthy = False
        clock_skew = False
        if last_ka and last_ka != "9999-12-31T23:59:59+00:00":
            try:
                ka_dt = dt.datetime.fromisoformat(last_ka)
                staleness_s = int((now - ka_dt).total_seconds())
                # Negative staleness => future timestamp => clock skew
                if staleness_s < 0:
                    clock_skew = True
                    summary["clock_skew"] += 1
                elif staleness_s > 300:
                    summary["stale"] += 1
                else:
                    healthy = True
            except (TypeError, ValueError):
                pass
        status = (a.get("status") or "").lower()
        if status == "active":
            if healthy:
                summary["active"] += 1
        elif status in ("disconnected", "down", "never_connected"):
            summary["down"] += 1
        else:
            summary["unknown_status"] += 1
        rows.append({
            "id": a.get("id"),
            "name": a.get("name"),
            "status": a.get("status"),
            "ip": a.get("ip"),
            "version": a.get("version"),
            "os": a.get("os"),
            "group": a.get("group") or [],
            "last_keepalive": last_ka,
            "staleness_seconds": staleness_s,
            "clock_skew": clock_skew,
            "healthy": healthy,
        })

    # Sort by name for stable display
    rows.sort(key=lambda r: (r.get("name") or "").lower())

    return {
        "ok": True,
        "tool": "fleet_status",
        "manager_url": c2,
        "fetched_at": now.isoformat(),
        "agents": rows,
        "summary": summary,
    }


def tool_fleet_summary(args: Dict[str, Any]) -> Dict[str, Any]:
    """fleet_summary() -> condensed fleet status (no per-agent rows).

    Returns just the summary dict from fleet_status, plus the
    realtime_soc_server healthz (alerts_logged, incidents_logged)
    so a single dashboard call covers Wazuh-side + SOC-realtime
    side. Useful for a small 'fleet overview' widget that doesn't
    need the full agent table.
    """
    fs = tool_fleet_status(args)
    rt = os.environ.get("SOC_REALTIME_URL", "http://127.0.0.1:8765")
    rt_code, rt_body = _http_get(f"{rt}/healthz", timeout=2.0)
    rt_summary: Dict[str, Any] = {}
    if rt_code == 200 and isinstance(rt_body, dict) and (
            rt_body.get("ok") is True or rt_body.get("status") == "ok"):
        rt_summary = {
            "alerts_logged": rt_body.get("alerts_logged", 0),
            "incidents_logged": rt_body.get("incidents_logged", 0),
            "alerts_in_memory": rt_body.get("alerts_in_memory", 0),
            "incidents_in_memory": rt_body.get("incidents_in_memory", 0),
            "reachable": True,
        }
    else:
        rt_summary = {"reachable": False, "url": rt}
    return {
        "ok": fs.get("ok", False),
        "tool": "fleet_summary",
        "fleet": fs.get("summary", {}),
        "realtime": rt_summary,
    }


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    server_version = "soc-dashboard/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _log(self, method: str, status: int, ms: float) -> None:
        sys.stderr.write(
            f"[{dt.datetime.now(dt.timezone.utc).isoformat(timespec='milliseconds')}] "
            f"{self.client_address[0]} {method} {self.path} -> {status} "
            f"({ms:.1f}ms)\n")
        sys.stderr.flush()

    def do_GET(self) -> None:  # noqa: N802
        t0 = time.monotonic()
        path = self.path or "/"
        # Strip query string
        path, _, _ = path.partition("?")
        if path == "/healthz":
            self._json(200, self._healthz())
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        if path == "/tools.json":
            self._json(200, {"ok": True, "tools": list(DASHBOARD_TOOLS)})
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        if path == "/tenants.json":
            tenants = _load_routing_tenants() or {}
            self._json(200, {"ok": True, "tenants": tenants})
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        # Static files
        if path == "/" or path == "/index.html":
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            if ".." in rel or rel.startswith("/"):
                self._json(400, {"ok": False, "error": "bad path"})
                self._log("GET", 400, (time.monotonic() - t0) * 1000)
                return
            self._serve_static(rel)
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        # SPA-style routes: serve index.html so the client
        # can render the page.
        if re.match(r"^/(tenants|agents|runs|fleet)/[A-Za-z0-9_.-]+/?$", path):
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        # /scores landing page (E6 compliance scoring)
        if path == "/scores":
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        # /scores/<tenant_id> drill-down
        if re.match(r"^/scores/[A-Za-z0-9_.-]+/?$", path):
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        # /fleet status page (one row per Wazuh agent)
        if path == "/fleet" or path == "/fleet/":
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        # /stig page (E1b STIG findings — Track E compliance)
        if path == "/stig" or path == "/stig/":
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        # /stig/host/<host> drill-down (per-host STIG findings)
        if re.match(r"^/stig/host/[A-Za-z0-9_.-]+/?$", path):
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        # /packages search + /packages/<name> detail + host diff
        if path == "/packages" or path == "/packages/":
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        if re.match(r"^/packages/[A-Za-z0-9+._%()-]+/?$", path):
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        if re.match(r"^/packages-diff/[A-Za-z0-9+._%()-]+/[A-Za-z0-9+._%()-]+/?$",
                    path):
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        # /cve fleet rollup + /cve/<agent> per-host CVE review
        if path == "/cve" or path == "/cve/":
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        if re.match(r"^/cve/[A-Za-z0-9_.-]+/?$", path):
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        # /logs/<agent> — recent Wazuh alerts for one agent (C1 proxy)
        if re.match(r"^/logs/[A-Za-z0-9_.-]+/?$", path):
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        # /tasks page (vCenter-style task history) + drill-down
        if path == "/tasks" or path == "/tasks/":
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        if re.match(r"^/tasks/[A-Za-z0-9_-]+/?$", path):
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        # OpenSCAP scan artifacts: /scans/<day>/report-<host>.html
        m_scans = re.match(
            r"^/scans/(\d{4}-\d{2}-\d{2})/(report-[A-Za-z0-9_.-]+\.html)$",
            path)
        if m_scans:
            base = os.environ.get(
                "SOC_SCAN_RESULTS_DIR",
                os.path.expanduser("~/.openclaw/soc/scans"))
            fpath = os.path.join(base, m_scans.group(1), m_scans.group(2))
            if (os.path.isfile(fpath) and os.path.realpath(fpath).startswith(
                    os.path.realpath(base) + os.sep)):
                with open(fpath, "rb") as fh:
                    body = fh.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                self._log("GET", 200, (time.monotonic() - t0) * 1000)
                return
            self._json(404, {"ok": False, "error": "not found"})
            self._log("GET", 404, (time.monotonic() - t0) * 1000)
            return
        # /tenants, /agents, /tickets SPA landing pages (drilldowns
        # at /<kind>/<id> are matched by the regex below).
        if path in ("/tenants", "/tenants/",
                   "/agents", "/agents/",
                   "/tickets", "/tickets/"):
            self._serve_static("index.html")
            self._log("GET", 200, (time.monotonic() - t0) * 1000)
            return
        self._json(404, {"ok": False, "error": "not found"})
        self._log("GET", 404, (time.monotonic() - t0) * 1000)

    def do_POST(self) -> None:  # noqa: N802
        t0 = time.monotonic()
        path = self.path or "/"
        path, _, _ = path.partition("?")
        m = re.match(r"^/tools/([A-Za-z0-9_]+)$", path)
        if not m:
            self._json(404, {"ok": False, "error": "not found"})
            self._log("POST", 404, (time.monotonic() - t0) * 1000)
            return
        tool = m.group(1)
        if tool not in DASHBOARD_TOOLS:
            self._json(404, {"ok": False, "error": f"unknown tool: {tool}"})
            self._log("POST", 404, (time.monotonic() - t0) * 1000)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            args = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError as e:
            self._json(400, {"ok": False, "error": f"bad json: {e}"})
            return
        impl = {
            "overview": tool_overview,
            "tenant_view": tool_tenant_view,
            "agent_view": tool_agent_view,
            "run_view": tool_run_view,
            "audit_stats_proxy": tool_audit_stats_proxy,
            "tickets_list_proxy": tool_tickets_list_proxy,
            "compliance_score": tool_compliance_score,
            "compliance_scores_all": tool_compliance_scores_all,
            "fleet_status": tool_fleet_status,
            "fleet_summary": tool_fleet_summary,
            "stig_overview": tool_stig_overview,
            "stig_findings": tool_stig_findings,
            "stig_host_view": tool_stig_host_view,
            "host_control_status": tool_host_control_status,
            "fleet_host_view": tool_fleet_host_view,
            "agent_logs": tool_agent_logs,
            "vulnerability_findings": tool_vulnerability_findings,
            "fleet_cve_overview": tool_fleet_cve_overview,
            "packages_search": tool_packages_search,
            "package_diff": tool_package_diff,
            "run_scan": tool_run_scan_proxy,
            "run_host_compliance_scan": tool_run_host_compliance_scan,
            "remediate_control": tool_remediate_control,
            "tasks_list": tool_tasks_list,
            "task_get": tool_task_get,
            "compliance_report": tool_compliance_report,
            "stig_report": tool_stig_report,
            "run_fleet_scan": tool_run_fleet_scan,
        }.get(tool)
        if impl is None:
            # Allowed in DASHBOARD_TOOLS but not dispatchable — fail clean
            # instead of KeyError-aborting the connection.
            self._json(404, {"ok": False, "error": f"unknown tool: {tool}"})
            self._log("POST", 404, (time.monotonic() - t0) * 1000)
            return
        started_ts = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat()
        logged_kind = _TASK_LOGGED_TOOLS.get(tool)
        if logged_kind:
            try:
                _tasklog().record_task(
                    logged_kind,
                    str((args or {}).get("agent_id")
                        or (args or {}).get("host") or (args or {}).get("control_id") or "-"),
                    "running", started_ts)
            except Exception:
                pass
        try:
            result = impl(args)
        except ValueError as e:
            try:
                if logged_kind:
                    _tasklog().record_task(
                        logged_kind,
                        str((args or {}).get("agent_id")
                            or (args or {}).get("host") or (args or {}).get("control_id") or "-"),
                        "failed", started_ts,
                        ended=__import__("datetime").datetime.now(
                            __import__("datetime").timezone.utc).isoformat(),
                        details={"tool": tool, "error": str(e)})
            except Exception:
                pass
            self._json(400, {"ok": False, "error": str(e), "tool": tool})
            self._log("POST", 400, (time.monotonic() - t0) * 1000)
            return
        except Exception as e:
            sys.stderr.write(
                f"[soc-dashboard] unhandled: {e!r}\n{traceback.format_exc()}\n")
            try:
                if logged_kind:
                    _tasklog().record_task(
                        logged_kind,
                        str((args or {}).get("agent_id")
                            or (args or {}).get("host") or (args or {}).get("control_id") or "-"),
                        "failed", started_ts,
                        ended=__import__("datetime").datetime.now(
                            __import__("datetime").timezone.utc).isoformat(),
                        details={"tool": tool, "error": repr(e)[:300]})
            except Exception:
                pass
            self._json(500, {"ok": False, "error": f"internal: {e!r}",
                             "tool": tool})
            self._log("POST", 500, (time.monotonic() - t0) * 1000)
            return
        if logged_kind and isinstance(result, dict):
            try:
                _tasklog().record_task(
                    logged_kind,
                    str((args or {}).get("agent_id")
                        or (args or {}).get("host") or (args or {}).get("control_id") or "-"),
                    "done" if result.get("ok") else "failed",
                    started_ts,
                    ended=__import__("datetime").datetime.now(
                        __import__("datetime").timezone.utc).isoformat(),
                    details={"tool": tool,
                             "fleet_score": (result.get("scores") or {}).get(
                                 "fleet_score")
                             if isinstance(result.get("scores"), dict)
                             else None})
            except Exception:
                pass
        self._json(200, result)
        self._log("POST", 200, (time.monotonic() - t0) * 1000)

    def do_PUT(self) -> None:  # noqa: N802
        self._json(405, {"ok": False,
                         "error": "method not allowed; this dashboard is read-only"})

    def do_DELETE(self) -> None:  # noqa: N802
        self._json(405, {"ok": False, "error": "method not allowed"})

    # ---- helpers ----
    def _healthz(self) -> Dict[str, Any]:
        """Check that the dashboard itself is up, and report
        whether the C4 / C3 backends are reachable. We don't
        fail healthz if they're down — the dashboard can
        still serve pages, they just show "backend offline"."""
        c4 = os.environ.get("SOC_DASHBOARD_C4_URL", DEFAULT_C4_URL)
        c3 = os.environ.get("SOC_DASHBOARD_C3_URL", DEFAULT_C3_URL)
        c4_status, c4_body = _http_get(f"{c4}/healthz", timeout=2.0)
        c3_status, c3_body = _http_get(f"{c3}/healthz", timeout=2.0)
        return {
            "ok": True,
            "server": self.server_version,
            "backends": {
                "soc-audit-mcp": {
                    "url": c4,
                    "reachable": c4_status == 200,
                    "ok": (c4_body.get("ok", False)
                           if isinstance(c4_body, dict) else False),
                },
                "soc-tickets-mcp": {
                    "url": c3,
                    "reachable": c3_status == 200,
                    "ok": (c3_body.get("ok", False)
                           if isinstance(c3_body, dict) else False),
                },
            },
        }

    def _serve_static(self, name: str) -> None:
        path = os.path.join(STATIC_DIR, name)
        if not os.path.exists(path):
            self._json(404, {"ok": False, "error": f"not found: {name}"})
            return
        with open(path, "rb") as f:
            data = f.read()
        if name.endswith(".html"):
            ctype = "text/html; charset=utf-8"
        elif name.endswith(".css"):
            ctype = "text/css; charset=utf-8"
        elif name.endswith(".js"):
            ctype = "application/javascript; charset=utf-8"
        elif name.endswith(".json"):
            ctype = "application/json; charset=utf-8"
        else:
            ctype = "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status: int, body: Dict[str, Any]) -> None:
        try:
            data = json.dumps(body, default=str).encode("utf-8")
        except (TypeError, ValueError) as e:
            data = json.dumps({"ok": False, "error": f"encode: {e}"}).encode("utf-8")
            status = 500
        if len(data) > MAX_RESPONSE_BYTES:
            data = data[:MAX_RESPONSE_BYTES]
            body = {"ok": False, "error": "response truncated", "size": len(data)}
            data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def serve(bind_host: str = DEFAULT_BIND_HOST,
          bind_port: int = DEFAULT_BIND_PORT) -> int:
    srv = ThreadingHTTPServer((bind_host, bind_port), _Handler)
    sys.stderr.write(
        f"[soc-dashboard] listening on http://{bind_host}:{bind_port}/soc/ "
        f"(static={STATIC_DIR}, "
        f"c4={os.environ.get('SOC_DASHBOARD_C4_URL', DEFAULT_C4_URL)})\n")
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("[soc-dashboard] shutting down\n")
        srv.shutdown()
    return 0


def _smoke() -> int:
    """Self-test: bring up the server in a thread, exercise the
    tool layer (the static HTML is trivial and we just check
    it's served). Mock the C4 + C3 HTTP calls by pointing at
    a non-existent URL — the tools should still return
    well-shaped responses (with the backend error in the
    body), not crash."""
    import threading
    import urllib.request as ur

    # Point at a port that's not running anything — the
    # dashboard should still serve its own tools; the
    # backend calls will report 'unreachable' in the body.
    os.environ["SOC_DASHBOARD_C4_URL"] = "http://127.0.0.1:1"
    os.environ["SOC_DASHBOARD_C3_URL"] = "http://127.0.0.1:1"
    os.environ["SOC_DASHBOARD_C2_URL"] = "http://127.0.0.1:1"

    port = 18770
    t = threading.Thread(target=serve, args=("127.0.0.1", port), daemon=True)
    t.start()
    time.sleep(0.5)

    # /healthz
    with ur.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as r:
        body = json.loads(r.read())
        assert body["ok"] is True
        # Backends are pointed at port 1; they should be unreachable.
        assert body["backends"]["soc-audit-mcp"]["reachable"] is False
        assert body["backends"]["soc-tickets-mcp"]["reachable"] is False

    # /tools.json
    with ur.urlopen(f"http://127.0.0.1:{port}/tools.json", timeout=2) as r:
        body = json.loads(r.read())
        assert "overview" in body["tools"]
        assert "tenant_view" in body["tools"]

    # /tenants.json (no PyYAML or no config file -> empty list)
    with ur.urlopen(f"http://127.0.0.1:{port}/tenants.json", timeout=2) as r:
        body = json.loads(r.read())
        assert body["ok"] is True
        # tenants may be empty if PyYAML is missing or config
        # not found; either way the endpoint works.

    # GET / (index.html)
    with ur.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as r:
        assert r.status == 200
        text = r.read().decode("utf-8")
        assert "<html" in text.lower() or "<!doctype" in text.lower()

    # GET /static/app.js
    try:
        with ur.urlopen(f"http://127.0.0.1:{port}/static/app.js",
                        timeout=2) as r:
            assert r.status == 200
            assert len(r.read()) > 100
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise

    # SPA route /tenants/example-soc -> index.html
    with ur.urlopen(f"http://127.0.0.1:{port}/tenants/example-soc",
                    timeout=2) as r:
        assert r.status == 200

    # SPA route /agents/soc-triage
    with ur.urlopen(f"http://127.0.0.1:{port}/agents/soc-triage",
                    timeout=2) as r:
        assert r.status == 200

    # SPA route /runs/some-id
    with ur.urlopen(f"http://127.0.0.1:{port}/runs/abc-123",
                    timeout=2) as r:
        assert r.status == 200

    # SPA route /scores (E6 compliance scoring landing page)
    with ur.urlopen(f"http://127.0.0.1:{port}/scores", timeout=2) as r:
        assert r.status == 200

    # SPA route /scores/example-soc (per-tenant score drill-down)
    with ur.urlopen(f"http://127.0.0.1:{port}/scores/example-soc",
                    timeout=2) as r:
        assert r.status == 200

    # SPA route /stig/host/darth (per-host STIG drill-down)
    with ur.urlopen(f"http://127.0.0.1:{port}/stig/host/darth",
                    timeout=2) as r:
        assert r.status == 200

    # SPA route /fleet (status page — one row per Wazuh agent)
    with ur.urlopen(f"http://127.0.0.1:{port}/fleet", timeout=2) as r:
        assert r.status == 200

    # POST /tools/fleet_status — if C2 is reachable in this
    # env (smoke is run on the SOC host), we get real data;
    # if not, we get a well-shaped unreachable response.
    # Either way, the response is well-shaped.
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/fleet_status",
            data=b"{}", method="POST"), timeout=10) as r:
        body = json.loads(r.read())
        assert "summary" in body, body
        assert "agents" in body, body
        assert isinstance(body["agents"], list), body
        assert isinstance(body["summary"]["total"], int), body
        # ok is True if we reached C2, False if we pointed at port 1.
        # The body shape is identical in both cases.

    # POST /tools/fleet_summary — same dual-path check
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/fleet_summary",
            data=b"{}", method="POST"), timeout=10) as r:
        body = json.loads(r.read())
        assert "fleet" in body, body
        assert "realtime" in body, body
        assert isinstance(body["fleet"], dict), body

    # POST /tools/compliance_scores_all
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/compliance_scores_all",
            data=b"{}", method="POST"), timeout=10) as r:
        body = json.loads(r.read())
        assert body["ok"] is True, body
        assert "tenants" in body, body
        # tenants may be empty if no evidence directory exists;
        # the tool itself should still return ok=True.

    # POST /tools/compliance_score missing tenant_id -> 400
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/compliance_score",
            data=b"{}", method="POST"), timeout=5)
    except urllib.error.HTTPError as e:
        assert e.code == 400
    else:
        raise AssertionError("expected 400 for missing tenant_id")

    # POST /tools/overview (backends unreachable; should
    # still return a well-shaped body, not 5xx)
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/overview",
            data=b"{}", method="POST"), timeout=10) as r:
        body = json.loads(r.read())
        assert body["ok"] is True, body
        # Backends are unreachable; audit_24h is a dict
        # (possibly empty) and tickets_recent is a list.
        assert isinstance(body.get("audit_24h"), dict), body
        assert isinstance(body.get("tickets_recent"), list), body
        assert isinstance(body.get("ticket_total"), int), body

    # POST /tools/tenant_view missing tenant_id -> 400
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/tenant_view",
            data=b"{}", method="POST"), timeout=5)
    except urllib.error.HTTPError as e:
        assert e.code == 400
    else:
        raise AssertionError("expected 400 for missing tenant_id")

    # POST /tools/tenant_view with tenant_id
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/tenant_view",
            data=b'{"tenant_id":"example-soc"}', method="POST"),
            timeout=10) as r:
        body = json.loads(r.read())
        assert body["ok"] is True
        assert body["tenant_id"] == "example-soc"

    # Bad path traversal -> 400
    try:
        ur.urlopen(f"http://127.0.0.1:{port}/static/../server.py",
                   timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 400
    else:
        raise AssertionError("expected 400 for path traversal")

    # PUT/DELETE -> 405
    for m in ("PUT", "DELETE"):
        try:
            ur.urlopen(ur.Request(
                f"http://127.0.0.1:{port}/tools/overview",
                data=b"{}", method=m), timeout=2)
        except urllib.error.HTTPError as e:
            assert e.code == 405, f"{m}: expected 405, got {e.code}"
        else:
            raise AssertionError(f"expected 405 for {m}")

    # Bad tool name -> 404
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/no_such_tool",
            data=b"{}", method="POST"), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 404
    else:
        raise AssertionError("expected 404 for bad tool")

    sys.stdout.write("soc-dashboard smoke test: OK\n")
    return 0


def _main() -> int:
    p = argparse.ArgumentParser(description="SOC web dashboard (Track D, D2)")
    p.add_argument("--bind", default=os.environ.get("SOC_DASHBOARD_BIND",
                                                    DEFAULT_BIND_HOST))
    p.add_argument("--port", type=int, default=int(os.environ.get(
        "SOC_DASHBOARD_PORT", DEFAULT_BIND_PORT)))
    p.add_argument("--smoke", action="store_true")
    args = p.parse_args()
    if args.smoke:
        return _smoke()
    return serve(args.bind, args.port)


if __name__ == "__main__":
    sys.exit(_main())
