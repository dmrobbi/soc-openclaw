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
    # __file__ is soc-dashboard/server.py, so the repo root
    # is 4 levels up: soc-dashboard/ -> soc/ -> scripts/ -> REPO.
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))))
    for path in (os.path.join(repo_root, "config", "soc-routing.yaml"),
                 os.path.join(repo_root, "config",
                              "soc-routing.yaml.example")):
        if os.path.exists(path):
            try:
                with open(path) as f:
                    raw = yaml.safe_load(f)
                tenants = raw.get("tenants") or {}
                return {tid: t.get("display_name", tid)
                        for tid, t in tenants.items()}
            except Exception as e:
                sys.stderr.write(
                    f"[soc-dashboard] routing config load failed: {e}\n")
                return None
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
        if re.match(r"^/(tenants|agents|runs)/[A-Za-z0-9_.-]+/?$", path):
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
        }[tool]
        try:
            result = impl(args)
        except ValueError as e:
            self._json(400, {"ok": False, "error": str(e), "tool": tool})
            self._log("POST", 400, (time.monotonic() - t0) * 1000)
            return
        except Exception as e:
            sys.stderr.write(
                f"[soc-dashboard] unhandled: {e!r}\n{traceback.format_exc()}\n")
            self._json(500, {"ok": False, "error": f"internal: {e!r}",
                             "tool": tool})
            self._log("POST", 500, (time.monotonic() - t0) * 1000)
            return
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
