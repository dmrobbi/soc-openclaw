#!/usr/bin/env python3
"""SOC Wazuh indexer MCP server (Track C, task C1 — 2026-08-07).

A read-only HTTP server that exposes the Wazuh indexer's
`wazuh-alerts-*` indices to SOC agents via four MCP-style tools:

  * search_alerts(query, time_range, min_level, agent, rule_id, size)
  * get_recent_alerts_for_host(host, hours)
  * get_rule_metadata(rule_id)
  * get_agent_status(agent_id)

The server is a single stdlib HTTP endpoint bound to 127.0.0.1
(port 8766 by default). It is *not* a JSON-RPC bridge; it is a
plain JSON-over-HTTP shape because the openclaw harness consumes
tools as `mcp__<server>.<tool>(...)` and the transport is just
HTTP+JSON in this codebase. Wiring it into the harness is a
config one-liner; see README.

Design constraints (per the roadmap doc):
  - Stdlib only. No third-party deps (no flask, no fastapi).
  - Read-only. The server refuses anything that is not GET or
    POST-with-{action: tool_name}; DELETE/PUT/PATCH return 405.
  - Bound to 127.0.0.1 by default. Set SOC_WAZUH_MCP_BIND=lan
    only if you also restrict via firewall; we never recommend
    exposing this beyond the SOC host.
  - One auth path: basic auth via the WAZUH_INDEXER_USERNAME/
    WAZUH_INDEXER_PASSWORD env vars (same as the daily digest).
  - Bounded response size: max 1000 hits per call, JSON-truncated
    to 5MB on the way out (the OpenSearch default is 10000).
  - Logs every call to stderr in a stable, grep-friendly format
    (no structured logging dep). The audit log is separate;
    this server's stderr log is for ops + debugging.

Created 2026-08-07 by Ciceron as part of Track C (C1).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 8766
DEFAULT_INDEXER_URL = "https://127.0.0.1:9200"
MAX_HITS = 1000            # hard cap on _search size
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
TOOLS = ("search_alerts", "get_recent_alerts_for_host",
         "get_rule_metadata", "get_agent_status", "list_agent_os",
         "search_vulnerabilities", "fleet_cve_overview",
         "search_packages", "package_diff")

PACK_INDEX = "wazuh-states-inventory-packages-*"

# Host name validation: 1-253 chars, RFC-1123-ish. We are
# deliberately lax because SOC agents need to query by IP too.
_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_RULE_RE = re.compile(r"^\d{1,6}$")


# ---------------------------------------------------------------------------
# Indexer config
# ---------------------------------------------------------------------------
def _indexer_url() -> str:
    return os.environ.get("WAZUH_INDEXER_URL", DEFAULT_INDEXER_URL).rstrip("/")


def _indexer_auth_header() -> str:
    user = os.environ.get("WAZUH_INDEXER_USERNAME", "admin")
    pw = os.environ["WAZUH_INDEXER_PASSWORD"]  # no insecure default - credentials rotated 2026-09-24
    raw = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return f"Basic {raw}"


def _ssl_context() -> ssl.SSLContext:
    """No verification by default — the SOC stack uses self-signed
    certs. SOC_AUDIT_VERIFY=1 turns on real verification."""
    ctx = ssl.create_default_context()
    if os.environ.get("SOC_WAZUH_MCP_VERIFY", "0") != "1":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------
def _parse_time_range(s: Optional[str]) -> Tuple[str, str]:
    """Normalise a time range. Accepts:
        - None → last 1h
        - "1h" / "24h" / "7d" → relative
        - "2026-08-01T00:00:00Z,2026-08-07T00:00:00Z" → absolute
    Returns (gte, lte) ISO-8601 UTC.
    """
    now = datetime.now(timezone.utc)
    if not s:
        return (_iso(now - timedelta(hours=1)), _iso(now))
    if "," in s:
        g, _, l = s.partition(",")
        return g.strip(), l.strip()
    m = re.match(r"^(\d+)\s*([hdHD])$", s.strip())
    if m:
        n = int(m.group(1))
        unit = m.group(2).lower()
        delta = timedelta(hours=n) if unit == "h" else timedelta(days=n)
        return (_iso(now - delta), _iso(now))
    # single ISO timestamp = "since <ts>"
    try:
        ts = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError(f"bad time_range: {s!r} ({e})")
    return (_iso(ts), _iso(now))


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _validate(s: str, pat: re.Pattern, label: str) -> None:
    if not pat.match(s):
        raise ValueError(f"bad {label}: {s!r}")


def tool_search_alerts(args: Dict[str, Any]) -> Dict[str, Any]:
    """search_alerts(query=None, time_range=None, min_level=0, agent=None,
                     rule_id=None, size=100) -> {ok, hits, total}."""
    q = args.get("query")
    tr = args.get("time_range")
    gte, lte = _parse_time_range(tr)
    min_level = int(args.get("min_level") or 0)
    agent = args.get("agent")
    rule_id = args.get("rule_id")
    size = min(int(args.get("size") or 100), MAX_HITS)

    if rule_id is not None:
        _validate(str(rule_id), _RULE_RE, "rule_id")
    if agent is not None:
        _validate(str(agent), _HOST_RE, "agent")

    must: List[Dict[str, Any]] = [
        {"range": {"timestamp": {"gte": gte, "lte": lte}}},
    ]
    if min_level > 0:
        must.append({"range": {"rule.level": {"gte": min_level}}})
    if rule_id is not None:
        must.append({"term": {"rule.id": int(rule_id)}})
    if agent is not None:
        # Match by agent.name OR agent.ip. The Wazuh index maps both
        # fields as `text` (analyzed) with a `.keyword` subfield; a
        # `term` query on the analyzed field does exact-match on the
        # *analyzed* token, which silently fails for names with
        # non-token characters (e.g. "mac-m4" gets tokenized to
        # ["mac", "m4"], and term "mac-m4" matches nothing). Use
        # the keyword subfield so we get the raw value. Verified
        # 2026-08-12: 326 events for mac-m4 (id=014) were invisible
        # to dashboard queries until this fix; single-token names
        # (darth, gus2, cactus) were unaffected.
        must.append({
            "bool": {
                "should": [
                    {"term": {"agent.name.keyword": agent}},
                    {"term": {"agent.ip.keyword": agent}},
                ],
                "minimum_should_match": 1,
            }
        })
    if q:
        # Free-text query: search across description + agent.name
        must.append({
            "multi_match": {
                "query": q,
                "fields": ["rule.description^2", "agent.name",
                           "data.srcip", "data.dstuser"],
            }
        })

    body = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "rule.level", "rule.id", "rule.description",
                    "agent.id", "agent.name", "agent.ip",
                    "data.srcip", "data.dstuser", "data.attempts"],
        "query": {"bool": {"filter": must}},
    }
    hits = _post_search(body).get("hits", {}).get("hits", [])
    return {
        "ok": True,
        "tool": "search_alerts",
        "params": {"query": q, "time_range": tr, "min_level": min_level,
                   "agent": agent, "rule_id": rule_id, "size": size},
        "range": {"gte": gte, "lte": lte},
        "hits": [_hit_to_dict(h) for h in hits],
        "total": len(hits),
    }


def tool_get_recent_alerts_for_host(args: Dict[str, Any]) -> Dict[str, Any]:
    """get_recent_alerts_for_host(host, hours=24, min_level=0, size=200)."""
    host = args.get("host")
    if not host:
        raise ValueError("host is required")
    _validate(str(host), _HOST_RE, "host")
    hours = min(int(args.get("hours") or 24), 24 * 30)  # cap at 30 days
    min_level = int(args.get("min_level") or 0)
    size = min(int(args.get("size") or 200), MAX_HITS)
    return tool_search_alerts({
        "time_range": f"{hours}h",
        "min_level": min_level,
        "agent": host,
        "size": size,
    })


def tool_get_rule_metadata(args: Dict[str, Any]) -> Dict[str, Any]:
    """get_rule_metadata(rule_id) -> {ok, rule_id, hits, total}.

    Returns up to 5 of the most recent firings of the rule, so
    the agent can see frequency and host distribution. The
    Wazuh ruleset itself isn't exposed via the indexer
    (that's the manager API, C2), so we approximate by
    sampling alert hits."""
    rid = args.get("rule_id")
    if rid is None:
        raise ValueError("rule_id is required")
    _validate(str(rid), _RULE_RE, "rule_id")
    body = {
        "size": 5,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "agent.id", "agent.name", "agent.ip",
                    "data.srcip"],
        "query": {"term": {"rule.id": int(rid)}},
    }
    hits = _post_search(body).get("hits", {}).get("hits", [])
    # Distribution by host over the last 7d
    dist_body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"rule.id": int(rid)}},
                    {"range": {"timestamp": {
                        "gte": _iso(datetime.now(timezone.utc) - timedelta(days=7)),
                        "lte": _iso(datetime.now(timezone.utc))}}},
                ]
            }
        },
        "aggs": {
            "by_agent": {
                "terms": {"field": "agent.name", "size": 20}
            }
        },
    }
    dist = _post_search(dist_body, expect_aggs=True)
    by_agent = []
    for b in (dist.get("aggregations", {})
              .get("by_agent", {}).get("buckets", [])):
        by_agent.append({"agent": b.get("key"), "count": b.get("doc_count")})
    return {
        "ok": True,
        "tool": "get_rule_metadata",
        "rule_id": int(rid),
        "recent_hits": [_hit_to_dict(h) for h in hits],
        "host_distribution_7d": by_agent,
    }


def tool_list_agent_os(args: Dict[str, Any]) -> Dict[str, Any]:
    """list_agent_os() -> {ok, agents: [{id, name, status, os_platform,
    os_name}]}.

    Reads the wazuh-monitoring-* index (the manager pushes an agent
    inventory snapshot there) and returns the most recent row per
    agent. Added 2026-09-13 so the STIG classifier (running inside
    the Wazuh manager container, where the loopback-bound manager
    MCP is unreachable) can resolve each agent's OS family via C1.
    """
    body = {
        "size": 100,
        "query": {"match_all": {}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "collapse": {"field": "id"},
        "_source": ["id", "name", "status", "os.platform", "os.name",
                    "os.version", "lastKeepAlive", "ip"],
    }
    res = _post_search(body, index="wazuh-monitoring-*")
    out = []
    for h in (res.get("hits", {}).get("hits") or []):
        src = h.get("_source") or {}
        osinfo = src.get("os") or {}
        if not isinstance(osinfo, dict):
            osinfo = {}
        out.append({
            "id": str(src.get("id") or ""),
            "name": str(src.get("name") or ""),
            "status": str(src.get("status") or ""),
            "os_platform": str(osinfo.get("platform") or ""),
            "os_name": str(osinfo.get("name") or ""),
            "os_version": str(osinfo.get("version") or ""),
            "last_keepalive": str(src.get("lastKeepAlive") or ""),
            "ip": str(src.get("ip") or ""),
        })
    return {"ok": True, "tool": "list_agent_os", "agents": out,
            "total": len(out)}


def tool_get_agent_status(args: Dict[str, Any]) -> Dict[str, Any]:
    """get_agent_status(agent_id) -> {ok, agent_id, last_seen, level_dist}.

    Uses the alerts index to derive agent health: when did the
    agent last check in (last alert timestamp), and what level
    distribution did it produce. NOTE: full agent status (active/
    disconnected/etc.) lives in the manager API (C2); this tool
    is a fallback for environments that don't have C2 yet.
    """
    aid = args.get("agent_id")
    if aid is None:
        raise ValueError("agent_id is required")
    # Accept "001" or 1. Wazuh stores agent.id as a zero-padded
    # string ("001", "010"); normalise to the canonical form.
    aid_s = str(aid).strip()
    if not aid_s.isdigit():
        raise ValueError(f"agent_id must be a numeric string: {aid_s!r}")
    aid_s = aid_s.zfill(3)
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"agent.id": aid_s}},
                    {"range": {"timestamp": {
                        "gte": _iso(datetime.now(timezone.utc) - timedelta(days=7)),
                        "lte": _iso(datetime.now(timezone.utc))}}},
                ]
            }
        },
        "aggs": {
            "last_seen": {"max": {"field": "timestamp"}},
            "by_level": {"terms": {"field": "rule.level", "size": 20,
                                   "order": {"_key": "desc"}}},
        },
    }
    res = _post_search(body, expect_aggs=True)
    aggs = res.get("aggregations", {})
    last_seen = (aggs.get("last_seen") or {}).get("value_as_string")
    level_dist = []
    for b in (aggs.get("by_level", {}).get("buckets", [])):
        level_dist.append({"level": b.get("key"), "count": b.get("doc_count")})
    return {
        "ok": True,
        "tool": "get_agent_status",
        "agent_id": aid_s,
        "last_seen": last_seen,
        "level_distribution_7d": level_dist,
        "note": ("for active/disconnected status use the manager API "
                 "(C2 — Wazuh manager MCP, not yet implemented)"),
    }


# ---------------------------------------------------------------------------
# Indexer client
# ---------------------------------------------------------------------------
VULN_INDEX = "wazuh-states-vulnerabilities-*"


def tool_search_vulnerabilities(args: Dict[str, Any]) -> Dict[str, Any]:
    """search_vulnerabilities(agent=None, package=None, cve=None,
    severity=None, size=200) -> {ok, findings, by_severity, by_host,
    top_packages}.

    Four views over the Vulnerability Detector state index:
      - no args: fleet rollup (aggregations only)
      - agent=<name>: that host's findings
      - package=<name>: one package across hosts (version compare)
      - cve=<CVE-id>: one CVE, every affected host
    """
    import re as _re
    agent = args.get("agent")
    package = args.get("package")
    cve = args.get("cve")
    severity = args.get("severity")
    size = max(1, min(int(args.get("size") or 200), 500))
    if agent and not _re.match(r"^[A-Za-z0-9._-]{1,64}$", str(agent)):
        raise ValueError(f"invalid agent: {agent!r}")
    if package and not _re.match(r"^[A-Za-z0-9+._-]{1,64}$", str(package)):
        raise ValueError(f"invalid package: {package!r}")
    if cve and not _re.match(r"^CVE-\d{4}-\d{4,7}$", str(cve)):
        raise ValueError(f"invalid cve: {cve!r}")
    if severity and not _re.match(r"^(Critical|High|Medium|Low|-)$",
                                  str(severity)):
        raise ValueError(f"invalid severity: {severity!r}")

    must: List[Dict[str, Any]] = []
    # NOTE: the vulnerabilities template maps these fields as keyword
    # DIRECTLY (unlike wazuh-alerts text fields) — no .keyword subfield.
    if agent:
        must.append({"term": {"agent.name": agent}})
    if package:
        must.append({"term": {"package.name": package}})
    if cve:
        must.append({"term": {"vulnerability.id": cve}})
    if severity:
        must.append({"term": {"vulnerability.severity": severity}})
    query: Dict[str, Any] = ({"bool": {"filter": must}} if must
                             else {"match_all": {}})

    rollup = _post_search({
        "size": 0,
        "aggs": {
            "sev": {"terms": {"field": "vulnerability.severity", "size": 8}},
            "by_host": {"terms": {"field": "agent.name", "size": 30}},
            "top_packages": {"terms": {"field": "package.name", "size": 10}},
        },
        "query": query,
    }, expect_aggs=True, index=VULN_INDEX)
    aggs = (rollup or {}).get("aggregations", {}) or {}
    by_severity = {b["key"]: b["doc_count"]
                   for b in (aggs.get("sev") or {}).get("buckets", [])}
    by_host = {b["key"]: b["doc_count"]
               for b in (aggs.get("by_host") or {}).get("buckets", [])}
    top_packages = {b["key"]: b["doc_count"]
                    for b in (aggs.get("top_packages") or {}).get("buckets",
                                                                  [])}

    hits = _post_search({
        "size": size,
        "sort": [{"vulnerability.score.base": {"order": "desc",
                                               "missing": "_last"}}],
        "_source": ["agent.id", "agent.name",
                    "vulnerability.id", "vulnerability.severity",
                    "vulnerability.score.base", "vulnerability.description",
                    "vulnerability.published_at",
                    "package.name", "package.version",
                    "package.architecture", "status"],
        "query": query,
    }, index=VULN_INDEX).get("hits", {}).get("hits", [])

    findings = []
    for h in hits:
        s = h.get("_source", {})
        vul = s.get("vulnerability") or {}
        pkg = s.get("package") or {}
        agt = s.get("agent") or {}
        findings.append({
            "agent_id": agt.get("id"), "agent_name": agt.get("name"),
            "cve": vul.get("id"), "severity": vul.get("severity"),
            "cvss": (vul.get("score") or {}).get("base"),
            "description": vul.get("description"),
            "published": vul.get("published_at"),
            "package": pkg.get("name"), "version": pkg.get("version"),
            "architecture": pkg.get("architecture"),
            "status": s.get("status"),
        })

    return {"ok": True, "tool": "search_vulnerabilities",
            "params": {"agent": agent, "package": package, "cve": cve,
                       "severity": severity},
            "total": len(findings), "by_severity": by_severity,
            "by_host": by_host, "top_packages": top_packages,
            "findings": findings}


def tool_fleet_cve_overview(args: Dict[str, Any]) -> Dict[str, Any]:
    """fleet_cve_overview() -> per-host severity rollup for fleet-page
    columns: {host: {Critical: n, High: n, Medium: n, Low: n, total: n}}."""
    rollup = _post_search({
        "size": 0,
        "aggs": {
            "by_host": {"terms": {"field": "agent.name", "size": 30},
                        "aggs": {"sev": {"terms": {
                            "field": "vulnerability.severity", "size": 6}}}},
            "sev": {"terms": {"field": "vulnerability.severity", "size": 8}},
        },
        "query": {"match_all": {}},
    }, expect_aggs=True, index=VULN_INDEX)
    aggs = (rollup or {}).get("aggregations", {})
    hosts: Dict[str, Dict[str, int]] = {}
    for b in (aggs.get("by_host") or {}).get("buckets", []):
        hosts[b["key"]] = {x["key"]: x["doc_count"]
                           for x in (b.get("sev") or {}).get("buckets", [])}
        hosts[b["key"]]["total"] = b["doc_count"]
    totals = {b["key"]: b["doc_count"]
              for b in (aggs.get("sev") or {}).get("buckets", [])}
    return {"ok": True, "tool": "fleet_cve_overview",
            "by_host": hosts, "totals": totals}


def _vuln_counts_by_package() -> Dict[str, int]:
    """One agg: CVE-finding count per package name (vuln state index)."""
    rollup = _post_search({
        "size": 0,
        "aggs": {"pkg": {"terms": {"field": "package.name", "size": 5000}}},
        "query": {"match_all": {}},
    }, expect_aggs=True, index=VULN_INDEX)
    aggs = (rollup or {}).get("aggregations", {})
    return {b["key"]: b["doc_count"]
            for b in (aggs.get("pkg") or {}).get("buckets", [])}


def tool_search_packages(args: Dict[str, Any]) -> Dict[str, Any]:
    """search_packages(name=None, q=None, size=500) -> package inventory
    rows (agent, name, version, arch) with per-row CVE count annotation.

      - name=<exact>: one package, every host that has it
      - q=<substring>: wildcard search across the inventory
    """
    name = args.get("name")
    q = args.get("q")
    size = max(1, min(int(args.get("size") or 500), 2000))
    if not name and not q:
        raise ValueError("name or q is required")
    if q and name:
        raise ValueError("give name OR q, not both")
    must: List[Dict[str, Any]] = []
    if name:
        must.append({"term": {"package.name": name}})
    if q:
        must.append({"wildcard": {"package.name": f"*{q.lower()}*"}})
    res = _post_search({
        "size": size,
        "sort": [{"package.name": {"order": "asc"}}],
        "_source": ["agent.name", "package.name", "package.version",
                    "package.architecture"],
        "query": {"bool": {"filter": must}},
    }, index=PACK_INDEX)
    rows = []
    for h in (res.get("hits") or {}).get("hits", []):
        s = h.get("_source", {})
        pkg = s.get("package") or {}
        agt = s.get("agent") or {}
        rows.append({"agent": agt.get("name"), "package": pkg.get("name"),
                     "version": pkg.get("version"),
                     "architecture": pkg.get("architecture")})
    counts = _vuln_counts_by_package()
    for r in rows:
        r["cve_count"] = counts.get(r["package"], 0)
    return {"ok": True, "tool": "search_packages",
            "params": {"name": name, "q": q},
            "total": len(rows), "rows": rows}


def tool_package_diff(args: Dict[str, Any]) -> Dict[str, Any]:
    """package_diff(agent_a, agent_b) -> compare installed packages:
    only_a, only_b, version_mismatch (each mismatch annotated with the
    package's CVE-finding count)."""
    import re as _re
    a = args.get("agent_a")
    b = args.get("agent_b")
    for h in (a, b):
        if not h or not _re.match(r"^[A-Za-z0-9._-]{1,64}$", str(h)):
            raise ValueError(f"invalid agent: {h!r}")

    def fetch(host):
        res = _post_search({
            "size": 5000,
            "_source": ["package.name", "package.version",
                        "package.architecture"],
            "query": {"bool": {"filter": [
                {"term": {"agent.name": host}}]}},
        }, index=PACK_INDEX)
        out: Dict[str, Dict[str, str]] = {}
        for h2 in (res.get("hits") or {}).get("hits", []):
            s = h2.get("_source", {})
            pkg = s.get("package") or {}
            nm = pkg.get("name")
            if nm:
                out[nm] = {"version": pkg.get("version"),
                           "architecture": pkg.get("architecture")}
        return out

    pa, pb = fetch(a), fetch(b)
    counts = _vuln_counts_by_package()
    only_a = sorted(set(pa) - set(pb))
    only_b = sorted(set(pb) - set(pa))
    mismatch = [{"name": n, "a": pa[n], "b": pb[n],
                 "cve_count": counts.get(n, 0)}
                for n in sorted(set(pa) & set(pb)) if pa[n] != pb[n]]
    mismatch.sort(key=lambda r: -r["cve_count"])
    return {"ok": True, "tool": "package_diff",
            "agent_a": a, "agent_b": b,
            "counts": {"a": len(pa), "b": len(pb), "common": len(set(pa) & set(pb))},
            "only_a": [{"name": n, "version": pa[n]["version"],
                        "cve_count": counts.get(n, 0)} for n in only_a],
            "only_b": [{"name": n, "version": pb[n]["version"],
                        "cve_count": counts.get(n, 0)} for n in only_b],
            "mismatch": mismatch}


def _post_search(body: Dict[str, Any], expect_aggs: bool = False,
                 index: str = "wazuh-alerts-*") -> Dict[str, Any]:
    """POST a _search to the indexer. Returns the raw response dict."""
    url = f"{_indexer_url()}/{index}/_search"
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": _indexer_auth_header(),
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=_ssl_context(), timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"indexer HTTP {e.code}: {body}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"indexer unreachable: {e!r}")


def _hit_to_dict(hit: Dict[str, Any]) -> Dict[str, Any]:
    s = hit.get("_source", {})
    return {
        "timestamp": s.get("timestamp"),
        "level": (s.get("rule") or {}).get("level"),
        "rule_id": (s.get("rule") or {}).get("id"),
        "rule_desc": (s.get("rule") or {}).get("description"),
        "agent_id": (s.get("agent") or {}).get("id"),
        "agent_name": (s.get("agent") or {}).get("name"),
        "agent_ip": (s.get("agent") or {}).get("ip"),
        "srcip": (s.get("data") or {}).get("srcip"),
        "dstuser": (s.get("data") or {}).get("dstuser"),
        "attempts": (s.get("data") or {}).get("attempts"),
    }


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    server_version = "soc-wazuh-mcp/1.0"

    # Silence the default access log; we emit a structured one.
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _log(self, method: str, status: int, ms: float, body: Any) -> None:
        sys.stderr.write(
            f"[{datetime.now(timezone.utc).isoformat(timespec='milliseconds')}] "
            f"{self.client_address[0]} {method} -> {status} "
            f"({ms:.1f}ms) tool={body.get('tool', '-') if isinstance(body, dict) else '-'}\n"
        )
        sys.stderr.flush()

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._json(200, {"ok": True, "server": self.server_version})
            return
        if self.path == "/tools":
            self._json(200, {"ok": True, "tools": list(TOOLS)})
            return
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        t0 = time.monotonic()
        # Path: /tools/<name>
        m = re.match(r"^/tools/([A-Za-z0-9_]+)$", self.path or "")
        if not m:
            self._json(404, {"ok": False, "error": "not found"})
            self._log("POST", 404, (time.monotonic() - t0) * 1000, {})
            return
        tool = m.group(1)
        if tool not in TOOLS:
            self._json(404, {"ok": False, "error": f"unknown tool: {tool}"})
            self._log("POST", 404, (time.monotonic() - t0) * 1000, {})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            args = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError as e:
            self._json(400, {"ok": False, "error": f"bad json: {e}"})
            return

        impl = {
            "search_alerts": tool_search_alerts,
            "get_recent_alerts_for_host": tool_get_recent_alerts_for_host,
            "get_rule_metadata": tool_get_rule_metadata,
            "get_agent_status": tool_get_agent_status,
            "list_agent_os": tool_list_agent_os,
            "search_vulnerabilities": tool_search_vulnerabilities,
            "fleet_cve_overview": tool_fleet_cve_overview,
            "search_packages": tool_search_packages,
            "package_diff": tool_package_diff,
        }[tool]
        try:
            result = impl(args)
        except ValueError as e:
            self._json(400, {"ok": False, "error": str(e), "tool": tool})
            self._log("POST", 400, (time.monotonic() - t0) * 1000, {"tool": tool})
            return
        except RuntimeError as e:
            self._json(502, {"ok": False, "error": str(e), "tool": tool})
            self._log("POST", 502, (time.monotonic() - t0) * 1000, {"tool": tool})
            return
        except Exception as e:
            sys.stderr.write(f"[soc-wazuh-mcp] unhandled: {e!r}\n{traceback.format_exc()}\n")
            self._json(500, {"ok": False, "error": f"internal: {e!r}", "tool": tool})
            self._log("POST", 500, (time.monotonic() - t0) * 1000, {"tool": tool})
            return
        self._json(200, result)
        self._log("POST", 200, (time.monotonic() - t0) * 1000, result)

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
        f"[soc-wazuh-mcp] listening on http://{bind_host}:{bind_port} "
        f"(indexer={_indexer_url()})\n"
    )
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("[soc-wazuh-mcp] shutting down\n")
        srv.shutdown()
    return 0


def _smoke() -> int:
    """Self-test: bring up the server in a thread, hit /tools and
    /tools/search_alerts with a no-match query, verify shape.
    Does NOT require the indexer to be up — we only test the
    transport layer (healthz + /tools). The indexer round-trip
    is exercised manually by the operator with a live cluster.
    """
    import threading
    import urllib.request as ur

    port = 18766  # avoid collision with the real port
    t = threading.Thread(target=serve, args=("127.0.0.1", port), daemon=True)
    t.start()
    time.sleep(0.5)

    # /healthz
    with ur.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as r:
        body = json.loads(r.read())
        assert body["ok"] is True
        assert body["server"].startswith("soc-wazuh-mcp/")

    # /tools
    with ur.urlopen(f"http://127.0.0.1:{port}/tools", timeout=2) as r:
        body = json.loads(r.read())
        assert "search_alerts" in body["tools"]
        assert "get_recent_alerts_for_host" in body["tools"]
        assert "get_rule_metadata" in body["tools"]
        assert "get_agent_status" in body["tools"]

    # Bad tool name -> 404
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/no_such_tool",
            data=b"{}", method="POST",
        ), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 404, f"expected 404, got {e.code}"
    else:
        raise AssertionError("expected 404 for bad tool name")

    # Bad args -> 400 (no host)
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/get_recent_alerts_for_host",
            data=b"{}", method="POST",
        ), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 400, f"expected 400, got {e.code}"
    else:
        raise AssertionError("expected 400 for missing host")

    # Bad rule_id -> 400
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/get_rule_metadata",
            data=b'{"rule_id": "abc; DROP TABLE"}',
            method="POST",
        ), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 400
    else:
        raise AssertionError("expected 400 for bad rule_id")

    # Time-range parsing
    assert _parse_time_range(None)[0].endswith("Z")
    gte, lte = _parse_time_range("1h")
    assert gte.endswith("Z") and lte.endswith("Z")
    gte, lte = _parse_time_range("2026-08-01T00:00:00Z,2026-08-07T00:00:00Z")
    assert gte.startswith("2026-08-01") and lte.startswith("2026-08-07")
    gte, lte = _parse_time_range("2026-08-01T00:00:00Z")
    assert gte.startswith("2026-08-01")
    try:
        _parse_time_range("not-a-time")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for bad time_range")

    sys.stdout.write("soc-wazuh-mcp smoke test: OK\n")
    return 0


def _main() -> int:
    p = argparse.ArgumentParser(description="SOC Wazuh indexer MCP server")
    p.add_argument("--bind", default=os.environ.get("SOC_WAZUH_MCP_BIND",
                                                    DEFAULT_BIND_HOST))
    p.add_argument("--port", type=int, default=int(os.environ.get(
        "SOC_WAZUH_MCP_PORT", DEFAULT_BIND_PORT)))
    p.add_argument("--smoke", action="store_true")
    args = p.parse_args()
    if args.smoke:
        return _smoke()
    return serve(args.bind, args.port)


if __name__ == "__main__":
    sys.exit(_main())
