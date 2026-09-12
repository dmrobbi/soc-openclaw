#!/usr/bin/env python3
"""SOC audit-log MCP server (Track C, task C4 — 2026-08-08).

A stdlib HTTP server that exposes the SOC audit log
(`~/.openclaw/audit_log.jsonl` by default) to SOC agents as
MCP-style tools. The audit log is the canonical record of every
LLM-driven SOC decision (produced by `soc_audit.record()` in
`soc_audit.py`). It is the input to the daily curator
(`soc_memory_curator.py`) and the source of truth for the
replay harness.

The MCP exists so external agents (notably `soc-incident-reviewer`
and the post-incident narrative tools) can ask "what did the
triage agent decide for run X?" or "show me every decision the
system made about host Y in the last 24h" without reading the
file directly. It is read-mostly: the only mutating tool is
`annotate_run`, which appends a non-destructive annotation to
`extra.annotations[]` (the underlying record is never edited).

Tools
-----
  * query_audit(agent_id=None, run_id=None, tenant_id=None,
                input_kind=None, time_range=None, has_tool_calls=False,
                search=None, limit=100, offset=0)
        -> {ok, hits[], total, params}
  * get_run(run_id)
        -> {ok, run_id, records: [...]} (a single runId can
           produce multiple records — one per sub-call, e.g.
           the delegated chain from soc_decision -> soc-comms
           shares parent_run_id)
  * get_record(record_ts, run_id, agent_id)
        -> {ok, record} (locates the exact record; ts is
           millisecond-precision and is the natural key)
  * annotate_run(record_ts, run_id, agent_id, author, note,
                 tags=None)
        -> {ok, record_ts, annotation_index, total_annotations}
        MUTATING (append-only). Refused if the audit log is
        read-only (chmod a-w on the file).
  * audit_stats(time_range=None)
        -> {ok, total, by_agent, by_input_kind, by_outcome,
            time_range}

The server is a single stdlib HTTP endpoint bound to 127.0.0.1
(port 8769 by default). The transport is plain JSON-over-HTTP
(same shape as the rest of the SOC MCP servers). Wiring it
into the openclaw harness is a one-liner in the agent config.

Design constraints
------------------
  - Stdlib only. No third-party deps.
  - Read-mostly. The only mutating tool is `annotate_run`,
    and it is append-only on `extra.annotations[]` — the
    underlying record's other fields are never modified.
  - Bound to 127.0.0.1 by default. Set
    `SOC_AUDIT_MCP_BIND=lan` only behind a firewall.
  - Capped response size: 5 MB.
  - The audit log is read line-by-line on every query (the
    file is small — 441 records as of 2026-08-08 — and this
    keeps the design hermetic). For very large logs we can
    add an in-memory index later; the tool shape doesn't
    change.
  - The default path is `~/.openclaw/audit_log.jsonl`,
    matching `soc_audit.default_path()`. Override with
    `SOC_AUDIT_LOG`.

Created 2026-08-08 by Ciceron as part of Track C (C4).
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
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 8769
DEFAULT_AUDIT_PATH = os.path.expanduser("~/.openclaw/audit_log.jsonl")
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_RECORDS_LOAD = 50_000  # safety cap on line-by-line read

# Canonical NIST SP 800-53 control families that appear in the
# DISA OS-level STIG catalogues we ingest (RHEL 9 + Ubuntu 22.04
# V2Rx — see config/stig-catalogue-disa*.json). Order is the
# canonical NIST ordering (AC..SR). Used by
# query_stig_findings to seed `by_nist_family` with 0-count
# entries so the dashboard always renders the full set.
NIST_800_53_FAMILIES: Tuple[str, ...] = (
    "AC", "AU", "CM", "CP", "IA", "IR", "MA", "MP",
    "PE", "PL", "PM", "RA", "SA", "SC", "SI", "SR",
)

# Default C2 manager-mcp endpoint for the monitored-hosts probe.
# Override with SOC_AUDIT_MCP_C2_URL. The probe is fail-soft:
# if the manager is unreachable, monitored_hosts falls back to
# the keys already present in by_host so the dashboard still
# renders rather than dropping the section entirely.
DEFAULT_C2_URL = "http://127.0.0.1:8767"
DEFAULT_MONITORED_HOSTS_TIMEOUT_S = 2.0
TOOLS = (
    "query_audit",
    "get_run",
    "get_record",
    "annotate_run",
    "audit_stats",
    "query_stig_findings",
)

def _fetch_monitored_hosts() -> Tuple[List[str], Dict[str, str]]:
    """Return ([host_name, ...], {host_name: status}) from the
    C2 soc-manager-mcp `list_agents` tool.

    The probe is fail-soft: a C2 outage (timeout, 5xx, refused)
    returns ([], {}) so the caller can decide. The manager
    daemon itself (agent id 000, name="wazuh.manager") is
    filtered out — it's the C2 source, not a monitored host.

    Used by query_stig_findings to seed `by_host` with
    0-count entries so the dashboard renders every monitored
    host, not just the ones with findings in the window.
    """
    url = os.environ.get("SOC_AUDIT_MCP_C2_URL", DEFAULT_C2_URL)
    payload = json.dumps({"tool": "list_agents",
                          "args": {"limit": 200}}).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + "/tools/list_agents",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(
            req,
            timeout=float(os.environ.get(
                "SOC_AUDIT_MCP_MONITORED_TIMEOUT_S",
                str(DEFAULT_MONITORED_HOSTS_TIMEOUT_S))),
        ) as r:
            body = json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError,
            json.JSONDecodeError, OSError) as e:
        sys.stderr.write(
            f"[soc-audit-mcp] monitored-hosts probe failed: {e}\n")
        return [], {}
    if not body.get("ok"):
        return [], {}
    agents = body.get("agents") or []
    names: List[str] = []
    statuses: Dict[str, str] = {}
    for a in agents:
        name = a.get("name")
        if not name or name == "wazuh.manager":
            continue
        names.append(name)
        statuses[name] = a.get("status") or "unknown"
    names.sort()
    return names, statuses


_RUN_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9_:.-]{1,64}$")
_TENANT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_INPUT_KIND_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:?\d{2}|Z)$")


# ---------------------------------------------------------------------------
# Audit log access
# ---------------------------------------------------------------------------
def _audit_path() -> str:
    p = os.environ.get("SOC_AUDIT_LOG", DEFAULT_AUDIT_PATH)
    return os.path.expanduser(p)


def _load_all() -> List[Dict[str, Any]]:
    """Read the audit log line-by-line. Skips blank lines and
    non-JSON lines; returns the parsed records. The file is
    append-only by design; the worst case is a few thousand
    records (currently 441)."""
    path = _audit_path()
    if not os.path.exists(path):
        return []
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if len(out) >= MAX_RECORDS_LOAD:
                break
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                # Skip corrupt lines but log to stderr.
                sys.stderr.write(
                    f"[soc-audit-mcp] skipping non-JSON line at {path}:{i+1}\n")
    return out


def _parse_time_range(s: Optional[str]) -> Optional[Tuple[str, str]]:
    """Normalise a time range like in soc-wazuh-mcp:
        - None → None (no filter)
        - "1h" / "24h" / "7d" → relative
        - "2026-08-01T00:00:00Z,2026-08-07T00:00:00Z" → absolute
        - "2026-08-01T00:00:00Z" → since
    Returns (gte, lte) ISO-8601 UTC, or None."""
    if not s:
        return None
    now = dt.datetime.now(dt.timezone.utc)
    if "," in s:
        g, _, l = s.partition(",")
        return g.strip(), l.strip()
    m = re.match(r"^(\d+)\s*([hdHD])$", s.strip())
    if m:
        n = int(m.group(1))
        unit = m.group(2).lower()
        delta = dt.timedelta(hours=n) if unit == "h" else dt.timedelta(days=n)
        return (_iso(now - delta), _iso(now))
    try:
        ts = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError(f"bad time_range: {s!r} ({e})")
    return (_iso(ts), _iso(now))


def _iso(d: dt.datetime) -> str:
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _validate(value: str, pat: re.Pattern, label: str) -> None:
    if not pat.match(value):
        raise ValueError(f"bad {label}: {value!r}")


def _match(rec: Dict[str, Any], args: Dict[str, Any]) -> bool:
    """Predicate: does this record match the query args?"""
    aid = args.get("agent_id")
    if aid and rec.get("agent_id") != aid:
        return False
    rid = args.get("run_id")
    if rid and rec.get("runId") != rid:
        return False
    ten = args.get("tenant_id")
    if ten and rec.get("tenant_id") != ten:
        return False
    ik = args.get("input_kind")
    if ik and rec.get("input_kind") != ik:
        return False
    htc = args.get("has_tool_calls")
    if htc is True and not (rec.get("tool_calls") or []):
        return False
    if htc is False and (rec.get("tool_calls") or []):
        return False
    tr = args.get("time_range_parsed")
    if tr:
        gte, lte = tr
        ts = rec.get("ts") or ""
        if not (gte <= ts <= lte):
            return False
    q = args.get("search")
    if q:
        ql = q.lower()
        hay = " ".join([
            str(rec.get("input_summary") or ""),
            str(rec.get("agent_id") or ""),
            str(rec.get("runId") or ""),
            str(rec.get("input_hash") or ""),
            str((rec.get("model_output") or "")[:500]),
        ]).lower()
        if ql not in hay:
            return False
    return True


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------
def tool_query_audit(args: Dict[str, Any]) -> Dict[str, Any]:
    """query_audit(...) -> filtered, sorted, paginated records."""
    if args.get("agent_id") is not None:
        _validate(str(args["agent_id"]), _AGENT_ID_RE, "agent_id")
    if args.get("run_id") is not None:
        _validate(str(args["run_id"]), _RUN_ID_RE, "run_id")
    if args.get("tenant_id") is not None:
        _validate(str(args["tenant_id"]), _TENANT_RE, "tenant_id")
    if args.get("input_kind") is not None:
        _validate(str(args["input_kind"]), _INPUT_KIND_RE, "input_kind")
    args["time_range_parsed"] = _parse_time_range(args.get("time_range"))
    limit = min(int(args.get("limit") or 100), 1000)
    offset = max(int(args.get("offset") or 0), 0)

    records = _load_all()
    matched = [r for r in records if _match(r, args)]
    matched.sort(key=lambda r: r.get("ts") or "", reverse=True)
    page = matched[offset:offset + limit]
    return {
        "ok": True,
        "tool": "query_audit",
        "params": {k: v for k, v in args.items()
                   if k not in ("time_range_parsed",)},
        "total": len(matched),
        "offset": offset,
        "limit": limit,
        "hits": [_record_summary(r) for r in page],
    }


def tool_get_run(args: Dict[str, Any]) -> Dict[str, Any]:
    """get_run(run_id) -> all records sharing a runId (one run
    can produce multiple records — one per sub-call).

    2026-08-14: also matches records whose extra.decision_run_id
    equals run_id. Shadow-mode B3 dispatches (Phase 3) emit audit
    rows with runId = 'remediate-<pattern>-<ts>' and the user-
    visible shadow run ID lives in extra.decision_run_id. Without
    this fallback, the SOC dashboard's per-run page (which loads
    via run_id = shadow run) would say "not found" even when the
    matching remediation + fix_verified rows are right there.
    Matches by runId take priority (more specific); the fallback
    is a strict superset of those plus the shadow records.
    """
    rid = args.get("run_id")
    if not rid:
        raise ValueError("run_id is required")
    _validate(str(rid), _RUN_ID_RE, "run_id")
    records = _load_all()
    matched = [r for r in records if r.get("runId") == rid]
    if not matched:
        # Fallback: shadow run IDs live in extra.decision_run_id.
        for r in records:
            extra = r.get("extra") or {}
            if extra.get("decision_run_id") == rid:
                matched.append(r)
    if not matched:
        raise LookupError(f"run_id not found: {rid}")
    matched.sort(key=lambda r: r.get("ts") or "")
    return {
        "ok": True,
        "tool": "get_run",
        "run_id": rid,
        "total": len(matched),
        "records": [_record_full(r) for r in matched],
    }


def tool_get_record(args: Dict[str, Any]) -> Dict[str, Any]:
    """get_record(record_ts, run_id, agent_id) -> full record
    (input + output + tool_calls + extras). The trio is
    required because timestamps aren't unique on their own."""
    ts = args.get("record_ts")
    rid = args.get("run_id")
    aid = args.get("agent_id")
    if not (ts and rid and aid):
        raise ValueError("record_ts, run_id, agent_id are all required")
    _validate(str(ts), _TS_RE, "record_ts")
    _validate(str(rid), _RUN_ID_RE, "run_id")
    _validate(str(aid), _AGENT_ID_RE, "agent_id")
    records = _load_all()
    for r in records:
        if (r.get("ts") == ts and r.get("runId") == rid
                and r.get("agent_id") == aid):
            return {
                "ok": True,
                "tool": "get_record",
                "record": _record_full(r),
            }
    raise LookupError(
        f"record not found: ts={ts} runId={rid} agent_id={aid}")


def tool_audit_stats(args: Dict[str, Any]) -> Dict[str, Any]:
    """audit_stats(time_range=None) -> aggregate counts.

    Lightweight, in-memory: one pass over the records, no
    external index. Returns:
        - total
        - by_agent: {agent_id: count}
        - by_input_kind: {input_kind: count}
        - by_outcome: {outcome: count}
        - time_range: {gte, lte} or None
    """
    parsed = _parse_time_range(args.get("time_range"))
    records = _load_all()
    if parsed:
        gte, lte = parsed
        records = [r for r in records
                   if gte <= (r.get("ts") or "") <= lte]
    by_agent: Dict[str, int] = {}
    by_kind: Dict[str, int] = {}
    by_out: Dict[str, int] = {}
    for r in records:
        a = r.get("agent_id") or "<none>"
        by_agent[a] = by_agent.get(a, 0) + 1
        k = r.get("input_kind") or "<none>"
        by_kind[k] = by_kind.get(k, 0) + 1
        o = r.get("outcome") or "<none>"
        by_out[o] = by_out.get(o, 0) + 1
    return {
        "ok": True,
        "tool": "audit_stats",
        "time_range": ({"gte": parsed[0], "lte": parsed[1]}
                       if parsed else None),
        "total": len(records),
        "by_agent": by_agent,
        "by_input_kind": by_kind,
        "by_outcome": by_out,
    }


def tool_query_stig_findings(args: Dict[str, Any]) -> Dict[str, Any]:
    """query_stig_findings(time_range=None, tenant_id=None,
    host=None, severity=None, limit=100) -> STIG findings +
    summary aggregates.

    Scans the audit log for records that carry
    `extra.stig_evidence` (set by soc-stig-classifier and the
    downstream soc-stig-remediate agent). Returns the matched
    records with the full `stig_evidence` payload expanded (not
    the summary shape that query_audit returns), plus
    aggregates by stig_id, control_id, nist_family, and
    severity.

    Used by the SOC dashboard's /stig page and the overview
    card. The work is done in-memory (one scan, then group-by
    over the matched rows); safe up to MAX_RECORDS_LOAD.

    The optional `host` filter matches `extra.wazuh_alert.agent`
    (the same key used to build by_host). Combined with the
    canonical monitored_hosts seed, this powers the
    /stig/host/<host> drilldown page.
    """
    parsed = _parse_time_range(args.get("time_range"))
    records = _load_all()
    if parsed:
        gte, lte = parsed
        records = [r for r in records
                   if gte <= (r.get("ts") or "") <= lte]
    tid = args.get("tenant_id")
    severity_filter = args.get("severity")
    host_filter = args.get("host")
    if host_filter:
        # Hostnames can contain letters, digits, dots, dashes,
        # and underscores. No slashes (so the URL path stays
        # safe). Capped at 64 chars to match the SOC host list.
        if (not isinstance(host_filter, str)
                or not re.match(r"^[A-Za-z0-9_.-]{1,64}$",
                                host_filter)):
            raise ValueError(
                "host must match [A-Za-z0-9_.-]{1,64} "
                f"(got {host_filter!r})")
    limit = min(int(args.get("limit") or 100), 1000)
    findings: List[Dict[str, Any]] = []
    for r in records:
        extra = r.get("extra") or {}
        ev = extra.get("stig_evidence")
        if not ev:
            continue
        if tid and r.get("tenant_id") != tid:
            continue
        if severity_filter and ev.get("severity") != severity_filter:
            continue
        if host_filter:
            wa = extra.get("wazuh_alert") or {}
            if wa.get("agent") != host_filter:
                continue
        findings.append({
            "ts": r.get("ts"),
            "runId": r.get("runId"),
            "agent_id": r.get("agent_id"),
            "tenant_id": r.get("tenant_id"),
            "input_summary": r.get("input_summary"),
            "stig_evidence": ev,
            "wazuh_alert": extra.get("wazuh_alert") or {},
        })
    findings.sort(key=lambda f: f.get("ts") or "", reverse=True)
    page = findings[:limit]
    by_stig: Dict[str, int] = {}
    by_ctrl: Dict[str, int] = {}
    by_family: Dict[str, int] = {}
    by_sev: Dict[str, int] = {}
    by_tenant: Dict[str, int] = {}
    by_host: Dict[str, int] = {}
    for f in findings:
        ev = f.get("stig_evidence") or {}
        sid = ev.get("stig_id") or "<none>"
        cid = ev.get("control_id") or "<none>"
        fam = ev.get("nist_family") or "<none>"
        sev = ev.get("severity") or "<none>"
        tn = f.get("tenant_id") or "<none>"
        host = (f.get("wazuh_alert") or {}).get("agent") or "<none>"
        by_stig[sid] = by_stig.get(sid, 0) + 1
        by_ctrl[cid] = by_ctrl.get(cid, 0) + 1
        by_family[fam] = by_family.get(fam, 0) + 1
        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_tenant[tn] = by_tenant.get(tn, 0) + 1
        by_host[host] = by_host.get(host, 0) + 1
    # ---- Zero-fill the canonical dimensions ----
    # NIST 800-53 families that appear in the DISA OS-STIG
    # catalogues we ingest (16 of the 18 — AT/PS are
    # operational/HR controls and not OS-level). Seeded with 0
    # so the dashboard always renders the full family list,
    # not just families with findings in the window.
    for fam in NIST_800_53_FAMILIES:
        by_family.setdefault(fam, 0)
    # Monitored hosts: prefer the live list from C2 manager-mcp
    # (fails soft to []), then union with whatever hosts already
    # have findings in the window so a C2 outage doesn't lose
    # data the dashboard is already rendering.
    monitored_names, monitored_status = _fetch_monitored_hosts()
    if monitored_names:
        for h in monitored_names:
            by_host.setdefault(h, 0)
    # Stable orderings: NIST families in canonical order,
    # monitored hosts alphabetical. Within each, descending by
    # count so the dashboard's "top" view stays useful.
    by_family_sorted = sorted(
        by_family.items(),
        key=lambda kv: (NIST_800_53_FAMILIES.index(kv[0])
                        if kv[0] in NIST_800_53_FAMILIES else 99,
                        -kv[1], kv[0]))
    by_host_sorted = sorted(
        by_host.items(),
        key=lambda kv: (-kv[1], kv[0]))
    return {
        "ok": True,
        "tool": "query_stig_findings",
        "params": {"time_range": args.get("time_range"),
                   "tenant_id": tid,
                   "host": host_filter,
                   "severity": severity_filter,
                   "limit": limit},
        "time_range": ({"gte": parsed[0], "lte": parsed[1]}
                       if parsed else None),
        "total": len(findings),
        "returned": len(page),
        "by_stig_id": dict(sorted(by_stig.items(),
                                  key=lambda kv: kv[1], reverse=True)),
        "by_control_id": dict(sorted(by_ctrl.items(),
                                     key=lambda kv: kv[1], reverse=True)),
        "by_nist_family": dict(by_family_sorted),
        "by_severity": by_sev,
        "by_tenant": dict(sorted(by_tenant.items(),
                                  key=lambda kv: kv[1], reverse=True)),
        "by_host": dict(by_host_sorted),
        "nist_families": list(NIST_800_53_FAMILIES),
        "monitored_hosts": monitored_names,
        "monitored_hosts_status": monitored_status,
        "unique_stig_ids": len(by_stig),
        "unique_controls": len(by_ctrl),
        "findings": page,
    }


def tool_annotate_run(args: Dict[str, Any]) -> Dict[str, Any]:
    """annotate_run(record_ts, run_id, agent_id, author, note,
    tags=None) -> append to extra.annotations[].

    The annotation is non-destructive: the record is re-read
    line-by-line from the source file, the matching record is
    augmented with a new entry in `extra.annotations[]`, and
    the file is rewritten atomically (write to a temp file
    in the same dir, fsync, rename). This preserves the
    append-only intent of the audit log while still letting
    downstream agents add comments.

    Refused if the file is not writable by the current user
    (e.g. someone has done `chmod a-w` to pin it).
    """
    ts = args.get("record_ts")
    rid = args.get("run_id")
    aid = args.get("agent_id")
    author = args.get("author")
    note = args.get("note")
    tags = args.get("tags") or []
    if not (ts and rid and aid and author and note):
        raise ValueError(
            "record_ts, run_id, agent_id, author, note are all required")
    _validate(str(ts), _TS_RE, "record_ts")
    _validate(str(rid), _RUN_ID_RE, "run_id")
    _validate(str(aid), _AGENT_ID_RE, "agent_id")
    if not isinstance(note, str) or len(note) > 2000:
        raise ValueError("note must be a string <=2000 chars")
    if not isinstance(tags, list) or not all(isinstance(t, str) and len(t) <= 64
                                            for t in tags):
        raise ValueError("tags must be a list of strings, each <=64 chars")

    path = _audit_path()
    if not os.access(path, os.W_OK):
        raise PermissionError(
            f"audit log not writable: {path} (chmod +w to annotate)")

    # Read the file, find the record, annotate, write back.
    with open(path, "r", encoding="utf-8") as f:
        raw_lines = f.readlines()

    found_idx = -1
    parsed: List[Optional[Dict[str, Any]]] = []
    for i, line in enumerate(raw_lines):
        line_stripped = line.strip()
        if not line_stripped:
            parsed.append(None)
            continue
        try:
            rec = json.loads(line_stripped)
        except json.JSONDecodeError:
            parsed.append(None)
            continue
        parsed.append(rec)
        if (rec.get("ts") == ts and rec.get("runId") == rid
                and rec.get("agent_id") == aid and found_idx == -1):
            found_idx = i

    if found_idx == -1:
        raise LookupError(
            f"record not found: ts={ts} runId={rid} agent_id={aid}")
    rec = parsed[found_idx]
    assert rec is not None
    extra = rec.setdefault("extra", {})
    if not isinstance(extra, dict):
        raise RuntimeError(
            f"record {ts}/{rid}/{aid} has non-dict 'extra'; refusing to "
            f"annotate (would corrupt the audit record)")
    anns = extra.setdefault("annotations", [])
    if not isinstance(anns, list):
        raise RuntimeError(
            f"record {ts}/{rid}/{aid} has non-list 'extra.annotations'; "
            f"refusing to annotate")
    annotation = {
        "ts": dt.datetime.now(dt.timezone.utc).isoformat(
            timespec="milliseconds"),
        "author": author,
        "note": note,
        "tags": list(tags),
    }
    anns.append(annotation)
    # Rewrite file atomically.
    tmp_path = path + ".annotate.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        for j, line in enumerate(raw_lines):
            p = parsed[j]
            if p is None:
                f.write(line if line.endswith("\n") else line + "\n")
            else:
                f.write(json.dumps(p, default=str) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)
    return {
        "ok": True,
        "tool": "annotate_run",
        "record_ts": ts,
        "run_id": rid,
        "agent_id": aid,
        "annotation_index": len(anns) - 1,
        "total_annotations": len(anns),
    }


# ---------------------------------------------------------------------------
# Record shaping
# ---------------------------------------------------------------------------
# SOC Phase 2 audit (2026-08-13): the summary shape strips `extra`,
# which downstream consumers (the selftest, the E3 evidence collector,
# the daily decision runner) need to filter by ticket_id, action_id,
# alert_signature, etc. The summary now includes a SUBSET of the
# commonly-needed extra fields (ticket_id, action_id, pattern,
# alert_signature, decision_run_id, severity_class, recommended_response)
# by default. The full record is still available via get_record.
_SUMMARY_EXTRA_KEYS = (
    "ticket_id", "action_id", "pattern", "alert_signature",
    "decision_run_id", "severity_class", "recommended_response",
    "ticket_outcome", "indexer_hits", "new_alert_id",
    # SOC Phase 3 (2026-08-13): shadow mode flag. The Phase 3
    # shadow selftest + the Phase 5 curator need to filter by
    # shadow=True to distinguish sandbox runs from real applies.
    "shadow",
)


def _record_summary(r: Dict[str, Any]) -> Dict[str, Any]:
    """Compact shape for list responses. Includes the top-level
    fields plus a subset of `extra` that Phase 1/2 selftests
    + the Phase 5 curator depend on for filtering."""
    extra = r.get("extra") or {}
    summary = {
        "ts": r.get("ts"),
        "runId": r.get("runId"),
        "agent_id": r.get("agent_id"),
        "tenant_id": r.get("tenant_id"),
        "input_kind": r.get("input_kind"),
        "input_hash": r.get("input_hash"),
        "input_summary": r.get("input_summary"),
        "model": r.get("model"),
        "duration_ms": r.get("duration_ms"),
        "outcome": r.get("outcome"),
        "tool_calls_count": len(r.get("tool_calls") or []),
        "annotation_count": len(extra.get("annotations") or []),
    }
    # Surface the most-queried extra fields at the top level so
    # downstream consumers can filter without doing get_record()
    # per row. The full extra is still available via get_record.
    for k in _SUMMARY_EXTRA_KEYS:
        if k in extra:
            summary[k] = extra[k]
    return summary


def _record_full(r: Dict[str, Any]) -> Dict[str, Any]:
    """Full record for get_run / get_record."""
    return {
        "ts": r.get("ts"),
        "runId": r.get("runId"),
        "agent_id": r.get("agent_id"),
        "tenant_id": r.get("tenant_id"),
        "input_kind": r.get("input_kind"),
        "input_hash": r.get("input_hash"),
        "input_summary": r.get("input_summary"),
        "tool_calls": r.get("tool_calls") or [],
        "model_output": r.get("model_output"),
        "model": r.get("model"),
        "duration_ms": r.get("duration_ms"),
        "outcome": r.get("outcome"),
        "error": r.get("error"),
        "extra": r.get("extra") or {},
        "schema": r.get("schema"),
    }


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    server_version = "soc-audit-mcp/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _log(self, method: str, status: int, ms: float, body: Any) -> None:
        sys.stderr.write(
            f"[{dt.datetime.now(dt.timezone.utc).isoformat(timespec='milliseconds')}] "
            f"{self.client_address[0]} {method} -> {status} "
            f"({ms:.1f}ms) tool={body.get('tool', '-') if isinstance(body, dict) else '-'}\n"
        )
        sys.stderr.flush()

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            path = _audit_path()
            exists = os.path.exists(path)
            writable = exists and os.access(path, os.W_OK)
            self._json(200, {
                "ok": exists,
                "server": self.server_version,
                "audit_path": path,
                "writable": writable,
                "missing": ([] if exists else ["audit log not found"]),
            })
            return
        if self.path == "/tools":
            self._json(200, {"ok": True, "tools": list(TOOLS)})
            return
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._json(405, {"ok": False,
                         "error": "method not allowed; use POST /tools/<name>"})

    def do_DELETE(self) -> None:  # noqa: N802
        self._json(405, {"ok": False, "error": "method not allowed"})

    def _dispatch(self, method: str) -> None:
        t0 = time.monotonic()
        m = re.match(r"^/tools/([A-Za-z0-9_]+)$", self.path or "")
        if not m:
            self._json(404, {"ok": False, "error": "not found"})
            self._log(method, 404, (time.monotonic() - t0) * 1000, {})
            return
        tool = m.group(1)
        if tool not in TOOLS:
            self._json(404, {"ok": False, "error": f"unknown tool: {tool}"})
            self._log(method, 404, (time.monotonic() - t0) * 1000, {})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            args = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError as e:
            self._json(400, {"ok": False, "error": f"bad json: {e}"})
            return
        impl = {
            "query_audit": tool_query_audit,
            "get_run": tool_get_run,
            "get_record": tool_get_record,
            "annotate_run": tool_annotate_run,
            "audit_stats": tool_audit_stats,
            "query_stig_findings": tool_query_stig_findings,
        }[tool]
        try:
            result = impl(args)
        except ValueError as e:
            self._json(400, {"ok": False, "error": str(e), "tool": tool})
            self._log(method, 400, (time.monotonic() - t0) * 1000, {"tool": tool})
            return
        except LookupError as e:
            self._json(404, {"ok": False, "error": str(e), "tool": tool})
            self._log(method, 404, (time.monotonic() - t0) * 1000, {"tool": tool})
            return
        except PermissionError as e:
            self._json(403, {"ok": False, "error": str(e), "tool": tool})
            self._log(method, 403, (time.monotonic() - t0) * 1000, {"tool": tool})
            return
        except Exception as e:
            sys.stderr.write(f"[soc-audit-mcp] unhandled: {e!r}\n{traceback.format_exc()}\n")
            self._json(500, {"ok": False, "error": f"internal: {e!r}", "tool": tool})
            self._log(method, 500, (time.monotonic() - t0) * 1000, {"tool": tool})
            return
        self._json(200, result)
        self._log(method, 200, (time.monotonic() - t0) * 1000, result)

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
        f"[soc-audit-mcp] listening on http://{bind_host}:{bind_port} "
        f"(audit={_audit_path()})\n"
    )
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("[soc-audit-mcp] shutting down\n")
        srv.shutdown()
    return 0


def _smoke() -> int:
    """Self-test: bring up the server in a thread, exercise
    transport + validation. Uses the real audit log if it
    exists (read-only operations only); annotate is
    skipped in --smoke to keep the audit log clean.
    """
    import shutil
    import tempfile
    import threading
    import urllib.request as ur

    # Create a tiny temporary audit log so the smoke test
    # doesn't touch the real one.
    tmpdir = tempfile.mkdtemp(prefix="soc-audit-mcp-smoke-")
    tmp_audit = os.path.join(tmpdir, "audit_log.jsonl")
    sample = [
        {
            "ts": "2026-08-08T10:00:00.000+00:00",
            "runId": "smoke-1",
            "agent_id": "soc-triage",
            "tenant_id": "example-soc",
            "input_kind": "decision_prompt",
            "input_hash": "sha256:" + "a" * 64,
            "input_summary": "L12 5763 agent=darth",
            "tool_calls": [{"name": "search_alerts", "args": {"min_level": 0}}],
            "model_output": "{\"severity_class\":\"low\"}",
            "model": "stub",
            "duration_ms": 12,
            "outcome": "ok",
            "error": None,
            "extra": {},
            "schema": 1,
        },
        {
            "ts": "2026-08-08T10:00:00.500+00:00",
            "runId": "smoke-1",
            "agent_id": "soc-comms",
            "tenant_id": "example-soc",
            "input_kind": "llm_prompt",
            "input_hash": "sha256:" + "b" * 64,
            "input_summary": "delegate from smoke-1",
            "tool_calls": [],
            "model_output": "{\"draft\":\"hi\"}",
            "model": "stub",
            "duration_ms": 7,
            "outcome": "ok",
            "error": None,
            "extra": {"annotations": [{
                "ts": "2026-08-08T10:01:00.000+00:00",
                "author": "soc-incident-reviewer",
                "note": "pre-existing annotation in the sample",
                "tags": ["smoke"],
            }]},
            "schema": 1,
        },
        {
            "ts": "2026-08-08T11:00:00.000+00:00",
            "runId": "smoke-2",
            "agent_id": "soc-narrator",
            "tenant_id": "example-soc",
            "input_kind": "wazuh_alert",
            "input_hash": "sha256:" + "c" * 64,
            "input_summary": "L9 5503 agent=vader",
            "tool_calls": [],
            "model_output": "{\"severity_class\":\"medium\"}",
            "model": "m",
            "duration_ms": 22,
            "outcome": "ok",
            "error": None,
            "extra": {},
            "schema": 1,
        },
        # 2026-08-14: shadow-mode dispatch (Phase 3). The
        # user-visible run id lives in extra.decision_run_id;
        # runId is the per-step handle. Tests the get_run
        # fallback that the SOC dashboard relies on.
        {
            "ts": "2026-08-08T11:30:00.000+00:00",
            "runId": "remediate-block_brute_force_source-20260808T113000-aaaaaaaa",
            "agent_id": "soc-safety-decider",
            "tenant_id": "example-soc",
            "input_kind": "remediation_apply",
            "input_hash": "sha256:" + "d" * 64,
            "input_summary": "shadow dispatch of block_brute_force_source",
            "tool_calls": [],
            "model_output": "applied shadow",
            "model": "stub",
            "duration_ms": 8,
            "outcome": "ok",
            "error": None,
            "extra": {
                "pattern": "block_brute_force_source",
                "action_id": "block_brute_force_source-20260808T113000-aaaaaaaa",
                "decision_run_id": "shadow-smoke-1",
                "decision_confidence": 0.95,
                "threshold": 0.85,
                "dry_run": False,
                "shadow": True,
            },
            "schema": 1,
        },
    ]
    with open(tmp_audit, "w") as f:
        for s in sample:
            f.write(json.dumps(s) + "\n")
    os.environ["SOC_AUDIT_LOG"] = tmp_audit

    port = 18769
    t = threading.Thread(target=serve, args=("127.0.0.1", port), daemon=True)
    t.start()
    time.sleep(0.5)

    # /healthz
    with ur.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as r:
        body = json.loads(r.read())
        assert body["ok"] is True, body
        assert body["writable"] is True, body
        assert body["audit_path"] == tmp_audit, body

    # /tools
    with ur.urlopen(f"http://127.0.0.1:{port}/tools", timeout=2) as r:
        body = json.loads(r.read())
        assert set(body["tools"]) == set(TOOLS), body["tools"]

    # query_audit (no filter)
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/query_audit",
            data=b"{}", method="POST"), timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 3, body["total"]
        assert body["hits"][0]["ts"].startswith("2026-08-08T11"), body["hits"]

    # query_audit agent_id=soc-triage
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/query_audit",
            data=b'{"agent_id":"soc-triage"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 1, body
        assert body["hits"][0]["agent_id"] == "soc-triage"
        assert body["hits"][0]["tool_calls_count"] == 1

    # query_audit run_id=smoke-1
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/query_audit",
            data=b'{"run_id":"smoke-1"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 2, body

    # query_audit has_tool_calls=true
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/query_audit",
            data=b'{"has_tool_calls":true}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 1
        assert body["hits"][0]["agent_id"] == "soc-triage"

    # query_audit time_range=24h (everything)
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/query_audit",
            data=b'{"time_range":"24h"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 4, body

    # query_audit bad time_range -> 400
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/query_audit",
            data=b'{"time_range":"not-a-time"}', method="POST"), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 400, f"expected 400, got {e.code}"
    else:
        raise AssertionError("expected 400 for bad time_range")

    # query_audit search=darth
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/query_audit",
            data=b'{"search":"darth"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 1
        assert "darth" in body["hits"][0]["input_summary"]

    # get_run smoke-1 (2 records, one with annotation)
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/get_run",
            data=b'{"run_id":"smoke-1"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 2
        ann = body["records"][1]["extra"]["annotations"]
        assert len(ann) == 1
        assert ann[0]["author"] == "soc-incident-reviewer"

    # get_run missing -> 404
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/get_run",
            data=b'{"run_id":"nope"}', method="POST"), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 404
    else:
        raise AssertionError("expected 404 for missing run")

    # get_run fallback: shadow run id matches via
    # extra.decision_run_id (2026-08-14). The 4th sample
    # record has runId='remediate-...' and
    # extra.decision_run_id='shadow-smoke-1'; querying by the
    # user-visible shadow run id should now succeed.
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/get_run",
            data=b'{"run_id":"shadow-smoke-1"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["ok"] is True, body
        assert body["total"] == 1, body
        rec = body["records"][0]
        assert rec["runId"].startswith("remediate-"), rec["runId"]
        assert rec["extra"]["decision_run_id"] == "shadow-smoke-1", rec
        assert rec["extra"]["shadow"] is True, rec

    # get_run primary match still wins when both could match.
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/get_run",
            data=b'{"run_id":"smoke-1"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 2, body

    # get_record
    rec_ts = sample[0]["ts"]
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/get_record",
            data=json.dumps({"record_ts": rec_ts, "run_id": "smoke-1",
                              "agent_id": "soc-triage"}).encode(),
            method="POST"), timeout=2) as r:
        body = json.loads(r.read())
        assert body["record"]["model_output"] == "{\"severity_class\":\"low\"}"

    # audit_stats
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/audit_stats",
            data=b"{}", method="POST"), timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 4
        assert body["by_agent"]["soc-triage"] == 1
        assert body["by_input_kind"]["decision_prompt"] == 1
        assert body["by_outcome"]["ok"] == 3

    # annotate_run (mutation — only run this in --smoke because
    # it writes back to the temp audit log)
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/annotate_run",
            data=json.dumps({
                "record_ts": rec_ts,
                "run_id": "smoke-1",
                "agent_id": "soc-triage",
                "author": "smoke",
                "note": "added by smoke test",
                "tags": ["test"],
            }).encode(),
            method="POST"), timeout=2) as r:
        body = json.loads(r.read())
        assert body["total_annotations"] == 1, body
        assert body["annotation_index"] == 0

    # Verify the annotation persisted (read the file directly).
    with open(tmp_audit) as f:
        lines = [json.loads(l) for l in f if l.strip()]
    annotated = [r for r in lines
                 if r["ts"] == rec_ts
                 and r["runId"] == "smoke-1"
                 and r["agent_id"] == "soc-triage"]
    assert len(annotated) == 1
    assert len(annotated[0]["extra"]["annotations"]) == 1
    assert annotated[0]["extra"]["annotations"][0]["author"] == "smoke"

    # Second annotation: should append, not overwrite
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/annotate_run",
            data=json.dumps({
                "record_ts": rec_ts,
                "run_id": "smoke-1",
                "agent_id": "soc-triage",
                "author": "smoke",
                "note": "second annotation",
            }).encode(),
            method="POST"), timeout=2) as r:
        body = json.loads(r.read())
        assert body["annotation_index"] == 1
        assert body["total_annotations"] == 2

    # annotate_run with bad record_ts -> 400
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/annotate_run",
            data=json.dumps({
                "record_ts": "not-a-time",
                "run_id": "smoke-1",
                "agent_id": "soc-triage",
                "author": "smoke",
                "note": "x",
            }).encode(),
            method="POST"), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 400
    else:
        raise AssertionError("expected 400 for bad record_ts")

    # annotate_run with missing fields -> 400
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/annotate_run",
            data=b'{"record_ts":"2026-08-08T10:00:00Z"}',
            method="POST"), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 400
    else:
        raise AssertionError("expected 400 for missing fields")

    # Direct PUT/DELETE -> 405
    for m in ("PUT", "DELETE"):
        try:
            ur.urlopen(ur.Request(
                f"http://127.0.0.1:{port}/tools/query_audit",
                data=b"{}", method=m), timeout=2)
        except urllib.error.HTTPError as e:
            assert e.code == 405, f"{m}: expected 405, got {e.code}"
        else:
            raise AssertionError(f"expected 405 for {m}")

    # Cleanup
    shutil.rmtree(tmpdir, ignore_errors=True)
    sys.stdout.write("soc-audit-mcp smoke test: OK\n")
    return 0


def _main() -> int:
    p = argparse.ArgumentParser(description="SOC audit-log MCP server")
    p.add_argument("--bind", default=os.environ.get("SOC_AUDIT_MCP_BIND",
                                                    DEFAULT_BIND_HOST))
    p.add_argument("--port", type=int, default=int(os.environ.get(
        "SOC_AUDIT_MCP_PORT", DEFAULT_BIND_PORT)))
    p.add_argument("--smoke", action="store_true")
    args = p.parse_args()
    if args.smoke:
        return _smoke()
    return serve(args.bind, args.port)


if __name__ == "__main__":
    sys.exit(_main())
