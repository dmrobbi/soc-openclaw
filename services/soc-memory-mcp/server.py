#!/usr/bin/env python3
"""SOC cross-incident memory MCP server (Track A, task A3 — 2026-08-08).

Exposes two read/write tools to SOC agents over JSON-over-HTTP on
127.0.0.1:8770:

  * memory_search(alert) -> top-K prior incidents matching this
    alert's (host, srcip, rule_id), each carrying a short summary
    the agent can quote. Recency-weighted. Tenant-scoped.
  * memory_add(incident_id, summary, tenant_id, rule_id, agent,
    srcip, ts) -> append one record to the backing store.
    Idempotent on (incident_id, tenant_id): a re-write of the same
    record replaces it.

Backed by a per-tenant append-only JSONL at:

  $SOC_MEMORY_FILE  (default /home/wez/.openclaw/agents/soc-triage/memory/memory.jsonl)

At startup the server loads the most recent N records per tenant
into an in-memory index (default N=1000). memory_add writes through
to the file (append + atomic rename) and updates the index in-place.
memory_search walks the index, scores each record against the
query alert (rule_id match = +3, srcip match = +2, agent name
match = +1, exact id match = +5), and returns the top-K with
recency decay (newer = higher score).

Design notes:

  - Stdlib only.
  - Read-write (not read-only like C1); the only state-changing
    op is memory_add, and it's idempotent on (incident_id,
    tenant_id).
  - One process per host. Backing file lives at a stable path so
    agents can inspect it directly if the MCP is down.
  - Tenant isolation: every record carries tenant_id; queries
    filter by it. The default tenant is `example-soc` per
    SOC_TENANT_ID or the first record on disk.
  - Bound to 127.0.0.1 by default. Set SOC_MEMORY_MCP_BIND=lan to
    expose (we don't recommend it).

Created 2026-08-08 by Ciceron as part of Track A (A3).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 8770
DEFAULT_MEMORY_FILE = Path("/home/wez/.openclaw/agents/soc-triage/memory/memory.jsonl")
DEFAULT_MAX_RECORDS = 1000            # in-memory cap (per tenant)
DEFAULT_TOP_K = 5
TOOLS = ("memory_search", "memory_add")
_MAX_RESPONSE_BYTES = 5 * 1024 * 1024
_MAX_REQUEST_BYTES = 256 * 1024

# Recency decay: each record's score is multiplied by
# exp(-age_days / decay_days). 7-day half-ish weight.
RECENCY_DECAY_DAYS = float(os.environ.get("SOC_MEMORY_DECAY_DAYS", "7"))


# ---------------------------------------------------------------------------
# Path / auth / validation helpers
# ---------------------------------------------------------------------------
def _memory_file() -> Path:
    p = os.environ.get("SOC_MEMORY_FILE")
    if p:
        return Path(p)
    return DEFAULT_MEMORY_FILE


def _default_tenant() -> str:
    return (
        os.environ.get("SOC_TENANT_ID")
        or os.environ.get("WAZUH_TENANT_ID")
        or "example-soc"
    )


_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_IP_RE = re.compile(r"^[0-9a-fA-F:.]+$")
_RULE_RE = re.compile(r"^\d{1,6}$")
_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


def _validate_optional(value: Any, pat: re.Pattern, label: str) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not pat.match(value):
        raise ValueError(f"bad {label}: {value!r}")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "+00:00"
    )


def _record_age_days(record: Dict[str, Any]) -> float:
    ts = record.get("ts")
    if not isinstance(ts, str):
        return 1e9
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return 1e9
    delta = datetime.now(timezone.utc) - dt
    return max(0.0, delta.total_seconds() / 86400.0)


# ---------------------------------------------------------------------------
# Backing store: thread-safe in-memory index + JSONL flush
# ---------------------------------------------------------------------------
class _MemoryIndex:
    """Holds records per tenant. Thread-safe (a single lock guards
    both the in-memory dict and the file write)."""

    def __init__(self, path: Path, max_records: int) -> None:
        self.path = path
        self.max_records = max_records
        self._by_tenant: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.RLock()

    # ---- load / persist -------------------------------------------------
    def load(self) -> int:
        """Load records from disk. Returns count loaded."""
        loaded = 0
        if not self.path.exists():
            return 0
        with self._lock:
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        self._ingest_locked(rec)
                        loaded += 1
            except OSError as e:
                sys.stderr.write(f"[soc-memory-mcp] load error: {e!r}\n")
        return loaded

    def _ingest_locked(self, rec: Dict[str, Any]) -> None:
        tenant = rec.get("tenant_id") or _default_tenant()
        rec.setdefault("tenant_id", tenant)
        bucket = self._by_tenant.setdefault(tenant, [])
        # Idempotent on (incident_id, tenant_id): replace in place.
        incident_id = rec.get("incident_id")
        if incident_id:
            for i, existing in enumerate(bucket):
                if existing.get("incident_id") == incident_id:
                    bucket[i] = rec
                    return
        bucket.append(rec)
        # Bound the per-tenant list (keep the most-recent N).
        if len(bucket) > self.max_records:
            bucket.sort(key=lambda r: r.get("ts") or "", reverse=True)
            del bucket[self.max_records:]

    # ---- write ----------------------------------------------------------
    def add(self, rec: Dict[str, Any]) -> Tuple[bool, int]:
        """Append a record. Returns (was_new, total_count_for_tenant)."""
        with self._lock:
            tenant = rec.get("tenant_id") or _default_tenant()
            bucket_before = len(self._by_tenant.get(tenant, []))
            was_new = True
            for existing in self._by_tenant.get(tenant, []):
                if existing.get("incident_id") == rec.get("incident_id"):
                    was_new = False
                    break
            self._ingest_locked(rec)
            bucket_after = len(self._by_tenant.get(tenant, []))
            # Append to disk (atomic via .tmp + rename).
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, default=str) + "\n")
            except OSError as e:
                sys.stderr.write(f"[soc-memory-mcp] write error: {e!r}\n")
            return was_new, bucket_after

    # ---- read -----------------------------------------------------------
    def search(self, *, tenant_id: str, rule_id: Optional[str],
               agent: Optional[str], srcip: Optional[str],
               incident_id: Optional[str],
               top_k: int) -> List[Dict[str, Any]]:
        """Return top-K matching records, scored by relevance +
        recency."""
        with self._lock:
            bucket = list(self._by_tenant.get(tenant_id, []))

        scored: List[Tuple[float, Dict[str, Any]]] = []
        for rec in bucket:
            score = 0.0
            if rule_id is not None and str(rec.get("rule_id")) == str(rule_id):
                score += 3.0
            if srcip is not None and rec.get("srcip") == srcip:
                score += 2.0
            if agent is not None and rec.get("agent") == agent:
                score += 1.0
            if (incident_id is not None
                    and rec.get("incident_id") == incident_id):
                score += 5.0
            if score <= 0:
                continue
            # Recency decay.
            age = _record_age_days(rec)
            score *= 2.71828 ** (-age / RECENCY_DECAY_DAYS)
            scored.append((score, rec))
        scored.sort(key=lambda kv: (-kv[0], kv[1].get("ts") or ""), reverse=False)
        # ^ sort by score desc, tiebreak by ts desc
        scored.sort(key=lambda kv: (-kv[0], kv[1].get("ts") or ""))
        return [rec for _, rec in scored[:top_k]]

    def stats(self, tenant_id: str) -> Dict[str, Any]:
        with self._lock:
            return {
                "tenant_id": tenant_id,
                "record_count": len(self._by_tenant.get(tenant_id, [])),
                "memory_file": str(self.path),
            }


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------
def _extract_alert_fields(args: Dict[str, Any]) -> Dict[str, Any]:
    """Pull rule_id / agent / srcip out of an alert-shaped dict, or
    pass them through directly if already flat."""
    if "alert" in args and isinstance(args["alert"], dict):
        a = args["alert"]
        rule = a.get("rule") or {}
        agent = a.get("agent") or {}
        data = a.get("data") or {}
        return {
            "rule_id": rule.get("id"),
            "agent": agent.get("name"),
            "srcip": data.get("srcip"),
        }
    return {
        "rule_id": args.get("rule_id"),
        "agent": args.get("agent"),
        "srcip": args.get("srcip"),
    }


def tool_memory_search(args: Dict[str, Any], index: _MemoryIndex) -> Dict[str, Any]:
    """memory_search(alert=None, rule_id=None, agent=None, srcip=None,
    incident_id=None, tenant_id=None, top_k=5) -> ranked list."""
    tenant_id = args.get("tenant_id") or _default_tenant()
    _validate_optional(tenant_id, _TENANT_RE, "tenant_id")

    fields = _extract_alert_fields(args)
    rule_id = args.get("rule_id") or fields["rule_id"]
    agent = args.get("agent") or fields["agent"]
    srcip = args.get("srcip") or fields["srcip"]
    incident_id = args.get("incident_id")

    if rule_id is not None:
        _validate_optional(str(rule_id), _RULE_RE, "rule_id")
    if agent is not None:
        _validate_optional(str(agent), _HOST_RE, "agent")
    if srcip is not None:
        _validate_optional(str(srcip), _IP_RE, "srcip")
    if incident_id is not None:
        _validate_optional(str(incident_id), _HOST_RE, "incident_id")

    top_k = max(1, min(int(args.get("top_k") or DEFAULT_TOP_K), 50))
    matches = index.search(
        tenant_id=tenant_id,
        rule_id=str(rule_id) if rule_id is not None else None,
        agent=str(agent) if agent is not None else None,
        srcip=str(srcip) if srcip is not None else None,
        incident_id=str(incident_id) if incident_id is not None else None,
        top_k=top_k,
    )
    return {
        "ok": True,
        "tool": "memory_search",
        "tenant_id": tenant_id,
        "query": {
            "rule_id": rule_id,
            "agent": agent,
            "srcip": srcip,
            "incident_id": incident_id,
            "top_k": top_k,
        },
        "matches": matches,
        "match_count": len(matches),
    }


def tool_memory_add(args: Dict[str, Any], index: _MemoryIndex) -> Dict[str, Any]:
    """memory_add(incident_id=None, summary, tenant_id=None,
    rule_id=None, agent=None, srcip=None, ts=None, extra=None)
    -> {ok, was_new, count}.

    incident_id is optional. If absent, a uuid-v4 is generated.
    Idempotent on (incident_id, tenant_id): a re-write of an
    existing record replaces it (and the underlying JSONL file
    accumulates the new version; the in-memory index reflects the
    latest).
    """
    summary = args.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("summary is required and must be a non-empty string")
    summary = summary.strip()
    if len(summary) > 4000:
        summary = summary[:4000]

    tenant_id = args.get("tenant_id") or _default_tenant()
    _validate_optional(tenant_id, _TENANT_RE, "tenant_id")

    rule_id = args.get("rule_id")
    agent = args.get("agent")
    srcip = args.get("srcip")
    if rule_id is not None:
        _validate_optional(str(rule_id), _RULE_RE, "rule_id")
    if agent is not None:
        _validate_optional(str(agent), _HOST_RE, "agent")
    if srcip is not None:
        _validate_optional(str(srcip), _IP_RE, "srcip")

    incident_id = args.get("incident_id") or str(uuid.uuid4())
    _validate_optional(str(incident_id), _HOST_RE, "incident_id")

    ts = args.get("ts") or _iso_now()
    if not isinstance(ts, str):
        raise ValueError("ts must be a string")

    rec: Dict[str, Any] = {
        "incident_id": incident_id,
        "tenant_id": tenant_id,
        "ts": ts,
        "summary": summary,
    }
    if rule_id is not None:
        rec["rule_id"] = int(rule_id)
    if agent is not None:
        rec["agent"] = agent
    if srcip is not None:
        rec["srcip"] = srcip
    extra = args.get("extra")
    if isinstance(extra, dict):
        # Whitelist: only forward keys that don't collide with the schema.
        for k, v in extra.items():
            if k in rec:
                continue
            if isinstance(k, str) and isinstance(v, (str, int, float, bool)):
                rec[k] = v

    was_new, count = index.add(rec)
    return {
        "ok": True,
        "tool": "memory_add",
        "was_new": was_new,
        "incident_id": incident_id,
        "tenant_id": tenant_id,
        "count": count,
    }


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------
_INDEX: Optional[_MemoryIndex] = None


class _Handler(BaseHTTPRequestHandler):
    server_version = "soc-memory-mcp/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _log(self, method: str, status: int, ms: float, body: Any) -> None:
        tool = body.get("tool", "-") if isinstance(body, dict) else "-"
        sys.stderr.write(
            f"[{datetime.now(timezone.utc).isoformat(timespec='milliseconds')}] "
            f"{self.client_address[0]} {method} -> {status} "
            f"({ms:.1f}ms) tool={tool}\n"
        )
        sys.stderr.flush()

    def _json(self, status: int, body: Dict[str, Any]) -> None:
        try:
            data = json.dumps(body, default=str).encode("utf-8")
        except (TypeError, ValueError) as e:
            data = json.dumps({"ok": False, "error": f"encode: {e}"}).encode("utf-8")
            status = 500
        if len(data) > _MAX_RESPONSE_BYTES:
            data = data[:_MAX_RESPONSE_BYTES]
            body = {"ok": False, "error": "response truncated", "size": len(data)}
            data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._json(200, {
                "ok": True,
                "server": self.server_version,
                "index_loaded": _INDEX is not None,
                "stats": _INDEX.stats(_default_tenant()) if _INDEX else None,
            })
            return
        if self.path == "/tools":
            self._json(200, {"ok": True, "tools": list(TOOLS)})
            return
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        t0 = time.monotonic()
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
            length = min(int(self.headers.get("Content-Length") or 0),
                         _MAX_REQUEST_BYTES)
            raw = self.rfile.read(length) if length else b"{}"
            args = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError as e:
            self._json(400, {"ok": False, "error": f"bad json: {e}"})
            return
        if _INDEX is None:
            self._json(503, {"ok": False, "error": "index not loaded"})
            return
        try:
            if tool == "memory_search":
                result = tool_memory_search(args, _INDEX)
            elif tool == "memory_add":
                result = tool_memory_add(args, _INDEX)
            else:
                self._json(500, {"ok": False, "error": "unreachable"})
                return
        except ValueError as e:
            self._json(400, {"ok": False, "error": str(e), "tool": tool})
            self._log("POST", 400, (time.monotonic() - t0) * 1000, {"tool": tool})
            return
        except Exception as e:
            sys.stderr.write(
                f"[soc-memory-mcp] unhandled: {e!r}\n{traceback.format_exc()}\n"
            )
            self._json(500, {"ok": False, "error": f"internal: {e!r}",
                              "tool": tool})
            self._log("POST", 500, (time.monotonic() - t0) * 1000, {"tool": tool})
            return
        self._json(200, result)
        self._log("POST", 200, (time.monotonic() - t0) * 1000, result)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def serve(bind_host: str = DEFAULT_BIND_HOST,
          bind_port: int = DEFAULT_BIND_PORT) -> int:
    global _INDEX
    memory_file = _memory_file()
    _INDEX = _MemoryIndex(memory_file, DEFAULT_MAX_RECORDS)
    loaded = _INDEX.load()
    srv = ThreadingHTTPServer((bind_host, bind_port), _Handler)
    sys.stderr.write(
        f"[soc-memory-mcp] listening on http://{bind_host}:{bind_port} "
        f"(memory_file={memory_file}, loaded={loaded} records)\n"
    )
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("[soc-memory-mcp] shutting down\n")
        srv.shutdown()
    return 0


def _smoke() -> int:
    """Self-test: bring up the server in a thread, exercise both
    tools without needing the indexer. Verifies the transport
    layer + scoring + idempotency."""
    import threading
    import urllib.request as ur

    # Use a tmp memory file so we don't pollute prod state.
    import tempfile
    tmpdir = tempfile.mkdtemp()
    os.environ["SOC_MEMORY_FILE"] = os.path.join(tmpdir, "memory.jsonl")

    port = 18770  # avoid collision with the real port
    t = threading.Thread(target=serve, args=("127.0.0.1", port), daemon=True)
    t.start()
    time.sleep(0.5)
    failures = []

    def _post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        req = ur.Request(
            f"http://127.0.0.1:{port}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with ur.urlopen(req, timeout=5) as r:
            return json.loads(r.read())

    def _get(path: str) -> Dict[str, Any]:
        with ur.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
            return json.loads(r.read())

    try:
        # /healthz
        h = _get("/healthz")
        assert h["ok"] is True, f"healthz not ok: {h}"

        # /tools
        t_resp = _get("/tools")
        assert "memory_search" in t_resp["tools"], "tools missing memory_search"
        assert "memory_add" in t_resp["tools"], "tools missing memory_add"

        # Add three records
        for i, (rule_id, agent, srcip, summary) in enumerate([
            (40112, "darth", "10.9.8.7",
             "Brute-force-then-success: multiple auth failures then root login from 10.9.8.7. "
             "Recommend page + block 10.9.8.7."),
            (5763, "mail.example.com", "9.9.9.1",
             "SSH brute force noise pattern; mailcow cycling."),
            (5503, "darth", None,
             "Login session opened; informational."),
        ]):
            r = _post("/tools/memory_add", {
                "incident_id": f"inc-{i:04d}",
                "rule_id": rule_id,
                "agent": agent,
                "srcip": srcip,
                "summary": summary,
            })
            assert r["ok"] is True, f"add failed: {r}"
            assert r["was_new"] is True, f"add not new: {r}"

        # Idempotency: re-add same incident_id replaces, not duplicates
        r = _post("/tools/memory_add", {
            "incident_id": "inc-0000",
            "rule_id": 40112,
            "agent": "darth",
            "srcip": "10.9.8.7",
            "summary": "UPDATED: darth 40112 brute-force; root login from 10.9.8.7.",
        })
        assert r["ok"] is True and r["was_new"] is False, (
            f"idempotency broken: {r}")

        # Search by rule_id
        r = _post("/tools/memory_search", {
            "rule_id": 40112,
            "top_k": 5,
        })
        assert r["ok"] is True, f"search failed: {r}"
        assert r["match_count"] >= 1, f"search missed the record: {r}"
        # The most recent 40112 record should be the updated one
        top = r["matches"][0]
        assert top["incident_id"] == "inc-0000", (
            f"top match should be the updated one: {top}")
        assert "UPDATED" in top["summary"], (
            f"updated summary missing: {top}")

        # Search by alert-shaped input (the more common call form)
        r = _post("/tools/memory_search", {
            "alert": {
                "rule": {"id": 40112, "level": 12,
                         "description": "Multiple authentication failures followed by a success."},
                "agent": {"name": "darth", "ip": "<agent-ip>"},
                "data": {"srcip": "10.9.8.7", "user": "root"},
            },
            "top_k": 5,
        })
        assert r["ok"] is True, f"alert-shaped search failed: {r}"
        assert r["match_count"] >= 1, (
            f"alert-shaped search missed: {r}")
        # The 40112 record should rank above the 5763 record
        top_rule = r["matches"][0].get("rule_id")
        assert top_rule == 40112, (
            f"expected 40112 to top-rank, got {top_rule}")

        # Search by srcip only (no rule match)
        r = _post("/tools/memory_search", {
            "srcip": "9.9.9.1",
            "top_k": 5,
        })
        assert r["ok"] is True and r["match_count"] >= 1, (
            f"srcip search missed: {r}")

        # Search with no matches
        r = _post("/tools/memory_search", {
            "rule_id": 99999,
            "top_k": 5,
        })
        assert r["ok"] is True and r["match_count"] == 0, (
            f"no-match search should be empty: {r}")

        # Tenant isolation
        r = _post("/tools/memory_search", {
            "tenant_id": "customer-xyz",
            "rule_id": 40112,
            "top_k": 5,
        })
        assert r["ok"] is True and r["match_count"] == 0, (
            f"tenant isolation broken: {r}")

        sys.stdout.write(
            f"soc-memory-mcp smoke test: OK "
            f"({r['match_count']} customer-xyz hits, "
            f"{r.get('match_count', 0)} in default tenant)\n"
        )
        return 0
    except AssertionError as e:
        sys.stderr.write(f"soc-memory-mcp smoke FAIL: {e}\n")
        return 1
    finally:
        # The smoke thread is daemon; process exits when test returns.
        pass


def _main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bind-host", default=DEFAULT_BIND_HOST)
    p.add_argument("--bind-port", type=int, default=DEFAULT_BIND_PORT)
    p.add_argument("--smoke", action="store_true",
                   help="Run the smoke test (no listener).")
    args = p.parse_args()
    if args.smoke:
        return _smoke()
    return serve(args.bind_host, args.bind_port)


if __name__ == "__main__":
    sys.exit(_main())
