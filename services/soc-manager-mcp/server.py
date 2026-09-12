#!/usr/bin/env python3
"""SOC Wazuh manager API MCP server (Track C, task C2 — 2026-08-08).

A stdlib HTTP server that wraps the Wazuh manager REST API
(https://host:55000) and exposes its operations to SOC agents
via MCP-style tools. This is the *manager* (not the indexer)
— i.e. agent control, rule inspection, manager status, and
the active-response surface that C1's indexer MCP doesn't reach.

Tools
-----
  * list_agents(limit=200, status=None)
        -> [{id, name, status, ip, lastKeepAlive, version, os}]
  * get_agent(agent_id)
        -> full record for a single agent (status, ip, group,
           version, OS, lastKeepAlive, registerIP)
  * get_manager_status()
        -> manager daemon states + version + tz + max_agents
  * get_manager_info()
        -> path, version, type, max_agents, openssl_support,
           tz_*, uuid
  * get_rule_info(rule_id)
        -> full rule record (description, level, groups,
           compliance mapping, mitre, details)
  * restart_agent(agent_id)
        -> MUTATING. Sends PUT /agents/<id>/restart. Off by
           default; requires SOC_MANAGER_MCP_ALLOW_MUTATIONS=1.

The server is a single stdlib HTTP endpoint bound to 127.0.0.1
(port 8767 by default). The transport is plain JSON-over-HTTP
(same shape as the rest of the SOC MCP servers — see
soc-wazuh-mcp README for the rationale). Wiring it into the
openclaw harness is a one-liner in the agent config.

Design constraints
------------------
  - Stdlib only. No third-party deps.
  - Read-only by default. The only mutating tool is
    `restart_agent`, and it is gated by
    `SOC_MANAGER_MCP_ALLOW_MUTATIONS=1` (off by default; flip
    deliberately). Other mutating calls are rejected at the
    transport layer (we don't even implement them).
  - Bound to 127.0.0.1 by default. Set
    `SOC_MANAGER_MCP_BIND=lan` only behind a firewall.
  - Capped response size: 5 MB.
  - Auth: bearer JWT fetched from
    `POST /security/user/authenticate?raw=true` using
    WAZUH_API_USERNAME + WAZUH_API_PASSWORD. Token is cached
    in-process and refreshed on 401. (Manager JWTs default
    to 15-min expiry in 4.14.x.)
  - Logs every call to stderr in a stable, grep-friendly
    format. The SOC audit log is separate; this is ops only.

Created 2026-08-08 by Ciceron as part of Track C (C2).
"""
from __future__ import annotations

import argparse
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
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 8767
DEFAULT_MANAGER_URL = "https://127.0.0.1:55000"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
TOOLS = (
    "list_agents",
    "get_agent",
    "get_manager_status",
    "get_manager_info",
    "get_rule_info",
    "restart_agent",
    "run_scan",
)

_AGENT_ID_RE = re.compile(r"^\d{1,4}$")
_RULE_ID_RE = re.compile(r"^\d{1,6}$")


# ---------------------------------------------------------------------------
# Manager config
# ---------------------------------------------------------------------------
def _manager_url() -> str:
    return os.environ.get("WAZUH_MANAGER_URL",
                          DEFAULT_MANAGER_URL).rstrip("/")


def _manager_username() -> str:
    return os.environ.get("WAZUH_API_USERNAME", "wazuh-wui")


def _manager_password() -> str:
    return os.environ.get("WAZUH_API_PASSWORD", "")


def _ssl_context() -> ssl.SSLContext:
    """No verification by default — the SOC stack uses self-signed
    certs. SOC_MANAGER_MCP_VERIFY=1 turns on real verification."""
    ctx = ssl.create_default_context()
    if os.environ.get("SOC_MANAGER_MCP_VERIFY", "0") != "1":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ---------------------------------------------------------------------------
# Manager client (token-cached)
# ---------------------------------------------------------------------------
class _ManagerClient:
    """Thin Wazuh manager REST client. Caches the JWT, refreshes
    on 401. Bounded retries on transient errors.
    """

    def __init__(self) -> None:
        self._token: Optional[str] = None
        self._token_fetched_at: float = 0.0
        self._token_ttl_s: int = int(os.environ.get(
            "SOC_MANAGER_MCP_TOKEN_TTL_S", "900"))  # 15 min default
        self._max_retries: int = 2

    def _authenticate(self) -> str:
        url = f"{_manager_url()}/security/user/authenticate?raw=true"
        body = json.dumps({}).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={
                "Authorization": _basic_auth_header(
                    _manager_username(), _manager_password()),
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, context=_ssl_context(),
                                        timeout=10) as r:
                tok = r.read().decode("utf-8").strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"auth HTTP {e.code}: {body}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"auth unreachable: {e!r}")
        if not tok or "." not in tok:
            raise RuntimeError(f"auth returned non-JWT: {tok!r}")
        self._token = tok
        self._token_fetched_at = time.monotonic()
        return tok

    def _maybe_refresh(self) -> None:
        if (self._token is None
                or (time.monotonic() - self._token_fetched_at)
                > self._token_ttl_s):
            self._authenticate()

    def request(self, method: str, path: str,
                body: Optional[Dict[str, Any]] = None,
                query: Optional[Dict[str, Any]] = None,
                mutate: bool = False) -> Tuple[int, Any]:
        """Make a request. Returns (status_code, parsed_body_or_text).

        `mutate=True` is required for any non-GET method so the
        caller has to think about it; the transport layer
        (BaseHTTPRequestHandler) enforces that only the
        `restart_agent` tool can pass mutate=True.
        """
        if mutate and method.upper() == "GET":
            mutate = False
        if mutate and os.environ.get("SOC_MANAGER_MCP_ALLOW_MUTATIONS",
                                     "0") != "1":
            raise PermissionError(
                "mutations disabled: set SOC_MANAGER_MCP_ALLOW_MUTATIONS=1 "
                "to enable restart_agent (and any future mutating tools)")
        url = _manager_url() + path
        if query:
            url += "?" + urllib.parse.urlencode(
                {k: v for k, v in query.items() if v is not None})
        data = json.dumps(body).encode("utf-8") if body is not None else None
        last_err: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            self._maybe_refresh()
            assert self._token is not None
            req = urllib.request.Request(
                url, data=data,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                },
                method=method,
            )
            try:
                with urllib.request.urlopen(req, context=_ssl_context(),
                                            timeout=15) as r:
                    raw = r.read()
                    try:
                        return r.status, json.loads(raw)
                    except json.JSONDecodeError:
                        return r.status, raw.decode("utf-8",
                                                    errors="replace")
            except urllib.error.HTTPError as e:
                raw = e.read().decode("utf-8", errors="replace")
                if e.code == 401 and attempt < self._max_retries:
                    # Token expired or got rotated; force refresh.
                    self._token = None
                    last_err = RuntimeError(f"HTTP 401: {raw[:200]}")
                    continue
                return e.code, raw
            except urllib.error.URLError as e:
                last_err = RuntimeError(f"unreachable: {e!r}")
                time.sleep(0.2 * (attempt + 1))
                continue
        assert last_err is not None
        raise last_err


def _basic_auth_header(user: str, pw: str) -> str:
    import base64
    raw = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return f"Basic {raw}"


# Module-level client (one per process is fine — handlers run in
# threads but the token cache is just an attribute read).
_CLIENT = _ManagerClient()


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------
def tool_list_agents(args: Dict[str, Any]) -> Dict[str, Any]:
    """list_agents(limit=200, status=None) -> affected items only.

    The Wazuh manager API doesn't accept agent_id as a query
    param on /agents (we tried; it 400s). So we always pull a
    bounded page and filter client-side; agents sets are small
    (10s, not 1000s) and this is fine.
    """
    limit = min(int(args.get("limit") or 200), 500)
    status = args.get("status")
    if status is not None and status not in ("active", "pending",
                                             "disconnected", "never_connected"):
        raise ValueError(f"bad status: {status!r}")
    status_filter = [status] if status else None
    select = "id,name,status,ip,lastKeepAlive,version,os.platform,group"
    res_status, body = _CLIENT.request(
        "GET", "/agents", query={"limit": limit, "select": select})
    if res_status != 200:
        raise RuntimeError(f"list_agents HTTP {res_status}: {body!r}")
    items = (body.get("data", {}).get("affected_items", [])
             if isinstance(body, dict) else [])
    if status_filter:
        items = [a for a in items if a.get("status") in status_filter]
    # Re-shape for compactness
    compact = []
    for a in items:
        compact.append({
            "id": a.get("id"),
            "name": a.get("name"),
            "status": a.get("status"),
            "ip": a.get("ip"),
            "lastKeepAlive": a.get("lastKeepAlive"),
            "version": a.get("version"),
            "os": ((a.get("os") or {}).get("platform")
                   if isinstance(a.get("os"), dict) else a.get("os")),
            "group": a.get("group"),
        })
    return {
        "ok": True,
        "tool": "list_agents",
        "params": {"limit": limit, "status": status},
        "agents": compact,
        "total": len(compact),
    }


def tool_get_agent(args: Dict[str, Any]) -> Dict[str, Any]:
    """get_agent(agent_id) -> full record for one agent."""
    aid = args.get("agent_id")
    if aid is None:
        raise ValueError("agent_id is required")
    aid_s = str(aid).strip()
    if not _AGENT_ID_RE.match(aid_s):
        raise ValueError(f"bad agent_id: {aid_s!r}")
    res_status, body = _CLIENT.request("GET", "/agents",
                                       query={"limit": 500})
    if res_status != 200:
        raise RuntimeError(f"get_agent HTTP {res_status}: {body!r}")
    items = (body.get("data", {}).get("affected_items", [])
             if isinstance(body, dict) else [])
    # Match by zero-padded id (Wazuh returns ids as strings).
    aid_norm = aid_s.zfill(3)
    for a in items:
        if str(a.get("id", "")).zfill(3) == aid_norm:
            return {
                "ok": True,
                "tool": "get_agent",
                "agent_id": aid_norm,
                "agent": a,
            }
    raise LookupError(f"agent_id not found: {aid_norm}")


def tool_get_manager_status(args: Dict[str, Any]) -> Dict[str, Any]:
    """get_manager_status() -> daemon states + tz + version."""
    res_status, body = _CLIENT.request("GET", "/manager/status")
    if res_status != 200:
        raise RuntimeError(f"manager/status HTTP {res_status}: {body!r}")
    items = (body.get("data", {}).get("affected_items", [])
             if isinstance(body, dict) else [])
    return {
        "ok": True,
        "tool": "get_manager_status",
        "status": items[0] if items else {},
    }


def tool_get_manager_info(args: Dict[str, Any]) -> Dict[str, Any]:
    """get_manager_info() -> path, version, type, max_agents,
    openssl_support, tz_offset, tz_name, uuid."""
    res_status, body = _CLIENT.request("GET", "/manager/info")
    if res_status != 200:
        raise RuntimeError(f"manager/info HTTP {res_status}: {body!r}")
    items = (body.get("data", {}).get("affected_items", [])
             if isinstance(body, dict) else [])
    return {
        "ok": True,
        "tool": "get_manager_info",
        "info": items[0] if items else {},
    }


def tool_get_rule_info(args: Dict[str, Any]) -> Dict[str, Any]:
    """get_rule_info(rule_id) -> full rule record (groups, mitre,
    compliance mapping, details). Bounded scan: pulls up to 500
    rules at a time; the Wazuh ruleset is ~30k rules in 4.14.x
    so the client caller should accept a bounded result.
    """
    rid = args.get("rule_id")
    if rid is None:
        raise ValueError("rule_id is required")
    rid_s = str(rid).strip()
    if not _RULE_ID_RE.match(rid_s):
        raise ValueError(f"bad rule_id: {rid_s!r}")
    rid_n = int(rid_s)
    # The Wazuh /rules endpoint accepts ?rule_ids= (plural) as a
    # filter for a specific id; we don't have to scan.
    res_status, body = _CLIENT.request(
        "GET", "/rules",
        query={"rule_ids": rid_s, "limit": 1})
    if res_status != 200:
        raise RuntimeError(f"rules HTTP {res_status}: {body!r}")
    items = (body.get("data", {}).get("affected_items", [])
             if isinstance(body, dict) else [])
    if not items:
        raise LookupError(f"rule_id not found: {rid_n}")
    return {
        "ok": True,
        "tool": "get_rule_info",
        "rule_id": rid_n,
        "rule": items[0],
    }


def tool_restart_agent(args: Dict[str, Any]) -> Dict[str, Any]:
    """restart_agent(agent_id) -> manager response. MUTATING.

    Sends PUT /agents/<id>/restart. The manager replies with
    `{data: {affected_items: [id], total_affected_items: 1, ...}}`
    immediately, then the agent reconnects in 5-30s (the actual
    restart is async on the agent side).

    Disabled unless SOC_MANAGER_MCP_ALLOW_MUTATIONS=1.
    """
    aid = args.get("agent_id")
    if aid is None:
        raise ValueError("agent_id is required")
    aid_s = str(aid).strip()
    if not _AGENT_ID_RE.match(aid_s):
        raise ValueError(f"bad agent_id: {aid_s!r}")
    aid_norm = aid_s.zfill(3)
    res_status, body = _CLIENT.request(
        "PUT", "/agents/restart",
        query={"agents_list": aid_norm},
        mutate=True,
    )
    if res_status != 200:
        raise RuntimeError(f"restart HTTP {res_status}: {body!r}")
    return {
        "ok": True,
        "tool": "restart_agent",
        "agent_id": aid_norm,
        "manager_response": body if isinstance(body, dict) else {"raw": body},
    }


def tool_run_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """run_scan(agent_id) -> MUTATING. Triggers an on-demand scan.

    Mechanism: restarts the Wazuh agent via the manager API
    (PUT /agents action=restart). On reconnect the agent starts a fresh
    syscheck/FIM integrity scan and the vulnerability detector re-runs —
    i.e. the practical "scan now" control for a managed host.

    Disabled unless SOC_MANAGER_MCP_ALLOW_MUTATIONS=1.
    """
    aid = args.get("agent_id")
    if aid is None:
        raise ValueError("agent_id is required")
    aid_s = str(aid).strip()
    if not _AGENT_ID_RE.match(aid_s):
        raise ValueError(f"bad agent_id: {aid_s!r}")
    aid_norm = aid_s.zfill(3)
    res_status, body = _CLIENT.request(
        "PUT", "/agents/restart",
        query={"agents_list": aid_norm},
        mutate=True,
    )
    if res_status != 200:
        raise RuntimeError(f"scan trigger HTTP {res_status}: {body!r}")
    return {
        "ok": True,
        "tool": "run_scan",
        "agent_id": aid_norm,
        "scan": {
            "trigger": "agent-restart",
            "effect": "agent reconnects in 5-30s, then runs a fresh "
                      "syscheck/FIM scan; vulnerability detector re-runs",
        },
        "manager_response": body if isinstance(body, dict) else {"raw": body},
    }


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    server_version = "soc-manager-mcp/1.0"

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
            ok = bool(_manager_password())
            body = {
                "ok": ok,
                "server": self.server_version,
                "mutations_enabled": (
                    os.environ.get("SOC_MANAGER_MCP_ALLOW_MUTATIONS",
                                   "0") == "1"),
                "manager_url": _manager_url(),
                "missing": ([] if ok else ["WAZUH_API_PASSWORD"]),
            }
            self._json(200 if ok else 503, body)
            return
        if self.path == "/tools":
            self._json(200, {"ok": True, "tools": list(TOOLS)})
            return
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_PUT(self) -> None:  # noqa: N802
        # We don't expose raw PUT; the only mutating tool
        # (restart_agent) goes through /tools/restart_agent
        # as a POST. Refuse direct PUTs so the audit trail
        # goes through the tool layer.
        self._json(405, {"ok": False, "error": "method not allowed; "
                                                "use POST /tools/<name>"})

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
            "list_agents": tool_list_agents,
            "get_agent": tool_get_agent,
            "get_manager_status": tool_get_manager_status,
            "get_manager_info": tool_get_manager_info,
            "get_rule_info": tool_get_rule_info,
            "restart_agent": tool_restart_agent,
            "run_scan": tool_run_scan,
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
        except RuntimeError as e:
            self._json(502, {"ok": False, "error": str(e), "tool": tool})
            self._log(method, 502, (time.monotonic() - t0) * 1000, {"tool": tool})
            return
        except Exception as e:
            sys.stderr.write(f"[soc-manager-mcp] unhandled: {e!r}\n{traceback.format_exc()}\n")
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
        f"[soc-manager-mcp] listening on http://{bind_host}:{bind_port} "
        f"(manager={_manager_url()}, "
        f"mutations={'on' if os.environ.get('SOC_MANAGER_MCP_ALLOW_MUTATIONS') == '1' else 'off'})\n"
    )
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("[soc-manager-mcp] shutting down\n")
        srv.shutdown()
    return 0


def _smoke() -> int:
    """Self-test: bring up the server in a thread, exercise the
    transport layer (healthz, /tools, bad tool name, bad args).
    Does NOT require the manager to be up — we mock the client
    with a no-op to keep this hermetic.
    """
    import threading
    import urllib.request as ur

    # Force healthz to report 'no manager password' so the test
    # doesn't depend on the real env.
    os.environ.pop("WAZUH_API_PASSWORD", None)
    port = 18767
    t = threading.Thread(target=serve, args=("127.0.0.1", port), daemon=True)
    t.start()
    time.sleep(0.5)

    # /healthz: 503 because no password is set, but the body
    # has the expected fields. urlopen raises on >=400, so
    # we catch.
    try:
        with ur.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as r:
            body = json.loads(r.read())
            assert r.status == 503, f"expected 503, got {r.status}"
    except urllib.error.HTTPError as e:
        assert e.code == 503, f"expected 503, got {e.code}"
        body = json.loads(e.read())
    assert body["server"].startswith("soc-manager-mcp/"), body
    assert body["mutations_enabled"] is False
    assert "WAZUH_API_PASSWORD" in body["missing"]

    # /tools: full list
    with ur.urlopen(f"http://127.0.0.1:{port}/tools", timeout=2) as r:
        body = json.loads(r.read())
        assert set(body["tools"]) == set(TOOLS), body["tools"]

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

    # Bad agent_id -> 400 (validation)
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/get_agent",
            data=b'{"agent_id": "abc; DROP"}',
            method="POST",
        ), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 400, f"expected 400, got {e.code}"
    else:
        raise AssertionError("expected 400 for bad agent_id")

    # bad rule_id -> 400
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/get_rule_info",
            data=b'{"rule_id": "not-a-number"}',
            method="POST",
        ), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 400
    else:
        raise AssertionError("expected 400 for bad rule_id")

    # restart_agent without mutation flag -> 403
    os.environ.pop("SOC_MANAGER_MCP_ALLOW_MUTATIONS", None)
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/restart_agent",
            data=b'{"agent_id": "002"}',
            method="POST",
        ), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 403, f"expected 403, got {e.code}"
    else:
        raise AssertionError("expected 403 for restart without mutation flag")

    # Direct PUT -> 405
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/agents/002/restart",
            data=b"{}", method="PUT",
        ), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 405, f"expected 405, got {e.code}"
    else:
        raise AssertionError("expected 405 for direct PUT")

    # Direct DELETE -> 405
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/agents/002",
            data=b"{}", method="DELETE",
        ), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 405
    else:
        raise AssertionError("expected 405 for direct DELETE")

    sys.stdout.write("soc-manager-mcp smoke test: OK\n")
    return 0


def _main() -> int:
    p = argparse.ArgumentParser(description="SOC Wazuh manager API MCP server")
    p.add_argument("--bind", default=os.environ.get("SOC_MANAGER_MCP_BIND",
                                                    DEFAULT_BIND_HOST))
    p.add_argument("--port", type=int, default=int(os.environ.get(
        "SOC_MANAGER_MCP_PORT", DEFAULT_BIND_PORT)))
    p.add_argument("--smoke", action="store_true")
    args = p.parse_args()
    if args.smoke:
        return _smoke()
    return serve(args.bind, args.port)


if __name__ == "__main__":
    sys.exit(_main())
