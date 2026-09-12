#!/usr/bin/env python3
"""SOC ticket API MCP server (Track C, task C3 — 2026-08-08).

A stdlib HTTP server that exposes a ticket API to SOC agents
as MCP-style tools. Backed by a local append-only JSONL file
(`~/.openclaw/soc_tickets.jsonl` by default) so the system
works without any external dependency. Designed to be replaced
later by a real ticket system (mailcow's REST API, Jira, etc.)
without changing the tool surface that the agents depend on.

Why a local JSONL store first
-----------------------------
The SOC agents currently produce "ticket" as a *recommendation*
in the soc-comms output (a channel/priority pair), but the
actual ticket system doesn't exist yet — there is no place to
file, search, or close a ticket. C3 fills that gap. We start
with a JSONL store because:

  1. It's the same shape as the audit log (Track B), so the
     pattern is proven and the daily curator can ingest it.
  2. There's no auth, schema, or migration to design up
     front — we ship the surface, then plug the real backend
     in later (the tool shape doesn't change).
  3. The system works offline (no mailcow/Jira network
     dependency), so the SOC fleet can be tested hermetically.

The tool surface here is the *contract* that future mailcow
integration will satisfy. When that lands, the only thing
that changes is the implementation of these tools; the agents
that call them are untouched.

Tools
-----
  * create_ticket(title, body, severity, source_alert_ref=None,
                  source_run_id=None, assignee=None, labels=None)
        -> {ok, ticket}  MUTATING (writes)
  * get_ticket(ticket_id)
        -> {ok, ticket}
  * list_tickets(status=None, severity=None, assignee=None,
                 limit=100, offset=0)
        -> {ok, tickets[], total, params}
  * search_tickets(q, limit=50)
        -> {ok, tickets[], total}   (case-insensitive substring
                                     over title/body/labels)
  * update_ticket(ticket_id, status=None, assignee=None,
                  add_comment=None, add_labels=None,
                  remove_labels=None)
        -> {ok, ticket}  MUTATING (writes)
  * close_ticket(ticket_id, resolution_note=None)
        -> {ok, ticket}  MUTATING (alias for update with
                                  status=closed + close time)

All writes are gated by `SOC_TICKET_MCP_ALLOW_WRITES=1` (off
by default). Reads are always on. The same precedent as
C2's `SOC_MANAGER_MCP_ALLOW_MUTATIONS`.

The server is a single stdlib HTTP endpoint bound to 127.0.0.1
(port 8768 by default). The transport is plain JSON-over-HTTP
(same shape as the rest of the SOC MCP servers).

Design constraints
------------------
  - Stdlib only. No third-party deps.
  - Read-only by default. Writes are gated by env flag.
  - Append-only when writing — `update_ticket` rewrites the
    matching line in place; everything else appends.
  - Bound to 127.0.0.1 by default. Set
    `SOC_TICKET_MCP_BIND=lan` only behind a firewall.
  - Capped response size: 5 MB.
  - Atomic writes: tempfile + fsync + os.replace in the same
    directory.
  - Ticket IDs are `TKT-YYYYMMDD-NNN` where NNN is a
    per-day counter re-read from the file on every create
    (no in-memory state, so restarts are safe and two
    processes on the same file are safe to within a day).

Created 2026-08-08 by Ciceron as part of Track C (C3).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import tempfile
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
DEFAULT_BIND_PORT = 8768
DEFAULT_TICKETS_PATH = os.path.expanduser("~/.openclaw/soc_tickets.jsonl")
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
TOOLS = (
    "create_ticket",
    "get_ticket",
    "list_tickets",
    "search_tickets",
    "update_ticket",
    "close_ticket",
)

# Allowed severities and statuses. Keep these tight so the
# downstream mailcow adapter has a stable contract.
ALLOWED_SEVERITY = ("low", "medium", "high", "critical")
ALLOWED_STATUS = ("open", "in_progress", "waiting", "closed")

# Length caps — a real ticket system will have its own, but we
# bound everything so a runaway agent can't write 1 GB.
TITLE_MAX = 200
BODY_MAX = 8000
COMMENT_MAX = 4000
ASSIGNEE_MAX = 64
LABEL_MAX = 64
LABELS_MAX_COUNT = 16
COMMENTS_MAX = 64

_ID_RE = re.compile(r"^TKT-\d{8}-\d{1,6}$")
_ASSIGNEE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


# ---------------------------------------------------------------------------
# Ticket store
# ---------------------------------------------------------------------------
def _tickets_path() -> str:
    p = os.environ.get("SOC_TICKETS_LOG", DEFAULT_TICKETS_PATH)
    return os.path.expanduser(p)


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(
        timespec="milliseconds")


def _today_compact() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d")


def _load_all() -> List[Dict[str, Any]]:
    """Read the ticket file line-by-line. Skips blank lines and
    non-JSON lines. The file is small (10s-100s of tickets) and
    this keeps the design hermetic."""
    path = _tickets_path()
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
                    f"[soc-tickets-mcp] skipping non-JSON line at "
                    f"{path}:{i+1}\n")
    return out


def _next_id(records: List[Dict[str, Any]]) -> str:
    """Compute the next TKT-YYYYMMDD-NNN id. Per-day counter:
    re-read from the file on every call (no in-memory state)."""
    today = _today_compact()
    prefix = f"TKT-{today}-"
    max_n = 0
    for r in records:
        tid = r.get("id", "")
        if tid.startswith(prefix):
            try:
                n = int(tid[len(prefix):])
                if n > max_n:
                    max_n = n
            except ValueError:
                pass
    return f"{prefix}{max_n + 1:03d}"


def _atomic_write(records: List[Dict[str, Any]]) -> None:
    """Write all records to the ticket file atomically."""
    path = _tickets_path()
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    # NamedTemporaryFile + rename = atomic on POSIX.
    fd, tmp_path = tempfile.mkstemp(
        prefix=".soc_tickets.", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def _require_writes_enabled() -> None:
    if os.environ.get("SOC_TICKET_MCP_ALLOW_WRITES", "0") != "1":
        raise PermissionError(
            "writes disabled: set SOC_TICKET_MCP_ALLOW_WRITES=1 to enable "
            "create_ticket / update_ticket / close_ticket (and any future "
            "mutating tools)")


def _validate_field(value: Any, *, label: str, max_len: int,
                    pattern: Optional[re.Pattern] = None) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    if len(value) > max_len:
        raise ValueError(f"{label} exceeds {max_len} chars (got {len(value)})")
    if pattern and not pattern.match(value):
        raise ValueError(f"bad {label}: {value!r}")
    return value


def _find_by_id(records: List[Dict[str, Any]],
                ticket_id: str) -> Tuple[int, Dict[str, Any]]:
    if not _ID_RE.match(ticket_id):
        raise ValueError(f"bad ticket_id: {ticket_id!r}")
    for i, r in enumerate(records):
        if r.get("id") == ticket_id:
            return i, r
    raise LookupError(f"ticket_id not found: {ticket_id}")


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------
def tool_create_ticket(args: Dict[str, Any]) -> Dict[str, Any]:
    """create_ticket(title, body, severity, source_alert_ref=None,
                    source_run_id=None, assignee=None, labels=None)
    -> {ok, ticket}"""
    _require_writes_enabled()
    title = _validate_field(args.get("title"), label="title",
                            max_len=TITLE_MAX)
    body = _validate_field(args.get("body"), label="body",
                           max_len=BODY_MAX)
    sev = _validate_field(args.get("severity"), label="severity",
                          max_len=16)
    if sev not in ALLOWED_SEVERITY:
        raise ValueError(
            f"bad severity: {sev!r} (allowed: {ALLOWED_SEVERITY})")
    if not body.strip():
        raise ValueError("body must be non-empty")
    if not title.strip():
        raise ValueError("title must be non-empty")
    assignee = args.get("assignee")
    if assignee is not None:
        assignee = _validate_field(assignee, label="assignee",
                                    max_len=ASSIGNEE_MAX,
                                    pattern=_ASSIGNEE_RE)
    labels = args.get("labels") or []
    if not isinstance(labels, list):
        raise ValueError("labels must be a list of strings")
    if len(labels) > LABELS_MAX_COUNT:
        raise ValueError(
            f"too many labels (max {LABELS_MAX_COUNT}, got {len(labels)})")
    labels = [_validate_field(l, label="label", max_len=LABEL_MAX,
                              pattern=_LABEL_RE) for l in labels]
    source_alert_ref = args.get("source_alert_ref")
    if source_alert_ref is not None and not isinstance(
            source_alert_ref, str):
        raise ValueError("source_alert_ref must be a string")
    if source_alert_ref and len(source_alert_ref) > 256:
        raise ValueError("source_alert_ref exceeds 256 chars")
    source_run_id = args.get("source_run_id")
    if source_run_id is not None and not isinstance(source_run_id, str):
        raise ValueError("source_run_id must be a string")
    if source_run_id and len(source_run_id) > 128:
        raise ValueError("source_run_id exceeds 128 chars")

    records = _load_all()
    tid = _next_id(records)
    ticket = {
        "id": tid,
        "title": title,
        "body": body,
        "severity": sev,
        "status": "open",
        "assignee": assignee,
        "source_alert_ref": source_alert_ref,
        "source_run_id": source_run_id,
        "labels": labels,
        "comments": [],
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "closed_at": None,
        "schema": 1,
    }
    records.append(ticket)
    _atomic_write(records)
    return {"ok": True, "tool": "create_ticket", "ticket": ticket}


def tool_get_ticket(args: Dict[str, Any]) -> Dict[str, Any]:
    """get_ticket(ticket_id) -> {ok, ticket}"""
    tid = args.get("ticket_id")
    if not tid:
        raise ValueError("ticket_id is required")
    _validate_field(tid, label="ticket_id", max_len=32, pattern=_ID_RE)
    records = _load_all()
    _, t = _find_by_id(records, tid)
    return {"ok": True, "tool": "get_ticket", "ticket": t}


def tool_list_tickets(args: Dict[str, Any]) -> Dict[str, Any]:
    """list_tickets(status=None, severity=None, assignee=None,
                   source_run_id=None, limit=100, offset=0)
    -> sorted by created_at DESC.

    2026-08-14: added source_run_id filter so the SOC dashboard
    can render tickets linked to a given run on the per-run
    detail page. Validation mirrors create_ticket's source_run_id
    rules (str, ≤128 chars).
    """
    status = args.get("status")
    if status is not None and status not in ALLOWED_STATUS:
        raise ValueError(
            f"bad status: {status!r} (allowed: {ALLOWED_STATUS})")
    severity = args.get("severity")
    if severity is not None and severity not in ALLOWED_SEVERITY:
        raise ValueError(
            f"bad severity: {severity!r} (allowed: {ALLOWED_SEVERITY})")
    assignee = args.get("assignee")
    if assignee is not None:
        _validate_field(assignee, label="assignee", max_len=ASSIGNEE_MAX,
                        pattern=_ASSIGNEE_RE)
    source_run_id = args.get("source_run_id")
    if source_run_id is not None:
        if not isinstance(source_run_id, str):
            raise ValueError("source_run_id must be a string")
        if len(source_run_id) > 128:
            raise ValueError("source_run_id exceeds 128 chars")
        if not source_run_id:
            # Treat empty string the same as omitted (don't
            # silently match everything). Easy to get this
            # wrong from JS without a guard.
            source_run_id = None
    limit = min(int(args.get("limit") or 100), 1000)
    offset = max(int(args.get("offset") or 0), 0)

    records = _load_all()
    out = []
    for r in records:
        if status and r.get("status") != status:
            continue
        if severity and r.get("severity") != severity:
            continue
        if assignee and r.get("assignee") != assignee:
            continue
        if source_run_id and r.get("source_run_id") != source_run_id:
            continue
        out.append(r)
    out.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    page = out[offset:offset + limit]
    return {
        "ok": True,
        "tool": "list_tickets",
        "params": {"status": status, "severity": severity,
                   "assignee": assignee, "source_run_id": source_run_id,
                   "limit": limit, "offset": offset},
        "total": len(out),
        "offset": offset,
        "limit": limit,
        "tickets": [_ticket_summary(t) for t in page],
    }


def tool_search_tickets(args: Dict[str, Any]) -> Dict[str, Any]:
    """search_tickets(q, limit=50) -> case-insensitive substring
    match over title + body + labels."""
    q = args.get("q")
    if not q or not isinstance(q, str):
        raise ValueError("q is required and must be a string")
    if len(q) > 256:
        raise ValueError("q exceeds 256 chars")
    limit = min(int(args.get("limit") or 50), 500)
    ql = q.lower()
    out = []
    for r in _load_all():
        hay = " ".join([
            r.get("title") or "",
            r.get("body") or "",
            " ".join(r.get("labels") or []),
        ]).lower()
        if ql in hay:
            out.append(r)
    out.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    return {
        "ok": True,
        "tool": "search_tickets",
        "params": {"q": q, "limit": limit},
        "total": len(out),
        "limit": limit,
        "tickets": [_ticket_summary(t) for t in out[:limit]],
    }


def tool_update_ticket(args: Dict[str, Any]) -> Dict[str, Any]:
    """update_ticket(ticket_id, status=None, assignee=None,
    add_comment=None, add_labels=None, remove_labels=None)
    -> {ok, ticket}. All fields except ticket_id are optional;
    only the ones provided are mutated. Setting status='closed'
    also sets closed_at."""
    _require_writes_enabled()
    tid = args.get("ticket_id")
    if not tid:
        raise ValueError("ticket_id is required")
    _validate_field(tid, label="ticket_id", max_len=32, pattern=_ID_RE)
    records = _load_all()
    idx, t = _find_by_id(records, tid)
    if t.get("status") == "closed":
        raise ValueError(
            f"ticket {tid} is closed; reopen by setting status='open' "
            f"first, then update")
    new_status = args.get("status")
    if new_status is not None and new_status not in ALLOWED_STATUS:
        raise ValueError(
            f"bad status: {new_status!r} (allowed: {ALLOWED_STATUS})")
    new_assignee = args.get("assignee")
    if new_assignee is not None:
        # empty string means "unassign"
        if new_assignee == "":
            t["assignee"] = None
        else:
            t["assignee"] = _validate_field(
                new_assignee, label="assignee", max_len=ASSIGNEE_MAX,
                pattern=_ASSIGNEE_RE)
    elif "assignee" in args:
        # explicit null to clear
        t["assignee"] = None
    add_comment = args.get("add_comment")
    if add_comment is not None:
        author = args.get("comment_author") or "system"
        _validate_field(author, label="comment_author", max_len=64)
        body = _validate_field(add_comment, label="add_comment",
                               max_len=COMMENT_MAX)
        comments = t.setdefault("comments", [])
        if len(comments) >= COMMENTS_MAX:
            raise ValueError(
                f"ticket {tid} already has {COMMENTS_MAX} comments; "
                f"refusing to append")
        comments.append({
            "ts": _now_iso(),
            "author": author,
            "body": body,
        })
    add_labels = args.get("add_labels") or []
    if not isinstance(add_labels, list):
        raise ValueError("add_labels must be a list of strings")
    remove_labels = args.get("remove_labels") or []
    if not isinstance(remove_labels, list):
        raise ValueError("remove_labels must be a list of strings")
    if add_labels or remove_labels:
        labels = list(t.get("labels") or [])
        for l in add_labels:
            v = _validate_field(l, label="add_label", max_len=LABEL_MAX,
                                pattern=_LABEL_RE)
            if v not in labels:
                labels.append(v)
        for l in remove_labels:
            v = _validate_field(l, label="remove_label", max_len=LABEL_MAX,
                                pattern=_LABEL_RE)
            if v in labels:
                labels.remove(v)
        if len(labels) > LABELS_MAX_COUNT:
            raise ValueError(
                f"label count after update would be {len(labels)}, "
                f"max is {LABELS_MAX_COUNT}")
        t["labels"] = labels
    if new_status is not None:
        t["status"] = new_status
        if new_status == "closed" and not t.get("closed_at"):
            t["closed_at"] = _now_iso()
    t["updated_at"] = _now_iso()
    records[idx] = t
    _atomic_write(records)
    return {"ok": True, "tool": "update_ticket", "ticket": t}


def tool_close_ticket(args: Dict[str, Any]) -> Dict[str, Any]:
    """close_ticket(ticket_id, resolution_note=None) -> {ok, ticket}.
    Alias for update_ticket with status='closed' and an optional
    final comment."""
    _require_writes_enabled()
    return tool_update_ticket({
        "ticket_id": args.get("ticket_id"),
        "status": "closed",
        "add_comment": args.get("resolution_note"),
        "comment_author": args.get("resolution_author") or "system",
    })


def _ticket_summary(t: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": t.get("id"),
        "title": t.get("title"),
        "severity": t.get("severity"),
        "status": t.get("status"),
        "assignee": t.get("assignee"),
        "labels": t.get("labels") or [],
        "source_alert_ref": t.get("source_alert_ref"),
        "source_run_id": t.get("source_run_id"),
        "comment_count": len(t.get("comments") or []),
        "created_at": t.get("created_at"),
        "updated_at": t.get("updated_at"),
        "closed_at": t.get("closed_at"),
    }


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    server_version = "soc-tickets-mcp/1.0"

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
            path = _tickets_path()
            exists = os.path.exists(path)
            writable = exists and os.access(path, os.W_OK)
            self._json(200, {
                "ok": True,
                "server": self.server_version,
                "tickets_path": path,
                "writable": writable,
                "writes_enabled": (
                    os.environ.get("SOC_TICKET_MCP_ALLOW_WRITES",
                                   "0") == "1"),
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
            "create_ticket": tool_create_ticket,
            "get_ticket": tool_get_ticket,
            "list_tickets": tool_list_tickets,
            "search_tickets": tool_search_tickets,
            "update_ticket": tool_update_ticket,
            "close_ticket": tool_close_ticket,
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
            sys.stderr.write(f"[soc-tickets-mcp] unhandled: {e!r}\n{traceback.format_exc()}\n")
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
        f"[soc-tickets-mcp] listening on http://{bind_host}:{bind_port} "
        f"(tickets={_tickets_path()}, "
        f"writes={'on' if os.environ.get('SOC_TICKET_MCP_ALLOW_WRITES') == '1' else 'off'})\n"
    )
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("[soc-tickets-mcp] shutting down\n")
        srv.shutdown()
    return 0


def _smoke() -> int:
    """Self-test: hermetic — uses a temp file under /tmp.

    Exercises transport + validation + write/read/update/close
    lifecycle + writes-disabled 403 + 405s.
    """
    import shutil
    import threading
    import urllib.request as ur

    tmpdir = tempfile.mkdtemp(prefix="soc-tickets-mcp-smoke-")
    tmp = os.path.join(tmpdir, "tickets.jsonl")
    os.environ["SOC_TICKETS_LOG"] = tmp
    os.environ["SOC_TICKET_MCP_ALLOW_WRITES"] = "1"

    port = 18768
    t = threading.Thread(target=serve, args=("127.0.0.1", port), daemon=True)
    t.start()
    time.sleep(0.5)

    # /healthz
    with ur.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as r:
        body = json.loads(r.read())
        assert body["ok"] is True
        assert body["writes_enabled"] is True
        assert body["tickets_path"] == tmp

    # /tools
    with ur.urlopen(f"http://127.0.0.1:{port}/tools", timeout=2) as r:
        body = json.loads(r.read())
        assert set(body["tools"]) == set(TOOLS), body["tools"]

    # create_ticket (TKT-1)
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/create_ticket",
            data=json.dumps({
                "title": "Brute-force on darth",
                "body": "Rule 40112 fired; 15 attempts from 10.9.8.7",
                "severity": "high",
                "assignee": "wez",
                "labels": ["bruteforce", "ssh"],
            }).encode(),
            method="POST"), timeout=2) as r:
        body = json.loads(r.read())
        assert body["ok"] is True
        tid1 = body["ticket"]["id"]
        assert tid1.startswith("TKT-"), tid1
        assert re.match(r"^TKT-\d{8}-\d{3}$", tid1), tid1
        assert body["ticket"]["status"] == "open"
        assert body["ticket"]["assignee"] == "wez"
        assert body["ticket"]["labels"] == ["bruteforce", "ssh"]
        assert body["ticket"]["comments"] == []
        assert body["ticket"]["schema"] == 1

    # create_ticket (TKT-2)
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/create_ticket",
            data=json.dumps({
                "title": "Suspicious login on mail.example.com",
                "body": "Rule 5763 fired; 15 attempts to root",
                "severity": "critical",
                "source_alert_ref": "wazuh:5763:agent006",
                "source_run_id": "r-test-1",
            }).encode(),
            method="POST"), timeout=2) as r:
        body = json.loads(r.read())
        assert body["ok"] is True
        tid2 = body["ticket"]["id"]
        assert tid2 != tid1, body

    # Per-day counter should keep both under the same date.
    assert tid1.split("-")[1] == tid2.split("-")[1], (tid1, tid2)
    n1 = int(tid1.split("-")[-1])
    n2 = int(tid2.split("-")[-1])
    assert n2 == n1 + 1, (n1, n2)

    # get_ticket
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/get_ticket",
            data=json.dumps({"ticket_id": tid1}).encode(),
            method="POST"), timeout=2) as r:
        body = json.loads(r.read())
        assert body["ticket"]["title"] == "Brute-force on darth"
        assert body["ticket"]["severity"] == "high"

    # get_ticket bad id -> 400
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/get_ticket",
            data=b'{"ticket_id":"TKT-bad"}', method="POST"), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 400
    else:
        raise AssertionError("expected 400 for bad ticket_id")

    # get_ticket missing -> 404
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/get_ticket",
            data=b'{"ticket_id":"TKT-20260808-999"}', method="POST"),
            timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 404
    else:
        raise AssertionError("expected 404 for missing")

    # list_tickets (no filter, newest first)
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/list_tickets",
            data=b"{}", method="POST"), timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 2
        assert body["tickets"][0]["id"] == tid2  # newest first
        assert body["tickets"][1]["id"] == tid1
        # summaries don't have the body field
        assert "body" not in body["tickets"][0]
        assert body["tickets"][0]["comment_count"] == 0

    # list_tickets severity=critical
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/list_tickets",
            data=b'{"severity":"critical"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 1
        assert body["tickets"][0]["id"] == tid2

    # list_tickets status=closed (none yet)
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/list_tickets",
            data=b'{"status":"closed"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 0

    # list_tickets assignee=wez
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/list_tickets",
            data=b'{"assignee":"wez"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 1
        assert body["tickets"][0]["id"] == tid1

    # list_tickets source_run_id (tid2 was created with
    # source_run_id=r-test-1; tid1 had none). 2026-08-14.
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/list_tickets",
            data=b'{"source_run_id":"r-test-1"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 1, body
        assert body["tickets"][0]["id"] == tid2, body
        assert body["params"]["source_run_id"] == "r-test-1", body

    # list_tickets source_run_id with no matches -> empty, not error.
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/list_tickets",
            data=b'{"source_run_id":"nope-no-such-run"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 0, body
        assert body["tickets"] == [], body

    # list_tickets source_run_id validation: non-string -> 400.
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/list_tickets",
            data=b'{"source_run_id":123}', method="POST"), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 400, f"expected 400, got {e.code}"
    else:
        raise AssertionError("expected 400 for non-string source_run_id")

    # list_tickets source_run_id validation: too long -> 400.
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/list_tickets",
            data=json.dumps({"source_run_id": "x" * 129}).encode(),
            method="POST"), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 400, f"expected 400, got {e.code}"
    else:
        raise AssertionError("expected 400 for too-long source_run_id")

    # search_tickets
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/search_tickets",
            data=b'{"q":"darth"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 1
        assert body["tickets"][0]["id"] == tid1

    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/search_tickets",
            data=b'{"q":"bruteforce"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 1  # matches the label

    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/search_tickets",
            data=b'{"q":"nope-not-here"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 0

    # update_ticket: status -> in_progress, add comment + label
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/update_ticket",
            data=json.dumps({
                "ticket_id": tid1,
                "status": "in_progress",
                "add_comment": "investigating, blocked on agent 9.9.9.7",
                "comment_author": "soc-triage",
                "add_labels": ["needs-ioc"],
            }).encode(),
            method="POST"), timeout=2) as r:
        body = json.loads(r.read())
        assert body["ok"] is True
        assert body["ticket"]["status"] == "in_progress"
        assert body["ticket"]["labels"] == ["bruteforce", "ssh", "needs-ioc"]
        assert len(body["ticket"]["comments"]) == 1
        assert body["ticket"]["comments"][0]["author"] == "soc-triage"
        assert "blocked" in body["ticket"]["comments"][0]["body"]
        assert body["ticket"]["closed_at"] is None

    # update_ticket: remove_labels
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/update_ticket",
            data=json.dumps({
                "ticket_id": tid1,
                "remove_labels": ["ssh"],
            }).encode(),
            method="POST"), timeout=2) as r:
        body = json.loads(r.read())
        assert body["ticket"]["labels"] == ["bruteforce", "needs-ioc"]

    # update_ticket: status -> closed (via update_ticket directly)
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/update_ticket",
            data=json.dumps({
                "ticket_id": tid1,
                "status": "closed",
            }).encode(),
            method="POST"), timeout=2) as r:
        body = json.loads(r.read())
        assert body["ticket"]["status"] == "closed"
        assert body["ticket"]["closed_at"] is not None

    # update on closed ticket -> 400
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/update_ticket",
            data=json.dumps({"ticket_id": tid1, "status": "open"}).encode(),
            method="POST"), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 400
    else:
        raise AssertionError("expected 400 for updating closed ticket")

    # close_ticket on the open one
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/close_ticket",
            data=json.dumps({
                "ticket_id": tid2,
                "resolution_note": "false positive, source IP is internal",
                "resolution_author": "soc-incident-reviewer",
            }).encode(),
            method="POST"), timeout=2) as r:
        body = json.loads(r.read())
        assert body["ok"] is True
        assert body["ticket"]["status"] == "closed"
        assert body["ticket"]["closed_at"] is not None
        assert len(body["ticket"]["comments"]) == 1
        assert body["ticket"]["comments"][0]["author"] == "soc-incident-reviewer"

    # list_tickets status=closed -> both
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/list_tickets",
            data=b'{"status":"closed"}', method="POST"),
            timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 2

    # Bad severity -> 400
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/create_ticket",
            data=json.dumps({"title": "x", "body": "y",
                              "severity": "emergency"}).encode(),
            method="POST"), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 400
    else:
        raise AssertionError("expected 400 for bad severity")

    # Body too long -> 400
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/create_ticket",
            data=json.dumps({"title": "x", "body": "y" * (BODY_MAX + 1),
                              "severity": "low"}).encode(),
            method="POST"), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 400
    else:
        raise AssertionError("expected 400 for body too long")

    # Writes disabled -> 403 (flip env without restart — we
    # test this with a *fresh* server since the env is read
    # at request time only via _require_writes_enabled; that
    # function reads os.environ on every call, so this works).
    os.environ["SOC_TICKET_MCP_ALLOW_WRITES"] = "0"
    try:
        ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/create_ticket",
            data=json.dumps({"title": "x", "body": "y",
                              "severity": "low"}).encode(),
            method="POST"), timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 403, f"expected 403, got {e.code}"
    else:
        raise AssertionError("expected 403 for writes disabled")
    # But reads still work
    with ur.urlopen(ur.Request(
            f"http://127.0.0.1:{port}/tools/list_tickets",
            data=b"{}", method="POST"), timeout=2) as r:
        body = json.loads(r.read())
        assert body["total"] == 2
    os.environ["SOC_TICKET_MCP_ALLOW_WRITES"] = "1"

    # Direct PUT/DELETE -> 405
    for m in ("PUT", "DELETE"):
        try:
            ur.urlopen(ur.Request(
                f"http://127.0.0.1:{port}/tools/list_tickets",
                data=b"{}", method=m), timeout=2)
        except urllib.error.HTTPError as e:
            assert e.code == 405, f"{m}: expected 405, got {e.code}"
        else:
            raise AssertionError(f"expected 405 for {m}")

    # Cleanup
    shutil.rmtree(tmpdir, ignore_errors=True)
    sys.stdout.write("soc-tickets-mcp smoke test: OK\n")
    return 0


def _main() -> int:
    p = argparse.ArgumentParser(description="SOC ticket API MCP server")
    p.add_argument("--bind", default=os.environ.get("SOC_TICKET_MCP_BIND",
                                                    DEFAULT_BIND_HOST))
    p.add_argument("--port", type=int, default=int(os.environ.get(
        "SOC_TICKET_MCP_PORT", DEFAULT_BIND_PORT)))
    p.add_argument("--smoke", action="store_true")
    args = p.parse_args()
    if args.smoke:
        return _smoke()
    return serve(args.bind, args.port)


if __name__ == "__main__":
    sys.exit(_main())
