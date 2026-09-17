#!/usr/bin/env python3
"""Realtime SOC ingest server — self-contained port (soc-openclaw).

Wazuh's `agentic-soc-send.py` integration POSTs alerts here; the server
triages each alert and appends JSONL records to
`$REALTIME_SOC_LOG` (default ~/.openclaw/soc/data/realtime_soc.jsonl).

HTTP contract (identical to the original Agentic-SOC 1.1 server):
    GET  /healthz   -> status/counters
    GET  /alerts    -> in-memory alerts
    GET  /incidents -> auto-escalated incidents
    POST /ingest    -> single alert dict, or a list of alert dicts
                       (as produced by agentic-soc-send.py)

Triage backends, selected automatically:
  1. Full agent: if the `agentic_ai` package (SecurityOperationsAgent)
     is importable, it is used exactly like the original server.
  2. Lite backend (default here): every alert is triaged by the local
     OpenClaw `soc-triage` sub-agent via lib/llm_runtime (stdlib only).
     A severity >= 7 (or triage text containing "escalate") opens an
     Incident.

Env:
  REALTIME_SOC_PORT   (default 8765)
  REALTIME_SOC_LOG    (default ~/.openclaw/soc/data/realtime_soc.jsonl)
  REALTIME_TRIAGE     (default "1") — call the LLM per alert
  SOC_LLM_RUNTIME     ("openclaw" | "ollama")
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Make lib/ (llm_runtime) importable when run from anywhere
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "lib"))

from llm_runtime import call_llm  # noqa: E402

# Optional heavy backend: the full SecurityOperationsAgent (if the
# operator has the agentic_ai project installed alongside).
try:  # pragma: no cover - environment-dependent
    ROOT = HERE.parent.parent.parent  # repo root if vendored
    _prev = None
    for p in os.environ.get("AGENTIC_AI_PATH", "").split(":"):
        if p:
            sys.path.insert(0, p)
    from agentic_ai.agents.cyber.soc import SecurityOperationsAgent  # type: ignore

    HAVE_FULL_AGENT = True
except Exception:  # ImportError and friends
    HAVE_FULL_AGENT = False

BIND_HOST = "0.0.0.0"
BIND_PORT = int(os.environ.get("REALTIME_SOC_PORT", "8765"))
LOG_PATH = Path(os.environ.get(
    "REALTIME_SOC_LOG",
    os.path.expanduser("~/.openclaw/soc/data/realtime_soc.jsonl"),
))

MAX_BODY = 2_000_000
ESCALATE_LEVEL = int(os.environ.get("REALTIME_ESCALATE_LEVEL", "10"))

_STATSCMD = {"alerts": 0, "incidents": 0}
_PERSISTED_INCIDENT_IDS: Set[str] = set()
_LOCK = threading.Lock()

_ALERT_SEQ = [0]


def _new_alert_id() -> str:
    _ALERT_SEQ[0] += 1
    return f"ALERT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{_ALERT_SEQ[0]:06d}"


def _new_incident_id() -> str:
    return f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{_ALERT_SEQ[0]:06d}"


# ---------------------------------------------------------------------------
# Lite triage agent (stdlib-only fallback for SecurityOperationsAgent)
# ---------------------------------------------------------------------------
class LiteTriageAgent:
    """Keeps alerts/incidents in memory and triages via the OpenClaw
    soc-triage sub-agent.  Mirrors the slice of SecurityOperationsAgent
    that the ingest server depends on: alerts / incidents dicts,
    ingest_wazuh_alert(), auto-escalation to incidents."""

    def __init__(self, agent_id: str = "soc-realtime") -> None:
        self.agent_id = agent_id
        self.alerts: Dict[str, dict] = {}
        self.incidents: Dict[str, dict] = {}
        self._n = 0

    def _field(self, a: dict, *names: str, default: str = "") -> str:
        lowered = {str(k).lower(): v for k, v in a.items()}
        for n in names:
            if n in lowered:
                return str(lowered[n])
            for k, v in lowered.items():
                if n in k:
                    return str(v)
        return default

    def ingest_wazuh_alert(self, a: dict) -> dict:
        """Triages one Wazuh alert dict; returns the stored alert record."""
        self._n += 1
        alert_id = f"ALERT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{self._n:06d}"
        rule_id = self._field(a, "rule_id", "id")
        rule_desc = self._field(a, "rule_description", "description", "rule")
        level_raw = self._field(a, "level", "rule_level", default="0")
        try:
            level = int(re.sub(r"[^0-9]", "", level_raw) or 0)
        except ValueError:
            level = 0
        host = self._field(a, "agent_name", "host", "hostname", "agent")
        src_ip = self._field(a, "src_ip", "srcip", "source_ip")
        ts = self._field(a, "timestamp", "ts", default=datetime.now(timezone.utc).isoformat())

        triage_text = ""
        triage_ok = False
        try:
            r = call_llm(
                agent_id="soc-triage",
                message=json.dumps(a, default=str)[:4000],
                audit=False,
                timeout=25.0,
            )
            triage_ok = bool(r.ok)
            triage_text = (r.text or "").strip()
        except Exception as exc:  # triage is best-effort
            triage_text = f"triage unavailable: {exc!r}"

        sev = "low"
        if level >= 12:
            sev = "critical"
        elif level >= 10:
            sev = "high"
        elif level >= 7:
            sev = "medium"
        if triage_ok:
            m = re.search(r"severity['\": =]+(critical|high|medium|low|info)", triage_text, re.I)
            if m:
                sev = m.group(1).lower()

        alert = {
            "alert_id": alert_id,
            "ts": ts,
            "level": level,
            "severity": sev,
            "rule_id": rule_id,
            "rule_description": rule_desc,
            "agent_name": host,
            "src_ip": src_ip,
            "triage": triage_text[:800],
            "triage_ok": triage_ok,
            "full_alert": a,
        }
        self.alerts[alert_id] = alert

        escalate = (
            sev in ("critical", "high")
            or (triage_ok and re.search(r"\bescalate\b", triage_text, re.I) is not None)
        )
        if escalate:
            inc_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{self._n:06d}"
            self.incidents[inc_id] = {
                "incident_id": inc_id,
                "title": f"[L{level}] {host or 'unknown'}: {rule_id_summary(alert)}",
                "severity": sev,
                "status": "open",
                "description": triage_text[:600],
                "affected_systems": [host] if host else [],
                "source_ip": src_ip,
                "detected_at": ts,
                "alert_id": alert_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        return alert


def rule_id_summary(rec: dict) -> str:
    d = rec.get("rule_description") or rec.get("description") or ""
    return str(d)[:60]


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def _to_jsonable(obj):
    from enum import Enum
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(v) for v in obj]
    return obj


def _append_log(rec: Dict[str, Any]) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    rec.setdefault("ts", datetime.now(timezone.utc).isoformat())
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(_to_jsonable(rec), default=str) + "\n")


_STATS = {"alerts": 0, "incidents": 0}


def rehydrate_counts() -> None:
    if not LOG_PATH.exists():
        return
    for line in LOG_PATH.open(encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = rec.get("type")
        if t == "alert":
            _STATS["alerts"] += 1
        elif t == "incident":
            _STATS["incidents"] += 1
            inc_id = rec.get("incident_id")
            if inc_id:
                _PERSISTED_INCIDENT_IDS.add(inc_id)


# ---------------------------------------------------------------------------
# Agent selection
# ---------------------------------------------------------------------------
if HAVE_FULL_AGENT:
    AGENT = SecurityOperationsAgent(agent_id="soc-realtime")
    BACKEND = "full-agent"
else:
    AGENT = LiteTriageAgent(agent_id="soc-realtime")
    BACKEND = "lite-triage"


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class IngestHandler(BaseHTTPRequestHandler):
    server_version = "RealtimeSOC/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        sys.stderr.write(
            f"[{datetime.now(timezone.utc).isoformat()}] "
            f"{self.address_string()} - {format % args}\n"
        )

    def _write_json(self, code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(_to_jsonable(payload), default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Optional[Any]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return None
        if length > MAX_BODY:
            self._write_json(413, {"error": "body too large", "max_bytes": MAX_BODY})
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception as e:
            self._write_json(400, {"error": f"invalid JSON: {e!r}"})
            return None

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            with _LOCK:
                self._write_json(200, {
                    "status": "ok",
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "backend": BACKEND,
                    "alerts_logged": _STATS["alerts"],
                    "incidents_logged": _STATS["incidents"],
                    "alerts_in_memory": len(AGENT.alerts),
                    "incidents_in_memory": len(AGENT.incidents),
                    "log_path": str(LOG_PATH),
                })
            return
        if self.path == "/alerts":
            with _LOCK:
                items = list(AGENT.alerts.values())
            self._write_json(200, {"alerts": items, "count": len(items)})
            return
        if self.path == "/incidents":
            with _LOCK:
                items = list(AGENT.incidents.values())
            self._write_json(200, {"incidents": items, "count": len(items)})
            return
        self._write_json(404, {"error": "not found", "path": self.path})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/ingest":
            self._write_json(404, {"error": "not found", "path": self.path})
            return
        body = self._read_json_body()
        if body is None:
            return
        alerts_in: List[dict] = body if isinstance(body, list) else [body]
        if not alerts_in:
            self._write_json(400, {"error": "empty payload"})
            return

        started = time.monotonic()
        results: List[dict] = []
        new_incident_ids: List[str] = []
        with _LOCK:
            for a in alerts_in:
                try:
                    alert = AGENT.ingest_wazuh_alert(a)
                except Exception as exc:
                    results.append({"ok": False, "error": repr(exc)})
                    continue
                results.append({"ok": True, "alert_id": alert.get("alert_id", "")})
                _append_log({"type": "alert", **alert})
                _STATS["alerts"] += 1
            for inc_id, inc in AGENT.incidents.items():
                if inc_id in _PERSISTED_INCIDENT_IDS:
                    continue
                _append_log({"type": "incident", **inc})
                _PERSISTED_INCIDENT_IDS.add(inc_id)
                _STATS["incidents"] += 1
                new_incident_ids.append(inc_id)
        elapsed_ms = round((time.monotonic() - started) * 1000.0, 1)
        self._write_json(200, {
            "ok": True,
            "elapsed_ms": elapsed_ms,
            "results": results,
            "new_incident_ids": new_incident_ids,
        })


def serve(bind_host: str = BIND_HOST, bind_port: int = BIND_PORT) -> int:
    rehydrate_counts()
    srv = ThreadingHTTPServer((bind_host, bind_port), IngestHandler)
    sys.stderr.write(
        f"[realtime-soc] listening on http://{bind_host}:{bind_port} "
        f"(backend={BACKEND}, log={LOG_PATH})\n"
    )
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(serve())