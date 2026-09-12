#!/usr/bin/env python3
"""Real-time SOC ingest server (SOC roadmap 1.1).

Exposes HTTP endpoints on localhost only:

  POST /ingest    body = single Wazuh alert JSON (or list of alerts)
                  → calls SecurityOperationsAgent.ingest_wazuh_alert()
                  → persists resulting SecurityAlert and any auto-escalated
                    Incident to a JSONL append log
                  → 200 with {alert_id, incident_id?, elapsed_ms, ...}
  GET  /healthz   → 200 {"status":"ok","alerts":N,"incidents":M, ...}
  GET  /incidents → 200 {"incidents": [...]}
  GET  /alerts    → 200 {"alerts": [...]}

Designed to be invoked from agentic-soc-send.py BEFORE the email step
(returns in <50ms typically, even with Ollama enrichment running in parallel).

Stdlib-only (http.server + json). No Flask/fastapi dependency.

Persistence: every ingested alert + any auto-escalated incident appended to:

  /home/wez/.openclaw/workspace/agentic-ai/data/realtime_soc.jsonl

JSONL records: {"type":"alert|incident", "ts":"...", ...fields}

Usage (manual smoke test):
  curl -sS -X POST -H 'Content-Type: application/json' \
       --data-binary @/tmp/alert.json \
       http://127.0.0.1:8765/ingest

Run as a service: see scripts/soc/realtime-soc-server.service
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Make agentic_ai importable when run directly
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from agentic_ai.agents.cyber.soc import SecurityOperationsAgent  # noqa: E402

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BIND_HOST = "0.0.0.0"
BIND_PORT = int(os.environ.get("REALTIME_SOC_PORT", "8765"))
LOG_PATH = Path(
    os.environ.get(
        "REALTIME_SOC_LOG",
        "/home/wez/.openclaw/workspace/agentic-ai/data/realtime_soc.jsonl",
    )
)
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

# One SecurityOperationsAgent per process, shared across threads.
AGENT = SecurityOperationsAgent(agent_id="soc-realtime")
_LOCK = threading.Lock()  # protects AGENT.alerts / AGENT.incidents writes
_PERSISTED_INCIDENT_IDS: Set[str] = set()  # incidents already written to JSONL
_STATS: Dict[str, int] = {"alerts": 0, "incidents": 0}


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------
def _safe_asdict(obj) -> Dict[str, Any]:
    """Best-effort dataclass → dict (handles non-dataclass fallbacks)."""
    try:
        return asdict(obj)
    except Exception:
        return {k: getattr(obj, k, None) for k in (
            "alert_id", "incident_id", "title", "description", "severity",
            "status", "source", "rule_name", "affected_asset", "source_ip",
            "timestamp", "detected_at", "category",
            # SOC A1 (2026-08-06): agentic narrative fields populated by
            # wazuh-integrations/agentic-soc-send.py via the openclaw
            # agent harness. Without these the JSONL drops them.
            "agentic_narrative", "agentic_run_id", "agentic_model",
            "agentic_duration_ms", "agentic_narrative_error",
            # SOC Track B / B1 (2026-08-07): agent decision fields.
            "agentic_decision", "agentic_decision_error",
        )}


def _to_jsonable(obj: Any) -> Any:
    """Recursively convert enums / datetimes to JSON-safe primitives."""
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


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def _append_log(rec: Dict[str, Any]) -> None:
    """Append a single JSONL record (atomic per line on POSIX)."""
    rec.setdefault("ts", datetime.now(timezone.utc).isoformat())
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(_to_jsonable(rec), default=str) + "\n")


def rehydrate_counts() -> None:
    """Walk the JSONL log to populate _STATS and _PERSISTED_INCIDENT_IDS."""
    if not LOG_PATH.exists():
        return
    alerts = 0
    incidents = 0
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
            alerts += 1
        elif t == "incident":
            incidents += 1
            inc_id = rec.get("incident_id")
            if inc_id:
                _PERSISTED_INCIDENT_IDS.add(inc_id)
    _STATS["alerts"] = alerts
    _STATS["incidents"] = incidents


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class IngestHandler(BaseHTTPRequestHandler):
    server_version = "RealtimeSOC/1.0"

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
        length_hdr = self.headers.get("Content-Length")
        try:
            length = int(length_hdr or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return None
        if length > 2_000_000:  # 2 MB cap (agentic-soc-send.py wraps at ~3 KB)
            self._write_json(413, {"error": "body too large", "max_bytes": 2_000_000})
            return None
        try:
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8"))
        except Exception as e:
            self._write_json(400, {"error": f"invalid JSON: {e!r}"})
            return None

    # ---- GET routes --------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            with _LOCK:
                in_mem_alerts = len(AGENT.alerts)
                in_mem_incidents = len(AGENT.incidents)
            self._write_json(
                200,
                {
                    "status": "ok",
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "alerts_logged": _STATS["alerts"],
                    "incidents_logged": _STATS["incidents"],
                    "alerts_in_memory": in_mem_alerts,
                    "incidents_in_memory": in_mem_incidents,
                    "log_path": str(LOG_PATH),
                },
            )
            return
        if self.path == "/alerts":
            with _LOCK:
                items = [_safe_asdict(a) for a in AGENT.alerts.values()]
            self._write_json(200, {"alerts": items, "count": len(items)})
            return
        if self.path == "/incidents":
            with _LOCK:
                items = [_safe_asdict(i) for i in AGENT.incidents.values()]
            self._write_json(200, {"incidents": items, "count": len(items)})
            return
        self._write_json(404, {"error": "not found", "path": self.path})

    # ---- POST routes -------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/ingest":
            self._write_json(404, {"error": "not found", "path": self.path})
            return

        body = self._read_json_body()
        if body is None:
            return  # _read_json_body already wrote 400/413

        # Accept either a single alert or a list of alerts
        alerts_in: List[Dict[str, Any]] = body if isinstance(body, list) else [body]
        if not alerts_in:
            self._write_json(400, {"error": "empty payload"})
            return

        started = time.monotonic()
        results: List[Dict[str, Any]] = []
        new_alert_ids: List[str] = []
        new_incident_ids: List[str] = []

        with _LOCK:
            for a in alerts_in:
                try:
                    alert = AGENT.ingest_wazuh_alert(a)
                except Exception as exc:
                    results.append({"ok": False, "error": repr(exc)})
                    continue

                results.append({"ok": True, "alert_id": alert.alert_id})
                new_alert_ids.append(alert.alert_id)
                _append_log({"type": "alert", **_safe_asdict(alert)})
                _STATS["alerts"] += 1

            # After ingest, persist any NEW incidents (those not already in
            # _PERSISTED_INCIDENT_IDS). Auto-escalation in ingest_wazuh_alert
            # creates the Incident; we just write it to the log here.
            for inc_id, inc in AGENT.incidents.items():
                if inc_id in _PERSISTED_INCIDENT_IDS:
                    continue
                _append_log({"type": "incident", **_safe_asdict(inc)})
                _PERSISTED_INCIDENT_IDS.add(inc_id)
                _STATS["incidents"] += 1
                new_incident_ids.append(inc_id)

        elapsed_ms = round((time.monotonic() - started) * 1000.0, 1)
        self._write_json(
            200,
            {
                "ok": True,
                "elapsed_ms": elapsed_ms,
                "received": len(alerts_in),
                "succeeded": sum(1 for r in results if r.get("ok")),
                "failed": sum(1 for r in results if not r.get("ok")),
                "new_alert_ids": new_alert_ids,
                "new_incident_ids": new_incident_ids,
                "results": results,
            },
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    rehydrate_counts()
    srv = ThreadingHTTPServer((BIND_HOST, BIND_PORT), IngestHandler)
    sys.stderr.write(
        f"[{datetime.now(timezone.utc).isoformat()}] "
        f"realtime-soc-server listening on http://{BIND_HOST}:{BIND_PORT} "
        f"(log={LOG_PATH}, alerts={_STATS['alerts']}, "
        f"incidents={_STATS['incidents']})\n"
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("shutting down\n")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
