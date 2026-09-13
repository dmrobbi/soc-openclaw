#!/usr/bin/env python3
"""SOC task log (2026-09-13) — records every task the SOC system runs
(compliance scans, agent-restart scans, evidence/score recomputes) to a
JSONL file so the dashboard can show a vCenter-style task pane and a
historic /tasks drill-down.

Line shape:
    {"id": "<12-hex>", "ts": <started iso>, "kind": "compliance_scan",
     "target": "RPI42", "status": "running|done|failed",
     "ended": <iso|null>, "details": {...}}

The file lives at $SOC_TASKS_LOG (default ~/.openclaw/soc/tasks.jsonl).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

TASKS_LOG = Path(os.environ.get(
    "SOC_TASKS_LOG", os.path.expanduser("~/.openclaw/soc/tasks.jsonl")))


def _task_id(ts: str, kind: str, target: str) -> str:
    return hashlib.sha1(f"{ts}|{kind}|{target}".encode()).hexdigest()[:12]


def record_task(kind: str, target: str, status: str,
                started: str, ended: Optional[str] = None,
                details: Optional[Dict[str, Any]] = None) -> str:
    """Append one task record; returns its stable id. Appends a NEW row
    per state change (tasks are keyed by ts+kind+target — the latest row
    for an id is its current state)."""
    TASKS_LOG.parent.mkdir(parents=True, exist_ok=True)
    rec = {
        "id": _task_id(started, kind, target),
        "ts": started,
        "kind": kind,
        "target": target,
        "status": status,
        "ended": ended,
        "details": details or {},
    }
    with open(TASKS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, default=str) + "\n")
    return rec["id"]


def load_tasks(limit: int = 200) -> List[Dict[str, Any]]:
    """Rows newest-first, deduped by id (latest row wins)."""
    if not TASKS_LOG.exists():
        return []
    rows: Dict[str, Dict[str, Any]] = {}
    with open(TASKS_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(r, dict) and r.get("id"):
                rows[r["id"]] = r
    out = sorted(rows.values(), key=lambda r: r.get("ts") or "",
                 reverse=True)
    return out[:max(1, int(limit))]


def get_task(task_id: str) -> Optional[Dict[str, Any]]:
    if not TASKS_LOG.exists():
        return None
    hits = []
    with open(TASKS_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(r, dict) and r.get("id") == task_id:
                hits.append(r)
    if not hits:
        return None
    if len(hits) == 1:
        return hits[0]
    out = dict(hits[-1])
    out["history"] = hits
    return out