#!/usr/bin/env python3
"""Lite in-repo replacement for `agentic_ai.agents.cyber.soc`.

Provides exactly the slice the realtime ingest + imap-watcher services
need, stdlib-only, triaging through the local OpenClaw sub-agents
instead of the bundled SecurityOperationsAgent:

  - SecurityOperationsAgent(agent_id=...) with .alerts / .incidents
  - .ingest_wazuh_alert(alert_dict) -> alert record (+ auto-incident)
  - .triage_inbound_email(...)      -> allowlist / thread-reply routing
  - .record_outbound_subject(...)   -> Message-ID -> incident tracking
  - module-level _RECENT_OUTBOUND / _RECENT_OUTBOUND_MAX

Allowlist: set `SOC_EMAIL_ALLOWLIST` (comma-separated addresses and/or
@example.com domains). Default: the reports mailbox itself.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "lib"))

from llm_runtime import call_llm  # noqa: E402

_RECENT_OUTBOUND: "Dict[str, str]" = {}
_RECENT_OUTBOUND_MAX = 1024

_RECIPIENT = os.environ.get("WAZUH_REPORTS_RECIPIENT", "")
_MAILBOX = os.environ.get("REPORTS_MAILBOX", "")
_extra = os.environ.get("SOC_EMAIL_ALLOWLIST", "")
_addrs = {x.strip().lower() for x in re.split(r"[,;\s]+", _extra) if x.strip()}
for a in (_RECIPIENT.lower(), _MAILBOX.lower()):
    if a:
        _addrs.add(a)
_DOMAINS = frozenset(x.split("@", 1)[1] for x in _addrs if "@" in x)
ALLOWLIST_ADDRESSES = frozenset(a for a in _addrs if "@" in a)
ALLOWLIST_DOMAINS = _DOMAINS


class SecurityOperationsAgent:  # lite
    def __init__(self, agent_id: str = "soc-lite") -> None:
        self.agent_id = agent_id
        self.alerts: Dict[str, dict] = {}
        self.incidents: Dict[str, dict] = {}
        self._n = 0

    # -- outbound tracking (same semantics as the full agent) ------------
    def record_outbound_subject(self, incident_id: str, message_id: str) -> None:
        if not incident_id or not message_id:
            return
        tag = message_id.strip().lstrip("<").rstrip(">").split("@", 1)[0]
        if len(_RECENT_OUTBOUND) >= _RECENT_OUTBOUND_MAX:
            next(iter(_RECENT_OUTBOUND.keys()))
            _RECENT_OUTBOUND.pop(next(iter(_RECENT_OUTBOUND)), None)
        _RECENT_OUTBOUND[tag] = incident_id

    # -- inbound email triage (allowlist + thread match, no LLM) ---------
    def triage_inbound_email(self, message_id, from_addr, subject, body,
                             in_reply_to=None, references=None, headers=None) -> dict:
        from_re = (from_addr or "").lower()
        at = from_re.rfind("@")
        domain = from_re[at + 1:] if at >= 0 else ""
        from_allowed = from_re in ALLOWLIST_ADDRESSES or domain in ALLOWLIST_DOMAINS

        matched = None
        refs = list(in_reply_to or []) if isinstance(in_reply_to, list) else [in_reply_to]
        refs += list(references or [])
        for ref in refs:
            if not ref:
                continue
            tag = str(ref).strip().lstrip("<").rstrip(">").split("@", 1)[0]
            if tag in _RECENT_OUTBOUND:
                matched = tag
                break
        if not from_allowed:
            return {"action": "review_later", "from_allowed": False,
                    "reason": f"sender {from_re!r} not in allowlist",
                    "message_id": message_id}
        if matched:
            return {"action": "respond_thread", "from_allowed": True,
                    "matched_incident_id": matched,
                    "reason": f"reply to incident {matched}",
                    "message_id": message_id}
        return {"action": "respond", "from_allowed": True,
                "reason": "free-form SOC question", "message_id": message_id}

    # -- realtime alert ingest ------------------------------------------
    def ingest_wazuh_alert(self, a: dict) -> dict:
        self._n += 1
        ts = datetime.now(timezone.utc).isoformat()
        # Option A (2026-09-26): nested-aware extraction — wazuh traffic arrives
        # as {rule: {...}, agent: {name}, data: {srcip}}; flat keys still win.
        def _scalar(v):
            if isinstance(v, dict):
                for k in ("name", "id", "value"):
                    if v.get(k) is not None:
                        return v[k]
                return ""
            return v

        def _nf(*names, default=""):
            for src in [a] + [a[s] for s in ("rule", "agent", "data", "decoder")
                              if isinstance(a.get(s), dict)]:
                lowered = {str(k).lower(): v for k, v in src.items()}
                for n in names:
                    if n in lowered:
                        return _scalar(lowered[n])
                    for k, v in lowered.items():
                        if n in k:
                            return _scalar(v)
            return default

        level = int(re.sub(r"[^0-9]", "", str(_nf("level", "rule_level", default="0")) or "0") or 0)
        host = str(_nf("agent_name", "host", "agent"))
        alert_id = f"ALERT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{self._n:06d}"
        rec = {
            "alert_id": alert_id, "ts": ts, "level": level,
            "rule_id": str(_nf("rule_id", "id")),
            "rule_description": str(_nf("rule_description", "description")),
            "agent_name": host,
            "src_ip": str(_nf("src_ip", "srcip", "source_ip")),
            "full_alert": a,
        }
        # Phase 2 (2026-09-26, option B): no LLM turn per alert (see
        # realtime_ingest) — deterministic severity + laya shadow carry triage.
        triage = "deterministic severity; no LLM turn (phase 2)"
        rec["triage"] = triage
        self.alerts[alert_id] = rec

        # Option B (2026-09-26): contract mapping (IDENTITY.md) — see realtime_ingest
        if level >= 14:
            sev = "critical"
        elif level >= 12:
            sev = "high"
        elif level >= 8:
            sev = "medium"
        elif level >= 3:
            sev = "low"
        else:
            sev = "informational"
        if sev in ("critical", "high"):
            inc_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{self._n:06d}"
            self.incidents[inc_id] = {
                "incident_id": inc_id,
                "title": f"[L{level}] {host or 'unknown'}",
                "severity": sev, "status": "open",
                "description": triage[:600], "detected_at": ts,
                "alert_id": alert_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        return rec