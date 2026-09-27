#!/usr/bin/env python3
"""Laya shadow client for the AI SOC (Phase 1.3).

Stdlib-only client that SOC services import for LAYA_MODE-managed shadow
predictions against a local laya-serve. NEVER raises — shadow must not break
the pipeline it observes.

Modes (env LAYA_MODE, default off):
  off     — no-op (no network, no log)
  shadow  — predict + log to laya-shadow.jsonl; caller ignores the result
  gated   — Phase 2: same as shadow today; caller may act on confident answers

Log rows: {ts, mode, endpoint, state_hash, state_chars, input_tokens, latency_ms,
answers{id:{choice|noul|score,confidence,answer_confidence}}, routing{model,repo},
error, context{...caller-supplied: alert ids, LLM verdict...}}

Self-test:  LAYA_MODE=shadow python3 laya_shadow.py --selftest
"""
import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DEFAULT_ENDPOINT = "http://127.0.0.1:8099"
DEFAULT_LOG = "/opt/soc-openclaw/data/laya-shadow.jsonl"

# --- SOC triage question set v1 (mirror of evals/laya_questions.yaml triage) ---
# --- SOC triage question set v1.1 (2026-09-26) ------------------------------
# severity REMOVED: deterministic from rule level since Option B (contract
# mapping in the ingest fallback) — Laya never needed for it (rich-state eval:
# level-mapping 1.00 vs Laya 0.269). Shadow keeps the NON-deterministic
# questions only; 3 questions/predict (~25% faster shadow latency).
TRIAGE_QUESTIONS = {
    "known_pattern": {
        "type": "noul",
        "instructions": "Is this a known, recurring event pattern (seen before, expected in this environment)?",
    },
    "response": {
        "type": "choice",
        "instructions": "Which immediate response does this alert warrant?",
        "criteria": {
            "note_only": "log a note only",
            "digest_only": "include in the periodic digest",
            "email": "email the analyst now",
            "page": "notify the analyst immediately (call/pager)",
            "auto_remediate": "apply the known-safe automated remediation",
        },
    },
    "escalate": {
        "type": "noul",
        "instructions": "Should this alert open an incident / reach a human now (high severity or unclear pattern)?",
    },
}


def extract_level(a: dict) -> int:
    """Robust rule-level extraction (nested wazuh format + flat fallbacks)."""
    rule = a.get("rule")
    if isinstance(rule, dict) and rule.get("level") is not None:
        try:
            return int(re.sub(r"[^0-9]", "", str(rule["level"])) or 0)
        except (ValueError, TypeError):
            pass
    low = {str(k).lower(): v for k, v in a.items()}
    raw = low.get("level", low.get("rule_level", 0))
    try:
        return int(re.sub(r"[^0-9]", "", str(raw)) or 0)
    except (ValueError, TypeError):
        return 0


def _first(d, *keys, default=None):
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return default


EMAIL_QUESTIONS = {
    "reply_worthy": {
        "type": "noul",
        "instructions": "Should the SOC send a substantive human reply to this inbound email?",
    },
    "priority": {
        "type": "score",
        "instructions": "How urgent is a response to this email?",
        "criteria": ["anytime", "soon", "critical"],
    },
    "automated_noise": {
        "type": "noul",
        "instructions": "Is this automated noise (bounce, notification, bot, ticket auto-update) rather than a human asking something?",
    },
}


def build_email_state(from_addr, subject, body, action=None, in_reply_to=None) -> str:
    """Compact state text from an inbound email (~<=300 tokens)."""
    import re as _re
    parts = ["Inbound email to the SOC reports mailbox."]
    if from_addr:
        parts.append(f"From: {from_addr}.")
    if subject:
        parts.append(f"Subject: {str(subject)[:200]}.")
    if action:
        parts.append(f"Router action: {action}.")
    if in_reply_to:
        parts.append("(it is a threaded reply)")
    if body:
        b = _re.sub(r"\s+", " ", str(body))[:1200]
        parts.append(f"Body: {b}")
    return " ".join(parts)


def build_alert_state(a: dict) -> str:
    """Compact state text from a wazuh alert dict (<= ~150 tokens)."""
    rule = a.get("rule") or {}
    desc = str(_first(rule, "description", default="") or "")[:220]
    agent = _first(a.get("agent") or {}, "name") or "unknown-agent"
    data = a.get("data") or {}
    srcip = _first(data, "srcip", "src_ip", "source_ip")
    decoder = a.get("decoder")
    decoder = decoder.get("name") if isinstance(decoder, dict) else decoder
    parts = [f"Wazuh alert rule {rule.get('id')} severity level {rule.get('level')} on agent {agent}."]
    if desc:
        parts.append(f"Rule: {desc}.")
    if decoder:
        parts.append(f"Decoder: {decoder}.")
    if srcip:
        parts.append(f"Source IP: {srcip}.")
    loc = a.get("location")
    if loc:
        parts.append(f"Location: {loc}.")
    return " ".join(parts)


class LayaShadow:
    def __init__(self, endpoint=None, mode=None, log_path=None, timeout=5.0):
        self.endpoint = (endpoint or os.environ.get("LAYA_ENDPOINT") or DEFAULT_ENDPOINT).rstrip("/")
        self.mode = (mode or os.environ.get("LAYA_MODE") or "off").strip().lower()
        self.log_path = log_path or os.environ.get("LAYA_SHADOW_LOG") or DEFAULT_LOG
        self.timeout = timeout
        self._lock = threading.Lock()

    @property
    def enabled(self):
        return self.mode in ("shadow", "gated")

    def health(self):
        req = urllib.request.Request(self.endpoint + "/health")
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.load(r)

    def predict(self, state, questions, context=None, model=None):
        """One decision. Returns the log row (or None when off/failed). Never raises."""
        if not self.enabled:
            return None
        row = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "mode": self.mode,
            "endpoint": self.endpoint,
            "state_hash": hashlib.sha256(state.encode("utf-8", "replace")).hexdigest()[:16],
            "state_chars": len(state),
            "input_tokens": None,
            "latency_ms": None,
            "answers": None,
            "routing": None,
            "error": None,
            "context": context or {},
        }
        payload = {"state": state, "questions": questions}
        if model:
            payload["model"] = model
        t0 = time.perf_counter()
        try:
            req = urllib.request.Request(
                self.endpoint + "/v1/systemone",
                data=json.dumps(payload).encode("utf-8"),
                headers={"content-type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                resp = json.load(r)
            row["answers"] = {
                q: {k: a.get(k) for k in ("type", "choice", "noul", "score",
                                          "confidence", "answer_confidence")}
                for q, a in (resp.get("answers") or {}).items()
            }
            row["routing"] = {k: (resp.get("routing") or {}).get(k) for k in ("model", "repo")}
            row["input_tokens"] = (resp.get("usage") or {}).get("input_tokens")
        except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
            row["error"] = repr(exc)[:200]
        row["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        self._log(row)
        return None if row["error"] else row

    def _log(self, row):
        try:
            d = os.path.dirname(self.log_path)
            if d:
                os.makedirs(d, exist_ok=True)
            with self._lock, open(self.log_path, "a") as f:
                f.write(json.dumps(row, default=str) + "\n")
        except OSError as exc:  # logging must never break the caller
            print(f"laya_shadow: log write failed: {exc!r}", file=sys.stderr)


def _selftest():
    sh = LayaShadow(mode=os.environ.get("LAYA_MODE") or "shadow")
    print("mode:", sh.mode, "endpoint:", sh.endpoint)
    print("health:", json.dumps(sh.health()))
    alert = {"rule": {"level": 12, "id": "5763", "description": "Multiple authentication failures."},
             "agent": {"name": "mail.stsgym.com"}, "data": {"srcip": "10.0.0.5"},
             "decoder": {"name": "sshd"}, "location": "/var/log/auth.log"}
    row = sh.predict(build_alert_state(alert), dict(TRIAGE_QUESTIONS),
                     context={"alert_id": "SELFTEST", "note": "selftest"})
    print("shadow row:", json.dumps(row, indent=2))
    return 0 if row else 1


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    print(__doc__)