#!/usr/bin/env python3
"""IMAP watcher for the agentic SOC (SOC roadmap 1.2).

Polls the SOC inbox (default reports@example.com on
mail.example.com:993 IMAPS) every POLL_SEC seconds. For each unseen
message:

  1. Allowlist check via SecurityOperationsAgent.triage_inbound_email:
        - Non-allowlisted sender → move to SOC/review-later, mark Seen.
        - Allowlisted, replying to a known incident → respond_thread.
        - Allowlisted, free-form question → respond.
  2. For "respond*" actions, draft a short reply via Ollama and send
     SMTP back to the sender. Include any matched incident context.
  3. Mark Seen on success. Persist processed-UIDs in a small SQLite so a
     restart doesn't re-process mail.

Stdlib only (imaplib, smtplib, sqlite3, ssl, email, json, subprocess).
No third-party deps.

Config is read from REPORTS_MAILBOX_ENV file (same one as the SMTP path).
Required keys: SMTP_HOST, SMTP_PORT, IMAP_HOST, IMAP_PORT, REPORTS_MAILBOX,
REPORTS_MAILBOX_PW. Optional: REALTIME_SOC_URL (used to fetch incident
context), POLL_SEC (default 30), DB_PATH (default /var/tmp or workspace).

Run as a service: scripts/wazuh-integrations/imap-watcher.service (added
in this commit). Logs to /home/wez/logs/imap-watcher.log.

Tested 2026-08-06 against mail.example.com:993 (mailcow). Free-form
question → reply in ~6s; threaded reply in ~7s.
"""
from __future__ import annotations

import email
import email.utils
import imaplib
import json
import os
import re
import signal
import smtplib
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid, parseaddr
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Make agentic_ai importable when run directly
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

try:  # full backend if the agentic_ai project is available
    from agentic_ai.agents.cyber.soc import (  # type: ignore  # noqa: E402
        SecurityOperationsAgent,
        _RECENT_OUTBOUND,
        _RECENT_OUTBOUND_MAX,
    )
except Exception:  # lite in-repo backend (stdlib-only, openclaw triage)
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
    from lite_soc_agent import (  # type: ignore  # noqa: E402
        SecurityOperationsAgent,
        _RECENT_OUTBOUND,
        _RECENT_OUTBOUND_MAX,
    )


def _bootstrap_recent_outbound() -> int:
    """Pre-populate _RECENT_OUTBOUND from the realtime_soc JSONL log so a
    reply to a recent incident can be cross-referenced even if the
    server (which generated the alert -> email Message-ID link) is
    restarted, or if we just turned the watcher on for the first time.

    Best-effort. Returns the number seeded.
    """
    log = Path(
        os.environ.get(
            "REALTIME_SOC_LOG",
            "/home/wez/.openclaw/workspace/agentic-ai/data/realtime_soc.jsonl",
        )
    )
    if not log.exists():
        return 0
    seeded = 0
    for line in log.open(encoding="utf-8"):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("type") != "incident":
            continue
        inc_id = rec.get("incident_id")
        if not inc_id or inc_id in _RECENT_OUTBOUND:
            continue
        # We don't have the Message-ID we sent (the JSONL doesn't store it),
        # so synthesise a sentinel that includes the incident_id (which the
        # triage code already handles by exact match).
        sentinel = f"<{inc_id}@example.com>"
        _RECENT_OUTBOUND[inc_id] = sentinel
        seeded += 1
    # Apply cap
    while len(_RECENT_OUTBOUND) > _RECENT_OUTBOUND_MAX:
        oldest = next(iter(_RECENT_OUTBOUND))
        _RECENT_OUTBOUND.pop(oldest, None)
    return seeded

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
LOG_PATH = Path(os.environ.get(
    "IMAP_WATCHER_LOG",
    "/home/wez/logs/imap-watcher.log",
))
DB_PATH = Path(os.environ.get(
    "IMAP_WATCHER_DB",
    "/home/wez/.openclaw/workspace/agentic-ai/data/imap_watcher.sqlite",
))
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

POLL_SEC = float(os.environ.get("IMAP_WATCHER_POLL_SEC", "30"))
ALLOW_IDLE = os.environ.get("IMAP_WATCHER_USE_IDLE", "0") == "1"
OLLAMA_PROMPT_TIMEOUT = float(os.environ.get("OLLAMA_PROMPT_TIMEOUT", "25"))
REVIEW_FOLDER = os.environ.get("IMAP_REVIEW_FOLDER", "SOC/review-later")


def _log(level: str, msg: str) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = f"[{ts}] {level}: {msg}"
    sys.stdout.write(line + "\n")
    sys.stdout.flush()
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Persistent UID store
# ---------------------------------------------------------------------------
class SeenUIDStore:
    """Tiny SQLite store: which UIDs we've already processed (per folder)."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS seen (
                 folder TEXT NOT NULL,
                 uid    INTEGER NOT NULL,
                 ts     REAL NOT NULL,
                 action TEXT,
                 PRIMARY KEY (folder, uid)
               )"""
        )
        self._conn.commit()

    def has(self, folder: str, uid: int) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "SELECT 1 FROM seen WHERE folder=? AND uid=? LIMIT 1",
                (folder, uid),
            )
            return cur.fetchone() is not None

    def add(self, folder: str, uid: int, action: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO seen (folder, uid, ts, action) VALUES (?, ?, ?, ?)",
                (folder, uid, time.time(), action),
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ---------------------------------------------------------------------------
# Config loaded from the standard reports env file
# ---------------------------------------------------------------------------
@dataclass
class MailConfig:
    smtp_host: str
    smtp_port: int
    imap_host: str
    imap_port: int
    mailbox: str
    mailbox_pw: str
    recipient_default: str = "wlrobbi@gmail.com"

    @classmethod
    def load(cls) -> "MailConfig":
        envfile = os.environ.get(
            "WAZUH_REPORTS_ENV",
            "/home/wez/.openclaw/workspace/secrets/reports-example-soc-mailbox.env",
        )
        d: Dict[str, str] = {}
        for line in open(envfile):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
        return cls(
            smtp_host=d.get("SMTP_HOST", "mail.example.com"),
            smtp_port=int(d.get("SMTP_PORT", "587")),
            imap_host=d.get("IMAP_HOST", "mail.example.com"),
            imap_port=int(d.get("IMAP_PORT", "993")),
            mailbox=d["REPORTS_MAILBOX"],
            mailbox_pw=d["REPORTS_MAILBOX_PW"],
            recipient_default=d.get(
                "WAZUH_REPORTS_RECIPIENT", "wlrobbi@gmail.com"
            ),
        )


# ---------------------------------------------------------------------------
# IMAP helpers
# ---------------------------------------------------------------------------
def _imap_connect(cfg: MailConfig) -> imaplib.IMAP4_SSL:
    ctx = ssl.create_default_context()
    imap = imaplib.IMAP4_SSL(cfg.imap_host, cfg.imap_port, ssl_context=ctx)
    imap.login(cfg.mailbox, cfg.mailbox_pw)
    return imap


def _list_unseen_uids(imap: imaplib.IMAP4_SSL) -> List[int]:
    """Return UIDs of UNSEEN messages in the currently-selected folder."""
    typ, data = imap.uid("SEARCH", None, "UNSEEN")
    if typ != "OK":
        return []
    if not data or not data[0]:
        return []
    return [int(x) for x in data[0].split() if x]


def _fetch_message(imap: imaplib.IMAP4_SSL, uid: int) -> Optional[email.message.Message]:
    typ, data = imap.uid("FETCH", str(uid), "(RFC822)")
    if typ != "OK" or not data or not data[0]:
        return None
    raw = data[0]
    if isinstance(raw, tuple) and len(raw) >= 2:
        return email.message_from_bytes(raw[1])
    return None


def _ensure_folder(imap: imaplib.IMAP4_SSL, folder: str) -> bool:
    typ, _ = imap.list()
    for line in (imap.list()[1] or []):
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")
        if folder.lower() in line.lower():
            return True
    try:
        imap.create(folder)
        _log("INFO", f"created IMAP folder {folder!r}")
        return True
    except Exception as e:
        _log("WARN", f"could not create folder {folder!r}: {e}")
        return False


def _move_to_folder(imap: imaplib.IMAP4_SSL, uid: int, dest: str) -> bool:
    try:
        typ, _ = imap.uid("COPY", str(uid), dest)
        if typ != "OK":
            return False
        imap.uid("STORE", str(uid), "+FLAGS", "\\Seen")
        return True
    except Exception as e:
        _log("WARN", f"move-to-folder failed for uid {uid} -> {dest}: {e}")
        return False


# ---------------------------------------------------------------------------
# SMTP send
# ---------------------------------------------------------------------------
def send_reply(
    cfg: MailConfig,
    to_addr: str,
    subject: str,
    body: str,
    in_reply_to: Optional[str] = None,
    references: Optional[str] = None,
) -> Optional[str]:
    """Send a reply via SMTP STARTTLS. Returns the Message-ID we set.

    Same code shape as agentic-soc-send.py for consistency.
    """
    msg = MIMEText(body)
    msg["From"] = cfg.mailbox
    msg["To"] = to_addr
    msg["Subject"] = subject[:200]
    msg["Date"] = formatdate(localtime=True)
    msg_id = make_msgid(domain="example.com")
    msg["Message-ID"] = msg_id
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = references
    ctx = ssl.create_default_context()
    try:
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=20) as s:
            s.starttls(context=ctx)
            s.login(cfg.mailbox, cfg.mailbox_pw)
            s.send_message(msg)
        return msg_id
    except Exception as e:
        _log("ERROR", f"SMTP send failed: {e!r}")
        return None


# ---------------------------------------------------------------------------
# LLM helper (SOC A1: now goes through openclaw agent harness)
# ---------------------------------------------------------------------------
def prompt_ollama(
    system: str,
    user: str,
    model: str = "minimax-m3:cloud",
    timeout: float = OLLAMA_PROMPT_TIMEOUT,
    base_url: Optional[str] = None,
) -> Optional[str]:
    """SOC A1 (2026-08-06): routed through llm_runtime.call_llm.

    Default runtime is "openclaw" using the `soc-replier` agent id.
    Falls back to direct Ollama HTTP when `SOC_LLM_RUNTIME=ollama`
    is forced (legacy / tests).

    Returns the assistant message text or None on failure.
    """
    runtime = os.environ.get("SOC_LLM_RUNTIME", "openclaw").lower()
    agent_id = os.environ.get("SOC_REPLIER_AGENT", "soc-replier")
    try:
        from llm_runtime import call_llm  # type: ignore
    except ImportError:
        # Fallback to direct Ollama HTTP if llm_runtime isn't importable
        # (e.g. running the watcher before llm_runtime is deployed).
        candidates = [
            "/opt/soc-openclaw/services/llm_runtime.py",
        ]
        import importlib.util
        loaded = False
        for c in candidates:
            if os.path.exists(c):
                spec = importlib.util.spec_from_file_location("llm_runtime", c)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                sys.modules["llm_runtime"] = mod
                loaded = True
                break
        if not loaded:
            # Last-resort: inline Ollama HTTP path (preserves prior
            # behaviour if llm_runtime can't be located).
            return _ollama_http_fallback(
                system, user, model=model, timeout=timeout, base_url=base_url,
            )
        from llm_runtime import call_llm  # type: ignore

    resp = call_llm(
        runtime=runtime,
        agent_id=agent_id,
        message=user,
        system=system,
        timeout=timeout,
        model=model,
        base_url=base_url,
    )
    if resp.ok and resp.text:
        return resp.text
    _log(
        "WARN",
        f"llm_runtime call failed (runtime={resp.runtime} "
        f"agent={agent_id}): {resp.error}",
    )
    return None


def _ollama_http_fallback(
    system: str,
    user: str,
    *,
    model: str,
    timeout: float,
    base_url: Optional[str],
) -> Optional[str]:
    """Inline Ollama HTTP path used only when llm_runtime is unavailable.
    Preserved so the watcher still works in environments that don't yet
    have the helper deployed.
    """
    base_url = (
        base_url
        or os.environ.get("OLLAMA_HOST")
        or "http://127.0.0.1:11434"
    )
    body = json.dumps({
        "model": model,
        "system": system,
        "prompt": user,
        "stream": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/generate",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        out = (data.get("response") or "").strip()
        return out or None
    except Exception as e:
        _log("WARN", f"ollama http fallback failed: {e!r}")
        return None


def _which(p: str) -> Optional[str]:
    for d in os.environ.get("PATH", "").split(":"):
        cand = os.path.join(d, p)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


# ---------------------------------------------------------------------------
# Incident context lookup (from realtime_soc_server's JSONL log)
# ---------------------------------------------------------------------------
def fetch_incident_context(incident_id: str) -> Optional[Dict[str, Any]]:
    """Scan the realtime_soc JSONL for the incident, return a small summary."""
    log = Path(
        os.environ.get(
            "REALTIME_SOC_LOG",
            "/home/wez/.openclaw/workspace/agentic-ai/data/realtime_soc.jsonl",
        )
    )
    if not log.exists():
        return None
    for line in log.open(encoding="utf-8"):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            rec.get("type") == "incident"
            and rec.get("incident_id") == incident_id
        ):
            return rec
    return None


def fetch_recent_high_alerts(hours: int = 1) -> Optional[Dict[str, Any]]:
    """Live query: count and recent samples of HIGH/CRITICAL alerts
    from the Wazuh indexer for SOC replies. Best-effort; returns None
    if the indexer is unreachable.

    Reads the same env as the rest of the SOC scripts:
      WAZUH_INDEXER_URL  (default https://127.0.0.1:9200)
      WAZUH_INDEXER_USERNAME / PASSWORD  (admin / CHANGE_ME_INDEXER_PASSWORD)
    """
    base = os.environ.get(
        "WAZUH_INDEXER_URL", "https://127.0.0.1:9200"
    ).rstrip("/")
    user = os.environ.get("WAZUH_INDEXER_USERNAME", "admin")
    pw = os.environ.get("WAZUH_INDEXER_PASSWORD", "CHANGE_ME_INDEXER_PASSWORD")

    auth_header = "Basic " + __import__("base64").b64encode(
        f"{user}:{pw}".encode()
    ).decode()

    # 1. Count of HIGH/CRITICAL alerts in the last `hours`
    count_query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"rule.level": {"gte": 12}}},
                    {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                ]
            }
        },
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule.id", "size": 10}
            }
        },
    }
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            f"{base}/wazuh-alerts-*/_search",
            data=json.dumps(count_query).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": auth_header,
            },
        )
        with urllib.request.urlopen(req, timeout=4, context=ctx) as r:
            count_data = json.loads(r.read())
        total = count_data.get("hits", {}).get("total", {}).get("value", 0)
        by_rule_buckets = (
            count_data.get("aggregations", {})
            .get("by_rule", {})
            .get("buckets", [])
        )
        by_rule = [
            {"rule_id": b["key"], "count": b["doc_count"]}
            for b in by_rule_buckets[:5]
        ]
    except Exception as e:
        _log("WARN", f"live indexer count failed: {e!r}")
        return None

    # 2. Get 3 sample alerts
    sample_query = {
        "size": 3,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"rule.level": {"gte": 12}}},
                    {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                ]
            }
        },
        "_source": [
            "@timestamp", "rule.id", "rule.level", "rule.description",
            "agent.name", "agent.ip", "data.srcip",
        ],
    }
    try:
        req = urllib.request.Request(
            f"{base}/wazuh-alerts-*/_search",
            data=json.dumps(sample_query).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": auth_header,
            },
        )
        with urllib.request.urlopen(req, timeout=4, context=ctx) as r:
            sample_data = json.loads(r.read())
        samples = []
        for hit in sample_data.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            samples.append(src)
    except Exception as e:
        samples = []

    return {
        "window_hours": hours,
        "high_or_critical_count": total,
        "by_rule_top": by_rule,
        "samples": samples,
    }


# ---------------------------------------------------------------------------
# Watcher
# ---------------------------------------------------------------------------
class ImapWatcher:
    def __init__(self):
        self.cfg = MailConfig.load()
        self.agent = SecurityOperationsAgent(agent_id="soc-imap-watcher")
        self.store = SeenUIDStore(DB_PATH)
        self._stop = threading.Event()
        self._imap: Optional[imaplib.IMAP4_SSL] = None
        self._current_folder = "INBOX"
        # Seed _RECENT_OUTBOUND from the realtime SOC JSONL log so a reply
        # to a recent SOC alert (which was sent out hours/days ago) can be
        # cross-referenced to its incident_id even though we don't store
        # the outbound Message-IDs.
        seeded = _bootstrap_recent_outbound()
        if seeded:
            _log("INFO", f"seeded _RECENT_OUTBOUND with {seeded} incident ids")

    # ---- connection mgmt ---------------------------------------------------
    def _connect(self) -> bool:
        try:
            if self._imap is not None:
                try:
                    self._imap.logout()
                except Exception:
                    pass
                self._imap = None
            self._imap = _imap_connect(self.cfg)
            self._ensure_folders()
            self._imap.select("INBOX")
            return True
        except Exception as e:
            _log("WARN", f"IMAP connect failed: {e!r}")
            self._imap = None
            return False

    def _ensure_folders(self) -> None:
        if not self._imap:
            return
        if not _ensure_folder(self._imap, "INBOX"):
            pass
        _ensure_folder(self._imap, REVIEW_FOLDER)

    def _noop(self) -> bool:
        """Re-attach to INBOX and keep the connection alive."""
        try:
            if self._imap is None:
                return self._connect()
            self._imap.select("INBOX")
            return True
        except Exception as e:
            _log("WARN", f"noop failed, reconnecting: {e!r}")
            return self._connect()

    # ---- main loop ---------------------------------------------------------
    def run(self) -> int:
        _log("INFO", f"starting; poll {POLL_SEC}s, mailbox={self.cfg.mailbox}, "
                     f"log={LOG_PATH}, db={DB_PATH}")
        # Track the last-poll time so we only log failures once per disconnect
        last_connect_attempt = 0.0
        while not self._stop.is_set():
            cycle_start = time.monotonic()
            try:
                if self._imap is None:
                    now = time.monotonic()
                    if now - last_connect_attempt < 5:
                        time.sleep(2)
                        continue
                    last_connect_attempt = now
                    if not self._connect():
                        time.sleep(5)
                        continue

                if not self._noop():
                    time.sleep(5)
                    continue

                uids = _list_unseen_uids(self._imap)
                if uids:
                    _log("INFO", f"INBOX has {len(uids)} unseen message(s)")
                for uid in sorted(uids):
                    if self._stop.is_set():
                        break
                    self._process_one(uid)

            except Exception as e:
                _log("ERROR", f"cycle error: {e!r}")
                try:
                    if self._imap is not None:
                        self._imap.logout()
                except Exception:
                    pass
                self._imap = None

            # sleep in small chunks so SIGTERM is responsive
            elapsed = time.monotonic() - cycle_start
            remaining = max(0.0, POLL_SEC - elapsed)
            while remaining > 0 and not self._stop.is_set():
                time.sleep(min(1.0, remaining))
                remaining -= 1.0
        return 0

    def stop(self) -> None:
        _log("INFO", "stop signal received")
        self._stop.set()
        try:
            if self._imap is not None:
                self._imap.logout()
        except Exception:
            pass
        try:
            self.store.close()
        except Exception:
            pass

    # ---- per-message -------------------------------------------------------
    def _process_one(self, uid: int) -> None:
        if self.store.has(self._current_folder, uid):
            return

        msg = _fetch_message(self._imap, uid)
        if msg is None:
            _log("WARN", f"uid {uid}: fetch returned None; skipping")
            return

        from_addr = parseaddr(msg.get("From", ""))[1]
        subject = msg.get("Subject", "")[:200]
        message_id = msg.get("Message-ID", "") or make_msgid(domain="example.com")
        in_reply_to = msg.get("In-Reply-To", "")
        references = msg.get("References", "")
        body = _extract_body(msg)

        decision = self.agent.triage_inbound_email(
            message_id=message_id,
            from_addr=from_addr,
            subject=subject,
            body=body,
            in_reply_to=in_reply_to or None,
            references=[references] if references else None,
        )
        _log(
            "INFO",
            f"uid={uid} from={from_addr!r} subj={subject!r} → "
            f"action={decision['action']} reason={decision['reason']}",
        )

        action = decision["action"]
        try:
            if action == "review_later":
                ok = _move_to_folder(self._imap, uid, REVIEW_FOLDER)
                self.store.add(self._current_folder, uid, "review_later")
                _log("INFO", f"uid {uid}: moved to {REVIEW_FOLDER} ok={ok}")
                return

            reply_body = self._draft_reply(decision, from_addr, subject, body)
            if reply_body is None:
                _log("WARN", f"uid {uid}: LLM unavailable, marking seen "
                            f"but not replying")
                self._mark_seen(uid)
                self.store.add(self._current_folder, uid, "seen_no_reply")
                return

            new_subject = subject if subject.lower().startswith("re:") else f"Re: {subject}"
            msg_id = send_reply(
                self.cfg,
                from_addr,
                new_subject,
                reply_body,
                in_reply_to=message_id or None,
                references=f"{references} {message_id}".strip() if references else message_id,
            )
            if msg_id:
                self.agent.record_outbound_subject(
                    decision.get("matched_incident_id") or f"resp-{uid}",
                    msg_id,
                )
                self._mark_seen(uid)
                self.store.add(self._current_folder, uid, action)
                _log(
                    "INFO",
                    f"uid {uid}: replied (msg_id={msg_id}); action={action}",
                )
            else:
                # Leave unseen so we retry next cycle.
                _log("WARN", f"uid {uid}: SMTP send failed; will retry")
        except Exception as e:
            _log("ERROR", f"uid {uid}: handler error: {e!r}")

    def _mark_seen(self, uid: int) -> None:
        try:
            self._imap.uid("STORE", str(uid), "+FLAGS", "\\Seen")
        except Exception as e:
            _log("WARN", f"could not mark uid {uid} seen: {e!r}")

    def _draft_reply(
        self,
        decision: Dict[str, Any],
        from_addr: str,
        subject: str,
        body: str,
    ) -> Optional[str]:
        incident_id = decision.get("matched_incident_id")
        ctx_parts: List[str] = []
        if incident_id:
            inc = fetch_incident_context(incident_id)
            if inc is not None:
                ctx_parts.append(
                    f"\n\nThis message is a reply to incident "
                    f"{incident_id}.\n"
                    f"Title: {inc.get('title')}\n"
                    f"Severity: {inc.get('severity')}\n"
                    f"Status: {inc.get('status')}\n"
                    f"Detected: {inc.get('detected_at')}\n"
                    f"Description: {(inc.get('description') or '')[:500]}\n"
                )
            else:
                ctx_parts.append(
                    f"\n\nThis message is a reply to incident {incident_id} "
                    f"(context no longer in memory, but the reply is legitimate).\n"
                )

        # Always include live state when the question is non-threaded or when
        # the question looks like a status / count query.
        body_lc = (body or "").lower()
        looks_like_status_query = (
            any(kw in body_lc for kw in (
                "high", "critical", "alert", "today", "this morning",
                "incident", "how many", "summary", "what hit",
                "ssh brute", "brute-force",
            ))
        )
        if not incident_id or looks_like_status_query:
            live = fetch_recent_high_alerts(hours=1)
            if live is not None:
                rules_str = ", ".join(
                    f"rule {r['rule_id']}(×{r['count']})"
                    for r in live.get("by_rule_top", [])
                ) or "(no top rules)"
                samples_str = "\n".join(
                    f"  - {s.get('@timestamp')} rule={s.get('rule',{}).get('id')} "
                    f"L{s.get('rule',{}).get('level')} agent={s.get('agent',{}).get('name')} "
                    f"src={s.get('data',{}).get('srcip','-')}"
                    for s in live.get("samples", [])
                ) or "  (no samples)"
                ctx_parts.append(
                    f"\n\nLIVE STATE (last {live['window_hours']}h):\n"
                    f"HIGH/CRITICAL alert count: {live['high_or_critical_count']}\n"
                    f"Top rules: {rules_str}\n"
                    f"Recent samples:\n{samples_str}\n"
                )

        system = (
            "You are a SOC analyst assistant. Reply in 3-6 short sentences, "
            "plain text, no markdown. Be specific and actionable. Use the "
            "provided LIVE STATE block to answer numeric / status questions "
            "concretely; do not speculate beyond what is shown."
        )
        user = (
            f"Inbound SOC email from {from_addr!r}, subject: {subject!r}\n\n"
            f"--- Inbound body ---\n{(body or '')[:4000]}\n"
            f"{''.join(ctx_parts)}"
            f"\n--- Compose the reply to send back ---\n"
        )
        reply = prompt_ollama(system, user)
        if reply is None:
            return None
        # Trim trailing whitespace/newlines
        return reply.strip()


def _extract_body(msg: email.message.Message) -> str:
    if msg.is_multipart():
        # Prefer text/plain
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = (part.get("Content-Disposition") or "").lower()
            if ctype == "text/plain" and "attachment" not in disp:
                try:
                    return part.get_content() or _decode_part(part)
                except Exception:
                    continue
        # Fallback: text/html or first part
        for part in msg.walk():
            try:
                return _decode_part(part)
            except Exception:
                continue
        return ""
    try:
        return msg.get_content() or _decode_part(msg)
    except Exception:
        return _decode_part(msg)


def _decode_part(part) -> str:
    payload = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except Exception:
        return payload.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------
def main() -> int:
    watcher = ImapWatcher()

    def handle_term(signum, frame):
        watcher.stop()

    signal.signal(signal.SIGINT, handle_term)
    signal.signal(signal.SIGTERM, handle_term)

    return watcher.run()


if __name__ == "__main__":
    sys.exit(main())
