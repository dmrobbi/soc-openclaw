#!/usr/bin/env python3
"""
Wazuh integration: receive a JSON alert, optionally enrich via OpenClaw,
# then email a SOC digest via reports@example.com.
#
# Created 2026-08-04 by Ciceron.
# - Receives alert JSON on stdin
# - Sends to OpenClaw (when reachable) for a 2-4 sentence narrative
# - Mails recipient via STARTTLS 587 to mail.example.com
#
# Required config (bind-mounted from /home/__SOC_USER__/.openclaw/workspace/secrets/):
#   /etc/reports-mailbox.env  -> contains REPORTS_MAILBOX, REPORTS_MAILBOX_PW,
#                                           SMTP_HOST, SMTP_PORT
#
# Optional env (override via env or via /etc/environment):
#   WAZUH_AGENTIC_ENABLE=1      (default 1; set 0 to skip the AI narrative step)
#   WAZUH_REPORTS_RECIPIENT     (default wes@example.com)
#   WAZUH_NOISE_DENYLIST        (default 1; set 0 to bypass the noise filter)
#   WAZUH_NOISE_LOG_DROPPED     (default 1; set 0 to silence the per-drop log)
"""
import os
import sys
import json
import time
import subprocess
import smtplib
import ssl
import logging
import urllib.request
import urllib.error
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid


# ---------------------------------------------------------------------------
# SOC 2.5 (2026-08-05): Noisy-rule denylist.
#
# Empirical analysis: 33,142 alerts in last 7 days; top 11 rules = 95% of
# volume. These 9 IDs are operational noise (mailcow container cycling,
# boot agent lifecycle, sshd connection-reset, PAM session open/close,
# SCA-passed). For each, exit_code=0 + no email + no OpenClaw call.
#
# Why not Wazuh-level suppression? `local_rules.xml` redefinitions with
# level=0 don't work in Wazuh 4.14 (engine uses MAX-of-matching-rules; the
# ruleset's level-N wins). `alert_by_email=no` is the same story. The only
# reliable place to drop these BEFORE they cost cycles is here.
#
# Reference: docs/soc/noisy-rule-suppression-2026-08-05.md
# ---------------------------------------------------------------------------
NOISY_RULE_IDS = frozenset({
    40704,  # L5  systemd: service exited due to failure (mailcow cycling)
    503,    # L3  Wazuh agent started (boot noise)
    506,    # L3  Wazuh agent stopped (boot noise)
    533,    # L7  Listened ports (netstat) changed (mailcow cycling)
    5740,   # L4  sshd: connection reset by peer
    5762,   # L4  sshd: connection reset
    5501,   # L3  PAM: login session opened
    5502,   # L3  PAM: login session closed
    19008,  # L3  SCA passed (compliance spam)
})

def realtime_ingest(alert):
    """SOC 1.1: push the alert to the local real-time SOC ingest server.

    Fast fail (200ms timeout). Server is on 127.0.0.1:8765 by default
    (realtime-soc-server.service). Returns nothing on success; logs +
    silently swallows failures so the email pipeline is not blocked.

    Behavior:
      - Disabled by default? No — enabled by default. The whole point of
        SOC 1.1 is to get the alert into the agent in real time.
      - Set REALTIME_SOC_DISABLED=1 to bypass (e.g. for the selftest
        harness that doesn't want a side effect).
      - Set REALTIME_SOC_URL to override host:port.
    """
    if os.environ.get("REALTIME_SOC_DISABLED", "0") == "1":
        return None
    url = os.environ.get("REALTIME_SOC_URL", "http://127.0.0.1:8765/ingest")
    try:
        data = json.dumps(alert).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        ingest_started = time.monotonic()
        with urllib.request.urlopen(req, timeout=0.2) as resp:
            elapsed_ms = round((time.monotonic() - ingest_started) * 1000.0, 1)
            body = resp.read().decode("utf-8", errors="replace")
            if resp.status != 200:
                _REALTIME_LOG.warning("realtime soc non-200: %s — %s",
                                      resp.status, body[:200])
                return None
            try:
                j = json.loads(body)
            except Exception:
                return None
            _REALTIME_LOG.info(
                "realtime soc ingest: ok=%s elapsed=%sms new_alert=%s new_incident=%s",
                j.get("ok"),
                j.get("elapsed_ms"),
                j.get("new_alert_ids"),
                j.get("new_incident_ids"),
            )
            # SOC 1.1 measurement: log total client-side latency including
            # connection setup + serialization. Used in the done-when test.
            sys.stderr.write(
                f"[soc-1.1] realtime_ingest client_total_ms={elapsed_ms} "
                f"server_elapsed_ms={j.get('elapsed_ms')} "
                f"new_incident_ids={j.get('new_incident_ids')}\n"
            )
            return j
    except urllib.error.URLError as e:
        # Most common: server not running. Fail soft — the email path is
        # still the primary delivery mechanism.
        _REALTIME_LOG.info("realtime soc unavailable (%s); continuing to email", e)
        return None
    except Exception as e:
        _REALTIME_LOG.warning("realtime soc unexpected error: %s", e)
        return None


_NOISE_LOG = logging.getLogger("agentic-soc-send.noise")
_REALTIME_LOG = logging.getLogger("agentic-soc-send.realtime")


def is_noisy(alert):
    """SOC 2.5: return True if this alert is in the operational-noise denylist."""
    if os.environ.get("WAZUH_NOISE_DENYLIST", "1") != "1":
        return False
    rule = alert.get("rule") or {}
    try:
        rid = int(rule.get("id", 0))
    except (TypeError, ValueError):
        return False
    return rid in NOISY_RULE_IDS


def load_env_file():
    ENVFILE = os.environ.get("WAZUH_REPORTS_ENV", "/etc/reports-mailbox.env")
    if not os.path.exists(ENVFILE):
        sys.stderr.write(f"missing env file: {ENVFILE}\n")
        sys.exit(1)
    for line in open(ENVFILE):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def maybe_enrich(alert):
    """SOC A1 (2026-08-06): use openclaw agent harness via llm_runtime.

    Previous version invoked `openclaw ask`, which does NOT exist in
    OpenClaw 2026.7.1 — the email narrative was silently skipped.
    Replaced with a structured `openclaw agent --agent soc-narrator`
    call routed through the shared `llm_runtime.py` helper. Falls
    back gracefully on any LLM failure (sets
    `agentic_narrative_error` so the email still goes out with the
    raw alert).
    """
    if os.environ.get("WAZUH_AGENTIC_ENABLE", "1") != "1":
        return alert
    # Allow per-tenant / per-deploy runtime override.
    runtime = os.environ.get("SOC_LLM_RUNTIME", "openclaw")
    agent_id = os.environ.get("WAZUH_NARRATOR_AGENT", "soc-narrator")
    try:
        from llm_runtime import call_llm  # type: ignore
    except ImportError:
        # llm_runtime is in scripts/soc/. When the integration script runs
        # inside the Wazuh manager container, that path is bind-mounted
        # at /home/__SOC_USER__/repos/soc-openclaw/services/ (or wherever the
        # container's compose file points). For the manager container we
        # preinstall the file at /usr/local/share/soc/llm_runtime.py.
        candidates = [
            "/usr/local/share/soc/llm_runtime.py",
            "/home/__SOC_USER__/.openclaw/soc/lib/llm_runtime.py",
        ]
        import importlib.util
        loaded = False
        for c in candidates:
            if os.path.exists(c):
                # IMPORTANT: register in sys.modules BEFORE exec_module.
                # Python 3.9's dataclasses need to look up the module
                # via sys.modules; without this, `@dataclass` raises
                # AttributeError: 'NoneType' object has no attribute
                # '__dict__' when it tries to resolve the type hints.
                spec = importlib.util.spec_from_file_location("llm_runtime", c)
                mod = importlib.util.module_from_spec(spec)
                sys.modules["llm_runtime"] = mod
                spec.loader.exec_module(mod)
                loaded = True
                break
        if not loaded:
            alert["agentic_narrative_error"] = (
                "llm_runtime.py not found; checked "
                + ", ".join(candidates)
            )
            return alert
        from llm_runtime import call_llm  # type: ignore

    prompt = (
        "Write a 2-4 sentence SOC analyst summary of the following Wazuh alert. "
        "State severity (low / medium / high / critical), what happened, the "
        "recommended next action. Plain text, no markdown headers.\n\n"
        "ALERT JSON:\n" + json.dumps(alert, indent=2)[:3000]
    )
    resp = call_llm(
        runtime=runtime,
        agent_id=agent_id,
        message=prompt,
        system="You are a SOC analyst. Be terse and actionable.",
        timeout=25.0,
        # Track B, B2 (2026-08-07): attach the alert as the audit input
        # so the audit row's input_hash + input_summary are populated
        # automatically. The hash ties this record to the full alert
        # without writing the alert (with PII) into the audit log.
        audit_input=alert,
        audit_input_kind="wazuh_alert",
        audit_input_summary=(
            f"L{(alert.get('rule') or {}).get('level', '?')} "
            f"{(alert.get('rule') or {}).get('id', '?')} "
            f"{(alert.get('agent') or {}).get('name', '?')}"
        ),
    )
    if resp.ok and resp.text:
        alert["agentic_narrative"] = resp.text
        if resp.run_id:
            alert["agentic_run_id"] = resp.run_id
        if resp.model:
            alert["agentic_model"] = resp.model
        if resp.duration_ms is not None:
            alert["agentic_duration_ms"] = resp.duration_ms
    else:
        alert["agentic_narrative_error"] = (
            resp.error or "unknown llm_runtime error"
        )
        # SOC 1.1 timing — still log the realtime ingest call regardless.
    return alert


def maybe_decide(alert):
    """SOC Track B / B1 (2026-08-07): invoke soc-triage's decision
    tool. Adds `agentic_decision` to the alert dict with the full
    Decision shape (severity_class, is_known_pattern,
    recommended_response, confidence, reasoning, low_confidence,
    run_id).

    This is the breakthrough: the system now PICKS a response
    based on alert content, not a hardcoded 3-branch if/elif. The
    Decision is consumed by:
      - the email body (formatted in build_email)
      - the realtime SOC JSONL record (via realtime_ingest)
      - the audit log (via B2's automatic llm_runtime hook)

    Failure mode: if soc_decision can't run (LLM down, parse
    error, etc.) the decision falls back to
    recommended_response=digest_only with low_confidence=True.
    The email still goes out; the operator reviews the digest.

    Disabled with WAZUH_DECISION_ENABLE=0 (default 1).
    """
    if os.environ.get("WAZUH_DECISION_ENABLE", "1") != "1":
        return alert
    try:
        # soc_decision.py is in scripts/soc/. Same import dance as
        # llm_runtime.py: try preinstalled /usr/local/share/soc/,
        # then the repo path. Register in sys.modules before exec.
        import importlib.util as _ilu
        candidates = [
            "/usr/local/share/soc/soc_decision.py",
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "..", "soc", "soc_decision.py"),
        ]
        decision_mod = None
        for c in candidates:
            c = os.path.abspath(c)
            if os.path.exists(c):
                spec = _ilu.spec_from_file_location("soc_decision", c)
                decision_mod = _ilu.module_from_spec(spec)
                sys.modules["soc_decision"] = decision_mod
                spec.loader.exec_module(decision_mod)
                break
        if decision_mod is None:
            alert["agentic_decision_error"] = (
                "soc_decision.py not found; checked " + ", ".join(candidates)
            )
            return alert
        tenant_id = os.environ.get("WAZUH_TENANT_ID")
        d = decision_mod.decide(alert, tenant_id=tenant_id)
        alert["agentic_decision"] = d.to_dict()
        return alert
    except Exception as e:
        alert["agentic_decision_error"] = f"maybe_decide failed: {e!r}"
        return alert


def build_email(alert, recipient):
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    level = rule.get("level", 0)
    descr = rule.get("description", "alert")
    agent_name = agent.get("name", "?")
    rule_id = rule.get("id", "?")
    subject = f"[Wazuh L{level}] {agent_name} rule {rule_id}: {descr}"[:200]
    lines = []
    lines.append(f"Wazuh alert — level {level}")
    lines.append("")
    lines.append(f"Rule:     {rule_id} — {descr}")
    lines.append(f"Agent:    {agent_name} ({agent.get('ip', '?')})")
    lines.append(f"Time:     {alert.get('timestamp', '?')}")
    if alert.get("agentic_narrative"):
        lines.append("")
        lines.append("--- Analyst summary ---")
        lines.append(alert["agentic_narrative"])
    if alert.get("agentic_narrative_error"):
        lines.append("")
        lines.append(f"--- (analyst unavailable: {alert['agentic_narrative_error']}) ---")
    # SOC Track B / B1: the agent's decision (severity,
    # recommended response, confidence, reasoning)
    decision = alert.get("agentic_decision") or {}
    if decision:
        lines.append("")
        lines.append("--- Agent decision (Track B) ---")
        sev = decision.get("severity_class", "?")
        resp = decision.get("recommended_response", "?")
        conf = decision.get("confidence", 0.0)
        kp = "yes" if decision.get("is_known_pattern") else "no"
        lines.append(f"Severity class : {sev}")
        lines.append(f"Known pattern  : {kp}")
        lines.append(f"Recommended    : {resp}  (confidence {conf:.2f})")
        if decision.get("low_confidence"):
            lines.append("                ↳ low confidence — will be reviewed")
        if decision.get("reasoning"):
            lines.append("")
            lines.append(f"Reasoning: {decision['reasoning']}")
    if alert.get("agentic_decision_error"):
        lines.append("")
        lines.append(f"--- (decision unavailable: {alert['agentic_decision_error']}) ---")
    lines.append("")
    lines.append("--- Raw alert (truncated) ---")
    lines.append(json.dumps(alert, indent=2)[:3500])
    body = "\n".join(lines)
    return subject, body


def main():
    load_env_file()

    raw = sys.stdin.read()
    try:
        alert = json.loads(raw) if raw.strip() else {"_note": "empty alert"}
    except Exception as e:
        alert = {"_raw": raw[:1000], "_parse_error": str(e)}

    if isinstance(alert, list):
        # If a multi-alert payload comes through, treat as a single digest
        alert = {"_multi": alert, "rule": {"level": 10, "description": f"{len(alert)} alerts batch"},
                 "agent": {"name": "batch", "ip": "?"}, "timestamp": "?"}

    # SOC 2.5: drop operational noise before any costly work
    if is_noisy(alert):
        if os.environ.get("WAZUH_NOISE_LOG_DROPPED", "1") == "1":
            rule_id = (alert.get("rule") or {}).get("id", "?")
            agent_name = (alert.get("agent") or {}).get("name", "?")
            _NOISE_LOG.info("dropped noisy rule %s from agent %s", rule_id, agent_name)
        # NOTE: noisy alerts skip realtime_ingest too — they are operational
        # noise and the daily digest already covers them.
        return 0

    # SOC A1 (2026-08-06): enrich with the LLM narrative FIRST so the
    # realtime SOC JSONL record carries the narrative. The latency cost
    # is ~10-12s per alert (acceptable for L12+); for high-volume
    # operational-noise rules we already skip via the denylist above.
    alert = maybe_enrich(alert)

    # SOC Track B / B1 (2026-08-07): invoke the decision tool AFTER
    # the narrative so the JSONL record carries both. The decision
    # cost is ~5-10s; total per-alert latency stays around 15-22s
    # for L12+ alerts (which is the path that matters; noisy L<10
    # rules skip both via the denylist).
    alert = maybe_decide(alert)

    # SOC 1.1: real-time ingest into SecurityOperationsAgent AFTER the
    # enrichment so the JSONL record carries the agentic_narrative
    # fields. Fast-fail (200ms); an unavailable server does NOT block
    # email delivery.
    realtime_ingest(alert)
    recipient = os.environ.get("WAZUH_REPORTS_RECIPIENT", "wes@example.com")
    subject, body = build_email(alert, recipient)

    ctx = ssl.create_default_context()
    # The Wazuh manager container sets SSL_CERTIFICATE_AUTHORITIES
    # to its internal CA (for agent↔manager TLS). For OUTBOUND
    # SMTP to mail.example.com (Let's Encrypt), we need the
    # system CA bundle, not the Wazuh internal CA. Pick the first
    # one that exists; fall back to the default context.
    # NOTE: 'os' is imported at the top of the file; do NOT add a
    # function-local `import os` here or Python will treat every
    # `os.environ` reference as a local variable (UnboundLocalError).
    for cafile in ("/etc/ssl/certs/ca-certificates.crt",
                   "/etc/pki/tls/certs/ca-bundle.crt"):
        if os.path.exists(cafile):
            ctx = ssl.create_default_context(cafile=cafile)
            break
    smtp_host = os.environ["SMTP_HOST"]
    smtp_port = int(os.environ["SMTP_PORT"])
    smtp_user = os.environ["REPORTS_MAILBOX"]
    smtp_pass = os.environ["REPORTS_MAILBOX_PW"]

    msg = MIMEText(body)
    msg["From"] = smtp_user
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="example.com")
    msg["X-Wazuh-Agent"] = (alert.get("agent") or {}).get("name", "?")
    msg["X-Wazuh-Level"] = str((alert.get("rule") or {}).get("level", 0))

    with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as s:
        s.starttls(context=ctx)
        s.login(smtp_user, smtp_pass)
        s.send_message(msg)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        sys.stderr.write(f"FAIL: {e!r}\n")
        sys.exit(1)
