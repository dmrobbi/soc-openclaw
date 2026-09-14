#!/usr/bin/env bash
# notify-healthcheck-failure.sh — SOC healthcheck failure alert.
#
# Invoked by systemd OnFailure as soc-healthcheck-alert@<unit>.service
# (%i = the failed unit, e.g. soc-healthcheck.service).
#
# Delivery order:
#   1. OpenClaw agent turn (lands in the operator's main chat).
#   2. Fallback: SMTP via the SOC reports mailbox creds (self-addressed).
#      Used when the gateway itself is the thing that's down.
# Always journald-logs the alert (logger) so it is never fully silent,
# and keeps a cooldown so a persistently broken stack does not spam
# the chat every hour.
#
# Security: secret file is read by python directly; nothing is echoed.
set -u

UNIT="${1:-soc-healthcheck.service}"
COOLDOWN_MIN="${SOC_HEALTHCHECK_ALERT_COOLDOWN_MIN:-240}"
STATE="${TMPDIR:-/tmp}/soc-healthcheck-alert.last"
STAMP="$(date -u '+%Y-%m-%d %H:%M UTC')"

# --- cooldown ---------------------------------------------------------------
if [ -f "$STATE" ]; then
  last="$(cat "$STATE" 2>/dev/null || echo 0)"
  now="$(date +%s)"
  age=$(( now - last ))
  if [ "$age" -lt $(( COOLDOWN_MIN * 60 )) ]; then
    logger -t soc-healthcheck-alert \
      "cooldown active ($((age / 60))m since last alert) — skipping notify for $UNIT"
    exit 0
  fi
fi
date +%s > "$STATE"

TAIL="$(journalctl -u "$UNIT" -n 20 --no-pager -o cat 2>/dev/null | tail -20)"
MSG="SOC HEALTHCHECK FAILED on $(hostname) at $STAMP ($UNIT)
---
$TAIL
---
Investigate: journalctl -u $UNIT -n 50"

logger -t soc-healthcheck-alert "failure detected in $UNIT — sending alert"

# --- 1) OpenClaw chat -------------------------------------------------------
OC_BIN="${OPENCLAW_BIN:-openclaw}"
if command -v "$OC_BIN" >/dev/null 2>&1; then
  if "$OC_BIN" agent --agent main --deliver -m "$MSG" >/dev/null 2>&1; then
    logger -t soc-healthcheck-alert "alert delivered via OpenClaw agent turn"
    exit 0
  fi
  logger -t soc-healthcheck-alert "OpenClaw delivery failed — trying SMTP fallback"
else
  logger -t soc-healthcheck-alert "openclaw CLI not found — trying SMTP fallback"
fi

# --- 2) SMTP fallback (self-addressed via the reports mailbox) --------------
ENV_FILE="${SOC_MAILBOX_ENV:-/home/wez/.openclaw/workspace/secrets/reports-bedimsecurity-mailbox.env}"
if [ -r "$ENV_FILE" ]; then
  python3 - "$ENV_FILE" "$MSG" <<'PYEOF'
import sys
import smtplib

env_file, msg = sys.argv[1], sys.argv[2]
cfg = {}
for line in open(env_file, encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, _, v = line.partition("=")
        cfg[k.strip()] = v.strip()
host = cfg.get("SMTP_HOST")
port = int(cfg.get("SMTP_PORT", "587"))
mailbox = cfg.get("REPORTS_MAILBOX")
pw = cfg.get("REPORTS_MAILBOX_PW")
if not (host and mailbox and pw):
    sys.exit(3)
s = smtplib.SMTP(host, port, timeout=20)
try:
    s.starttls()
    s.login(mailbox, pw)
    s.sendmail(mailbox, [mailbox],
               "Subject: [SOC] healthcheck FAILED\r\n\r\n" + msg)
finally:
    s.quit()
PYEOF
  rc=$?
  if [ "$rc" -eq 0 ]; then
    logger -t soc-healthcheck-alert "alert delivered via SMTP fallback"
    exit 0
  fi
  logger -t soc-healthcheck-alert "SMTP fallback failed (rc=$rc) — alert only in journal"
  exit 0
fi

logger -t soc-healthcheck-alert "no openclaw + no readable mailbox env — alert only in journal"
exit 0