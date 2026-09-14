#!/usr/bin/env bash
# soc-openclaw healthcheck — exit 0 = all green.
#
# Run hourly by soc-healthcheck.timer; on failure systemd fires
# soc-healthcheck-alert@soc-healthcheck.service (OpenClaw chat + SMTP
# fallback). Also safe to run by hand: deploy/healthcheck.sh
#
# NOTE: run as wez — the sub-agent check shells out to the openclaw CLI
# (not on root's PATH) and the secret files are wez-owned.
DASH="${SOC_DASHBOARD_URL:-http://127.0.0.1:8771}"
PASS=0
FAIL=0
ok()  { echo "  ok   $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL $1"; FAIL=$((FAIL+1)); }

echo "--- systemd units ---"
for u in soc-dashboard soc-audit-mcp soc-wazuh-mcp soc-tickets-mcp soc-memory-mcp soc-manager-mcp realtime-soc-server imap-watcher; do
  st=$(systemctl is-active "$u" 2>/dev/null || echo unknown)
  [ "$st" = "active" ] && ok "unit $u" || bad "unit $u ($st)"
done
echo "--- systemd timers ---"
for t in soc-daily-decisions.timer soc-compliance-daily.timer soc-audit-shipper.timer soc-realtime-shipper.timer soc-healthcheck.timer; do
  st=$(systemctl is-active "$t" 2>/dev/null || echo unknown)
  [ "$st" = "active" ] && ok "timer $t" || bad "timer $t ($st)"
done

echo "--- HTTP backends ---"
for p in 8765 8766 8767 8768 8769; do
  curl -sf -m 5 "http://127.0.0.1:$p/healthz" >/dev/null 2>&1 && ok "port $p healthz" || bad "port $p healthz"
done
curl -sf -m 5 "$DASH/healthz" >/dev/null 2>&1 && ok "dashboard $DASH/healthz" || bad "dashboard $DASH/healthz"

echo "--- fleet (via C2 manager) ---"
FLEET=$(curl -sf -m 10 -X POST -H "Content-Type: application/json" -d '{}' "$DASH/tools/fleet_status" 2>/dev/null)
if [ -n "$FLEET" ]; then
  eval "$(echo "$FLEET" | python3 -c 'import json,sys; d=json.load(sys.stdin); s=d.get("summary",{}); print("T=%s A=%s" % (s.get("total",0), s.get("active",0)))' 2>/dev/null || echo "T=0 A=0")"
  T=${T:-0}; A=${A:-0}
  [ "$T" -gt 0 ] 2>/dev/null && ok "fleet: $A/$T agents active" || bad "fleet: total=0 (manager unreachable?)"
else
  bad "fleet_status call failed"
fi

echo "--- sub-agents ---"
OC_BIN="${OPENCLAW_BIN:-openclaw}"
N=$("$OC_BIN" agents list 2>/dev/null | grep -cE "^- soc-")
[ "$N" -ge 6 ] && ok "sub-agents registered: $N" || bad "sub-agents registered: $N (want >=6)"

echo "--- secrets perms (assert, never rewrite) ---"
# 2026-09-12 incident: reports-mailbox.env was 600 wez:wez, the wazuh
# container (uid 999) could not read it, and EVERY level>=12 alert was
# silently dropped for a day. Numeric ids only — group names collide on
# this host (gid 1001 displays as "dnsmasq").
WEZ_UID="$(id -u)"
MB="${SOC_MAILBOX_ENV:-$HOME/.openclaw/workspace/secrets/reports-bedimsecurity-mailbox.env}"
if [ -e "$MB" ]; then
  perms=$(stat -c '%u:%g:%a' "$MB")
  [ "$perms" = "999:${WEZ_UID}:640" ] \
    && ok "mailbox env perms ($perms)" \
    || bad "mailbox env perms $perms (want 999:${WEZ_UID}:640) — L12+ alerts drop when wrong"
else
  bad "mailbox env missing: $MB"
fi
# legacy deployed copy — assert only if present (workspace file is canonical)
if [ -e /etc/reports-mailbox.env ]; then
  perms=$(stat -c '%u:%g:%a' /etc/reports-mailbox.env)
  [ "$perms" = "999:${WEZ_UID}:640" ] \
    && ok "/etc/reports-mailbox.env perms" \
    || bad "/etc/reports-mailbox.env perms $perms (want 999:${WEZ_UID}:640)"
fi
for f in "${SOC_SECRETS_DIR:-$HOME/.openclaw/soc/secrets}"/*.env; do
  if [ ! -e "$f" ]; then
    bad "no secret files in ${SOC_SECRETS_DIR:-$HOME/.openclaw/soc/secrets}"
    break
  fi
  perms=$(stat -c '%u:%g:%a' "$f")
  case "$perms" in
    "${WEZ_UID}:${WEZ_UID}:600") ok "secret $(basename "$f") ($perms)" ;;
    *) bad "secret $(basename "$f") perms $perms (want ${WEZ_UID}:${WEZ_UID}:600)" ;;
  esac
done

echo "---"
echo "healthcheck: $PASS ok, $FAIL failed"
[ "$FAIL" -eq 0 ]