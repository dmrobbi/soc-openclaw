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
# Bearer token for the dashboard tool API (2026-10-16 auth gate on
# POST /tools/* — soc-dashboard.service loads the same file).
# Empty token -> the unauthed call is refused and fleet goes red.
DASH_TOKEN="$(sed -n 's/^SOC_DASHBOARD_TOKEN=//p' "${SOC_DASHBOARD_TOKEN_FILE:-/opt/soc-dashboard/soc-dashboard.env}" 2>/dev/null | head -n1)"
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
DASH_AUTH=()
[ -n "$DASH_TOKEN" ] && DASH_AUTH=(-H "Authorization: Bearer $DASH_TOKEN")
FLEET=$(curl -sf -m 10 -X POST -H "Content-Type: application/json" \
  "${DASH_AUTH[@]}" -d '{}' "$DASH/tools/fleet_status" 2>/dev/null)
if [ -n "$FLEET" ]; then
  eval "$(echo "$FLEET" | python3 -c 'import json,sys; d=json.load(sys.stdin); s=d.get("summary",{}); print("T=%s A=%s" % (s.get("total",0), s.get("active",0)))' 2>/dev/null || echo "T=0 A=0")"
  T=${T:-0}; A=${A:-0}
  [ "$T" -gt 0 ] 2>/dev/null && ok "fleet: $A/$T agents active" || bad "fleet: total=0 (manager unreachable?)"
else
  bad "fleet_status call failed"
fi

echo "--- sub-agents ---"
OC_BIN="${OPENCLAW_BIN:-openclaw}"
# The agents-list RPC can transiently return nothing while the gateway is
# busy (memory-dreaming + soc-compliance-daily both fire at 03:00:00); a
# suppressed stderr turned that into false "sub-agents: 0" pages
# (2026-09-28..10-03: red at 03:00 only, green every other sampled hour).
# Retry before declaring a registry drop.
N=0
for hc_try in 1 2 3; do
  [ "$hc_try" -gt 1 ] && sleep 5
  N=$("$OC_BIN" agents list 2>/dev/null | grep -cE "^- soc-") || true
  [ "$N" -ge 6 ] && break
done
if [ "$N" -ge 6 ]; then
  ok "sub-agents registered: $N"
# Registry-file cross-check: the agents-list RPC can stay empty through the
# WHOLE 03:00 busy window (2026-10-04/06/07: 3 retries could not cross it;
# green every other hour), so fall back to the registry FILE — the explicit
# agents.entries is the registration truth and is immune to gateway load.
if [ "$N" -lt 6 ]; then
  CFG_N=$(python3 -c "
import json, os
try:
    cfg = json.load(open(os.path.expanduser('~/.openclaw/openclaw.json')))
    entries = (cfg.get('agents') or {}).get('entries') or []
    print(sum(1 for e in entries if str(e.get('id') or e.get('agentId') or e.get('name') or '').startswith('soc-')))
except Exception:
    print(0)
" 2>/dev/null) || CFG_N=0
  if [ "$CFG_N" -ge 6 ]; then
    ok "sub-agents registered: $CFG_N (via config file; CLI RPC flapped under load)"
    N=$CFG_N
    AGENTS=$N
  fi
fi

else
  "$OC_BIN" agents list 2>&1 | tail -3 >&2
  bad "sub-agents registered: $N (want >=6) — CLI output above; red here but green at other hours = RPC flap, not a restore signal"
fi

echo "--- kali-agent op-presence ---"
# OPT-74 (KA-074): the kali agent's planner surface must stay importable on
# this host. Planner-only probe: imports the two kali classes and counts
# public op methods; nothing executes, no network.
KALI_REPO="${SOC_KALI_REPO:-$HOME/agentic-ai}"
KALI_N=$(cd "$KALI_REPO" 2>/dev/null && python3 -c "
import importlib
ka = importlib.import_module('agentic_ai.agents.cyber.kali').KaliAgent
kv = importlib.import_module('agentic_ai.agents.cyber.kali_v2').KaliAgentV2
n = len([x for x in dir(ka) if not x.startswith('_')])
n2 = len([x for x in dir(kv) if not x.startswith('_')])
assert n >= 100 and n2 >= 100, 'kali surface collapsed: %d+%d' % (n, n2)
print(n + n2)" 2>/dev/null || echo 0)
KALI_N=${KALI_N:-0}
[ "$KALI_N" -gt 0 ] 2>/dev/null \
  && ok "kali-agent ops: $KALI_N" \
  || bad "kali-agent ops: $KALI_N (want >0) — kali import or composition failed; repo at $KALI_REPO"

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

echo "--- soc pipeline state perms (container uid 999) ---"
# 2026-09-14: root-owned files under the container state dir (from
# manual `docker exec` WITHOUT `-u wazuh`) broke every LLM decision
# turn for 3 weeks (EACCES + fallback to a token without
# operator.write). Assert, never rewrite.
SD=/home/wez/.openclaw-wazuh
N=$(sudo -n find "$SD" -user 0 -not -type l 2>/dev/null | wc -l)
[ "$N" -eq 0 ] && ok "pipeline state: no root-owned files" || bad "pipeline state: $N root-owned files — wazuh-context agent turns fail (run docker exec -u wazuh!)"
O=$(sudo -n stat -c '%u' "$SD/identity" 2>/dev/null)
[ "$O" = "999" ] && ok "identity dir owned by container user (999)" || bad "identity dir owner uid $O (want 999) — device credential unreadable by the pipeline"

echo "--- laya gated decision path (SOC 2.6) ---"
# 2026-09-28 incident: laya_shadow.py mode 660 raised PermissionError on
# the import (an OSError, not ImportError) inside the uid-999 integration
# children; every organic alert silently took the LLM path (90 s
# timeouts) while all root-run drills passed. Probe the module load
# exactly as the integration user, and assert the gate engages when
# organic decisions are flowing.
docker exec -u 999 wazuh-stack-wazuh.manager-1 /var/ossec/framework/python/bin/python3 -c "
import importlib.util as ilu, sys
spec = ilu.spec_from_file_location('soc_decision', '/usr/local/share/soc/soc_decision.py')
m = ilu.module_from_spec(spec); sys.modules['soc_decision'] = m; spec.loader.exec_module(m)
spec2 = ilu.spec_from_file_location('laya_shadow', '/usr/local/share/soc/laya_shadow.py')
m2 = ilu.module_from_spec(spec2); spec2.loader.exec_module(m2)
sh = m2.LayaShadow(mode='gated')
assert sh.enabled
" >/dev/null 2>&1 \
  && ok "laya modules load as integration user (uid 999)" \
  || bad "laya modules FAIL as integration user (uid 999) — check laya_shadow.py perms/import path"
LAYA_MODE_NOW=$(docker exec wazuh-stack-wazuh.manager-1 printenv LAYA_MODE 2>/dev/null || echo off)
AUDIT_LOG="${SOC_AUDIT_LOG:-$HOME/.openclaw-wazuh/audit_log.jsonl}"
LAYA_RECENT=$(tail -1000 "$AUDIT_LOG" 2>/dev/null | grep -c laya_gated_decision || true)
DEC_RECENT=$(tail -1000 "$AUDIT_LOG" 2>/dev/null | grep -c decision_prompt || true)
if [ "$LAYA_MODE_NOW" = "gated" ]; then
  if [ "$LAYA_RECENT" -ge 1 ]; then
    ok "laya gate engaging ($LAYA_RECENT laya rows in last 1000 audit lines)"
  elif [ "$DEC_RECENT" -ge 5 ]; then
    bad "laya gate NOT engaging: $DEC_RECENT LLM decisions, 0 laya rows — check laya_shadow.py perms as uid 999"
  else
    ok "laya idle (no recent organic decisions)"
  fi
else
  ok "laya mode: $LAYA_MODE_NOW (gate-engagement check skipped)"
fi

echo "---"
echo "healthcheck: $PASS ok, $FAIL failed"
[ "$FAIL" -eq 0 ]