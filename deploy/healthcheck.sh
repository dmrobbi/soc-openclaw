#!/usr/bin/env bash
# soc-openclaw healthcheck — exit 0 = all green.
DASH="${SOC_DASHBOARD_URL:-http://127.0.0.1:8771}"
PASS=0
FAIL=0
ok()  { echo "  ok   $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL $1"; FAIL=$((FAIL+1)); }

echo "--- systemd units ---"
for u in soc-dashboard soc-audit-mcp soc-tickets-mcp soc-memory-mcp soc-manager-mcp realtime-soc-server imap-watcher; do
  st=$(systemctl is-active "$u" 2>/dev/null || echo unknown)
  [ "$st" = "active" ] && ok "unit $u" || bad "unit $u ($st)"
done
systemctl is-enabled soc-daily-decisions.timer >/dev/null 2>&1 \
  && ok "timer soc-daily-decisions.timer" || bad "timer soc-daily-decisions.timer"

echo "--- HTTP backends ---"
for p in 8765 8767 8768 8769; do
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

echo "---"
echo "healthcheck: $PASS ok, $FAIL failed"
[ "$FAIL" -eq 0 ]