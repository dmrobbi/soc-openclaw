#!/usr/bin/env bash
# ============================================================================
# soc-openclaw deploy — installs the Agentic-SOC systemd stack and the
# OpenClaw sub-agent fleet.  Idempotent; safe to re-run.
#
# Prereqs: python3, systemd, an OpenClaw gateway, the Wazuh manager
# reachable on https://127.0.0.1:55000 (see wazuh/).
#
# Secrets (KEY=*** env files, chmod 600 — never committed):
#   $SOC_SECRETS_DIR/wazuh-manager-api.env    WAZUH_API_USERNAME / WAZUH_API_PASSWORD
#   $SOC_SECRETS_DIR/reports-mailbox.env      SMTP/IMAP hosts + mailbox creds
#
# Usage:
#   cp deploy/soc-stack.env.example deploy/soc-stack.env && $EDITOR deploy/soc-stack.env
#   sudo bash deploy/install.sh                  # real install
#   sudo SOC_DRY_RUN=1 bash deploy/install.sh    # preview
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- config -----------------------------------------------------------------
if [ -f "$SCRIPT_DIR/soc-stack.env" ]; then
  # shellcheck disable=SC1091
  . "$SCRIPT_DIR/soc-stack.env"
fi

SOC_HOME="${SOC_HOME:-$(cd "$SCRIPT_DIR/.." && pwd)}"
SOC_USER="${SOC_USER:-wez}"
SOC_STATE_DIR="${SOC_STATE_DIR:-/home/$SOC_USER/.openclaw/soc}"
SOC_AGENTS_DIR="${SOC_AGENTS_DIR:-/home/$SOC_USER/soc-agents}"
SOC_LOGS_DIR="${SOC_LOGS_DIR:-/home/$SOC_USER/logs}"
SOC_SECRETS_DIR="${SOC_SECRETS_DIR:-/home/$SOC_USER/.openclaw/soc/secrets}"
SOC_MANAGER_BIND="${SOC_MANAGER_BIND:-loopback}"
GLUE_STATE="${GLUE_STATE:-/home/$SOC_USER/.openclaw/agents}"
DRY_RUN="${SOC_DRY_RUN:-0}"
OPENCLAW_BIN="${OPENCLAW_BIN:-}"

fail() { echo "[deploy] FAIL: $*" >&2; exit 1; }
log()  { echo "[deploy] $*"; }
run()  { if [ "$DRY_RUN" = "1" ]; then log "(dry-run) $*"; else "$@"; fi; }

[ "$(id -u)" -eq 0 ] || fail "run with sudo"
[ -d "$SCRIPT_DIR/../services" ] || fail "run from the soc-openclaw checkout"
command -v python3 >/dev/null || fail "python3 not found"

if [ -z "$OPENCLAW_BIN" ]; then
  for c in "$(command -v openclaw || true)" /home/$SOC_USER/.npm-global/bin/openclaw /usr/local/bin/openclaw; do
    [ -x "$c" ] && OPENCLAW_BIN="$c" && break
  done
  [ -n "$OPENCLAW_BIN" ] || fail "openclaw binary not found; set OPENCLAW_BIN"
fi
log "openclaw: $OPENCLAW_BIN"

TPL="$SCRIPT_DIR/templates"

# ---- secrets check ----
log "checking secrets in $SOC_SECRETS_DIR"
MISSING=0
for f in wazuh-manager-api.env reports-mailbox.env; do
  [ -s "$SOC_SECRETS_DIR/$f" ] || { log "WARN: $SOC_SECRETS_DIR/$f missing/empty"; MISSING=1; }
done
if [ "$MISSING" = "1" ]; then
  cat <<INSTR
[deploy] required secret files (chmod 600, KEY=*** lines):
  $SOC_SECRETS_DIR/wazuh-manager-api.env:
    WAZUH_API_USERNAME=wazuh-wui
    WAZUH_API_PASSWORD=*** (rotate via container rbac_control if lost)
  $SOC_SECRETS_DIR/reports-mailbox.env:
    SMTP_HOST, SMTP_PORT, IMAP_HOST, IMAP_PORT, REPORTS_MAILBOX,
    REPORTS_MAILBOX_PW, WAZUH_REPORTS_RECIPIENT, WAZUH_AGENTIC_ENABLE=1
Continuing anyway; the manager 502s until its secret exists.
INSTR
fi

# ---- directories ----
log "creating directories"
run mkdir -p \
  "$SOC_STATE_DIR/data" "$SOC_STATE_DIR/secrets" \
  "$SOC_LOGS_DIR" "$SOC_AGENTS_DIR" \
  "$GLUE_STATE/soc-manager-mcp" "$GLUE_STATE/soc-daily-decisions"

# ---- glue: manager pre-start + env ----
log "writing glue"
if [ "$DRY_RUN" != "1" ]; then
  cat > "$GLUE_STATE/soc-manager-mcp/pre-start.sh" <<PRESTART
#!/usr/bin/env bash
# Materialises /tmp/soc-manager-mcp.env from the canonical secret file.
# Installed by soc-openclaw deploy/install.sh on $(date -u +%FT%TZ).
set -euo pipefail
SECRET_DIR="$SOC_SECRETS_DIR"
OUT="/tmp/soc-manager-mcp.env"
# shellcheck disable=SC1090
[ -f "\$SECRET_DIR/wazuh-manager-api.env" ] && . "\$SECRET_DIR/wazuh-manager-api.env"
: "\${WAZUH_API_USERNAME:=wazuh-wui}"
: "\${WAZUH_MANAGER_URL:=https://127.0.0.1:55000}"
if [ -z "\${WAZUH_API_PASSWORD:-}" ]; then
  echo "pre-start: WAZUH_API_PASSWORD missing from \$SECRET_DIR/wazuh-manager-api.env" >&2
  exit 1
fi
{
  echo "WAZUH_API_USERNAME=\${WAZUH_API_USERNAME}"
  echo "WAZUH_API_PASSWORD=\${WAZUH_API_PASSWORD}"
  echo "WAZUH_MANAGER_URL=\${WAZUH_MANAGER_URL}"
} > "\$OUT"
chmod 600 "\$OUT"
PRESTART
  chmod +x "$GLUE_STATE/soc-manager-mcp/pre-start.sh"

  cat > "$GLUE_STATE/soc-manager-mcp/env" <<ENVEOF
# Static environment for soc-manager-mcp.service.
# NOTE (systemd semantics): EnvironmentFile is read at service start,
# BEFORE ExecStartPre — credentials must live in THIS file, not in a
# /tmp file written by pre-start. Kept chmod 600, user-owned.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WAZUH_MANAGER_URL=https://127.0.0.1:55000
# SOC_MANAGER_MCP_ALLOW_MUTATIONS=1   # enable restart_agent only if needed
ENVEOF
  if [ -s "$SOC_SECRETS_DIR/wazuh-manager-api.env" ]; then
    # shellcheck disable=SC1090
    . "$SOC_SECRETS_DIR/wazuh-manager-api.env"
    echo "WAZUH_API_USERNAME=${WAZUH_API_USERNAME:-wazuh-wui}" >> "$GLUE_STATE/soc-manager-mcp/env"
    echo "WAZUH_API_PASSWORD=${WAZUH_API_PASSWORD}" >> "$GLUE_STATE/soc-manager-mcp/env"
    unset WAZUH_API_PASSWORD
  fi
  chmod 600 "$GLUE_STATE/soc-manager-mcp/env"

  cat > "$GLUE_STATE/soc-daily-decisions/pre-start.sh" <<PRESTART2
#!/usr/bin/env bash
# SOC daily decisions pre-start — installed by soc-openclaw deploy/install.sh
set -euo pipefail
exec /usr/bin/python3 "$SOC_HOME/services/daily-decisions/soc_daily_decisions.py" --day "\$(date -u +%Y-%m-%d)"
PRESTART2
  chmod +x "$GLUE_STATE/soc-daily-decisions/pre-start.sh"
else
  log "(dry-run) would write glue under $GLUE_STATE"
fi

# ---- systemd units (render templates) ----
log "installing systemd units"
render() { # template dst
  sed -e "s|__SOC_USER__|$SOC_USER|g" \
      -e "s|/opt/soc-openclaw|$SOC_HOME|g" \
      -e "s|/home/__SOC_USER__\.openclaw/soc|$SOC_STATE_DIR|g" \
      -e "s|/home/__SOC_USER__/.openclaw/soc|$SOC_STATE_DIR|g" \
      "$1" > /tmp/rendered-unit
  run cp /tmp/rendered-unit "$2"
  [ "$DRY_RUN" != "1" ] && chmod 644 "$2"
  return 0
}
for u in soc-dashboard soc-audit-mcp soc-tickets-mcp soc-memory-mcp soc-manager-mcp soc-wazuh-mcp; do
  render "$TPL/$u.service" "/etc/systemd/system/$u.service"
done
render "$TPL/realtime-soc-server.service" /etc/systemd/system/realtime-soc-server.service
render "$TPL/imap-watcher.service"        /etc/systemd/system/imap-watcher.service
render "$TPL/soc-daily-decisions.service" /etc/systemd/system/soc-daily-decisions.service
render "$TPL/soc-daily-decisions.timer"   /etc/systemd/system/soc-daily-decisions.timer

# IMPROVEMENT from the 2026-09-12 outage: the manager unit must actually
# load the /tmp env its ExecStartPre materialises. Idempotent append.
if [ "$DRY_RUN" != "1" ]; then
  U=/etc/systemd/system/soc-manager-mcp.service
  grep -q "EnvironmentFile=-/tmp/soc-manager-mcp.env" "$U" || \
    sed -i '/^EnvironmentFile=/a EnvironmentFile=-/tmp/soc-manager-mcp.env' "$U"
  if [ "$SOC_MANAGER_BIND" = "lan" ]; then
    sed -i 's|services/soc-manager-mcp/server.py$|services/soc-manager-mcp/server.py --bind 0.0.0.0|' "$U"
  fi
fi

# Services run as $SOC_USER — leave nothing root-owned in their paths.
log "fixing ownership"
run chown -R "$SOC_USER:$SOC_USER" "$SOC_STATE_DIR" "$SOC_LOGS_DIR" "$SOC_AGENTS_DIR" "$GLUE_STATE"

# ---- enable ----
log "daemon-reload + enable --now"
run systemctl daemon-reload
for u in soc-dashboard soc-audit-mcp soc-tickets-mcp soc-memory-mcp soc-wazuh-mcp soc-manager-mcp realtime-soc-server imap-watcher; do
  run systemctl enable --now "$u" || log "WARN: enable --now $u failed (continuing)"
done
run systemctl enable --now soc-daily-decisions.timer

# ---- sub-agent fleet ----
log "bootstrapping the sub-agent fleet"
if [ "$DRY_RUN" = "1" ]; then
  log "(dry-run) would run agents/bootstrap-fleet.sh"
else
  OPENCLAW_BIN="$OPENCLAW_BIN" SOC_AGENTS_DIR="$SOC_AGENTS_DIR" \
    bash "$SOC_HOME/agents/bootstrap-fleet.sh" || log "WARN: fleet bootstrap errors"
fi

log "install complete — run: bash $SCRIPT_DIR/healthcheck.sh"