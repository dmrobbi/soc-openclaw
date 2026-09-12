#!/usr/bin/env bash
# Bootstrap the SOC sub-agent fleet for OpenClaw.
#
# Creates each agent's workspace (IDENTITY.md / MEMORY.md / AGENTS.md /
# USER.md from this repo's agents/<id>/) and registers it with the local
# OpenClaw gateway.  Idempotent — re-running propagates persona edits.
#
# Env:
#   SOC_AGENTS_DIR   workspace root (default /home/wez/soc-agents)
#   OPENCLAW_BIN     openclaw binary (default: discovered)
#
# Usage: bash agents/bootstrap-fleet.sh
set -euo pipefail

SOC_AGENTS_DIR="${SOC_AGENTS_DIR:-/home/wez/soc-agents}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "${OPENCLAW_BIN:-}" ]; then
  if command -v openclaw >/dev/null 2>&1; then
    OPENCLAW_BIN="$(command -v openclaw)"
  elif [ -x /home/wez/.npm-global/bin/openclaw ]; then
    OPENCLAW_BIN=/home/wez/.npm-global/bin/openclaw
  elif [ -x /usr/local/bin/openclaw ]; then
    OPENCLAW_BIN=/usr/local/bin/openclaw
  else
    echo "[fleet] FAIL: openclaw not found; set OPENCLAW_BIN" >&2
    exit 1
  fi
fi

# The fleet: one dir per agent under agents/ — the single source of truth.
# Add an agent by adding a dir + a row here.
SOC_AGENTS=(
  "soc-narrator"
  "soc-triage"
  "soc-replier"
  "soc-incident-reviewer"
  "soc-ioc-enricher"
  "soc-comms"
)

created=0
for agent_id in "${SOC_AGENTS[@]}"; do
  src="$SCRIPT_DIR/$agent_id"
  if [ ! -f "$src/IDENTITY.md" ]; then
    echo "[fleet] SKIP $agent_id: missing $src/IDENTITY.md" >&2
    continue
  fi
  target_dir="$SOC_AGENTS_DIR/$agent_id"
  mkdir -p "$target_dir/sessions"
  cp "$src/IDENTITY.md" "$target_dir/IDENTITY.md"
  [ -f "$src/MEMORY.md" ] && cp "$src/MEMORY.md" "$target_dir/MEMORY.md"
  [ -f "$SCRIPT_DIR/AGENTS.md" ] && cp "$SCRIPT_DIR/AGENTS.md" "$target_dir/AGENTS.md"
  [ -f "$SCRIPT_DIR/USER.md" ] && cp "$SCRIPT_DIR/USER.md" "$target_dir/USER.md"
  echo "[fleet] $agent_id: files copied to $target_dir"

  if "$OPENCLAW_BIN" agents list 2>/dev/null | awk '/^- /{print $2}' | grep -qx "$agent_id"; then
    echo "[fleet] $agent_id: already registered"
  else
    echo "[fleet] $agent_id: registering"
    "$OPENCLAW_BIN" agents add "$agent_id" --workspace "$target_dir" --non-interactive 2>&1 \
      || echo "[fleet] WARN: agents add failed for $agent_id" >&2
  fi
  created=$((created + 1))
done

echo "[fleet] done: $created agents processed; workspaces under $SOC_AGENTS_DIR"
"$OPENCLAW_BIN" agents list 2>/dev/null | grep -E "^- " || true