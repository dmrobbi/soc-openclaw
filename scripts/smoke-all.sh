#!/usr/bin/env bash
# smoke-all.sh — run every module --smoke in isolation.
#
# Usage: scripts/smoke-all.sh
#
# Every smoke runs with:
#   SOC_ROUTING_CONFIG  -> config/soc-routing.yaml.example (never live)
#   SOC_EVIDENCE_DIR / SOC_SNAPSHOT_DIR / SOC_REMEDIATION_LOG /
#   SOC_AUDIT_LOG / SOC_REALTIME_LOG -> a throwaway temp dir
#
# Smokes that seed their own fixtures (soc_score, soc_evidence)
# override these env vars internally; the exports above are the
# safety net that keeps any other code path off live state.
#
# Nonzero exit on any smoke failure. Run this before every
# deploy (rsync to /opt) and in CI — it is the only guard
# against smoke rot today.

set -u
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd -P)"

TMP="$(mktemp -d /tmp/soc-smoke-all.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

export SOC_ROUTING_CONFIG="$REPO_ROOT/config/soc-routing.yaml.example"
export SOC_EVIDENCE_DIR="$TMP/evidence"
export SOC_SNAPSHOT_DIR="$TMP/snapshots"
export SOC_REMEDIATION_LOG="$TMP/remediations.jsonl"
export SOC_AUDIT_LOG="$TMP/audit.jsonl"
export SOC_REALTIME_LOG="$TMP/realtime.jsonl"
mkdir -p "$SOC_EVIDENCE_DIR" "$SOC_SNAPSHOT_DIR"

MODULES=(
  "services/soc_routing.py"
  "services/soc_stig.py"
  "services/soc_score.py"
  "services/soc_evidence.py"
  "services/soc_stig_classifier.py"
  "services/daily-decisions/soc_daily_decisions.py"
)

fail=0
for mod in "${MODULES[@]}"; do
  name="$(basename "$mod" .py)"
  printf '=== %s\n' "$mod"
  log="$TMP/$name.log"
  if python3 "$mod" --smoke >"$log" 2>&1; then
    tail -n 1 "$log"
  else
    fail=1
    status=$?
    echo "FAILED (exit $status):" >&2
    tail -n 15 "$log" >&2
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "smoke-all: FAILED (full logs kept in $TMP)" >&2
  exit 1
fi
echo "smoke-all: all ${#MODULES[@]} smokes OK"