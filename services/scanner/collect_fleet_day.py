#!/usr/bin/env python3
"""collect_fleet_day.py — merge multiple hosts' OpenSCAP results into ONE
evidence write per control/day.

Why: the evidence store keys files as <tenant>/<control>/<day>.jsonl and
_write_evidence replaces the whole file (first line carries _status). A
per-host write therefore makes each host's collection overwrite the
previous host's evidence for the same day ("last-scan-wins"). The merge
parses every host's results.xml, reduces rules to the worst result across
hosts, and performs a single write_evidence() — a coherent fleet-wide
snapshot for the day.

The merge logic lives in soc_scanner.merge_results (canonical since
2026-09-14 — soc_scanner.py --collect and --fleet use the same code);
this CLI remains for compatibility with the documented manual flow.

Usage:
  env SOC_EVIDENCE_DIR=... python3 collect_fleet_day.py \
      --tenant bedimsecurity --day 2026-09-13 \
      --manifest /path/manifest.json [--score]

manifest.json: [{"host": str, "results": path, "ds": path,
                 "tenant": str (optional)}, ...]

Merge rule (per rule id, across hosts):
  any "fail"            -> fail
  all "pass"/"fixed"    -> pass
  otherwise             -> rule dropped (neutral; contributes nothing)

Output: JSON {per_host, merged_rules, evidence_counts, score?}
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from soc_scanner import merge_results, parse_ds_rule_nist, parse_rule_results, write_evidence  # noqa: E402,F401

_PASS = {"pass", "fixed"}


def _worst(occurrences):
    """Worst result across (host, result) tuples — kept for backward
    compatibility; the canonical implementation is inline in
    soc_scanner.merge_results."""
    results = {o[1] for o in occurrences}
    if "fail" in results:
        return "fail"
    if results and results <= _PASS:
        return "pass"
    return None  # neutral / mixed / notchecked -> drop


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tenant", required=True)
    ap.add_argument("--day", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--score", action="store_true")
    args = ap.parse_args()

    manifest = json.loads(Path(args.manifest).read_text())
    specs = [{"host": str(row.get("host") or ""),
              "results": str(row.get("results") or ""),
              "ds": str(row.get("ds") or ""),
              "tenant": args.tenant}
             for row in manifest]

    res = merge_results(specs, args.tenant, args.day)
    out = {"per_host": res["per_host"],
           "merged_rules": res["merged_rules"],
           "evidence_counts": res["evidence_counts"]}
    if res.get("skipped"):
        out["skipped"] = res["skipped"]

    if args.score:
        try:
            from soc_score import tool_compute_score
            out["score"] = tool_compute_score({"tenant_id": args.tenant,
                                               "day": args.day})
        except Exception as exc:  # score is best-effort in the collector
            out["score_error"] = repr(exc)

    print(json.dumps(out, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())