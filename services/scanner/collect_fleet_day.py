#!/usr/bin/env python3
"""collect_fleet_day.py — merge multiple hosts' OpenSCAP results into ONE
evidence write per control/day.

Why: the evidence store keys files as <tenant>/<control>/<day>.jsonl and
_write_evidence replaces the whole file (first line carries _status). A
per-host write therefore makes each host's collection overwrite the
previous host's evidence for the same day ("last-scan-wins"). This script
parses every host's results.xml, reduces rules to the worst result across
hosts, and performs a single write_evidence() — a coherent fleet-wide
snapshot for the day.

Usage:
  env SOC_EVIDENCE_DIR=... python3 collect_fleet_day.py \
      --tenant bedimsecurity --day 2026-09-13 \
      --manifest /path/manifest.json [--score]

manifest.json: [{"host": str, "results": path, "ds": path}, ...]

Merge rule (per rule id, across hosts):
  any "fail"            -> fail
  all "pass"/"fixed"    -> pass
  otherwise             -> rule dropped (neutral; contributes nothing)

Output: JSON {per_host, merged_counts, evidence_counts, score}
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from soc_scanner import parse_ds_rule_nist, parse_rule_results, write_evidence  # noqa: E402

_PASS = {"pass", "fixed"}


def _worst(occurrences):
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

    per_host = {}
    occurrences: Dict[str, List[Tuple[str, str]]] = defaultdict(list)  # rule -> [(host, result)]
    refs: Dict[str, list] = {}

    for spec in manifest:
        host, xml_path, ds_path = spec["host"], spec["results"], spec["ds"]
        rows = parse_rule_results(xml_path)
        per_host[host] = {
            "rules": len(rows),
            "pass": sum(1 for r in rows if r["result"] in _PASS),
            "fail": sum(1 for r in rows if r["result"] == "fail"),
        }
        for r in rows:
            occurrences[r["rule"]].append((host, r["result"]))
        for rule, rl in parse_ds_rule_nist(ds_path).items():
            refs.setdefault(rule, [])
            for ref in rl:
                if ref not in refs[rule]:
                    refs[rule].append(ref)

    merged_rows = []
    for rule, occ in occurrences.items():
        w = _worst(occ)
        if w is None:
            continue
        hosts = sorted({h for h, _ in occ})
        merged_rows.append({"rule": rule, "result": w,
                            "hosts": hosts, "source": "oscap"})

    counts = write_evidence(args.tenant, merged_rows, refs, args.day,
                            "fleet:" + ",".join(sorted(per_host)))

    out = {"per_host": per_host, "merged_rules": len(merged_rows),
           "evidence_counts": counts}

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