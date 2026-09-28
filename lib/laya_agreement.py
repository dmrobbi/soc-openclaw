#!/usr/bin/env python3
"""Nightly Laya-vs-SOC agreement analysis (Phase 1.4, edge host).

Joins /opt/soc-openclaw/data/laya-shadow.jsonl (Laya predictions) against
~/.openclaw/soc/data/realtime_soc.jsonl (ingest records: alert_id, level,
severity, triage LLM text) and reports per-question agreement + the
deterministic-level baseline.

Outputs: /opt/soc-openclaw/data/laya-agreement-latest.json + stdout markdown.
Cron: 55 5 * * * (edge host, operator). Log-only; changes nothing.
"""
import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

SHADOW = Path("/opt/soc-openclaw/data/laya-shadow.jsonl")
REALTIME = Path.home() / ".openclaw/soc/data/realtime_soc.jsonl"
OUT = Path("/opt/soc-openclaw/data/laya-agreement-latest.json")

LEVEL_TO_SEVERITY = [(14, "critical"), (12, "high"), (8, "medium"), (3, "low"), (0, "informational")]

def sev_from_level(level):
    for floor, sev in LEVEL_TO_SEVERITY:
        if level >= floor:
            return sev
    return "informational"

def parse_response(text):
    m = re.search(r"recommended_response['\": =]+(note_only|digest_only|email|page|auto_remediate)", text or "", re.I)
    return m.group(1).lower() if m else None

def parse_known_pattern(text):
    m = re.search(r"is_known_pattern['\": =]+(true|false)", text or "", re.I)
    return m.group(1).lower() == "true" if m else None

def main():
    shadow = {}
    if SHADOW.exists():
        for line in SHADOW.open():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("error") or (r.get("context") or {}).get("alert_id", "").startswith("SELFTEST"):
                continue
            aid = (r.get("context") or {}).get("alert_id")
            if aid:
                shadow[aid] = r
    ingest = {}
    if REALTIME.exists():
        for line in REALTIME.open():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("type") == "alert" and r.get("alert_id"):
                ingest[r["alert_id"]] = r

    pairs = [(aid, shadow[aid], ingest[aid]) for aid in shadow if aid in ingest]
    rep = {"ts": datetime.now(timezone.utc).isoformat(), "shadow_rows": len(shadow),
           "ingest_rows": len(ingest), "joined": len(pairs), "questions": {}}
    acc = defaultdict(lambda: {"agree": 0, "n": 0})
    lat, errs = [], Counter()
    for aid, s, ing in pairs:
        if s.get("latency_ms"):
            lat.append(s["latency_ms"])
        a = s.get("answers") or {}
        ing_sev = (ing.get("severity") or "").lower()
        level = s.get("context", {}).get("level")
        obj_sev = sev_from_level(int(level)) if level is not None else None
        laya_sev = (a.get("severity") or {}).get("choice")
        if laya_sev:
            for target, val in (("vs_ingest", ing_sev), ("vs_objective", obj_sev)):
                if val:
                    acc[f"severity_{target}"]["n"] += 1
                    acc[f"severity_{target}"]["agree"] += int((laya_sev or "").lower() == val)
        laya_resp = (a.get("response") or {}).get("choice")
        llm_resp = parse_response(ing.get("triage"))
        if llm_resp:
            acc["response_vs_llm"]["n"] += 1
            acc["response_vs_llm"]["agree"] += int((laya_resp or "") == llm_resp)
        laya_kp = (a.get("known_pattern") or {}).get("noul")
        llm_kp = parse_known_pattern(ing.get("triage"))
        if laya_kp is not None and llm_kp is not None:
            acc["known_pattern_vs_llm"]["n"] += 1
            acc["known_pattern_vs_llm"]["agree"] += int((laya_kp >= 0.5) == llm_kp)
        laya_esc = (a.get("escalate") or {}).get("noul")
        if laya_esc is not None and ing_sev:
            acc["escalate_vs_ingest"]["n"] += 1
            acc["escalate_vs_ingest"]["agree"] += int((laya_esc >= 0.5) == (ing_sev in ("critical", "high")))
    rep["questions"] = {q: {"agreement": round(d["agree"] / d["n"], 3), "n": d["n"]}
                        for q, d in sorted(acc.items())}
    rep["latency_ms_mean"] = round(statistics.mean(lat), 1) if lat else None
    rep["generated_at"] = rep["ts"]
    OUT.write_text(json.dumps(rep, indent=2))
    print(f"# laya agreement report {rep['ts']}")
    print(f"shadow={rep['shadow_rows']} ingest={rep['ingest_rows']} joined={rep['joined']} "
          f"lat_mean={rep['latency_ms_mean']}")
    for q, m in rep["questions"].items():
        print(f"  {q:22s} agreement {m['agreement']:.3f} (n={m['n']})")
    if rep["joined"] < 30:
        print("  (n<30: soak-phase numbers, not gate decisions)")
    return 0

if __name__ == "__main__":
    sys.exit(main())