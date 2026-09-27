#!/usr/bin/env python3
"""Count real (non-selftest) laya shadow decisions. Used by the laya-300 cron trigger."""
import json

n = 0
for l in open("/opt/soc-openclaw/data/laya-shadow.jsonl"):
    try:
        r = json.loads(l)
    except Exception:
        continue
    ctx = r.get("context") or {}
    aid = str(ctx.get("alert_id", ""))
    if aid and not aid.startswith("SELFTEST"):
        n += 1
print(n)