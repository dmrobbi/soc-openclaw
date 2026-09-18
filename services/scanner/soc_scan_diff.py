#!/usr/bin/env python3
"""SOC scan diff — compares two scan-day results directories and
reports which XCCDF rules flipped per host.

Input shape (the scanner's own layout, `soc_scanner.py`):
    <scans-dir>/<day>/results-<host>.xml   (XCCDF 1.1/1.2 results)

Diff categories per host:
    fixed      — day A fail → day B pass (also fail→fixed/fixed after
                 remediation)
    regressed  — day A pass → day B fail, or a rule that appears as
                 fail in day B but wasn't there in day A
    still_bad  — fail in both days

Rules that are notapplicable/notchecked/notselected in either day are
ignored (they carry no grade signal).

CLI:
    python3 soc_scan_diff.py --day-a 2026-09-13 --day-b 2026-09-16 \
        [--scans-dir ~/.openclaw/soc/scans] [--host thing1] \
        [--out /tmp/diff.md]

Output: markdown report (stdout or --out). Importable:
    from soc_scan_diff import diff_days, render_markdown
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

SCAN_RESULTS_DIR = Path(os.environ.get(
    "SOC_SCAN_RESULTS_DIR", os.path.expanduser("~/.openclaw/soc/scans")))

GRADED = {"pass", "fail", "error", "unknown", "fixed"}
SKIP = {"notapplicable", "notchecked", "notselected", "informational"}


def parse_results(path: str) -> Dict[str, str]:
    """Extract {rule_id_short: result} from one results XML.

    Returns {} when the file is missing/empty/unparseable (a failed
    scan on some host must not abort the whole diff).
    """
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return {}
    try:
        root = ET.parse(str(p)).getroot()
    except ET.ParseError:
        return {}
    out: Dict[str, str] = {}
    for r in root.iter():
        if not r.tag.endswith("rule-result"):
            continue
        idref = r.get("idref", "")
        if not idref:
            continue
        rid = idref.split("content_rule_")[-1]
        res = None
        for c in r:
            if c.tag.endswith("result"):
                res = (c.text or "").strip()
        if res is None:
            continue
        res = res.lower()
        if res in GRADED:
            out[rid] = res
    return out


def hosts_in_day(day: str, base: Path) -> List[str]:
    d = base / day
    if not d.exists():
        return []
    hosts = []
    for f in sorted(d.glob("results-*.xml")):
        host = f.stem[len("results-"):]
        if host.endswith("-pre"):
            continue
        hosts.append(host)
    return hosts


def diff_host(day_a: str, day_b: str, host: str,
              base: Path) -> Optional[Dict[str, Any]]:
    a = parse_results(base / day_a / f"results-{host}.xml")
    b = parse_results(base / day_b / f"results-{host}.xml")
    if not a and not b:
        return None
    fixed, regressed, new_fail, still_bad, dropped = [], [], [], [], []
    for rid in sorted(set(a) | set(b)):
        ra, rb = a.get(rid), b.get(rid)
        if ra == rb:
            if ra == "fail":
                still_bad.append(rid)
            continue
        if ra == "fail" and rb in ("pass", "fixed"):
            fixed.append(rid)
        elif ra in ("pass", "fixed") and rb == "fail":
            regressed.append(rid)
        elif ra is None and rb == "fail":
            new_fail.append(rid)   # rule newly graded, failing
        elif ra == "fail" and rb is None:
            dropped.append(rid)    # rule left the scan's graded set
    if not (fixed or regressed or new_fail or still_bad or dropped):
        return None
    return {"host": host, "fixed": fixed, "regressed": regressed,
            "new_fail": new_fail, "still_bad": still_bad,
            "dropped": dropped}


def diff_days(day_a: str, day_b: str,
              base: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Diff every host present in either day. Returns a list of
    per-host dicts that actually have changes (hosts with identical
    graded state are omitted)."""
    base = Path(base) if base else SCAN_RESULTS_DIR
    hosts = sorted(set(hosts_in_day(day_a, base))
                   | set(hosts_in_day(day_b, base)))
    out: List[Dict[str, Any]] = []
    for h in hosts:
        d = diff_host(day_a, day_b, h, base)
        if d and (d["fixed"] or d["regressed"] or d["new_fail"]
                  or d["still_bad"] or d["dropped"]):
            out.append(d)
    return out


def render_markdown(day_a: str, day_b: str,
                    diffs: List[Dict[str, Any]]) -> str:
    """Markdown section for the daily report / standalone delivery."""
    if not diffs:
        return (f"### Scan diff {day_a} → {day_b}\n\n"
                "No graded rule changes between the two scan days.\n")
    lines = [f"### Scan diff {day_a} → {day_b}", ""]
    tf = sum(len(d["fixed"]) for d in diffs)
    tr = sum(len(d["regressed"]) for d in diffs)
    tn = sum(len(d["new_fail"]) for d in diffs)
    ts = sum(len(d["still_bad"]) for d in diffs)
    td = sum(len(d["dropped"]) for d in diffs)
    lines.append(f"**{len(diffs)} host(s) with changes** — "
                 f"{tf} fixed, {tr} regressed, {tn} new-fail, "
                 f"{ts} still failing, {td} dropped from grading.\n")
    for d in diffs:
        lines.append(f"#### {d['host']}")
        if d["fixed"]:
            lines.append(f"- **fixed ({len(d['fixed'])}):** "
                         + ", ".join(f"`{r}`" for r in d["fixed"]))
        if d["regressed"]:
            lines.append(f"- **regressed ({len(d['regressed'])})**: "
                         + ", ".join(f"`{r}`" for r in d["regressed"]))
        if d["new_fail"]:
            lines.append(f"- new-fail ({len(d['new_fail'])}): "
                         + ", ".join(f"`{r}`" for r in d["new_fail"]))
        if d["still_bad"]:
            lines.append(f"- still failing ({len(d['still_bad'])}): "
                         + ", ".join(f"`{r}`" for r in d["still_bad"]))
        if d["dropped"]:
            lines.append(f"- dropped ({len(d['dropped'])}): "
                         + ", ".join(f"`{r}`" for r in d["dropped"]))
        lines.append("")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="SOC scan diff")
    p.add_argument("--day-a", required=True)
    p.add_argument("--day-b", required=True)
    p.add_argument("--scans-dir", default=None)
    p.add_argument("--out", default=None, help="write markdown here")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    base = Path(args.scans_dir) if args.scans_dir else SCAN_RESULTS_DIR
    diffs = diff_days(args.day_a, args.day_b, base)
    if args.json:
        print(json.dumps(diffs, indent=1))
    md = render_markdown(args.day_a, args.day_b, diffs)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        print(f"[soc-scan-diff] wrote {out}")
    else:
        sys.stdout.write(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())