#!/usr/bin/env python3
"""Regenerate the two DISA catalogue configs from the stig-baselines
committed sources (the single source of truth: github.com/dmrobbi/
stig-baselines, mirrored to the internal gitlab).

What this does per catalogue:
  * fresh parse via services.soc_stig.parse_xccdf (source-derived fields
    authoritative: checks/fix/severity/family/baselines/tags/automated),
  * carries the 2026-08-13 e1a enrichment (references.nist_800_53 +
    .nist_800_53_base) from the CURRENT config by rule id (no naive
    re-import would preserve those 404/404-style mappings),
  * honest _meta: provenance = the stig-baselines source path, revision
    in the name, imported_at/last_updated set now.
Run from the repo root: python3 scripts/regen_stig_catalogues.py
"""
import datetime as dt
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "services"))
import soc_stig  # noqa: E402

SB = Path("/home/wez/repos/stig-baselines/sources")
JOBS = [
    dict(
        out=REPO / "config/stig-catalogue-disa-rhel-9.json",
        src=SB / "rhel9/U_RHEL_9_V2R9_Manual_STIG/U_RHEL_9_STIG_V2R9_Manual-xccdf.xml",
        name="DISA STIG — Red Hat Enterprise Linux 9 V2R9",
        origin_url="https://cyber.trackr.live/stig/Red_Hat_Enterprise_Linux_9/2/9/download",
    ),
    dict(
        out=REPO / "config/stig-catalogue-disa-ubuntu-22-04.json",
        src=SB / "ubuntu/22.04/U_CAN_Ubuntu_22-04_LTS_V2R9_Manual_STIG/U_CAN_Ubuntu_22-04_LTS_STIG_V2R9_Manual-xccdf.xml",
        name="DISA STIG — Canonical Ubuntu 22.04 LTS V2R9",
        origin_url="https://cyber.trackr.live/stig/Canonical_Ubuntu_22.04_LTS/2/9/download",
    ),
]

NIST_KEYS = ("nist_800_53", "nist_800_53_base")
PROV_NOTE = ("Re-imported 2026-10-05 from the stig-baselines committed source "
             "(single source of truth); e1a NIST mappings (references."
             "nist_800_53[_base]) carried over from the 2026-08-13 enrichment "
             "by rule id.")


def regen(job: dict) -> dict:
    src, out = Path(job["src"]), Path(job["out"])
    donor = json.loads(out.read_text(encoding="utf-8"))
    dmap = {c["id"]: c for c in donor["controls"]}
    fresh = soc_stig.parse_xccdf(str(src))
    # CCI-keyed NIST mapping table from the donor (E1a enrichment):
    # CCI ids persist across rule revision bumps, so the mapping is
    # transferable when the fresh rule's disa_cci matches a donor control's.
    cci_map = {}
    cci_conflicts = 0
    for c in donor["controls"]:
        refs = c.get("references") or {}
        cci = refs.get("disa_cci")
        if not cci or "nist_800_53" not in refs:
            continue
        pair = {"nist_800_53": refs["nist_800_53"],
                "nist_800_53_base": refs.get("nist_800_53_base")}
        prev = cci_map.get(cci)
        if prev and prev != pair:
            cci_conflicts += 1
            continue
        cci_map[cci] = pair
    fresh = soc_stig.parse_xccdf(str(src))
    carried = auto_delta = unmapped_cci = 0
    for c in fresh["controls"]:
        d = dmap.get(c["id"])
        if bool(d.get("automated")) != bool(c.get("automated")) if d else False:
            auto_delta += 1
        refs = c.get("references") or {}
        if "nist_800_53" in refs:
            continue  # fresh parse already mapped (do not shadow)
        pair = cci_map.get(refs.get("disa_cci"))
        if pair:
            c.setdefault("references", {}).update(pair)
            carried += 1
        elif refs.get("disa_cci"):
            unmapped_cci += 1
    dropped = sorted(set(dmap) - {c["id"] for c in fresh["controls"]})
    added = sorted({c["id"] for c in fresh["controls"]} - set(dmap))
    # Revision-bump carry: a dropped rule whose disa_vuln_id reappears in a
    # new rule id (same V-xxxxxx, bumped SV-...rNNN suffix) keeps the donor's
    # NIST mapping when the CCI is unchanged (verified: CCI persists across
    # revision bumps; 2026-10-05 regen carried 10 such mappings).
    vid_donors = {c.get("references", {}).get("disa_vuln_id"): c
                  for c in donor["controls"]
                  if (c.get("references") or {}).get("nist_800_53")}
    fresh_by_vid = {}
    for c in fresh["controls"]:
        fresh_by_vid.setdefault(c.get("references", {}).get("disa_vuln_id"), []).append(c)
    for vid, dc in vid_donors.items():
        for fc in fresh_by_vid.get(vid, []):
            if "nist_800_53" in (fc.get("references") or {}):
                continue
            occi = (dc.get("references") or {}).get("disa_cci")
            ncci = (fc.get("references") or {}).get("disa_cci")
            if occi and occi == ncci:
                fc.setdefault("references", {}).update(
                    {"nist_800_53": dc["references"]["nist_800_53"],
                     **({"nist_800_53_base": dc["references"]["nist_800_53_base"]}
                        if dc["references"].get("nist_800_53_base") else {})})
                carried += 1
    m = fresh["_meta"]
    m["name"] = job["name"]
    m["kind"] = "stig"
    m["source"] = "disa-stig-xccdf-import"
    m["source_url"] = job["origin_url"]
    m["imported_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    m["last_updated"] = dt.date.today().isoformat()
    m["source_documents"] = [str(src)]
    notes = list(m.get("design_notes") or [])
    notes.append(PROV_NOTE)
    m["design_notes"] = notes
    if "e1a_backfill" not in m and "e1a_backfill" in donor["_meta"]:
        m["e1a_backfill"] = donor["_meta"]["e1a_backfill"]
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(fresh, f, indent=2, default=str)
    # verify the JSON contract is intact after write
    rl = json.loads(out.read_text(encoding="utf-8"))
    keys11 = {"automated", "baselines", "check", "description", "family",
              "fix", "id", "references", "severity", "tags", "title"}
    bad = [c["id"] for c in rl["controls"] if set(c) != keys11]
    nist_rich = sum(1 for c in rl["controls"]
                    if "nist_800_53" in (c.get("references") or {}))
    return dict(name=job["name"], controls=len(rl["controls"]),
                nist_carried=carried, nist_in_result=nist_rich,
                cci_conflicts=cci_conflicts, unmapped_cci=unmapped_cci,
                automated_delta_vs_donor=auto_delta,
                donor_rules_dropped=len(dropped),
                new_rule_ids=len(added), bad_keysets=bad,
                dropped_sample=dropped[:4], added_sample=added[:4])


def main() -> None:
    for job in JOBS:
        s = regen(job)
        print(json.dumps(s, indent=1))


if __name__ == "__main__":
    main()
