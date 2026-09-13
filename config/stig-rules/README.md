# DISA STIG classifier catalogues

This directory holds the per-STIG rule-mapping YAMLs that the
SOC classifier (E1b) walks at alert-time, plus the canonical
DISA CCI → NIST 800-53 mapping JSON that the E1a follow-up
introduced.

## Files

| File | Purpose |
|---|---|
| `catalogue-rhel-9-v2r9.yaml` | Maps Wazuh rule IDs to DISA STIG Vuln IDs for the RHEL 9 V2R9 STIG. |
| `catalogue-ubuntu-22-04-v2r9.yaml` | Same, for Ubuntu 22.04 V2R8. (Filename says v2r9; carry-forward to rename.) |
| `cci-to-nist-800-53.json` | Canonical DISA CCI → NIST 800-53 mapping (3550 CCIs × 3 NIST revs). Built from DISA's published CCI registry. Used by `scripts/soc/soc_stig.py::parse_xccdf()` to enrich imported DISA XCCDF entries with `nist_800_53`. |

## Refreshing the CCI mapping

The current 2016-vintage source covers 90.7% of the CCIs in our
imported DISA catalogues (574/633). To lift coverage:

```bash
# 1. Download a fresh DISA CCI list
#    (DISA publishes U_CCI_List.zip at
#     https://public.cyber.mil/stigs/cci/; the working
#     community mirror is the JJediny gist).
curl -sS -o /tmp/disa-cci.csv \
  "https://gist.githubusercontent.com/JJediny/b73c26c353ce3d4f0d3fb48972b43d62/raw/DISA-STIG-CCI2NIST-800-53.csv"

# 2. Rebuild the mapping JSON (see scripts/soc/soc_cci_lookup.py
#    for the loader format; the build step is one Python pipeline
#    that reads the CSV and writes cci-to-nist-800-53.json with
#    the {_meta, cci_to_nist} shape).

# 3. Re-run the backfill (idempotent; only fills gaps).
python3 scripts/soc/soc_e1a_backfill.py
```

See `docs/soc/soc-loop-e1a-cci-to-nist-shape.md` for the full
frozen contract + refresh recipe.

## Per-STIG YAMLs

Each catalogue YAML is a flat list of `entries:` with the shape:

```yaml
- wazuh_rules: [40112, 5763, 53503]    # Wazuh rule IDs
  stig_id: RHEL-08-010010               # DISA Vuln id (V-NNNNNN form)
  control_id: AU-2                      # NIST 800-53 control id
  nist_family: AU                       # 2-letter family code
  title: Audit SUID binary execution    # short label
  severity: medium                      # low | medium | high
  evidence_required: [audit_log_lines]  # E3 collector hints
  remediate_hint: The auditd rule...    # LLM narrative text
```

See `scripts/soc/soc_stig_classifier.py` for the loader and
`scripts/soc/soc_e1b_selftest.py` for the done-when test.
