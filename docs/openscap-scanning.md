# OpenSCAP compliance scanning

Per-host XCCDF compliance scans (DISA STIG / CIS), evidence extraction to
CMMC controls, and fleet-wide scoring. The scanner lives in
`services/scanner/soc_scanner.py` (CLI: `--host/--host-ip/--family/
--os-version/--profile/--fleet/--dry-run`).

## 1. Provision a target

One-time per host — installs the `oscap` binary (the datastream is pushed
from the SOC host at scan time):

```bash
ssh wez@<target> 'sudo -n bash -s' < deploy/openscap-setup.sh
```

## 2. Datastream / profile matrix

| OS | Datastream (installed on the SOC host) | Profile |
|---|---|---|
| Ubuntu 24.04 | `ssg-ubuntu2404-ds.xml` (built from ComplianceAsCode 0.1.82) | DISA STIG (`xccdf_org.ssgproject.content_profile_stig`) |
| Debian 12 | `ssg-debian12-ds.xml` (SSG 0.1.82 — has CIS L1/L2; Debian ships no DISA STIG) | `cis_level2_server` (strongest Debian baseline) |

Installed at `/usr/share/xml/scap/ssg/content/`. Check profiles before
assuming: `oscap info <ds>`. CPE mismatch (wrong OS family/version) makes
every rule notapplicable — always confirm the datastream matches the host.

## 3. Quick single-host scan

```bash
cd services && python3 scanner/soc_scanner.py --host vader \
  --tenant bedimsecurity --day $(date -u +%F)
```

Writes results + HTML report under `~/.openclaw/soc/scans/<day>/`,
extracts evidence (SSG 800-53 refs → CMMC controls via
`services/soc_evidence.py`), recomputes the tenant score
(`services/soc_score.py`).

## 4. Long scans: detach on the target (IMPORTANT)

Full-profile scans run 15–45 min (a Debian 12 CIS L2 scan took ~90 min on
a Raspberry Pi). An `oscap-ssh` run coupled to an agent session dies if
the session is killed. For anything non-trivial, launch **detached on the
target** and collect later:

```bash
scp /usr/share/xml/scap/ssg/content/<ds>.xml wez@<target>:/tmp/
ssh wez@<target> 'sudo -n nohup oscap xccdf eval \
  --profile <profile-id> --results /tmp/scan-results.xml \
  --report /tmp/scan-report.html /tmp/<ds>.xml > /tmp/scan.log 2>&1 &'
# later: scp the results back into ~/.openclaw/soc/scans/<day>/ as
# results-<host>.xml, then run the automated collect (§5):
#   python3 scanner/soc_scanner.py --collect <day> --score
```

## 5. Collect + merge results (ONE evidence write per control/day)

The evidence store is keyed `<tenant>/<control>/<day>.jsonl` and each
write **replaces** the day file — per-host writes would thrash scores
(last-write-wins). The scanner merges automatically. A weekly cadence is shipped as
`soc-scan-weekly.timer` (Sunday 03:00 UTC, `SOC_SCAN_PARALLEL=2`,
per-run tasklog rows in `/tasks`); evidence merges in-run and the next
nightly refresh rescores:

- `--fleet` scans all reachable hosts and then performs a **single
  merged write** (worst result per rule across hosts).
- `--collect <day>` re-collects from archived results — the post-scan
  half of the detached flow in §4. It discovers
  `~/.openclaw/soc/scans/<day>/results-*.xml` (or the recorded
  `manifest.json`), infers each host's datastream from the results'
  Benchmark id, merges, writes evidence once, records the tenant into
  the manifest, and optionally rescores:

```bash
cd services && env SOC_ROUTING_CONFIG=$HOME/.openclaw/soc/soc-routing.yaml \
  SOC_EVIDENCE_DIR=$HOME/.openclaw/soc/compliance/evidence \
  python3 scanner/soc_scanner.py --collect 2026-09-13 \
  --tenant bedimsecurity --score
```

`--dry-run` prints what would be merged without writing. Tenant
attribution is recorded in the day's `manifest.json` by `--collect`,
and the nightly `soc-compliance-daily.timer` (06:30 UTC) re-collects
any scans archived that day and recomputes all tenant scores
automatically.

`scanner/collect_fleet_day.py --tenant T --day D --manifest M [--score]`
remains for compatibility; it now delegates to the same
`soc_scanner.merge_results` implementation.

Merge rule per rule-id across hosts: any fail → fail; all pass/fixed →
pass; otherwise the rule is dropped (neutral). The output JSON includes
per-host tallies, evidence counts, and the recomputed score.

## 6. Dashboard integration

- Host page (`/fleet/<id>`): **Re-run compliance scan** button (mutation-
  gated — needs `SOC_MANAGER_MCP_ALLOW_MUTATIONS=1` on C2; restarts the
  agent then re-collects evidence and recomputes scores).
- `/tasks` + `/tasks/<id>`: every scan run is recorded
  (`services/soc_tasklog.py` → `~/.openclaw/soc/tasks.jsonl`), with links
  to the HTML report when available.
- Scores/evidence: `/scores`, `/tenants/<id>`, `compliance_report` tool.

## 7. Evidence → score semantics

- Evidence rows live in `~/.openclaw/soc/compliance/evidence/<tenant>/
  <control>/<day>.jsonl`; the first line carries the control status.
- Alerts classified as STIG findings (classifier → audit log) grade
  `stig_evidence` controls as fail; OpenSCAP passes grade controls as
  pass. Controls with neither stay `manual_review` (no score credit).
- Remediation (turning findings into fixes and pass-grade evidence) is
  ported (Track E2, `services/soc_stig_remediate.py`, 2026-09-14):
  `check_control` / `remediate_control` / `rollback_control` /
  `list_remediations` / `get_remediation`. CLI:
  `python3 services/soc_stig_remediate.py --tool remediate_control
  --args '{"control_id":"...","tenant_id":"...","confidence":0.95}'`
  (add `"dry_run":true` to preview; `SOC_REMEDIATION_DRY_RUN=1` forces
  it globally). The dashboard exposes `remediate_control` (mutation-
  gated via C2 `/healthz` like the scan triggers; tasklog kind
  `stig_remediate`). Applied fixes write snapshot + audit row +
  remediation log entry — the rows soc_evidence grades into PASS
  evidence, so the next collect/score credits the pass. Commands run
  as the invoking user; root-needing local fixes fail honestly (rc≠0) —
  run the CLI under sudo for those.
- **Fleet remediation (Phase 1.4, 2026-09-14)**: add `"host":"<fleet
  name/id>"` (or `"host_ip"` for out-of-band targets) to the tool args
  and the fix runs ON the target via `ssh <user>@<ip> 'sudo -n bash
  -s'` — the same SSH contract as the scanner (NOPASSWD sudo for the
  SSH user, from `deploy/openscap-setup.sh`). No local root needed:
  the local CLI runs as your user (ssh keys under `~/.ssh`), the fix
  executes as remote root. Host resolution goes through C2/C1
  (`fleet_agents`); unknown hosts fail fast. Snapshots/audit rows carry
  the host. Example:
  `python3 services/soc_stig_remediate.py --tool remediate_control
  --args '{"control_id":"IA.L1-3.5.002","tenant_id":"...",
  "confidence":0.95,"host":"evgen-b"}'` — verified live on evgen-b
  (minlen = 14 + libpam-pwquality installed). The nightly
  auto-remediation pass stays LOCAL-only by design; fleet remediation
  is operator-triggered for now.
