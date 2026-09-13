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
# later: scp the results back and parse
```

## 5. Fleet scans → ONE merged evidence write

The evidence store is keyed `<tenant>/<control>/<day>.jsonl` and each
write **replaces** the day file — per-host writes would thrash scores
(last-write-wins). Use the fleet collector: it parses every host's
results, takes the worst result per rule across hosts, and does a single
write.

```bash
# manifest: [{"host":"thing1","results":".../results-thing1.xml","ds":"...xml"}, ...]
cd services && env SOC_ROUTING_CONFIG=$HOME/.openclaw/soc/soc-routing.yaml \
  SOC_EVIDENCE_DIR=$HOME/.openclaw/soc/compliance/evidence \
  python3 scanner/collect_fleet_day.py \
  --tenant bedimsecurity --day 2026-09-13 \
  --manifest $HOME/.openclaw/soc/scans/2026-09-13/manifest.json --score
```

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
  the remaining half — `soc_stig_remediate.py` port is pending.
