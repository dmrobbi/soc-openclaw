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

## Fleet-scale nightly remediation (Phase 1.3+, 2026-09-14/15)

The nightly `soc-compliance-daily` runs two gated remediation passes
between collect and scoring:

| Env | Gate | What it does |
|---|---|---|
| `SOC_AUTO_REMEDIATE=1` | operator | applies safe shell fixes for controls that are **not pass today** on the SOC host itself (thing1) |
| `SOC_AUTO_REMEDIATE_FLEET=1` | operator | for every **(host, control)** failing in the day's archived scans, applies the fix **on that host** via `ssh <SCAN_USER>@<ip> 'sudo -n bash -s'` |
| `SOC_AUTO_REMEDIATE_FLEET_HOSTS=` | host allowlist | fail-closed: empty = no fleet hosts; comma-separated names to opt hosts in |

Per-host attribution (`soc_scanner.py --collect` → `host_control_status`)
derives the failing (host, control) pairs from the day's scan results
XMLs — the merge loses this, the attribution keeps it. The fleet pass
runs before the score step so remediation evidence is graded in-run.

### Fleet host resolution + SOC_FLEET_EXTRA override

`fleet_agents()` resolves name → ip in order: **C2 manager-mcp
`list_agents` first, C1 indexer fallback, then `SOC_FLEET_EXTRA` rows**
(`name:ip:platform:os_version`, comma-separated). Since 2026-09-17 an
env row whose name matches a registry (C2/C1) row **overrides it in
place** instead of appending a duplicate: the registry's agent id is
kept, an empty platform/os_version field inherits the registry's value
(so a bare `name:ip` row is a pure IP pin), and rows with no registry
match append unchanged (the docker-hosted evgen-d/e/f case). Prefer NOT
pinning agent-running hosts in `SOC_FLEET_EXTRA` — the registry IP is
live-correct (agent keepalives re-learn it on every reconnect) and
DHCP-aware; a stale pin can silently target the wrong VM when a NAT
network's DHCP pool is shared.

Two reachability contracts for the fleet ssh path (BatchMode,
passwordless sudo on the target):

1. **Every fleet IP must be SSH-reachable from the SOC host
   non-interactively.** Hosts on NAT-only libvirt/compose networks
   (e.g. the evgen-a/b/c VMs on trooper2's `demo_nat` 192.168.200.0/24)
   are unreachable directly — wire an `ssh` ProxyCommand pattern in the
   SOC user's `~/.ssh/config` (`Host 192.168.200.*` → `ssh -W %h:%p
   <nat-host>`); ICMP to such segments never works and is not a health
   signal.
2. **Transient link hiccups are retried once.** The fleet ssh step
   retries a single time (3s later) on rc=255 (connection error) or
   rc=124 (timeout) — genuine remote-command failures (rc 1–254) are
   never retried, and recovery is noted in the audit row stderr.

Both gates ship **enabled** in the unit template (2026-09-14/15),
because every fix is idempotent, audited (snapshot + audit row +
remediation log) and tenant-gated; set both to `0` for a collect +
rescore-only night.
