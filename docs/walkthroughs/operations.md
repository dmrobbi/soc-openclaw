# Operations walkthrough — running it day to day

What happens automatically, where to look, and how to drive the manual
parts. Companion: [setup.md](setup.md) for installation,
[docs/architecture.md](../architecture.md) for the full decision trees.

## 1. The daily loop (all automatic)

```bash
systemctl list-timers 'soc-*' --no-pager
```

| When (UTC) | What runs | Where to see it |
|---|---|---|
| 06:00 | daily decisions report (delivered to chat/mail + file) | `journalctl -u soc-daily-decisions`, delivered summary |
| 06:30 | evidence re-collect + auto-remediation pass + rescore | `/tasks` page, `journalctl -u soc-compliance-daily` |
| Sunday 03:00 | fleet OpenSCAP scan (all hosts) | `/tasks`, `~/.openclaw/soc/scans/<day>/` |
| every 5 min | audit + realtime shippers mirror records | shipper journals |
| hourly | healthcheck across the stack | `journalctl -u soc-healthcheck` |

The 06:00 report is delivered (OpenClaw agent turn or SMTP fallback)
and embeds a **scan diff** — what got fixed or regressed between the
two latest scan days — plus the day's decisions per tenant.

## 2. Alerts → action (the pipeline in one minute)

An alert ≥ the integration gate (level 10) leaves Wazuh and becomes an
agent turn: soc-triage classifies it, soc-narrator writes the story,
and — depending on severity and your routing config — a ticket or a
digest email goes out. Every turn is audited.

Where to look:

```bash
# the audit trail (canonical JSONL)
tail -5 ~/.openclaw-wazuh/audit_log.jsonl | python3 -m json.tool

# what the SOC agents decided today
journalctl -u soc-daily-decisions --since today | head -40
```

On the dashboard, `/tasks` shows every automated run with its history
and scan-report links:

![Task log](media/07-tasks.png)

Drill into one task to see each state transition (running → done) and
the links to its artifacts:

![Task detail](media/09-task-detail.png)

## 3. Remediation and the mutation gates

Two gates protect every mutation:

1. **Tenant policy** (`config/soc-routing.yaml` per tenant):
   `auto_remediate` allowed or refused — a refused fix never runs, it
   lands as a "refused" row for a human.
2. **The mutation switch** (`SOC_MANAGER_MCP_ALLOW_MUTATIONS` on the
   C2 manager): off = the dashboard can *dry-run* fixes but never
   apply them.

The safe rhythm: find a failing control on a host page, **Dry run** it
(read the exact command it would run), then **Remediate** when the
gate is on:

![Host drill-down](media/03-fleet-host.png)

Fleet-wide remediation is allowlisted in the nightly unit
(`SOC_AUTO_REMEDIATE_FLEET_HOSTS=...`) — only those hosts get touched,
and only the automated fix classes in the catalogue.

## 4. Scan exceptions — `config/ignore_list.yml`

Rules that must not run on a host (breaks a service, will never
apply, handled manually) are deselected from scans. The scanner builds
an XCCDF tailoring per host; excluded rules return `notselected` and
never pass or fail — they simply don't run.

```yaml
# config/ignore_list.yml
global: []
hosts:
  some-host:
    - rule: aide_build_database
      reason: "db rebuild churns nightly; reviewed manually"
```

Reload is automatic (read fresh per scan). Verify with a dry run:

```bash
python3 services/scanner/soc_scanner.py --host <agent> --dry-run
# → "[soc-scan] <agent>: ignoring 1 rule(s) via tailoring"
```

Details: [docs/openscap-scanning.md § Scan exceptions](../openscap-scanning.md).

## 5. Diffing scans

See what changed between two scan days — fixed, regressed, new
failures, still-failing, dropped:

```bash
python3 services/scanner/soc_scan_diff.py --day-a 2026-09-13 --day-b 2026-09-16
# or write it to a file: --out /tmp/diff.md
```

The daily report embeds this automatically for the two latest scan
days. Scores trend on `/scores`:

![Scores](media/06-scores.png)

## 6. Adding a host to the fleet

```bash
# 1. Wazuh agent on the target (or your automation of choice)
# 2. passwordless sudo probe (root-only checks need it)
ssh <host> 'sudo -n true' && echo SUDO-OK
# 3. openscap-scanner on the target (pushed DS handled by the SOC host)
ssh <host> 'sudo apt-get install -y openscap-scanner'   # or dnf
# 4. first scan
python3 services/scanner/soc_scanner.py --host <agent> --dry-run
python3 services/scanner/soc_scanner.py --host <agent>
```

Details: [docs/fleet-onboarding.md](../fleet-onboarding.md).

## 7. Troubleshooting, by symptom

| Symptom | First command | Likely cause |
|---|---|---|
| Dashboard empty/`healthz` down | `curl -s :8771/healthz` | a backend MCP down — see `backends` in healthz |
| Scan `notapplicable` for every rule | `python3 services/scanner/soc_scanner.py --host X --dry-run` | datastream CPE doesn't match the host OS |
| Remediate button refuses | `curl -s :8767/healthz` | mutation gate off (by design) — Dry run works |
| No daily report | `journalctl -u soc-daily-decisions -n 30` | delivery fallback (SMTP env) missing |
| Scores look stale | `journalctl -u soc-compliance-daily --since today` | nightly pass failed — rerun same-day via `--day` |

Deep-dive: [docs/security-notes.md](../security-notes.md) and the
quickstart's [safety model](../../quickstart.md).

## 8. Rotating a credential (worked example)

When any secret is exposed, rotate both ends — never just delete it
from a file. Example: the gateway auth token.

```bash
# 1. new value on the gateway side
openssl rand -hex 24   # → openclaw.json: gateway.auth.token
# 2. same value on every client (soc-stack.env / container env)
# 3. restart the gateway, recreate dependent containers
# 4. verify BOTH ways: old token rejected, new token completes a turn
```

The 2026-09-18 rotation of this exact token is the full worked
example — see the repo's security history.