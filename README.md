# soc-openclaw

An **agentic Security Operations Center (SOC)** built on two open pieces:

- **Wazuh** — the SIEM: fleet agents on every managed system, a manager
  that raises alerts, an indexer (OpenSearch) for history, FIM, a
  vulnerability detector and a system-inventory collector on every host.
- **OpenClaw** — the agent gateway: a fleet of specialist LLM sub-agents
  (triage, narration, replies, curation, enrichment, comms) that turn raw
  Wazuh alerts into decisions, tickets, and reports — with humans
  reviewing anything the agents route as "needs human" — plus a managing
  agent that operates the SOC day to day (fleet scans, service repair,
  dashboards, documentation).

Everything here is deployable as **eight systemd services** plus **three
maintenance timers** (daily decisions report 06:00 UTC, nightly
compliance refresh 06:30 UTC, hourly healthcheck with OnFailure
alerting), an OpenClaw
sub-agent fleet, and one Wazuh integration script. Stdlib-only Python;
no vendor lock-in; secrets stay outside the repo.

```
                    ┌───────────────────────────────┐
 managed systems ──▶│ Wazuh stack (docker)          │
 (Wazuh agents)     │  manager :55000  indexer      │
                    │  integration: agentic-soc-send│
                    └───────┬───────────────────────┘
                            │ POST /ingest (8765)
                            ▼
                    ┌────────────────────┐     ┌──────────────────┐
                    │ realtime ingest    │────▶│ JSONL data log   │
                    │ (triage via OpenCl │     └──────────────────┘
                    │  soc-triage agent) │
                    └────────────────────┘
   ┌──────────────────────── MCP backends ────────────────────────┐
   │ :8766 wazuh-mcp (C1 → alerts/CVEs/inventory)                 │
   │ :8767 manager-mcp (C2 → Wazuh API)  :8768 tickets-mcp (C3)   │
   │ :8769 audit-mcp (C4)                memory-mcp               │
   └───────────────┬──────────────────────────────────────────────┘
                   ▼
           soc-dashboard :8771
           Fleet · CVEs · Packages · Logs · Tasks · STIG · Scores · Tenants
                   ▲
           OpenClaw sub-agents: soc-triage · soc-narrator · soc-replier
           soc-incident-reviewer · soc-ioc-enricher · soc-comms
           (+ the managing main agent: fleet scans, repairs, docs)
```

## What it does

**Detection & response pipeline** — every Wazuh alert is triaged by an
LLM sub-agent (severity, recommended response, confidence), ingested
into a JSONL data log, classified (STIG/CMMC mapping), and — when a
human is needed — turned into a ticket or email. Every LLM call is
audited. Mutations (agent restarts, fleet actions) are gated behind an
explicit allow flag.

**Fleet & CVE review** — per-host views for every agent: status and
keepalives, recent alerts (Logs), vulnerability findings with CVSS
severity (CVEs), installed packages with versions compared across hosts
(Packages & CVEs), and host-vs-host package diffs. Backed by the
Vulnerability Detector + syscollector inventory indices.

**Compliance scanning & scoring** — OpenSCAP scans (DISA STIG on
Ubuntu, CIS L1/L2 on Debian) provisioned per target, launched per-host
or fleet-wide, with evidence extracted to CMMC controls and scored
continuously; alert-derived STIG findings feed the same evidence store.

**Stocked dashboards** — 11 Wazuh/OpenSearch dashboards (fleet health,
alert volume, critical alerts, MITRE tactics, FIM, vulnerabilities,
geography, …) rebuilt from live index mappings and re-importable after
any stack rebuild with one command.

**Operations task pane** — every scan/run is recorded to a task log and
surfaced vCenter-style on every dashboard page, with per-task drill-down.

## How OpenClaw manages it

Two layers of agents run the SOC:

1. **The alert pipeline (per event).** Each Wazuh alert triggers the
   `soc-triage` sub-agent, which classifies severity and recommends a
   response; `soc-narrator` writes analyst summaries, `soc-replier`
   drafts email replies on the allowlisted SOC mailbox,
   `soc-incident-reviewer` curates memory, `soc-ioc-enricher` enriches
   indicators, `soc-comms` handles outbound comms. Humans see whatever
   is escalated; everything else is on the record in the audit log.

2. **The managing agent (continuous ops).** The main OpenClaw agent
   operates the infrastructure itself: provisioning compliance scanners
   on new fleet hosts, running OpenSCAP scans (detached on targets for
   long scans) and collecting evidence fleet-wide, recomputing scores,
   fixing broken services and frozen agent syncs, keeping the Wazuh
   dashboards stocked after rebuilds, and updating these docs. Work can
   be delegated to background runs or scheduled automations (e.g. a
   timed collection pass for a 45-minute scan), and everything the
   agent changes lands in git with these docs.

Fail-safe posture: LLM actions are audit-logged end to end, mutations
default **off**, triage failures degrade to "route to digest for human
review" (never silently dropped), and secrets live only in chmod-600
env files outside the repo.

## Quickstart

```bash
git clone https://github.com/dmrobbi/soc-openclaw /opt/soc-openclaw
cd /opt/soc-openclaw

# 1. Wazuh stack (manager + indexer + dashboard in docker)
cd wazuh && docker compose up -d && cd ..

# 2. Secrets (never committed — see docs/security-notes.md)
sudo mkdir -p /home/wez/.openclaw/soc/secrets
sudo cp deploy/secrets/*.env.example ...   # see deploy-guide.md

# 3. Install the stack + sub-agent fleet (idempotent)
cp deploy/soc-stack.env.example deploy/soc-stack.env && ${EDITOR:-vi} deploy/soc-stack.env
bash scripts/smoke-all.sh          # optional gate: all 7 module smokes
sudo bash deploy/install.sh

# 4. Stock the Wazuh dashboards (11 dashboards, 56 visualizations)
cd deploy/wazuh-dashboards && python3 build-wazuh-dashboards.py --import && cd ../..

# 5. Verify
bash deploy/healthcheck.sh               # ~27 checks, exit 0 = green
systemctl list-timers 'soc-*'            # daily-decisions 06:00, compliance-daily 06:30, healthcheck hourly, scan-weekly Sun 03:00
open http://<host>:8771   # SOC Dashboard
```

Full walkthrough: **[docs/deploy-guide.md](docs/deploy-guide.md)**.
Enrolling managed systems: **[docs/fleet-onboarding.md](docs/fleet-onboarding.md)**
(read it — a minimal agent config without the syscollector block
silently disables inventory; onboarding explains the required block).

## Components

| Path | What it is |
|---|---|
| `services/` | The systemd-hosted services: SOC dashboard (8771) + MCP servers (wazuh-mcp 8766, manager-mcp 8767, tickets-mcp 8768, audit-mcp 8769) + realtime ingest (8765) + imap watcher + daily report + nightly compliance refresh (`soc_compliance_daily.py`) + STIG remediation (`soc_stig_remediate.py`) |
| `services/scanner/` | OpenSCAP scanner (CLI + fleet resolver) and the fleet evidence collector (`collect_fleet_day.py`) |
| `services/soc_evidence.py`, `services/soc_score.py` | Evidence store (SSG 800-53 → CMMC controls) and compliance scoring |
| `agents/` | The OpenClaw sub-agent fleet: identities + bootstrap |
| `deploy/` | Idempotent installer, healthcheck, unit templates, OpenSCAP target provisioner, stocked Wazuh dashboards (`deploy/wazuh-dashboards/`) |
| `wazuh/` | Wazuh stack compose + the alert-ingest integration |
| `lib/` | Shared stdlib libs: LLM runtime (openclaw/ollama), audit log, ticket helper |
| `docs/` | Architecture, deployment, fleet onboarding, CVE/packages, OpenSCAP scanning, Wazuh dashboards, security notes |

## The sub-agents

| Agent | Role |
|---|---|
| `soc-triage` | Per-alert decision: severity, recommended response, confidence |
| `soc-narrator` | 2–4 sentence analyst summaries for alert emails |
| `soc-replier` | Drafts replies to inbound allowlisted SOC email |
| `soc-incident-reviewer` | Curated-memory pass over the audit log |
| `soc-ioc-enricher` | IOC lookups and enrichment |
| `soc-comms` | Outbound communications |

Registration is idempotent — `deploy/install.sh` runs `agents/bootstrap-fleet.sh`,
which copies each workspace from `agents/<id>/` and registers it. Re-run after
editing personas to propagate updates.

## Docs

- [Deployment guide](docs/deploy-guide.md) — bare host → running SOC
- [Fleet onboarding](docs/fleet-onboarding.md) — enrolling systems (incl. the required syscollector block)
- [OpenSCAP scanning](docs/openscap-scanning.md) — compliance scans, evidence, scoring, **remediation** (`soc_scanner.py --collect`, `soc_stig_remediate.py` + dashboard button)
- [CVE review & packages](docs/cve-packages.md) — per-host CVE findings, package comparison, host diffs
- [Stocked Wazuh dashboards](docs/wazuh-dashboards.md) — 11 dashboards + one-command reload
- [Security notes](docs/security-notes.md) — secrets, rotation procedures, exposure posture

## License

MIT — see [LICENSE](LICENSE).
