# soc-openclaw

An **agentic Security Operations Center (SOC)** built on two open pieces:

- **Wazuh** — the SIEM: fleet agents on every managed system, a manager
  that raises alerts, an indexer for history.
- **OpenClaw** — the agent gateway: a fleet of specialist LLM sub-agents
  (triage, narration, replies, curation, enrichment, comms) that turn raw
  Wazuh alerts into decisions, tickets, and reports — with humans
  reviewing anything the agents route as "needs human".

Everything here is deployable as **eight systemd services**, an OpenClaw
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
   │ :8767 manager-mcp (C2 → Wazuh API)  :8768 tickets-mcp        │
   │ :8769 audit-mcp                      memory-mcp              │
   └───────────────┬──────────────────────────────────────────────┘
                   ▼
           soc-dashboard :8771  (Fleet / Tickets / STIG / Tenants / Scores)
                   ▲
           OpenClaw sub-agents: soc-triage · soc-narrator · soc-replier
           soc-incident-reviewer · soc-ioc-enricher · soc-comms
```

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
sudo bash deploy/install.sh

# 4. Verify
bash deploy/healthcheck.sh
open http://<host>:8771   # SOC Dashboard
```

Full walkthrough: **[docs/deploy-guide.md](docs/deploy-guide.md)**.
Enrolling managed systems: **[docs/fleet-onboarding.md](docs/fleet-onboarding.md)**.

## Components

| Path | What it is |
|---|---|
| `services/` | The systemd-hosted services (dashboard + 4 MCP servers + realtime ingest + imap watcher + daily report) |
| `agents/` | The OpenClaw sub-agent fleet: identities + bootstrap |
| `deploy/` | Idempotent installer, healthcheck, unit templates |
| `wazuh/` | Wazuh stack compose + the alert-ingest integration |
| `lib/` | Shared stdlib libs: LLM runtime (openclaw/ollama), audit log, ticket helper |
| `docs/` | Architecture, deployment, onboarding, security notes |

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

## License

MIT — see [LICENSE](LICENSE).