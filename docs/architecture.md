# Architecture

## Components

### Wazuh stack (docker)
Manager (:55000 API, :1514/:1515 agent ingestion), indexer (9200),
dashboard. Agents run on every managed system. The manager carries a
custom integration (`wazuh/integrations/agentic-soc-send.py`,
bind-mounted to `/var/ossec/integrations/`) that fires on configured
rule levels: it narrates the alert via `soc-narrator`, decides via
`soc-triage`, e-mails the digest via the reports mailbox, and POSTs the
alert to the realtime ingest server.

### Realtime ingest (:8765)
Receives alerts (`POST /ingest`), triages (full `SecurityOperationsAgent`
if the operator supplies the `agentic_ai` project, otherwise the lite
backend triaging through the OpenClaw `soc-triage` sub-agent), escalates
high/critical alerts into incidents, and appends everything to a JSONL
log (`$SOC_STATE_DIR/data/realtime_soc.jsonl`) — the durable record the
daily decisions report reads.

### MCP backends
| Server | Port | Data |
|---|---|---|
| soc-manager-mcp | 8767 | Wazuh manager REST API (fleet, rules, gated mutations) |
| soc-tickets-mcp | 8768 | SQLite ticket store (create/comment/close workflow) |
| soc-audit-mcp | 8769 | The SOC audit log (every LLM call + agent run) |
| soc-memory-mcp | 8766+ | Cross-incident memory, tenant-scoped |

### Dashboard (:8771)
Read-only Python HTTP server that proxies `/tools/<name>` calls to the
MCP backends and renders the SPA (Overview, Fleet, Scores, STIG,
Tenants, Agents, Tickets, Health).

### Daily decisions (timer, 06:00 UTC)
Reads the audit log + the realtime JSONL for "today" and writes a
Markdown decisions report to memory — the D1 artifact.

## Sub-agent fleet

Six OpenClaw agents, one concern each, all invoked through
`lib/llm_runtime.py` (openclaw harness first, Ollama fallback, audit row
on every call). Workspaces live under `$SOC_AGENTS_DIR/<id>/` with
IDENTITY/MEMORY/AGENTS/USER files copied from `agents/<id>/` — the repo
is the source of truth for personas.

## Data flow for one alert

1. Wazuh agent on a managed system detects a match → alert hits the
   manager.
2. `agentic-soc-send.py` runs: denylist → `soc-triage` decision →
   email (if recipient/routing says so) → `POST :8765/ingest`.
3. Realtime ingest triages/logs; auto-escalation writes an incident.
4. The dashboard shows fleet health, the ticket queue, scores, and the
   realtime feed; tickets are worked to closure with full audit trails.
5. The 06:00 UTC daily decisions report summarizes the day per tenant.