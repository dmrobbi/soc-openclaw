# AGENTS.md

You are part of the SOC agent fleet. Your workspace is
this directory. You have access to:

- `IDENTITY.md` — who you are
- `MEMORY.md` — your long-term memory (curated by the curator
  agent, B5)
- `sessions/` — your session history (one JSONL per session)

## What you MUST do

- Read IDENTITY.md at the start of every session.
- Check MEMORY.md before making a recommendation.
- Write decisions to the SOC audit log via the harness
  (B2 — automatic; you don't need to call it explicitly).
- Use the tools exposed to you by the harness; do not call
  external services directly except via the MCP servers
  provided.

## What you MUST NOT do

- Do not write to MEMORY.md yourself. The curator agent (B5)
  is the only writer.
- Do not call other agents' tools directly. Your parent
  agent (the one that invoked you) handles delegation.
- Do not run iptables / firewall / system changes. The
  safety decider (B3) is the only path to host changes,
  and only for known-safe patterns at the right confidence
  threshold.

---

## Tasks: how they are outlined and used (presentation, 2026-08-08)

This section is the **SOC IDENTITY.md** presentation. It shows how
each task in the SOC agent fleet is outlined and how they are
used in the live pipeline.

### The 6 personas (who does what)

| # | Agent ID | Task | Persona file |
|---|---|---|---|
| 1 | `soc-narrator` | Meta-agent that routes alerts to specialists | `soc-narrator/IDENTITY.md` |
| 2 | `soc-triage` | Per-alert triage: severity, response, confidence | `soc-triage/IDENTITY.md` |
| 3 | `soc-ioc-enricher` | Enrich IPs / hashes / domains with reputation | `soc-ioc-enricher/IDENTITY.md` |
| 4 | `soc-comms` | Draft page / Slack / customer messages | `soc-comms/IDENTITY.md` |
| 5 | `soc-replier` | Reply to inbound messages from on-call or customers | `soc-replier/IDENTITY.md` |
| 6 | `soc-incident-reviewer` | Curator: propose MEMORY.md updates from closed incidents | `soc-incident-reviewer/IDENTITY.md` |

Each persona is a directory under `scripts/soc/agent-identities/`
containing `IDENTITY.md` (who you are — voice, rules, hard NOs)
and `MEMORY.md` (long-term curated context).

### How tasks are **set**

1. **Per-agent persona** (`IDENTITY.md` + `MEMORY.md`).
   - `IDENTITY.md` declares the agent's role, what it does,
     what it MUST NOT do, what tools it uses, and the handoff
     format.
   - `MEMORY.md` is curated by `soc-incident-reviewer` (B5) and
     seeded at bootstrap with the patterns the agent needs to
     recognize.

2. **Workspace bootstrap.** On the SOC host, the personas are
   staged into the per-agent workspace via the
   `wazuh_soc_agentic_ai` Ansible role:
   ```
   ~/.openclaw/agents/soc-triage/IDENTITY.md
   ~/.openclaw/agents/soc-triage/MEMORY.md
   ```
   On the manager container they are bind-mounted into
   `/home/wez/soc-agents/<id>/`. Bootstrap script:
   `bootstrap-b4-agents.sh`.

3. **Harness wiring.** The openclaw agent harness reads the
   persona when a task arrives for `agent_id=<id>`. The harness
   prepends `IDENTITY.md` to the LLM's system prompt and the
   harness's audit log captures every Decision JSON (B2).

4. **MCP tool access.** Each agent has a specific subset of MCP
   tools available:
   - `soc-triage`: `mcp__soc_memory.memory_search`,
     `mcp__soc_memory.memory_add`
   - `soc-ioc-enricher`: `mcp__soc_wazuh.search_alerts`,
     `mcp__soc_wazuh.get_recent_alerts_for_host`
   - `soc-comms`: no MCP tools (drafts only; B3 sends)
   - `soc-incident-reviewer`: read-only MCP for incident state
   - `soc-narrator`: read-only MCP for all personas
   - `soc-replier`: read-only MCP for incident state

### How tasks are **used**

```
   alert (wazuh 40112 on darth from 10.9.8.7)
      │
      ▼
   wazuh-integratord  (manager container)
      │  via <integration>custom-agentic-soc-send</integration>
      ▼
   agentic-soc-send.py  (POST /ingest on thing1)
      │
      ▼
   realtime_soc_server  (:8765, thing1)
      │  writes to /home/wez/.openclaw/workspace/agentic-ai/data/realtime_soc.jsonl
      │  creates incident inc-XXXXXXXX-YYYY
      │
      ▼  (every 5 min, soc-realtime-shipper.timer)
   trooper2  (SOC agent gateway)
      │
      ▼
   soc-narrator  → routes alert to specialists
      │
      ├─▶ soc-triage       (mandatory; classifies)
      ├─▶ soc-ioc-enricher (if srcip/hash/domain present)
      └─▶ soc-comms        (if recommended_response=page|email)
      │
      ▼
   soc-replier  (on inbound messages; bidirectional)

   (async, post-incident)
      │
      ▼
   soc-incident-reviewer  → proposes MEMORY.md updates
```

### Per-task details (the spec)

**`soc-narrator`** — invoked once per new incident.
- **Input:** incident id, alert summary
- **Output:** routing plan: list of specialists to invoke + order
- **Rules:** always include `soc-triage` first. Add
  `soc-ioc-enricher` when srcip or hash present. Add
  `soc-comms` when recommended_response is `page|email|notify`.
- **Skip:** if recommended_response is `note_only`, only
  invoke `soc-triage`.

**`soc-triage`** — invoked per alert (and per routing plan).
- **Input:** alert JSON
- **Output:** Decision JSON
  ```json
  {
    "severity_class": "high|medium|low|informational",
    "is_known_pattern": true|false,
    "recommended_response": "page|email|notify|note_only|defer",
    "confidence": 0.0-1.0,
    "reasoning": "...",
    "low_confidence": true|false
  }
  ```
- **Rules (A3):**
  - MUST call `mcp__soc_memory.memory_search` **before**
    drafting a Decision. If prior incidents match (same
    host, srcip, or rule), **cite them in reasoning**.
  - MUST call `mcp__soc_memory.memory_add` **after**
    producing a Decision for level ≥ 10. Summary format:
    1–3 sentences including rule id, host, srcip,
    recommended response.
  - MUST NOT call `memory_add` for `severity_class=
    informational` or `recommended_response=note_only`
    (noise filter).

**`soc-ioc-enricher`** — invoked when IoCs present.
- **Input:** alert with srcip / hash / domain
- **Output:** enriched IoC list with reputation scores
- **Tools:** `mcp__soc_wazuh.search_alerts`,
  `mcp__soc_wazuh.get_recent_alerts_for_host` (C1 MCP)
- **Optional:** query external reputation feeds via the
  IOC MCP (Track D; not yet built)

**`soc-comms`** — invoked when notification is recommended.
- **Input:** Decision + alert + recipient list
- **Output:** draft message body + channel + recipient
- **Rules:** draft-only; the safety decider (B3) is the
  only path that actually sends. Never bypass.

**`soc-replier`** — invoked on inbound messages.
- **Input:** message text + sender + thread context
- **Output:** reply text + suggested actions
- **Rules:** read-only access to incident state. No
  outbound side effects except via B3.

**`soc-incident-reviewer`** — invoked async after incident
close.
- **Input:** closed incident + decisions + transcripts
- **Output:** curated memory candidates
- **Rules:** staging writes only; human reviews before
  merging into MEMORY.md. This is the only writer of
  MEMORY.md (B5).

### Where the live demo lives

- HTML replay: `~/.openclaw/workspace/agentic-ai/data/demos/soc-demo-2026-08-08.html`
- JSONL artifacts: `~/.openclaw/workspace/agentic-ai/data/demos/`
- Daily memory: `~/.openclaw/workspace/memory/2026-08-08.md`
- Memory MCP backing store: `~/.openclaw/agents/soc-triage/memory/memory.jsonl`
- Realtime incident store: `~/.openclaw/workspace/agentic-ai/data/realtime_soc.jsonl`

### Live service status (15:30 UTC 2026-08-08)

```
soc-memory-mcp.service            Active: running
soc-realtime-soc-server           Active: running
soc-realtime-shipper.timer        NEXT: every 5 min
soc-audit-shipper.timer           NEXT: every 5 min
LISTEN 127.0.0.1:8770  soc-memory-mcp   (A3, this commit)
LISTEN 127.0.0.1:8766  soc-wazuh-mcp    (C1)
LISTEN 0.0.0.0:8765    soc-realtime-soc-server
```

### Done-when for A3 (verified 15:05 UTC)

A repeat-incident scenario (same source IP, same host)
**explicitly cites the prior incident** in the agent's
response. Verified with soc-triage on darth 40112 / 10.9.8.7:
the agent's reasoning named `inc-2024-darth-brute` and bumped
confidence from 0.92 → 0.93.
- Do not send email / open tickets / page humans directly.
  The dispatcher (B3 + D3 routing) is the only path.

## Handoff

When you finish a turn, return your output to your caller.
The harness handles audit + session logging.
