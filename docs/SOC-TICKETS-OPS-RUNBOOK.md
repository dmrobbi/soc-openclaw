# SOC Tickets — Operations Runbook (2026-10-15)

How the ticket pipeline works, what broke and how it was repaired,
how to operate/verify it, and what a human should check going forward.
Written on 2026-10-15 by the thing1 OpenClaw agent (wez-authorized
session) after wez reported: ticket click errors ("run_id not found:
TKT-…"), a ~10.9k-ticket duplicate backlog, and requested default
closed-filtering, 30-day archiving, searchable history, and
open-only overview counts.

---

## 1. Architecture (everything on thing1)

```
wazuh docker stack (compose: /home/wez/wazuh-stack/docker-compose.yml)
  wazuh-stack-wazuh.manager-1   :55000 API · :1514/1515 agents
  wazuh-stack-wazuh.indexer-1   127.0.0.1:9200
  wazuh-stack-wazuh.dashboard-1 :5601
        │  integration <name>custom-agentic-soc-send</name>, fires on
        │  EVERY rule-level ≥10 alert
        ▼
/home/wez/repos/stsgym-work/scripts/soc/agentic-soc-send.py
  (bind-mounted ro into the manager container as
   /var/ossec/integrations/agentic-soc-send.py — repo file is the
   source of truth; wazuh-integratord runs it fresh per alert)
        │  maybe_decide → maybe_classify_stig → maybe_create_ticket
        │  → realtime_ingest (+ gated email/dispatch)
        ▼
SOC MCP backends (thing1 loopback, systemd units):
  C1 soc-wazuh-mcp      :8766  indexer queries (read-only)
  C2 soc-manager-mcp    :8767  wazuh manager API (read-mostly)
  C3 soc-tickets-mcp    :8768  tickets store
                               ~/.openclaw/soc_tickets.jsonl
  C4 soc-audit-mcp      :8769  audit log
                               /home/wez/.openclaw-wazuh/audit_log.jsonl
  soc-dashboard         :8771  UI (0.0.0.0 — LAN-facing)
                               /opt/soc-openclaw/services/soc-dashboard/
```

- Containers reach host MCPs via docker-bridge forwarders
  (`soc-tickets-bridge` etc. forward 172.19.0.1:* → 127.0.0.1:*;
  container env `SOC_TICKETS_HELPER_URL=http://172.19.0.1:8768`).
- Real audit run ids are **UUIDs** (one per agent decision run);
  ticket ids are `TKT-YYYYMMDD-NNN` — they are NOT run ids.

## 2. What broke and how it was fixed (2026-10-15)

### Bug 1 — "Not found in the C4 audit log … run_id not found: TKT-…" on ticket click (wez's report)
- **Cause:** the dashboard's ticket list linked every ticket to
  `/runs/<source_run_id || ticket_id>`. Alert-created tickets have
  `source_run_id: null`, so clicking went to `/runs/TKT-…`, the UI
  called C4 `get_run` with a ticket id, and C4 (correctly) said
  `run_id not found`.
- **Fix** (`/opt/soc-openclaw/services/soc-dashboard/`):
  - `static/app.js`: ticket rows link to `/tickets/<id>`; new
    `pageTicket` detail view (fields, body, comments, audit-ref);
    router accepts `/tickets/<id>`; `pageRun` redirects any `TKT-…`
    id to the ticket page.
  - `server.py`: new read-only proxies
    `get_ticket_proxy`, `tickets_search_proxy`, `tickets_stats_proxy`
    (the dashboard never talks to C3 directly for ticket data).

### Bug 2 — the duplicate flood (~10.9k tickets)
- **Cause:** `maybe_create_ticket` filed one ticket **per alert
  event** — no dedup, and it filed tickets even when the triage
  decision was `digest_only` (informational; the email path already
  skipped those but the ticket path didn't).
- **Fix** (`scripts/soc/agentic-soc-send.py`, live via the
  bind-mount — no container restart needed):
  1. `digest_only` / `note_only` decisions → no ticket (alert
     carries `_ticket_skipped`).
  2. Dedup: before creating, it asks C3
     `list_tickets(status=open, source_alert_ref=<ref>)`; an OPEN
     ticket for the same ref already existing ⇒ the new firing is
     **folded into that ticket** (`update_ticket` + comment naming
     the firing time and, for vul-detector firings, the specific
     CVE/package). Alert carries `_ticket_folded_into`.
  3. Kill switches: `SOC_TICKETS_DEDUP=0` (old behavior),
     `WAZUH_AGENTIC_LOOP_ENABLE=0` (whole loop). The e2e selftest
     (`WAZUH_E2E_DECISION_FIXTURE` set) is exempt from both so the
     regression test still exercises real creation.
- **Backing C3 change:** `list_tickets` gained a `source_alert_ref`
  filter so the dedup query is one clean pass.

### Bug 3 — helper timeouts vs the grown store (0.2 s)
- `soc_tickets_helper` defaulted `TIMEOUT_S=0.2`, but every C3
  mutation rewrites the **whole** JSONL store atomically
  (tempfile+`os.replace`). At ~10.9k rows (~50 MB) that became
  multi-second work: creates intermittently returned
  `create_returned_none` (`TimeoutError`), C3's journal filled with
  `BrokenPipeError` storms (the flooding client disconnecting
  mid-response), and the e2e timed out.
- **Fix:** helper default timeout 0.2 s → **5.0 s**
  (`SOC_TICKETS_HELPER_TIMEOUT_S` env still wins when set).
  Backups: `*.bak-20261015` next to each edited file.
- **Perf note:** the store design is fine at ~10k rows. If it grows
  another 10×, budget a compaction pass (§6) or store compaction
  (rotate closed bodies into an archive file).

### Bug 4 — the e2e selftest had been red for weeks (pre-existing)
Found while verifying the flood fix; three stacked issues:
1. `tests/fixtures/alert_rule_40112.json` had **no top-level alert
   `id`**, so schema-2 evidence validation rejected the fallback
   `alert_id: "?"` → every e2e run died at
   `validation_error`. Fixed by adding the id
   (wazuh-style `1786660800.40112`).
2. Bug 3's timeout also killed e2e creates.
3. The selftest's env overrides didn't pin `SOC_AUDIT_LOG`, so the
   host-run e2e subprocess appended audit rows to the **stale**
   `~/.openclaw/audit_log.jsonl` (the pre-2026-09-13 path; see the
   `soc-audit-mcp.service.d/audit-path.conf` drop-in comment) while
   C4 reads the canonical
   `/home/wez/.openclaw-wazuh/audit_log.jsonl` → the run-tag
   assertion ("no decision_prompt row with runId=e2e-…") never
   found anything. Production gets this right via the container env
   `OPENCLAW_STATE_DIR=/home/wez/.openclaw-wazuh`. Fixed by pinning
   `SOC_AUDIT_LOG` in `soc_loop_e2e_selftest.py`'s
   `_test_env_overrides`.
- **Proof:** `python3
  /home/wez/repos/stsgym-work/scripts/soc/soc_loop_e2e_selftest.py`
  → `LOOP E2E: PASS`, decision_prompt + wazuh_alert +
  remediation_apply + fix_verified rows all present; the test
  creates and closes its own ticket.

### Bug 5 — C1 `get_rule_metadata` HTTP 400 (indexer fielddata)
- Terms-agg on `agent.name` (a TEXT field) — OpenSearch requires the
  `.keyword` subfield. Fixed to `agent.name.keyword`; also the
  `_source` list now includes `rule.id/level/description` (recent
  hits used to show null level/desc). Restarted, verified ok.

### Bug 6 — helper smoke-tests write to the LIVE store (documented, not fixed)
- `soc_tickets_helper --smoke` sets `SOC_TICKETS_LOG` in the
  **client** process, but that env only matters to the C3 **server**;
  the smoke's live create landed in the real store
  (TKT-20261015-046 = title "x", body "y"). Until fixed, run smokes
  only with writes disabled or with C3 pointed at a temp store:

  ```
  # smoke session (then revert):
  sudo systemctl edit soc-tickets-mcp       # Environment=SOC_TICKETS_LOG=/tmp/smoke.jsonl
  sudo systemctl daemon-reload && sudo systemctl restart soc-tickets-mcp
  python3 /home/wez/repos/stsgym-work/scripts/soc/soc_tickets_helper.py --smoke
  sudo rm /etc/systemd/system/soc-tickets-mcp.service.d/override.conf  # (only if you added a temp override file)
  sudo systemctl daemon-reload && sudo systemctl restart soc-tickets-mcp
  ```

## 3. Ticket archive semantics (owner requirement, 2026-10-15)

- `ARCHIVE_AFTER_DAYS = 30` in
  `/opt/soc-openclaw/services/soc-tickets-mcp/server.py`. A ticket
  whose `closed_at` is older than 30 days is **archived**
  (computed at query time from `closed_at` — no schema change, fully
  reversible; tune the constant if needed).
- Default `list_tickets` **excludes** archived tickets from every
  listing and count (any status). Reach them with:
  - `list_tickets {archived: "only"}` → archived only
  - `list_tickets {archived: "all"}` → everything
  - Full-text `search_tickets` (UI "Search") scans the **whole**
    store, archived included — the way back to older work.
- Dashboard (/tickets, http://192.168.1.106:8771/tickets):
  - Filter select: **Open (default)** · In progress · Waiting ·
    Closed (last 30d) · Archived (closed >30d) · All
  - Search box: Enter → full-text search over all tickets
    (incl. archived), results carry status badges.
  - The open view also shows: open total, open-created-24h,
    closed <30d, archived >30d counts (from `tickets_stats`).
- **Overview counts are open-centric:** `/tools/overview` now
  returns `tickets_stats` (open_total, open_by_severity,
  open_created_24h, closed_recent_30d, archived_total) and
  `tickets_recent` lists OPEN tickets only. The UI cards read from
  `tickets_stats`.

## 4. 2026-10-15 backlog processing record

- Store: `~/.openclaw/soc_tickets.jsonl` — 10,937 rows
  (1 pre-existing closed + 2 verification artifacts closed during
  the session) → after the sweep **5 open / 10,932 closed**
  (+1 e2e row later: 10,938 rows).
- Pre-sweep backup: `soc_tickets.jsonl.bak-20261015-pre-dedup`
  (49.8 MB, same dir). Per-service code backups:
  `server.py.bak-20261015` style next to every edited file,
  `scripts/soc/*.bak-20261015` in the repo.
- Sweep pattern (reusable): group OPEN tickets by
  `source_alert_ref` → keep the **newest** as representative →
  close the rest as duplicates of it → disposition reps with
  evidence comments. (Sweep tooling was transient at
  `/tmp/process_backlog.py`; the permanent record is this section +
  the per-ticket comments.)

### The 5 tickets left OPEN (all verified live today, assignee=wez)

| Ticket | Ref | What | Evidence / action |
|---|---|---|---|
| TKT-20261014-1683 | wazuh:23506:013 | CVE-2026-74493, L13, **CVSS 9.8 NETWORK**, affects installed `linux-image-6.8.0-147` | trooper2 runs 6.16.12 w/ 147 installed; **no fixed release yet** — watch noble pocket |
| TKT-20261014-1753 | wazuh:23506:029 | same CVE on gus2 | gus2 runs 6.8.0-142 w/ 147 installed |
| TKT-20261014-1687 | wazuh:23505:013 | CVE-2025-40170, L10, CVSS 7.8 LOCAL, same package | trooper2 |
| TKT-20261014-1763 | wazuh:23505:029 | same CVE on gus2 | gus2 |
| TKT-20261015-077 | wazuh:100402:029 | **NVMe /dev/nvme0 on gus2 at 75 °C vs smartd critical limit 65 °C** (Min/Max 66/77), recurring ~every 30 min (through 12:27Z today); /dev/sda fine (27–28 °C) | verified via smartd journal + smartctl; action: thermal/cooling review, NVMe wear check, or threshold tune in `smartd-custom.xml` |

(Exact ids in the store are authoritative; the table is the map.)

### Closure categories (every closed ticket carries its reason as a comment)

- **Duplicates (10,871):** one-ticket-per-alert-event flood →
  "duplicate of <rep> — bulk dedup 2026-10-15".
- **Permanently blocked (9, agents 018/019/020 = evgen-a/b/c):**
  hosts unresolvable (no DNS, not in tailnet), wazuh agent
  Disconnected, no 90-day firings — "system no longer able to be
  worked on" per owner instruction.
- **Superseded enrollment ids (6 refs; ids 008→gus2 now 029,
  021–024→pve-pilot/pve2/pve3/pve4 now 025–028):** hosts alive under
  their re-enrolled ids.
- **AIDE integrity findings (100102 L12 / 100103 L10):** verified
  benign churn — nightly checks caught `added/removed/changed`
  counts matching the unattended-upgrades + logrotate windows
  (fleet dpkg logs: 10-14 06:53 `linux-libc-dev`/`linux-tools` →
  6.8.0-147; daily 06:1x–06:5x runs). Sampled changed paths = log
  rotations and monitoring state files. Recommended at next
  maintenance: full AIDE diff review + `aideinit` baseline rebuild.
  (LLM triage was down at alert time — gateway 1006 — so these were
  routed-to-digest; reviewed here.)
- **Package installs (100300):** unattended-upgrades windows —
  routine authorized patching (SI-2 audit-trail only).
- **Kernel-CVE scanner re-fires on vader/darth/pve/old-ids
  (superseded):** verified host kernel state (vader 6.8.0-142+147ii,
  darth 6.8.0-146+147ii, gus2 6.8.0-142+147ii, trooper2
  6.16.12+147ii, thing1 6.8.0-146+147ii agentless); scanner quiet on
  those hosts since; open watch centralized in the 4 kept tickets.
- **Shellshock L15 (11 × 31168, mail.stsgym.com, 09-29 ~10:34Z):**
  VERIFIED NOT-VULNERABLE — bash on mail is 5.2.21(1); CVE-2014-6271
  family does not apply; the alerts were IDS signatures of failed
  exploitation attempts; source IPs preserved in the bodies.
- **Web/auth background noise (mail: 31151 ×2300, 31153 ×254,
  31533 ×5, 5710, 5712, 80710; darth: 5710):** public-host scan
  traffic (400 storms, common web-attack probes, sshd
  nonexistent-user brute force, POST bots, auditd promiscuous-mode
  info events from monitoring tooling); last firings dated in each
  comment; wazuh + fail2ban monitoring continue.
- **OOM (5108, pve-pilot, single fire 10-06):** resolved, no
  recurrence in 9 days.
- **Test artifacts (2):** the smoke "x/y" ticket + the e2e sandbox
  (agent 000) tickets.

## 5. Operating procedures (humans)

- **Restart a backend:** `sudo systemctl restart soc-tickets-mcp`
  (same pattern: soc-audit-mcp / soc-wazuh-mcp / soc-manager-mcp /
  soc-dashboard / realtime-soc-server). List with
  `systemctl list-units 'soc-*' 'laya-*' 'realtime-*' 'imap-*'`.
- **Writes gate:** the drop-in
  `/etc/systemd/system/soc-tickets-mcp.service.d/override.conf`
  sets `SOC_TICKET_MCP_ALLOW_WRITES=1` (in place since the
  phase-1.1 agentic flow). To go read-only: remove it (see the
  comment in the file), `daemon-reload`, restart.
- **End-to-end regression:** run the selftest (§Bug 4 proof). Expect
  `LOOP E2E: PASS`.
- **Confirm the pipeline dedup on the next real L≥10 alert:**
  `journalctl -u soc-tickets-mcp --since today` (POST log lines) and
  the realtime JSONL row (grep `_ticket_folded_into` or
  `_ticket_skipped`).
- **Bulk re-dedup if a flood recurs:** restore/commit the sweep
  script (see §7 open items) or follow the pattern in §4.
- **Static frontend edits** are live on browser refresh; any change
  to `server.py` files needs the matching restart.
- **Store compaction (future):** if the JSONL grows much past
  ~100 MB, plan a pass that keeps open/recent-closed rows in full
  and summarizes older closed bodies (or move them to an
  `soc_tickets_archive.jsonl`); C3 then points at both files or the
  archive stays searchable via the same search tool extended there.

## 6. Quick reference

| Thing | Where |
|---|---|
| Ticket store (JSONL, one row/ticket incl. comments[]) | `/home/wez/.openclaw/soc_tickets.jsonl` |
| Pre-sweep backup | `…/soc_tickets.jsonl.bak-20261015-pre-dedup` |
| Ticket API (C3) | 127.0.0.1:8768, unit `soc-tickets-mcp` |
| Audit log (C4) | `/home/wez/.openclaw-wazuh/audit_log.jsonl` (unit `soc-audit-mcp`, drop-in `audit-path.conf`) |
| Dashboard | `http://192.168.1.106:8771` (thing1 LAN br1) / unit `soc-dashboard` |
| Integration script (creator) | repo `scripts/soc/agentic-soc-send.py` (bind-mounted into the wazuh manager container) |
| Helper client (timeouts) | repo `scripts/soc/soc_tickets_helper.py` |
| e2e selftest | repo `scripts/soc/soc_loop_e2e_selftest.py` |
| Wazuh compose | `/home/wez/wazuh-stack/docker-compose.yml` |
| STIG catalogue mount | repo `config/stig-rules` → container `/usr/local/stig-rules` |

## 7. Open items for wez (the real remaining work)

1. **The 5 kept tickets** (§4 table): kernel-CVE watch ×4 (incl. the
   CVSS-9.8 network kernel CVE with no fix released) + the NVMe
   thermal decision on gus2.
2. **Wazuh agents Down/Disconnected on live hosts** (mail since
   ~10-09, then gus2/darth/vader/cactus): re-enroll or accept the
   monitor gaps. The fleet's alert coverage quietly disappeared for
   those hosts — worth a decision.
3. **Commit the sweep tooling** into `scripts/soc/tools/` so the
   next flood has a checked-in script instead of a runbook
   description.
4. **Helper smoke isolation** (Bug 6) — small patch to actually
   honor a temp store.
5. **`source_run_id` on digest-path tickets:** soc_decision's
   laya-gated path builds decisions with `run_id=None`; tickets
   created from those will always show "No linked audit run" in the
   UI (handled gracefully). If you want run linkage there too, the
   laya path needs to thread its audit runId into the Decision.
6. distro-info-data on the Ubuntu fleet is outdated (unattended-
   upgrades warning 10-15) — harmless but noisy.

— end of runbook (2026-10-15) —