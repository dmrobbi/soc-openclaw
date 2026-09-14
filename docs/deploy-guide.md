# Deployment guide

Step-by-step from a bare Ubuntu-style host to a working SOC: Wazuh
stack, the eight systemd services, the three maintenance timers, and
the OpenClaw sub-agent fleet.

## 0. Prerequisites

- Linux host with systemd, python3.10+, and **Docker** (for the Wazuh stack)
- An **OpenClaw gateway** installed and running (`openclaw` binary on PATH),
  with an LLM provider configured for its agents
- ~4 GB free RAM for the Wazuh containers
- The host must be able to reach the Wazuh manager API on
  `https://127.0.0.1:55000` (the dashboard host IS the manager host)

## 1. Wazuh stack

```bash
sudo mkdir -p /opt/soc-openclaw/wazuh
cd wazuh
# edit docker-compose.yml: replace every __...__ placeholder:
#   __INDEXER_PASSWORD__   (pick a strong one)
#   __SOC_HOST_LAN_IP__    (this host's LAN IP — where the realtime
#                           ingest and the MCP servers listen)
#   __SMTP_HOST_IP__       (your SMTP relay, or 127.0.0.1 + relay)
docker compose up -d
# verify
curl -sk -u wazuh-wui:<API_PASSWORD> https://127.0.0.1:55000/security/user/authenticate -X POST | head -c 80
```

Set the manager API password before first start (or rotate later via
`rbac_control` — see docs/security-notes.md).

## 1b. Stock the Wazuh dashboards

Right after the stack comes up, load the SOC dashboards (11 dashboards /
56 visualizations, built from the live index mappings):

```bash
cd deploy/wazuh-dashboards && python3 build-wazuh-dashboards.py --import
```

Details, manual UI import, and the reload-after-rebuild flow:
docs/wazuh-dashboards.md. After the first agents enroll, skim
docs/cve-packages.md (per-host CVE review) and
docs/openscap-scanning.md (compliance scans → evidence → scores).

## 2. Secrets

Create `SOC_SECRETS_DIR` (default `/home/$SOC_USER/.openclaw/soc/secrets`),
chmod 700 the dir, and add two `KEY=***` files, chmod 600:

**wazuh-manager-api.env**
```
WAZUH_API_USERNAME=wazuh-wui
WAZUH_API_PASSWORD=<24-char random secret>
```

**reports-mailbox.env** (the one-way SOC mailbox)
```
SMTP_HOST=<mail host>
SMTP_PORT=587
IMAP_HOST=<mail host>
IMAP_PORT=993
REPORTS_MAILBOX=reports@example.com
REPORTS_MAILBOX_PW=<mailbox password>
WAZUH_REPORTS_RECIPIENT=you@example.com
WAZUH_AGENTIC_ENABLE=1
```

**Container-readable copies (IMPORTANT — the 2026-09-12 incident):** any
`.env` the Wazuh manager container must read through a bind-mount (e.g.
its `/etc/reports-mailbox.env`) must be **readable by the container
user (uid 999)**, NOT chmod 600: `chown 999:<SOC_USER gid> <file> &&
chmod 640 <file>`. A 600 wez-owned copy silently drops every level≥12
alert from the classification pipeline. `deploy/healthcheck.sh`
asserts these perms (999:<uid>:640 for the mailbox env, <uid>:<uid>:600
for the `soc/secrets/*.env`) and fails on drift.

## 3. OpenClaw gateway

The sub-agents register with the OpenClaw gateway on this host.
Install OpenClaw and make sure the `openclaw` binary is on PATH for the
service user (or set `OPENCLAW_BIN` in `deploy/soc-stack.env`).

## 4. Install the SOC stack

```bash
cd /opt/soc-openclaw/deploy
cp soc-stack.env.example soc-stack.env
$EDITOR soc-stack.env          # set SOC_HOME / SOC_USER / paths
sudo SOC_DRY_RUN=1 bash install.sh    # preview what will happen
sudo bash install.sh
```

The installer:
1. creates all runtime dirs (logs, data, agent workspaces, glue),
2. writes the per-agent glue (manager `pre-start.sh` materialises the
   Wazuh API creds into PrivateTmp'd `/tmp`; the daily-decisions runner),
3. installs + enables the eight systemd **services** and the three
   maintenance **timers** — daily-decisions (06:00 UTC report),
   compliance-daily (06:30 UTC: evidence collect for all tenants, merge
   of any OpenSCAP results archived that day, score recompute for every
   tenant) and healthcheck (hourly; on failure fires
   `soc-healthcheck-alert@.service` → `deploy/notify-healthcheck-failure.sh`,
   which notifies the operator via OpenClaw chat with an SMTP fallback),
4. registers the six sub-agents (idempotent, re-run to propagate
   persona edits),
5. leaves a **compat symlink** if the legacy
   `~/.openclaw/workspace/agentic-ai` path is referenced anywhere.

## 5. Verify

```bash
bash deploy/healthcheck.sh
```

~27 checks: every unit active, every timer active, every healthz green,
fleet populated through the C2 manager, six `soc-*` agents registered,
secrets-perm contract and pipeline state ownership correct. Exit 0 =
green. The healthcheck itself is **automated**: `soc-healthcheck.timer`
runs it hourly and on failure `deploy/notify-healthcheck-failure.sh`
sends the operator a message (OpenClaw chat first, SMTP fallback) with
a 4h cooldown.

Test the alert path once after install (sends one message to the
operator's chat):

```bash
deploy/notify-healthcheck-failure.sh soc-healthcheck.service
```

```bash
systemctl list-timers 'soc-*'   # daily-decisions / compliance-daily / healthcheck next-runs
journalctl -u soc-compliance-daily.service -n 20   # nightly refresh output (JSON)
```

## 5b. Maintenance & automation (what runs itself)

| Timer | Schedule | What it does |
|---|---|---|
| `soc-daily-decisions` | 06:00 UTC | Daily decisions report (audit + realtime logs → `soc-agent-decisions-<day>.md`) |
| `soc-compliance-daily` | 06:30 UTC | Collect evidence for every tenant, merge any OpenSCAP results archived that day (worst-result across hosts), recompute all tenant scores |
| `soc-healthcheck` | hourly | `deploy/healthcheck.sh`; on failure pages the operator (OpenClaw chat → SMTP fallback, 4h cooldown) |

Manual remediation of a failing control (dashboard: host page →
**Remediate** tool, mutation-gated via C2 `/healthz`; CLI):

```bash
# preview (no system change)
python3 services/soc_stig_remediate.py --tool remediate_control \
  --args '{"control_id":"AU.L1-3.3.003","tenant_id":"<tenant>","confidence":0.95,"dry_run":true}'
# apply (fixes needing root run the CLI under sudo; pass the state envs —
# sudo strips them and HOME=/root would point the defaults elsewhere)
sudo -n env SOC_ROUTING_CONFIG=$HOME/.openclaw/soc/soc-routing.yaml \
  SOC_SNAPSHOT_DIR=$HOME/.openclaw/compliance/snapshots \
  SOC_REMEDIATION_LOG=$HOME/.openclaw/compliance/remediations.jsonl \
  SOC_AUDIT_LOG=$HOME/.openclaw-wazuh/audit_log.jsonl \
  python3 services/soc_stig_remediate.py --tool remediate_control \
  --args '{"control_id":"AU.L1-3.3.003","tenant_id":"<tenant>","confidence":0.95}'
# then re-own root-created artifacts and re-run the healthcheck
sudo chown -R 999:999 ~/.openclaw-wazuh ~/.openclaw/compliance 2>/dev/null || true
```

Evidence + scoring land automatically after an apply through the
dashboard tool; for CLI runs re-collect with
`python3 services/soc_compliance_daily.py` (or wait for the 06:30
refresh). After detached scans, collect with
`soc_scanner.py --collect <day> --score` — see docs/openscap-scanning.md.

## 6. Point Wazuh at the ingest server

In `wazuh/docker-compose.yml` the manager container's
`REALTIME_SOC_URL` must point at this host's realtime ingest:

```
REALTIME_SOC_URL=http://<SOC_HOST_LAN_IP>:8765/ingest
```

The integration `wazuh/integrations/agentic-soc-send.py` is bind-mounted
into the manager container and fires on every alert that survives the
noise denylist.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| unit `226/NAMESPACE`, no journal | `ReadWritePaths` dir missing | `mkdir -p $SOC_STATE_DIR/data` (installer does this) |
| manager `502` on fleet_status | missing/unreachable Wazuh API creds | `curl http://127.0.0.1:8767/healthz` → `missing` array tells you which key |
| LLM calls exit 1 | sub-agents not registered | re-run `agents/bootstrap-fleet.sh` |
| dashboard down | static dir moved | reinstall via `deploy/install.sh` |
| lost API password entirely | rotate without old secret | docs/security-notes.md § rotation |
| daily report nearly empty (`Total decisions: 1`) | daily-decisions reading the legacy audit log | unit must pin `SOC_AUDIT_LOG` to the canonical log + `SOC_REALTIME_LOG` to the live ingest path (installer's template does this) |
| dashboard writes silently fail (evidence/snapshots) | `ReadWritePaths` in the dashboard unit missing the state dirs | re-render via `deploy/install.sh` — the template includes `~/.openclaw/soc`, `~/.openclaw/compliance`, `~/.openclaw-wazuh` |
| agent turns exit 1: EACCES on `~/.openclaw-wazuh/...` or `missing scope: operator.write` | root-owned files in the pipeline state dir (created by a bare `docker exec`) | `sudo chown -R 999:999 <root-owned files>`; **always run in-container openclaw work as `docker exec -u wazuh`** — healthcheck asserts this hourly |