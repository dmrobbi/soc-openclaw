# Deployment guide

Step-by-step from a bare Ubuntu-style host to a working SOC: Wazuh
stack, the eight systemd services, and the OpenClaw sub-agent fleet.

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
3. installs + enables the eight systemd units,
4. registers the six sub-agents (idempotent, re-run to propagate
   persona edits),
5. leaves a **compat symlink** if the legacy
   `~/.openclaw/workspace/agentic-ai` path is referenced anywhere.

## 5. Verify

```bash
bash deploy/healthcheck.sh
```

15 checks: every unit active, every healthz green, fleet populated
through the C2 manager, six `soc-*` agents registered. Wire it into a
cron watchdog if you like — non-zero exit means "look at me".

```
# e.g. /etc/cron.d/soc-healthcheck
*/15 * * * * root /opt/soc-openclaw/deploy/healthcheck.sh >> /var/log/soc-healthcheck.log 2>&1
```

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