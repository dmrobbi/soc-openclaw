# Security notes

Secrets, credentials, and the recovery paths that bite.

## Ground rules

1. **Secrets never live in this repo.** The installer only checks for
   their existence and never prints values. Two files, chmod 600:
   - `wazuh-manager-api.env` — `WAZUH_API_USERNAME`, `WAZUH_API_PASSWORD`
   - `reports-mailbox.env` — SMTP/IMAP hosts + `REPORTS_MAILBOX_PW`
2. **Credentials reach processes via PrivateTmp.** The manager unit's
   `ExecStartPre` writes `/tmp/soc-manager-mcp.env` (PrivateTmp'd, 600)
   from the canonical secret; the unit loads it with
   `EnvironmentFile=-/tmp/soc-manager-mcp.env`. Nothing secret lands in
   the journal.
3. **The Wazuh manager container bind-mounts the mailbox env** — deleting
   the host file does not unmount it (inode stays alive), which is also
   how you recover it:

   ```bash
   docker exec wazuh-stack-wazuh.manager-1 cat /etc/reports-mailbox.env \
     > /home/wez/.openclaw/soc/secrets/reports-mailbox.env
   chmod 600 /home/wez/.openclaw/soc/secrets/reports-mailbox.env
   ```

## Rotating the Wazuh API password (lost-secret procedure)

Wazuh 4.14 stores API user hashes as **werkzeug scrypt** strings —
*not* bcrypt. Verify format first (`scrypt:` prefix). Rotate without
knowing the old one:

```bash
# 1. new random secret
openssl rand -base64 18    # 24 chars; store it in wazuh-manager-api.env

# 2. hash with the CONTAINER's werkzeug (version-matched):
PW='<new secret>'
docker exec -i wazuh-stack-wazuh.manager-1 /var/ossec/framework/python/bin/python3 \
  -c 'import sys; from werkzeug.security import generate_password_hash; \
      print(generate_password_hash(sys.stdin.read().strip(), method="scrypt"))' <<< "$PW"

# 3. swap it into the RBAC database:
docker cp wazuh-stack-wazuh.manager-1:/var/ossec/api/configuration/security/rbac.db /tmp/rbac.db
python3 -c "import sqlite3; ..."   # UPDATE users SET password=<hash> WHERE username='wazuh-wui'
docker cp /tmp/rbac.db wazuh-stack-wazuh.manager-1:/var/ossec/api/configuration/security/rbac.db
docker exec wazuh-stack-wazuh.manager-1 chown wazuh:wazuh \
  /var/ossec/api/configuration/security/rbac.db
docker restart wazuh-stack-wazuh.manager-1

# 4. verify (status code 200 = good)
curl -sk -o /dev/null -w "%{http_code}\n" -u "wazuh-wui:<new>" \
  -X POST https://127.0.0.1:55000/security/user/authenticate
```

(There is also `/var/ossec/bin/rbac_control change-password`, but it is
interactive-only.)

## Dashboard ↔ manager API credentials

The Wazuh dashboard's plugin uses its own stored manager API credentials
in `/home/wez/wazuh-stack/config/wazuh_dashboard/wazuh.yml` (bind-mounted
into the dashboard container). When the manager API password rotates,
**that file must be updated too** — a stale password makes the plugin
401 every five minutes and every Wazuh-native view (Overview, Agents,
Events) silently empties while the SOC dashboard keeps working.

- Verify creds: `POST https://127.0.0.1:55000/security/user/authenticate`
  with the stored user/password (basic auth is accepted ONLY on this
  endpoint; other endpoints need a Bearer token from it).
- The file is a **single-file bind mount**: edit it **in place** (never
  `os.replace`/rename a new file over it — the container keeps reading
  the old inode), keep ownership/mode readable by the container uid
  (uid 1000; host file `wez:wez` 664 works), then
  `sudo docker restart wazuh-stack_wazuh.dashboard_1`.
- Signs of the stale-credential failure mode: repeated
  `cron-scheduler ... AxiosError 401` in the dashboard container logs.

## Systemd failure modes worth knowing

| Result | Cause | Prevented by |
|---|---|---|
| `status=226/NAMESPACE`, no journal | `ReadWritePaths` points at a missing dir | installer pre-creates every data dir |
| `Result: resources` | missing `ExecStartPre` binary or mandatory `EnvironmentFile` | installer writes glue before enabling units; `-` prefix on optional files |
| creds silently missing (`missing: [...]` in `/healthz`) | env file written by ExecStartPre never loaded | the manager unit carries
  `EnvironmentFile=-/tmp/soc-manager-mcp.env` — keep that line if you edit units |
| evidence/snapshot writes silently fail | dashboard unit is `ProtectSystem=strict` + `ProtectHome=read-only`; only `ReadWritePaths` dirs are writable | the soc-dashboard template whitelists `~/.openclaw/soc`, `~/.openclaw/compliance` and `~/.openclaw-wazuh` — keep those lines if you edit units (2026-09-14: without them every dashboard-triggered write failed with EROFS, swallowed by try/except) |

## Pipeline state ownership (the `docker exec -u wazuh` rule)

The Wazuh manager container runs the alert pipeline (and therefore
`openclaw agent` for soc-narrator/soc-triage) as the container user
**uid 999**, against the shared state dir `~/.openclaw-wazuh`
(bind-mounted at the same in-container path). Contract:

- every file/directory under `~/.openclaw-wazuh` must be readable
  (and where written, writable) by uid 999 — owner or via the default
  ACLs (`d:u:999:rwX` set on every directory by the 2026-09-14 fix);
- a **bare `docker exec`** into the manager container runs as root and
  creates root:root 600 state files (session state, device
  credentials) that the wazuh user then cannot read — the result is
  every LLM decision turn failing with EACCES or
  `missing scope: operator.write` (the gateway rejects the env-token
  fallback). Always `docker exec -u wazuh` for in-container openclaw
  work; if state did get re-rooted:
  `sudo chown -R 999:999 ~/.openclaw-wazuh` (healthcheck asserts this
  hourly);
- the mailbox env copy the container bind-mounts must be
  `chown 999:<SOC_USER gid> && chmod 640` — 600 wez-owned copies
  silently drop every level≥12 alert (the 2026-09-12 incident).

## Exposure posture

- All MCP servers bind **0.0.0.0** in the shipped templates for LAN
  dashboard use; if the dashboard is only used locally, flip
  `SOC_MANAGER_BIND=loopback` (default) and keep the others firewalled.
- Wazuh API (55000) and indexer (9200) are TLS with self-signed certs;
  the stack sets `SOC_MANAGER_MCP_VERIFY=0` by default — turn it on
  (`=1`) once you distribute a real CA.
- The mailbox is one-way (SMTP out + IMAP triage of replies from an
  allowlisted set). Never let it receive anything that auto-executes.

## LLM safety posture

- Every LLM call is audited (`lib/soc_audit.py`) — runtime, agent,
  input kind, outcome — feeding the dashboard's Scores view.
- Triage failures degrade to "route to digest for human review" and open
  a ticket; they never silently drop an alert.
- Mutations (agent restarts) are gated behind
  `SOC_MANAGER_MCP_ALLOW_MUTATIONS=1` and default off.