# SOC Wazuh manager API MCP server (Track C, C2)

Read-mostly HTTP server that wraps the Wazuh manager REST API
(`https://host:55000`) and exposes it to SOC agents. This is the
*manager* — i.e. agent control, rule inspection, manager status,
and the active-response surface. For alert *content* and the
`wazuh-alerts-*` index, use the indexer MCP
(`soc-wazuh-mcp` / C1, port 8766) instead.

## Tools

| Tool | Args | Returns | Mutating? |
|---|---|---|---|
| `list_agents` | `limit=200, status=None` | `{ok, agents[], total, params}` | no |
| `get_agent` | `agent_id` | `{ok, agent}` | no |
| `get_manager_status` | — | `{ok, status: {daemon: state, ...}}` | no |
| `get_manager_info` | — | `{ok, info: {path, version, type, ...}}` | no |
| `get_rule_info` | `rule_id` | `{ok, rule_id, rule}` | no |
| `restart_agent` | `agent_id` | `{ok, manager_response}` | **yes (gated)** |

`status` filter for `list_agents` accepts: `active`, `pending`,
`disconnected`, `never_connected`.

`restart_agent` requires the server to be started with
`SOC_MANAGER_MCP_ALLOW_MUTATIONS=1`. Without it, calls return
HTTP 403. Direct `PUT` and `DELETE` to the server are refused
at the transport layer (HTTP 405); all writes go through the
tool layer so the audit trail is preserved.

## Endpoints

- `GET /healthz` — liveness; 200 if `WAZUH_API_PASSWORD` is set,
  503 otherwise (so a misconfigured systemd unit is loud).
- `GET /tools` — list of registered tools
- `POST /tools/<name>` — invoke; body = JSON args
- `PUT` / `DELETE` on any path — 405

## Configuration

Environment variables:

| Var | Default | Notes |
|---|---|---|
| `WAZUH_MANAGER_URL` | `https://127.0.0.1:55000` | Manager API base |
| `WAZUH_API_USERNAME` | `wazuh-wui` | RBAC user (wui role recommended) |
| `WAZUH_API_PASSWORD` | _empty_ | **Required.** Loaded from `secrets/wazuh-agent-keys-2026-08-03.env` |
| `SOC_MANAGER_MCP_BIND` | `127.0.0.1` | Use `lan` only behind a firewall |
| `SOC_MANAGER_MCP_PORT` | `8767` | |
| `SOC_MANAGER_MCP_TOKEN_TTL_S` | `900` | JWT cache lifetime; force-refresh on 401 regardless |
| `SOC_MANAGER_MCP_ALLOW_MUTATIONS` | `0` | Set to `1` to enable `restart_agent` |
| `SOC_MANAGER_MCP_VERIFY` | `0` | Set to `1` to enable TLS verification |

## Run

```bash
# foreground
python3 /opt/soc-openclaw/services/soc-manager-mcp/server.py

# systemd (preferred)
sudo cp soc-manager-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soc-manager-mcp

# smoke (no live manager required)
python3 /opt/soc-openclaw/services/soc-manager-mcp/server.py --smoke
```

## Wire it into the openclaw harness

Add to the agent's `~/.openclaw/<agent>/openclaw.json` (or the
gateway's central config):

```json
{
  "mcpServers": {
    "wazuh_manager": {
      "type": "http",
      "url": "http://127.0.0.1:8767/tools",
      "tools": ["list_agents", "get_agent", "get_manager_status",
                "get_manager_info", "get_rule_info", "restart_agent"]
    }
  }
}
```

The agent then calls `mcp__wazuh_manager.<tool>(...)`.

## Safety

- **Read-mostly by default.** The only mutating tool is
  `restart_agent`, and it is disabled unless
  `SOC_MANAGER_MCP_ALLOW_MUTATIONS=1` is explicitly set.
- **Bound to loopback by default.** If you need a remote agent,
  set `SOC_MANAGER_MCP_BIND=lan` and add a firewall allow rule.
- **Capped responses.** Hard cap of 5 MB JSON per call.
- **Self-signed cert handling** — the SOC stack uses self-signed
  certs; TLS verification is off by default. Turn it on with
  `SOC_MANAGER_MCP_VERIFY=1` if you've added proper certs.
- **Token rotation safe.** The cached JWT is force-refreshed
  on any 401, so a manual `WAZUH_API_PASSWORD` rotation
  (the 2026-08-03 pattern) is handled by the next call.
- **Healthz 503 on misconfig.** If `WAZUH_API_PASSWORD` is
  empty, `/healthz` returns 503 with a `missing[]` list, so a
  broken systemd unit shows up in `systemctl status` rather
  than as a silent startup.

Created 2026-08-08 by Ciceron as part of Track C (C2).
