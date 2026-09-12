# Fleet onboarding — managing systems with Wazuh + OpenClaw

"Managed system" = any machine running a Wazuh agent. Enrollment takes
under a minute; the SOC side picks it up automatically.

## 1. Enroll the machine into Wazuh

On the **manager host** (where the Wazuh stack runs):

```bash
# Option A: any-IP enrollment is already open (authd on :1515)
docker exec wazuh-stack-wazuh.manager-1 \
  /var/ossec/bin/manage_agents -a -n <NEW-HOSTNAME> -a any
# note the agent id it prints; extract the key:
docker exec wazuh-stack-wazuh.manager-1 \
  /var/ossec/bin/manage_agents -e -i <AGENT_ID>
```

On the **new system** (Ubuntu-family):

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | gpg --dearmor | sudo tee /usr/share/keyrings/wazuh.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update && sudo apt install -y wazuh-agent
sudo sed -i "s/MANAGER_IP/$(dig +short <manager-host> | head -1)/; s/<MANAGER_IP>/<manager-host>/" /var/ossec/etc/ossec.conf
sudo sed -i "s/<MANAGER_IP>/<manager-host>/" /var/ossec/etc/ossec.conf
sudo systemctl enable --now wazuh-agent
```

Or with the registration password/keys from step A pasted into
`/var/ossec/etc/authd.pass` / `client.keys`.

## 2. Verify it joined the fleet

On the SOC host:

```bash
curl -sS -X POST -H "Content-Type: application/json" -d '{}' \
  http://127.0.0.1:8767/tools/list_agents | python3 -m json.tool | head -30
```

or open the dashboard → **Fleet**. A fresh agent shows `status: never
connected` until the agent daemon starts and checks in (keepalive every
10 s by default). The dashboard marks agents `stale`/`disconnected`
based on keepalive age — that freshness view is what the C2 manager-mcp
serves.

## 3. What the SOC does with a new agent

Nothing needs configuring: the manager's integration
(`agentic-soc-send.py`) fires on alerts from **any** agent; the alert is
triaged by `soc-triage`, ingested into the realtime JSONL, and appears
on the dashboard. Group-specific policies (e.g. web servers vs
workstations) are a Wazuh concern: assign agent groups via
`manage_agents`/`agent_groups` and match them with Wazuh rules.

## 4. Acting on a managed system (C2)

The manager-mcp exposes read-only fleet tools by default
(`list_agents`, `get_agent`, `get_rule_info`, ...) and a gated
`restart_agent` mutation. To enable mutations:

```
# in the manager glue env (deploy/soc-stack.env controls the file):
SOC_MANAGER_MCP_ALLOW_MUTATIONS=1
sudo systemctl restart soc-manager-mcp
```

Keep it off unless an agent (human or sub-agent) is wired up to approve
restarts — an LLM-triggered restart of production boxes is a policy
decision, not a default.

## 5. OpenClaw side

Sub-agents (the LLM half) are registered on the OpenClaw gateway by
`agents/bootstrap-fleet.sh` and live under `$SOC_AGENTS_DIR/<id>/`.
Their LLM calls go through `lib/llm_runtime.py`, which prefers the
`openclaw agent` harness and falls back to a local Ollama
(`/api/generate`). Audit rows for every LLM call land in the SOC audit
log (Track B), which the dashboard's Scores/Tenants views read.

## 6. Removing a system

```bash
docker exec wazuh-stack-wazuh.manager-1 /var/ossec/bin/manage_agents -r <AGENT_ID>
```

Wazuh keeps history; the dashboard will drop it from Fleet on the next
poll.