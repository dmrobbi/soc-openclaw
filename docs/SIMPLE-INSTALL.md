# SIMPLE-INSTALL.md — the whole SOC from our public GitHub repos

One host, two repos, a handful of commands. This page = the shortest real
path; every detail lives in [deploy-guide.md](deploy-guide.md) and the
[quickstart](../quickstart.md).

## The repos (all public)

| repo | what it gives you |
|---|---|
| [wazuh-stack](https://github.com/dmrobbi/wazuh-stack) | the detector: Wazuh manager + indexer + dashboard (docker compose, certs tooling, .env pattern) |
| [soc-openclaw](https://github.com/dmrobbi/soc-openclaw) (this repo) | the brain and the panels: 8 systemd services, 4 maintenance timers, the dashboard on :8771, the OpenClaw sub-agent fleet |

Optional companions (same org, same pattern):
[stig-baselines](https://github.com/dmrobbi/stig-baselines) (the DISA
baselines the compliance timers score against),
[kevstig](https://github.com/dmrobbi/kevstig) (CISA KEV × STIG gap
checker), [laya-control](https://github.com/dmrobbi/laya-control) (the
local model that gates triage decisions),
[luks-container-guide](https://github.com/dmrobbi/luks-container-guide)
(secrets at rest behind a TPM hardware lock).

## 0. What one host needs

- Ubuntu-style Linux: systemd, python3, sudo
- Docker Engine (`docker --version`)
- [OpenClaw](https://github.com/openclaw/openclaw) installed with an LLM
  provider configured; `openclaw` on PATH; `openclaw gateway start` works
- ~4 GB free RAM for the Wazuh containers; everything else is light
- The dashboard host IS the Wazuh manager host (they talk over 127.0.0.1)

## 1. Wazuh — the detector

```bash
git clone https://github.com/dmrobbi/wazuh-stack.git wazuh-stack && cd wazuh-stack
./wazuh-certs-tool.sh --config-file config.yml     # generate node certs
cp .env.example .env && ${EDITOR:-nano} .env       # passwords + the agentic token
docker compose up -d                               # indexer, then manager, then dashboard
curl -sk https://127.0.0.1:55000/ -o /dev/null -w '%{http_code}\n'   # 401 = alive + authing
```

Other fleet hosts connect to THIS host's :1514. Onboard them with
[docs/fleet-onboarding.md](fleet-onboarding.md) (install `wazuh-agent`,
request enrollment, approve with `manage_agents`).

## 2. The SOC — the brain and the panels

```bash
sudo mkdir /opt/soc-openclaw && sudo chown "$USER" /opt/soc-openclaw
git clone https://github.com/dmrobbi/soc-openclaw.git /opt/soc-openclaw
cd /opt/soc-openclaw/deploy
cp soc-stack.env.example soc-stack.env && ${EDITOR:-nano} soc-stack.env   # the four knobs
sudo bash install.sh                              # idempotent; dry-run first if you like:
                                                  #   sudo SOC_DRY_RUN=1 bash install.sh
```

What install.sh does: creates the runtime dirs, writes the per-agent glue,
installs and enables **8 services** (soc-dashboard :8771, the realtime
ingest :8765, the wazuh/manager/memory/tickets/audit MCPs :8766-8769 and the
IMAP watcher) and **4 timers** (daily-decisions 06:00Z, compliance-daily
06:30Z, healthcheck hourly + alert-on-failure, scan-weekly), then registers
the **six OpenClaw sub-agents** (soc-triage, soc-narrator, soc-replier,
soc-incident-reviewer, soc-ioc-enricher, soc-comms). Re-run any time to
propagate changes.

## 3. Two secret files

In `$SOC_SECRETS_DIR` (default `/home/<user>/.openclaw/soc/secrets`,
chmod 700; both files chmod 600):

```bash
# wazuh-manager-api.env
WAZUH_API_USERNAME=wazuh-wui
WAZUH_API_PASSWORD=<24-char random secret>

# reports-mailbox.env   (the one-way SOC mailbox)
SMTP_HOST=<your mail host>       SMTP_PORT=587
IMAP_HOST=<your mail host>       IMAP_PORT=993
REPORTS_MAILBOX=reports@example.com
REPORTS_MAILBOX_PW=<mailbox password>
WAZUH_REPORTS_RECIPIENT=you@example.com
WAZUH_AGENTIC_ENABLE=1
```

Container note: any `.env` the Wazuh manager container reads through a
bind-mount must be readable by the container user (uid 999), never 600:

```bash
chown 999:<your gid> <file> && chmod 640 <file>
```

The healthcheck asserts these perms and fails loudly on drift.

## 4. Verify (2 commands)

```bash
bash /opt/soc-openclaw/deploy/healthcheck.sh
curl -s http://127.0.0.1:8771/healthz     # {"ok":true, ...}
```

Then open **http://<host>:8771** — the SOC dashboard.

## 5. First alert drill

```bash
curl -s -X POST http://127.0.0.1:8765/ingest -H 'Content-Type: application/json' \
  -d '{"id":"drill-1","rule_id":100103,"level":10,"agent_name":"drill-host",
       "rule_description":"SYNTHETIC DRILL - synthetic-alert training row",
       "src_ip":"192.0.2.55"}'
```

You should get `{"ok": true, alert_id ...}` back; the row lands in the
store the dashboard reads.

## 6. The layers above the floor (optional, all dmrobbi)

- **stig-baselines** — the maintained DISA baseline set the compliance
  timers collect evidence and score against
- **kevstig** — routes the CISA KEV catalog against those baselines
- **laya-control** — a small local model gating the deterministic triage
  (see its /laya page on bedimsecurity.com)
- **luks-container-guide** — LUKS2 vault in a container with TPM
  machine-binding; secrets stay ciphertext once the container stops

That's the whole system: two repos, one script of glue per repo, everything
else = the platform doing what it says.