# soc-openclaw

A step-by-step guide to setting up a home SOC (Security Operations
Center) where **OpenClaw is the always-on AI analyst**: it watches
your host's logs and security tooling in real time, runs scheduled
sweeps, triages what it finds, and pages you on your chat channel.

```
 Linux host(s)          OpenClaw gateway              you
 ---------------        -------------------          --------
 fail2ban, auth.log --> stream automations    ----->  Discord /
 auditd, journald  --> cron sweeps + skills  ----->  Telegram /
 Wazuh (optional)  --> agent triage          ----->  WebChat
```

Scope and honesty: this is a **home-lab SOC**, not an enterprise
stack. It is deliberately built from existing, maintained tools
(fail2ban, auditd, Wazuh) with OpenClaw gluing them together — no
custom SIEM code. Steps are written for Ubuntu/Debian and a fresh
OpenClaw install; if you already run a gateway, skip Step 1.

---

## Step 0 — Prerequisites

- A Linux server you control (Ubuntu 24.04 or similar), with sudo.
- Node.js 20+ (LTS) installed (`node -v`).
- A chat channel you control for alerts: a Discord server (create a
  bot application at discord.com/developers) or a Telegram bot (via
  @BotFather). You need the bot token and, for Discord, the channel
  ID you want alerts in.
- OpenClaw docs for reference: https://docs.openclaw.ai

## Step 1 — Install OpenClaw

On the server:

    npm install -g openclaw

Then launch it:

    openclaw

The first run starts the gateway and walks you through onboarding
(account, workspace). The CLI prints the Control UI URL — open it in
a browser on the same machine or over your LAN, and finish the setup
wizard. Verify health at any time with:

    openclaw status

Later, keep it current with `openclaw update`.

## Step 2 — Connect a chat channel

The SOC is only useful if it can reach you.

1. In the Control UI: Agent Settings -> Channels.
2. Pick Discord or Telegram, paste the bot token, invite the bot to
   your server/chat, and send it a test message.
3. Confirm the gateway is connected (`openclaw status` shows
   channels).

Note the exact channel/chat ID where you want alerts delivered — the
automations in later steps reference it.

## Step 3 — Harden the host (the SOC watches the watcher)

A monitoring box that is itself wide open is decoration. On the SOC
host:

    # firewall: allow SSH only, then enable
    sudo ufw allow OpenSSH && sudo ufw enable

    # SSH: keys only
    sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo systemctl restart ssh

    # unattended security updates
    sudo apt install -y unattended-upgrades
    sudo dpkg-reconfigure -plow unattended-upgrades

**Do this before** adding agents that read logs. If you connect the
Control UI over the network, keep it behind SSH tunnel or Tailscale
rather than exposing the port.

## Step 4 — Baseline security tooling

Install the tools the SOC will watch:

    sudo apt install -y fail2ban
    sudo systemctl enable --now fail2ban
    # check which log file SSH auth lands in on your distro:
    ls -l /var/log/auth.log

Ubuntu keeps `/var/log/auth.log` when rsyslog is installed; on
journald-only systems the stream below can use
`journalctl -f -t sshd` instead.

Optional but recommended: auditd for syscall-level events:

    sudo apt install -y auditd
    sudo systemctl enable --now auditd

## Step 5 — Real-time alerting with a stream automation

OpenClaw automations support `stream` jobs: a supervised process whose
output triggers a run. Point one at the SSH auth log.

Create this job (Control UI -> Automations -> Add; the shape of the
JSON is what matters — adapt to the form fields):

```json
{
  "name": "soc-ssh-bruteforce",
  "schedule": {
    "kind": "stream",
    "command": ["sudo", "tail", "-F", "/var/log/auth.log"],
    "mode": "match",
    "match": "Failed password|Invalid user|authentication failure",
    "batchMs": 2000
  },
  "sessionTarget": "isolated",
  "payload": {
    "kind": "agentTurn",
    "message": "SSH auth failures just hit the SOC host (see the triggering lines). Triage: how many attempts, from which source IPs, is fail2ban already banning them (fail2ban-client status sshd)? If this looks like an active brute force, report details to me; if it looks like background noise, say so briefly."
  },
  "delivery": { "mode": "announce", "channel": "discord", "to": "<YOUR_CHANNEL_ID>" }
}
```

What this gives you:

- `batchMs` groups a burst of matches into one alert instead of forty.
- The agent turn does real triage (counts, IPs, fail2ban state), not
  just forwarding — you get "12 attempts from 203.x, fail2ban banned
  it", not a raw log dump.
- Delivery announces to your channel; the run itself is detached.

The same pattern works for any line-oriented log: NGINX/SSH on other
hosts via `ssh tail -F`, container logs, etc.

## Step 6 — Scheduled sweeps with a skill

Streams catch loud events; sweeps catch slow rot. Give the agent a
playbook first, then schedule it.

Create `~/.openclaw/workspace/skills/soc-sweep/SKILL.md`:

```markdown
---
name: soc-sweep
description: Run the host security sweep. Use for scheduled SOC checks, security audits, or when asked to check the host.
---

# SOC sweep

Run each check on the SOC host and note anything abnormal:

1. `systemctl --failed` — any failed units?
2. `journalctl -p err --since "-24h" -q | tail -n 50` — new errors?
3. `fail2ban-client status` then `fail2ban-client status sshd` —
   current bans; is the ban list much larger than usual?
4. `last -n 20` and `sudo lastb -n 20` — logins and failed logins;
   anything you don't recognize?
5. `ss -tulpn` — listening sockets; anything new or unexpected?
6. `df -h` — disk pressure?
7. `apt list --upgradable 2>/dev/null | wc -l` and
   `apt-get -s upgrade | grep -ci security` — pending updates?

Report one line per finding with a severity (info/warn/urgent). If
everything is clean, report clean in one line.
```

Then schedule it (Control UI -> Automations -> Add):

```json
{
  "name": "soc-morning-sweep",
  "schedule": { "kind": "cron", "expr": "0 8 * * *", "tz": "America/New_York" },
  "sessionTarget": "isolated",
  "payload": {
    "kind": "agentTurn",
    "message": "Run the soc-sweep skill on the host and report the results."
  },
  "delivery": { "mode": "announce", "channel": "discord", "to": "<YOUR_CHANNEL_ID>" }
}
```

Set `tz` to your timezone. Two or three sweeps a day is plenty — one
morning, one end-of-day, optionally one after patch Tuesday.

## Step 7 — Optional: Wazuh as the SIEM tier

When file/auth-log watching is not enough, add a real SIEM and let
OpenClaw be its analyst. Wazuh (open source, agent-based) is the
recommended fit — install it from the official quickstart rather than
commands pasted from any guide (they change per release):
https://documentation.wazuh.com — quickstart "all-in-one" installs the
manager, dashboard, and enrollment in one assisted script.

Once Wazuh is up:

1. Install the Wazuh agent on the monitored host(s) and enroll them.
2. Alerts accumulate at `/var/ossec/logs/alerts/` (JSON lines).
3. Have OpenClaw pull, not push: a scheduled job every 5 minutes:

```json
{
  "name": "soc-wazuh-pull",
  "schedule": { "kind": "every", "everyMs": 300000 },
  "sessionTarget": "isolated",
  "payload": {
    "kind": "agentTurn",
    "message": "Check the last 5 minutes of Wazuh alerts (level 7 and above) via the local Wazuh API or /var/ossec/logs/alerts/alerts.json, filtered by timestamp. If there are none, reply that all is quiet and do not alert me. If there are, triage the important ones: what rule fired, on which host, and what it means. Report findings."
  },
  "delivery": { "mode": "announce", "channel": "discord", "to": "<YOUR_CHANNEL_ID>" }
}
```

The pull pattern is stateless — the agent computes its own time
window — so it survives restarts without losing or double-sending
alerts. Keep the "none = quiet, don't page me" instruction in the
message; a SOC that cries wolf every 5 minutes gets muted on day two.

## Step 8 — Test the pipeline end to end

1. **Stream path:** from another machine, fail SSH logins a few
   times (`ssh wronguser@soc-host` with a bad password). Within
   seconds you should get one batched triage message, and fail2ban
   should show the ban.
2. **Sweep path:** trigger the sweep job manually from the
   Automations page (or wait for the cron) — expect a clean report
   listing all checks.
3. **Wazuh path (if installed):** run something Wazuh watches (e.g.
   a file change in a monitored path) and wait for the next pull to
   report it.
4. **Failure alerting:** automations with a delivery route alert you
   if they keep failing — check that a deliberately broken job gets
   flagged rather than silently dying.

## Step 9 — Operating rules

- **Report, don't nuke.** The agent triages and recommends; it should
  never auto-run destructive remediation (bans, deletes, restarts of
  services) without a human confirming. Build that instinct into the
  skill and automation messages explicitly.
- **Quiet hours.** Instruct the agent (workspace AGENTS.md) not to
  page you at night for low-severity findings; urgent only.
- **Keep the loop small.** Few, well-deduplicated alerts beat a fire
  hose. Batch aggressively (`batchMs`, pull windows) and let the LLM
  do the summarizing — that is its whole job here.
- **Review monthly:** what fired, what you ignored, tune the match
  patterns and alert levels accordingly.

## Maintenance

- `openclaw update` for the gateway (and Node security updates land
  via unattended-upgrades from Step 3).
- Keep the `soc-sweep` skill current as your host changes (new
  services -> new expected sockets).
- Wazuh: follow their upgrade path per release notes.

---

That is the whole build: hardened host, watched logs, a brain that
reads them, and a chat channel it talks to. Total cost: one server,
one bot token, zero license fees — and an AI analyst that never
sleeps, which is more than can be said for the person it reports to.