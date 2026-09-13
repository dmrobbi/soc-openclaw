# Stocked Wazuh dashboards

The Wazuh stack ships no legacy saved dashboards — after any stack rebuild
the Dashboards app starts empty. This repo carries **11 SOC-tailored
dashboards (56 visualizations)** that can be rebuilt and re-imported in one
command, plus a UI-importable export.

## What's included

| Dashboard | Focus | Source index |
|---|---|---|
| SOC · Fleet Health | agent status, versions, keepalive trend | wazuh-monitoring-* |
| SOC · Alert Volume by Agent | alerts over time, per-agent split | wazuh-alerts-* |
| SOC · Critical Alerts (L12+) | rule.level >= 12 (the pager tier) | wazuh-alerts-* |
| SOC · Authentication Activity | logins/failures (rule.groups auth/sshd) | wazuh-alerts-* |
| SOC · Rule Ranking | top rules, severity mix, rule groups | wazuh-alerts-* |
| SOC · Sources & Targets | events with data.srcip | wazuh-alerts-* |
| SOC · Threat Tactics (MITRE) | tactic pie, technique word cloud | wazuh-alerts-* |
| SOC · Geography of Sources | country/city breakdowns | wazuh-alerts-* |
| SOC · System Integrity (FIM) | syscheck added/modified/deleted | wazuh-alerts-* |
| SOC · Vulnerability Findings | severity, CVSS, top packages/CVEs | wazuh-states-vulnerabilities-* |
| SOC · Severity Mix & Trends | stacked severity trend, avg per agent | wazuh-alerts-* |

## Reload after a rebuild (one command)

```bash
cd deploy/wazuh-dashboards
python3 build-wazuh-dashboards.py --import
```

The builder reads the **live index mappings** (so panels always query real
fields), regenerates `wazuh-dashboards.ndjson`, and PUTs every saved object
into `.kibana`. Idempotent. Requires the indexer creds env file
(`~/.openclaw/soc/secrets/wazuh-indexer.env`).

## Manual alternatives

- **Browser**: Wazuh dashboard → Stack Management → Saved Objects →
  Import → `deploy/wazuh-dashboards/wazuh-dashboards.ndjson` (UI import
  format). Overwrite on conflicts when re-importing.
- **Raw curl**: see the step-by-step in `deploy/wazuh-dashboards/README.md`.

## Prerequisites and gotchas

- The index patterns must exist and be non-hollow (fields + a time field).
  The Wazuh plugin auto-creates `wazuh-alerts-*` on first login; the
  vulnerability-states pattern is built by the dashboards importer.
- `.kibana` has a **strict mapping**: never PUT documents containing a
  `version` field (the importer strips it).
- Aggregations on `wazuh-alerts-*` text fields need the `.keyword`
  subfield (`agent.name.keyword`); the vulnerabilities and inventory
  indices map their fields as keyword **directly** (no subfield).
- If the Dashboards UI shows data but saved dashboards are gone, that is
  normal for Wazuh 4.14 — only the stocked set restores them.
- The Wazuh plugin talks to the manager API using credentials in
  `/home/wez/wazuh-stack/config/wazuh_dashboard/wazuh.yml` (bind-mounted
  into the dashboard container). If you rotate the manager API password,
  update that file **in place** (it is a single-file bind mount — replacing
  the file breaks the mount; see docs/security-notes.md) and restart the
  dashboard container.
