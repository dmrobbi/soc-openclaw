# Stocked Wazuh Dashboards

Six SOC-tailored dashboards (26 visualizations) for the Wazuh stack's
OpenSearch Dashboards UI, built from the **live index mappings** so every
panel queries real fields. Wazuh 4.14 ships no legacy saved dashboards —
after a stack rebuild the Dashboards app starts empty; this folder makes
that a one-command (or one-upload) fix.

## What's included

| Dashboard | Panels | Source index |
|---|---|---|
| SOC · Fleet Health | agents metric, status pie, active-over-time, agent inventory table, version breakdown | `wazuh-monitoring-*` |
| SOC · Alert Volume by Agent | stacked area per agent, by-agent pie, top locations table | `wazuh-alerts-*` |
| SOC · Critical Alerts (L12+) | count, trend, by-agent, detail table (rule/agent/srcip/dstuser), filtered `rule.level >= 12` | `wazuh-alerts-*` |
| SOC · Authentication Activity | auth trend, by dstuser, top auth rules (`rule.groups: authentication/sshd`) | `wazuh-alerts-*` |
| SOC · Rule Ranking | distinct rules, severity pie, top rule groups, top rules table | `wazuh-alerts-*` |
| SOC · Sources & Targets | events with `data.srcip`: trend, top source IPs, agent+user table | `wazuh-alerts-*` |

## Prerequisites

- The Wazuh stack is up (indexer on `https://<manager-host>:9200`).
- The `wazuh-alerts-*` and `wazuh-monitoring-*` **index patterns exist and
  are not hollow** (fields + `timeFieldName: timestamp`). If the
  Dashboards UI shows no data at all, fix the patterns first — see the
  repair notes in the repo history (they can be rebuilt from `_mapping`).
- Indexer credentials. The importer reads them from
  `~/.openclaw/soc/secrets/wazuh-indexer.env` (`WAZUH_INDEXER_PASSWORD`,
  user `admin`). For manual installs, substitute your own.

## Install — Option A: importer script (recommended)

```bash
cd deploy/wazuh-dashboards
python3 build-wazuh-dashboards.py --import
```

- Regenerates all definitions from the **current** live mappings (so it
  adapts to index template changes), writes `wazuh-dashboards.ndjson`,
  then PUTs every saved object directly into `.kibana`.
- Idempotent — safe to re-run any time (e.g. after a stack rebuild).
- Requires: python3, network access to the indexer, the creds env file.
- Flags: `--ndjson-only` (regenerate the file without importing),
  `--out PATH` (write the ndjson elsewhere).

## Install — Option B: through the browser (no shell access to indexer needed)

1. Log into the Wazuh dashboard (`https://<manager-ip>:5601`) as admin.
2. Open **Stack Management → Saved Objects → Import** (under Management in
   OpenSearch Dashboards it may appear as "Saved objects" in the main menu).
3. Select `wazuh-dashboards.ndjson` from this folder → Import.
   - Conflicts: choose **overwrite** if re-importing over an existing set.
4. Open the **Dashboards** app — the six "SOC · ..." dashboards are there.

The ndjson is in saved-object import format (one JSON object per line with
`type`/`id`/`attributes`/`references`), so it imports cleanly both via UI
and API.

## Install — Option C: raw curl (one PUT per object)

If you'd rather not run the script against the live indexer:

```bash
cd deploy/wazuh-dashboards
source ~/.openclaw/soc/secrets/wazuh-indexer.env   # WAZUH_INDEXER_PASSWORD
# python3 stdlib one-liner equivalent of the importer, object by object:
python3 - <<'EOF'
import json, ssl, urllib.request, base64, os
tok = "Basic " + base64.b64encode(
    ("admin:" + os.environ["WAZUH_INDEXER_PASSWORD"]).encode()).decode()
ctx = ssl.create_default_context(); ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
for line in open("wazuh-dashboards.ndjson"):
    o = json.loads(line)
    body = {"type": o["type"], o["type"]: o["attributes"],
            "references": o.get("references", []),
            "migrationVersion": o.get("migrationVersion", {})}
    r = urllib.request.Request(
        "https://127.0.0.1:9200/.kibana/_doc/" + o["type"] + ":" + o["id"],
        method="PUT", headers={"Content-Type": "application/json",
                               "Authorization": tok},
        data=json.dumps(body).encode())
    with urllib.request.urlopen(r, context=ctx, timeout=20) as resp:
        print(o["id"], json.loads(resp.read())["result"])
EOF
```

Notes:
- The `.kibana` mapping is **strict** — do not add a `version` field to
  externally-PUT documents (the importer and the snippet above already
  omit it; raw bulk payloads copied from elsewhere may not).
- Direct PUTs bypass the UI import conflict checks; re-running simply
  overwrites the same ids.

## Rebuilding / customizing

Edit the dashboard definitions in `build-wazuh-dashboards.py` (each
dashboard is a small block of `vis_*` + `dashboard(...)` calls), then
re-run Option A. Visualizations are built with the legacy 7.10 visState
schema (`histogram`, `pie`, `table`, `metric`, `horizontal_bar`), which the
Wazuh fork of OpenSearch Dashboards renders natively.

## Files

- `build-wazuh-dashboards.py` — generator + importer
- `wazuh-dashboards.ndjson` — generated saved-object export (UI import format)