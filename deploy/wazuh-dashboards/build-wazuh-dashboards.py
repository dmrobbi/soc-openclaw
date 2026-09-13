#!/usr/bin/env python3
"""build-wazuh-dashboards.py — generate + import stocked OpenSearch
Dashboards saved objects (6 dashboards, ~24 visualizations) for the
Wazuh stack, then write deploy/wazuh-dashboards.ndjson so the set is
reloadable after any stack rebuild.

Why: Wazuh 4.14 ships no legacy saved dashboards (the Dashboards app
starts empty) and this repo had none. These are SOC-tailored: fleet
health, alert volume by agent, critical (L12+) alerts, authentication
activity, rule ranking, web/attack traffic.

Usage:
  python3 build-wazuh-dashboards.py --import   # import + write ndjson
  python3 build-wazuh-dashboards.py --ndjson-only  # just write ndjson

Env: reads indexer creds from ~/.openclaw/soc/secrets/wazuh-indexer.env
(WAZUH_INDEXER_PASSWORD). Secrets are used in-process only, never printed.
"""
import argparse
import datetime
import json
import ssl
import urllib.request
from pathlib import Path

ALERTS = "wazuh-alerts-*"
MON = "wazuh-monitoring-*"
MV = {"index-pattern": "7.6.0", "visualization": "7.10.0", "dashboard": "7.9.3"}
NOW = datetime.datetime.now(datetime.timezone.utc).isoformat()

# ---------------------------------------------------------------------------
# Saved-object builders (OpenSearch Dashboards 7.10 legacy schema)
# ---------------------------------------------------------------------------

def kql_filter(field, op, value):
    return {"meta": {"key": field, "params": {"query": value},
                     "type": "phrase", "index": ALERTS},
            "query": {"match": {field: {"query": value, "type": "phrase"}}},
            "$state": {"store": "appState"}}


def vis(id_, title, index_pattern, vis_state,
        filters=None, lang="lucene"):
    ss = {"index": index_pattern, "query": {"query": "", "language": lang},
          "filter": filters or []}
    return {
        "_id": "visualization:" + id_,
        "_source": {
            "type": "visualization",
            "visualization": {
                "title": title, "description": "",
                "visState": json.dumps(vis_state),
                "uiStateJSON": "{}",
                "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)},
            },
            "references": [{"id": index_pattern, "type": "index-pattern",
                            "name": "kibanaSavedObjectMeta.searchSourceJSON.index"}],
            "migrationVersion": {"visualization": "7.10.0"},
            "updated_at": NOW, "version": "WzE=",
        },
    }


def dashboard(id_, title, desc, panels, vis_refs):
    panels_json = []
    refs = []
    for i, (vis_id, vtitle, x, y, w, h) in enumerate(panels):
        name = f"panel_{i+1}"
        panels_json.append({
            "panelIndex": str(i + 1), "version": "7.10.2",
            "type": "visualization", "title": vtitle,
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i + 1)},
            "panelRefName": name, "embeddableConfig": {"title": vtitle},
        })
        refs.append({"id": vis_id, "type": "visualization", "name": name})
    return {
        "_id": "dashboard:" + id_,
        "_source": {
            "type": "dashboard",
            "dashboard": {
                "title": title, "description": desc,
                "panelsJSON": json.dumps(panels_json),
                "optionsJSON": json.dumps(
                    {"darkTheme": False, "hidePanelTitles": False,
                     "useMargins": True, "syncColors": False}),
                "timeRestore": False,
                "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"},
                     "filter": []})},
            },
            "references": refs + vis_refs,
            "migrationVersion": {"dashboard": "7.9.3"},
            "updated_at": NOW, "version": "WzE=",
        },
    }


# ---------------------------------------------------------------------------
# Visualization primitives
# ---------------------------------------------------------------------------

def agg_metric(label="Count"):
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric",
            "params": {}}


def vis_metric(id_, title, index, filters=None):
    vs = {"type": "metric", "aggs": [agg_metric()], "params": {
        "addTooltip": True, "addLegend": False, "metricStyles": {
            "labelColor": False, "colors": ["#68BC00"]}}}
    return vis(id_, title, index, vs, filters)


def vis_series(id_, title, index, series_type, split_field=None, size=10,
               interval="auto", filters=None, split_mode=None):
    aggs = [agg_metric()]
    if split_field:
        aggs.append({"id": "3", "enabled": True, "type": "terms",
                     "schema": "segment", "params": {
                         "field": split_field, "size": size,
                         "orderBy": "1", "order": "desc"}})
    aggs.append({"id": "2", "enabled": True, "type": "date_histogram",
                 "schema": "segment", "params": {
                     "field": "timestamp", "interval": interval,
                     "timeRange": {"from": "now-24h", "to": "now"},
                     "useNormalizedEsInterval": True,
                     "drop_partials": False, "min_doc_count": 1}})
    params = {
        "type": series_type, "grid": {"categoryLines": False, "valueAxis": ""},
        "categoryAxes": [{
            "id": "ValueAxis-1", "type": "category", "position": "bottom",
            "scale": {"type": "linear"},
            "labels": {"show": True, "truncate": 100},
            "title": {"text": "timestamp"}}],
        "valueAxes": [{
            "id": "ValueAxis-2", "type": "value", "position": "left",
            "scale": {"type": "linear", "mode": "normal",
                      "setYExtents": False, "defaultYExtents": False},
            "labels": {"show": True}, "title": {"text": "Count"}}],
        "seriesParams": [{
            "show": True, "mode": "stacked" if split_field else "normal",
            "type": series_type, "drawLinesBetweenPoints": True,
            "interpolate": "linear", "lineWidth": 2,
            "data": {"id": "1", "label": "Count"},
            "valueAxis": "ValueAxis-2"}],
        "addTooltip": True, "addLegend": bool(split_field),
        "legendPosition": "right", "times": [], "addTimeMarker": False,
        "thresholdLine": {"show": False, "value": 10, "width": 1,
                          "style": "full", "color": "#E7664C"},
        "labels": {}, "orderBysBySum": False,
    }
    vs = {"type": "histogram", "aggs": aggs, "params": params}
    return vis(id_, title, index, vs, filters)


def vis_pie(id_, title, index, field, size=10, filters=None):
    vs = {"type": "pie", "aggs": [
        agg_metric(),
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {"field": field, "size": size, "orderBy": "1",
                    "orderByAgg": {"id": "1", "enabled": True, "type": "count",
                                   "schema": "metric", "params": {}}}}],
        "params": {"type": "pie", "addTooltip": True, "addLegend": True,
                   "legendPosition": "right", "isDonut": True,
                   "labels": {"show": False, "values": True,
                              "last_level": True, "truncate": 100}}}
    return vis(id_, title, index, vs, filters)


def vis_table(id_, title, index, fields, size=10, filters=None,
              metric="count"):
    aggs = [agg_metric()]
    for i, f in enumerate(fields):
        aggs.append({"id": str(i + 2), "enabled": True, "type": "terms",
                     "schema": "bucket", "params": {
                         "field": f, "size": size, "orderBy": "1",
                         "order": "desc"}})
    vs = {"type": "table", "aggs": aggs, "params": {
        "perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
        "showTotal": False, "totalFunc": "sum", "percentageCol": ""}}
    return vis(id_, title, index, vs, filters)


def vis_topline(id_, title, index, field, size=1, filters=None):
    """Top-N as horizontal bar (compact stat bar)."""
    vs = {"type": "horizontal_bar", "aggs": [
        agg_metric(),
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {"field": field, "size": 5, "orderBy": "1", "order": "desc"}}],
        "params": {
            "type": "horizontal_bar",
            "grid": {"categoryLines": False, "valueAxis": ""},
            "categoryAxes": [{
                "id": "ValueAxis-1", "type": "category", "position": "left",
                "scale": {"type": "linear"},
                "labels": {"show": True, "truncate": 64},
                "title": {"text": field}}],
            "valueAxes": [{
                "id": "ValueAxis-2", "type": "value", "position": "bottom",
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True}, "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "mode": "normal", "type": "histogram",
                              "data": {"id": "1", "label": "Count"},
                              "valueAxis": "ValueAxis-2"}],
            "addTooltip": True, "addLegend": False, "legendPosition": "right",
            "times": [], "addTimeMarker": False, "labels": {},
            "thresholdLine": {"show": False}}}
    return vis(id_, title, index, vs, filters)


# ---------------------------------------------------------------------------
# Field helpers
# ---------------------------------------------------------------------------

KW = ".keyword"


def f_alerts(name):
    """Aggregatable field name on wazuh-alerts-* (keyword subfield for text)."""
    return name + KW if name in ("agent.name", "agent.id", "rule.description",
                                 "rule.groups", "data.srcip", "data.dstuser",
                                 "location", "rule.id") else name


# ---------------------------------------------------------------------------
# Dashboard definitions
# ---------------------------------------------------------------------------

def build_objects():
    objs = []

    # ---- 1. SOC Fleet Health (monitoring index) ---------------------------
    o = []
    o.append(vis_metric("vis-fleet-total", "Agents reporting", MON))
    o.append(vis_pie("vis-fleet-status", "Agent status", MON, "status"))
    o.append(vis_series("vis-fleet-status-over-time", "Active agents over time",
                        MON, "area", split_field="status", size=5))
    o.append(vis_table("vis-fleet-table", "Agents (name, status, ip, os, version)",
                       MON, ["name", "status", "ip", "os.name", "version"], size=15))
    o.append(vis_topline("vis-fleet-versions", "Agent versions", MON, "version"))
    objs.extend(o)
    objs.append(dashboard(
        "dash-soc-fleet-health", "SOC · Fleet Health",
        "Wazuh agent fleet: status, versions, keepalive trend. Source: wazuh-monitoring-*.",
        [("vis-fleet-total", "Agents reporting", 0, 0, 4, 4),
         ("vis-fleet-status", "Agent status", 4, 0, 6, 4),
         ("vis-fleet-versions", "Agent versions", 10, 0, 14, 4),
         ("vis-fleet-status-over-time", "Active agents over time", 0, 4, 10, 8),
         ("vis-fleet-table", "Agent inventory", 10, 4, 14, 8)],
        []))

    # ---- 2. Alert Volume by Agent (alerts) ---------------------------------
    o = []
    o.append(vis_metric("vis-vol-total", "Alerts (window)", ALERTS))
    o.append(vis_series("vis-vol-over-time", "Alerts over time (stacked by agent)",
                        ALERTS, "area", split_field=f_alerts("agent.name"), size=10))
    o.append(vis_pie("vis-vol-by-agent", "Alerts by agent", ALERTS,
                     f_alerts("agent.name"), size=10))
    o.append(vis_table("vis-vol-by-agent", "Top agents by count", ALERTS,
                       [f_alerts("agent.name"), f_alerts("agent.id")], size=10))
    o.append(vis_table("vis-vol-by-location", "Top sources (location)",
                       ALERTS, [f_alerts("location")], size=10))
    objs.extend(o)
    objs.append(dashboard(
        "dash-soc-alert-volume", "SOC · Alert Volume by Agent",
        "Alert counts over time, split by agent and source. Source: wazuh-alerts-*.",
        [("vis-vol-over-time", "Alerts over time", 0, 0, 12, 5),
         ("vis-vol-by-agent", "By agent", 12, 0, 6, 5),
         ("vis-vol-total", "Total", 18, 0, 6, 2),
         ("vis-vol-by-location", "Top sources", 18, 2, 6, 3),
         ("vis-vol-by-agent", "Top agents", 0, 5, 24, 5)],
        []))
    # fix: dashboard 2 needs refs for its vis (panels reference them)
    # (refs are built from panels automatically; the extra vis_refs arg stays empty)

    # ---- 3. Critical Alerts (L12+) ----------------------------------------
    o = []
    o.append(vis_metric("vis-crit-count", "Critical (L12+) alerts", ALERTS,
                        filters=lvl12()))
    o.append(vis_series("vis-crit-over-time", "Critical alerts over time",
                        ALERTS, "bar", filters=lvl12()))
    o.append(vis_pie("vis-crit-by-agent", "Critical by agent", ALERTS,
                     f_alerts("agent.name"), size=10, filters=lvl12()))
    o.append(vis_table("vis-crit-table", "Critical alerts detail", ALERTS,
                       [f_alerts("rule.id"), f_alerts("rule.description"),
                        f_alerts("agent.name"), f_alerts("data.srcip"),
                        f_alerts("data.dstuser")], size=15, filters=lvl12()))
    objs.extend(o)
    objs.append(dashboard(
        "dash-soc-critical", "SOC · Critical Alerts (L12+)",
        "Highest-severity alerts (rule.level >= 12) — the ones that page the SOC. Source: wazuh-alerts-*.",
        [("vis-crit-count", "Critical alerts", 0, 0, 4, 4),
         ("vis-crit-over-time", "Over time", 4, 0, 10, 4),
         ("vis-crit-by-agent", "By agent", 14, 0, 10, 4),
         ("vis-crit-table", "Detail", 0, 4, 24, 10)],
        []))

    # ---- 4. Authentication Activity ---------------------------------------
    auth_q = {"meta": {"index": ALERTS}, "query": {
        "bool": {"should": [
            {"match": {"rule.groups": "authentication"}},
            {"match": {"rule.groups": "authentication_failed"}},
            {"match": {"rule.groups": "sshd"}},
        ], "minimum_should_match": 1}}}
    o = []
    o.append(vis_metric("vis-auth-total", "Auth events", ALERTS,
                        filters=[auth_q]))
    o.append(vis_series("vis-auth-over-time", "Auth events over time",
                        ALERTS, "area", filters=[auth_q]))
    o.append(vis_pie("vis-auth-by-user", "By user (dstuser)", ALERTS,
                     f_alerts("data.dstuser"), size=8, filters=[auth_q]))
    o.append(vis_table("vis-auth-by-rule", "Top auth rules", ALERTS,
                       [f_alerts("rule.id"), f_alerts("rule.description"),
                        f_alerts("agent.name")], size=10, filters=[auth_q]))
    objs.extend(o)
    objs.append(dashboard(
        "dash-soc-auth", "SOC · Authentication Activity",
        "Logins, sessions and auth failures across the fleet (rule.groups: authentication/sshd). Source: wazuh-alerts-*.",
        [("vis-auth-total", "Auth events", 0, 0, 4, 4),
         ("vis-auth-over-time", "Over time", 4, 0, 12, 4),
         ("vis-auth-by-user", "By user", 16, 0, 8, 4),
         ("vis-auth-by-rule", "Top auth rules", 0, 4, 24, 10)],
        []))

    # ---- 5. Rule Ranking ---------------------------------------------------
    o = []
    o.append(vis_metric("vis-rules-unique", "Distinct rules firing", ALERTS))
    o.append(vis_table("vis-rules-top", "Top rules (id, description)",
                       ALERTS, [f_alerts("rule.id"),
                                f_alerts("rule.description")], size=15))
    o.append(vis_pie("vis-rules-level", "By severity level", ALERTS,
                     "rule.level", size=16))
    o.append(vis_table("vis-rules-groups", "Top rule groups", ALERTS,
                       [f_alerts("rule.groups")], size=10))
    objs.extend(o)
    objs.append(dashboard(
        "dash-soc-rule-ranking", "SOC · Rule Ranking",
        "Which rules and severities dominate the fleet. Source: wazuh-alerts-*.",
        [("vis-rules-unique", "Distinct rules", 0, 0, 4, 4),
         ("vis-rules-level", "By severity", 4, 0, 8, 4),
         ("vis-rules-groups", "Rule groups", 12, 0, 12, 4),
         ("vis-rules-top", "Top rules", 0, 4, 24, 10)],
        []))

    # ---- 6. Sources & Targets (web/attack traffic) -------------------------
    net_q = {"meta": {"index": ALERTS}, "query": {
        "bool": {"must": [{"exists": {"field": "data.srcip"}}]}}}
    o = []
    o.append(vis_metric("vis-net-total", "Events with srcip", ALERTS,
                        filters=[net_q]))
    o.append(vis_series("vis-net-over-time", "Network events over time",
                        ALERTS, "area", filters=[net_q]))
    o.append(vis_table("vis-net-top-src", "Top source IPs", ALERTS,
                       [f_alerts("data.srcip")], size=10, filters=[net_q]))
    o.append(vis_table("vis-net-by-agent", "By agent + target user", ALERTS,
                       [f_alerts("agent.name"), f_alerts("data.dstuser")],
                       size=10, filters=[net_q]))
    objs.extend(o)
    objs.append(dashboard(
        "dash-soc-sources", "SOC · Sources & Targets",
        "Events carrying a source IP: who is talking to your fleet. Source: wazuh-alerts-*.",
        [("vis-net-total", "Events with srcip", 0, 0, 4, 4),
         ("vis-net-over-time", "Over time", 4, 0, 12, 4),
         ("vis-net-top-src", "Top source IPs", 16, 0, 8, 4),
         ("vis-net-by-agent", "By agent + user", 0, 4, 24, 10)],
        []))

    return objs


def lvl12():
    return [{"meta": {"key": "rule.level", "params": {"gte": 12, "lte": 16},
                      "type": "range", "index": ALERTS},
             "query": {"range": {"rule.level": {"gte": 12, "lte": 16}}}}]


# ---------------------------------------------------------------------------
# Output + import
# ---------------------------------------------------------------------------

def to_ui_format(o):
    """Saved-object import format (Dashboards UI: Management -> Saved
    Objects -> Import, and the _import API)."""
    src = o["_source"]
    t = src["type"]
    short_id = o["_id"].split(":", 1)[1]
    attrs = dict(src[t])
    return json.dumps({
        "type": t, "id": short_id, "attributes": attrs,
        "references": src.get("references", []),
        "migrationVersion": src.get("migrationVersion", {}),
    })


def to_ndjson(objs):
    """One JSON object per line (UI import format)."""
    return "\n".join(to_ui_format(o) for o in objs) + "\n"


def import_objects(objs):
    import base64
    env = {}
    for line in open("/home/wez/.openclaw/soc/secrets/wazuh-indexer.env"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            env[k] = v.strip().strip('"')
    tok = "Basic " + base64.b64encode(
        ("admin:" + env["WAZUH_INDEXER_PASSWORD"]).encode()).decode()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ok = fail = 0
    for o in objs:
        body = {k: v for k, v in o["_source"].items() if k != "version"}
        r = urllib.request.Request(
            "https://127.0.0.1:9200/.kibana/_doc/" + o["_id"],
            method="PUT",
            headers={"Content-Type": "application/json", "Authorization": tok},
            data=json.dumps(body).encode())
        try:
            with urllib.request.urlopen(r, context=ctx, timeout=20) as resp:
                resp.read()
            ok += 1
        except Exception as e:
            fail += 1
            print(f"  FAIL {o['_id']}: {type(e).__name__} {str(e)[:80]}")
    return ok, fail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--import", dest="do_import", action="store_true")
    ap.add_argument("--ndjson-only", action="store_true")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    objs = build_objects()
    vis_n = sum(1 for o in objs if o["_source"]["type"] == "visualization")
    dash_n = sum(1 for o in objs if o["_source"]["type"] == "dashboard")
    print(f"built {len(objs)} objects: {vis_n} visualizations, {dash_n} dashboards")

    ndjson = to_ndjson(objs)
    out = Path(args.out or (Path(__file__).resolve().parent
                            / "wazuh-dashboards.ndjson"))
    out.write_text(ndjson)
    print(f"ndjson written: {out}")

    if args.do_import:
        ok, fail = import_objects(objs)
        print(f"imported: {ok} ok, {fail} failed")


if __name__ == "__main__":
    main()