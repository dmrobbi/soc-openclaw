// SOC dashboard — vanilla JS client-side router.
// Calls /tools/<name> on this same server, which proxies to
// the C4 / C3 MCPs.
(function() {
  "use strict";

  const root = document.getElementById("root");
  const status = document.getElementById("status");

  // ---- helpers --------------------------------------------------------
  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    if (attrs) {
      for (const k in attrs) {
        if (k === "class") e.className = attrs[k];
        else if (k === "html") e.innerHTML = attrs[k];
        else if (k.startsWith("on") && typeof attrs[k] === "function") {
          e.addEventListener(k.substring(2), attrs[k]);
        } else if (attrs[k] !== undefined && attrs[k] !== null) {
          e.setAttribute(k, attrs[k]);
        }
      }
    }
    for (const c of children) {
      if (c == null) continue;
      if (Array.isArray(c)) c.forEach(cc => cc != null && e.appendChild(
        typeof cc === "string" ? document.createTextNode(cc) : cc));
      else e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return e;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function esc(s) {
    if (s == null) return "";
    return String(s).replace(/[<>&"']/g, c => (
      {"<":"&lt;",">":"&gt;","&":"&amp;",'"':"&quot;","'":"&#39;"}[c]));
  }
  function badge(kind) {
    const cls = (kind === "ok" || kind === "low" || kind === "active" || kind === "closed")
      ? "good"
      : (kind === "warn" || kind === "medium" || kind === "in_progress" || kind === "waiting")
      ? "warn"
      : (kind === "bad" || kind === "error" || kind === "high" || kind === "critical" || kind === "disconnected")
      ? "bad"
      : "dim";
    return el("span", { class: "badge " + cls }, String(kind || "?"));
  }
  async function api(path, method, body) {
    const opts = { method: method || "GET" };
    if (body) {
      opts.headers = { "Content-Type": "application/json" };
      opts.body = JSON.stringify(body);
    }
    const r = await fetch(path, opts);
    const ct = r.headers.get("content-type") || "";
    const data = ct.includes("json") ? await r.json() : await r.text();
    if (!r.ok) throw new Error(`${r.status}: ${typeof data === "string" ? data : JSON.stringify(data)}`);
    return data;
  }
  function fmtTime(s) {
    if (!s) return "-";
    return s.substring(0, 19).replace("T", " ");
  }
  function shortId(s, n) {
    if (!s) return "-";
    n = n || 8;
    return s.length > n ? s.substring(0, n) + "…" : s;
  }

  // ---- pages ----------------------------------------------------------
  async function pageFleet() {
    // Fleet status (D2 fleet_status tool). Pulls the Wazuh-side
    // state from C2 manager-mcp and renders one row per agent.
    // The page polls every 30s; staleness_seconds is the delta
    // between now and the agent's last keepalive.
    let data;
    try { data = await api("/tools/fleet_status", "POST", {}); }
    catch (e) { return errorView(e); }
    // STIG findings per host (single C4 call; feeds the STIG column).
    // Non-fatal: the fleet page renders without counts if C4 hiccups.
    let stigByHost = {};
    try {
      const sq = await api("/tools/query_stig_findings", "POST",
                           { time_range: "30d", limit: 1 });
      stigByHost = (sq && sq.by_host) || {};
    } catch (e) { /* ignore */ }
    const s = data.summary || {};
    const rows = data.agents || [];
    const nodes = [
      el("h1", null, "Fleet status"),
      el("p", { class: "muted" },
        "One row per Wazuh agent. ",
        "Healthy = active AND last_keepalive within 5 min. ",
        "Stale = active but keepalive older than 5 min. ",
        "Down = disconnected / never_connected. ",
        "Manager self (id=000) uses a sentinel date and is rendered as ",
        el("em", null, "(manager self)"),
        "."),
      el("div", { class: "cards" },
        card("Total", s.total || 0, ""),
        card("Healthy", s.active || 0, "good"),
        card("Stale", s.stale || 0, s.stale ? "warn" : "good"),
        card("Down", s.down || 0, s.down ? "bad" : "good"),
        card("Clock skew", s.clock_skew || 0, s.clock_skew ? "warn" : "good"),
        card("Unknown status", s.unknown_status || 0, "dim"),
      ),
      el("div", { class: "section" },
        fleetTable(rows, stigByHost),
      ),
      el("p", { class: "muted" },
        "Source: C2 manager-mcp (",
        el("code", null, data.manager_url || "?"),
        "). Fetched at ",
        el("code", null, (data.fetched_at || "?").substring(0, 19).replace("T", " ")),
        ". Auto-refreshes every 30s."),
    ];
    return nodes;
  }

  function fleetTable(rows, stigByHost) {
    stigByHost = stigByHost || {};
    if (!rows.length) {
      return el("p", { class: "empty" },
        "No agents returned by C2 manager-mcp. ",
        "Is the Wazuh manager running?");
    }
    // Stable order: healthy first, then stale, down, manager-self, unknown
    const order = { healthy: 0, stale: 1, down: 2, manager_self: 3, unknown: 4 };
    function rank(r) {
      if (r.status === "disconnected" || r.status === "never_connected") return order.down;
      if (r.staleness_seconds !== null && r.staleness_seconds !== undefined &&
          r.staleness_seconds > 300) return order.stale;
      if (r.last_keepalive && r.last_keepalive.startsWith("9999")) return order.manager_self;
      if (r.status === "active") return order.healthy;
      return order.unknown;
    }
    const sorted = rows.slice().sort((a, b) => {
      const ra = rank(a), rb = rank(b);
      if (ra !== rb) return ra - rb;
      return (a.name || "").localeCompare(b.name || "");
    });
    return el("table", null,
      el("thead", null, el("tr", null,
        el("th", null, ""),
        el("th", null, "id"),
        el("th", null, "name"),
        el("th", null, "status"),
        el("th", null, "ip"),
        el("th", null, "version"),
        el("th", null, "os"),
        el("th", null, "keepalive"),
        el("th", null, "staleness"),
        el("th", null, "STIG (30d)"),
        el("th", null, "logs"),
      )),
      el("tbody", null, ...sorted.map(r => {
        const isMgr = r.last_keepalive && r.last_keepalive.startsWith("9999");
        const isStale = r.staleness_seconds !== null && r.staleness_seconds > 300;
        const isDown = r.status === "disconnected" || r.status === "never_connected";
        const icon = isMgr ? "•" : (r.healthy ? "✓" : (isStale || isDown ? "✗" : "?"));
        const iconCls = isMgr ? "dim" : (r.healthy ? "good" : (isStale ? "warn" : "bad"));
        const statusKind = r.status === "active" ? "good" :
          (r.status === "disconnected" || r.status === "never_connected") ? "bad" : "dim";
        const staleness = isMgr ? "(manager self)" :
          (r.staleness_seconds === null || r.staleness_seconds === undefined ? "?" :
            r.staleness_seconds + "s");
        return el("tr", isMgr ? { class: "muted" } : null,
          el("td", null, badge(icon + " " + iconCls)),
          el("td", null, el("code", null, r.id || "-")),
          el("td", null, el("a", {
            href: "/fleet/" + encodeURIComponent(r.id || r.name),
            "data-link": "",
            style: "font-weight:600;text-decoration:underline;cursor:pointer",
          }, r.name || "-")),
          el("td", null, badge(r.status || "?" + " " + statusKind)),
          el("td", null, el("code", null, r.ip || "-")),
          el("td", null, el("code", null, r.version || "-")),
          el("td", null, r.os || "-"),
          el("td", null, fmtTime(r.last_keepalive)),
          el("td", null, staleness),
          el("td", null, el("a", {
            href: "/stig/host/" + encodeURIComponent(r.name || r.id),
            "data-link": "",
            title: "STIG findings for " + (r.name || r.id) + " (30d)",
          }, el("span", { class: "badge " + ((stigByHost[r.name] || 0) > 0 ? "warn" : "dim") },
             String(stigByHost[r.name] || 0)))),
          el("td", null, isMgr ? el("span", { class: "muted" }, "-") : el("a", {
            href: "/logs/" + encodeURIComponent(r.name || r.id),
            "data-link": "",
            title: "Recent Wazuh alerts for " + (r.name || r.id),
          }, "Logs")),
        );
      })),
    );
  }

  // Wazuh dashboard deep link: discover filtered to one agent.
  // The dashboard container publishes https on :5601 (LAN).
  const WZ_DASH = "https://192.168.1.106:5601";
  function wzDiscoverUrl(agent) {
    const state = "(filters:!((query:(match:(('agent.name.keyword':'" +
      agent + "'))))))";
    return WZ_DASH + "/app/discover#/?_a=" + encodeURIComponent(state);
  }
  let agentLogsHours = 24;
  async function pageAgentLogs(name) {
    let data;
    try {
      data = await api("/tools/agent_logs", "POST",
                       { agent: name, hours: agentLogsHours, size: 200 });
    } catch (e) { return errorView(e); }
    if (!data.ok) return errorView(new Error(data.error || "agent_logs failed"));
    const hits = data.hits || [];
    const sel = el("select", {
      onchange: (ev) => { agentLogsHours = Number(ev.target.value); render(); },
    }, ...[["6", "Last 6 hours"], ["24", "Last 24 hours"],
           ["72", "Last 3 days"], ["168", "Last 7 days"]].map(([v, label]) =>
      el("option", { value: v,
                     ...(String(agentLogsHours) === v ? { selected: "selected" } : {}) },
         label)));
    const lvBadge = (lv) => badge(String(lv ?? "?") + " " +
      ((lv ?? 0) >= 10 ? "bad" : (lv ?? 0) >= 7 ? "warn" : "dim"));
    return [
      el("h1", null, "Logs: " + name),
      el("div", { class: "btn-row" },
        sel,
        el("button", { class: "btn", onclick: () => render() }, "Refresh"),
        el("a", { class: "btn", target: "_blank", rel: "noopener",
                  href: wzDiscoverUrl(name) }, "Open in Wazuh \u2197"),
        el("a", { class: "btn", href: "/fleet", "data-link": "" }, "\u2190 Fleet"),
      ),
      el("p", { class: "muted" },
        el("code", null, String(hits.length)),
        " alert(s) in the selected window, newest first. Source: C1 ",
        el("code", null, "search_alerts"), " (wazuh-alerts-*)."),
      hits.length ? el("table", null,
        el("thead", null, el("tr", null,
          el("th", null, "time"), el("th", null, "level"), el("th", null, "rule"),
          el("th", null, "description"), el("th", null, "src ip"),
          el("th", null, "dst user"))),
        el("tbody", null, ...hits.map(h => el("tr", null,
          el("td", null, fmtTime(h.timestamp)),
          el("td", null, lvBadge(h.level)),
          el("td", null, el("code", null, String(h.rule_id || "-"))),
          el("td", null, h.rule_desc || "-"),
          el("td", null, el("code", null, h.srcip || "-")),
          el("td", null, el("code", null, h.dstuser || "-")),
        )))) : el("p", { class: "empty" }, "No alerts in this window."),
    ];
  }

  async function pageFleetHost(agentId) {
    let data;
    try { data = await api("/tools/fleet_host_view", "POST", { agent_id: agentId }); }
    catch (e) { return errorView(e); }
    if (!data.ok) return errorView(new Error(data.error || "fleet_host_view failed"));
    const a = data.agent || {};
    const alerts = data.alerts || [];
    const stig = data.stig || {};
    const nodes = [
      el("h1", null, "Host: " + (a.name || agentId)),
      el("div", { class: "btn-row" },
        el("a", { class: "btn", href: "/logs/" + encodeURIComponent(a.name || agentId),
                  "data-link": "", title: "Recent Wazuh alerts for " + (a.name || agentId) }, "Logs"),
        el("a", { class: "btn", target: "_blank", rel: "noopener",
                  href: wzDiscoverUrl(a.name || agentId) }, "Open in Wazuh \u2197"),
      ),
      el("div", { class: "cards" },
        card("Status", a.status || "?", a.status === "active" ? "good" : "bad"),
        card("IP", a.ip || "-", ""),
        card("Version", a.version || "-", ""),
        card("Group", (a.group || []).join(", ") || "-", ""),
        card("Last keepalive", fmtTime(a.last_keepalive) || "-", ""),
        card("STIG findings (30d)", stig.total ?? 0,
             (stig.total ?? 0) > 0 ? "warn" : "dim"),
      ),
      el("div", { class: "section" },
        el("h2", null, "Scan control"),
        el("p", { class: "muted" },
          "Runs the Wazuh agent-restart active response on this host: the agent reconnects within ~30 s and immediately starts a fresh syscheck/FIM integrity scan; the vulnerability detector re-runs."),
        el("div", { class: "btn-row" },
          el("button", {
            class: "btn",
            onclick: async (ev) => {
              ev.preventDefault();
              if (!confirm("Trigger scan on " + (a.name || agentId) + "? (agent restart)")) return;
              ev.target.disabled = true;
              ev.target.textContent = "triggering…";
              try {
                const r = await api("/tools/run_scan", "POST", { agent_id: agentId });
                ev.target.textContent = r.ok ? "scan triggered ✓" : "failed: " + (r.error || "?");
              } catch (e) {
                ev.target.textContent = "failed: " + (e.message || e);
              }
              setTimeout(() => { ev.target.disabled = false; ev.target.textContent = "Run scan now"; }, 8000);
            },
          }, "Run scan now"),
          el("button", {
            class: "btn",
            onclick: async (ev) => {
              ev.preventDefault();
              if (!confirm("Re-run compliance scan on " + (a.name || agentId) + "? (agent restart + evidence + score recompute)")) return;
              ev.target.disabled = true;
              ev.target.textContent = "running compliance scan…";
              try {
                const r = await api("/tools/run_host_compliance_scan", "POST", { agent_id: agentId });
                if (r.ok) {
                  const t = (r.tenants_scanned || []).join(", ") || "?";
                  ev.target.textContent = "done ✓ (evidence: " + t + ")";
                } else {
                  ev.target.textContent = "failed: " + (r.error || "?");
                }
              } catch (e) {
                ev.target.textContent = "failed: " + (e.message || e);
              }
              setTimeout(() => { ev.target.disabled = false; ev.target.textContent = "Re-run compliance scan"; }, 8000);
            },
          }, "Re-run compliance scan"),
          el("a", { class: "btn", href: "/stig/host/" + encodeURIComponent(a.name || agentId),
                   "data-link": "", title: "STIG findings for this host (30d)" },
            "View STIG findings"),
        ),
        data.mutations_enabled
          ? null
          : el("p", { class: "muted" }, "Note: manager mutations are DISABLED (SOC_MANAGER_MCP_ALLOW_MUTATIONS=1 not set) — the scan buttons will fail until enabled."),
      ),
      el("div", { class: "section" },
        el("h2", null, "Recent alerts" + (alerts.length ? " (" + alerts.length + ")" : " (none)")),
        alerts.length
          ? el("table", null,
              el("thead", null, el("tr", null,
                el("th", null, "ts"), el("th", null, "level"), el("th", null, "rule"),
                el("th", null, "severity"), el("th", null, "triage"))),
              el("tbody", null, ...alerts.slice(0, 15).map(al =>
                el("tr", null,
                  el("td", null, el("code", null, (al.ts || "").substring(0, 19).replace("T", " "))),
                  el("td", null, badge(String(al.level ?? "?"))),
                  el("td", null, el("code", null, String(al.rule_id || "-"))),
                  el("td", null, al.severity ? badge(al.severity) : "-"),
                  el("td", null, String(al.triage || "").substring(0, 120))))),
            )
          : el("p", { class: "empty" }, "No alerts recorded for this host yet."),
      ),
      el("div", { class: "section" },
        el("h2", null, "STIG findings (last 30d)"),
        stig.ok
          ? el("div", null,
              el("p", null,
                el("strong", null, String(stig.total ?? 0) + " findings"),
                " across " + (stig.unique_controls ?? 0) + " controls" +
                (() => { const bs = Object.entries(stig.by_severity || {})
                    .filter(([, n]) => n > 0)
                    .map(([k, n]) => n + " " + k);
                  return bs.length ? " — " + bs.join(", ") : ""; })()),
              stig.total > 0
                ? el("a", { class: "btn", href: "/stig/host/" + encodeURIComponent(a.name || agentId),
                           "data-link": "" }, "View STIG findings →")
                : el("p", { class: "muted" },
                    "No STIG-relevant alerts matched the catalogue rules for this host in the window. ",
                    "Findings appear when a L12+ alert maps to a ",
                    el("code", null, "config/stig-rules/"), " entry."),
            )
          : el("p", { class: "empty" }, "No STIG data for this host."),
      ),
      el("p", { class: "muted" },
        el("a", { href: "/fleet", "data-link": "" }, "← back to fleet")),
    ];
    return nodes;
  }

  async function pageOverview() {
    let data;
    try { data = await api("/tools/overview", "POST", {}); }
    catch (e) { return errorView(e); }
    let stig = null;
    try { stig = await api("/tools/stig_overview", "POST", { time_range: "24h" }); }
    catch (e) { stig = { ok: false, error: String(e.message || e), total: 0 }; }
    const stats = data.audit_24h || {};
    const tenants = stats.by_agent || {};
    const byKind = stats.by_input_kind || {};
    const byOut = stats.by_outcome || {};
    const bySev = (stig && stig.by_severity) || {};
    const byFam = (stig && stig.by_nist_family) || {};
    const stigTotal = (stig && stig.total) || 0;

    const nodes = [];
    nodes.push(el("h1", null, "Overview — last 24h"));
    nodes.push(el("div", { class: "cards" },
      card("Total", stats.total || 0, ""),
      card("OK", byOut.ok || 0, "ok"),
      card("Errors", byOut.error || 0, "bad"),
      card("Tickets", data.ticket_total || 0, "info"),
    ));
    nodes.push(el("div", { class: "section" },
      el("h2", null,
        "STIG findings ",
        el("a", { href: "/stig", "data-link": "", class: "muted" }, "(full report \u2192"), ")"),
      stigTotal === 0
        ? el("p", { class: "empty" },
            "No STIG findings in the last 24h. ",
            "The classifier attaches stig_id to L12+ alerts that hit a Wazuh rule in ",
            el("code", null, "config/stig-rules/"),
            " (currently 13 mapped rules across RHEL 9 + Ubuntu 22.04 catalogues).")
        : el("div", null,
            el("div", { class: "cards" },
              card("Findings", stigTotal, stigTotal > 0 ? "info" : ""),
              card("Unique stig_ids", stig.unique_stig_ids || 0, ""),
              card("Unique controls", stig.unique_controls || 0, ""),
              card("Hosts",
                   (stig.unique_hosts || 0) + " of " +
                   ((stig.monitored_hosts || []).length || 0),
                   "info"),
            ),
            el("div", { class: "row" },
              el("div", { class: "col section" },
                el("h3", null, "By severity"),
                agentTable(bySev),
              ),
              el("div", { class: "col section" },
                el("h3", null, "By NIST family"),
                agentTable(byFam),
              ),
            ),
          ),
    ));
    nodes.push(el("div", { class: "row" },
      el("div", { class: "col section" },
        el("h2", null, "By agent"),
        agentTable(stats.by_agent || {}),
      ),
      el("div", { class: "col section" },
        el("h2", null, "By input kind"),
        agentTable(stats.by_input_kind || {}),
      ),
      el("div", { class: "col section" },
        el("h2", null, "By outcome"),
        agentTable(stats.by_outcome || {}),
      ),
    ));
    nodes.push(el("div", { class: "section" },
      el("h2", null, "Recent tickets"),
      ticketsList(data.tickets_recent || []),
    ));
    nodes.push(el("p", { class: "muted" },
      "Drill into a run via the C4 audit MCP. ",
      el("a", { href: "/healthz" }, "Check backend health"), "."));
    return nodes;
  }

  async function pageTenants() {
    let tenants = {};
    try {
      const r = await api("/tenants.json", "GET");
      tenants = r.tenants || {};
    } catch (e) { return errorView(e); }
    if (!Object.keys(tenants).length) {
      return [
        el("h1", null, "Tenants"),
        el("p", { class: "muted" },
          "No tenants loaded. Install ",
          el("code", null, "config/soc-routing.yaml"),
          " (or the ",
          el("code", null, ".example"),
          ") and restart."),
      ];
    }
    const nodes = [el("h1", null, "Tenants")];
    const cards = el("div", { class: "cards" });
    for (const tid in tenants) {
      cards.appendChild(el("a", { class: "card", href: "/tenants/" + tid, "data-link": "" },
        el("div", { class: "label" }, tid),
        el("div", { class: "value" }, shortId(tenants[tid], 20)),
        el("div", { class: "sub" }, "View →"),
      ));
    }
    nodes.push(cards);
    return nodes;
  }

  async function pageTenant(tenantId) {
    let data;
    try { data = await api("/tools/tenant_view", "POST", { tenant_id: tenantId }); }
    catch (e) { return errorView(e); }
    const nodes = [
      el("h1", null, "Tenant: ", el("code", null, tenantId)),
      el("div", { class: "section" },
        el("h2", null, "Last 24h activity"),
        el("p", null, "Total audit records: ",
          el("strong", null, String(data.audit_total || 0))),
        auditTable(data.audit_24h || []),
      ),
      el("div", { class: "section" },
        el("h2", null, "Recent tickets"),
        ticketsList(data.tickets_recent || []),
      ),
    ];
    return nodes;
  }

  async function pageAgents() {
    // We don't have a "list agents" tool on the dashboard;
    // the source of truth is the C4 audit log. Pull a wide
    // query and aggregate.
    let data;
    try {
      data = await api("/tools/audit_stats_proxy", "POST",
                       { time_range: "24h" });
    } catch (e) { return errorView(e); }
    const byAgent = (data && data.by_agent) || {};
    const nodes = [el("h1", null, "Agents — last 24h")];
    const cards = el("div", { class: "cards" });
    for (const a in byAgent) {
      cards.appendChild(el("a", { class: "card", href: "/agents/" + encodeURIComponent(a), "data-link": "" },
        el("div", { class: "label" }, a),
        el("div", { class: "value" }, String(byAgent[a])),
        el("div", { class: "sub" }, "View →"),
      ));
    }
    nodes.push(cards);
    return nodes;
  }

  async function pageAgent(agentId) {
    let data;
    try { data = await api("/tools/agent_view", "POST",
                           { agent_id: agentId }); }
    catch (e) { return errorView(e); }
    const errRate = data.audit_total > 0
      ? ((data.error_count / data.audit_total) * 100).toFixed(1) + "%"
      : "-";
    return [
      el("h1", null, "Agent: ", el("code", null, agentId)),
      el("div", { class: "cards" },
        card("Total 24h", data.audit_total || 0, ""),
        card("Errors", data.error_count || 0,
             data.error_count > 0 ? "bad" : "good"),
        card("Error rate", errRate, ""),
      ),
      el("div", { class: "section" },
        el("h2", null, "Recent activity"),
        auditTable(data.audit_24h || []),
      ),
    ];
  }

  async function pageRun(runId) {
    let data;
    try { data = await api("/tools/run_view", "POST",
                           { run_id: runId }); }
    catch (e) { return errorView(e); }
    if (!data.ok) {
      return [el("h1", null, "Run: ", el("code", null, runId)),
              el("p", { class: "alert bad" },
                 "Not found in the C4 audit log: ", data.error || "?")];
    }
    // 2026-08-14: also fetch tickets linked to this run via
    // source_run_id. Independent call so a tickets-MCP failure
    // doesn't blank the page — we still show the audit rows.
    let tickets = [];
    let ticketsErr = null;
    try {
      const t = await api("/tools/tickets_list_proxy", "POST",
                          { source_run_id: runId, limit: 100 });
      if (t && t.ok) tickets = t.tickets || [];
      else ticketsErr = (t && t.error) || "tickets list returned !ok";
    } catch (e) { ticketsErr = e.message || String(e); }
    const nodes = [
      el("h1", null, "Run: ", el("code", null, runId)),
      el("p", { class: "muted" },
        data.total + " record" + (data.total === 1 ? "" : "s"),
        " — sorted by ts ASC"),
    ];
    // Tickets section first (operationally the most actionable).
    if (tickets.length) {
      nodes.push(el("div", { class: "section" },
        el("h2", null, "Tickets (", String(tickets.length), ")"),
        ticketsList(tickets),
      ));
    } else if (!ticketsErr) {
      nodes.push(el("div", { class: "section" },
        el("h2", null, "Tickets"),
        el("p", { class: "muted" }, "No tickets linked to this run."),
      ));
    } else {
      // tickets-MCP down: don't blank the page, just announce.
      nodes.push(el("div", { class: "section" },
        el("h2", null, "Tickets"),
        el("p", { class: "alert bad" },
          "Tickets MCP unavailable: ", ticketsErr),
      ));
    }
    // Then the audit-log records.
    nodes.push(el("h2", null, "Audit log"));
    for (const r of (data.records || [])) {
      nodes.push(el("div", { class: "section" },
        el("h3", null, r.agent_id + " · " + r.input_kind),
        el("div", { class: "kv" },
          el("div", { class: "k" }, "ts"), el("div", null, fmtTime(r.ts)),
          el("div", { class: "k" }, "tenant"), el("div", null, r.tenant_id || "-"),
          el("div", { class: "k" }, "input"), el("div", null, r.input_summary || "-"),
          el("div", { class: "k" }, "model"), el("div", null, r.model || "-"),
          el("div", { class: "k" }, "duration"), el("div", null, (r.duration_ms || 0) + " ms"),
          el("div", { class: "k" }, "outcome"), el("div", null, badge(r.outcome || "?")),
        ),
        r.model_output ? el("details", null,
          el("summary", null, "model_output"),
          el("pre", null, esc(r.model_output)),
        ) : null,
        r.tool_calls && r.tool_calls.length ? el("details", null,
          el("summary", null, "tool_calls (" + r.tool_calls.length + ")"),
          el("pre", null, esc(JSON.stringify(r.tool_calls, null, 2))),
        ) : null,
        r.error ? el("p", { class: "alert bad" },
          "error: ", el("code", null, r.error)) : null,
        r.extra && r.extra.annotations && r.extra.annotations.length
          ? el("div", null,
              el("h3", null, "Annotations (" + r.extra.annotations.length + ")"),
              el("ul", { class: "list" },
                ...r.extra.annotations.map(a => el("li", null,
                  el("strong", null, a.author + ": "), a.note,
                  el("span", { class: "muted" }, " (" + fmtTime(a.ts) + ")")))))
          : null,
      ));
    }
    return nodes;
  }

  async function pageScores() {
    // E6 — compliance scores across all tenants.
    let data;
    try { data = await api("/tools/compliance_scores_all", "POST", {}); }
    catch (e) { return errorView(e); }
    if (!data.ok) {
      return [el("h1", null, "Compliance scores"),
              el("p", { class: "alert bad" }, data.error || "score compute failed")];
    }
    const scores = data.tenants || [];
    const day = data.day || "?";
    const fleetScore = data.fleet_score || 0;
    const fleetTotal = data.fleet_total || 0;
    const fleetPass = data.fleet_pass || 0;
    const nodes = [
      el("h1", null, "Compliance scores — ", el("code", null, day)),
      el("p", { class: "muted" },
        "Continuous scoring (E6). Source: ",
        el("code", null, "soc_score.tool_score_all_tenants"),
        ". Tenant list derived from ",
        el("code", null, "config/soc-routing.yaml"),
        " + the evidence directory."),
    ];
    if (!scores.length) {
      nodes.push(el("p", { class: "empty" },
        "No tenant score data yet. Run the E6 pipeline (e.g. via ",
        el("code", null, "python3 scripts/soc/soc_score.py"),
        ", or via the soc-curator cron at 04:00 UTC) to populate evidence + snapshots."));
      return nodes;
    }
    // Fleet-wide summary cards
    let totalPass = 0, totalFail = 0, totalMr = 0;
    for (const s of scores) {
      totalPass += s.pass || 0;
      totalFail += s.fail || 0;
      totalMr += s.manual_review || 0;
    }
    nodes.push(el("div", { class: "cards" },
      card("Tenants", scores.length, "info"),
      card("Controls", fleetTotal, ""),
      card("Pass", totalPass, "good"),
      card("Fail", totalFail, totalFail ? "bad" : "good"),
      card("Manual review", totalMr, "warn"),
      card("Fleet score", fleetScore.toFixed(1) + "%", "info"),
    ));
    // Per-tenant cards
    const grid = el("div", { class: "cards" });
    for (const s of scores) {
      const score = s.score || 0;
      const cls = score >= 80 ? "good" : score >= 50 ? "warn" : "bad";
      grid.appendChild(el("a", { class: "card", href: "/scores/" + encodeURIComponent(s.tenant_id), "data-link": "" },
        el("div", { class: "label" }, s.tenant_id),
        el("div", { class: "value" }, score.toFixed(1) + "%"),
        el("div", { class: "sub" },
          s.pass + " pass · " + s.fail + " fail · " +
          s.manual_review + " manual"),
        scoreBar(score),
      ));
    }
    nodes.push(grid);
    return nodes;
  }

  async function pageScore(tenantId) {
    let data;
    try { data = await api("/tools/compliance_score", "POST",
                           { tenant_id: tenantId }); }
    catch (e) { return errorView(e); }
    if (!data.ok) {
      return [el("h1", null, "Score: ", el("code", null, tenantId)),
              el("p", { class: "alert bad" }, data.error || "score compute failed")];
    }
    const c = data.current || {};
    const score = c.score || 0;
    const cls = score >= 80 ? "good" : score >= 50 ? "warn" : "bad";
    const nodes = [
      el("h1", null, "Score: ", el("code", null, tenantId)),
      el("div", { class: "cards" },
        card("Score", score.toFixed(1) + "%", cls),
        card("Day", c.day || "?", "info"),
        card("Pass", c.pass || 0, "good"),
        card("Fail", c.fail || 0, c.fail ? "bad" : "good"),
        card("Manual review", c.manual_review || 0, "warn"),
        card("Total", c.total || 0, ""),
      ),
      el("div", { class: "section" },
        el("h2", null, "Trend (last 7 days)"),
        scoreTrend(data.trend || []),
      ),
    ];
    if (data.by_family && Object.keys(data.by_family).length) {
      nodes.push(el("div", { class: "section" },
        el("h2", null, "By family"),
        scoreByFamily(data.by_family),
      ));
    }
    if (data.by_baseline && Object.keys(data.by_baseline).length) {
      nodes.push(el("div", { class: "section" },
        el("h2", null, "By baseline"),
        scoreBreakdown(data.by_baseline),
      ));
    }
    if (data.by_severity && Object.keys(data.by_severity).length) {
      nodes.push(el("div", { class: "section" },
        el("h2", null, "By severity"),
        scoreBreakdown(data.by_severity),
      ));
    }
    return nodes;
  }

  // ---- score visualizations --------------------------------------
  function scoreBar(score) {
    // 0..100; returns a small inline progress bar under the card value.
    const w = Math.max(0, Math.min(100, score));
    const cls = w >= 80 ? "good" : w >= 50 ? "warn" : "bad";
    return el("div", { class: "score-bar" },
      el("div", { class: "score-fill " + cls, style: "width:" + w + "%" })
    );
  }

  function scoreTrend(points) {
    if (!points.length) {
      return el("p", { class: "empty" }, "No trend data yet.");
    }
    const rows = points.map(p => {
      const score = p.score || 0;
      const cls = score >= 80 ? "good" : score >= 50 ? "warn" : "bad";
      return el("tr", null,
        el("td", null, p.day || "?"),
        el("td", null, score.toFixed(1) + "%"),
        el("td", null, scoreBar(score)),
        el("td", { class: "muted" },
          (p.pass || 0) + " pass · " + (p.fail || 0) + " fail · " +
          (p.manual_review || 0) + " manual"),
      );
    });
    return el("table", null,
      el("thead", null, el("tr", null,
        el("th", null, "Day"),
        el("th", null, "Score"),
        el("th", null, ""),
        el("th", null, "Breakdown"),
      )),
      el("tbody", null, ...rows),
    );
  }

  function scoreByFamily(byFamily) {
    const rows = [];
    for (const fam in byFamily) {
      const stats = byFamily[fam] || {};
      const pass = stats.pass || 0;
      const fail = stats.fail || 0;
      const mr = stats.manual_review || 0;
      const total = pass + fail + mr;
      const score = total ? (pass / total * 100) : 0;
      const cls = score >= 80 ? "good" : score >= 50 ? "warn" : "bad";
      rows.push(el("tr", null,
        el("td", null, el("code", null, fam)),
        el("td", null, score.toFixed(1) + "%"),
        el("td", null, scoreBar(score)),
        el("td", { class: "muted" },
          pass + " pass · " + fail + " fail · " + mr + " manual"),
      ));
    }
    rows.sort((a, b) => a.firstChild.textContent.localeCompare(b.firstChild.textContent));
    return el("table", null,
      el("thead", null, el("tr", null,
        el("th", null, "Family"),
        el("th", null, "Score"),
        el("th", null, ""),
        el("th", null, "Breakdown"),
      )),
      el("tbody", null, ...rows),
    );
  }

  function scoreBreakdown(byKey) {
    const rows = [];
    for (const k in byKey) {
      const stats = byKey[k] || {};
      const pass = stats.pass || 0;
      const fail = stats.fail || 0;
      const mr = stats.manual_review || 0;
      rows.push(el("tr", null,
        el("td", null, el("code", null, k)),
        el("td", { class: "good" }, pass),
        el("td", { class: fail ? "bad" : "muted" }, fail),
        el("td", { class: mr ? "warn" : "muted" }, mr),
      ));
    }
    return el("table", null,
      el("thead", null, el("tr", null,
        el("th", null, "Key"),
        el("th", null, "Pass"),
        el("th", null, "Fail"),
        el("th", null, "Manual review"),
      )),
      el("tbody", null, ...rows),
    );
  }

  async function pageTickets() {
    let data;
    try { data = await api("/tools/tickets_list_proxy", "POST",
                           { limit: 100 }); }
    catch (e) { return errorView(e); }
    return [
      el("h1", null, "Tickets"),
      el("div", { class: "section" },
        el("h2", null, "Total: " + (data.total || 0)),
        ticketsList(data.tickets || []),
      ),
    ];
  }

  async function pageStig() {
    let data;
    try { data = await api("/tools/stig_findings", "POST",
                           { time_range: "7d", limit: 200 }); }
    catch (e) { return errorView(e); }
    if (!data || !data.ok) {
      return [el("h1", null, "STIG findings"),
              el("p", { class: "alert bad" },
                 "C4 audit-mcp error: ",
                 (data && data.error) || (data && data.message) || "unknown")];
    }
    const findings = data.findings || [];
    const bySev = data.by_severity || {};
    const byFam = data.by_nist_family || {};
    const byStig = data.by_stig_id || {};
    const byCtrl = data.by_control_id || {};
    const byHost = data.by_host || {};
    const byTenant = data.by_tenant || {};
    const tr = data.time_range;
    const timeLabel = tr
      ? fmtTime(tr.gte) + "  \u2192  " + fmtTime(tr.lte)
      : "all time";
    return [
      el("h1", null, "STIG findings"),
      el("p", { class: "muted" },
        "Window: ", timeLabel,
        " \u00b7 total ", String(data.total || 0),
        " \u00b7 unique stig_ids ", String(data.unique_stig_ids || 0),
        " \u00b7 unique controls ", String(data.unique_controls || 0),
        " \u00b7 ", el("a", { href: "/", "data-link": "" }, "\u2190 overview")),
      el("div", { class: "cards" },
        card("Findings", data.total || 0, (data.total || 0) > 0 ? "info" : ""),
        card("Unique stig_ids", data.unique_stig_ids || 0, ""),
        card("Unique controls", data.unique_controls || 0, ""),
        card("Hosts affected", Object.keys(byHost).length, ""),
      ),
      el("div", { class: "row" },
        el("div", { class: "col section" },
          el("h2", null, "By severity"),
          agentTable(bySev),
        ),
        el("div", { class: "col section" },
          el("h2", null, "By NIST family"),
          // Render in canonical NIST order (not by-count) so the
          // table is stable across windows. Counts of 0 still
          // render — that's the whole point of the seed.
          orderedTable(toEntries(data.by_nist_family),
                       data.nist_families),
        ),
        el("div", { class: "col section" },
          el("h2", null, "By host"),
          orderedTable(toEntries(data.by_host),
                       data.monitored_hosts,
                       data.monitored_hosts_status,
                       "/stig/host/"),
        ),
      ),
      el("div", { class: "row" },
        el("div", { class: "col section" },
          el("h2", null, "Top stig_ids"),
          agentTable(byStig),
        ),
        el("div", { class: "col section" },
          el("h2", null, "Top controls"),
          agentTable(byCtrl),
        ),
        el("div", { class: "col section" },
          el("h2", null, "By tenant"),
          agentTable(byTenant),
        ),
      ),
      el("div", { class: "section" },
        el("h2", null, "Findings (" + findings.length + ")"),
        stigFindingsTable(findings),
      ),
    ];
  }
  function stigFindingsTable(rows) {
    if (!rows.length) {
      return el("p", { class: "empty" },
        "No STIG findings in the selected window. ",
        "The classifier attaches stig_id to L12+ alerts that hit ",
        "a Wazuh rule in ",
        el("code", null, "config/stig-rules/"),
        " (currently 13 mapped rules across RHEL 9 + Ubuntu 22.04 catalogues).");
    }
    return el("table", null,
      el("thead", null, el("tr", null,
        el("th", null, "ts"),
        el("th", null, "stig_id"),
        el("th", null, "control"),
        el("th", null, "family"),
        el("th", null, "severity"),
        el("th", null, "host"),
        el("th", null, "rule"),
        el("th", null, "title"),
      )),
      el("tbody", null, ...rows.map(f => {
        const ev = f.stig_evidence || {};
        const wa = f.wazuh_alert || {};
        return el("tr", null,
          el("td", null, fmtTime(f.ts)),
          el("td", null, el("code", null, ev.stig_id || "-")),
          el("td", null, ev.control_id || "-"),
          el("td", null, ev.nist_family || "-"),
          el("td", null, badge(ev.severity || "?")),
          el("td", null, wa.agent || "-"),
          el("td", null, el("code", null, ev.wazuh_rule_id || (wa.rule_id || "-"))),
          el("td", { class: "muted" },
            ev.title ? ev.title.substring(0, 60) : "-",
            ev.title && ev.title.length > 60 ? "\u2026" : ""),
        );
      })),
    );
  }
  async function pageStigHost(host) {
    let data;
    try { data = await api("/tools/stig_host_view", "POST",
                           { host: host, time_range: "30d", limit: 200 }); }
    catch (e) { return errorView(e); }
    if (!data || !data.ok) {
      return [el("h1", null, "STIG findings — " + host),
              el("p", { class: "alert bad" },
                 "stig_host_view error: ",
                 (data && data.error) || (data && data.message) || "unknown")];
    }
    const findings = data.findings || [];
    const byFam = data.by_nist_family || {};
    const bySev = data.by_severity || {};
    const byStig = data.by_stig_id || {};
    const byCtrl = data.by_control_id || {};
    const total = data.total || 0;
    const status = data.host_status || "unknown";
    const statusClass = status === "active" ? "ok"
                      : status === "disconnected" ? "warn"
                      : "bad";
    const tr = data.time_range;
    const timeLabel = tr
      ? fmtTime(tr.gte) + "  \u2192  " + fmtTime(tr.lte)
      : "all time";
    // Sanity check: every finding's wazuh_alert.agent must
    // match the requested host. If it doesn't, that's a
    // server-side filter bug — surface it loudly.
    const wrongHost = findings.filter(f => {
      const a = (f.wazuh_alert || {}).agent;
      return a && a !== host;
    });
    return [
      el("h1", null,
        "STIG findings — ",
        el("code", null, host), " ",
        el("span", { class: "badge " + statusClass,
                     style: "font-size:0.6em;padding:2px 8px;border-radius:8px;",
                     title: "Wazuh agent status" }, status)),
      el("p", { class: "muted" },
        "Window: ", timeLabel,
        " \u00b7 total ", String(total),
        " \u00b7 unique stig_ids ", String(data.unique_stig_ids || 0),
        " \u00b7 unique controls ", String(data.unique_controls || 0),
        " \u00b7 ", el("a", { href: "/stig", "data-link": "" }, "\u2190 all hosts")),
      wrongHost.length
        ? el("p", { class: "alert bad" },
            "Filter bug: ", String(wrongHost.length),
            " finding(s) returned for hosts other than ", el("code", null, host),
            " — server-side host filter is broken.")
        : null,
      el("div", { class: "cards" },
        card("Findings", total, total > 0 ? "info" : ""),
        card("Unique stig_ids", data.unique_stig_ids || 0, ""),
        card("Unique controls", data.unique_controls || 0, ""),
        card("Status", status, statusClass),
      ),
      el("div", { class: "row" },
        el("div", { class: "col section" },
          el("h2", null, "By severity"),
          agentTable(bySev),
        ),
        el("div", { class: "col section" },
          el("h2", null, "By NIST family"),
          // Canonical NIST order, not by-count — same as /stig.
          orderedTable(toEntries(byFam), data.nist_families),
        ),
      ),
      el("div", { class: "row" },
        el("div", { class: "col section" },
          el("h2", null, "Top stig_ids"),
          agentTable(byStig),
        ),
        el("div", { class: "col section" },
          el("h2", null, "Top controls"),
          agentTable(byCtrl),
        ),
      ),
      el("div", { class: "section" },
        el("h2", null, "Findings (" + findings.length + ")"),
        stigFindingsTable(findings),
      ),
    ];
  }
  async function pageHealth() {
    let h;
    try { h = await api("/healthz", "GET"); }
    catch (e) { return errorView(e); }
    const rows = [];
    for (const k in (h.backends || {})) {
      const b = h.backends[k];
      rows.push(el("tr", null,
        el("td", null, k),
        el("td", null, badge(b.reachable ? (b.ok ? "good" : "warn") : "bad")),
        el("td", null, el("code", null, b.url)),
        el("td", { class: "muted" }, b.reachable ? "reachable" : "unreachable"),
      ));
    }
    return [
      el("h1", null, "Backend health"),
      el("p", { class: "muted" },
        "The dashboard itself is up; the rows below are the ",
        "downstream MCPs that power the pages."),
      el("table", null,
        el("thead", null, el("tr", null,
          el("th", null, "Backend"),
          el("th", null, "Status"),
          el("th", null, "URL"),
          el("th", null, "Detail"),
        )),
        el("tbody", null, ...rows),
      ),
    ];
  }

  // ---- building blocks -----------------------------------------------
  function card(label, value, kind) {
    return el("div", { class: "card" },
      el("div", { class: "label" }, label),
      el("div", { class: "value" }, String(value)),
      kind ? el("div", null, badge(kind)) : null,
    );
  }
  // Convert an {key: count} object to [key, count] pairs.
  function toEntries(obj) {
    return Object.entries(obj || {});
  }
  // Render a count table in a caller-supplied canonical order
  // (e.g. NIST families AC..SR, or monitored hosts alphabetical).
  // Entries present in `obj` but NOT in `order` are appended at
  // the bottom (descending by count) so sandbox / synthetic
  // hosts don't disappear — they just render after the
  // canonical ones. `statuses` is optional: {key: "active"|...}
  // and renders a small badge in the Key cell. `linkPrefix`
  // is optional: when set, each key renders as
  // <a href="<prefix><key>"> so the operator can drill from
  // the summary table into a per-key page in one click.
  function orderedTable(entries, order, statuses, linkPrefix) {
    const have = new Set(entries.map(e => e[0]));
    const idxOf = (k) => {
      const i = order ? order.indexOf(k) : -1;
      return i;
    };
    const inOrder = (order || [])
      .map(k => [k, (entries.find(e => e[0] === k) || [k, 0])[1]]);
    const extras = entries
      .filter(([k]) => !order || !have || idxOf(k) === -1 || !order.includes(k))
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const rows = inOrder.concat(extras);
    if (!rows.length) return el("p", { class: "empty" }, "No data.");
    return el("table", null,
      el("thead", null, el("tr", null,
        el("th", null, "Key"), el("th", null, "Count"),
      )),
      el("tbody", null, ...rows.map(([k, v]) => {
        const status = statuses && statuses[k];
        const codeEl = el("code", null, k);
        const keyInner = linkPrefix
          ? el("a", { href: linkPrefix + encodeURIComponent(k),
                      "data-link": "" }, codeEl)
          : codeEl;
        const keyCell = el("td", null,
          keyInner,
          status ? el("span", {
            class: "badge " + (status === "active" ? "ok" : "warn"),
            style: "margin-left:6px;font-size:0.75em;padding:1px 6px;border-radius:6px;",
            title: status,
          }, status) : null);
        return el("tr", null,
          keyCell,
          el("td", null, String(v)),
        );
      })));
  }
  function agentTable(obj) {
    const entries = Object.entries(obj).sort((a, b) => b[1] - a[1]);
    if (!entries.length) return el("p", { class: "empty" }, "No data.");
    return el("table", null,
      el("thead", null, el("tr", null,
        el("th", null, "Key"), el("th", null, "Count"),
      )),
      el("tbody", null, ...entries.map(([k, v]) => el("tr", null,
        el("td", null, el("code", null, k)),
        el("td", null, String(v)),
      ))),
    );
  }
  function auditTable(rows) {
    if (!rows.length) return el("p", { class: "empty" }, "No activity.");
    return el("table", null,
      el("thead", null, el("tr", null,
        el("th", null, "ts"), el("th", null, "agent"),
        el("th", null, "tenant"), el("th", null, "kind"),
        el("th", null, "input"), el("th", null, "ms"),
        el("th", null, "outcome"),
      )),
      el("tbody", null, ...rows.map(r => el("tr", null,
        el("td", null, fmtTime(r.ts)),
        el("td", null, el("code", null, r.agent_id || "-")),
        el("td", null, r.tenant_id || "-"),
        el("td", null, r.input_kind || "-"),
        el("td", { class: "muted" },
          el("a", { href: "/runs/" + encodeURIComponent(r.runId || ""), "data-link": "" },
            r.input_summary ? r.input_summary.substring(0, 60) : "-")),
        el("td", null, String(r.duration_ms || 0)),
        el("td", null, badge(r.outcome || "?")),
      ))),
    );
  }
  function ticketsList(rows) {
    if (!rows.length) return el("p", { class: "empty" }, "No tickets.");
    return el("ul", { class: "list" },
      ...rows.map(t => el("li", null,
        el("a", { href: "/runs/" + encodeURIComponent(t.source_run_id || t.id || ""), "data-link": "" },
          t.id + " · " + t.title),
        " ", badge(t.severity), " ", badge(t.status),
        t.assignee ? el("span", { class: "muted" }, " · @" + t.assignee) : null,
        el("div", { class: "muted" }, fmtTime(t.created_at)),
      )),
    );
  }
  function errorView(e) {
    return [el("h1", null, "Error"),
            el("div", { class: "alert bad" }, esc(String(e.message || e)))];
  }

  // ---- task pane (vCenter-style) --------------------------------------
  function taskStatusCell(r) {
    const cls = r.status === "running" ? "warn" : r.status === "done"
      ? "good" : r.status === "timeout" ? "warn" : "bad";
    return el("span", { class: "badge " + cls }, r.status || "?");
  }
  function tasksTable(rows) {
    if (!rows.length) return el("p", { class: "empty" },
      "No tasks recorded yet — run a scan from a host page and it appears here.");
    return el("table", null,
      el("thead", null, el("tr", null,
        el("th", null, "task"), el("th", null, "target"),
        el("th", null, "status"), el("th", null, "started"),
        el("th", null, "ended"), el("th", null, "report"),
        el("th", null, ""))),
      el("tbody", null, ...rows.map(r => {
        const d = r.details || {};
        return el("tr", null,
          el("td", null, badge((r.kind || "?") === "compliance_scan"
            ? "medium" : (r.kind || "?") === "stig_scan" ? "info" : "dim"),
            " ", el("code", null, r.kind || "?")),
          el("td", null, el("code", null, r.target || "-")),
          el("td", null, taskStatusCell(r)),
          el("td", null, el("code", null, (r.ts || "").substring(0, 19).replace("T", " "))),
          el("td", null, el("code", null, (r.ended || "").substring(0, 19).replace("T", " ") || "-")),
          el("td", null, d.report_url
            ? el("a", { href: d.report_url, target: "_blank" }, "report")
            : el("span", { class: "muted" }, "—")),
          el("td", null, el("a", { href: "/tasks/" + encodeURIComponent(r.id),
            "data-link": "" }, "details")));
      })),
    );
  }
  async function pageTasks() {
    let data;
    try { data = await api("/tools/tasks_list", "POST", { limit: 200 }); }
    catch (e) { return errorView(e); }
    const rows = data.tasks || [];
    const running = rows.filter(r => r.status === "running").length;
    return [
      el("h1", null, "Tasks"),
      el("p", { class: "muted" },
        "Every task the SOC system has run: compliance scans, agent-restart " +
        "triggers, OpenSCAP scans. Newest first — click a task for the " +
        "drill-down (steps, evidence, report)." +
        (running ? " " + running + " running." : "")),
      el("div", { class: "section" }, tasksTable(rows)),
      el("p", { class: "muted" }, "Auto-refreshes every 30s."),
    ];
  }
  async function pageTaskDetail(id) {
    let data;
    try { data = await api("/tools/task_get", "POST", { id }); }
    catch (e) { return errorView(e); }
    if (!data.ok) return errorView(new Error(data.error || "task_get failed"));
    const t = data.task || {};
    const d = (t.details && typeof t.details === "object") ? t.details : {};
    return [
      el("h1", null, "Task: " + (t.kind || "?") + " · " + (t.target || "?")),
      el("div", { class: "cards" },
        card("Status", t.status || "?",
             t.status === "done" ? "good" : (t.status === "running" ? "warn" : "bad")),
        card("Started", fmtTime(t.ts) || "-", ""),
        card("Ended", fmtTime(t.ended) || "-", ""),
        t.report_available ? card("Report", "available", "info") : null,
      ),
      el("div", { class: "section" },
        el("h2", null, "Details"),
        el("pre", null, esc(JSON.stringify(d, null, 2))),
      ),
      t.history && t.history.length > 1
        ? el("div", { class: "section" },
            el("h2", null, "History"),
            el("ul", { class: "list" }, ...t.history.map(h => el("li", null,
              el("code", null, (h.ts || "").substring(0, 19)), " — ",
              badge(h.status || "?")))))
        : null,
      el("div", { class: "btn-row" },
        el("a", { class: "btn", href: "/tasks", "data-link": "" }, "← all tasks"),
        t.report_available
          ? el("a", { class: "btn", href: d.report_url || "/tasks", target: "_blank" },
              "Open scan report")
          : null,
      ),
    ];
  }
  async function updateTaskbar() {
    const bar = document.getElementById("taskbar");
    if (!bar) return;
    try {
      const data = await api("/tools/tasks_list", "POST", { limit: 30 });
      const rows = (data.tasks || []).slice(0, 4);
      bar.textContent = "";
      const mk = (t) => {
        const a = document.createElement("a");
        a.href = "/tasks/" + encodeURIComponent(t.id);
        a.setAttribute("data-link", "");
        a.className = "tb-item " + (t.status === "running" ? "run"
          : t.status === "done" ? "ok" : "fail");
        a.textContent = (t.status === "running" ? "🔴 "
          : t.status === "done" ? "✓ " : "✗ ")
          + (t.kind || "task") + ": " + (t.target || "");
        return a;
      };
      const running = rows.find(r => r.status === "running");
      if (running) bar.appendChild(mk(running));
      rows.filter(r => r.status !== "running").slice(0, 3)
        .forEach(t => bar.appendChild(mk(t)));
      const all = document.createElement("a");
      all.href = "/tasks";
      all.setAttribute("data-link", "");
      all.className = "tb-all";
      all.textContent = "all tasks →";
      bar.appendChild(all);
    } catch (e) { /* taskbar is best-effort */ }
  }

  // ---- router ---------------------------------------------------------
  async function render() {
    const path = location.pathname.replace(/\/+$/, "") || "/";
    let nodes;
    if (path === "/" || path === "/index.html") {
      nodes = await pageOverview();
    } else if (path === "/tenants") {
      nodes = await pageTenants();
    } else if (path === "/fleet") {
      nodes = await pageFleet();
      scheduleFleetRefresh();
    } else if (path.startsWith("/fleet/")) {
      const fid = decodeURIComponent(path.replace(/^\/fleet\//, "").replace(/\/+$/, ""));
      if (fid) nodes = await pageFleetHost(fid);
    } else if (path === "/scores") {
      nodes = await pageScores();
    } else if (path === "/stig") {
      nodes = await pageStig();
    } else if (path === "/tasks") {
      nodes = await pageTasks();
    } else if (path.startsWith("/tasks/")) {
      const tid = decodeURIComponent(path.replace(/^\/tasks\//, "").replace(/\/+$/, ""));
      if (tid) nodes = await pageTaskDetail(tid);
    } else if (path.startsWith("/stig/host/")) {
      const host = decodeURIComponent(path.replace(/^\/stig\/host\//, "").replace(/\/+$/, ""));
      if (host) nodes = await pageStigHost(host);
    } else if (path.startsWith("/logs/")) {
      const name = decodeURIComponent(path.replace(/^\/logs\//, "").replace(/\/+$/, ""));
      if (name) nodes = await pageAgentLogs(name);
    } else if (path === "/agents") {
      nodes = await pageAgents();
    } else if (path === "/tickets") {
      nodes = await pageTickets();
    } else if (path === "/healthz") {
      nodes = await pageHealth();
    } else {
      const m = path.match(/^\/(tenants|agents|runs)\/([^/]+)$/);
      if (m) {
        const kind = m[1], id = decodeURIComponent(m[2]);
        if (kind === "tenants") nodes = await pageTenant(id);
        else if (kind === "agents") nodes = await pageAgent(id);
        else if (kind === "runs") nodes = await pageRun(id);
      }
      if (!m) {
        const sm = path.match(/^\/scores\/([^/]+)$/);
        if (sm) nodes = await pageScore(decodeURIComponent(sm[1]));
      }
      if (!nodes) nodes = [el("h1", null, "Not found"),
                           el("p", null, el("a", { href: "/" }, "← back to overview"))];
    }
    clear(root);
    nodes.forEach(n => { if (n) root.appendChild(n); });
    updateTaskbar();
    // Highlight current nav
    document.querySelectorAll(".nav a").forEach(a => {
      const href = a.getAttribute("href");
      if (href === path || (href !== "/" && path.startsWith(href))) {
        a.classList.add("active");
      } else {
        a.classList.remove("active");
      }
    });
  }
  function updateStatus() {
    api("/healthz", "GET").then(h => {
      const c4 = h.backends && h.backends["soc-audit-mcp"];
      const c3 = h.backends && h.backends["soc-tickets-mcp"];
      const c4ok = c4 && c4.reachable;
      const c3ok = c3 && c3.reachable;
      const ok = c4ok || c3ok;   // partial counts as "degraded"
      status.innerHTML = (ok ? "🟢" : "🔴") + " C4:" + (c4ok ? "✓" : "✗")
        + " C3:" + (c3ok ? "✓" : "✗");
    }).catch(() => { status.textContent = "🔴 backend unreachable"; });
  }

  // Intercept nav clicks
  document.addEventListener("click", e => {
    const a = e.target.closest("a[data-link]");
    if (!a) return;
    const href = a.getAttribute("href");
    if (!href || href.startsWith("http")) return;
    e.preventDefault();
    history.pushState({}, "", href);
    render();
  });
  window.addEventListener("popstate", render);

  // Auto-refresh /fleet every 30s while the page is visible.
  let _fleetRefreshTimer = null;
  function scheduleFleetRefresh() {
    if (_fleetRefreshTimer) clearInterval(_fleetRefreshTimer);
    _fleetRefreshTimer = setInterval(() => {
      if (location.pathname.replace(/\/+$/, "") === "/fleet") render();
    }, 30000);
  }

  // First render
  render();
  // Seed fleet refresh on initial load if /fleet is the landing page
  if (location.pathname.replace(/\/+$/, "") === "/fleet") scheduleFleetRefresh();
  updateStatus();
  setInterval(updateStatus, 15000);
  updateTaskbar();
  setInterval(updateTaskbar, 30000);
})();
