# SOC dashboard — screenshot series (2026-09-16)

Actual pages from the running soc-openclaw dashboard, shot headless
(chromium) at 1600x1000. IPs are redacted to the first octet via the
dashboard's `SOC_DASHBOARD_MASK_IPS=1` share-safe mode; host names and
scores are real. The mutations-disabled notice on the host page is the
real current gate state (SOC_MANAGER_MCP_ALLOW_MUTATIONS off).

| File | Page | What it shows |
|---|---|---|
| 01-overview.png | `/` | 24h overview: agents, tickets, STIG findings, feed |
| 02-fleet.png | `/fleet` | fleet table: status, STIG (30d), CVE columns |
| 03-fleet-host-remediate.png | `/fleet/evgen-a` | host drill-down: OpenSCAP controls + Dry run / Remediate buttons |
| 04-stig.png | `/stig` | STIG findings (30d): severity, families, hosts, top controls |
| 05-stig-host.png | `/stig/host/vader` | per-host STIG findings |
| 06-scores.png | `/scores` | per-tenant scores + 7-day trend |
| 07-tasks.png | `/tasks` | tasklog: every automated run (scans, remediations) |
| 08-cve-host.png | `/cve/evgen-a` | per-host vulnerability findings |
