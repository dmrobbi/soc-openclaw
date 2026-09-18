# Walkthroughs

Step-by-step guides for setting up and running soc-openclaw — with the
real dashboard, real commands, and a video tour. All screenshots are
from the live system, shot through the dashboard's share-safe mode
(`SOC_DASHBOARD_MASK_IPS=1` — IPs masked to `100.x.x.x`, hostnames and
scores are real).

## Video — the dashboard in 50 seconds

https://github.com/dmrobbi/soc-openclaw/raw/main/docs/walkthroughs/media/walkthrough-dashboard.mp4

<video src="media/walkthrough-dashboard.mp4" controls muted width="100%"></video>

(If your markdown viewer doesn't embed it, download
[`walkthrough-dashboard.mp4`](media/walkthrough-dashboard.mp4) — 0.9 MB.)

## The guides

| Guide | What it covers |
|---|---|
| [Setup — zero to running](setup.md) | Clone → configure → install → verify → first scan → dashboard tour. ~30 minutes end-to-end. |
| [Operations — running it day to day](operations.md) | The daily loop, reading reports, remediation gates, scan exceptions, diffing scans, troubleshooting. |

## Screenshot index (all in [media/](media/))

| Shot | Page | What it shows |
|---|---|---|
| [01](media/01-overview.png) | `/` | 24h overview: agents, alerts, tickets, STIG findings |
| [02](media/02-fleet.png) | `/fleet` | fleet table: status, STIG (30d), CVE columns |
| [03](media/03-fleet-host.png) | `/fleet/<host>` | host drill-down + gated Dry run / Remediate buttons |
| [04](media/04-stig.png) | `/stig` | STIG findings (7d): severity, families, top controls |
| [05](media/05-stig-host.png) | `/stig/host/<host>` | per-host STIG findings |
| [06](media/06-scores.png) | `/scores` | per-tenant compliance scores + 7-day trend |
| [07](media/07-tasks.png) | `/tasks` | task log: every automated run |
| [08](media/08-cve-host.png) | `/cve/<host>` | per-host vulnerability findings |
| [09](media/09-task-detail.png) | `/tasks/<id>` | task detail: history + scan-report links |

Companion reading: [quickstart.md](../../quickstart.md) (concepts),
[docs/architecture.md](../architecture.md) (decision trees),
[docs/deploy-guide.md](../deploy-guide.md) (reference).