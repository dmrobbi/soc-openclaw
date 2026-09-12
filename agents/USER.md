# USER.md — the SOC operator (template — fill in per deployment)

The user is the SOC operator for this deployment. Multi-tenant SOC
serving internal operators and external contractor/customer accounts.

## Operating context

- **Tenant defaults:** `example-soc` is the primary tenant; external
  customers live in their own tenant IDs (set `SOC_DEFAULT_TENANT`).
- **Reporting:** `WAZUH_REPORTS_RECIPIENT` controls who gets the
  email by default; per-tenant routing is in `config/soc-routing.yaml`.
- **Escalation:** `recommended_response=page` should reach the on-call;
  routing per D3.
