# Changelog

Dates are UTC.

## v0.1.0 — 2026-10-19

First public tagged release. Tagged state = current main.

- A step-by-step guide + implementation for a home SOC where
  OpenClaw is the always-on AI analyst: realtime watch, scheduled
  sweeps, triage, and paging to a chat channel.
- Dashboard: dynamic faceted tickets browser; ticket rows are the
  select surface with an inline detail drawer.
- Deploy pattern: loopback-to-docker-bridge forwarders for the
  MCP/ingest/laya/memory/manager services; SIMPLE-INSTALL.md gives
  a one-page install from the public GitHub repos.
- Deterministic contract severity and no-LLM-turn-per-alert ingest;
  the laya shadow framework provides gated decisioning; the indexer
  credential is required — no default-credential fallback.
- DISA catalogues regenerated from stig-baselines V2R9 sources;
  the Addons section cross-links soc-disk-health (SMART disk
  monitoring).
- Scan diffing across scan days, exception lists via XCCDF
  tailoring, daily report delivery, a pytest suite and CI gates —
  all shipped earlier in the line.

Honest limits: sized for a single-estate, single-node stack;
alert content is scrubbed manually before any public artifact;
the AI layer is gated by default and needs tuning per
environment.