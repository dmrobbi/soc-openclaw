#!/usr/bin/env python3
"""SOC per-tenant routing configuration loader (Track D, D3).

Loads and validates `config/soc-routing.yaml` (or the path in
`SOC_ROUTING_CONFIG`) and exposes a typed `RoutingConfig` object
to the rest of the SOC fleet. The schema covers:

  - auto-remediation thresholds (per-tenant)
  - notification routing (per-decision → per-channel)
  - recipients per channel
  - quiet hours + severity overrides
  - allowed actions (per-tenant gate)
  - blocked source IPs
  - STIG / CMMC applicability + baseline (the E3 unblock)

The loader is a thin wrapper around PyYAML with a strict
schema. Bad files fail loudly at import time, not silently
during an incident.

Usage
-----

    from soc_routing import get_config, RoutingError

    cfg = get_config()                     # cached after first load
    t = cfg.tenant("example-soc")
    if t.is_quiet_hours(now):
        # ...
    if t.can_auto_remediate(confidence=0.92, severity="high"):
        # ...
    recipients = t.recipients_for("page", "page")

The default config path is `config/soc-routing.yaml` relative
to the SOC repo root, falling back to the example file if
the real one doesn't exist yet (so dev/test works out of the
box). Override with `SOC_ROUTING_CONFIG=/path/to/file.yaml`.

Multi-tenant from day 1 (Wes's decision 2026-08-06).

Created 2026-08-08 by Ciceron as part of Track D (D3).
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError as e:  # pragma: no cover
    raise SystemExit(
        "PyYAML is required for soc_routing.py. Install with:\n"
        "  pip install pyyaml\n"
        f"(import error: {e!r})")


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "soc-routing.yaml"
FALLBACK_CONFIG_PATH = REPO_ROOT / "config" / "soc-routing.yaml.example"


def _config_path() -> Path:
    p = os.environ.get("SOC_ROUTING_CONFIG")
    if p:
        return Path(p).expanduser()
    if DEFAULT_CONFIG_PATH.exists():
        return DEFAULT_CONFIG_PATH
    return FALLBACK_CONFIG_PATH


# ---------------------------------------------------------------------------
# Schema constants
# ---------------------------------------------------------------------------
ALLOWED_RECOMMENDED_RESPONSES = (
    "note_only", "digest_only", "email", "page", "auto_remediate",
    "log",  # synthetic; not produced by soc-triage but allowed in routing
)
ALLOWED_CHANNELS = ("email", "page", "digest", "log")
ALLOWED_SEVERITIES = ("low", "medium", "high", "critical")
ALLOWED_BASELINES = ("low", "moderate", "high")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class RoutingError(Exception):
    """Raised on config load / validation failure."""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class QuietHours:
    enabled: bool
    start: str
    end: str
    timezone: str
    overrides: List[str] = field(default_factory=list)


@dataclass
class STIGConfig:
    applicability_tags: List[str]
    baseline: str
    # Path to the catalogue file for this tenant, relative to
    # the repo root or absolute. Two catalogues are shipped:
    #   - config/stig-catalogue-cmmc.json  (24-control hand-curated seed)
    #   - config/stig-catalogue-disa.json  (DISA STIG import)
    # The default is the CMMC seed (back-compat with the
    # pre-DISA-import behaviour). Tenants that need real STIG
    # coverage override this to point at the DISA catalogue.
    catalogue: str = "config/stig-catalogue.json"


@dataclass
class TenantRouting:
    tenant_id: str
    display_name: str
    auto_remediation_threshold: float
    auto_remediation_severities: List[str]
    notification_routing: Dict[str, List[str]]
    recipients: Dict[str, Dict[str, str]]
    quiet_hours: QuietHours
    allowed_actions: List[str]
    blocked_source_ips: List[str]
    stig: STIGConfig
    # SOC Phase 4 (2026-08-17): per-tenant pattern whitelist.
    # The dispatcher refuses to auto-apply a pattern that
    # isn't in this list, even if the LLM says
    # recommended_response=auto_remediate and the threshold
    # is met. Empty list = no pattern auto-remediates.
    # Validated to be a list of pattern names (each is a
    # .py file stem under soc-remediations/).
    allow_auto_remediate_patterns: List[str] = field(default_factory=list)

    def is_quiet_hours(self, now: Optional[dt.datetime] = None) -> bool:
        """Return True if `now` (default: UTC now) falls within
        the tenant's quiet hours. Handles overnight ranges
        (e.g. 22:00 → 07:00) by comparing across midnight."""
        if not self.quiet_hours.enabled:
            return False
        try:
            tz = _tz_from_name(self.quiet_hours.timezone)
        except Exception:
            tz = dt.timezone.utc
        now = now or dt.datetime.now(dt.timezone.utc)
        now_local = now.astimezone(tz)
        sh, sm = _parse_hhmm(self.quiet_hours.start)
        eh, em = _parse_hhmm(self.quiet_hours.end)
        now_mins = now_local.hour * 60 + now_local.minute
        start_mins = sh * 60 + sm
        end_mins = eh * 60 + em
        if start_mins <= end_mins:
            return start_mins <= now_mins < end_mins
        # overnight (e.g. 22:00 → 07:00)
        return now_mins >= start_mins or now_mins < end_mins

    def can_auto_remediate(self, *, confidence: float,
                           severity: str) -> Tuple[bool, str]:
        """Return (eligible, reason). Reason is empty on
        success; explains why on failure."""
        if "auto_remediate" not in self.allowed_actions:
            return False, "action 'auto_remediate' not in allowed_actions"
        if severity not in self.auto_remediation_severities:
            return False, f"severity {severity!r} not eligible"
        if confidence < self.auto_remediation_threshold:
            return False, (f"confidence {confidence:.2f} below threshold "
                           f"{self.auto_remediation_threshold:.2f}")
        return True, ""

    def can_auto_remediate_pattern(self, pattern_name: str
                                   ) -> Tuple[bool, str]:
        """Phase 4 (2026-08-17) / Phase 6 (2026-08-24):
        per-tenant pattern gate. Returns (eligible, reason).
        The dispatcher consults this AFTER the existing
        can_auto_remediate() check passes.

        Phase 4 semantics: empty allow_auto_remediate_patterns =
        no pattern auto-remediates (safe default).

        Phase 6 semantics (full production rollout): the
        per-tenant whitelist is REMOVED — an empty list now
        means ALL patterns are eligible (the default). A
        non-empty list still acts as an explicit allowlist
        for tenants that want to opt back into a narrower
        scope. This is the "default to all" flip."""
        if not self.allow_auto_remediate_patterns:
            # Phase 6: empty whitelist = allow all patterns.
            return True, ""
        if pattern_name not in self.allow_auto_remediate_patterns:
            return False, (f"pattern {pattern_name!r} not in tenant "
                           f"whitelist (allowed: "
                           f"{self.allow_auto_remediate_patterns})")
        return True, ""

    def recipients_for(self, action: str,
                       channel: str) -> List[str]:
        """Return the recipient *labels* for a given decision
        action and notification channel. The caller resolves
        labels to actual addresses (e.g. emails) via
        `recipients[channel][label]`."""
        channels = self.notification_routing.get(action, [])
        if channel not in channels:
            return []
        # For now we route by channel name; the per-channel
        # address resolution is the caller's job. We expose
        # a sensible default: the first label of each
        # channel.
        ch_recs = self.recipients.get(channel, {})
        if not ch_recs:
            return []
        # Common conventions: prefer `primary` and
        # `oncall_primary`, fall back to all values.
        preferred = ("primary", "oncall_primary", "stakeholders",
                     "audit_target")
        for p in preferred:
            if p in ch_recs:
                return [ch_recs[p]]
        return list(ch_recs.values())


def _parse_hhmm(s: str) -> Tuple[int, int]:
    h, _, m = s.partition(":")
    h_i, m_i = int(h), int(m)
    if not (0 <= h_i <= 23 and 0 <= m_i <= 59):
        raise ValueError(f"bad time {s!r}: hours must be 0-23, minutes 0-59")
    return h_i, m_i


def _tz_from_name(name: str) -> dt.tzinfo:
    """Resolve an IANA timezone name. Fall back to UTC if
    the system tzdata isn't available (e.g. minimal
    containers)."""
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:
        return dt.timezone.utc


@dataclass
class RoutingConfig:
    """The full config (defaults + per-tenant)."""
    raw: Dict[str, Any]
    path: str
    defaults: TenantRouting
    tenants: Dict[str, TenantRouting]
    _cache: Dict[str, Any] = field(default_factory=dict)

    def tenant(self, tenant_id: str) -> TenantRouting:
        if tenant_id not in self.tenants:
            raise RoutingError(
                f"unknown tenant {tenant_id!r} (known: "
                f"{sorted(self.tenants.keys())})")
        return self.tenants[tenant_id]

    def known_tenants(self) -> List[str]:
        return sorted(self.tenants.keys())


# ---------------------------------------------------------------------------
# Loader + validation
# ---------------------------------------------------------------------------
def _deep_merge(base: Dict[str, Any],
               override: Dict[str, Any]) -> Dict[str, Any]:
    """Deep-merge two dicts. Lists are replaced (not concatenated).
    Nested dicts are merged recursively. Used to apply per-tenant
    overrides on top of the defaults."""
    out = dict(base)
    for k, v in (override or {}).items():
        if (k in out and isinstance(out[k], dict)
                and isinstance(v, dict)):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _validate_tenant(tid: str, raw: Dict[str, Any],
                    defaults: Dict[str, Any]) -> TenantRouting:
    if not isinstance(raw, dict):
        raise RoutingError(f"tenant {tid!r} must be a mapping, got {type(raw)}")
    # Deep-merge with defaults so partial overrides work
    # (e.g. tenant only specifies allowed_actions).
    merged: Dict[str, Any] = _deep_merge(defaults, raw)

    # auto_remediation_threshold
    th = merged.get("auto_remediation_threshold")
    if not isinstance(th, (int, float)) or not 0.0 <= th <= 1.0:
        raise RoutingError(
            f"tenant {tid!r}: auto_remediation_threshold must be "
            f"0.0..1.0, got {th!r}")

    # auto_remediation_severities
    ar_sev = merged.get("auto_remediation_severities", [])
    if not isinstance(ar_sev, list):
        raise RoutingError(
            f"tenant {tid!r}: auto_remediation_severities must be a list")
    for s in ar_sev:
        if s not in ALLOWED_SEVERITIES:
            raise RoutingError(
                f"tenant {tid!r}: bad severity in "
                f"auto_remediation_severities: {s!r}")

    # notification_routing
    nr = merged.get("notification_routing", {})
    if not isinstance(nr, dict):
        raise RoutingError(
            f"tenant {tid!r}: notification_routing must be a mapping")
    for action, channels in nr.items():
        if action not in ALLOWED_RECOMMENDED_RESPONSES:
            raise RoutingError(
                f"tenant {tid!r}: bad action in notification_routing: "
                f"{action!r} (allowed: {ALLOWED_RECOMMENDED_RESPONSES})")
        if not isinstance(channels, list):
            raise RoutingError(
                f"tenant {tid!r}: notification_routing.{action} must be a "
                f"list of channels")
        for ch in channels:
            if ch not in ALLOWED_CHANNELS:
                raise RoutingError(
                    f"tenant {tid!r}: bad channel in "
                    f"notification_routing.{action}: {ch!r} "
                    f"(allowed: {ALLOWED_CHANNELS})")

    # recipients
    rec = merged.get("recipients", {})
    if not isinstance(rec, dict):
        raise RoutingError(f"tenant {tid!r}: recipients must be a mapping")
    for channel, labels in rec.items():
        if channel not in ALLOWED_CHANNELS:
            raise RoutingError(
                f"tenant {tid!r}: bad channel in recipients: {channel!r}")
        if not isinstance(labels, dict):
            raise RoutingError(
                f"tenant {tid!r}: recipients.{channel} must be a mapping")
        for label, value in labels.items():
            if not isinstance(value, str):
                raise RoutingError(
                    f"tenant {tid!r}: recipients.{channel}.{label} must be "
                    f"a string, got {type(value)}")

    # quiet_hours
    qh_raw = merged.get("quiet_hours", {})
    if not isinstance(qh_raw, dict):
        raise RoutingError(f"tenant {tid!r}: quiet_hours must be a mapping")
    qh = QuietHours(
        enabled=bool(qh_raw.get("enabled", False)),
        start=str(qh_raw.get("start", "22:00")),
        end=str(qh_raw.get("end", "07:00")),
        timezone=str(qh_raw.get("timezone", "UTC")),
        overrides=list(qh_raw.get("overrides", []) or []),
    )
    for s in qh.overrides:
        if s not in ALLOWED_SEVERITIES:
            raise RoutingError(
                f"tenant {tid!r}: bad severity in quiet_hours.overrides: "
                f"{s!r}")
    try:
        _parse_hhmm(qh.start)
        _parse_hhmm(qh.end)
    except Exception as e:
        raise RoutingError(
            f"tenant {tid!r}: bad quiet_hours start/end "
            f"({qh.start!r} / {qh.end!r}): {e}")

    # allowed_actions
    aa = merged.get("allowed_actions", [])
    if not isinstance(aa, list):
        raise RoutingError(f"tenant {tid!r}: allowed_actions must be a list")
    for a in aa:
        if a not in ALLOWED_RECOMMENDED_RESPONSES:
            raise RoutingError(
                f"tenant {tid!r}: bad action in allowed_actions: {a!r}")

    # blocked_source_ips
    bsi = merged.get("blocked_source_ips", [])
    if not isinstance(bsi, list):
        raise RoutingError(
            f"tenant {tid!r}: blocked_source_ips must be a list")
    for ip in bsi:
        if not isinstance(ip, str):
            raise RoutingError(
                f"tenant {tid!r}: blocked_source_ips entries must be strings")

    # SOC Phase 4 (2026-08-17): per-tenant pattern whitelist.
    # Pattern names are .py file stems under
    # soc-remediations/ (e.g. block_brute_force_source,
    # stig_fix_world_writable_file). Validated as a list
    # of non-empty strings, each ≤ 128 chars, each matching
    # the pattern-name regex [a-z0-9_]+. Empty list = no
    # pattern auto-remediates (safe default).
    allow_ar = merged.get("allow_auto_remediate_patterns", [])
    if not isinstance(allow_ar, list):
        raise RoutingError(
            f"tenant {tid!r}: allow_auto_remediate_patterns must be a list")
    import re as _re_ar
    for p in allow_ar:
        if not isinstance(p, str) or not _re_ar.fullmatch(
                r"[a-z0-9_]{1,128}", p):
            raise RoutingError(
                f"tenant {tid!r}: bad pattern in "
                f"allow_auto_remediate_patterns: {p!r} "
                f"(allowed: [a-z0-9_]{{1,128}})")

    # stig
    stig_raw = merged.get("stig", {})
    if not isinstance(stig_raw, dict):
        raise RoutingError(f"tenant {tid!r}: stig must be a mapping")
    baseline = str(stig_raw.get("baseline", "moderate"))
    if baseline not in ALLOWED_BASELINES:
        raise RoutingError(
            f"tenant {tid!r}: bad stig.baseline: {baseline!r} "
            f"(allowed: {ALLOWED_BASELINES})")
    tags = list(stig_raw.get("applicability_tags", []) or [])
    for t in tags:
        if not isinstance(t, str) or len(t) > 8:
            raise RoutingError(
                f"tenant {tid!r}: bad stig.applicability_tags entry: {t!r}")
    stig = STIGConfig(
        applicability_tags=tags, baseline=baseline,
        catalogue=str(stig_raw.get(
            "catalogue", "config/stig-catalogue.json")),
    )

    return TenantRouting(
        tenant_id=tid,
        display_name=str(merged.get("display_name", tid)),
        auto_remediation_threshold=float(th),
        auto_remediation_severities=list(ar_sev),
        notification_routing={k: list(v) for k, v in nr.items()},
        recipients={k: dict(v) for k, v in rec.items()},
        quiet_hours=qh,
        allowed_actions=list(aa),
        blocked_source_ips=list(bsi),
        stig=stig,
        allow_auto_remediate_patterns=list(allow_ar),
    )


def load_config(path: Optional[Path] = None) -> RoutingConfig:
    """Load and validate the routing config. Raises
    RoutingError on any schema violation."""
    p = Path(path) if path else _config_path()
    if not p.exists():
        raise RoutingError(f"config file not found: {p}")
    try:
        with open(p, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise RoutingError(f"YAML parse error in {p}: {e}")
    if not isinstance(raw, dict):
        raise RoutingError(f"top-level of {p} must be a mapping")

    defaults_raw = raw.get("defaults", {})
    if not isinstance(defaults_raw, dict):
        raise RoutingError("`defaults:` must be a mapping")
    # We need to validate the defaults as a "tenant" too, but
    # we use a synthetic tenant_id for that.
    default_tenant = _validate_tenant("__defaults__", defaults_raw, {})

    tenants_raw = raw.get("tenants", {})
    if not isinstance(tenants_raw, dict):
        raise RoutingError("`tenants:` must be a mapping")
    if not tenants_raw:
        raise RoutingError("`tenants:` is empty; at least one tenant required")
    tenants: Dict[str, TenantRouting] = {}
    for tid, traw in tenants_raw.items():
        tenants[tid] = _validate_tenant(
            tid, traw if isinstance(traw, dict) else {},
            defaults_raw)

    return RoutingConfig(
        raw=raw,
        path=str(p),
        defaults=default_tenant,
        tenants=tenants,
    )


# ---------------------------------------------------------------------------
# Cached singleton
# ---------------------------------------------------------------------------
_CFG: Optional[RoutingConfig] = None


def get_config() -> RoutingConfig:
    """Get the routing config, caching it after the first load.
    Use `reload_config()` to force a re-read (e.g. after the
    operator edits the YAML)."""
    global _CFG
    if _CFG is None:
        _CFG = load_config()
    return _CFG


def reload_config() -> RoutingConfig:
    """Force-reload the config from disk."""
    global _CFG
    _CFG = load_config()
    return _CFG


# ---------------------------------------------------------------------------
# CLI / smoke
# ---------------------------------------------------------------------------
def _print_tenant(t: TenantRouting) -> None:
    print(f"  - {t.tenant_id} ({t.display_name})")
    print(f"      auto_remediation_threshold: "
          f"{t.auto_remediation_threshold:.2f}")
    print(f"      auto_remediation_severities: "
          f"{t.auto_remediation_severities}")
    print(f"      allowed_actions: {t.allowed_actions}")
    print(f"      stig.baseline: {t.stig.baseline}  "
          f"tags: {t.stig.applicability_tags}")
    print(f"      quiet_hours: enabled={t.quiet_hours.enabled} "
          f"{t.quiet_hours.start}-{t.quiet_hours.end} "
          f"({t.quiet_hours.timezone}) overrides={t.quiet_hours.overrides}")


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="SOC per-tenant routing config (Track D, D3)")
    p.add_argument("--config", default=None,
                   help="Path to soc-routing.yaml "
                        "(default: $SOC_ROUTING_CONFIG or "
                        "config/soc-routing.yaml[.example])")
    p.add_argument("--show", action="store_true",
                   help="Print the loaded config and exit")
    p.add_argument("--smoke", action="store_true",
                   help="Self-test (no config file required)")
    args = p.parse_args(argv)

    if args.smoke:
        return _smoke()
    cfg = load_config(Path(args.config) if args.config else None)
    print(f"[soc-routing] loaded {cfg.path}")
    print(f"  tenants: {cfg.known_tenants()}")
    if args.show:
        for tid in cfg.known_tenants():
            _print_tenant(cfg.tenant(tid))
    return 0


def _smoke() -> int:
    """Self-test: validate the example config, exercise the
    TenantRouting helpers, and run a battery of bad-config
    cases. Uses a temp copy of the example config so the
    smoke is hermetic and doesn't depend on the operator
    having deployed the live config."""
    import shutil
    import tempfile
    # Copy the example config to a temp file; the smoke
    # exercises the loader via SOC_ROUTING_CONFIG.
    tmp = tempfile.mkdtemp(prefix="soc-routing-smoke-")
    tmp_cfg = os.path.join(tmp, "soc-routing.yaml")
    shutil.copy(str(FALLBACK_CONFIG_PATH), tmp_cfg)
    os.environ["SOC_ROUTING_CONFIG"] = tmp_cfg
    # Reset the cached singleton so the new env var is picked up.
    global _CFG
    _CFG = None
    try:
        return _smoke_inner()
    finally:
        if "SOC_ROUTING_CONFIG" in os.environ:
            del os.environ["SOC_ROUTING_CONFIG"]
        shutil.rmtree(tmp, ignore_errors=True)


def _smoke_inner() -> int:
    cfg = load_config()
    assert cfg.path.endswith("soc-routing.yaml"), cfg.path
    assert set(cfg.known_tenants()) == {"example-soc", "example-soc"}, \
        cfg.known_tenants()
    # bedimsecurity is the prod tenant
    bedim = cfg.tenant("example-soc")
    assert bedim.auto_remediation_threshold == 0.85
    assert "auto_remediate" in bedim.allowed_actions
    assert bedim.stig.baseline == "high"
    assert "AC" in bedim.stig.applicability_tags
    assert "page" in bedim.notification_routing["page"]
    assert "email" in bedim.notification_routing["page"]

    # can_auto_remediate
    ok, why = bedim.can_auto_remediate(confidence=0.92, severity="high")
    assert ok, why
    ok, why = bedim.can_auto_remediate(confidence=0.70, severity="high")
    assert not ok and "below threshold" in why, why
    ok, why = bedim.can_auto_remediate(confidence=0.92, severity="low")
    assert not ok and "not eligible" in why, why

    # stsgym is the demo — auto_remediation not in allowed_actions
    stsgym = cfg.tenant("example-soc")
    assert "auto_remediate" not in stsgym.allowed_actions
    ok, why = stsgym.can_auto_remediate(confidence=0.99, severity="critical")
    assert not ok and "not in allowed_actions" in why, why
    assert stsgym.stig.baseline == "moderate"

    # recipients_for
    recs = bedim.recipients_for("page", "page")
    assert recs == ["wlrobbi@bedimsecurity.com"], recs
    recs = bedim.recipients_for("email", "email")
    assert recs and "@" in recs[0], recs
    recs = bedim.recipients_for("note_only", "log")
    # bedimsecurity's defaults route note_only -> [log] and
    # the example provides a default log.audit_target. So this
    # is the audit log path.
    assert recs == ["/var/log/soc/audit.jsonl"], recs
    # But asking for a channel that's not in the routing
    # for this action returns [].
    recs = bedim.recipients_for("auto_remediate", "digest")
    assert recs == [], recs

    # quiet_hours: enable + 23:30 UTC = 19:30 NY (EDT) — not in
    # quiet hours, but we test the method, not the clock.
    assert isinstance(bedim.is_quiet_hours(), bool)
    # Test the overnight case directly: 23:00 NY should be quiet,
    # 12:00 NY should not.
    from datetime import datetime, timezone
    ny_tz = _tz_from_name("America/New_York")
    quiet_night = datetime(2026, 8, 8, 23, 0, tzinfo=ny_tz)
    quiet_morning = datetime(2026, 8, 8, 6, 30, tzinfo=ny_tz)
    day_time = datetime(2026, 8, 8, 12, 0, tzinfo=ny_tz)
    assert bedim.is_quiet_hours(quiet_night), "23:00 NY should be quiet"
    assert bedim.is_quiet_hours(quiet_morning), "06:30 NY should be quiet"
    assert not bedim.is_quiet_hours(day_time), "12:00 NY should NOT be quiet"
    # stsgym has quiet hours disabled
    assert not stsgym.is_quiet_hours(day_time)

    # Bad config cases
    def _expect_fail(yaml_text: str, needle: str) -> None:
        import tempfile
        with tempfile.NamedTemporaryFile(
                "w", suffix=".yaml", delete=False) as f:
            f.write(yaml_text)
            tmpname = f.name
        try:
            try:
                load_config(Path(tmpname))
            except RoutingError as e:
                assert needle in str(e), f"expected {needle!r} in error: {e}"
            else:
                raise AssertionError(
                    f"expected RoutingError containing {needle!r}")
        finally:
            os.unlink(tmpname)

    _expect_fail('defaults:\n  auto_remediation_threshold: 0.85\ntenants:\n  t1:\n    auto_remediation_threshold: 1.5\n', "0.0..1.0")
    _expect_fail('defaults:\n  auto_remediation_threshold: 0.85\ntenants:\n  t1:\n    auto_remediation_severities: [huge]\n', "bad severity")
    _expect_fail('defaults:\n  auto_remediation_threshold: 0.85\ntenants:\n  t1:\n    notification_routing:\n      bad_action: [email]\n', "bad action")
    _expect_fail('defaults:\n  auto_remediation_threshold: 0.85\ntenants:\n  t1:\n    notification_routing:\n      page: [carrier-pigeon]\n', "bad channel")
    _expect_fail('defaults:\n  auto_remediation_threshold: 0.85\ntenants:\n  t1:\n    quiet_hours:\n      enabled: true\n      start: "25:00"\n      end: "07:00"\n      timezone: UTC\n', "bad quiet_hours")
    _expect_fail('defaults:\n  auto_remediation_threshold: 0.85\ntenants:\n  t1:\n    allowed_actions: [nuke]\n', "bad action")
    _expect_fail('defaults:\n  auto_remediation_threshold: 0.85\ntenants:\n  t1:\n    stig:\n      baseline: extreme\n', "bad stig.baseline")
    sys.stdout.write("soc-routing smoke test: OK\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
