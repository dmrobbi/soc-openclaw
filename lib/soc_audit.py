#!/usr/bin/env python3
"""SOC audit log writer (Track B, task B2 — 2026-08-07).

Append-only JSONL writer that records every SOC LLM decision so
the system is auditable, replayable, and (later) the input to the
weekly curator agent (B5) and the per-decision dashboard (D1/D2).

Schema (one line per record):
    {
      "ts": "2026-08-07T13:35:01.234+00:00",     # UTC, ISO-8601
      "runId": "uuid-v4 or openclaw-issued",     # ties all related records
      "agent_id": "soc-narrator",                 # which agent decided
      "tenant_id": "example-soc",               # multi-tenant from day 1
      "input_hash": "sha256:abc...",              # ties to full payload (no PII in log)
      "input_summary": "L12 5763 SSH brute force from 9.9.9.9 to mail.example.com",
      "input_kind": "wazuh_alert" | "inbound_email" | "decision_prompt" | ...,
      "tool_calls": [...],                        # MCP tool invocations
      "model_output": "...",                      # LLM text (truncated to 4KB)
      "model": "minimax-m3:cloud",
      "duration_ms": 9085,
      "outcome": "ok" | "timeout" | "error" | "no_text" | "filtered",
      "confidence": 0.86,                         # optional, populated by B1
      "severity_class": "high",                   # optional, populated by B1
      "recommended_response": "auto_remediate",   # optional, populated by B1
      "error": "...",                             # if outcome != ok
      "extra": {...}                              # free-form per-call-site data
    }

Design constraints (all per the roadmap doc):
  - Stdlib only. No third-party deps.
  - File-lock to avoid interleaving when multiple processes append.
  - input_hash is sha256 of the canonical-JSON of the full input
    payload; the payload itself is NOT written (PII, size). The
    "incident id" recorded in the realtime_soc JSONL ties back to
    the audit row via runId.
  - Tenant_id is required. We refuse to write a record without
    one (defence-in-depth against accidentally writing to a
    cross-tenant log).
  - Append-only. We do not provide a "delete" or "compact" path
    on the writer; the curator agent (B5) summarises + rotates.
  - Truncation: model_output is capped at 4096 chars; input_summary
    at 512 chars. Larger content is suffixed with "...[truncated]".

The module is importable as `soc_audit` and exposes a single
function `record(record_dict, path=None)` plus a `default_path()`
helper. A CLI `--smoke` flag exercises the writer end-to-end.

Created 2026-08-07 by Ciceron as part of Track B (B2).
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


# ---------------------------------------------------------------------------
# Schema constants
# ---------------------------------------------------------------------------
SCHEMA_VERSION = 1

MAX_MODEL_OUTPUT_CHARS = 4096
MAX_INPUT_SUMMARY_CHARS = 512
MAX_TOOL_CALLS = 64  # belt-and-braces; an alert should never have more

VALID_OUTCOMES = frozenset({
    "ok",            # LLM returned text + decided
    "no_text",       # LLM ran but returned nothing
    "timeout",       # subprocess / HTTP timeout
    "error",         # anything else (network, parse, etc.)
    "filtered",      # dropped by a pre-filter (noise denylist etc.)
    "low_confidence",# B1: produced a decision but below threshold
})

REQUIRED_FIELDS = ("ts", "runId", "agent_id", "tenant_id", "outcome")


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
def default_path() -> Path:
    """Resolve the audit log path.

    Resolution order:
      1. $SOC_AUDIT_LOG (explicit override)
      2. $OPENCLAW_STATE_DIR/audit_log.jsonl  (alongside the openclaw state)
      3. ~/.openclaw/audit_log.jsonl  (canonical default for the SOC host)
    """
    env = os.environ.get("SOC_AUDIT_LOG")
    if env:
        return Path(env)
    state = os.environ.get("OPENCLAW_STATE_DIR")
    if state:
        return Path(state) / "audit_log.jsonl"
    return Path.home() / ".openclaw" / "audit_log.jsonl"


def default_tenant() -> str:
    """Resolve the tenant id (multi-tenant from day 1).

    Resolution order:
      1. $SOC_TENANT_ID
      2. $WAZUH_TENANT_ID (set by the integration if known)
      3. "example-soc"  (default; the first tenant)
    """
    return (
        os.environ.get("SOC_TENANT_ID")
        or os.environ.get("WAZUH_TENANT_ID")
        or "example-soc"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _canonical_json(payload: Any) -> str:
    """Canonical JSON: sorted keys, no whitespace, UTF-8.

    Used for input_hash. Ensures the same payload always produces
    the same hash regardless of dict ordering.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def hash_input(payload: Any) -> str:
    """sha256 of the canonical JSON. Prefix `sha256:` for clarity."""
    h = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def _truncate(s: str, n: int) -> str:
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    if len(s) <= n:
        return s
    return s[: max(0, n - 14)] + "...[truncated]"


def _now() -> str:
    """UTC ISO-8601 with milliseconds, e.g. 2026-08-07T13:35:01.234+00:00."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "+00:00")  # already tz-aware; explicit
    )


def _new_run_id() -> str:
    """Return a uuid-v4. Callers may override (e.g. for parent_runId chains)."""
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def _validate(rec: Dict[str, Any]) -> None:
    """Raise ValueError if the record is missing required fields or
    has an out-of-range outcome. Defence-in-depth: bad data should
    fail loudly, not be silently dropped.
    """
    missing = [k for k in REQUIRED_FIELDS if k not in rec or rec[k] in (None, "")]
    if missing:
        raise ValueError(f"audit record missing required fields: {missing}")
    if rec["outcome"] not in VALID_OUTCOMES:
        raise ValueError(
            f"audit record outcome={rec['outcome']!r} not in {sorted(VALID_OUTCOMES)}"
        )
    if not isinstance(rec.get("runId"), str) or not rec["runId"]:
        raise ValueError("runId must be a non-empty string")
    if not isinstance(rec.get("agent_id"), str) or not rec["agent_id"]:
        raise ValueError("agent_id must be a non-empty string")
    if not isinstance(rec.get("tenant_id"), str) or not rec["tenant_id"]:
        raise ValueError("tenant_id must be a non-empty string")


# ---------------------------------------------------------------------------
# Core writer
# ---------------------------------------------------------------------------
def _ensure_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def record(
    rec: Dict[str, Any],
    *,
    path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Append one audit record to the JSONL log. Returns the
    canonicalised record (with `ts` filled in if not set, with
    `schema` stamped, with field truncations applied).

    The writer is intentionally synchronous — the SOC scripts are
    not high-volume (a few per minute at most), and we want a
    hard guarantee that the record landed before the next pipeline
    step reads it back.

    Concurrency: uses an exclusive flock on the log file. Two
    concurrent writers will serialise. There is no in-process
    queue; if you need async, use the realtime_soc_server queue
    pattern (out of scope here).
    """
    path = path or default_path()
    _ensure_dir(path)

    out = dict(rec)  # shallow copy; we don't mutate the caller's dict
    out.setdefault("ts", _now())
    out.setdefault("schema", SCHEMA_VERSION)
    if "model_output" in out and isinstance(out["model_output"], str):
        out["model_output"] = _truncate(out["model_output"], MAX_MODEL_OUTPUT_CHARS)
    if "input_summary" in out and isinstance(out["input_summary"], str):
        out["input_summary"] = _truncate(out["input_summary"], MAX_INPUT_SUMMARY_CHARS)
    if "tool_calls" in out and isinstance(out["tool_calls"], list):
        out["tool_calls"] = out["tool_calls"][:MAX_TOOL_CALLS]
    if "error" in out and isinstance(out["error"], str):
        out["error"] = _truncate(out["error"], 1024)

    _validate(out)

    line = json.dumps(out, ensure_ascii=False, default=str) + "\n"
    with open(path, "a", encoding="utf-8") as f:
        # Block until we get an exclusive lock. Other writers in
        # other processes will wait their turn. The lock is
        # released when the file handle closes.
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.write(line)
            f.flush()
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    return out


# ---------------------------------------------------------------------------
# Convenience helpers (the patterns used by the SOC call sites)
# ---------------------------------------------------------------------------
def record_llm_call(
    *,
    agent_id: str,
    response,
    input_payload: Any,
    input_kind: str = "wazuh_alert",
    input_summary: Optional[str] = None,
    tool_calls: Optional[Iterable[Dict[str, Any]]] = None,
    tenant_id: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
    run_id: Optional[str] = None,
    path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Wrap an LlmResponse-shaped object into an audit record.

    This is the function llm_runtime.py will call after every
    call_llm() invocation. Keeps the call sites tiny:

        resp = call_llm(...)
        record_llm_call(
            agent_id="soc-narrator",
            response=resp,
            input_payload=alert,
            input_summary=summary,
        )
    """
    ok = bool(getattr(response, "ok", False))
    text = getattr(response, "text", None)
    if ok and text:
        outcome = "ok"
    elif ok and not text:
        outcome = "no_text"
    else:
        err = (getattr(response, "error", "") or "").lower()
        outcome = "timeout" if "timeout" in err else "error"

    return record({
        "ts": _now(),
        "runId": run_id or getattr(response, "run_id", None) or _new_run_id(),
        "agent_id": agent_id,
        "tenant_id": tenant_id or default_tenant(),
        "input_kind": input_kind,
        "input_hash": hash_input(input_payload),
        "input_summary": input_summary or _summarise(input_payload),
        "tool_calls": list(tool_calls) if tool_calls else [],
        "model_output": text,
        "model": getattr(response, "model", None),
        "duration_ms": getattr(response, "duration_ms", None),
        "outcome": outcome,
        "error": getattr(response, "error", None) if outcome != "ok" else None,
        "extra": extra or {},
    }, path=path)


# ---------------------------------------------------------------------------
# Verification audit rows (Phase 1.3.b)
# ---------------------------------------------------------------------------
# These two wrappers exist for ONE reason: so the curator (B5) and
# any future call site can write a verification row without
# knowing the exact wire shape. The shape itself is frozen in
# docs/soc/agentic-soc-agentic-2026-08-06.md §B3.5 and
# docs/soc/soc-loop-1.2c-verify-one-shape.md §3. If you change
# the shape here, change it there too.
#
# Currently both wrappers are NOT called by soc_safety_decider
# (which inlines the record(...) call for the ticket_outcome
# ordering reason documented in 1.2.c). They exist so that
# (a) the curator can write fix_verified / verification_failed
# rows for retroactive events, and (b) test code can write
# canonical verification rows without duplicating the schema.


def write_fix_verified(
    *,
    action_id: str,
    alert: Dict[str, Any],
    apply_at: Any,
    verify_at: Any,
    verified_at: str,
    pattern: str,
    decision_run_id: Optional[str] = None,
    indexer_hits: int = 0,
    ticket_id: Optional[str] = None,
    ticket_outcome: str = "closed:auto_verified",
    path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Write a `fix_verified` audit row.

    Mirrors the schema in §B3.5 of
    `docs/soc/agentic-soc-agentic-2026-08-06.md`. Returns the
    canonicalised record (same shape as `record(...)`).

    Args:
      action_id: the apply() action_id this verification
        corresponds to.
      alert: the original alert dict (must have rule.id, agent.id
        or agent.name, data.srcip).
      apply_at: epoch seconds or ISO string. Preserved as-is
        in extra.apply_at (curator must handle both forms).
      verify_at: same.
      verified_at: ISO string (caller-computed; we don't
        re-stamp it).
      pattern: the pattern name (e.g. "block_brute_force_source").
      decision_run_id: optional, used for tenant_id inference.
      indexer_hits: 0 (this is the pass case).
      ticket_id: the ticket that was closed (or None if no
        ticket existed).
      ticket_outcome: usually "closed:auto_verified" for the
        pass case. Other values: "close_failed_retry_next_tick",
        "skipped_no_ticket".
    """
    agent = alert.get("agent") or {}
    rule = alert.get("rule") or {}
    data = alert.get("data") or {}
    alert_signature = {
        "host": str(agent.get("id") or agent.get("name") or ""),
        "rule_id": str(rule.get("id") or ""),
        "srcip": data.get("srcip"),
    }
    return record({
        "runId": f"verify-{action_id}",
        "agent_id": "soc-safety-decider",
        "tenant_id": decision_run_id or default_tenant(),
        "outcome": "ok",
        "input_kind": "fix_verified",
        "input_hash": hash_input(alert),
        "input_summary": (
            f"pattern={pattern} action_id={action_id} "
            f"srcip={data.get('srcip')}"),
        "model_output": f"fix_verified at {verified_at}",
        "extra": {
            "action_id": action_id,
            "pattern": pattern,
            "apply_at": apply_at,
            "verify_at": verify_at,
            "verified_at": verified_at,
            "alert_signature": alert_signature,
            "indexer_hits": indexer_hits,
            "ticket_id": ticket_id,
            "ticket_outcome": ticket_outcome,
        },
    }, path=path)


def write_verification_failed(
    *,
    action_id: str,
    alert: Dict[str, Any],
    apply_at: Any,
    verify_at: Any,
    verified_at: str,
    pattern: str,
    new_alert_id: str,
    decision_run_id: Optional[str] = None,
    indexer_hits: int = 1,
    ticket_id: Optional[str] = None,
    ticket_outcome: str = "reopened",
    path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Write a `verification_failed` audit row.

    Same shape as `fix_verified` but with:
      - extra.new_alert_id populated (the first new hit that
        caused the failure)
      - extra.indexer_hits >= 1
      - extra.ticket_outcome usually "reopened" (the verifier
        moved the ticket from `closed`/`open` to
        `in_progress` with a verification_failed comment)
    """
    agent = alert.get("agent") or {}
    rule = alert.get("rule") or {}
    data = alert.get("data") or {}
    alert_signature = {
        "host": str(agent.get("id") or agent.get("name") or ""),
        "rule_id": str(rule.get("id") or ""),
        "srcip": data.get("srcip"),
    }
    return record({
        "runId": f"verify-{action_id}",
        "agent_id": "soc-safety-decider",
        "tenant_id": decision_run_id or default_tenant(),
        "outcome": "ok",
        "input_kind": "verification_failed",
        "input_hash": hash_input(alert),
        "input_summary": (
            f"pattern={pattern} action_id={action_id} "
            f"srcip={data.get('srcip')}"),
        "model_output": (
            f"verification_failed at {verified_at}; "
            f"new_alert_id={new_alert_id}"),
        "extra": {
            "action_id": action_id,
            "pattern": pattern,
            "apply_at": apply_at,
            "verify_at": verify_at,
            "verified_at": verified_at,
            "alert_signature": alert_signature,
            "indexer_hits": indexer_hits,
            "new_alert_id": new_alert_id,
            "ticket_id": ticket_id,
            "ticket_outcome": ticket_outcome,
        },
    }, path=path)


def _summarise(payload: Any) -> str:
    """Best-effort one-line summary of an input payload.

    Recognises Wazuh alert shape ({rule: {...}, agent: {...}}). Falls
    back to a JSON truncation. Used only when the caller doesn't
    pass input_summary explicitly.
    """
    if not isinstance(payload, dict):
        return _truncate(_canonical_json(payload), MAX_INPUT_SUMMARY_CHARS)
    rule = payload.get("rule") or {}
    agent = payload.get("agent") or {}
    data = payload.get("data") or {}
    if rule or agent:
        parts = []
        if rule:
            parts.append(f"L{rule.get('level', '?')} {rule.get('id', '?')}")
            if rule.get("description"):
                parts.append(str(rule["description"])[:120])
        if agent:
            parts.append(f"agent={agent.get('name', '?')}")
        if data.get("srcip"):
            parts.append(f"srcip={data['srcip']}")
        if data.get("dstuser"):
            parts.append(f"dstuser={data['dstuser']}")
        return _truncate(" | ".join(p for p in parts if p), MAX_INPUT_SUMMARY_CHARS)
    return _truncate(_canonical_json(payload), MAX_INPUT_SUMMARY_CHARS)


# ---------------------------------------------------------------------------
# Reader (small; the dashboard + curator use it; not the writer's job
# but a single file is easier to ship than two)
# ---------------------------------------------------------------------------
def iter_records(
    path: Optional[Path] = None,
    *,
    tenant_id: Optional[str] = None,
    since: Optional[str] = None,
    outcome: Optional[str] = None,
) -> Iterable[Dict[str, Any]]:
    """Yield audit records, optionally filtered.

    `since` is an ISO-8601 timestamp; records strictly older are
    skipped. `tenant_id` and `outcome` are exact matches.

    A malformed line is skipped with a stderr warning (one line;
    we don't want to spam).
    """
    path = path or default_path()
    if not path.exists():
        return
    warned = False
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                if not warned:
                    sys.stderr.write(f"[soc_audit] malformed line in {path}; skipping rest\n")
                    warned = True
                continue
            if tenant_id and rec.get("tenant_id") != tenant_id:
                continue
            if outcome and rec.get("outcome") != outcome:
                continue
            if since and (rec.get("ts") or "") < since:
                continue
            yield rec


# ---------------------------------------------------------------------------
# CLI / smoke test
# ---------------------------------------------------------------------------
def _smoke() -> int:
    """Self-test: write three records, read them back, check shape."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "audit.jsonl"
        # 1. ok
        r1 = record({
            "runId": "smoke-1",
            "agent_id": "soc-narrator",
            "tenant_id": "example-soc",
            "outcome": "ok",
            "input_summary": "L12 5763 SSH brute force from 9.9.9.9 to mail.example.com",
            "input_hash": hash_input({"rule": {"id": 5763}}),
            "input_kind": "wazuh_alert",
            "model": "minimax-m3:cloud",
            "model_output": "High severity SSH brute force; investigate.",
            "duration_ms": 9085,
        }, path=log)
        # 2. timeout
        r2 = record({
            "runId": "smoke-2",
            "agent_id": "soc-triage",
            "tenant_id": "example-soc",
            "outcome": "timeout",
            "error": "timeout after 30s",
            "duration_ms": 30000,
        }, path=log)
        # 3. tenant isolation
        r3 = record({
            "runId": "smoke-3",
            "agent_id": "soc-triage",
            "tenant_id": "customer-xyz",
            "outcome": "ok",
        }, path=log)

        # Read back; verify count, schema, tenant filter
        all_recs = list(iter_records(path=log))
        assert len(all_recs) == 3, f"expected 3 records, got {len(all_recs)}"
        assert all_recs[0]["schema"] == SCHEMA_VERSION
        assert all_recs[0]["input_hash"].startswith("sha256:")
        assert all_recs[1]["outcome"] == "timeout"

        # Tenant filter
        bedim = list(iter_records(path=log, tenant_id="example-soc"))
        assert len(bedim) == 2, f"expected 2 example-soc records, got {len(bedim)}"
        cust = list(iter_records(path=log, tenant_id="customer-xyz"))
        assert len(cust) == 1, f"expected 1 customer-xyz record, got {len(cust)}"

        # Outcome filter
        oks = list(iter_records(path=log, outcome="ok"))
        assert len(oks) == 2

        # Required field validation
        try:
            record({"outcome": "ok", "agent_id": "x", "tenant_id": "y"},
                   path=log)
        except ValueError as e:
            assert "runId" in str(e)
        else:
            raise AssertionError("expected ValueError for missing runId")

        try:
            record({"runId": "x", "agent_id": "x", "tenant_id": "y",
                    "outcome": "wat"}, path=log)
        except ValueError as e:
            assert "outcome" in str(e)
        else:
            raise AssertionError("expected ValueError for bad outcome")

        # Truncation
        big = "x" * 10000
        r4 = record({
            "runId": "smoke-4",
            "agent_id": "x",
            "tenant_id": "y",
            "outcome": "ok",
            "model_output": big,
        }, path=log)
        assert r4["model_output"].endswith("...[truncated]")
        assert len(r4["model_output"]) <= MAX_MODEL_OUTPUT_CHARS

        # Concurrency: two threads writing simultaneously
        import threading
        errors: list = []
        def writer(prefix: str):
            try:
                for i in range(50):
                    record({
                        "runId": f"{prefix}-{i}",
                        "agent_id": "x",
                        "tenant_id": "y",
                        "outcome": "ok",
                    }, path=log)
            except Exception as e:
                errors.append(e)
        t1 = threading.Thread(target=writer, args=("A",))
        t2 = threading.Thread(target=writer, args=("B",))
        t1.start(); t2.start()
        t1.join(); t2.join()
        assert not errors, f"concurrent writes failed: {errors}"
        all_recs = list(iter_records(path=log))
        assert len(all_recs) == 4 + 100, f"expected 104 records, got {len(all_recs)}"

    # === Phase 1.3.b smoke: verification row wrappers ===
    # Verify that write_fix_verified + write_verification_failed
    # produce records matching the §B3.5 schema frozen in
    # docs/soc/agentic-soc-agentic-2026-08-06.md. Hermetic —
    # no network; writes to a temp file, iterates, asserts.
    print("[phase 1.3.b] write_fix_verified + write_verification_failed")
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "audit-1.3.jsonl"
        _alert = {
            "rule": {"id": "40112", "level": 12,
                     "description": "SSH brute force"},
            "agent": {"id": "002", "name": "darth",
                      "ip": "10.0.0.114"},
            "data": {"srcip": "9.9.9.9", "dstuser": "root"},
        }
        _now_iso = "2026-08-13T03:00:00.000+00:00"
        # Pass row
        rec_p = write_fix_verified(
            action_id="smoke-1.3-pass",
            alert=_alert,
            apply_at=1_700_000_000.0,
            verify_at=1_700_000_120.0,
            verified_at=_now_iso,
            pattern="block_brute_force_source",
            decision_run_id="smoke-1.3",
            indexer_hits=0,
            ticket_id="TKT-20260813-001",
            ticket_outcome="closed:auto_verified",
            path=log,
        )
        # Required top-level fields
        for f in ("runId", "agent_id", "tenant_id", "outcome",
                  "input_kind", "input_hash", "input_summary",
                  "model_output", "extra", "ts", "schema"):
            assert f in rec_p, f"missing {f} in fix_verified record"
        assert rec_p["input_kind"] == "fix_verified"
        assert rec_p["runId"] == "verify-smoke-1.3-pass"
        assert rec_p["agent_id"] == "soc-safety-decider"
        assert rec_p["tenant_id"] == "smoke-1.3"
        assert rec_p["input_hash"].startswith("sha256:")
        # Extra sub-fields (the §B3.5 contract)
        ep = rec_p["extra"]
        for f in ("action_id", "pattern", "apply_at", "verify_at",
                  "verified_at", "alert_signature", "indexer_hits",
                  "ticket_id", "ticket_outcome"):
            assert f in ep, f"missing extra.{f}"
        assert ep["action_id"] == "smoke-1.3-pass"
        assert ep["pattern"] == "block_brute_force_source"
        assert ep["indexer_hits"] == 0
        assert ep["ticket_outcome"] == "closed:auto_verified"
        # alert_signature shape
        assert set(ep["alert_signature"].keys()) == {
            "host", "rule_id", "srcip"}
        assert ep["alert_signature"]["host"] == "002"
        assert ep["alert_signature"]["rule_id"] == "40112"
        assert ep["alert_signature"]["srcip"] == "9.9.9.9"
        # Pass row should NOT have new_alert_id
        assert "new_alert_id" not in ep, (
            "fix_verified row should not have new_alert_id")
        print(f"  ✓ write_fix_verified: 14 required fields present, "
              f"alert_signature shape OK, no new_alert_id")

        # Fail row
        rec_f = write_verification_failed(
            action_id="smoke-1.3-fail",
            alert=_alert,
            apply_at=1_700_000_000.0,
            verify_at=1_700_000_120.0,
            verified_at=_now_iso,
            pattern="block_brute_force_source",
            new_alert_id="wazuh:40112:002:re-fire-1.3-smoke",
            decision_run_id="smoke-1.3",
            indexer_hits=1,
            ticket_id="TKT-20260813-002",
            ticket_outcome="reopened",
            path=log,
        )
        for f in ("runId", "agent_id", "tenant_id", "outcome",
                  "input_kind", "input_hash", "input_summary",
                  "model_output", "extra", "ts", "schema"):
            assert f in rec_f, f"missing {f} in verification_failed record"
        assert rec_f["input_kind"] == "verification_failed"
        assert rec_f["runId"] == "verify-smoke-1.3-fail"
        # model_output must mention 'verification_failed'
        assert "verification_failed" in rec_f["model_output"], (
            rec_f["model_output"])
        # Extra sub-fields
        ef = rec_f["extra"]
        for f in ("action_id", "pattern", "apply_at", "verify_at",
                  "verified_at", "alert_signature", "indexer_hits",
                  "new_alert_id", "ticket_id", "ticket_outcome"):
            assert f in ef, f"missing extra.{f}"
        assert ef["new_alert_id"] == (
            "wazuh:40112:002:re-fire-1.3-smoke")
        assert ef["indexer_hits"] == 1
        assert ef["ticket_outcome"] == "reopened"
        # alert_signature identical to pass row
        assert ef["alert_signature"] == ep["alert_signature"], (
            "alert_signature should be identical between "
            "pass and fail rows for the same alert")
        print(f"  ✓ write_verification_failed: 15 required fields "
              f"(+new_alert_id), model_output prefix OK, "
              f"alert_signature matches pass row")

        # iter_records finds both
        all_recs = list(iter_records(path=log))
        kinds = [r.get("input_kind") for r in all_recs]
        assert kinds.count("fix_verified") == 1
        assert kinds.count("verification_failed") == 1
        # input_kind filter (iter_records has no input_kind
        # filter param; filter the list ourselves)
        just_pass = [r for r in all_recs
                     if r.get("input_kind") == "fix_verified"]
        assert len(just_pass) == 1
        assert just_pass[0]["runId"] == "verify-smoke-1.3-pass"
        just_fail = [r for r in all_recs
                     if r.get("input_kind") == "verification_failed"]
        assert len(just_fail) == 1
        assert just_fail[0]["runId"] == "verify-smoke-1.3-fail"
        print(f"  ✓ iter_records finds both new rows, filter works")

    sys.stdout.write("soc_audit smoke test: OK\n")
    return 0


def _main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="SOC audit log writer / reader")
    p.add_argument("--smoke", action="store_true", help="run self-test")
    p.add_argument("--count", action="store_true",
                   help="print record count + tenant breakdown")
    p.add_argument("--last", type=int, default=0,
                   help="print the last N records (most recent)")
    p.add_argument("--tenant", default=None, help="filter by tenant_id")
    p.add_argument("--path", default=None, help="override audit log path")
    args = p.parse_args()

    if args.smoke:
        return _smoke()

    path = Path(args.path) if args.path else default_path()
    if not path.exists():
        sys.stderr.write(f"no audit log at {path}\n")
        return 1

    if args.count:
        recs = list(iter_records(path=path, tenant_id=args.tenant))
        by_tenant: Dict[str, int] = {}
        by_outcome: Dict[str, int] = {}
        for r in recs:
            by_tenant[r.get("tenant_id", "?")] = by_tenant.get(r.get("tenant_id", "?"), 0) + 1
            by_outcome[r.get("outcome", "?")] = by_outcome.get(r.get("outcome", "?"), 0) + 1
        sys.stdout.write(json.dumps({
            "path": str(path),
            "total": len(recs),
            "by_tenant": by_tenant,
            "by_outcome": by_outcome,
        }, indent=2) + "\n")
        return 0

    if args.last:
        # Read tail of file
        recs = list(iter_records(path=path, tenant_id=args.tenant))
        for r in recs[-args.last:]:
            sys.stdout.write(json.dumps(r, default=str) + "\n")
        return 0

    p.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(_main())
