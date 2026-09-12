#!/usr/bin/env python3
"""LLM runtime adapter (SOC A1).

Wraps the openclaw agent harness subprocess so SOC scripts (the
realtime_soc_server, imap_idle_watcher, agentic-soc-send) can call a
single helper and stay runtime-agnostic.

Why this exists (2026-08-06). Both `imap_idle_watcher.py` and
`agentic-soc-send.py` had ad-hoc LLM call paths:

  - imap_idle_watcher used `urllib.request` against Ollama's
    /api/generate HTTP API directly.
  - agentic-soc-send.py used `subprocess.run(["openclaw", "ask", ...])`
    but `openclaw ask` does NOT exist in OpenClaw 2026.7.1 — so the
    email narrative has been silently skipped for weeks.

This module replaces both with one subprocess call to
`openclaw agent --agent <id> --message <text> --json`, plus a
pluggable fallback to direct Ollama HTTP for environments that
don't yet have an openclaw agent registered.

Runtime selection (priority order):
  1. `runtime` argument (explicit).
  2. `SOC_LLM_RUNTIME` env var ("openclaw" or "ollama").
  3. Default: "openclaw" — the SOC scripts are SOC-bound.

Each runtime returns a normalised LlmResponse with the same shape:

    LlmResponse(
        ok=bool,
        text=str|None,
        run_id=str|None,
        duration_ms=int|None,
        model=str|None,
        usage=dict|None,
        runtime=str,
        error=str|None,
        raw=dict|None,
    )

Stdlib only. No third-party deps. Tested 2026-08-06 against
openclaw 2026.7.1 (live harness invocation, 5s response) and
ollama /api/generate (live).

Audit logging (Track B, B2 — 2026-08-07): every successful call
through this module records one row in the SOC audit log
(`soc_audit.record_llm_call`). Disable per-call with
`audit=False`; disable globally with `SOC_AUDIT_DISABLED=1`.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# Default agents (created via `openclaw agents add ... --non-interactive`
# on 2026-08-06). These IDs are referenced by the SOC scripts.
# ---------------------------------------------------------------------------
DEFAULT_AGENTS = {
    "soc-narrator": "Writes 2-4 sentence analyst summaries for Wazuh "
                    "alert emails. Reads structured JSON, produces "
                    "terse natural-language prose.",
    "soc-replier":  "Drafts replies to inbound allowlisted SOC emails. "
                    "Uses incident context + live Wazuh state to "
                    "answer status / count questions concretely.",
    "soc-triage":   "Per-alert triage. Decides severity, recommended "
                    "response, and confidence. Used by the realtime "
                    "SOC server.",
    "soc-incident-reviewer": "Weekly curated-memory pass. Reads the "
                    "JSONL audit log and proposes MEMORY.md updates "
                    "and playbook additions.",
}


@dataclass
class LlmResponse:
    ok: bool
    text: Optional[str]
    run_id: Optional[str] = None
    duration_ms: Optional[int] = None
    model: Optional[str] = None
    usage: Optional[Dict[str, Any]] = None
    runtime: str = "openclaw"
    error: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# openclaw runtime
# ---------------------------------------------------------------------------
def _resolve_openclaw_path() -> str:
    """Locate the `openclaw` binary, with safe fallbacks for cron.

    Cron on Debian/Ubuntu runs with PATH=/usr/bin:/bin by default,
    which omits both /usr/local/bin and /home/wez/.npm-global/bin
    where the openclaw runtime is typically installed. Trying
    `shutil.which` first respects any PATH the caller (or a wrapper
    script) has set, then falls back to the two known absolute paths.

    Returns the absolute path. Raises FileNotFoundError if no
    candidate is found (the caller's `except FileNotFoundError`
    handler converts that to a clean error message).
    """
    found = shutil.which("openclaw")
    if found:
        return found
    for candidate in (
        "/usr/local/bin/openclaw",
        "/home/wez/.npm-global/bin/openclaw",
    ):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    # Last-ditch: surface the standard error so the caller can
    # produce its usual "binary not on PATH" message.
    raise FileNotFoundError("openclaw")


def call_openclaw(
    agent_id: str,
    message: str,
    *,
    system: Optional[str] = None,
    timeout: float = 30.0,
    extra_args: Optional[list] = None,
) -> LlmResponse:
    """Invoke `openclaw agent --agent <id> --message <text> --json`.

    Returns an LlmResponse. On any failure returns ok=False with
    `error` populated. Never raises — call sites can decide what to
    do with a failed LLM call (the SOC agent's current behaviour is
    'fall back to the raw alert + log warning').

    Note (2026-08-06): openclaw 2026.7.1 does NOT accept a
    `--system` flag on `openclaw agent`. The system prompt comes
    from the agent's IDENTITY.md / AGENTS.md. The `system` argument
    is therefore accepted (for future compatibility) but currently
    not passed; callers that need ad-hoc system instructions
    should bake them into the agent's AGENTS.md instead.

    Note (2026-08-09): we resolve `openclaw` via an absolute path
    so cron-launched curators (PATH=/usr/bin:/bin) can find it.
    """
    cmd = [
        _resolve_openclaw_path(), "agent",
        "--agent", agent_id,
        "--message", message,
        "--json",
    ]
    if extra_args:
        cmd.extend(extra_args)

    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        return LlmResponse(
            ok=False, text=None, runtime="openclaw",
            error=f"timeout after {timeout}s",
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    except FileNotFoundError:
        return LlmResponse(
            ok=False, text=None, runtime="openclaw",
            error="openclaw binary not on PATH",
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    except Exception as e:
        return LlmResponse(
            ok=False, text=None, runtime="openclaw",
            error=f"subprocess error: {e!r}",
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    elapsed_ms = int((time.monotonic() - started) * 1000)
    if proc.returncode != 0:
        return LlmResponse(
            ok=False, text=None, runtime="openclaw",
            error=f"non-zero exit {proc.returncode}: "
                  f"{(proc.stderr or '').strip()[:300]}",
            duration_ms=elapsed_ms,
        )

    # Parse JSON; tolerate non-JSON output by returning raw text.
    raw_text = (proc.stdout or "").strip()
    if not raw_text:
        return LlmResponse(
            ok=False, text=None, runtime="openclaw",
            error="empty stdout from openclaw agent",
            duration_ms=elapsed_ms,
        )
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        return LlmResponse(
            ok=True, text=raw_text, runtime="openclaw",
            run_id=None, duration_ms=elapsed_ms,
            model=None, usage=None, raw={"stdout_raw": True},
        )

    # OpenClaw 2026.7.1 response shapes (two variants observed):
    #
    #   A) Top-level (trooper2 SOC gateway):
    #      {"payloads": [{"text": "...", "mediaUrl": null}, ...],
    #       "meta": {"durationMs": N, "agentMeta": {"model": "...",
    #                "sessionId": "..."}, "aborted": false,
    #                "usage": {...}, ...}}
    #
    #   B) Wrapped (thing1 main gateway):
    #      {"runId": "...", "status": "ok", "summary": "completed",
    #       "result": {"payloads": [...], "meta": {...}}}
    #
    # We try the wrapped shape first (most explicit), then fall back
    # to the top-level shape. Success signals in either shape:
    #   - subprocess returned 0 (checked above)
    #   - meta.aborted is false (or absent)
    #   - payloads has at least one entry with a non-empty text field
    #   - for the wrapped shape: top-level status == "ok"
    if "result" in parsed and isinstance(parsed["result"], dict):
        body = parsed["result"]
        top_status = parsed.get("status")
    else:
        body = parsed
        top_status = None
    text = None
    payloads = body.get("payloads") or []
    if isinstance(payloads, list) and payloads:
        first = payloads[0]
        if isinstance(first, dict):
            t = first.get("text") or first.get("mediaUrl")
            if isinstance(t, str):
                text = t.strip() or None
    meta = body.get("meta") or {}
    agent_meta = meta.get("agentMeta") or {}
    usage = meta.get("usage") or meta.get("lastCallUsage") or None
    aborted = bool(meta.get("aborted"))

    # ok iff: (not aborted) AND (non-empty text) AND (no explicit top-level
    # failure status if one is present). Wrapped shape with status:err
    # also fails.
    ok = (not aborted) and bool(text) and (top_status is None
                                            or top_status == "ok")

    error = None
    if not ok:
        if aborted:
            error = f"openclaw agent aborted: {meta.get('abortReason', 'unknown')}"
        elif top_status and top_status != "ok":
            error = f"openclaw status={top_status} summary={parsed.get('summary')}"
        elif not text:
            error = "openclaw agent returned no text payload"
        else:
            error = "openclaw agent returned empty/error response"

    return LlmResponse(
        ok=ok,
        text=text,
        run_id=parsed.get("runId") or agent_meta.get("sessionId"),
        duration_ms=meta.get("durationMs") or elapsed_ms,
        model=agent_meta.get("model"),
        usage=usage,
        runtime="openclaw",
        error=None if parsed.get("status") == "ok" else
              f"openclaw status={parsed.get('status')} "
              f"summary={parsed.get('summary')}",
        raw=parsed,
    )


# ---------------------------------------------------------------------------
# Direct Ollama runtime (fallback for environments without openclaw agents)
# ---------------------------------------------------------------------------
def call_ollama(
    prompt: str,
    *,
    system: Optional[str] = None,
    model: str = "minimax-m3:cloud",
    timeout: float = 30.0,
    base_url: Optional[str] = None,
) -> LlmResponse:
    """Direct Ollama HTTP /api/generate call. Same LlmResponse shape.

    Used when `runtime == "ollama"` is forced (e.g. tests, or
    environments where the openclaw harness isn't available).
    """
    base_url = (
        base_url
        or os.environ.get("OLLAMA_HOST")
        or "http://127.0.0.1:11434"
    ).rstrip("/")
    body = json.dumps({
        "model": model,
        "system": system or "",
        "prompt": prompt,
        "stream": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/api/generate",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        elapsed_ms = int((time.monotonic() - started) * 1000)
    except urllib.error.URLError as e:
        return LlmResponse(
            ok=False, text=None, runtime="ollama",
            error=f"http error: {e!r}",
        )
    except Exception as e:
        return LlmResponse(
            ok=False, text=None, runtime="ollama",
            error=f"unexpected error: {e!r}",
        )

    out = (data.get("response") or "").strip()
    return LlmResponse(
        ok=bool(out),
        text=out or None,
        run_id=None,
        duration_ms=elapsed_ms,
        model=model,
        usage=None,
        runtime="ollama",
        error=None if out else "empty response from ollama",
        raw=data,
    )


# ---------------------------------------------------------------------------
# Public dispatcher
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Audit logging (Track B, B2)
#
# When SOC_AUDIT_DISABLED != "1", every call through this module
# records one row in the audit log. The audit module is
# imported lazily so the SOC scripts that don't need it don't
# pay the import cost (and so the test suite doesn't need to
# have a writable audit log dir).
# ---------------------------------------------------------------------------
_AUDIT_DISABLED = os.environ.get("SOC_AUDIT_DISABLED", "0") == "1"
_audit = None
def _get_audit():
    global _audit
    if _audit is None:
        try:
            from soc_audit import record_llm_call  # type: ignore
            _audit = record_llm_call
        except Exception:
            # Audit module unavailable; treat as disabled.
            _audit = False
    return _audit


def call_llm(
    *,
    runtime: Optional[str] = None,
    agent_id: Optional[str] = None,
    message: Optional[str] = None,
    prompt: Optional[str] = None,
    system: Optional[str] = None,
    timeout: float = 30.0,
    audit: bool = True,
    audit_input: Any = None,
    audit_input_kind: str = "llm_prompt",
    audit_input_summary: Optional[str] = None,
    audit_run_id: Optional[str] = None,
    audit_extra: Optional[Dict[str, Any]] = None,
    **kwargs,
) -> LlmResponse:
    """Single entry point. Choose runtime via arg or env.

    For the openclaw runtime, pass `agent_id` + `message`.
    For the ollama runtime, pass `prompt` (and optionally `system`).
    Both surfaces are kept so call sites that don't need an
    agent persona can fall back to raw Ollama without losing the
    observability shape.

    Audit logging: by default every invocation produces one
    audit row. Pass `audit=False` to skip, or use the
    `audit_input*` kwargs to attach payload context for the
    audit row's input_hash + input_summary.
    """
    runtime = (
        runtime
        or os.environ.get("SOC_LLM_RUNTIME")
        or "openclaw"
    ).lower()

    if runtime == "openclaw":
        if not agent_id or not message:
            resp = LlmResponse(
                ok=False, text=None, runtime="openclaw",
                error="openclaw runtime requires agent_id and message",
            )
        else:
            resp = call_openclaw(
                agent_id, message,
                system=system, timeout=timeout,
                extra_args=kwargs.get("extra_args"),
            )
    elif runtime == "ollama":
        if prompt is None:
            prompt = message or ""
        resp = call_ollama(
            prompt, system=system, timeout=timeout,
            model=kwargs.get("model", "minimax-m3:cloud"),
            base_url=kwargs.get("base_url"),
        )
    else:
        resp = LlmResponse(
            ok=False, text=None, runtime=runtime,
            error=f"unknown runtime: {runtime!r}",
        )

    # Audit (Track B, B2). Lazy import; never breaks the call.
    if audit and not _AUDIT_DISABLED:
        rec = _get_audit()
        if rec:
            try:
                rec(
                    agent_id=agent_id or f"ollama:{kwargs.get('model', 'minimax-m3:cloud')}",
                    response=resp,
                    input_payload=(audit_input if audit_input is not None
                                   else {"message": message, "prompt": prompt,
                                         "system": system}),
                    input_kind=audit_input_kind,
                    input_summary=audit_input_summary,
                    run_id=audit_run_id,
                    extra=audit_extra,
                )
            except Exception as e:
                # Audit must never break the call path. Log to stderr.
                sys.stderr.write(f"[llm_runtime] audit failed: {e!r}\n")

    return resp


# ---------------------------------------------------------------------------
# CLI for ad-hoc testing
# ---------------------------------------------------------------------------
def _main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="SOC LLM runtime helper")
    p.add_argument("--runtime", choices=["openclaw", "ollama"], default=None)
    p.add_argument("--agent", help="openclaw agent id (e.g. soc-narrator)")
    p.add_argument("--message", help="message text (openclaw)")
    p.add_argument("--prompt", help="prompt text (ollama)")
    p.add_argument("--system", default=None)
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()

    r = call_llm(
        runtime=args.runtime,
        agent_id=args.agent,
        message=args.message,
        prompt=args.prompt,
        system=args.system,
        timeout=args.timeout,
    )

    if args.quiet:
        # Just the text, nothing else — useful for piping.
        sys.stdout.write(r.text or "")
        sys.stdout.write("\n")
    else:
        sys.stdout.write(json.dumps(r.to_dict(), indent=2, default=str))
        sys.stdout.write("\n")

    return 0 if r.ok else 1


if __name__ == "__main__":
    sys.exit(_main())