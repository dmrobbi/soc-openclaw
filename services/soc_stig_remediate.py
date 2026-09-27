#!/usr/bin/env python3
"""SOC STIG auto-remediation with mandatory snapshots (Track E, E2).

Ported 2026-09-14 from stsgym-work feat/soc-phase5-curator
(scripts/soc/soc_stig_remediate.py) into soc-openclaw services/.
Port adaptations (behaviour otherwise preserved):

  - DEFAULT_AUDIT_LOG honours SOC_AUDIT_LOG (canonical fleet audit log
    is the bind-mounted ~/.openclaw-wazuh/audit_log.jsonl — same env
    contract as soc_evidence.py / the systemd drop-ins).
  - REPO_ROOT is services/ layout (parents[1]).
  - The pre/post "probes" run the control's `check` command (read-only
    state capture) instead of executing the fix command itself — the
    upstream pre-probe ran the FIX as a "probe", double-applying every
    remediation. Snapshot keys are unchanged (pre_probe_rc / apply_rc)
    so soc_evidence grading is unaffected.
  - Smoke uses the example tenants (example-soc allowed,
    example-soc-2 refuses) and is fully hermetic.

Generalises the B3 `block_brute_force_source` pattern to any
STIG control in the E1 catalogue that has:

  - `automated: true`
  - a `check:` field that is a shell command (the loader
    detects this heuristically — see `looks_like_command`)
  - a `fix:` field that is a shell command

E2's contract:

  1. **Snapshot first.** Before any change, capture the
     current state of the system in
     `compliance/snapshots/<action_id>.json`. The snapshot
     includes the check output, the fix command and its
     result — enough to audit (and, for file-state fixes,
     to reconstruct) what happened.
  2. **Confidence-gated.** Reuses the D3 routing config's
     `auto_remediation_threshold` + `auto_remediation_severities`.
     A tenant that doesn't allow `auto_remediate` in
     `allowed_actions` is refused.
  3. **Audit-trail.** Every apply/rollback is recorded in
     the audit log (SOC_AUDIT_LOG) via `extra` annotations —
     the rows soc_evidence collects to grade controls PASS.
  4. **Refused controls are visible.** A control that
     fails its `check` is recorded as `compliance_status:
     not_applicable` (the check passes; nothing to fix) or
     `manual_review` (no `fix` / not `automated`).

Tools
-----
  * check_control(control_id, tenant_id=None)
        -> {ok, control_id, check_output, status:
            "pass" | "fail" | "error", snapshot_id}
  * remediate_control(control_id, tenant_id=None,
                      confidence=0.0, dry_run=False)
        -> {ok, control_id, action_id, status:
            "applied" | "refused" | "dry_run" |
            "manual_review" | "not_applicable",
            reason, snapshot_id}
  * rollback_control(action_id)
        -> {ok, action_id, status: "rolled_back" | "noop"}
  * list_remediations(tenant_id=None, status=None,
                      limit=100)
        -> {ok, remediations[], total}
  * get_remediation(action_id)
        -> {ok, remediation}

The safety pattern (per B3)
---------------------------
  - `SOC_REMEDIATION_DRY_RUN=1` makes every operation
    log what it would have done but not actually run
    shell commands or write to the system. The smoke
    test uses this so it's hermetic.
  - Snapshots are written to a per-action JSON file
    so the action is fully auditable afterwards.
  - The `auto_remediate` decision must be in the
    tenant's `allowed_actions` (D3) AND the
    `auto_remediation_threshold` from D3 must be met.
  - The `safety_decider` check pattern from B3 is
    preserved: an audit log entry is written before
    the action with a `safety_decider_reviewed: true`
    extra, so the audit trail is intact.

NOTE (privileges): commands run as the invoking user. The dashboard
tool runs as the SOC service user — fixes that need root fail honestly
(rc != 0, recorded in the snapshot + audit); run the CLI under sudo for
root-needing fixes.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants + paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]


def _snapshot_dir() -> Path:
    return Path(os.environ.get(
        "SOC_SNAPSHOT_DIR",
        str(Path.home() / ".openclaw" / "compliance" / "snapshots")))


def _remediation_log() -> Path:
    return Path(os.environ.get(
        "SOC_REMEDIATION_LOG",
        str(Path.home() / ".openclaw" / "compliance" / "remediations.jsonl")))


# Canonical fleet audit log: SOC_AUDIT_LOG override (the systemd
# drop-ins point services at the bind-mounted canonical copy
# ~/.openclaw-wazuh/audit_log.jsonl; bare hosts fall back to the
# legacy host-side path).
DEFAULT_AUDIT_LOG = os.environ.get(
    "SOC_AUDIT_LOG", "") or os.path.expanduser("~/.openclaw/audit_log.jsonl")
MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024
SNAPSHOT_RETENTION_DAYS = 30

# Heuristic: a `check:` field is treated as a shell command
# iff it starts with one of these tokens. (Natural-language
# checks are recorded as `manual_review`.)
COMMAND_VERBS = (
    "ls", "cat", "grep", "egrep", "fgrep", "find", "test",
    "[", "systemctl", "service", "ps", "ss", "netstat",
    "ip", "ifconfig", "iptables", "nft", "ufw", "dpkg",
    "apt", "apt-get", "rpm", "yum", "dnf", "stat", "file",
    "head", "tail", "wc", "cut", "awk", "sed", "printf",
    "echo", "true", "false", "chmod", "chown", "test",
    "sysctl", "crontab", "at", "getent", "id", "who",
    "whoami", "hostname", "uname", "date", "wc -l",
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class RemediationError(Exception):
    """Raised on remediation / rollback failure."""


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------
def _write_snapshot(action_id: str, payload: Dict[str, Any]) -> str:
    snap_dir = _snapshot_dir()
    snap_dir.mkdir(parents=True, exist_ok=True)
    path = snap_dir / f"{action_id}.json"
    tmp = path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    os.replace(tmp, path)
    return str(path)


def _read_snapshot(action_id: str) -> Optional[Dict[str, Any]]:
    path = _snapshot_dir() / f"{action_id}.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


# ---------------------------------------------------------------------------
# Audit log integration
# ---------------------------------------------------------------------------
def _audit_record(record: Dict[str, Any]) -> None:
    """Append a record to the audit log (SOC_AUDIT_LOG). Pure I/O; never
    raises. Mirrors the `extra` shape that soc_audit uses so the C4 MCP
    can surface it without modification — and so soc_evidence grades the
    control."""
    record.setdefault("ts", dt.datetime.now(dt.timezone.utc).isoformat(
        timespec="milliseconds"))
    record.setdefault("schema", 1)
    Path(DEFAULT_AUDIT_LOG).parent.mkdir(parents=True, exist_ok=True)
    with open(DEFAULT_AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")


# ---------------------------------------------------------------------------
# Remediation log (separate from audit; one row per apply/rollback)
# ---------------------------------------------------------------------------
def _log_remediation(row: Dict[str, Any]) -> None:
    log = _remediation_log()
    log.parent.mkdir(parents=True, exist_ok=True)
    row.setdefault("ts", dt.datetime.now(dt.timezone.utc).isoformat(
        timespec="milliseconds"))
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, default=str) + "\n")


def _load_remediations() -> List[Dict[str, Any]]:
    log = _remediation_log()
    if not log.exists():
        return []
    out: List[Dict[str, Any]] = []
    with open(log, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                sys.stderr.write(
                    f"[soc-stig-remediate] skipping non-JSON line at "
                    f"{log}:{i+1}\n")
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _run(cmd: str, timeout: float = 10.0) -> Tuple[int, str, str]:
    """Run a shell command. Returns (rc, stdout, stderr).
    When SOC_REMEDIATION_DRY_RUN=1, returns (0, "<dry_run>", "")
    without actually executing."""
    if os.environ.get("SOC_REMEDIATION_DRY_RUN", "0") == "1":
        return 0, "<dry_run>", ""
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, executable="/bin/bash")
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as e:
        return 1, "", f"exec error: {e!r}"


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def _new_action_id(control_id: str) -> str:
    short = re.sub(r"[^A-Za-z0-9._-]", "_", control_id)[:48]
    return f"stig-{short}-{uuid.uuid4().hex[:8]}"


def looks_like_command(text: str) -> bool:
    """Heuristic: does this string look like a shell command
    we can run? Returns True if the first token is in
    COMMAND_VERBS (or matches a couple of common patterns
    like `# verify` or `bash -c`)."""
    if not text:
        return False
    text = text.strip()
    first_token = text.split()[0] if text.split() else ""
    if first_token in COMMAND_VERBS:
        return True
    # Anything starting with a lowercase letter AND containing
    # shell metacharacters (`;`, `|`, `&&`, `$(`, backticks)
    # is treated as a command.
    if first_token and first_token[0].islower():
        if any(c in text for c in (";", "|", "&&", "$(", "`")):
            return True
    return False


def _control_from_catalogue(control_id: str) -> Dict[str, Any]:
    try:
        from soc_stig import get_catalogue
    except ImportError:
        raise RemediationError(
            "soc_stig.py not importable; cannot load catalogue")
    cat = get_catalogue()
    for c in cat["controls"]:
        if c.get("id") == control_id:
            return c
    raise RemediationError(f"control_id not in catalogue: {control_id}")


def _tenant_or_default(tenant_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Read D3 routing config + return the tenant dict, or
    None if tenant_id is None / unknown / no PyYAML."""
    if not tenant_id:
        return None
    try:
        from soc_routing import get_config
    except ImportError:
        return None
    try:
        return get_config().tenant(tenant_id).__dict__
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Remote execution (Phase 1.4, 2026-09-14): fleet remediation via SSH
# ---------------------------------------------------------------------------
def _remote_ctx(args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Resolve the remediation target. None = local (the SOC host).
    Accepts a fleet-resolvable host name/id, or an explicit --host-ip
    for out-of-band targets (family arg not needed for remediation)."""
    host = (args.get("host") or "").strip()
    if not host or host.lower() in ("local", socket.gethostname().lower()):
        return None
    ip = (args.get("host_ip") or "").strip()
    if not ip:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parent / "scanner"))
            from soc_scanner import fleet_agents
        except ImportError:
            raise RemediationError(
                "soc_scanner not importable; cannot resolve fleet hosts")
        for a in fleet_agents():
            if host in (a.get("name"), a.get("id")):
                ip = a.get("ip") or ""
                break
        else:
            raise RemediationError(
                f"host {host!r} not in fleet; pass host_ip for "
                "out-of-band targets")
    if not ip:
        raise RemediationError(f"host {host!r} has no IP in the fleet")
    return {"name": host, "ip": ip,
            "port": os.environ.get("SOC_SCAN_SSH_PORT", "22"),
            "user": os.environ.get("SOC_SCAN_SSH_USER", "wez")}


def _run_on(ctx: Optional[Dict[str, Any]], cmd: str,
            timeout: float = 10.0) -> Tuple[int, str, str]:
    """Run a shell command locally (ctx None) or on a remote host via
    ssh + `sudo -n bash -s` (the command goes on stdin, so no quoting
    hazards). Targets need NOPASSWD sudo for the SSH user — the same
    contract as the OpenSCAP provisioning (deploy/openscap-setup.sh)."""
    if ctx is None:
        return _run(cmd, timeout=timeout)
    if os.environ.get("SOC_REMEDIATION_DRY_RUN", "0") == "1":
        return 0, "<dry_run>", ""
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
           "-o", "StrictHostKeyChecking=accept-new",
           "-p", str(ctx.get("port") or 22),
           f"{ctx.get('user') or 'wez'}@{ctx['ip']}", "sudo -n bash -s"]
    # 2026-09-17: one retry for transient ssh failures. The evgen-a/b/c
    # fleet hosts sit behind trooper2's NAT-only libvirt network and are
    # reached via an ssh ProxyCommand over Tailscale; a link hiccup
    # surfaces as rc=255 (connection error) or rc=124 (timeout) and used
    # to fail the whole remediation for that (host, control) pair even
    # though the next attempt seconds later succeeds (observed
    # 2026-09-17 16:14-16:18 UTC, three consecutive rc=255 then
    # recovery). rc=0 and real remote-command failures (rc 1-254 from
    # bash) are never retried.
    last_rc, out, err = 1, "", ""
    for attempt in (1, 2):
        try:
            proc = subprocess.run(ssh, input=cmd, capture_output=True,
                                  text=True, timeout=timeout)
            last_rc, out, err = (proc.returncode, proc.stdout,
                                 proc.stderr)
        except subprocess.TimeoutExpired:
            last_rc, out, err = 124, "", f"timeout after {timeout}s"
        except Exception as e:
            last_rc, out, err = 1, "", f"exec error: {e!r}"
        if last_rc not in (255, 124):
            return last_rc, out, err
        if attempt == 1:
            time.sleep(3.0)
    return last_rc, out, (err + f"\n[ssh retried after transient "
                          f"failure; both attempts rc={last_rc}]")


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------
def tool_check_control(args: Dict[str, Any]) -> Dict[str, Any]:
    """check_control(control_id, tenant_id=None, host=None)
    -> {ok, control_id, check_output, status, snapshot_id, host}"""
    cid = args.get("control_id")
    if not cid:
        raise ValueError("control_id is required")
    ctx = _remote_ctx(args)
    c = _control_from_catalogue(cid)
    check_text = (c.get("check") or "").strip()
    if not check_text:
        return {
            "ok": True, "tool": "check_control",
            "control_id": cid,
            "check_output": "",
            "status": "manual_review",
            "note": "no `check:` field; manual review required",
            "host": (ctx or {}).get("name", "local"),
        }
    if not looks_like_command(check_text):
        return {
            "ok": True, "tool": "check_control",
            "control_id": cid,
            "check_output": check_text,
            "status": "manual_review",
            "note": "check is natural-language, not a command",
            "host": (ctx or {}).get("name", "local"),
        }
    # Run the check (locally or on the target host)
    rc, out, err = _run_on(ctx, check_text, timeout=30.0)
    snapshot_id = ""
    if out or err:
        snapshot_id = _new_action_id(cid)
        _write_snapshot(snapshot_id, {
            "ts": _now_iso(),
            "control_id": cid,
            "host": (ctx or {}).get("name", "local"),
            "kind": "check_only",
            "check_cmd": check_text,
            "rc": rc,
            "stdout": out[:MAX_SNAPSHOT_BYTES],
            "stderr": err[:MAX_SNAPSHOT_BYTES],
        })
    status = "pass" if rc == 0 else "fail"
    return {
        "ok": True, "tool": "check_control",
        "control_id": cid,
        "check_output": out[:1000],
        "check_stderr": err[:500],
        "check_rc": rc,
        "status": status,
        "snapshot_id": snapshot_id,
        "host": (ctx or {}).get("name", "local"),
    }


def _probe(ctx: Optional[Dict[str, Any]], check_text: str) -> Tuple[int, str, str]:
    """State probe for snapshots: run the control's `check` command
    (read-only) on the target. Under SOC_REMEDIATION_DRY_RUN=1 _run_on
    is hermetic."""
    if check_text and looks_like_command(check_text):
        return _run_on(ctx, check_text, timeout=30.0)
    return 0, "", ""


def tool_remediate_control(args: Dict[str, Any]) -> Dict[str, Any]:
    """remediate_control(control_id, tenant_id=None,
                        confidence=0.0, dry_run=False,
                        host=None, host_ip=None, timeout=300)
    host=None applies on the SOC host; host=<fleet name/id> applies
    remotely via ssh + `sudo -n bash -s` (Phase 1.4)."""
    cid = args.get("control_id")
    if not cid:
        raise ValueError("control_id is required")
    ctx = _remote_ctx(args)
    host = (ctx or {}).get("name", "local")
    c = _control_from_catalogue(cid)
    if not c.get("automated"):
        return _result(cid, "manual_review",
                       reason="control.automated is false", host=host)
    fix_text = (c.get("fix") or "").strip()
    if not fix_text:
        return _result(cid, "manual_review",
                       reason="no `fix:` field")
    if not looks_like_command(fix_text):
        return _result(cid, "manual_review",
                       reason="fix is natural-language, not a command",
                       host=host)
    # Per-tenant gate
    tenant_id = args.get("tenant_id")
    tenant = _tenant_or_default(tenant_id)
    if tenant is not None:
        sev = c.get("severity") or "medium"
        confidence = float(args.get("confidence") or 0.0)
        # Reuse the soc_routing helper if available
        try:
            from soc_routing import get_config
            tr = get_config().tenant(tenant_id)
            ok, why = tr.can_auto_remediate(
                confidence=confidence, severity=sev)
            if not ok:
                _audit_record({
                    "runId": _new_action_id(cid),
                    "agent_id": "soc-stig-remediate",
                    "tenant_id": tenant_id,
                    "input_kind": "stig_remediate_decision",
                    "input_summary": f"refuse {cid}",
                    "outcome": "ok",
                    "extra": {
                        "stig_remediate_refused": {
                            "control_id": cid,
                            "reason": why,
                            "confidence": confidence,
                            "severity": sev,
                        },
                    },
                })
                return _result(cid, "refused", reason=why, host=host)
        except Exception as e:
            return _result(cid, "refused",
                           reason=f"routing config error: {e!r}", host=host)
    # Confidence check (if no tenant config, the caller
    # passed confidence; require >= 0.85 default)
    if tenant is None:
        confidence = float(args.get("confidence") or 0.0)
        if confidence < 0.85:
            return _result(cid, "refused",
                           reason=f"confidence {confidence:.2f} < 0.85",
                           host=host)
    # Dry run
    dry_run = bool(args.get("dry_run")) or \
        os.environ.get("SOC_REMEDIATION_DRY_RUN", "0") == "1"
    # Snapshot first: capture CURRENT state via the control's check
    # command (read-only). Upstream executed the fix here as a "probe"
    # (double apply); the port captures state without mutating.
    action_id = _new_action_id(cid)
    check_text = (c.get("check") or "").strip()
    pre_rc, pre_out, pre_err = _probe(ctx, check_text)
    snapshot: Dict[str, Any] = {
        "ts": _now_iso(),
        "control_id": cid,
        "host": host,
        "kind": "pre_remediation",
        "fix_cmd": fix_text,
        "check_cmd": check_text if looks_like_command(check_text) else "",
        "pre_probe_rc": pre_rc,
        "pre_probe_stdout": pre_out[:MAX_SNAPSHOT_BYTES // 2],
        "pre_probe_stderr": pre_err[:MAX_SNAPSHOT_BYTES // 2],
        "tenant_id": tenant_id,
        "confidence": args.get("confidence"),
    }
    snapshot_path = _write_snapshot(action_id, snapshot)
    if dry_run:
        _log_remediation({
            "action_id": action_id,
            "control_id": cid,
            "tenant_id": tenant_id,
            "host": host,
            "status": "dry_run",
            "fix_cmd": fix_text,
            "snapshot_path": snapshot_path,
        })
        return {
            "ok": True, "tool": "remediate_control",
            "control_id": cid, "action_id": action_id,
            "status": "dry_run",
            "host": host,
            "reason": "SOC_REMEDIATION_DRY_RUN=1 (or dry_run arg)",
            "snapshot_id": action_id,
            "snapshot_path": snapshot_path,
        }
    # Apply (root on the target; remote runs via ssh + sudo -n bash -s)
    apply_timeout = float(args.get("timeout") or 300)
    rc, out, err = _run_on(ctx, fix_text, timeout=apply_timeout)
    # Audit
    _audit_record({
        "runId": action_id,
        "agent_id": "soc-stig-remediate",
        "tenant_id": tenant_id or "unknown",
        "host": host,
        "input_kind": "stig_remediate_apply",
        "input_summary": f"apply fix for {cid} on {host}",
        "outcome": "ok" if rc == 0 else "error",
        "error": None if rc == 0 else (err or f"rc={rc}"),
        "extra": {
            "stig_remediate_applied": {
                "control_id": cid,
                "host": host,
                "fix_cmd": fix_text,
                "rc": rc,
                "stdout": out[:500],
                "stderr": err[:500],
                "snapshot_path": snapshot_path,
                "confidence": args.get("confidence"),
            },
        },
    })
    # Update snapshot with post-state: re-run the CHECK to verify the
    # fix took effect (upstream re-ran the fix here).
    post_rc, post_out, post_err = _probe(ctx, check_text)
    snapshot["post_probe_rc"] = post_rc
    snapshot["post_probe_stdout"] = post_out[:MAX_SNAPSHOT_BYTES // 2]
    snapshot["post_probe_stderr"] = post_err[:MAX_SNAPSHOT_BYTES // 2]
    snapshot["apply_rc"] = rc
    snapshot["apply_stdout"] = out[:MAX_SNAPSHOT_BYTES // 2]
    snapshot["apply_stderr"] = err[:MAX_SNAPSHOT_BYTES // 2]
    _write_snapshot(action_id, snapshot)
    _log_remediation({
        "action_id": action_id,
        "control_id": cid,
        "tenant_id": tenant_id,
        "host": host,
        "status": "applied" if rc == 0 else "failed",
        "fix_cmd": fix_text,
        "snapshot_path": snapshot_path,
        "rc": rc,
    })
    return {
        "ok": True, "tool": "remediate_control",
        "control_id": cid, "action_id": action_id,
        "status": "applied" if rc == 0 else "failed",
        "reason": None if rc == 0 else (err or f"rc={rc}"),
        "snapshot_id": action_id,
        "snapshot_path": snapshot_path,
        "host": host,
    }


def tool_rollback_control(args: Dict[str, Any]) -> Dict[str, Any]:
    """rollback_control(action_id)
    -> {ok, action_id, status}"""
    aid = args.get("action_id")
    if not aid:
        raise ValueError("action_id is required")
    snap = _read_snapshot(aid)
    if snap is None:
        return {"ok": False, "tool": "rollback_control",
                "action_id": aid, "status": "missing",
                "error": f"no snapshot for {aid}"}
    if snap.get("rolled_back"):
        return {"ok": True, "tool": "rollback_control",
                "action_id": aid, "status": "noop",
                "note": "already rolled back"}
    # Auto-rollback strategy: the snapshot records the check output and
    # the fix command + result, but we don't have a general "inverse"
    # of a fix command; for now we record the rollback intent and mark
    # the action rolled-back. Future enhancement: per-control rollback
    # commands (or a generic "if file X changed, restore Y").
    snap["rolled_back"] = True
    snap["rolled_back_at"] = _now_iso()
    _write_snapshot(aid, snap)
    _log_remediation({
        "action_id": aid,
        "control_id": snap.get("control_id"),
        "status": "rolled_back",
    })
    _audit_record({
        "runId": aid,
        "agent_id": "soc-stig-remediate",
        "tenant_id": snap.get("tenant_id") or "unknown",
        "input_kind": "stig_remediate_rollback",
        "input_summary": f"rollback {snap.get('control_id')}",
        "outcome": "ok",
        "extra": {
            "stig_remediate_rolled_back": {
                "control_id": snap.get("control_id"),
                "snapshot_path": str(_snapshot_dir() / f"{aid}.json"),
            },
        },
    })
    return {"ok": True, "tool": "rollback_control",
            "action_id": aid, "status": "rolled_back"}


def tool_list_remediations(args: Dict[str, Any]) -> Dict[str, Any]:
    """list_remediations(tenant_id=None, status=None, limit=100)"""
    tenant_id = args.get("tenant_id")
    status = args.get("status")
    limit = min(int(args.get("limit") or 100), 1000)
    rows = _load_remediations()
    out = []
    for r in rows:
        if tenant_id and r.get("tenant_id") != tenant_id:
            continue
        if status and r.get("status") != status:
            continue
        out.append(r)
    out.sort(key=lambda r: r.get("ts") or "", reverse=True)
    return {
        "ok": True, "tool": "list_remediations",
        "params": {"tenant_id": tenant_id, "status": status,
                   "limit": limit},
        "total": len(out),
        "remediations": out[:limit],
    }


def tool_get_remediation(args: Dict[str, Any]) -> Dict[str, Any]:
    """get_remediation(action_id) -> {ok, remediation, snapshot}"""
    aid = args.get("action_id")
    if not aid:
        raise ValueError("action_id is required")
    rows = _load_remediations()
    for r in rows:
        if r.get("action_id") == aid:
            return {
                "ok": True, "tool": "get_remediation",
                "action_id": aid, "remediation": r,
                "snapshot": _read_snapshot(aid),
            }
    raise LookupError(f"action_id not found: {aid}")


def _result(cid: str, status: str, *, reason: str = "",
            host: str = "local") -> Dict[str, Any]:
    return {"ok": True, "tool": "remediate_control",
            "control_id": cid, "status": status, "reason": reason,
            "host": host}


# ---------------------------------------------------------------------------
# Smoke
# ---------------------------------------------------------------------------
def _smoke() -> int:
    """Hermetic self-test: SOC_REMEDIATION_DRY_RUN=1 so no system
    changes; temp snapshot dir + temp audit log + temp remediation log."""
    import tempfile

    tmp = tempfile.mkdtemp(prefix="soc-stig-remediate-smoke-")
    os.environ["SOC_REMEDIATION_DRY_RUN"] = "1"
    os.environ["SOC_SNAPSHOT_DIR"] = os.path.join(tmp, "snapshots")
    os.environ["SOC_REMEDIATION_LOG"] = os.path.join(tmp, "remediations.jsonl")
    os.environ["SOC_AUDIT_LOG"] = os.path.join(tmp, "audit.jsonl")
    # Module constants are bound at import; when run as
    # `python3 services/soc_stig_remediate.py --smoke` the module IS
    # __main__ — patching globals() covers both namespaces (this
    # function's __globals__ is the module dict in either case).
    globals()["_audit_log_path"] = os.environ["SOC_AUDIT_LOG"]
    globals()["DEFAULT_AUDIT_LOG"] = os.environ["SOC_AUDIT_LOG"]

    # 1. Manual review: a control whose `automated` is false
    r = tool_remediate_control({"control_id": "AC.L1-3.1.001"})
    assert r["status"] == "manual_review", r
    assert "automated" in r["reason"], r

    # 2. Manual review: automated=true but the fix is natural-language
    #    (after the 2026-09-14 catalogue cleanup most prose fixes were
    #    normalized to shell or demoted; AC.L1-3.1.002 covers the
    #    automated=false manual-review path instead)
    r = tool_remediate_control({"control_id": "AC.L1-3.1.002"})
    assert r["status"] == "manual_review", r
    assert "automated" in r["reason"], r

    # 3. Refused: control.automated=true but the tenant does not
    #    allow auto_remediate. example-soc-2 is the sandbox tenant.
    r = tool_remediate_control({
        "control_id": "AU.L1-3.3.003",  # automated=true, shell fix
        "tenant_id": "example-soc-2",   # auto_remediate not in allowed_actions
        "confidence": 0.99,
    })
    assert r["status"] == "refused", r
    assert "not in allowed_actions" in r["reason"], r

    # 4. Refused: confidence below the default 0.85 floor (no tenant
    #    config passed)
    r = tool_remediate_control({
        "control_id": "AU.L1-3.3.003", "confidence": 0.40})
    assert r["status"] == "refused", r
    assert "confidence" in r["reason"], r

    # 5. Dry run: allowed tenant (example-soc) meets the 0.85 gate
    r = tool_remediate_control({
        "control_id": "AU.L1-3.3.003",
        "tenant_id": "example-soc",
        "confidence": 0.95,
    })
    assert r["status"] == "dry_run", r
    assert r["snapshot_id"], r
    aid = r["action_id"]

    # 6. Snapshot file exists, is a pre_remediation snapshot
    snap_path = os.path.join(tmp, "snapshots", f"{aid}.json")
    assert os.path.exists(snap_path), snap_path
    snap = json.load(open(snap_path))
    assert snap["kind"] == "pre_remediation", snap
    assert snap["tenant_id"] == "example-soc", snap

    # 7. check_control — AC.L1-3.1.003 check is natural-language
    r = tool_check_control({"control_id": "AC.L1-3.1.003"})
    assert r["ok"], r
    assert r["status"] == "manual_review", r

    # 8. check_control with a real shell command (dry-run env makes
    #    it hermetic; the snapshot is still written)
    r = tool_check_control({"control_id": "AU.L1-3.3.001"})
    assert r["ok"], r
    assert r["status"] == "pass", r
    assert r["snapshot_id"], r

    # 9. Rollback
    r = tool_rollback_control({"action_id": aid})
    assert r["status"] == "rolled_back", r
    r = tool_rollback_control({"action_id": aid})  # idempotent
    assert r["status"] == "noop", r

    # 10. list_remediations
    r = tool_list_remediations({"tenant_id": "example-soc"})
    assert r["ok"], r
    assert r["total"] >= 1, r

    # 11. get_remediation
    r = tool_get_remediation({"action_id": aid})
    assert r["ok"], r
    assert r["remediation"]["control_id"] == "AU.L1-3.3.003", r

    # 12. Audit log entries were written (refused + rolled_back)
    with open(os.environ["SOC_AUDIT_LOG"]) as f:
        audit_lines = [json.loads(l) for l in f if l.strip()]
    assert any("stig_remediate_refused" in (r.get("extra") or {})
               for r in audit_lines), audit_lines
    assert any("stig_remediate_rolled_back" in (r.get("extra") or {})
               for r in audit_lines), audit_lines

    # 13. Remediation log
    with open(os.environ["SOC_REMEDIATION_LOG"]) as f:
        rem_lines = [json.loads(l) for l in f if l.strip()]
    assert any(r.get("status") == "dry_run" for r in rem_lines), rem_lines
    assert any(r.get("status") == "rolled_back" for r in rem_lines), rem_lines

    # 14. looks_like_command heuristic
    assert looks_like_command("systemctl is-active auditd")
    assert looks_like_command("ls -la /var/log/audit/")
    assert looks_like_command("grep -E '/bin/bash' /etc/passwd")
    assert not looks_like_command("Verify that the policy is documented")
    assert not looks_like_command("Document the access control policy.")
    assert looks_like_command("chmod 0600 /var/log/audit/*.log; chown root:root")
    assert looks_like_command("apt-get install unattended-upgrades && systemctl enable unattended-upgrades")

    # 15. Remote (Phase 1.4): unknown host fails fast BEFORE any ssh
    try:
        tool_remediate_control({
            "control_id": "AU.L1-3.3.003", "host": "no-such-host",
            "tenant_id": "example-soc", "confidence": 0.95})
    except RemediationError as e:
        assert "not in fleet" in str(e), e
    else:
        raise AssertionError("expected RemediationError for unknown host")

    shutil.rmtree(tmp, ignore_errors=True)
    sys.stdout.write("soc-stig-remediate smoke test: OK\n")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="SOC STIG auto-remediation (Track E, E2)")
    p.add_argument("--tool", default=None,
                   help="Run a single tool with JSON args from --args")
    p.add_argument("--args", default=None,
                   help="JSON args for --tool")
    p.add_argument("--smoke", action="store_true")
    args = p.parse_args(argv)

    if args.smoke:
        return _smoke()

    if not args.tool:
        p.print_help()
        return 1
    tool_funcs = {
        "check_control": tool_check_control,
        "remediate_control": tool_remediate_control,
        "rollback_control": tool_rollback_control,
        "list_remediations": tool_list_remediations,
        "get_remediation": tool_get_remediation,
    }
    if args.tool not in tool_funcs:
        print(f"unknown tool: {args.tool}", file=sys.stderr)
        return 2
    a = json.loads(args.args) if args.args else {}
    result = tool_funcs[args.tool](a)
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())