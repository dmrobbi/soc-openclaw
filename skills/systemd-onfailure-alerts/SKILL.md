---
name: "systemd-onfailure-alerts"
description: "Failed systemd OnFailure alert sidecar, TimeoutStartSec timeout kill, doubled @unit.service.service name. Diagnose journal, bound delivery, verify forced run."
---

# Repairing failed systemd OnFailure alert sidecars

Trigger: an `<x>-alert@<unit>.service` unit shows `failed` in
`systemctl list-units`, or an alert unit died with `Failed with result
'timeout'` under a `TimeoutStartSec`. Goal: green alert plumbing with
the fix mirrored in the live unit, the deploy template, and the repo.

## Steps

1. Enumerate all instances before diagnosing: run
   `systemctl list-units '<alert-template>@*' --all --no-legend`.
   OnFailure templating errors instantiate units under wrong names (a
   doubled suffix like `alert@unit.service.service`) while the
   correctly named instance looks clean and inactive — status of the
   "obvious" name can waste a cycle. Then journal the exact failed
   name: `sudo journalctl -u '<failed-name>' -n 50` (plain user reads
   miss system journal lines; use sudo). Complete when the journal
   shows the failure mode.

2. Classify from the journal before editing anything:
   `Failed with result 'timeout'` with low `Consumed ... CPU time` =
   the main process blocked on an unbounded external call (network or
   CLI hang), not a code bug. The failure date may be days old — stale
   failed state persists until reset, so do not assume it is failing
   now. Non-zero exits or stderr lines point at the script or config
   instead. Complete when the cause is named with the journal line
   quoted.

3. Fix OnFailure templating in the parent unit: `%n` already carries
   its `.service` suffix, so `OnFailure=<alert>@%n.service` produces a
   doubled instance (`alert@unit.service.service`) and `%i` ends with
   `.service.service`. Write `OnFailure=<alert>@%n` — unit references
   auto-append `.service`, so `%i` becomes exactly the failed unit's
   name the script expects. Apply to the live unit, its deploy
   template, and the repo copy, then verify:
   `sudo systemd-analyze verify <parent-unit> <alert-template>`.
   Complete when verify is clean (pre-existing unrelated warnings are
   tolerated, note them).

4. Bound every external delivery call in the alert script so all
   steps fit inside the unit's `TimeoutStartSec`: wrap each external
   call as `timeout -k 5 <cap> <cmd>` plus the tool's own budget flag
   when one exists (e.g. a CLI `--timeout <seconds>`), and keep the
   sum of caps plus each fallback's budget below `TimeoutStartSec`.
   A `timeout` exit is falsy, so it falls through to the next
   fallback like any other delivery failure. Complete when every
   ExecStart code path provably finishes inside the window.

5. Reset and prove: `sudo systemctl daemon-reload && sudo systemctl
   reset-failed '<stale-instance>'`, confirm
   `systemctl list-units '<alert-template>@*' --all` shows no failed
   instances, then force `sudo systemctl start <parent-unit>` and
   require `Result=success` with the alert instance not triggered (or
   one clean delivery if the parent genuinely fails). Do not fabricate
   a failure to exercise the alert path — note that the fixed delivery
   branch gets its live proof on the next real failure. Complete when
   the forced run is green and no failed instances remain.

6. Mirror the fix everywhere it lives: the live deployed copy, the
   deploy/templates source (rendered placeholders like __SOC_USER__
   make the files differ textually — the OnFailure/ExecStart lines
   must still match), and the repo checkout; commit and publish.
   Complete when the repo commit contains the same fix as /etc and
   /opt.
