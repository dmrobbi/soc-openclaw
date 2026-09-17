# Tests

Pytest suite for the pure-logic modules. Run from the repo root:

    python3 -m pytest tests/ -q

Requires: pytest + pyyaml (`pip install pytest pyyaml`).

Coverage today:

- `test_tasklog.py` — services/soc_tasklog.py (jsonl round-trip,
  newest-first + dedup, history, malformed-line tolerance). Uses a
  tmp log file (patched `TASKS_LOG`), never the live
  `~/.openclaw/soc/tasks.jsonl`.
- `test_score.py` — services/soc_score.py `_compute` (score math,
  family/baseline/severity grouping, n/a exclusion).
- `test_classifier.py` — services/soc_stig_classifier.py
  (family-from-blob, benchmark matching, and
  `classify_stig_finding` against a synthetic catalogue injected via
  `SOC_STIG_RULES_DIR` — isolated from the live `config/stig-rules`).
- `test_parse_xccdf.py` — services/soc_stig.py `parse_xccdf` on a
  synthetic DISA-style XCCDF (namespace-flexible path, Profile/select
  baseline mapping, CCI/NIST idents, HTML-stripped descriptions,
  nested Groups, duplicate/invalid-input error paths).

Isolation notes:

- Catalogue tests always call `reload_catalogue()` with
  `SOC_STIG_RULES_DIR` pointed at a tmp dir — the classifier caches
  its index at module level, so never rely on import-time state.
- CI (`.github/workflows/ci.yml`) runs pytest plus a high-signal
  ruff gate (`E9,F63,F7,F82,F821`); cosmetic rules are not gated.