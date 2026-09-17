"""Unit tests for services/soc_tasklog.py (pure jsonl logic)."""
from __future__ import annotations

import json

import soc_tasklog as tl


def test_record_and_load_roundtrip(tmp_tasks_log):
    tid = tl.record_task(
        "compliance_scan", "thing1", "running", "2026-09-17T10:00:00Z",
        details={"profile": "CIS L2"})
    assert tid == tl._task_id("2026-09-17T10:00:00Z", "compliance_scan", "thing1")
    rows = tl.load_tasks()
    assert len(rows) == 1
    assert rows[0]["kind"] == "compliance_scan"
    assert rows[0]["target"] == "thing1"
    assert rows[0]["status"] == "running"
    assert rows[0]["details"] == {"profile": "CIS L2"}


def test_missing_file_loads_empty(tmp_tasks_log):
    assert tl.load_tasks() == []
    assert tl.get_task("whatever") is None


def test_load_newest_first_and_limit(tmp_tasks_log):
    for ts in ("2026-09-17T10:00:00Z", "2026-09-17T11:00:00Z",
               "2026-09-17T12:00:00Z"):
        tl.record_task("compliance_scan", "thing1", "running", ts)
    rows = tl.load_tasks()
    assert [r["ts"] for r in rows] == [
        "2026-09-17T12:00:00Z", "2026-09-17T11:00:00Z",
        "2026-09-17T10:00:00Z"]
    assert len(tl.load_tasks(limit=2)) == 2
    assert len(tl.load_tasks(limit=0)) == 1  # max(1, limit) floor


def test_latest_row_wins_dedup(tmp_tasks_log):
    tid = tl.record_task("run_scan", "cactus", "running",
                         "2026-09-17T10:00:00Z")
    # same ts+kind+target -> same id; append a "done" row for it
    tl.record_task("run_scan", "cactus", "done", "2026-09-17T10:00:00Z",
                   ended="2026-09-17T10:05:00Z")
    rows = tl.load_tasks()
    assert len(rows) == 1
    assert rows[0]["id"] == tid
    assert rows[0]["status"] == "done"
    assert rows[0]["ended"] == "2026-09-17T10:05:00Z"


def test_get_task_history(tmp_tasks_log):
    tid = tl.record_task("run_scan", "cactus", "running",
                         "2026-09-17T10:00:00Z")
    tl.record_task("run_scan", "cactus", "done", "2026-09-17T10:00:00Z")
    task = tl.get_task(tid)
    assert task["status"] == "done"
    assert len(task["history"]) == 2
    assert task["history"][0]["status"] == "running"


def test_malformed_lines_skipped(tmp_tasks_log):
    tid = tl.record_task("run_scan", "vader", "done", "2026-09-17T10:00:00Z")
    with open(tmp_tasks_log, "a", encoding="utf-8") as f:
        f.write("not json\n")
        f.write('{"id": "", "ts": "x"}\n')  # no id -> ignored
        f.write("\n")
    rows = tl.load_tasks()
    assert [r["id"] for r in rows] == [tid]