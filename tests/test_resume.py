# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for probe-level resume (garak.run_state + ProbewiseHarness)."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import garak._config as _config
from garak import run_state
from garak.harnesses.probewise import ProbewiseHarness


# ----- run_state file I/O -----------------------------------------------------


def test_create_run_writes_state_json(tmp_path, monkeypatch):
    monkeypatch.setattr(_config.transient, "data_dir", tmp_path)
    state = run_state.create_run(
        run_id="run-1",
        probe_spec="probes.a,probes.b",
        generator_name="gen.X",
        report_dir="reports",
        report_prefix="garak.run-1",
    )
    assert state["completed_probes"] == []
    path = tmp_path / "runs" / "run-1" / "state.json"
    assert path.is_file()
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["probe_spec"] == "probes.a,probes.b"
    assert saved["generator_name"] == "gen.X"


def test_load_state_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(_config.transient, "data_dir", tmp_path)
    original = run_state.create_run(
        run_id="run-2",
        probe_spec="probes.x",
        generator_name="gen.Y",
        report_dir="reports",
        report_prefix="garak.run-2",
    )
    loaded = run_state.load_state("run-2")
    assert loaded == original


def test_load_state_missing_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(_config.transient, "data_dir", tmp_path)
    with pytest.raises(FileNotFoundError):
        run_state.load_state("does-not-exist")


def test_load_state_rejects_probe_spec_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr(_config.transient, "data_dir", tmp_path)
    run_state.create_run(
        run_id="run-3",
        probe_spec="probes.original",
        generator_name="gen.Y",
        report_dir="reports",
        report_prefix="garak.run-3",
    )
    with pytest.raises(ValueError, match="probe_spec"):
        run_state.load_state(
            "run-3",
            expected_probe_spec="probes.changed",
            expected_generator="gen.Y",
        )


def test_load_state_rejects_generator_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr(_config.transient, "data_dir", tmp_path)
    run_state.create_run(
        run_id="run-4",
        probe_spec="probes.x",
        generator_name="gen.Original",
        report_dir="reports",
        report_prefix="garak.run-4",
    )
    with pytest.raises(ValueError, match="generator"):
        run_state.load_state(
            "run-4",
            expected_probe_spec="probes.x",
            expected_generator="gen.Different",
        )


def test_mark_probe_complete_appends_and_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(_config.transient, "data_dir", tmp_path)
    run_state.create_run(
        run_id="run-5",
        probe_spec="probes.x",
        generator_name="gen.Y",
        report_dir="reports",
        report_prefix="garak.run-5",
    )
    run_state.mark_probe_complete("run-5", "AntiDAN")
    run_state.mark_probe_complete("run-5", "AntiDAN")  # duplicate ignored
    run_state.mark_probe_complete("run-5", "Dan_11_0")

    state = run_state.load_state("run-5")
    assert state["completed_probes"] == ["AntiDAN", "Dan_11_0"]


# ----- harness skip behavior --------------------------------------------------


def _make_probe(class_name, primary_detector="always.Pass"):
    p = MagicMock()
    p.__class__ = type(class_name, (), {})
    p.probename = f"garak.probes.x.{class_name}"
    p.primary_detector = primary_detector
    p.extended_detectors = []
    return p


def test_harness_skips_completed_probes_on_resume(tmp_path, monkeypatch):
    """Resume run: probes whose class names are in state['completed_probes']
    must be skipped (no super().run() invocation, no probe.probe() call)."""
    monkeypatch.setattr(_config.transient, "data_dir", tmp_path)
    monkeypatch.setattr(_config.plugins, "extended_detectors", False, raising=False)
    monkeypatch.setattr(
        "garak.harnesses.base._initialize_runtime_services",
        lambda: None,
    )

    # bypass parent harness logic and just record probes that would be executed
    super_run = MagicMock()
    monkeypatch.setattr(
        "garak.harnesses.probewise.Harness.run", super_run, raising=True
    )
    monkeypatch.setattr(
        ProbewiseHarness, "_load_buffs", lambda self, names: None, raising=True
    )

    skipped = _make_probe("AlreadyDone")
    runnable = _make_probe("StillTodo")

    def load_plugin(name, *args, **kwargs):
        if name.endswith("AlreadyDone"):
            return skipped
        return runnable

    monkeypatch.setattr(
        "garak.harnesses.probewise._plugins.load_plugin", load_plugin
    )

    model = MagicMock()

    # seed state.json with one probe already complete; use the same generator
    # name format the harness will compute for ``model``
    generator_name = f"{model.__class__.__module__}.{model.__class__.__name__}"
    run_state.create_run(
        run_id="resume-1",
        probe_spec="probes.x.AlreadyDone,probes.x.StillTodo",
        generator_name=generator_name,
        report_dir=str(tmp_path / "reports"),
        report_prefix="garak.resume-1",
    )
    run_state.mark_probe_complete("resume-1", "AlreadyDone")

    # ensure the report-file rotation has a file to close
    (tmp_path / "reports").mkdir(parents=True, exist_ok=True)
    existing = tmp_path / "reports" / "garak.resume-1.report.jsonl"
    existing.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        _config.transient,
        "reportfile",
        open(existing, "w", encoding="utf-8"),
    )
    monkeypatch.setattr(_config.transient, "report_filename", str(existing))

    h = ProbewiseHarness()
    h._load_detector = MagicMock(return_value=MagicMock())
    h.run(
        model,
        ["probes.x.AlreadyDone", "probes.x.StillTodo"],
        MagicMock(),
        resume_id="resume-1",
    )

    invoked = [probe for call in super_run.call_args_list for probe in call.args[1]]
    assert skipped not in invoked, "completed probe must not be re-run"
    assert runnable in invoked, "non-completed probe must run"

    # new resume report file exists alongside (and distinct from) the original
    resume_files = list(Path(tmp_path / "reports").glob("garak.resume-1.resume_*.report.jsonl"))
    assert resume_files, "harness should rotate to a timestamped resume report file"


def test_harness_records_completion_on_fresh_run(tmp_path, monkeypatch):
    """Fresh run (no resume_id): state.json is created and each probe that
    runs is recorded as complete."""
    monkeypatch.setattr(_config.transient, "data_dir", tmp_path)
    monkeypatch.setattr(_config.transient, "run_id", "fresh-1")
    monkeypatch.setattr(
        _config.transient,
        "report_filename",
        str(tmp_path / "reports" / "garak.fresh-1.report.jsonl"),
    )
    monkeypatch.setattr(_config.plugins, "extended_detectors", False, raising=False)
    monkeypatch.setattr(
        "garak.harnesses.base._initialize_runtime_services",
        lambda: None,
    )
    monkeypatch.setattr(
        "garak.harnesses.probewise.Harness.run", MagicMock(), raising=True
    )
    monkeypatch.setattr(
        ProbewiseHarness, "_load_buffs", lambda self, names: None, raising=True
    )

    p1 = _make_probe("ProbeOne")
    p2 = _make_probe("ProbeTwo")
    by_name = {"probes.x.ProbeOne": p1, "probes.x.ProbeTwo": p2}
    monkeypatch.setattr(
        "garak.harnesses.probewise._plugins.load_plugin",
        lambda name, *a, **kw: by_name[name],
    )

    h = ProbewiseHarness()
    h._load_detector = MagicMock(return_value=MagicMock())
    h.run(MagicMock(), ["probes.x.ProbeOne", "probes.x.ProbeTwo"], MagicMock())

    state = run_state.load_state("fresh-1")
    assert state["completed_probes"] == ["ProbeOne", "ProbeTwo"]
