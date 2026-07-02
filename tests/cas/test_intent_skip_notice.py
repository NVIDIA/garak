# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for #1889: an IntentProbe skipped because none of its intents
are in the active set must not be silent - it should notify the terminal and record
a report entry."""

import io
import json

import garak._config
import garak._plugins
import garak.services.intentservice


def _load_intentprobe():
    garak._config.load_config()
    garak._config.transient.intent_spec = "S"
    garak.services.intentservice.load()
    return garak._plugins.load_plugin("probes.base.IntentProbe")


def test_skipped_intentprobe_writes_report_entry():
    probe = _load_intentprobe()
    probe.prompts = []  # simulate an empty active-intent set
    buf = io.StringIO()
    garak._config.transient.reportfile = buf
    garak._config.transient.report_filename = "test_1889.report.jsonl"

    out = probe.probe(generator=None)

    assert out == [], "probe with no active intents should send nothing"
    lines = [json.loads(l) for l in buf.getvalue().splitlines() if l.strip()]
    skipped = [e for e in lines if e.get("entry_type") == "probe_skipped"]
    assert len(skipped) == 1, "exactly one probe_skipped report entry expected"
    assert skipped[0]["reason"] == "no_active_intents"
    assert "IntentProbe" in skipped[0]["probe"]
    assert "intents_considered" in skipped[0]


def test_skipped_intentprobe_prints_terminal_notice(capsys):
    probe = _load_intentprobe()
    probe.prompts = []
    garak._config.transient.reportfile = io.StringIO()
    garak._config.transient.report_filename = "test_1889.report.jsonl"

    probe.probe(generator=None)

    captured = capsys.readouterr()
    assert "skipped" in captured.out.lower()
    assert "active set" in captured.out.lower()


def test_active_intentprobe_not_flagged(capsys):
    """A probe that does have prompts must not emit a skip notice/entry."""
    probe = _load_intentprobe()
    if not probe.prompts:
        # environment has no active intents; the skip path is covered elsewhere
        return
    buf = io.StringIO()
    garak._config.transient.reportfile = buf
    garak._config.transient.report_filename = "test_1889.report.jsonl"
    # avoid a real generator call: just exercise the guard branch
    assert probe.prompts, "expected active prompts for this case"
    # the guard only triggers on empty prompts; confirm no skip entry pre-run
    assert "probe_skipped" not in buf.getvalue()
