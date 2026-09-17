# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for #1889: a probe left with no prompts (e.g. an IntentProbe whose intents
are all outside the active set) must be skipped cleanly - logged, not printed, and not
written to the report - instead of crashing on ``prompts[0]`` or running silently."""

import io
import logging

import garak._config
import garak._plugins
import garak.services.intentservice


def _load_intentprobe():
    garak._config.load_config()
    garak._config.transient.intent_spec = "S"
    garak.services.intentservice.load()
    return garak._plugins.load_plugin("probes.base.IntentProbe")


def test_probe_with_no_prompts_returns_empty_and_logs(caplog):
    probe = _load_intentprobe()
    probe.prompts = []  # simulate an empty active-intent set
    with caplog.at_level(logging.INFO):
        out = probe.probe(generator=None)
    assert out == []
    assert any("no prompts to send" in r.message for r in caplog.records)


def test_probe_with_no_prompts_writes_nothing_to_report():
    probe = _load_intentprobe()
    probe.prompts = []
    buf = io.StringIO()
    garak._config.transient.reportfile = buf
    garak._config.transient.report_filename = "test_1889.report.jsonl"
    probe.probe(generator=None)
    assert buf.getvalue() == "", "a skipped probe must not write to the report"


def test_probe_with_no_prompts_no_stdout(capsys):
    probe = _load_intentprobe()
    probe.prompts = []
    garak._config.transient.reportfile = io.StringIO()
    garak._config.transient.report_filename = "test_1889.report.jsonl"
    capsys.readouterr()  # discard stdout produced during loading
    probe.probe(generator=None)
    assert capsys.readouterr().out == "", "probes must not write to stdout"
