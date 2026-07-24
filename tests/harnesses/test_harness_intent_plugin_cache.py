# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for plugin_cache registration on the IntentProbe path.

``garak.harnesses.base.Harness.run`` snapshots the plugin cache once at run
start (``base.py``: ``_emit_plugin_cache_entry``) using only the detectors
passed in by the harness. For ``IntentProbe`` runs the detectors that actually
score the attempts are resolved later via ``intentservice.get_detectors`` and
loaded inside the run loop, so without an extra emission they never reach the
report's ``plugin_cache`` snapshot. ``report_digest.build_digest`` then rejects
the report with ``ReportIncompatibleError`` because the intent-resolved
detector has no metadata.

These tests exercise the real ``intentservice`` integration (no mocking of the
emission) with a registered ``IntentProbe`` class and the offline ``test.Repeat``
generator, using the single mapped intent ``M010`` -> ``any.AnyNonspaceOutput``
to avoid the unrelated detector-less-intent path.
"""

import json

import pytest

import garak._config
import garak._plugins
import garak.attempt
import garak.harnesses.base
from garak.analyze import report_digest
from garak.evaluators.base import ThresholdEvaluator
from garak.exception import ReportIncompatibleError
from garak.services import intentservice

MAPPED_INTENT = "M010"
INTENT_DETECTOR = "detectors.any.AnyNonspaceOutput"
INTENT_PROBE = "probes.grandma.GrandmaIntent"


def _make_attempt(intent_code: str) -> garak.attempt.Attempt:
    a = garak.attempt.Attempt(
        prompt=garak.attempt.Message(text="probe prompt", lang="*"),
        intent=intent_code,
        seq=0,
    )
    # probes set probe_classname (unprefixed) on each attempt; the evaluator
    # relies on it, so mirror that for the stubbed probe() output.
    a.probe_classname = "grandma.GrandmaIntent"
    a.outputs = [garak.attempt.Message(text="model response", lang="*")]
    return a


@pytest.fixture
def intent_report(tmp_path, monkeypatch):
    """Run the harness over an IntentProbe with the real intentservice and
    return the path to the produced report.jsonl.

    The probe's ``probe()`` is replaced with a single fixed ``M010`` attempt so
    the run is fast; everything else (intent resolution, detector loading,
    plugin_cache emission, evaluation) uses the production code paths.
    """
    garak._config.load_config()
    garak._config.run.generations = 1
    garak._config.transient.intent_spec = MAPPED_INTENT
    garak._config.run.serve_detectorless_intents = False

    report_path = tmp_path / "intent_plugin_cache.report.jsonl"
    garak._config.transient.report_filename = str(report_path)
    garak._config.transient.reportfile = report_path.open(
        "w", buffering=1, encoding="utf-8"
    )
    garak._config.transient.run_id = "test-run-intent-plugin-cache"
    garak._config.buffmanager.buffs = []

    # minimal header records so report_digest.build_digest can run
    garak._config.transient.reportfile.write(
        json.dumps(
            {
                "entry_type": "start_run setup",
                "plugins.probe_spec": "grandma.GrandmaIntent",
                "plugins.target_type": "test",
                "plugins.target_name": "Repeat",
            }
        )
        + "\n"
    )
    garak._config.transient.reportfile.write(
        json.dumps(
            {
                "entry_type": "init",
                "garak_version": garak._config.version,
                "start_time": "2026-01-01T00:00:00",
                "run": garak._config.transient.run_id,
            }
        )
        + "\n"
    )

    intentservice.load()

    model = garak._plugins.load_plugin("generators.test.Repeat")
    probe = garak._plugins.load_plugin(INTENT_PROBE)
    monkeypatch.setattr(
        probe, "probe", lambda generator: [_make_attempt(MAPPED_INTENT)]
    )
    detector = garak._plugins.load_plugin("detectors.always.Pass")

    harness = garak.harnesses.base.Harness()
    harness.run(model, [probe], [detector], ThresholdEvaluator())

    garak._config.transient.reportfile.flush()
    # config_cleanup finalizer closes the reportfile and reloads _config
    return report_path


def _plugin_cache_detectors(report_path) -> set:
    detectors = set()
    for line in report_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("entry_type") == "plugin_cache":
            detectors.update(record["plugin_cache"].get("detectors", {}))
    return detectors


def test_intent_path_detectors_registered_in_plugin_cache(intent_report):
    """The intent-resolved detector must appear in the report's plugin_cache."""
    detectors = _plugin_cache_detectors(intent_report)
    assert INTENT_DETECTOR in detectors, (
        f"intent-resolved detector {INTENT_DETECTOR} missing from plugin_cache "
        f"snapshot; found: {sorted(detectors)}"
    )


def test_report_digest_completes_for_intent_run(intent_report):
    """report_digest must build a digest for an IntentProbe run without raising
    ReportIncompatibleError for the intent-resolved detector."""
    try:
        digest = report_digest.build_digest(str(intent_report))
    except ReportIncompatibleError as e:
        pytest.fail(
            f"build_digest rejected an IntentProbe report (intent detector "
            f"missing from plugin_cache): {e}"
        )
    assert digest is not None, "build_digest returned no digest for intent run"
