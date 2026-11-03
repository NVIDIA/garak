# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: IntentProbe must not corrupt run() detectors (#2391)."""

from unittest.mock import MagicMock, patch

import garak.harnesses.base as hb
import garak.probes.base as pb
import garak.services.intentservice as intentservice
from garak.attempt import Attempt, Message


def _attempt(intent=None):
    attempt = Attempt(prompt=Message(text="hi", lang="en"))
    attempt.intent = intent
    return attempt


def _intent_probe(name):
    probe = MagicMock(spec=pb.IntentProbe)
    probe.__class__ = pb.IntentProbe
    probe.modality = {"in": {"text"}}
    probe.probename = name
    probe.probe.return_value = [_attempt("S001")]
    return probe


def _normal_probe(name):
    probe = MagicMock()
    probe.modality = {"in": {"text"}}
    probe.probename = name
    probe.probe.return_value = [_attempt()]
    return probe


def _run(probes):
    harness = hb.Harness.__new__(hb.Harness)
    harness.strict_modality_match = False
    harness._start_run_hook = lambda: None
    harness._end_run_hook = lambda: None

    model = MagicMock()
    model.modality = {"in": {"text"}}

    detector = MagicMock()
    detector.detectorname = "garak.detectors.always.Pass"
    detector.skip = False
    detector.detect.return_value = [0.0]

    detectors = [detector]
    evaluator = MagicMock()

    with (
        patch.object(hb._config.transient, "reportfile", MagicMock()),
        patch.object(intentservice, "get_detectors", return_value={"always.Pass"}),
        patch.object(hb._plugins, "load_plugin", return_value=detector),
        patch.object(hb, "_emit_plugin_cache_entry", lambda *a: None),
    ):
        harness.run(model, probes, detectors, evaluator)
    return detectors, detector, evaluator


def test_intent_probe_then_normal_probe_keeps_detectors():
    detectors, detector, evaluator = _run(
        [_intent_probe("intent.Probe"), _normal_probe("normal.Probe")]
    )

    assert detectors == [detector], "run() must not reassign detectors argument"
    assert evaluator.evaluate.call_count == 2, "both probes must be evaluated"
    normal_attempt = evaluator.evaluate.call_args_list[1].args[0][0]
    assert normal_attempt.detector_results.get("always.Pass") == [
        0.0
    ], "second probe must be scored with detector object"


def test_two_intent_probes_in_row():
    detectors, detector, evaluator = _run(
        [_intent_probe("intent.One"), _intent_probe("intent.Two")]
    )

    assert detectors == [detector], "run() must not reassign detectors argument"
    assert evaluator.evaluate.call_count == 2, "both IntentProbes must be evaluated"
