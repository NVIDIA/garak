# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import List, Tuple
import garak._plugins
from garak.attempt import Attempt, Message
import garak.detectors.base
import garak.detectors.mitigation


def test_mitigation_init():
    d = garak.detectors.mitigation.MitigationBypass()
    assert isinstance(d, garak.detectors.base.Detector)


_EMPTY_OUTPUTS = ["", "   ", "\t", "\n"]


def test_mitigation_empty_output_inconclusive():
    """MitigationBypass: empty/whitespace outputs must be inconclusive (None), not a hit.

    Without this guard, StringDetector returns 0.0 (no refusal keyword found) and
    MitigationBypass inverts that to 1.0 — a false-positive jailbreak hit (#1114)."""
    d = garak.detectors.mitigation.MitigationBypass()
    lang = d.lang_spec.split(",")[0]
    for empty in _EMPTY_OUTPUTS:
        attempt = Attempt(prompt=Message(text="testing prompt", lang=lang))
        attempt.outputs = [Message(empty)]
        results = d.detect(attempt)
        assert results == [None], (
            f"MitigationBypass: empty output {repr(empty)} should be inconclusive (None)"
        )


def test_prefixes_empty_output_inconclusive():
    """Prefixes: empty/whitespace outputs must be inconclusive (None), not a hit.

    Same inversion hazard as MitigationBypass — an empty response has no refusal
    prefix, so the base returns 0.0 which would flip to 1.0 (#1114)."""
    d = garak.detectors.mitigation.Prefixes()
    lang = d.lang_spec.split(",")[0]
    for empty in _EMPTY_OUTPUTS:
        attempt = Attempt(prompt=Message(text="testing prompt", lang=lang))
        attempt.outputs = [Message(empty)]
        results = d.detect(attempt)
        assert results == [None], (
            f"Prefixes: empty output {repr(empty)} should be inconclusive (None)"
        )


def test_mitigation_strings(mitigation_outputs: Tuple[List[str], List[str]]) -> None:
    COMPLYING_OUTPUTS, REFUSAL_OUTPUTS = mitigation_outputs
    d = garak._plugins.load_plugin("detectors.mitigation.MitigationBypass")
    attempt = Attempt(
        prompt=Message(text="testing prompt", lang=d.lang_spec.split(",")[0])
    )
    attempt.outputs = COMPLYING_OUTPUTS + REFUSAL_OUTPUTS
    assert d.detect(attempt) == [1.0] * len(COMPLYING_OUTPUTS) + [0.0] * len(
        REFUSAL_OUTPUTS
    )
