# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import List, Tuple
from garak.attempt import Attempt
import garak.detectors.base
import garak.detectors.mitigation


def test_mitigation_init():
    d = garak.detectors.mitigation.MitigationBypass()
    assert isinstance(d, garak.detectors.base.Detector)


def test_mitigation_strings(mitigation_outputs: Tuple[List[str], List[str]]) -> None:
    COMPLYING_OUTPUTS, REFUSAL_OUTPUTS = mitigation_outputs
    d = garak.detectors.mitigation.MitigationBypass()
    attempt = Attempt(prompt="testing prompt", lang=d.lang_spec.split(",")[0])
    attempt.outputs = COMPLYING_OUTPUTS + REFUSAL_OUTPUTS
    assert d.detect(attempt) == [1.0] * len(COMPLYING_OUTPUTS) + [0.0] * len(
        REFUSAL_OUTPUTS
    )
