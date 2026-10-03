# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak._plugins
from garak.probes.av_spam_scanning import (
    EICAR_SIGNATURE,
    GTUBE_SIGNATURE,
    GTPHISH_SIGNATURE,
    REPEAT_PROMPTS,
)

EXPECTED_PROMPT_COUNT = len(REPEAT_PROMPTS)


def test_eicar_prompts():
    a = garak._plugins.load_plugin("probes.av_spam_scanning.EICAR")
    assert (
        len(a.prompts) == EXPECTED_PROMPT_COUNT
    ), f"EICAR must have {EXPECTED_PROMPT_COUNT} prompts"
    assert len(set(a.prompts)) == len(a.prompts), "No duplicate prompts should exist"
    for prompt in a.prompts:
        assert (
            EICAR_SIGNATURE in prompt
        ), "Every EICAR prompt must contain the EICAR signature"
        assert (
            GTUBE_SIGNATURE not in prompt
        ), "EICAR prompts must not contain the GTUBE signature"
        assert (
            GTPHISH_SIGNATURE not in prompt
        ), "EICAR prompts must not contain the GTphish signature"
    assert a.aliases == ["knownbadsignatures.EICAR"]
    assert a.primary_detector == "knownbadsignatures.EICAR"


def test_gtube_prompts():
    a = garak._plugins.load_plugin("probes.av_spam_scanning.GTUBE")
    assert (
        len(a.prompts) == EXPECTED_PROMPT_COUNT
    ), f"GTUBE must have {EXPECTED_PROMPT_COUNT} prompts"
    assert len(set(a.prompts)) == len(a.prompts), "No duplicate prompts should exist"
    for prompt in a.prompts:
        assert (
            GTUBE_SIGNATURE in prompt
        ), "Every GTUBE prompt must contain the GTUBE signature"
        assert (
            EICAR_SIGNATURE not in prompt
        ), "GTUBE prompts must not contain the EICAR signature"
        assert (
            GTPHISH_SIGNATURE not in prompt
        ), "GTUBE prompts must not contain the GTphish signature"
    assert a.aliases == ["knownbadsignatures.GTUBE"]
    assert a.primary_detector == "knownbadsignatures.GTUBE"


def test_gtphish_prompts():
    a = garak._plugins.load_plugin("probes.av_spam_scanning.GTphish")
    assert (
        len(a.prompts) == EXPECTED_PROMPT_COUNT
    ), f"GTphish must have {EXPECTED_PROMPT_COUNT} prompts"
    assert len(set(a.prompts)) == len(a.prompts), "No duplicate prompts should exist"
    for prompt in a.prompts:
        assert (
            GTPHISH_SIGNATURE in prompt
        ), "Every GTphish prompt must contain the GTphish signature"
        assert (
            EICAR_SIGNATURE not in prompt
        ), "GTphish prompts must not contain the EICAR signature"
        assert (
            GTUBE_SIGNATURE not in prompt
        ), "GTphish prompts must not contain the GTUBE signature"
    assert a.aliases == ["knownbadsignatures.GTphish"]
    assert a.primary_detector == "knownbadsignatures.GTphish"
