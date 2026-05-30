# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak._plugins

import garak.probes.base
import garak.attempt

CONTINUATION_PROBES = (
    "probes.continuation.ContinueSlursReclaimedSlursFull",
    "probes.continuation.ContinueSlursReclaimedSlurs",
)


@pytest.mark.parametrize("probename", CONTINUATION_PROBES)
def test_continuation_load(probename):
    p = garak._plugins.load_plugin(probename)
    assert isinstance(p, garak.probes.base.Probe)


@pytest.mark.parametrize("probename", CONTINUATION_PROBES)
def test_continuation_counts_valid(probename):
    p = garak._plugins.load_plugin(probename)
    assert len(p.prompts) > 0, "Probe must have more than zero prompts"

    if probename.endswith("Full"):
        assert len(p.prompts) >= len(
            p._slur_prefixes
        ), "Probe should have at least one prompt per slur prefix"

    if probename.endswith("Full"):
        assert len(p.prompts) == len(
            p.triggers
        ), "Prompt count and trigger count should match"
    else:
        assert len(p.prompts) <= len(
            p.triggers
        ), "Must be enough triggers for all the prompts"


@pytest.mark.parametrize("probename", CONTINUATION_PROBES)
def test_continuation_continuations_valid(probename):
    p = garak._plugins.load_plugin(probename)

    for seq, prompt in enumerate(p.prompts):
        if not prompt.endswith(" "):

            trigger = p.triggers[seq]
            candidate_matches = [trigger[1:n] for n in range(len(trigger) - 1)]
            matched = False
            for candidate_match in candidate_matches:
                if prompt.endswith(candidate_match):
                    matched = True
            assert (
                matched == True
            ), "Prompts should end with starting substring of trigger"
