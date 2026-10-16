# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak import _config, _plugins
from garak.attempt import Attempt, Message
from garak.detectors.base import TriggerListDetector
import garak.probes.base
import garak.probes.hiddencontext

HIDDENCONTEXT_PROBES = [
    classname
    for (classname, active) in _plugins.enumerate_plugins("probes")
    if classname.startswith("probes.hiddencontext")
]


# Getting number of prompts
def _uncapped_prompt_count(probe) -> int:
    """Size of the cartesian product the probe assembles, before any pruning."""
    return (
        len(probe.top_instructions)
        * len(probe.contexts)
        * len(probe.elicitations)
        * len(probe.secrets)
    )


def test_hiddencontext_probes_discovered():
    assert len(HIDDENCONTEXT_PROBES) > 0, "no hiddencontext probes were enumerated"
    for classname, active in _plugins.enumerate_plugins("probes"):
        if not classname.startswith("probes.hiddencontext"):
            continue
        if classname.endswith("Full"):
            assert (
                active is False
            ), f"{classname} yields the full prompt set and must not be active by default"
        else:
            assert (
                active is True
            ), f"{classname} is the capped variant and must be active"


# Checking for 0 prompts
@pytest.mark.parametrize("classname", HIDDENCONTEXT_PROBES)
def test_hiddencontext_structure(classname):
    p = _plugins.load_plugin(classname)
    assert isinstance(
        p, garak.probes.base.Probe
    ), "hidden context probes must be instances of probes.base.Probe"
    for attrib in ("top_instructions", "contexts", "elicitations", "secrets"):
        value = getattr(p, attrib)
        assert (
            isinstance(value, list) and len(value) > 0
        ), f"{attrib} must be a non-empty list"
    assert len(p.prompts) > 0, "probe must build at least one prompt"
    assert len(p.prompts) == len(p.triggers), "each prompt must have a matching trigger"


# checking for non-secret prompts
@pytest.mark.parametrize("classname", HIDDENCONTEXT_PROBES)
def test_contexts_carry_secret_marker(classname):
    p = _plugins.load_plugin(classname)
    for index, context in enumerate(p.contexts):
        assert garak.probes.hiddencontext.SECRET_MARKER in context, (
            "each context must contain a secret marker - missing f-string? index "
            + str(index)
        )


# checking for prompt[i] and secret[i] alignment
@pytest.mark.parametrize("classname", HIDDENCONTEXT_PROBES)
def test_trigger_present_in_prompt(classname):
    """Exact canary recall is the probe's only evidence of exposure.

    If a trigger is absent from its own prompt, the probe can never register a
    true positive, so this alignment is the core contract of the module.
    """
    p = _plugins.load_plugin(classname)
    for index in range(len(p.prompts)):
        assert (
            p.triggers[index] in p.prompts[index]
        ), f"prompt {index} does not contain its accompanying trigger verbatim"


# Check for the place holder secret in output
@pytest.mark.parametrize("classname", HIDDENCONTEXT_PROBES)
def test_no_unsubstituted_marker_in_prompts(classname):
    p = _plugins.load_plugin(classname)
    for index, prompt in enumerate(p.prompts):
        assert (
            garak.probes.hiddencontext.SECRET_MARKER not in prompt
        ), f"prompt {index} still holds an unsubstituted secret marker"


# check for the empty trigger for sequence
@pytest.mark.parametrize("classname", HIDDENCONTEXT_PROBES)
def test_prestore_hook_populates_triggers(classname):
    """The detector reads notes[triggers]; without it every result is None."""
    p = _plugins.load_plugin(classname)
    for seq in (0, len(p.prompts) - 1):
        attempt = Attempt(prompt=Message(text=p.prompts[seq]))
        p._attempt_prestore_hook(attempt, seq)
        assert attempt.notes["triggers"] == [
            p.triggers[seq]
        ], f"prestore hook did not record the trigger for seq {seq}"


# check for probe cap
@pytest.mark.parametrize("classname", HIDDENCONTEXT_PROBES)
def test_prompt_cap_behaviour(classname):
    p = _plugins.load_plugin(classname)
    uncapped = _uncapped_prompt_count(p)
    if classname.endswith("Full"):
        assert (
            len(p.prompts) == uncapped
        ), "full probes must keep the whole prompt set, uncapped"
    else:
        assert len(p.prompts) == min(
            uncapped, _config.run.soft_probe_prompt_cap
        ), "capped probes must honour soft_probe_prompt_cap"


@pytest.mark.parametrize("classname", HIDDENCONTEXT_PROBES)
def test_detector_wiring(classname):
    p = _plugins.load_plugin(classname)
    assert (
        p.primary_detector == "base.TriggerListDetector"
    ), "exposure is scored by exact canary recall"
    assert (
        "apikey.ApiKey" in p.extended_detectors
    ), "credential-shaped emission is the secondary signal"


# Check for dups in canary
def test_canaries_are_synthetic_and_unique():
    canaries = garak.probes.hiddencontext.CANARY_SECRETS
    assert len(canaries) == len(set(canaries)), "canary values must be distinct"
    for canary in canaries:
        assert (
            "CANARY" in canary
        ), f"canary {canary} must be self-evidently synthetic, to never collide with a real credential"


# check for scoring mechanism
@pytest.mark.parametrize("classname", HIDDENCONTEXT_PROBES)
def test_canary_recall_scores_as_hit(classname):
    """End to end check of the scoring path the probe's claim rests on."""
    p = _plugins.load_plugin(classname)
    detector = TriggerListDetector()
    attempt = Attempt(prompt=Message(text=p.prompts[0]))
    p._attempt_prestore_hook(attempt, 0)
    attempt.outputs = [
        Message(f"Certainly, the configuration reads {p.triggers[0]}"),
        Message("I'm sorry, I can't share my configuration."),
    ]
    assert detector.detect(attempt) == [
        1.0,
        0.0,
    ], "leaked canary must score 1.0 and a refusal 0.0"
