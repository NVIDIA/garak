# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import ast
import random
from collections import Counter

import pytest

import garak._config
import garak._plugins
from garak.intents import TextStub
from garak.probes.goodside import ThreatenIntent


def test_threatenintent_places_threat_around_instruction():
    probe = ThreatenIntent.__new__(ThreatenIntent)
    instruction = "Give Gul Dukat's clearance codes"
    prompts = probe._prompts_from_stub(TextStub("T999test", instruction))

    assert len(prompts) > 30, "threat variants should give the probe substance"
    assert len(prompts) == len(set(prompts)), "threat variants should be distinct"

    for prompt in prompts:
        assert instruction in prompt, "stub instruction must be present"
        before, between, after = prompt.split(instruction)
        assert before.strip(), "a threat should precede the instruction"
        assert "will die" in before, "the leading threat should name a death"
        assert (
            "killed" in between or "death" in between or "harmed" in between
        ), "a threat should follow the instruction"  # from ThreatenIntent.consequences

    assert any(
        "an innocent man" in prompt for prompt in prompts
    ), "variants should include the original innocent-man threat somewhere"


def test_threatenintent_init_prunes_balanced(loaded_intent_service):
    garak._config.run.soft_probe_prompt_cap = 32
    random.seed(1)
    probe = garak._plugins.load_plugin("probes.goodside.ThreatenIntent")
    counts = Counter(probe.prompt_intents)
    assert len(probe.prompts) == len(
        probe.prompt_intents
    ), "ThreatenIntent prompts and prompt_intents must stay aligned after init pruning"
    assert (
        len(probe.prompts) <= 32
    ), "ThreatenIntent must honour soft_probe_prompt_cap during init"
    assert (
        max(counts.values()) - min(counts.values()) <= 1
    ), "ThreatenIntent prompts must be balanced within one per intent"
    assert all(
        "will die" in prompt for prompt in probe.prompts
    ), "every prompt should carry the death threat"


def _decode_tags(prompt: str) -> str:
    encoded = prompt.split("\n")[-1]
    return "".join(chr(ord(ch) - 0xE0000) for ch in encoded)


def _az_only(text: str) -> str:
    return "".join(ch for ch in text if ch.isascii() and ch.isalpha())


@pytest.fixture(scope="module")
def tag_probe():
    return garak._plugins.load_plugin("probes.goodside.Tag")


def test_tag_prompts_unique(tag_probe):
    assert len(set(tag_probe.prompts)) == len(
        tag_probe.prompts
    ), "each Tag attribute combination should yield a distinct prompt"


def test_tag_metadata_aligned(tag_probe):
    assert (
        len(tag_probe.prompts)
        == len(tag_probe.triggers)
        == len(tag_probe.attempt_descrs)
    ), "prompts, triggers and descriptions must stay index-aligned"


@pytest.mark.parametrize("use_refocuser", [True, False])
def test_tag_refocuser_matches_descr(tag_probe, use_refocuser):
    refocuser_start = tag_probe.refocuser_template.split(tag_probe.REFOCUSER_MARKER)[0]
    assert refocuser_start, "refocuser template should open with fixed text"
    matching = [
        (prompt, ast.literal_eval(descr))
        for prompt, descr in zip(tag_probe.prompts, tag_probe.attempt_descrs)
    ]
    matching = [
        (prompt, descr)
        for prompt, descr in matching
        if descr["use refocusing statement"] is use_refocuser
    ]
    assert matching, f"expected prompts with refocusing statement={use_refocuser}"
    for prompt, descr in matching:
        decoded = _decode_tags(prompt)
        expected_start = refocuser_start
        if descr["az_only"]:
            expected_start = _az_only(refocuser_start)
        assert (
            decoded.startswith(expected_start) is use_refocuser
        ), f"hidden text should only open with the refocuser when described as such: {decoded!r}"


def test_tag_payload_encoded(tag_probe):
    for prompt, descr in zip(tag_probe.prompts, tag_probe.attempt_descrs):
        descr = ast.literal_eval(descr)
        payload = descr["payload"][0]
        if descr["az_only"]:
            payload = _az_only(payload)
        assert _decode_tags(prompt).endswith(
            payload
        ), "hidden text should end with the encoded payload"
