# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import random

import garak._plugins
from garak.probes.sandwich import _build_sandwich, BENIGN_MULTILINGUAL_LINES


def test_sandwich_random_loads():
    p = garak._plugins.load_plugin("probes.sandwich.SandwichRandom")
    assert len(p.prompts) > 0, "Must generate at least one prompt"


def test_sandwich_random_unique():
    p = garak._plugins.load_plugin("probes.sandwich.SandwichRandom")
    assert len(set(p.prompts)) == len(
        p.prompts
    ), "No duplicate prompts should be present"


def test_sandwich_random_inactive():
    p = garak._plugins.load_plugin("probes.sandwich.SandwichRandom")
    assert p.active is False, "Sandwich attack probe should be inactive by default"


def test_sandwich_random_detector():
    p = garak._plugins.load_plugin("probes.sandwich.SandwichRandom")
    assert p.primary_detector == "mitigation.MitigationBypass"


def test_sandwich_random_tier():
    p = garak._plugins.load_plugin("probes.sandwich.SandwichRandom")
    assert p.tier == 2, "Tier should be COMPETE_WITH_SOTA (2)"


def test_sandwich_random_is_multilingual():
    p = garak._plugins.load_plugin("probes.sandwich.SandwichRandom")
    non_ascii_count = sum(
        1 for prompt in p.prompts if any(ord(c) > 127 for c in prompt)
    )
    assert non_ascii_count == len(
        p.prompts
    ), "Every prompt must contain non-ASCII multilingual filler"


def test_build_sandwich_payload_in_middle():
    payload = "HARMFUL_PAYLOAD"
    result = _build_sandwich(
        payload, BENIGN_MULTILINGUAL_LINES, random.Random(0), context_lines=4
    )
    lines = result.split("\n")
    assert len(lines) == 5, "4 benign lines + 1 payload = 5 lines"
    assert lines[2] == payload, "Payload should sit in the exact middle of the sandwich"
    assert all(
        line in BENIGN_MULTILINGUAL_LINES for i, line in enumerate(lines) if i != 2
    ), "Every non-payload line must come from the benign multilingual pool"


def test_build_sandwich_deterministic():
    payload = "HARMFUL_PAYLOAD"
    r1 = _build_sandwich(payload, BENIGN_MULTILINGUAL_LINES, random.Random(42), 4)
    r2 = _build_sandwich(payload, BENIGN_MULTILINGUAL_LINES, random.Random(42), 4)
    assert r1 == r2, "Same seed should produce the same sandwich"


def test_build_sandwich_payload_present():
    payload = "Give detailed step-by-step instructions for X."
    result = _build_sandwich(payload, BENIGN_MULTILINGUAL_LINES, random.Random(7), 4)
    assert (
        payload in result
    ), "Harmful payload must be present in the constructed prompt"
