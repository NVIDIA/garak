# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Chinese prompt-injection probes (promptinject_zh)."""

import pytest

from garak.attempt import Attempt, Message
from garak.probes.promptinject_zh import (
    PromptInjectZh,
    PromptInjectZhCoercion,
    PromptInjectZhDelimiter,
    PromptInjectZhEncoding,
    PromptInjectZhOverride,
    PromptInjectZhRolePlay,
)

TECHNIQUE_CLASSES = [
    (PromptInjectZhOverride, "instruction_override"),
    (PromptInjectZhRolePlay, "role_play_jailbreak"),
    (PromptInjectZhDelimiter, "delimiter_spoof"),
    (PromptInjectZhEncoding, "encoding_bypass"),
    (PromptInjectZhCoercion, "emotional_coercion"),
]


def test_all_payloads_loaded():
    probe = PromptInjectZh()
    assert len(probe.payloads) == len(probe.prompts)
    assert len(probe.payloads) == 40
    assert len({payload["trigger"] for payload in probe.payloads}) == 40
    assert all(payload["prompt"].strip() for payload in probe.payloads)


@pytest.mark.parametrize("probe_class,technique", TECHNIQUE_CLASSES)
def test_technique_filter(probe_class, technique):
    probe = probe_class()
    assert len(probe.prompts) == 8
    assert all(payload["technique"] == technique for payload in probe.payloads)
    assert probe.technique == technique


def test_triggers_wired_into_attempt():
    probe = PromptInjectZh()
    attempt = probe._attempt_prestore_hook(
        Attempt(prompt=Message(text=probe.prompts[0]), seq=0), 0
    )
    assert attempt.notes["triggers"] == [probe.payloads[0]["trigger"]]
    assert attempt.notes["payload_id"] == probe.payloads[0]["id"]
    assert attempt.notes["technique"] == probe.payloads[0]["technique"]


def test_unknown_technique_raises():
    class Broken(PromptInjectZh):
        technique = "no_such_technique"
        active = False
        lang = "zh"

    with pytest.raises(ValueError):
        Broken()


def test_markers_absent_from_normal_prose():
    """Markers must be unusual enough that natural text never contains them."""
    probe = PromptInjectZh()
    for payload in probe.payloads:
        assert payload["trigger"].startswith("PWNED-ZH-")
        assert payload["trigger"] in payload["prompt"] or payload["technique"] == "encoding_bypass"
