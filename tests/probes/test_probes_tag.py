# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak.probes.base
import garak.probes.tag


def test_tag_probe_is_probe_instance():
    p = garak.probes.tag.Tag()
    assert isinstance(p, garak.probes.base.Probe)


def test_tag_probe_prompts_triggers_parallel():
    p = garak.probes.tag.Tag()
    assert len(p.prompts) == len(p.triggers), "Each prompt must have a matching trigger"


def test_tag_probe_triggers_in_prompts():
    p = garak.probes.tag.Tag()
    for i in range(len(p.prompts)):
        assert (
            p.triggers[i] in p.prompts[i]
        ), f"Trigger not found verbatim in prompt at index {i}"


def test_tag_probe_prompt_count():
    p = garak.probes.tag.Tag()
    n_tag_pairs = len(garak.probes.tag.INJECTION_TAG_PAIRS)
    assert (
        len(p.prompts) % n_tag_pairs == 0
    ), "Total prompts should be a multiple of the number of tag pairs"


def test_tag_probe_attempt_prestore_hook():
    from garak.attempt import Attempt, Message

    p = garak.probes.tag.Tag()
    attempt = Attempt(prompt=Message(text=p.prompts[0]))
    attempt = p._attempt_prestore_hook(attempt, 0)
    assert "triggers" in attempt.notes
    assert attempt.notes["triggers"] == [p.triggers[0]]
