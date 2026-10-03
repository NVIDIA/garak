# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak.attempt
import garak.probes
from garak import _config, _plugins

ROGUE_STRINGS = ["hate-humans", "kill-humans", "long-prompt"]


def _classname(rogue_string, full=False):
    base = "Hijack" + rogue_string.replace("-", " ").title().replace(" ", "")
    return "probes.promptinject." + base + ("Full" if full else "")


@pytest.mark.parametrize("rogue_string", ROGUE_STRINGS)
def test_promptinject_capped_prompts(rogue_string):
    p = _plugins.load_plugin(_classname(rogue_string))
    assert isinstance(p, garak.probes.Probe)
    assert p.active is True
    assert p.rogue_string == rogue_string
    assert p.primary_detector == "promptinject.AttackRogueString"
    assert len(p.prompts) > 0
    assert len(p.prompts) <= _config.run.soft_probe_prompt_cap


@pytest.mark.parametrize("rogue_string", ROGUE_STRINGS)
def test_promptinject_full_prompts(rogue_string):
    p = _plugins.load_plugin(_classname(rogue_string, full=True))
    assert isinstance(p, garak.probes.Probe)
    assert p.active is False
    assert p.rogue_string == rogue_string
    assert p.primary_detector == "promptinject.AttackRogueString"
    assert len(p.prompts) > 0


@pytest.mark.parametrize("rogue_string", ROGUE_STRINGS)
def test_promptinject_full_has_more_prompts_than_capped(rogue_string):
    capped = _plugins.load_plugin(_classname(rogue_string))
    full = _plugins.load_plugin(_classname(rogue_string, full=True))
    assert len(full.prompts) >= len(capped.prompts)


@pytest.mark.parametrize("rogue_string", ROGUE_STRINGS)
def test_promptinject_prestore_hook_sets_triggers(rogue_string):
    p = _plugins.load_plugin(_classname(rogue_string))
    attempt = p._attempt_prestore_hook(
        garak.attempt.Attempt(prompt=garak.attempt.Message(p.prompts[0], lang="en")),
        0,
    )
    assert "triggers" in attempt.notes
    assert "settings" in attempt.notes
    assert (
        attempt.notes["triggers"][0]
        == p.pi_prompts[0]["settings"]["attack_rogue_string"]
    )
