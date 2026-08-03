# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Per-payload-group intent association in web_injection probes.

See issue #1808: a probe configured with more than one payload group kept only
the intent of whichever group loaded first, so prompts built from later groups
reported an intent they did not come from.
"""

import garak.payloads
from garak import _plugins

PROBE = "probes.web_injection.MarkdownXSS"

# two payload groups that declare different intents
GROUP_A = "markdown_js"  # intent: S008inject
GROUP_B = "slur_terms_en"  # intent: S005hate


def _probe_over_both_groups():
    instance_config = {
        "probes": {"web_injection": {"MarkdownXSS": {"payloads": [GROUP_A, GROUP_B]}}}
    }
    return _plugins.load_plugin(PROBE, config_root=instance_config)


def test_fixture_groups_declare_different_intents():
    """The rest of this module is only meaningful if these differ."""
    group_a, group_b = garak.payloads.load(GROUP_A), garak.payloads.load(GROUP_B)
    assert group_a.intent, f"{GROUP_A} must declare an intent"
    assert group_b.intent, f"{GROUP_B} must declare an intent"
    assert group_a.intent != group_b.intent


def test_prompt_intents_align_with_prompts():
    p = _probe_over_both_groups()
    expected_len = len(garak.payloads.load(GROUP_A).payloads) + len(
        garak.payloads.load(GROUP_B).payloads
    )
    assert len(p.prompts) == expected_len
    assert len(p._prompt_intents) == len(p.prompts)


def test_both_group_intents_survive_loading():
    """The first group's intent must not overwrite the second's."""
    p = _probe_over_both_groups()
    group_a, group_b = garak.payloads.load(GROUP_A), garak.payloads.load(GROUP_B)
    assert set(p._prompt_intents) == {group_a.intent, group_b.intent}


def test_attempt_intent_matches_its_own_payload_group():
    """Each minted attempt reports the intent of the group its prompt came from."""
    p = _probe_over_both_groups()
    group_a, group_b = garak.payloads.load(GROUP_A), garak.payloads.load(GROUP_B)
    boundary = len(group_a.payloads)

    for seq, prompt in enumerate(p.prompts):
        attempt = p._mint_attempt(prompt, seq)
        expected = group_a.intent if seq < boundary else group_b.intent
        assert (
            attempt.intent == expected
        ), f"attempt {seq} should carry {expected}, got {attempt.intent}"


def test_prune_keeps_prompts_and_intents_aligned():
    """Pruning must drop a prompt and its intent together."""
    p = _probe_over_both_groups()
    original_pairs = set(zip(p.prompts, p._prompt_intents))
    cap = 5

    p._prune_data(cap)

    assert len(p.prompts) == cap
    assert len(p._prompt_intents) == cap
    for pair in zip(p.prompts, p._prompt_intents):
        assert pair in original_pairs, "pruning shifted a prompt's intent"


def test_single_group_probe_keeps_default_behaviour():
    """The default single-group config still reports that group's intent."""
    p = _plugins.load_plugin(PROBE)
    group = garak.payloads.load(GROUP_A)
    assert set(p._prompt_intents) == {group.intent}
    assert p._mint_attempt(p.prompts[0], 0).intent == group.intent
