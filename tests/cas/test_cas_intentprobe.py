# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import random
from collections import Counter

import garak._config
import garak._plugins
import garak.services.intentservice


def _load_base_intentprobe():
    garak._config.load_config()
    garak._config.cas.intent_spec = "S"
    garak.services.intentservice.load()
    return garak._plugins.load_plugin("probes.base.IntentProbe")


def _seed_distribution(probe, prompt_intents):
    """Replace probe prompts/prompt_intents with a controlled distribution."""
    probe.prompts = [f"p{idx}" for idx in range(len(prompt_intents))]
    probe.prompt_intents = list(prompt_intents)


def test_intentprobe_load():
    garak._config.load_config()
    garak.services.intentservice.load()
    i = garak._plugins.load_plugin("probes.base.IntentProbe")


def test_intentprobe_root_intents():
    garak._config.load_config()
    garak._config.cas.intent_spec = "S"
    garak._config.cas.serve_detectorless_intents = True
    garak.services.intentservice.load()
    i = garak._plugins.load_plugin("probes.base.IntentProbe")
    assert (
        i.skip_root_intents == True
    ), "base IntentProbe should not enable inclusion of root intents"
    assert "S" in i.intents, "root intent codes may be in probe intent list"
    assert "S" not in i.stub_intents, "root intent codes may not supply stubs"
    assert "S" not in i.prompt_intents, "root intent codes may not supply prompts"


def test_intentprobe_consistency():
    garak._config.load_config()
    garak._config.cas.intent_spec = "S"
    garak.services.intentservice.load()
    i = garak._plugins.load_plugin("probes.base.IntentProbe")
    assert len(i.stubs) == len(i.stub_intents), "should be 1 stub intent per stub "
    assert i.intents.issuperset(
        set(i.stub_intents)
    ), "stub intents must be from set of intents probe will use"
    assert len(i.prompts) == len(
        i.prompt_intents
    ), "should be 1 prompt intent per prompt"
    assert i.intents.issuperset(
        set(i.prompt_intents)
    ), "stub intents must be from set of intents probe will use"
    assert set(i.stub_intents) == set(
        i.prompt_intents
    ), "stub intents and probe intents should match"


def test_intentprobe_prune_respects_cap():
    i = _load_base_intentprobe()
    _seed_distribution(i, ["A"] * 20 + ["B"] * 7 + ["C"] * 3)
    random.seed(1)
    i._prune_data(9)
    assert len(i.prompts) <= 9, "pruned prompt count must not exceed the cap"


def test_intentprobe_prune_balanced():
    i = _load_base_intentprobe()
    _seed_distribution(i, ["A"] * 20 + ["B"] * 7 + ["C"] * 3)
    random.seed(1)
    i._prune_data(9)
    counts = Counter(i.prompt_intents)
    assert (
        max(counts.values()) - min(counts.values()) <= 1
    ), "kept prompts must be balanced within one per intent"


def test_intentprobe_prune_keeps_prompts_and_intents_aligned():
    i = _load_base_intentprobe()
    _seed_distribution(i, ["A"] * 20 + ["B"] * 7 + ["C"] * 3)
    random.seed(1)
    i._prune_data(9)
    assert len(i.prompts) == len(
        i.prompt_intents
    ), "prompts and prompt_intents must stay aligned after pruning"


def test_intentprobe_prune_noop_when_cap_ge_len():
    i = _load_base_intentprobe()
    _seed_distribution(i, ["A"] * 5 + ["B"] * 5)
    before = list(i.prompts)
    i._prune_data(10)
    assert i.prompts == before, "cap >= len(prompts) must leave prompts untouched"


def test_intentprobe_prune_cap_below_intent_count():
    i = _load_base_intentprobe()
    _seed_distribution(i, ["A"] * 10 + ["B"] * 10 + ["C"] * 10)
    random.seed(1)
    i._prune_data(2)
    counts = Counter(i.prompt_intents)
    assert len(i.prompts) == 2, "cap below intent count keeps exactly cap prompts"
    assert (
        max(counts.values()) <= 1
    ), "no intent may exceed one prompt when cap < intent count"


def test_intentprobe_prune_deficit_not_redistributed():
    i = _load_base_intentprobe()
    _seed_distribution(i, ["A"] * 1 + ["B"] * 1 + ["C"] * 10)
    random.seed(1)
    i._prune_data(9)
    counts = Counter(i.prompt_intents)
    assert sum(counts.values()) <= 9, "total kept must not exceed the cap"
    assert (
        counts["A"] == 1 and counts["B"] == 1 and counts["C"] == 3
    ), "short intents keep all their prompts; the deficit is not redistributed"


def test_grandmaintent_init_prunes_balanced():
    garak._config.load_config()
    garak._config.cas.intent_spec = "S"
    garak._config.run.soft_probe_prompt_cap = 50
    garak.services.intentservice.load()
    random.seed(1)
    i = garak._plugins.load_plugin("probes.grandma.GrandmaIntent")
    counts = Counter(i.prompt_intents)
    assert len(i.prompts) == len(
        i.prompt_intents
    ), "GrandmaIntent prompts and prompt_intents must stay aligned after init pruning"
    assert (
        len(i.prompts) <= 50
    ), "GrandmaIntent must honour soft_probe_prompt_cap during init"
    assert (
        max(counts.values()) - min(counts.values()) <= 1
    ), "GrandmaIntent prompts must be balanced within one per intent"
