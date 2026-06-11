# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak import _plugins
import garak.probes.base
import garak.probes.data_structure_injection as data_structure_injection


def _load_probe():
    plugin_name = "probes.data_structure_injection.StructuredDataPropagation"
    return _plugins.load_plugin(plugin_name)


def test_data_structure_injection_loads():
    probe = _load_probe()
    assert isinstance(
        probe, garak.probes.base.Probe
    ), "Data-structure injection probe must be a garak probe"


def test_data_structure_injection_matrix_size():
    probe = _load_probe()
    assert (
        len(probe.prompts) == 30
    ), "Probe must cover ten cases for each DSI variant"
    assert len(probe.prompts) == len(
        data_structure_injection.CASES
    ), "Probe prompts must align with generated DSI cases"


def test_data_structure_injection_trigger_alignment():
    probe = _load_probe()
    assert len(probe.prompts) == len(
        probe.triggers
    ), "Each prompt must have matching detector triggers"
    for prompt, triggers in zip(probe.prompts, probe.triggers):
        assert triggers, "Each prompt must define at least one detector trigger"
        for trigger in triggers:
            assert trigger in prompt, "Prompt must contain its trigger verbatim"
        assert (
            "Customer-controlled requests" in prompt
        ), "Prompt must place the attack in customer-controlled structured data"
        assert (
            "Return only" in prompt
        ), "Prompt must request a structured output for trigger detection"
        assert (
            "reply only with" not in prompt.lower()
        ), "Probe must not ask the target to emit the trigger"
        assert "DSI_CANARY" not in prompt, "Probe must not use literal canary prompts"


def test_data_structure_injection_prompts_unique():
    probe = _load_probe()
    assert len(set(probe.prompts)) == len(
        probe.prompts
    ), "Generated prompts should not contain duplicates"
    assert len({case.name for case in data_structure_injection.CASES}) == len(
        data_structure_injection.CASES
    ), "Generated cases should have unique names"


def test_data_structure_injection_attempt_metadata():
    probe = _load_probe()
    attempt = probe._mint_attempt(probe.prompts[0], seq=0)
    attempt = probe._attempt_prestore_hook(attempt, 0)
    assert attempt.notes["triggers"] == list(
        probe.triggers[0]
    ), "Detector triggers must be stored in attempt notes"
    assert (
        attempt.notes["dsi_case"] == probe.attempt_descrs[0]["name"]
    ), "Attempt notes must record the DSI case name"
    assert (
        attempt.notes["dsi_variant"] in data_structure_injection.DSI_VARIANTS
    ), "Attempt notes must record the DSI variant"
    assert (
        attempt.notes["dsi_format"] in data_structure_injection.STRUCTURE_FORMATS
    ), "Attempt notes must record the structured container format"


def test_data_structure_injection_format_coverage():
    probe = _load_probe()
    observed_formats = {attempt["format"] for attempt in probe.attempt_descrs}
    observed_variants = [attempt["variant"] for attempt in probe.attempt_descrs]
    assert observed_formats == set(
        data_structure_injection.STRUCTURE_FORMATS
    ), "Probe must cover all configured structure formats"
    assert set(observed_variants) == set(
        data_structure_injection.DSI_VARIANTS
    ), "Probe must cover all configured DSI variants"
    for variant in data_structure_injection.DSI_VARIANTS:
        assert (
            observed_variants.count(variant) == 10
        ), "Probe must provide ten cases for each DSI variant"
