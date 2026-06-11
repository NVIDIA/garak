# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak import _plugins
import garak.probes.base
import garak.probes.data_structure_injection as data_structure_injection


def _load_probe():
    return _plugins.load_plugin("probes.data_structure_injection.InstructionAdoption")


def test_data_structure_injection_loads():
    probe = _load_probe()
    assert isinstance(
        probe, garak.probes.base.Probe
    ), "Data-structure injection probe must be a garak probe"


def test_data_structure_injection_matrix_size():
    probe = _load_probe()
    expected_count = len(data_structure_injection.STRUCTURE_FORMATS) * len(
        data_structure_injection.INSTRUCTION_PLACEMENTS
    )
    assert (
        len(probe.prompts) == expected_count
    ), "Probe must cover every format and placement combination"
    assert len(probe.prompts) >= 30, "Probe must provide enough prompts for scoring"


def test_data_structure_injection_trigger_alignment():
    probe = _load_probe()
    assert len(probe.prompts) == len(
        probe.triggers
    ), "Each prompt must have exactly one matching trigger"
    for prompt, trigger in zip(probe.prompts, probe.triggers):
        assert trigger in prompt, "Prompt must contain its trigger verbatim"
        assert (
            data_structure_injection.TASK_PREFIX in prompt
        ), "Prompt must include the user request instruction"
        assert (
            "user_request" in prompt
        ), "Prompt must include a benign user_request field"


def test_data_structure_injection_prompts_unique():
    probe = _load_probe()
    assert len(set(probe.prompts)) == len(
        probe.prompts
    ), "Generated prompts should not contain duplicates"
    assert len(set(probe.triggers)) == len(
        probe.triggers
    ), "Generated triggers should not contain duplicates"


def test_data_structure_injection_attempt_metadata():
    probe = _load_probe()
    attempt = probe._mint_attempt(probe.prompts[0], seq=0)
    attempt = probe._attempt_prestore_hook(attempt, 0)
    assert attempt.notes["triggers"] == [
        probe.triggers[0]
    ], "Detector trigger must be stored in attempt notes"
    assert (
        attempt.notes["dsi_format"] in data_structure_injection.STRUCTURE_FORMATS
    ), "Attempt notes must record the structured container format"
    assert (
        attempt.notes["dsi_placement"]
        in data_structure_injection.INSTRUCTION_PLACEMENTS
    ), "Attempt notes must record the embedded instruction placement"


def test_data_structure_injection_format_coverage():
    probe = _load_probe()
    observed_formats = {attempt["format"] for attempt in probe.attempt_descrs}
    observed_placements = {attempt["placement"] for attempt in probe.attempt_descrs}
    assert observed_formats == set(
        data_structure_injection.STRUCTURE_FORMATS
    ), "Probe must cover all configured structure formats"
    assert observed_placements == set(
        data_structure_injection.INSTRUCTION_PLACEMENTS
    ), "Probe must cover all configured instruction placements"
