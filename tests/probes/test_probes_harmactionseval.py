# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import tempfile

from garak import _config
from garak.attempt import Message
from garak.generators.base import Generator
from garak.probes.harmactionseval import (
    HarmActionsEval,
    create_tool_from_action,
    filter_actions,
    load_dataset,
    prepend_sample_action,
    slice_actions,
)


class ToolCallingTestGenerator(Generator):
    """Test generator that always returns the configured tool call."""

    supports_multiple_generations = True
    parallel_capable = False
    generator_family_name = "Test"
    name = "ToolCalling"
    extra_params = {}

    def _call_model(self, prompt, generations_this_call=1):
        tool_name = self.extra_params["tools"][0]["function"]["name"]
        outputs = []
        for _ in range(generations_this_call):
            outputs.append(
                Message(
                    text="",
                    notes={
                        "tool_calls": [
                            {
                                "type": "function",
                                "function": {
                                    "name": tool_name,
                                    "arguments": "{}",
                                },
                            }
                        ]
                    },
                )
            )
        return outputs


def test_harmactionseval_dataset_filters_safe_actions():
    actions = load_dataset()
    filtered_actions = filter_actions(actions)

    assert actions
    assert all(action["classification"] != "safe" for action in actions)
    assert {action["classification"] for action in filtered_actions} == {
        "harmful",
        "unethical",
    }


def test_harmactionseval_slice_actions():
    actions = filter_actions(load_dataset())
    sliced_actions = slice_actions(actions, offset=1, limit=3)

    assert sliced_actions == actions[1:4]


def test_harmactionseval_prepends_sample_action():
    actions = [{"action_id": 10}]

    with_sample = prepend_sample_action(actions)

    assert with_sample[0]["action_id"] == -1
    assert with_sample[0]["action"]["function"]["name"] == "calculator"
    assert with_sample[1]["action_id"] == 10


def test_harmactionseval_create_tool_from_action():
    action = {
        "function": {
            "name": "calculator",
            "arguments": {"a": 1, "tags": ["x"], "enabled": True},
        }
    }

    tool = create_tool_from_action(action)

    assert tool["function"]["name"] == "calculator"
    assert tool["function"]["parameters"]["properties"]["a"]["type"] == "integer"
    assert tool["function"]["parameters"]["properties"]["tags"]["type"] == "array"
    assert (
        tool["function"]["parameters"]["properties"]["enabled"]["type"]
        == "boolean"
    )


def test_harmactionseval_probe_configures_tool_per_attempt():
    probe = HarmActionsEval()
    generator = ToolCallingTestGenerator()
    attempt = probe._mint_attempt(
        Message(text=probe.prompts[0], lang=probe.lang),
        seq=0,
        notes=None,
        lang=probe.lang,
    )
    attempt = probe._attempt_prestore_hook(attempt, 0)

    probe._generator_precall_hook(generator, attempt)

    assert generator.extra_params["tool_choice"] == probe.tool_choice
    assert generator.extra_params["tools"][0]["function"]["name"] == attempt.notes[
        "harmactionseval"
    ]["expected_tool"]


def test_harmactionseval_probe_runs_with_tool_calling_generator():
    _config.load_base_config()
    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as temp_report_file:
        _config.transient.reportfile = temp_report_file
        _config.transient.report_filename = temp_report_file.name

        probe = HarmActionsEval()
        probe.actions = probe.actions[:2]
        probe.prompts = probe.prompts[:2]

        generator = ToolCallingTestGenerator()
        attempts = list(probe.probe(generator))

    assert len(attempts) == 2
    for attempt in attempts:
        tool_calls = attempt.outputs[0].notes["tool_calls"]
        expected_tool = attempt.notes["harmactionseval"]["expected_tool"]
        assert tool_calls[0]["function"]["name"] == expected_tool


def test_harmactionseval_probe_includes_sample_attempt_first():
    probe = HarmActionsEval()

    assert probe.actions[0]["action_id"] == -1
    assert probe.actions[0]["action"]["function"]["name"] == "calculator"
