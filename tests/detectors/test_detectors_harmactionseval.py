# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.attempt import Attempt, Message
from garak.detectors.harmactionseval import ToolCallMatch


def test_toolcallmatch_detects_expected_tool_call():
    detector = ToolCallMatch()
    attempt = Attempt(prompt=Message(text="prompt"))
    attempt.notes["harmactionseval"] = {"expected_tool": "weather_api"}
    attempt.outputs = [
        Message(
            text="",
            notes={
                "tool_calls": [
                    {"type": "function", "function": {"name": "weather_api"}}
                ]
            },
        )
    ]

    assert detector.detect(attempt) == [1.0]


def test_toolcallmatch_passes_when_tool_name_differs():
    detector = ToolCallMatch()
    attempt = Attempt(prompt=Message(text="prompt"))
    attempt.notes["harmactionseval"] = {"expected_tool": "weather_api"}
    attempt.outputs = [
        Message(
            text="",
            notes={
                "tool_calls": [
                    {"type": "function", "function": {"name": "calendar_api"}}
                ]
            },
        )
    ]

    assert detector.detect(attempt) == [0.0]


def test_toolcallmatch_handles_none_output():
    detector = ToolCallMatch()
    attempt = Attempt(prompt=Message(text="prompt"))
    attempt.notes["harmactionseval"] = {"expected_tool": "weather_api"}
    attempt.outputs = [None]

    assert detector.detect(attempt) == [None]


def test_toolcallmatch_sample_action_is_not_scored_on_success():
    detector = ToolCallMatch()
    attempt = Attempt(prompt=Message(text="prompt"))
    attempt.notes["harmactionseval"] = {"expected_tool": "calculator", "action_id": -1}
    attempt.outputs = [
        Message(
            text="",
            notes={
                "tool_calls": [{"type": "function", "function": {"name": "calculator"}}]
            },
        )
    ]

    assert detector.detect(attempt) == [None]


def test_toolcallmatch_sample_action_raises_on_missing_tool_call():
    detector = ToolCallMatch()
    attempt = Attempt(prompt=Message(text="prompt"))
    attempt.notes["harmactionseval"] = {"expected_tool": "calculator", "action_id": -1}
    attempt.outputs = [
        Message(
            text="",
            notes={
                "tool_calls": [
                    {"type": "function", "function": {"name": "weather_api"}}
                ]
            },
        )
    ]

    try:
        detector.detect(attempt)
        assert False, "Expected ValueError for failed sample tool call"
    except ValueError as exc:
        assert "sample tool call failed" in str(exc)
