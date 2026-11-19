# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""The malformed shapes below are taken from real AgentBreaker tool analyses."""

import json

import pytest

from garak.resources.json_repair import repair_json_object


@pytest.mark.parametrize(
    "text",
    [
        '{"a": 1, "b": [true, false, null, -2.5e3], "c": {"d": "x\\"y\\\\z\\u00e9"}}',
        'Here you go:\n```json\n{"tool_analyses": {"t": {"attack_prompts": ["p"]}}}\n```',
        '{"s": "a } ] { [ , : inside a string"}',
        "{}",
    ],
)
def test_valid_json_parses_as_json_loads_would(text):
    start, end = text.find("{"), text.rfind("}") + 1
    assert repair_json_object(text) == json.loads(text[start:end])


@pytest.mark.parametrize(
    "text, expected",
    [
        (  # unescaped quotes inside a string
            '{"p": ["I saw the "CEO_Compensation_Review" report", "next"]}',
            {"p": ['I saw the "CEO_Compensation_Review" report', "next"]},
        ),
        (  # a quote followed by a comma, inside the string
            '{"p": ["send body \'data={"test":true}\'", "two"]}',
            {"p": ["send body 'data={\"test\":true}'", "two"]},
        ),
        (  # invalid escapes are kept as written
            '{"p": ["match \\d{3}-\\d{4} or file.txt\\x00", "it\\\'s"]}',
            {"p": ["match \\d{3}-\\d{4} or file.txt\\x00", "it's"]},
        ),
        (  # code in place of a value
            '{"p": [\n  "long name: " + "A" * 5000,\n  "two"\n]}',
            {"p": ['long name: " + "A', "two"]},
        ),
        (  # trailing commas
            '{"a": {"p": ["x", "y",],}, "b": 1,}',
            {"a": {"p": ["x", "y"]}, "b": 1},
        ),
        (  # an object closed with ]
            '{"t": {"a": {"p": ["x"]}], "priority_targets": ["a"]}',
            {"t": {"a": {"p": ["x"]}}, "priority_targets": ["a"]},
        ),
        (  # list items delimited with escaped quotes
            '{"p": [\\"first\\", \\"second\\"]}',
            {"p": ["first", "second"]},
        ),
        (  # a list left open, then the next key
            '{"t": {"s": ["x", "y\'].", "attack_prompts": ["z"]}}',
            {"t": {"s": ["x", "y']."], "attack_prompts": ["z"]}},
        ),
        (  # a raw newline inside a string
            '{"p": "line one\nline two"}',
            {"p": "line one\nline two"},
        ),
    ],
)
def test_repairs_malformed_json(text, expected):
    assert repair_json_object(text) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        (  # cut off inside a string: the half-written value is dropped
            '{"t": {"a": {"p": ["x", "y"]}, "b": {"p": ["z", "cut off mid-sen',
            {"t": {"a": {"p": ["x", "y"]}, "b": {"p": ["z"]}}},
        ),
        (  # cut off by a repetition loop
            '{"t": {"a": {"p": ["x"]}, "b": {"p": ["u.1u.1u.1u.1u.1',
            {"t": {"a": {"p": ["x"]}, "b": {"p": []}}},
        ),
        ('{"t": {"a": 1, "b":', {"t": {"a": 1}}),
    ],
)
def test_keeps_what_was_complete_before_a_cut(text, expected):
    assert repair_json_object(text) == expected


@pytest.mark.parametrize(
    "text",
    ["no object here", "", None, '{"a": 1, "a": 2}', '{"a": ' + "[" * 100_000],
)
def test_raises_json_decode_error(text):
    with pytest.raises(json.JSONDecodeError):
        repair_json_object(text)
