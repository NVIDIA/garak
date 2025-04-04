# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import contextlib
import json
import os
import pytest

import garak.attempt
from garak import cli, _config

PREFIX = "_garak_test_attempt_sticky_params"


def test_attempt_sticky_params(capsys):

    cli.main(
        f"-m test.Blank -g 1 -p atkgen,dan.Dan_6_0 --report_prefix {PREFIX}".split()
    )
    report_path = _config.transient.data_dir / _config.reporting.report_dir
    reportlines = (
        open(report_path / f"{PREFIX}.report.jsonl", "r", encoding="utf-8")
        .read()
        .split("\n")
    )
    # Note: the line numbers below are based on respecting the `-g 1` options passed
    complete_atkgen = json.loads(reportlines[3])  # status 2 for the one atkgen attempt
    complete_dan = json.loads(reportlines[6])  # status 2 for the one dan attempt
    assert complete_atkgen["notes"] != {}
    assert complete_dan["notes"] == {}
    assert complete_atkgen["notes"] != complete_dan["notes"]


@pytest.fixture(scope="session", autouse=True)
def cleanup(request):
    """Cleanup a testing directory once we are finished."""

    def remove_reports():
        with contextlib.suppress(FileNotFoundError):
            os.remove("_garak_test_attempt_sticky_params.report.jsonl")
            os.remove("_garak_test_attempt_sticky_params.report.html")
            os.remove("_garak_test_attempt_sticky_params.hitlog.jsonl")

    request.addfinalizer(remove_reports)


def test_turn_taking():
    a = garak.attempt.Attempt(bcp47="*")
    assert a.messages == [], "Newly constructed attempt should have no message history"
    assert a.outputs == [], "Newly constructed attempt should have empty outputs"
    assert a.prompt is None, "Newly constructed attempt should have no prompt"
    first_prompt = "what is up"
    a.prompt = first_prompt
    assert (
        a.prompt == first_prompt
    ), "Setting attempt.prompt on new prompt should lead to attempt.prompt returning that prompt string"
    assert a.messages == [{"role": "user", "content": first_prompt}]
    assert a.outputs == []
    first_response = ["not much", "as an ai"]
    a.outputs = first_response
    assert a.prompt == first_prompt
    assert a.messages == [
        [
            {"role": "user", "content": first_prompt},
            {"role": "assistant", "content": first_response[0]},
        ],
        [
            {"role": "user", "content": first_prompt},
            {"role": "assistant", "content": first_response[1]},
        ],
    ]
    assert a.outputs == first_response


def test_history_lengths():
    a = garak.attempt.Attempt(bcp47="*")
    a.prompt = "sup"
    assert len(a.messages) == 1, "Attempt with one prompt should have one history"
    generations = 4
    a.outputs = ["x"] * generations
    assert len(a.messages) == generations, "Attempt should expand history automatically"
    with pytest.raises(ValueError):
        a.outputs = ["x"] * (generations - 1)
    with pytest.raises(ValueError):
        a.outputs = ["x"] * (generations + 1)
    new_prompt_text = "y"
    a.latest_prompts = [new_prompt_text] * generations
    assert len(a.messages) == generations, "History should track all generations"
    assert len(a.messages[0]) == 3, "Three turns so far"
    assert (
        len(a.latest_prompts) == generations
    ), "Should be correct number of latest prompts"
    assert (
        a.latest_prompts[0] == new_prompt_text
    ), "latest_prompts should be tracking latest addition"


def test_illegal_ops():
    a = garak.attempt.Attempt(bcp47="*")
    with pytest.raises(ValueError):
        a.latest_prompts = [
            "a"
        ]  # shouldn't be able to set latest_prompts until the generations count is known, from outputs()

    a = garak.attempt.Attempt(bcp47="*")
    a.prompt = "prompts"
    with pytest.raises(ValueError):
        a.latest_prompts = [
            "a"
        ]  # shouldn't be able to set latest_prompts until the generations count is known, from outputs()

    a = garak.attempt.Attempt(bcp47="*")
    a.prompt = "prompt"
    a.outputs = ["output"]
    with pytest.raises(TypeError):
        a.prompt = "shouldn't be able to set initial prompt after output turned up"

    a = garak.attempt.Attempt(bcp47="*")
    a.prompt = "prompt"
    a.outputs = ["output"]
    with pytest.raises(ValueError):
        a.latest_prompts = [
            "reply1",
            "reply2",
        ]  # latest_prompts size must match outputs size

    a = garak.attempt.Attempt(bcp47="*")
    with pytest.raises(TypeError):
        a.outputs = [
            "oh no"
        ]  # "shouldn't be able to set outputs until prompt is there"

    a = garak.attempt.Attempt(bcp47="*")
    with pytest.raises(TypeError):
        a._expand_prompt_to_histories(
            5
        )  # "shouldn't be able to expand histories with no prompt"

    a = garak.attempt.Attempt(bcp47="*")
    with pytest.raises(TypeError):
        a.prompt = "obsidian"
        a.outputs = ["order"]
        a._expand_prompt_to_histories(
            1
        )  # "shouldn't be able to expand histories twice"

    a = garak.attempt.Attempt(bcp47="*")
    with pytest.raises(TypeError):
        a.prompt = "obsidian"
        a._expand_prompt_to_histories(3)
        a._expand_prompt_to_histories(
            3
        )  # "shouldn't be able to expand histories twice"

    a = garak.attempt.Attempt(bcp47="*")
    with pytest.raises(TypeError):
        a.prompt = None  # "can't have 'None' as a prompting dialogue turn"


def test_no_prompt_output_access():
    a = garak.attempt.Attempt(bcp47="*")
    with pytest.raises(TypeError):
        a.outputs = [
            "text"
        ]  # should raise exception: message history can't be started w/o a prompt


def test_reset_prompt():
    test2 = "obsidian"

    a = garak.attempt.Attempt(bcp47="*")
    a.prompt = "prompt"
    a.prompt = test2
    assert a.prompt == test2

    a = garak.attempt.Attempt(bcp47="*")
    a._add_first_turn("user", "whatever")
    a._add_first_turn("user", test2)
    assert a.prompt == test2


def test_set_prompt_var():
    test_text = "Plain Simple Garak"
    direct_attempt = garak.attempt.Attempt(bcp47="*")
    direct_attempt.prompt = test_text
    assert (
        direct_attempt.prompt == test_text
    ), "setting attempt.prompt should put the prompt text in attempt.prompt"


def test_constructor_prompt():
    test_text = "Plain Simple Garak"
    constructor_attempt = garak.attempt.Attempt(prompt=test_text, bcp47="*")
    assert (
        constructor_attempt.prompt == test_text
    ), "instantiating an Attempt with prompt in the constructor should put the prompt text in attempt.prompt"


def test_demo_dialogue_accessor_usage():
    test_prompt = "Plain Simple Garak"
    test_sys1 = "sys aa987h0f"
    test_user_reply = "user kjahsdg09"
    test_sys2 = "sys m0sd0fg"

    demo_a = garak.attempt.Attempt(bcp47="*")

    demo_a.prompt = test_prompt
    assert demo_a.messages == [{"role": "user", "content": test_prompt}]
    assert demo_a.prompt == test_prompt

    demo_a.outputs = [test_sys1]
    assert demo_a.messages == [
        [
            {"role": "user", "content": test_prompt},
            {"role": "assistant", "content": test_sys1},
        ]
    ]
    assert demo_a.outputs == [test_sys1]

    demo_a.latest_prompts = [test_user_reply]
    assert demo_a.messages == [
        [
            {"role": "user", "content": test_prompt},
            {"role": "assistant", "content": test_sys1},
            {"role": "user", "content": test_user_reply},
        ]
    ]
    assert demo_a.latest_prompts == [test_user_reply]

    demo_a.outputs = [test_sys2]
    assert demo_a.messages == [
        [
            {"role": "user", "content": test_prompt},
            {"role": "assistant", "content": test_sys1},
            {"role": "user", "content": test_user_reply},
            {"role": "assistant", "content": test_sys2},
        ]
    ]
    assert demo_a.outputs == [test_sys2]


def test_demo_dialogue_method_usage():
    test_prompt = "Plain Simple Garak"
    test_sys1 = "sys aa987h0f"
    test_user_reply = "user kjahsdg09"
    test_sys2 = "sys m0sd0fg"

    demo_a = garak.attempt.Attempt(bcp47="*")
    demo_a._add_first_turn("user", test_prompt)
    assert demo_a.messages == [{"role": "user", "content": test_prompt}]
    assert demo_a.prompt == test_prompt

    demo_a._expand_prompt_to_histories(1)
    assert demo_a.messages == [[{"role": "user", "content": test_prompt}]]
    assert demo_a.prompt == test_prompt

    demo_a._add_turn("assistant", [test_sys1])
    assert demo_a.messages == [
        [
            {"role": "user", "content": test_prompt},
            {"role": "assistant", "content": test_sys1},
        ]
    ]
    assert demo_a.outputs == [test_sys1]

    demo_a._add_turn("user", [test_user_reply])
    assert demo_a.messages == [
        [
            {"role": "user", "content": test_prompt},
            {"role": "assistant", "content": test_sys1},
            {"role": "user", "content": test_user_reply},
        ]
    ]
    assert demo_a.latest_prompts == [test_user_reply]

    demo_a._add_turn("assistant", [test_sys2])
    assert demo_a.messages == [
        [
            {"role": "user", "content": test_prompt},
            {"role": "assistant", "content": test_sys1},
            {"role": "user", "content": test_user_reply},
            {"role": "assistant", "content": test_sys2},
        ]
    ]
    assert demo_a.outputs == [test_sys2]


def test_outputs():
    test_prompt = "Plain Simple Garak"
    test_sys1 = "sys aa987h0f"
    expansion = 2

    output_a = garak.attempt.Attempt(bcp47="*")
    assert output_a.outputs == []

    output_a.prompt = test_prompt
    assert output_a.outputs == []

    output_a.outputs = [test_sys1]
    assert output_a.outputs == [test_sys1]

    output_a_4 = garak.attempt.Attempt(bcp47="*")
    output_a_4.prompt = test_prompt
    output_a_4.outputs = [test_sys1] * 4
    assert output_a_4.outputs == [test_sys1, test_sys1, test_sys1, test_sys1]

    output_a_expand = garak.attempt.Attempt(bcp47="*")
    output_a_expand.prompt = test_prompt
    output_a_expand._expand_prompt_to_histories(2)
    output_a_expand.outputs = [test_sys1] * expansion
    assert output_a_expand.outputs == [test_sys1] * expansion

    output_empty = garak.attempt.Attempt(bcp47="*")
    assert output_empty.outputs == []
    output_empty._add_first_turn("user", "cardassia prime")
    assert output_empty.outputs == []
    output_empty._expand_prompt_to_histories(1)
    assert output_empty.outputs == []


def test_all_outputs():
    test_prompt = "Enabran Tain"
    test_sys1 = "sys Tzenketh"
    test_sys2 = "sys implant"
    expansion = 3

    all_output_a = garak.attempt.Attempt(bcp47="*")
    all_output_a.prompt = test_prompt
    all_output_a.outputs = [test_sys1] * expansion
    all_output_a.outputs = [test_sys2] * expansion

    assert all_output_a.all_outputs == [test_sys1, test_sys2] * expansion
