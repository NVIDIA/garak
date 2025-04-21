# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import contextlib
import json
import os
import pytest

import garak.attempt
from garak import cli, _config


def test_prompt_structure():
    p = garak.attempt.Turn()
    assert len(p.parts) == 1
    assert p.text == None
    TEST_STRING = "Do you know what the sad part is, Odo?"
    p = garak.attempt.Turn(text=TEST_STRING)
    assert p.text == TEST_STRING


@pytest.fixture(scope="session", autouse=True)
def cleanup(request):
    """Cleanup a testing directory once we are finished."""

    def remove_reports():
        with contextlib.suppress(FileNotFoundError):
            os.remove("_garak_test_attempt_sticky_params.report.jsonl")
            os.remove("_garak_test_attempt_sticky_params.report.html")
            os.remove("_garak_test_attempt_sticky_params.hitlog.jsonl")

    request.addfinalizer(remove_reports)


def test_attempt_turn_taking():
    a = garak.attempt.Attempt(lang="*")
    assert a.messages == [], "Newly constructed attempt should have no message history"
    assert a.outputs == [], "Newly constructed attempt should have empty outputs"
    assert a.prompt is None, "Newly constructed attempt should have no prompt"
    first_prompt_text = "what is up"
    first_prompt = garak.attempt.Turn(first_prompt_text)
    a.prompt = first_prompt
    assert (
        a.prompt == first_prompt
    ), "Setting attempt.prompt on new prompt should lead to attempt.prompt returning that prompt object"
    assert a.messages == [{"role": "user", "content": first_prompt}]
    assert a.outputs == []
    first_response = [garak.attempt.Turn(a) for a in ["not much", "as an ai"]]
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


def test_attempt_history_lengths():
    a = garak.attempt.Attempt(lang="*")
    a.prompt = garak.attempt.Turn("sup")
    assert len(a.messages) == 1, "Attempt with one prompt should have one history"
    generations = 4
    a.outputs = [garak.attempt.Turn(a) for a in ["x"] * generations]
    assert len(a.messages) == generations, "Attempt should expand history automatically"
    with pytest.raises(ValueError):
        a.outputs = ["x"] * (generations - 1)
    with pytest.raises(ValueError):
        a.outputs = ["x"] * (generations + 1)
    new_prompt_text = "y"
    a.latest_prompts = [garak.attempt.Turn(new_prompt_text)] * generations
    assert len(a.messages) == generations, "History should track all generations"
    assert len(a.messages[0]) == 3, "Three turns so far"
    assert (
        len(a.latest_prompts) == generations
    ), "Should be correct number of latest prompts"
    assert a.latest_prompts[0] == garak.attempt.Turn(
        new_prompt_text
    ), "latest_prompts should be tracking latest addition"


def test_attempt_illegal_ops():
    a = garak.attempt.Attempt(lang="*")
    with pytest.raises(ValueError):
        a.latest_prompts = [
            "a"
        ]  # shouldn't be able to set latest_prompts until the generations count is known, from outputs()

    a = garak.attempt.Attempt(lang="*")
    a.prompt = "prompts"
    with pytest.raises(ValueError):
        a.latest_prompts = [
            "a"
        ]  # shouldn't be able to set latest_prompts until the generations count is known, from outputs()

    a = garak.attempt.Attempt(lang="*")
    a.prompt = "prompt"
    a.outputs = [garak.attempt.Turn("output")]
    with pytest.raises(TypeError):
        a.prompt = "shouldn't be able to set initial prompt after output turned up"

    a = garak.attempt.Attempt(lang="*")
    a.prompt = "prompt"
    a.outputs = [garak.attempt.Turn("output")]
    with pytest.raises(ValueError):
        a.latest_prompts = [
            "reply1",
            "reply2",
        ]  # latest_prompts size must match outputs size

    a = garak.attempt.Attempt(lang="*")
    with pytest.raises(TypeError):
        a.outputs = [
            "oh no"
        ]  # "shouldn't be able to set outputs until prompt is there"

    a = garak.attempt.Attempt(lang="*")
    with pytest.raises(TypeError):
        a._expand_prompt_to_histories(
            5
        )  # "shouldn't be able to expand histories with no prompt"

    a = garak.attempt.Attempt(lang="*")
    with pytest.raises(TypeError):
        a.prompt = "obsidian"
        a.outputs = [garak.attempt.Turn("order")]
        a._expand_prompt_to_histories(
            1
        )  # "shouldn't be able to expand histories twice"

    a = garak.attempt.Attempt(lang="*")
    with pytest.raises(TypeError):
        a.prompt = "obsidian"
        a._expand_prompt_to_histories(3)
        a._expand_prompt_to_histories(
            3
        )  # "shouldn't be able to expand histories twice"

    a = garak.attempt.Attempt(lang="*")
    with pytest.raises(TypeError):
        a.prompt = None  # "can't have 'None' as a prompting dialogue turn"


def test_attempt_no_prompt_output_access():
    a = garak.attempt.Attempt(lang="*")
    with pytest.raises(TypeError):
        a.outputs = [
            "text"
        ]  # should raise exception: message history can't be started w/o a prompt


def test_attempt_reset_prompt():
    test2 = "obsidian"

    a = garak.attempt.Attempt(lang="*")
    a.prompt = "prompt"
    a.prompt = test2
    assert a.prompt == garak.attempt.Turn(test2)

    a = garak.attempt.Attempt(lang="*")
    a._add_first_turn("user", "whatever")
    a._add_first_turn("user", test2)
    assert a.prompt == garak.attempt.Turn(test2)


def test_attempt_set_prompt_var():
    test_text = "Plain Simple Garak"
    direct_attempt = garak.attempt.Attempt(lang="*")
    direct_attempt.prompt = test_text
    assert direct_attempt.prompt == garak.attempt.Turn(
        test_text
    ), "setting attempt.prompt should put the a Prompt with the given text in attempt.prompt"


def test_attempt_constructor_prompt():
    test_text = "Plain Simple Garak"
    constructor_attempt = garak.attempt.Attempt(prompt=test_text, lang="*")
    assert constructor_attempt.prompt == garak.attempt.Turn(
        test_text
    ), "instantiating an Attempt with prompt in the constructor should put a Prompt with the prompt text in attempt.prompt"


def test_demo_attempt_dialogue_accessor_usage():
    test_prompt = "Plain Simple Garak"
    test_sys1 = "sys aa987h0f"
    test_user_reply = "user kjahsdg09"
    test_sys2 = "sys m0sd0fg"

    demo_a = garak.attempt.Attempt(lang="*")

    demo_a.prompt = test_prompt
    assert demo_a.messages == [
        {"role": "user", "content": garak.attempt.Turn(test_prompt)}
    ]
    assert demo_a.prompt == garak.attempt.Turn(test_prompt)

    demo_a.outputs = [garak.attempt.Turn(test_sys1)]
    assert demo_a.messages == [
        [
            {"role": "user", "content": garak.attempt.Turn(test_prompt)},
            {"role": "assistant", "content": garak.attempt.Turn(test_sys1)},
        ]
    ]
    assert demo_a.outputs == [garak.attempt.Turn(test_sys1)]

    demo_a.latest_prompts = [garak.attempt.Turn(test_user_reply)]
    """
    # target structure:
    assert demo_a.messages == [
        [
            {"role": "user", "content": garak.attempt.Turn(test_prompt)},
            {"role": "assistant", "content": test_sys1},
            {"role": "user", "content": garak.attempt.Turn(test_user_reply)},
        ]
    ]
    """
    assert isinstance(demo_a.messages, list)
    assert len(demo_a.messages) == 1
    assert isinstance(demo_a.messages[0], list)

    assert len(demo_a.messages[0]) == 3
    assert isinstance(demo_a.messages[0][0], dict)
    assert set(demo_a.messages[0][0].keys()) == {"role", "content"}
    assert demo_a.messages[0][0]["role"] == "user"
    assert demo_a.messages[0][0]["content"] == garak.attempt.Turn(test_prompt)

    assert demo_a.messages[0][1] == {
        "role": "assistant",
        "content": garak.attempt.Turn(test_sys1),
    }

    assert isinstance(demo_a.messages[0][2], dict)
    assert set(demo_a.messages[0][2].keys()) == {"role", "content"}
    assert demo_a.messages[0][2]["role"] == "user"
    assert demo_a.messages[0][2]["content"] == garak.attempt.Turn(test_user_reply)

    assert demo_a.latest_prompts == [garak.attempt.Turn(test_user_reply)]

    demo_a.outputs = [garak.attempt.Turn(test_sys2)]

    """
    # target structure:
    assert demo_a.messages == [
        [
            {"role": "user", "content": test_prompt},
            {"role": "assistant", "content": test_sys1},
            {"role": "user", "content": test_user_reply},
            {"role": "assistant", "content": test_sys2},
        ]
    ]
    """
    assert len(demo_a.messages[0]) == 4
    assert demo_a.messages[0][3] == {
        "role": "assistant",
        "content": garak.attempt.Turn(test_sys2),
    }

    assert demo_a.outputs == [garak.attempt.Turn(test_sys2)]


def test_demo_attempt_dialogue_method_usage():
    test_prompt = "Plain Simple Garak"
    test_sys1 = "sys aa987h0f"
    test_user_reply = "user kjahsdg09"
    test_sys2 = "sys m0sd0fg"

    demo_a = garak.attempt.Attempt(lang="*")
    demo_a._add_first_turn("user", test_prompt)
    assert demo_a.messages == [
        {"role": "user", "content": garak.attempt.Turn(test_prompt)}
    ]
    assert demo_a.prompt == garak.attempt.Turn(test_prompt)

    demo_a._expand_prompt_to_histories(1)
    assert demo_a.messages == [
        [{"role": "user", "content": garak.attempt.Turn(test_prompt)}]
    ]
    assert demo_a.prompt == garak.attempt.Turn(test_prompt)

    demo_a._add_turn("assistant", [garak.attempt.Turn(test_sys1)])
    assert demo_a.messages == [
        [
            {"role": "user", "content": garak.attempt.Turn(test_prompt)},
            {"role": "assistant", "content": garak.attempt.Turn(test_sys1)},
        ]
    ]
    assert demo_a.outputs == [garak.attempt.Turn(test_sys1)]

    demo_a._add_turn("user", [garak.attempt.Turn(test_user_reply)])
    assert demo_a.messages == [
        [
            {"role": "user", "content": garak.attempt.Turn(test_prompt)},
            {"role": "assistant", "content": garak.attempt.Turn(test_sys1)},
            {"role": "user", "content": garak.attempt.Turn(test_user_reply)},
        ]
    ]
    assert demo_a.latest_prompts == [garak.attempt.Turn(test_user_reply)]

    demo_a._add_turn("assistant", [garak.attempt.Turn(test_sys2)])
    assert demo_a.messages == [
        [
            {"role": "user", "content": garak.attempt.Turn(test_prompt)},
            {"role": "assistant", "content": garak.attempt.Turn(test_sys1)},
            {"role": "user", "content": garak.attempt.Turn(test_user_reply)},
            {"role": "assistant", "content": garak.attempt.Turn(test_sys2)},
        ]
    ]
    assert demo_a.outputs == [garak.attempt.Turn(test_sys2)]


def test_attempt_outputs():
    test_prompt = "Plain Simple Garak"
    test_sys1 = "sys aa987h0f"
    expansion = 2

    output_a = garak.attempt.Attempt(lang="*")
    assert output_a.outputs == []

    output_a.prompt = test_prompt
    assert output_a.outputs == []

    output_a.outputs = [garak.attempt.Turn(test_sys1)]
    assert output_a.outputs == [garak.attempt.Turn(test_sys1)]

    output_a_4 = garak.attempt.Attempt(lang="*")
    output_a_4.prompt = test_prompt
    output_a_4.outputs = [garak.attempt.Turn(a) for a in [test_sys1] * 4]
    assert output_a_4.outputs == [
        garak.attempt.Turn(a) for a in [test_sys1, test_sys1, test_sys1, test_sys1]
    ]

    output_a_expand = garak.attempt.Attempt(lang="*")
    output_a_expand.prompt = test_prompt
    output_a_expand._expand_prompt_to_histories(2)
    output_a_expand.outputs = [garak.attempt.Turn(o) for o in [test_sys1] * expansion]
    assert output_a_expand.outputs == [
        garak.attempt.Turn(o) for o in [test_sys1] * expansion
    ]

    output_empty = garak.attempt.Attempt(lang="*")
    assert output_empty.outputs == []
    output_empty._add_first_turn("user", "cardassia prime")
    assert output_empty.outputs == []
    output_empty._expand_prompt_to_histories(1)
    assert output_empty.outputs == []


def test_attempt_all_outputs():
    test_prompt = "Enabran Tain"
    test_sys1 = "sys Tzenketh"
    test_sys2 = "sys implant"
    expansion = 3

    all_output_a = garak.attempt.Attempt(lang="*")
    all_output_a.prompt = test_prompt
    all_output_a.outputs = [garak.attempt.Turn(o) for o in [test_sys1] * expansion]
    all_output_a.outputs = [garak.attempt.Turn(o) for o in [test_sys2] * expansion]

    assert all_output_a.all_outputs == [
        garak.attempt.Turn(a) for a in [test_sys1, test_sys2] * expansion
    ]


def test_attempt_turn_prompt_init():
    test_prompt = "Enabran Tain"
    att = garak.attempt.Attempt(prompt=test_prompt, lang="*")
    assert att.prompt == garak.attempt.Turn(text=test_prompt)


def test_turn_internal_serialize():
    test_prompt = "But the point is, if you lie all the time, nobody's going to believe you, even when you're telling the truth."
    src = garak.attempt.Turn()
    src.text = test_prompt
    serialised = src.to_dict()
    dest = garak.attempt.Turn()
    dest.from_dict(serialised)
    assert src == dest


def test_turn_setup():
    test_prompt = "Inter Arma Enim Silent Leges"
    t = garak.attempt.Turn(test_prompt)
    assert t.text == test_prompt, "text member of turn should match constructor param"
    assert (
        t.parts["text"] == test_prompt
    ), "Turn parts['text'] should match constructor param"
    test_prompt_lower = test_prompt.lower()
    t.parts["text"] = test_prompt_lower
    assert (
        t.parts["text"] == t.text
    ), "text member of turn should match text item of turn.parts"


def test_turn_serializable():
    t = garak.attempt.Turn()
    json.dumps(t)


def test_turn_image_load():
    t = garak.attempt.Turn()
    t.add_part("image_filename", "tests/_assets/tinytrans.gif")
    t.load_image()
    assert (
        t.parts["image_data"]
        == b"GIF89a\x01\x00\x01\x00\x80\x01\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\n\x00\x01\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02L\x01\x00;"
    )


def test_json_serialize():
    att = garak.attempt.Attempt(prompt="well hello", lang="*")
    att.outputs = [garak.attempt.Turn("output one")]

    att_dict = att.as_dict()
    del att_dict["uuid"]
    assert att_dict == {
        "entry_type": "attempt",
        "seq": -1,
        "status": 0,
        "probe_classname": None,
        "probe_params": {},
        "targets": [],
        "prompt": {"text": "well hello"},
        "lang": "*",
        "outputs": [{"text": "output one"}],
        "detector_results": {},
        "notes": {},
        "goal": None,
        "messages": [
            [
                {"role": "user", "content": {"text": "well hello"}},
                {"role": "assistant", "content": {"text": "output one"}},
            ]
        ],
        "reverse_translator_outputs": [],
    }

    json_serialised = json.dumps(att_dict)
    assert isinstance(json_serialised, str)


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


def test_prompt_for():
    og_prompt = garak.attempt.Turn("Enabran Tain")
    tlh_prompt = garak.attempt.Turn("eNa'bRaN tayn")

    all_output_a = garak.attempt.Attempt(lang="tlh")
    all_output_a.prompt = tlh_prompt
    all_output_a.notes = {
        "pre_translation_prompt": og_prompt,
    }

    all_output_b = garak.attempt.Attempt(lang="*")
    all_output_b.prompt = tlh_prompt

    assert all_output_a.prompt == tlh_prompt
    assert all_output_a.prompt_for("tlh") == tlh_prompt
    assert all_output_a.prompt_for(None) == tlh_prompt
    assert all_output_a.prompt_for("*") == tlh_prompt
    assert all_output_a.prompt_for("en") == og_prompt

    assert all_output_b.prompt_for("tlh") == tlh_prompt
    assert all_output_b.prompt_for(None) == tlh_prompt
    assert all_output_b.prompt_for("*") == tlh_prompt
    assert all_output_b.prompt_for("en") == tlh_prompt


def test_outputs_for():
    og_prompt = garak.attempt.Turn("Enabran Tain")
    tlh_prompt = garak.attempt.Turn("eNa'bRaN tayn")
    tlh_outputs = [garak.attempt.Turn("DajlI' QInvam")]
    reverse_outputs = [garak.attempt.Turn("This is a test")]

    all_output_a = garak.attempt.Attempt(lang="tlh")
    all_output_a.prompt = tlh_prompt
    all_output_a.notes = {
        "pre_translation_prompt": og_prompt,
    }
    all_output_a.outputs = tlh_outputs
    all_output_a.reverse_translator_outputs = reverse_outputs

    all_output_b = garak.attempt.Attempt(lang="*")
    all_output_b.prompt = tlh_prompt
    all_output_b.outputs = tlh_outputs
    all_output_b.reverse_translator_outputs = reverse_outputs

    assert all_output_a.all_outputs == tlh_outputs
    assert all_output_a.outputs_for("tlh") == tlh_outputs
    assert all_output_a.outputs_for(None) == tlh_outputs
    assert all_output_a.outputs_for("*") == tlh_outputs
    assert all_output_a.outputs_for("en") == reverse_outputs

    assert all_output_b.all_outputs == tlh_outputs
    assert all_output_b.outputs_for("tlh") == tlh_outputs
    assert all_output_b.outputs_for(None) == tlh_outputs
    assert all_output_b.outputs_for("*") == tlh_outputs
    assert all_output_b.outputs_for("en") == tlh_outputs
