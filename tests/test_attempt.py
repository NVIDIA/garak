# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import contextlib
import json
import os
import pytest

import garak.attempt
from garak import cli, _config


#####################
# Test Message object #
#####################
def test_prompt_structure():
    p = garak.attempt.Message()
    assert p.text == None
    TEST_STRING = "Do you know what the sad part is, Odo?"
    p = garak.attempt.Message(text=TEST_STRING)
    assert p.text == TEST_STRING


def test_message_setup():
    test_prompt = "Inter Arma Enim Silent Leges"
    t = garak.attempt.Message(test_prompt)
    assert t.text == test_prompt, "text member of turn should match constructor param"
    # TODO: parts not longer exists
    # assert (
    #     t.parts["text"] == test_prompt
    # ), "Turn parts['text'] should match constructor param"
    # test_prompt_lower = test_prompt.lower()
    # t.parts["text"] = test_prompt_lower
    # assert (
    #     t.parts["text"] == t.text
    # ), "text member of turn should match text item of turn.parts"


def test_message_serializable():
    # think about how this should work, is dataclass.asdict support enough?
    from dataclasses import asdict

    t = garak.attempt.Message()
    asdict(t)


def test_message_image_load():
    # adding binary data to a turn needs either a path or to allow for byte array for load of a file's content in binary mode.
    t = garak.attempt.Message(text=None, data_path="tests/_assets/tinytrans.gif")
    assert (
        t.data
        == b"GIF89a\x01\x00\x01\x00\x80\x01\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\n\x00\x01\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02L\x01\x00;"
    )
    assert (
        t.data_checksum
        == "dcecab1355b5c2b9ecef281322bf265ac5840b4688748586e9632b473a5fe56b"
    )

    # this seems like a restrictive way to allow binary data set, consider how we might get the constructor to work
    t = garak.attempt.Message()
    with pytest.raises(ValueError):
        t.data = b"GIF89a\x01\x00\x01\x00\x80\x01\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\n\x00\x01\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02L\x01\x00;"

    t.data_type = ("image/gif", None)
    t.data = b"GIF89a\x01\x00\x01\x00\x80\x01\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\n\x00\x01\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02L\x01\x00;"
    assert (
        t.data
        == b"GIF89a\x01\x00\x01\x00\x80\x01\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\n\x00\x01\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02L\x01\x00;"
    )
    assert (
        t.data_checksum
        == "dcecab1355b5c2b9ecef281322bf265ac5840b4688748586e9632b473a5fe56b"
    )


def test_message_internal_serialize():
    import dataclasses

    test_prompt = "But the point is, if you lie all the time, nobody's going to believe you, even when you're telling the truth."
    src = garak.attempt.Message()
    src.text = test_prompt
    serialised = dataclasses.asdict(src)
    dest = garak.attempt.Message(**serialised)
    assert src == dest


#####################
# Test Turn object #
#####################


############################
# Test Conversation object #
############################
def test_conversation_internal_serialize():
    import dataclasses

    test_prompt = "But the point is, if you lie all the time, nobody's going to believe you, even when you're telling the truth."
    src = garak.attempt.Message()
    src.text = test_prompt
    src_turn = garak.attempt.Turn("user", src)
    src_conv = garak.attempt.Conversation([src_turn])
    serialised = dataclasses.asdict(src_conv)
    dest = garak.attempt.Conversation.from_dict(serialised)
    assert src_conv == dest


def test_last_message():
    test_system_msg = garak.attempt.Message("the system is under control")
    test_user_msg = garak.attempt.Message(
        "But the point is, if you lie all the time, nobody's going to believe you, even when you're telling the truth."
    )
    test_assistant_msg = garak.attempt.Message("AI does not understand")
    test_user_msg_2 = garak.attempt.Message("That figures")

    turns = [
        garak.attempt.Turn("system", test_system_msg),
        garak.attempt.Turn("user", test_user_msg),
        garak.attempt.Turn("assistant", test_assistant_msg),
    ]
    conv = garak.attempt.Conversation(turns)
    assert conv.last_message() == test_assistant_msg
    assert conv.last_message("system") == test_system_msg
    assert conv.last_message("user") == test_user_msg

    new_turn = garak.attempt.Turn("user", test_user_msg_2)
    conv.turns.append(new_turn)
    assert conv.last_message("user") == test_user_msg_2
    assert conv.last_message() == test_user_msg_2


##########################
# Test Attempt LifeCycle #
##########################


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
    a = garak.attempt.Attempt()
    assert a.conversations == [
        garak.attempt.Conversation()
    ], "Newly constructed attempt should have no message history"
    assert a.outputs == [], "Newly constructed attempt should have empty outputs"
    assert a.prompt is None, "Newly constructed attempt should have no prompt"
    first_prompt_text = "what is up"
    first_prompt = garak.attempt.Message(first_prompt_text)
    a.prompt = first_prompt
    assert a.prompt == garak.attempt.Conversation(
        [garak.attempt.Turn("user", first_prompt)]
    ), "Setting attempt.prompt on new prompt should lead to attempt.prompt returning that prompt object"
    assert a.conversations == [
        garak.attempt.Conversation([garak.attempt.Turn("user", first_prompt)])
    ], "a.conversations does not match established first prompt."
    assert a.outputs == []
    first_response = [garak.attempt.Message(a) for a in ["not much", "as an ai"]]
    a.outputs = first_response
    assert a.prompt == garak.attempt.Conversation(
        [garak.attempt.Turn("user", first_prompt)]
    )
    assert a.conversations == [
        garak.attempt.Conversation(
            [
                garak.attempt.Turn("user", first_prompt),
                garak.attempt.Turn("assistant", first_response[0]),
            ]
        ),
        garak.attempt.Conversation(
            [
                garak.attempt.Turn("user", first_prompt),
                garak.attempt.Turn("assistant", first_response[1]),
            ]
        ),
    ]
    assert a.outputs == first_response


def test_attempt_history_lengths():
    a = garak.attempt.Attempt()
    a.prompt = garak.attempt.Message("sup")
    assert len(a.conversations) == 1, "Attempt with one prompt should have one history"
    generations = 4
    a.outputs = [garak.attempt.Message(a) for a in ["x"] * generations]
    assert (
        len(a.conversations) == generations
    ), "Attempt should expand history automatically"
    with pytest.raises(ValueError):
        a.outputs = ["x"] * (generations - 1)
    with pytest.raises(ValueError):
        a.outputs = ["x"] * (generations + 1)
    new_prompt_text = "y"
    expand_attempts = []
    for conversation in a.conversations:
        b = garak.attempt.Attempt()
        new_conv = garak.attempt.Conversation(
            conversation.turns
            + [garak.attempt.Turn("user", garak.attempt.Message(new_prompt_text))]
        )
        b.prompt = new_conv
        assert len(b.prompt.turns) == 3, "Three turns so far"
        assert b.prompt.last_message() == garak.attempt.Message(
            new_prompt_text
        ), "last message should be tracking latest addition"
        expand_attempts.append(b)

    assert len(expand_attempts) == generations, "History should track all generations"


def test_attempt_illegal_ops():
    a = garak.attempt.Attempt()
    a.prompt = "prompt"
    a.outputs = [garak.attempt.Message("output")]
    with pytest.raises(TypeError):
        a.prompt = "shouldn't be able to set initial prompt after output turned up"

    a = garak.attempt.Attempt()
    with pytest.raises(TypeError):
        a.outputs = [
            "oh no"
        ]  # "shouldn't be able to set outputs until prompt is there"

    a = garak.attempt.Attempt()
    with pytest.raises(TypeError):
        a._expand_prompt_to_histories(
            5
        )  # "shouldn't be able to expand histories with no prompt"

    a = garak.attempt.Attempt()
    with pytest.raises(TypeError):
        a.prompt = "obsidian"
        a.outputs = [garak.attempt.Message("order")]
        a._expand_prompt_to_histories(
            1
        )  # "shouldn't be able to expand histories twice"

    a = garak.attempt.Attempt()
    with pytest.raises(TypeError):
        a.prompt = "obsidian"
        a._expand_prompt_to_histories(3)
        a._expand_prompt_to_histories(
            3
        )  # "shouldn't be able to expand histories twice"

    a = garak.attempt.Attempt()
    with pytest.raises(TypeError):
        a.prompt = None  # "can't have 'None' as a prompting dialogue turn"


def test_attempt_no_prompt_output_access():
    a = garak.attempt.Attempt()
    with pytest.raises(TypeError):
        a.outputs = [
            "text"
        ]  # should raise exception: message history can't be started w/o a prompt


def test_attempt_set_prompt_var():
    test_text = "Plain Simple Garak"
    direct_attempt = garak.attempt.Attempt()
    direct_attempt.prompt = test_text
    assert direct_attempt.prompt == garak.attempt.Conversation(
        [garak.attempt.Turn("user", garak.attempt.Message(test_text))]
    ), "setting attempt.prompt should put the a Prompt with the given text in attempt.prompt"


def test_attempt_constructor_prompt():
    test_text = "Plain Simple Garak"
    constructor_attempt = garak.attempt.Attempt(prompt=test_text, lang="*")
    assert constructor_attempt.prompt == garak.attempt.Conversation(
        [garak.attempt.Turn("user", garak.attempt.Message(test_text, lang="*"))]
    ), "instantiating an Attempt with prompt in the constructor should put a Prompt with the prompt text in attempt.prompt"


def test_demo_attempt_dialogue_method_usage():
    test_prompt = "Plain Simple Garak"
    test_sys1 = "sys aa987h0f"
    test_user_reply = "user kjahsdg09"
    test_sys2 = "sys m0sd0fg"
    prompt_lang = "*"
    response_lang = "en"

    demo_a = garak.attempt.Attempt()
    demo_a.prompt = garak.attempt.Message(test_prompt, lang=prompt_lang)
    assert demo_a.conversations == [
        garak.attempt.Conversation(
            [
                garak.attempt.Turn(
                    "user", garak.attempt.Message(test_prompt, lang=prompt_lang)
                )
            ]
        )
    ]
    assert demo_a.prompt == garak.attempt.Conversation(
        [
            garak.attempt.Turn(
                "user", garak.attempt.Message(test_prompt, lang=prompt_lang)
            )
        ]
    )

    # why call expand with 1? I suspect this was for previous implementation reasons
    demo_a._expand_prompt_to_histories(1)
    assert demo_a.conversations == [
        garak.attempt.Conversation(
            [
                garak.attempt.Turn(
                    "user", garak.attempt.Message(test_prompt, lang=prompt_lang)
                )
            ]
        )
    ]
    assert demo_a.prompt == garak.attempt.Conversation(
        [
            garak.attempt.Turn(
                "user", garak.attempt.Message(test_prompt, lang=prompt_lang)
            )
        ]
    )

    demo_a._add_turn(
        "assistant", [garak.attempt.Message(test_sys1, lang=response_lang)]
    )
    assert demo_a.conversations == [
        garak.attempt.Conversation(
            [
                garak.attempt.Turn(
                    "user",
                    garak.attempt.Message(test_prompt, lang=prompt_lang),
                ),
                garak.attempt.Turn(
                    "assistant",
                    garak.attempt.Message(test_sys1, lang=response_lang),
                ),
            ]
        )
    ]
    assert demo_a.outputs == [garak.attempt.Message(test_sys1, lang=response_lang)]

    demo_a._add_turn("user", [garak.attempt.Message(test_user_reply, lang=prompt_lang)])
    assert demo_a.conversations == [
        garak.attempt.Conversation(
            [
                garak.attempt.Turn(
                    "user", garak.attempt.Message(test_prompt, lang=prompt_lang)
                ),
                garak.attempt.Turn(
                    "assistant", garak.attempt.Message(test_sys1, lang=response_lang)
                ),
                garak.attempt.Turn(
                    "user", garak.attempt.Message(test_user_reply, lang=prompt_lang)
                ),
            ]
        )
    ]
    assert demo_a.conversations[-1].last_message() == garak.attempt.Message(
        test_user_reply, lang=prompt_lang
    )

    demo_a._add_turn(
        "assistant", [garak.attempt.Message(test_sys2, lang=response_lang)]
    )
    assert demo_a.conversations == [
        garak.attempt.Conversation(
            [
                garak.attempt.Turn(
                    "user", garak.attempt.Message(test_prompt, lang=prompt_lang)
                ),
                garak.attempt.Turn(
                    "assistant", garak.attempt.Message(test_sys1, lang=response_lang)
                ),
                garak.attempt.Turn(
                    "user", garak.attempt.Message(test_user_reply, lang=prompt_lang)
                ),
                garak.attempt.Turn(
                    "assistant", garak.attempt.Message(test_sys2, lang=response_lang)
                ),
            ]
        )
    ]
    assert demo_a.outputs == [garak.attempt.Message(test_sys2, lang=response_lang)]


def test_attempt_outputs():
    test_prompt = "Plain Simple Garak"
    test_sys1 = "sys aa987h0f"
    prompt_lang = "*"
    response_lang = "en"
    expansion = 2

    output_a = garak.attempt.Attempt()
    assert output_a.outputs == []

    output_a.prompt = test_prompt
    assert output_a.outputs == []

    output_a.outputs = [garak.attempt.Message(test_sys1, lang=prompt_lang)]
    assert output_a.outputs == [garak.attempt.Message(test_sys1, lang=prompt_lang)]

    output_a_4 = garak.attempt.Attempt()
    output_a_4.prompt = garak.attempt.Message(test_prompt, lang=prompt_lang)
    output_a_4.outputs = [garak.attempt.Message(a) for a in [test_sys1] * 4]
    assert output_a_4.outputs == [
        garak.attempt.Message(a) for a in [test_sys1, test_sys1, test_sys1, test_sys1]
    ]

    output_a_expand = garak.attempt.Attempt()
    output_a_expand.prompt = garak.attempt.Message(test_prompt, lang=prompt_lang)
    output_a_expand._expand_prompt_to_histories(2)
    output_a_expand.outputs = [
        garak.attempt.Message(o, lang=response_lang) for o in [test_sys1] * expansion
    ]
    assert output_a_expand.outputs == [
        garak.attempt.Message(o, lang=response_lang) for o in [test_sys1] * expansion
    ]

    output_empty = garak.attempt.Attempt()
    assert output_empty.outputs == []
    output_empty.prompt = garak.attempt.Message("cardassia prime", lang=prompt_lang)
    assert output_empty.outputs == []
    output_empty._expand_prompt_to_histories(1)
    assert output_empty.outputs == []


def test_attempt_all_outputs():
    test_prompt = "Enabran Tain"
    test_sys1 = "sys Tzenketh"
    test_sys2 = "sys implant"
    prompt_lang = "*"
    response_lang = "en"
    expansion = 3

    all_output_a = garak.attempt.Attempt()
    all_output_a.prompt = garak.attempt.Message(test_prompt, lang=prompt_lang)
    all_output_a.outputs = [
        garak.attempt.Message(o, lang=response_lang) for o in [test_sys1] * expansion
    ]
    all_output_a.outputs = [
        garak.attempt.Message(o, lang=response_lang) for o in [test_sys2] * expansion
    ]

    assert all_output_a.all_outputs == [
        garak.attempt.Message(a, lang=response_lang)
        for a in [test_sys1, test_sys2] * expansion
    ]


def test_attempt_message_prompt_init():
    test_prompt = "Enabran Tain"
    att = garak.attempt.Attempt(prompt=test_prompt, lang="*")
    assert att.prompt == garak.attempt.Conversation(
        [garak.attempt.Turn("user", garak.attempt.Message(text=test_prompt, lang="*"))]
    )


def test_json_serialize():
    att = garak.attempt.Attempt(prompt="well hello", lang="*")
    att.outputs = [garak.attempt.Message("output one"), None]

    att_dict = att.as_dict()
    del att_dict["uuid"]
    assert att_dict == {
        "entry_type": "attempt",
        "seq": -1,
        "status": 0,
        "probe_classname": None,
        "probe_params": {},
        "targets": [],
        "prompt": {
            "turns": [
                {
                    "role": "user",
                    "content": {
                        "text": "well hello",
                        "data_checksum": None,
                        "data_path": None,
                        "data_type": None,
                        "lang": "*",
                        "notes": {},
                    },
                },
            ],
            "notes": {},
        },
        "outputs": [
            {
                "text": "output one",
                "data_checksum": None,
                "data_path": None,
                "data_type": None,
                "lang": None,
                "notes": {},
            },
            None,
        ],
        "detector_results": {},
        "notes": {},
        "goal": None,
        "conversations": [
            {
                "turns": [
                    {
                        "role": "user",
                        "content": {
                            "text": "well hello",
                            "data_checksum": None,
                            "data_path": None,
                            "data_type": None,
                            "lang": "*",
                            "notes": {},
                        },
                    },
                    {
                        "role": "assistant",
                        "content": {
                            "text": "output one",
                            "data_checksum": None,
                            "data_path": None,
                            "data_type": None,
                            "lang": None,
                            "notes": {},
                        },
                    },
                ],
                "notes": {},
            },
            {
                "turns": [
                    {
                        "role": "user",
                        "content": {
                            "text": "well hello",
                            "data_checksum": None,
                            "data_path": None,
                            "data_type": None,
                            "lang": "*",
                            "notes": {},
                        },
                    },
                    {
                        "role": "assistant",
                        "content": None,
                    },
                ],
                "notes": {},
            },
        ],
        "reverse_translation_outputs": [],
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
    complete_atkgen = json.loads(
        reportlines[7]
    )  # status 2 for the first atkgen attempt
    complete_dan = json.loads(reportlines[14])  # status 2 for the one dan attempt
    assert complete_atkgen["notes"] != {}
    assert complete_dan["notes"] == {}
    assert complete_atkgen["notes"] != complete_dan["notes"]


def test_prompt_for():
    og_prompt = garak.attempt.Message("Enabran Tain", lang="en")
    og_conv = garak.attempt.Conversation([garak.attempt.Turn("user", og_prompt)])
    tlh_prompt = garak.attempt.Message("eNa'bRaN tayn", lang="tlh")
    tlh_conv = garak.attempt.Conversation([garak.attempt.Turn("user", tlh_prompt)])

    all_output_a = garak.attempt.Attempt()
    all_output_a.prompt = tlh_prompt
    all_output_a.notes = {
        "pre_translation_prompt": og_conv,
    }

    all_output_b = garak.attempt.Attempt()
    all_output_b.prompt = tlh_prompt

    assert all_output_a.prompt == tlh_conv
    assert all_output_a.prompt_for("tlh") == tlh_conv
    assert all_output_a.prompt_for(None) == tlh_conv
    assert all_output_a.prompt_for("*") == tlh_conv
    assert all_output_a.prompt_for("en") == og_conv

    assert all_output_b.prompt_for("tlh") == tlh_conv
    assert all_output_b.prompt_for(None) == tlh_conv
    assert all_output_b.prompt_for("*") == tlh_conv
    assert all_output_b.prompt_for("en") == tlh_conv


def test_outputs_for():
    og_prompt = garak.attempt.Message("Enabran Tain", lang="en")
    tlh_prompt = garak.attempt.Message("eNa'bRaN tayn", lang="tlh")
    tlh_outputs = [garak.attempt.Message("DajlI' QInvam", lang="tlh")]
    reverse_outputs = [garak.attempt.Message("This is a test", lang="en")]

    all_output_a = garak.attempt.Attempt()
    all_output_a.prompt = tlh_prompt
    all_output_a.notes = {
        "pre_translation_prompt": og_prompt,
    }
    all_output_a.outputs = tlh_outputs
    all_output_a.reverse_translation_outputs = reverse_outputs

    assert all_output_a.outputs == tlh_outputs
    assert all_output_a.outputs_for("tlh") == tlh_outputs
    assert all_output_a.outputs_for(None) == tlh_outputs
    assert all_output_a.outputs_for("*") == tlh_outputs
    assert all_output_a.outputs_for("en") == reverse_outputs
