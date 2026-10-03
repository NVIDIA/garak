# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak import attempt
from garak.buffs.encoding import Base64, CharCode
from garak.buffs.lowercase import Lowercase


@pytest.mark.parametrize("buff_class", [Lowercase, Base64, CharCode])
def test_buffs_preserve_conversation_context(buff_class):
    source = attempt.Attempt()
    source.prompt = attempt.Conversation(
        turns=[
            attempt.Turn("system", attempt.Message("Keep this instruction")),
            attempt.Turn("user", attempt.Message("Previous question")),
            attempt.Turn("user", attempt.Message("CURRENT QUESTION")),
        ],
        notes={"probe_note": "keep me"},
    )

    transformed = list(buff_class().transform(source))[0]

    assert [turn.role for turn in transformed.prompt.turns] == [
        "system",
        "user",
        "user",
    ]
    assert [turn.content.text for turn in transformed.prompt.turns[:2]] == [
        "Keep this instruction",
        "Previous question",
    ]
    assert transformed.prompt.turns[-1].content.text != "CURRENT QUESTION"
    assert transformed.prompt.notes == {"probe_note": "keep me"}
    assert transformed.conversations[0] == transformed.prompt


def test_lowercase_preserves_generated_histories():
    source = attempt.Attempt()
    source.prompt = attempt.Conversation(
        turns=[
            attempt.Turn("system", attempt.Message("Keep this instruction")),
            attempt.Turn("user", attempt.Message("CURRENT QUESTION")),
        ]
    )
    source.outputs = ["first answer", "second answer"]

    transformed = list(Lowercase().transform(source))[0]

    assert len(transformed.conversations) == 2
    assert all(
        conversation.turns[1].content.text == "current question"
        for conversation in transformed.conversations
    )
    assert [
        conversation.turns[-1].content.text
        for conversation in transformed.conversations
    ] == ["first answer", "second answer"]
