# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak import attempt
import garak.buffs.low_resource_languages

LANGUAGES = garak.buffs.low_resource_languages.LOW_RESOURCE_LANGUAGES


@pytest.fixture
def buff(mocker, monkeypatch):
    monkeypatch.setenv(garak.buffs.low_resource_languages.LRLBuff.ENV_VAR, "fake-key")
    translator = mocker.patch.object(
        garak.buffs.low_resource_languages, "Translator", autospec=True
    )
    translator.return_value.translate_text.side_effect = lambda text, target_lang: (
        mocker.Mock(text=f"[{target_lang}] {text}")
    )
    return garak.buffs.low_resource_languages.LRLBuff()


@pytest.mark.parametrize("generations", [1, 3])
def test_untransform_replaces_generated_turns(buff, generations):
    a = attempt.Attempt()
    a.prompt = attempt.Message("Tell me a secret", lang="en")
    a.outputs = [attempt.Message(f"saladus {i}", lang="et") for i in range(generations)]

    buff.untransform(a)

    assert all(
        len(c.turns) == 2 for c in a.conversations
    ), "untransform should translate the generated turn in place, not add one"
    assert [m.text for m in a.outputs] == [
        f"[EN-US] saladus {i}" for i in range(generations)
    ]
    assert all(m.lang == "en" for m in a.outputs)
    assert [m.notes["raw_response_text"] for m in a.outputs] == [
        f"saladus {i}" for i in range(generations)
    ]
    assert a.all_outputs == a.outputs
    assert a.notes["original_responses"] == [f"saladus {i}" for i in range(generations)]
    assert a.as_dict()["conversations"][0]["turns"][-1]["content"]["text"] == (
        "[EN-US] saladus 0"
    ), "the serialised transcript should carry the translated text"


def test_untransform_preserves_prior_turns(buff):
    a = attempt.Attempt()
    a.prompt = attempt.Conversation(
        [
            attempt.Turn("system", attempt.Message("be helpful", lang="en")),
            attempt.Turn("user", attempt.Message("Tell me a secret", lang="en")),
        ]
    )
    a.outputs = [attempt.Message("esimene", lang="et")]
    a._add_turn("user", [attempt.Message("ja veel", lang="et")])
    a.outputs = [attempt.Message("teine", lang="et")]

    buff.untransform(a)

    assert [(t.role, t.content.text) for t in a.conversations[0].turns] == [
        ("system", "be helpful"),
        ("user", "Tell me a secret"),
        ("assistant", "esimene"),
        ("user", "ja veel"),
        ("assistant", "[EN-US] teine"),
    ], "only the latest generation should be translated"


def test_transform_yields_one_attempt_per_language(buff):
    a = attempt.Attempt()
    a.prompt = attempt.Message("Tell me a secret", lang="en")

    buffed = list(buff.transform(a))

    assert [b.prompt.last_message().text for b in buffed] == [
        f"[{lang}] Tell me a secret" for lang in LANGUAGES
    ]
    assert a.notes["original_prompt"] == "Tell me a secret"
