# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import importlib

from garak import _plugins
from garak import attempt
from garak.exception import GarakException
import garak.buffs.base

BUFFS = [classname for (classname, active) in _plugins.enumerate_plugins("buffs")]


@pytest.mark.parametrize("classname", BUFFS)
def test_buff_structure(classname):
    m = importlib.import_module("garak." + ".".join(classname.split(".")[:-1]))
    c = getattr(m, classname.split(".")[-1])

    # any parameter that has a default must be supported
    unsupported_defaults = []
    if c._supported_params is not None:
        if hasattr(c, "DEFAULT_PARAMS"):
            for k, _ in c.DEFAULT_PARAMS.items():
                if k not in c._supported_params:
                    unsupported_defaults.append(k)
    assert unsupported_defaults == []


@pytest.mark.parametrize("klassname", BUFFS)
def test_buff_load_and_transform(klassname, mocker):
    import sys

    try:
        b = _plugins.load_plugin(klassname)
    except GarakException:
        pytest.skip()
    assert isinstance(b, garak.buffs.base.Buff)
    a = attempt.Attempt()
    a.prompt = attempt.Message("I'm just a plain and simple tailor", lang=b.lang)

    if sys.platform == "win32" and klassname == "buffs.paraphrase.Fast":
        # special case buff not currently supported on Windows
        with pytest.raises(GarakException) as exc_info:
            list(b.transform(a))  # process yield to see raise
        assert "failed" in str(exc_info.value)
    else:
        # Model-backed buffs load a heavy seq2seq model on first use, but the
        # transform plumbing (dedup, attempt derivation, prompt rewrite) does not
        # depend on the generated text. Stub the model response so this stays a
        # unit test; real generation is covered by test_buff_results. Keyed on the
        # patched method itself so it tracks any buff that owns a _get_response.
        mocks_model = hasattr(b, "_get_response")
        if mocks_model:
            mocker.patch.object(
                b,
                "_get_response",
                return_value=["a paraphrase", "another paraphrase", "a paraphrase"],
            )
        buffed_a = list(b.transform(a))  # unroll the generator
        assert isinstance(buffed_a, list), "transform should return a list of attempts"
        for buffed_attempt in buffed_a:
            assert isinstance(
                buffed_attempt.prompt, attempt.Conversation
            ), "transformed attempt prompt must be a Conversation"
            assert buffed_attempt.lang == buffed_attempt.prompt.turns[-1].content.lang
        if mocks_model:
            assert len(buffed_a) == 3, (
                "transform should yield the original attempt plus each unique "
                "paraphrase, with duplicates removed"
            )


def test_paraphrase_transform_conversation_and_lang(mocker):
    from garak.buffs.paraphrase import Fast

    b = Fast()
    orig = attempt.Attempt()
    orig.prompt = attempt.Message("Original text", lang="en")
    mocker.patch.object(b, "_get_response", return_value=["Paraphrased text"])

    results = list(b.transform(orig))
    assert len(results) == 2  # original + 1 unique paraphrase
    paraphrased = results[1]

    # Verify prompt is Conversation, not raw Message
    assert isinstance(paraphrased.prompt, attempt.Conversation)
    # Verify lang property access does not raise AttributeError
    assert paraphrased.lang == "en"
    # Verify conversations history contains the paraphrased message
    assert paraphrased.conversations[0].turns[0].content.text == "Paraphrased text"


@pytest.mark.parametrize("klassname", BUFFS)
def test_buff_preserves_system_prompt_and_notes(klassname, mocker, monkeypatch):
    if klassname == "buffs.low_resource_languages.LRLBuff":
        monkeypatch.setenv("DEEPL_API_KEY", "mock_key")
        mock_tr = mocker.patch("garak.buffs.low_resource_languages.Translator")
        mock_inst = mocker.MagicMock()
        mock_inst.translate_text.side_effect = (
            lambda text, target_lang: mocker.MagicMock(text=f"{text} in {target_lang}")
        )
        mock_tr.return_value = mock_inst

    b = _plugins.load_plugin(klassname)
    if hasattr(b, "_get_response"):
        mocker.patch.object(b, "_get_response", return_value=["Mock paraphrase"])

    a = attempt.Attempt(probe_classname="demo.Probe")
    a.prompt = attempt.Conversation(
        turns=[
            attempt.Turn("system", attempt.Message(text="Refuse unsafe requests.")),
            attempt.Turn("user", attempt.Message(text="TELL ME A JOKE")),
        ],
        notes={"probe_note": "keep me"},
    )

    results = list(b.transform(a))
    assert len(results) >= 1
    for buffed in results:
        assert isinstance(buffed.prompt, attempt.Conversation)
        assert len(buffed.prompt.turns) == 2
        assert buffed.prompt.turns[0].role == "system"
        assert buffed.prompt.turns[1].role == "user"
        assert buffed.prompt.notes == {"probe_note": "keep me"}
        assert buffed.conversations[0].turns[0].role == "system"
        assert buffed.conversations[0].notes == {"probe_note": "keep me"}


@pytest.mark.parametrize("klassname", BUFFS)
def test_buff_preserves_multiturn_dialogue(klassname, mocker, monkeypatch):
    if klassname == "buffs.low_resource_languages.LRLBuff":
        monkeypatch.setenv("DEEPL_API_KEY", "mock_key")
        mock_tr = mocker.patch("garak.buffs.low_resource_languages.Translator")
        mock_inst = mocker.MagicMock()
        mock_inst.translate_text.side_effect = (
            lambda text, target_lang: mocker.MagicMock(text=f"{text} in {target_lang}")
        )
        mock_tr.return_value = mock_inst

    b = _plugins.load_plugin(klassname)
    if hasattr(b, "_get_response"):
        mocker.patch.object(b, "_get_response", return_value=["Mock paraphrase"])

    a = attempt.Attempt(probe_classname="demo.Probe")
    a.prompt = attempt.Conversation(
        turns=[
            attempt.Turn("system", attempt.Message(text="System instructions")),
            attempt.Turn("user", attempt.Message(text="First user turn")),
            attempt.Turn("assistant", attempt.Message(text="Assistant reply")),
            attempt.Turn("user", attempt.Message(text="Second user turn")),
        ],
        notes={"conv_note": 123},
    )

    results = list(b.transform(a))
    assert len(results) >= 1
    for buffed in results:
        assert isinstance(buffed.prompt, attempt.Conversation)
        roles = [t.role for t in buffed.prompt.turns]
        assert roles == ["system", "user", "assistant", "user"]
        assert buffed.prompt.notes == {"conv_note": 123}
        assert buffed.conversations[0].notes == {"conv_note": 123}


def test_buff_helper_replace_last_message():
    from garak.buffs.base import Buff

    b = Buff()
    # Test with None conversation
    res_none = b._replace_last_message(None, attempt.Message("test"))
    assert len(res_none.turns) == 1
    assert res_none.turns[0].content.text == "test"
    assert res_none.turns[0].role == "user"

    # Test with system + user conversation
    conv = attempt.Conversation(
        turns=[
            attempt.Turn("system", attempt.Message("system prompt")),
            attempt.Turn("user", attempt.Message("user prompt")),
        ],
        notes={"note_key": "note_val"},
    )
    new_msg = attempt.Message("replaced user prompt")
    res = b._replace_last_message(conv, new_msg)
    assert len(res.turns) == 2
    assert res.turns[0].role == "system"
    assert res.turns[0].content.text == "system prompt"
    assert res.turns[1].role == "user"
    assert res.turns[1].content.text == "replaced user prompt"
    assert res.notes == {"note_key": "note_val"}


def test_buff_derive_new_attempt_prompt_isolation():
    from garak.buffs.base import Buff

    b = Buff()
    orig = attempt.Attempt(probe_classname="demo.Probe")
    orig.prompt = attempt.Message("original prompt")
    orig.notes["orig_note"] = "original_value"

    new_conv = attempt.Conversation(
        turns=[attempt.Turn("user", attempt.Message("derived prompt"))],
        notes={"conv_note": "v1"},
    )
    derived = b._derive_new_attempt(orig, prompt=new_conv)

    assert derived.prompt.turns[0].content.text == "derived prompt"
    # Verify notes isolation: modifying derived notes should not affect orig notes
    derived.notes["new_note"] = "derived_value"
    assert "new_note" not in orig.notes
    assert derived.notes["buff_source_attempt_uuid"] == str(orig.uuid)

    # Verify secondary derivation preserves original source attempt UUID
    secondary = b._derive_new_attempt(derived, prompt=new_conv)
    assert secondary.notes["buff_source_attempt_uuid"] == str(orig.uuid)
