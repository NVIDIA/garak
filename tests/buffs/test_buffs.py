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
            assert isinstance(buffed_attempt.prompt, attempt.Conversation), (
                "transformed attempt prompt must be a Conversation"
            )
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


def test_derive_new_attempt_preserves_attributes():
    buff = garak.buffs.base.Buff()
    orig_attempt = attempt.Attempt(
        intent="DirectIntent",
        reverse_translation_outputs={"en": ["test output"]},
        notes={"custom_note": "value"},
        detector_results={"detector_a": [0.0, 1.0]},
        targets=["target1"],
        probe_params={"param1": "val1"},
    )
    derived = buff._derive_new_attempt(orig_attempt)

    # Verify attributes preserved
    assert derived.intent == "DirectIntent"
    assert derived.reverse_translation_outputs == {"en": ["test output"]}
    assert derived.notes["custom_note"] == "value"
    assert derived.detector_results == {"detector_a": [0.0, 1.0]}
    assert derived.targets == ["target1"]
    assert derived.probe_params == {"param1": "val1"}
    assert derived.notes["buff_creator"] == "Buff"

    # Verify deep copy isolation: mutating derived doesn't affect orig
    derived.notes["custom_note"] = "mutated"
    assert orig_attempt.notes["custom_note"] == "value"
    assert "buff_creator" not in orig_attempt.notes

    derived.reverse_translation_outputs["en"].append("new output")
    assert orig_attempt.reverse_translation_outputs == {"en": ["test output"]}

    derived.detector_results["detector_a"].append(0.5)
    assert orig_attempt.detector_results["detector_a"] == [0.0, 1.0]

    derived.targets.append("target2")
    assert orig_attempt.targets == ["target1"]

    derived.probe_params["param1"] = "mutated_val"
    assert orig_attempt.probe_params["param1"] == "val1"
