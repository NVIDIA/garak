# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
from unittest.mock import MagicMock, patch
import pytest

import garak.cli
from garak.attempt import Message, Turn, Conversation
from garak.generators.nim import NVOpenAIChat, NVOpenAICompletion, NVMultimodal, Vision


@pytest.mark.skipif(
    os.getenv(NVOpenAIChat.ENV_VAR, None) is None,
    reason=f"NIM API key is not set in {NVOpenAIChat.ENV_VAR}",
)
def test_nim_instantiate():
    g = NVOpenAIChat(name="google/gemma-2b")


@pytest.mark.skipif(
    os.getenv(NVOpenAIChat.ENV_VAR, None) is None,
    reason=f"NIM API key is not set in {NVOpenAIChat.ENV_VAR}",
)
def test_nim_generate_1():
    g = NVOpenAIChat(name="google/gemma-2b")
    result = g._call_model(
        Conversation([Turn(role="user", content=Message("this is a test"))])
    )
    assert isinstance(result, list), "NIM _call_model should return a list"
    assert len(result) == 1, "NIM _call_model result list should have one item"
    assert isinstance(result[0], Message), "NIM _call_model should return a list"
    result = g.generate(
        Conversation([Turn(role="user", content=Message("this is a test"))])
    )
    assert isinstance(result, list), "NIM generate() should return a list"
    assert (
        len(result) == 1
    ), "NIM generate() result list should have one item using default generations_this_call"
    assert isinstance(
        result[0], Message
    ), "NIM generate() should return a list of Turns"


@pytest.mark.skipif(
    os.getenv(NVOpenAIChat.ENV_VAR, None) is None,
    reason=f"NIM API key is not set in {NVOpenAIChat.ENV_VAR}",
)
def test_nim_parallel_attempts():
    garak.cli.main(
        "-m nim -p lmrc.Anthropomorphisation -g 1 -n google/gemma-2b --parallel_attempts 10".split()
    )
    assert True


@pytest.mark.skipif(
    os.getenv(NVOpenAIChat.ENV_VAR, None) is None,
    reason=f"NIM API key is not set in {NVOpenAIChat.ENV_VAR}",
)
def test_nim_hf_detector():
    garak.cli.main("-m nim -p lmrc.Bullying -g 1 -n google/gemma-2b".split())
    assert True


@pytest.mark.skipif(
    os.getenv(NVOpenAIChat.ENV_VAR, None) is None,
    reason=f"NIM API key is not set in {NVOpenAIChat.ENV_VAR}",
)
def test_nim_conservative_api():  # extraneous params can throw 422
    g = NVOpenAIChat(name="nvidia/nemotron-4-340b-instruct")
    result = g._call_model(
        Conversation([Turn(role="user", content=Message("this is a test"))])
    )
    assert isinstance(result, list), "NIM _call_model should return a list"
    assert len(result) == 1, "NIM _call_model result list should have one item"
    assert isinstance(
        result[0], Message
    ), "NIM _call_model should return a list of Messages"
    result = g.generate(
        Conversation([Turn(role="user", content=Message("this is a test"))])
    )
    assert isinstance(result, list), "NIM generate() should return a list"
    assert (
        len(result) == 1
    ), "NIM generate() result list should have one item using default generations_this_call"
    assert isinstance(
        result[0], Message
    ), "NIM generate() should return a list of Turns"


def test_nim_vision_prep():
    test_prompt = "test vision prompt"
    expected_text = (
        test_prompt
        + ' <img src="data:image/gif;base64,R0lGODlhAQABAIABAP///wAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==" />'
    )
    t = Conversation(
        [
            Turn(
                "user",
                Message(text=test_prompt, data_path="tests/_assets/tinytrans.gif"),
            )
        ]
    )

    v = Vision  # skip instantiation, not req'd
    setattr(v, "max_input_len", 100_000)
    setattr(v, "embed_data", True)
    try:
        vision_conv = Vision._prepare_prompt(v, t)
        assert vision_conv.last_message().text == expected_text
        assert vision_conv.last_message().data is None
        assert Vision._conversation_to_list(vision_conv) == [
            {"role": "user", "content": expected_text}
        ]
        assert t.last_message().data is not None
    finally:
        delattr(v, "max_input_len")  # remove to avoid follow on test impacts
        delattr(v, "embed_data")


def test_nim_multimodal_audio_in_memory_prep():
    msg = Message(text="test audio prompt", data_type=("audio/wav", None))
    msg.data = b"RIFF"
    t = Conversation([Turn("user", msg)])
    expected_text = 'test audio prompt <audio src="data:audio/wav;base64,UklGRg==" />'

    m = NVMultimodal
    setattr(m, "max_input_len", 100_000)
    setattr(m, "embed_data", True)
    try:
        prepared_conv = NVMultimodal._prepare_prompt(m, t)
        assert prepared_conv.last_message().text == expected_text
        assert prepared_conv.last_message().data is None
        assert NVMultimodal._conversation_to_list(prepared_conv) == [
            {"role": "user", "content": expected_text}
        ]
        assert t.last_message().data == b"RIFF"
    finally:
        delattr(m, "max_input_len")
        delattr(m, "embed_data")


def test_nim_completion_missing_model_name(monkeypatch):
    monkeypatch.setenv(NVOpenAICompletion.ENV_VAR, "test-fake-key")
    mock_client = MagicMock()
    mock_client.models.list.return_value.data = []
    with (
        patch.object(NVOpenAICompletion, "_validate_uri_connectivity"),
        patch("openai.OpenAI", return_value=mock_client),
        pytest.raises(ValueError, match="NIMs require model name to be set"),
    ):
        NVOpenAICompletion(name="")
