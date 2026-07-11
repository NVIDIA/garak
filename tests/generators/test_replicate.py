# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import MagicMock

from garak.attempt import Message, Turn, Conversation
import garak.generators.replicate


def test_inference_endpoint_returns_single_message(monkeypatch):
    """InferenceEndpoint must return one Message for the whole output.

    The output is joined into a single string, so ``[Message(r) for r in
    response]`` iterated over the characters and returned one Message per
    character. The base class returns a single ``[Message("".join(...))]``.
    """
    monkeypatch.setenv("REPLICATE_API_TOKEN", "placeholder")
    g = garak.generators.replicate.InferenceEndpoint(name="user/deployed-model")

    prediction = MagicMock()
    prediction.output = ["Hello ", "world"]  # "".join(...) -> "Hello world"
    g.client = MagicMock()
    g.client.deployments.get.return_value.predictions.create.return_value = prediction

    conv = Conversation([Turn("user", Message("hi"))])
    result = g._call_model(conv)

    assert len(result) == 1, "should return one Message, not one per character"
    assert result[0].text == "Hello world"
