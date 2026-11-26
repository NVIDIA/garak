# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib

import pytest

from garak.generators.base import Generator

# generators whose request carries the system turn
SENDS_SYSTEM_TURN = [
    "anthropic.AnthropicGenerator",
    "cohere.CohereGenerator",
    "guardrails.NeMoGuardrails",
    "huggingface.InferenceAPI",
    "langchain.LangChainLLMGenerator",
    "litellm.LiteLLMGenerator",
    "llm.LLMGenerator",
    "mistral.MistralGenerator",
    "nim.NVOpenAIChat",
    "nvcf.NvcfChat",
    "ollama.OllamaGeneratorChat",
    "openai.OpenAICompatible",
]

# generators that build the request from the last message only
SENDS_LAST_MESSAGE_ONLY = [
    "function.Single",
    "ggml.GgmlGenerator",
    "huggingface.LLaVA",
    "langchain_serve.LangChainServeLLMGenerator",
    "nim.NVOpenAICompletion",
    "nvcf.NvcfCompletion",
    "ollama.OllamaGenerator",
    "replicate.ReplicateGenerator",
    "rest.RestGenerator",
    "watsonx.WatsonXGenerator",
    "websocket.WebSocketGenerator",
]


def _generator_class(path):
    module, name = path.rsplit(".", 1)
    return getattr(importlib.import_module(f"garak.generators.{module}"), name)


def test_system_prompt_support_is_off_by_default():
    assert Generator.supports_system_prompt is False


@pytest.mark.parametrize("path", SENDS_SYSTEM_TURN)
def test_generator_that_sends_system_turn_declares_support(path):
    assert _generator_class(path).supports_system_prompt is True


@pytest.mark.parametrize("path", SENDS_LAST_MESSAGE_ONLY)
def test_generator_that_drops_system_turn_declares_no_support(path):
    assert _generator_class(path).supports_system_prompt is False
