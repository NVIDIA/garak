"""Tests for OpenRouter.ai API Generator"""

import os
import httpx
import pytest

import openai

import garak.exception
from garak.generators.openrouter import OpenRouterGenerator


@pytest.fixture
def set_fake_env(request) -> None:
    stored_env = os.getenv(OpenRouterGenerator.ENV_VAR, None)

    def restore_env():
        if stored_env is not None:
            os.environ[OpenRouterGenerator.ENV_VAR] = stored_env
        else:
            del os.environ[OpenRouterGenerator.ENV_VAR]

    os.environ[OpenRouterGenerator.ENV_VAR] = os.path.abspath(__file__)

    request.addfinalizer(restore_env)


def test_openai_version():
    assert openai.__version__.split(".")[0] == "1"  # expect openai module v1.x


@pytest.mark.usefixtures("set_fake_env")
def test_openrouter_invalid_model_names():
    with pytest.raises(ValueError) as e_info:
        generator = OpenRouterGenerator(name="")
    assert "Model name must be specified" in str(e_info.value)


@pytest.mark.skipif(
    os.getenv(OpenRouterGenerator.ENV_VAR, None) is None,
    reason=f"OpenRouter API key is not set in {OpenRouterGenerator.ENV_VAR}",
)
def test_openrouter_chat():
    generator = OpenRouterGenerator(name="anthropic/claude-3-sonnet")
    assert generator.name == "anthropic/claude-3-sonnet"
    assert isinstance(generator.max_tokens, int)
    generator.max_tokens = 99
    assert generator.max_tokens == 99
    generator.temperature = 0.5
    assert generator.temperature == 0.5
    output = generator.generate("Hello OpenRouter!")
    assert len(output) == 1  # expect 1 generation by default
    for item in output:
        assert isinstance(item, str)
    # Test with chat messages
    messages = [
        {"role": "user", "content": "Hello OpenRouter!"},
        {"role": "assistant", "content": "Hello! How can I help you today?"},
        {"role": "user", "content": "How do I write a sonnet?"},
    ]
    output = generator.generate(messages)
    assert len(output) == 1  # expect 1 generation by default
    for item in output:
        assert isinstance(item, str)


def test_context_lengths():
    # Test with a known model
    generator = OpenRouterGenerator(name="anthropic/claude-3-sonnet")
    assert generator.context_len == 200000

    # Test with an unknown model
    generator = OpenRouterGenerator(name="unknown/model")
    assert generator.context_len == 4096  # default context length
