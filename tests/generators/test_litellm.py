import pytest

from os import getenv

from garak.attempt import Message, Turn, Conversation
from garak.exception import BadGeneratorException
from garak.generators.litellm import LiteLLMGenerator


@pytest.mark.skipif(
    getenv("OPENAI_API_KEY", None) is None,
    reason="OpenAI API key is not set in OPENAI_API_KEY",
)
def test_litellm_openai():
    model_name = "gpt-3.5-turbo"
    generator = LiteLLMGenerator(name=model_name)
    assert generator.name == model_name
    assert isinstance(generator.max_tokens, int)

    output = generator.generate(
        Conversation([Turn(role="user", content=Message("How do I write a sonnet?"))])
    )
    assert len(output) == 1  # expect 1 generation by default

    for item in output:
        assert isinstance(item, Message)


@pytest.mark.skipif(
    getenv("OPENROUTER_API_KEY", None) is None,
    reason="OpenRouter API key is not set in OPENROUTER_API_KEY",
)
def test_litellm_openrouter():
    model_name = "openrouter/google/gemma-7b-it"
    generator = LiteLLMGenerator(name=model_name)
    assert generator.name == model_name
    assert isinstance(generator.max_tokens, int)

    output = generator.generate(Message("How do I write a sonnet?"))
    assert len(output) == 1  # expect 1 generation by default

    for item in output:
        assert isinstance(item, Message)


def test_litellm_model_detection():
    custom_config = {
        "generators": {
            "litellm": {
                "api_base": "https://garak.example.com/v1",
            }
        }
    }
    model_name = "non-existent-model"
    generator = LiteLLMGenerator(name=model_name, config_root=custom_config)
    conv = Conversation(
        [Turn("user", Message("This should raise a BadGeneratorException"))]
    )
    with pytest.raises(BadGeneratorException):
        generator.generate(conv)
    generator = LiteLLMGenerator(name="openai/invalid-model", config_root=custom_config)
    with pytest.raises(BadGeneratorException):
        generator.generate(conv)
