import os
import pytest

from garak.attempt import Message, Conversation
from garak.generators.groq import GroqChat


def test_groq_invalid_multiple_completions():
    if os.getenv(GroqChat.ENV_VAR, None) is None:
        os.environ[GroqChat.ENV_VAR] = "fake_api_key"
    with pytest.raises(AssertionError) as e_info:
        generator = GroqChat(name="llama3-8b-8192")
        generator._call_model(
            prompt=Message("this is expected to fail"), generations_this_call=2
        )
    assert "n > 1 is not supported" in str(e_info.value)


@pytest.mark.skipif(
    os.getenv(GroqChat.ENV_VAR, None) is None,
    reason=f"GroqChat API key is not set in {GroqChat.ENV_VAR}",
)
def test_groq_instantiate():
    g = GroqChat(name="llama3-8b-8192")


@pytest.mark.skipif(
    os.getenv(GroqChat.ENV_VAR, None) is None,
    reason=f"GroqChat API key is not set in {GroqChat.ENV_VAR}",
)
def test_groq_generate_1():
    g = GroqChat(name="llama3-8b-8192")
    result = g._call_model(Message("this is a test"), generations_this_call=1)
    assert isinstance(result, list), "GroqChat _call_model should return a list"
    assert len(result) == 1, "GroqChat _call_model result list should have one item"
    assert isinstance(result[0], Message), "GroqChat generate() should contain a str"
    result = g.generate(Message("this is a test"), generations_this_call=1)
    assert isinstance(result, list), "GroqChat generate() should return a list"
    assert (
        len(result) == 1
    ), "GroqChat generate() result list should have one item when generations_this_call=1"
    assert isinstance(result[0], Message), "GroqChat generate() should contain a str"
