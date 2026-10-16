import os
import pytest

from garak.attempt import Message, Turn, Conversation
from garak.generators.orcarouter import OrcaRouter


def test_orcarouter_invalid_multiple_completions():
    if os.getenv(OrcaRouter.ENV_VAR, None) is None:
        os.environ[OrcaRouter.ENV_VAR] = "fake_api_key"
    with pytest.raises(AssertionError) as e_info:
        generator = OrcaRouter(name="orcarouter/auto")
        generator._call_model(
            prompt=Message("this is expected to fail"), generations_this_call=2
        )
    assert "n > 1 is not supported" in str(e_info.value)


@pytest.mark.skipif(
    os.getenv(OrcaRouter.ENV_VAR, None) is None,
    reason=f"OrcaRouter API key is not set in {OrcaRouter.ENV_VAR}",
)
def test_orcarouter_instantiate():
    g = OrcaRouter(name="orcarouter/auto")


@pytest.mark.skipif(
    os.getenv(OrcaRouter.ENV_VAR, None) is None,
    reason=f"OrcaRouter API key is not set in {OrcaRouter.ENV_VAR}",
)
def test_orcarouter_generate_1():
    g = OrcaRouter(name="orcarouter/auto")
    convo = Conversation([Turn("user", Message("this is a test"))])
    result = g._call_model(convo, generations_this_call=1)
    assert isinstance(result, list), "OrcaRouter _call_model should return a list"
    assert len(result) == 1, "OrcaRouter _call_model result list should have one item"
    assert isinstance(result[0], Message), "OrcaRouter generate() should contain a str"
    result = g.generate(convo, generations_this_call=1)
    assert isinstance(result, list), "OrcaRouter generate() should return a list"
    assert (
        len(result) == 1
    ), "OrcaRouter generate() result list should have one item when generations_this_call=1"
    assert isinstance(result[0], Message), "OrcaRouter generate() should contain a str"
