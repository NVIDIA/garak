import httpx
import importlib
import os
import pytest
from unittest.mock import patch
from garak.attempt import Message, Turn, Conversation
from garak.exception import BadGeneratorException, RateLimitHit
from garak.generators.mistral import MistralGenerator

DEFAULT_DEPLOYMENT_NAME = "mistral-small-latest"


@pytest.fixture
def set_fake_env(request) -> None:
    stored_env = os.getenv(MistralGenerator.ENV_VAR, None)

    def restore_env():
        if stored_env is not None:
            os.environ[MistralGenerator.ENV_VAR] = stored_env
        else:
            del os.environ[MistralGenerator.ENV_VAR]

    os.environ[MistralGenerator.ENV_VAR] = os.path.abspath(__file__)
    request.addfinalizer(restore_env)


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in MistralGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.usefixtures("set_fake_env")
@pytest.mark.respx(base_url="https://api.mistral.ai/v1")
def test_mistral_generator(respx_mock, mistral_compat_mocks):

    mock_response = mistral_compat_mocks["mistralai_generation"]
    extended_request = "chat/completions"
    respx_mock.post(extended_request).mock(
        return_value=httpx.Response(mock_response["code"], json=mock_response["json"])
    )
    generator = MistralGenerator(name=DEFAULT_DEPLOYMENT_NAME)
    assert generator.name == DEFAULT_DEPLOYMENT_NAME
    conv = Conversation([Turn("user", Message("Hello Mistral!"))])
    output = generator.generate(conv)
    assert len(output) == 1  # expect 1 generation by default


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in MistralGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.skipif(
    os.getenv(MistralGenerator.ENV_VAR, None) is None,
    reason=f"Mistral API key is not set in {MistralGenerator.ENV_VAR}",
)
def test_mistral_chat():
    generator = MistralGenerator(name=DEFAULT_DEPLOYMENT_NAME)
    assert generator.name == DEFAULT_DEPLOYMENT_NAME
    output = generator.generate(Conversation([Turn("user", Message("Hello Mistral!"))]))
    assert len(output) == 1  # expect 1 generation by default


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in MistralGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.usefixtures("set_fake_env")
def test_mistral_403_raises_bad_generator_exception():
    generator = MistralGenerator(name=DEFAULT_DEPLOYMENT_NAME)
    conv = Conversation([Turn("user", Message("Hello Mistral!"))])
    sdk_error = generator.mistralai.models.SDKError("Forbidden", 403, "")
    with patch.object(generator.client.chat, "complete", side_effect=sdk_error):
        with pytest.raises(BadGeneratorException):
            generator.generate(conv)


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in MistralGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.usefixtures("set_fake_env")
def test_mistral_429_raises_rate_limit_hit():
    generator = MistralGenerator(name=DEFAULT_DEPLOYMENT_NAME)
    conv = Conversation([Turn("user", Message("Hello Mistral!"))])
    sdk_error = generator.mistralai.models.SDKError("Rate Limited", 429, "")
    with patch.object(generator.client.chat, "complete", side_effect=sdk_error):
        with pytest.raises(RateLimitHit):
            generator._call_model.__wrapped__(generator, conv)
