import os
import pytest
import httpx

from garak.attempt import Message, Turn, Conversation
from garak.generators.azure import AzureOpenAIGenerator

DEFAULT_DEPLOYMENT_NAME = "gpt-4o-deployment-test"


@pytest.fixture
def set_fake_env(request) -> None:
    stored_env = {
        AzureOpenAIGenerator.ENV_VAR: os.getenv(AzureOpenAIGenerator.ENV_VAR, None),
        AzureOpenAIGenerator.MODEL_NAME_ENV_VAR: os.getenv(
            AzureOpenAIGenerator.MODEL_NAME_ENV_VAR, None
        ),
        AzureOpenAIGenerator.ENDPOINT_ENV_VAR: os.getenv(
            AzureOpenAIGenerator.ENDPOINT_ENV_VAR, None
        ),
    }

    def restore_env():
        for k, v in stored_env.items():
            if v is not None:
                os.environ[k] = v
            else:
                del os.environ[k]

    os.environ[AzureOpenAIGenerator.ENV_VAR] = "test_value"
    os.environ[AzureOpenAIGenerator.MODEL_NAME_ENV_VAR] = "gpt-4o"
    os.environ[AzureOpenAIGenerator.ENDPOINT_ENV_VAR] = "https://garak.example.com/"
    request.addfinalizer(restore_env)


@pytest.mark.usefixtures("set_fake_env")
def test_azureopenai_invalid_model_names():
    with pytest.raises(ValueError) as e_info:
        del os.environ[AzureOpenAIGenerator.MODEL_NAME_ENV_VAR]
        _ = AzureOpenAIGenerator(name="this is the deployment name")
    assert "environment variable is required" in str(e_info.value)
    with pytest.raises(ValueError) as e_info:
        os.environ[AzureOpenAIGenerator.MODEL_NAME_ENV_VAR] = "gpt-4o"
        _ = AzureOpenAIGenerator(name="")
    assert "name is required for" in str(e_info.value)
    with pytest.raises(ValueError) as e_info:
        os.environ[AzureOpenAIGenerator.MODEL_NAME_ENV_VAR] = "incorrect-model-name"
        _ = AzureOpenAIGenerator(name="this is the deployment name")
    assert "please add one!" in str(e_info.value)


@pytest.mark.usefixtures("set_fake_env")
@pytest.mark.respx(base_url="https://garak.example.com/")
def test_azureopenai_chat(respx_mock, openai_compat_mocks):
    mock_response = openai_compat_mocks["azure_chat_default_generations"]
    extended_request = "openai/deployments/"
    extended_request += DEFAULT_DEPLOYMENT_NAME
    extended_request += "/chat/completions?api-version="
    extended_request += AzureOpenAIGenerator.api_version
    respx_mock.post(extended_request).mock(
        return_value=httpx.Response(mock_response["code"], json=mock_response["json"])
    )
    generator = AzureOpenAIGenerator(name=DEFAULT_DEPLOYMENT_NAME)
    assert generator.name == DEFAULT_DEPLOYMENT_NAME
    assert generator.target_name == os.environ[AzureOpenAIGenerator.MODEL_NAME_ENV_VAR]
    assert isinstance(generator.max_tokens, int)
    generator.max_tokens = 99
    assert generator.max_tokens == 99
    generator.temperature = 0.5
    assert generator.temperature == 0.5
    conv = Conversation([Turn("user", Message("Hello OpenAI!"))])
    output = generator.generate(conv, 1)
    assert len(output) == 1
    for item in output:
        assert isinstance(item, Message)


@pytest.mark.usefixtures("set_fake_env")
@pytest.mark.respx(base_url="https://garak.example.com/")
def test_azureopenai_chat_null_choices(respx_mock, openai_compat_mocks):
    mock_response = openai_compat_mocks["azure_chat_null_choices"]
    extended_request = "openai/deployments/"
    extended_request += DEFAULT_DEPLOYMENT_NAME
    extended_request += "/chat/completions?api-version="
    extended_request += AzureOpenAIGenerator.api_version
    respx_mock.post(extended_request).mock(
        return_value=httpx.Response(mock_response["code"], json=mock_response["json"])
    )
    generator = AzureOpenAIGenerator(name=DEFAULT_DEPLOYMENT_NAME)
    conv = Conversation([Turn("user", Message("Hello OpenAI!"))])
    output = generator.generate(conv, 1)
    assert output == [None]


DATED_CHAT_DEPLOYMENT = "gpt-4o-mini-0718"


@pytest.mark.usefixtures("set_fake_env")
def test_azureopenai_dated_chat_model_uses_chat_endpoint():
    """A chat model carrying an -MMDD suffix must reach the chat endpoint.

    Azure deployment names routinely carry a date suffix, so the model misses
    the exact ``chat_models`` match and falls to the suffix branch. That branch
    only matches when the undated prefix is in ``chat_models``, so everything
    reaching it is a chat model, and sending it to ``client.completions`` puts
    a chat model on the legacy completions API.
    """
    os.environ[AzureOpenAIGenerator.MODEL_NAME_ENV_VAR] = DATED_CHAT_DEPLOYMENT
    generator = AzureOpenAIGenerator(name=DEFAULT_DEPLOYMENT_NAME)

    assert generator.target_name == DATED_CHAT_DEPLOYMENT
    assert generator.generator is generator.client.chat.completions
    assert generator.generator is not generator.client.completions
