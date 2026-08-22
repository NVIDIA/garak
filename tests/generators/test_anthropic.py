import httpx
import importlib
import os
import pytest
from garak.attempt import Message, Turn, Conversation
from garak.generators.anthropic import AnthropicGenerator

DEFAULT_MODEL_NAME = "claude-sonnet-4-5"


@pytest.fixture
def set_fake_env(request) -> None:
    stored_env = os.getenv(AnthropicGenerator.ENV_VAR, None)

    def restore_env():
        if stored_env is not None:
            os.environ[AnthropicGenerator.ENV_VAR] = stored_env
        else:
            del os.environ[AnthropicGenerator.ENV_VAR]

    os.environ[AnthropicGenerator.ENV_VAR] = os.path.abspath(__file__)
    request.addfinalizer(restore_env)


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in AnthropicGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.usefixtures("set_fake_env")
@pytest.mark.respx(base_url="https://api.anthropic.com")
def test_anthropic_generator(respx_mock, anthropic_compat_mocks):
    mock_response = anthropic_compat_mocks["anthropic_generation"]
    respx_mock.post("/v1/messages").mock(
        return_value=httpx.Response(mock_response["code"], json=mock_response["json"])
    )
    generator = AnthropicGenerator(name=DEFAULT_MODEL_NAME)
    assert generator.name == DEFAULT_MODEL_NAME
    conv = Conversation([Turn("user", Message("Hello, Claude!"))])
    output = generator.generate(conv)
    assert len(output) == 1
    assert output[0].text == "Hi there! How can I help you today?"


def test_anthropic_splits_system_from_messages():
    conv = Conversation(
        [
            Turn("system", Message("You are concise.")),
            Turn("user", Message("Hi.")),
        ]
    )
    system, messages = AnthropicGenerator._split_system_and_messages(conv)
    assert system == "You are concise."
    assert messages == [{"role": "user", "content": "Hi."}]


def test_anthropic_no_system_returns_none():
    conv = Conversation([Turn("user", Message("Hi."))])
    system, messages = AnthropicGenerator._split_system_and_messages(conv)
    assert system is None
    assert messages == [{"role": "user", "content": "Hi."}]


def test_anthropic_default_params_shape():
    # `max_tokens` is inherited from Generator.DEFAULT_PARAMS, so the override
    # only adds the Anthropic-specific knobs.
    assert "uri" in AnthropicGenerator.DEFAULT_PARAMS
    assert AnthropicGenerator.DEFAULT_PARAMS["uri"] is None
    assert "max_tokens" in AnthropicGenerator.DEFAULT_PARAMS


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in AnthropicGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.usefixtures("set_fake_env")
def test_anthropic_uri_threads_to_client_base_url():
    custom = "https://custom-anthropic-endpoint.example.com"
    generator = AnthropicGenerator(name=DEFAULT_MODEL_NAME)
    generator.uri = custom
    generator._load_unsafe()
    assert str(generator.client.base_url).startswith(custom)


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in AnthropicGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.skipif(
    os.getenv(AnthropicGenerator.ENV_VAR, None) is None,
    reason=f"Anthropic API key is not set in {AnthropicGenerator.ENV_VAR}",
)
def test_anthropic_chat():
    generator = AnthropicGenerator(name=DEFAULT_MODEL_NAME)
    assert generator.name == DEFAULT_MODEL_NAME
    conv = Conversation([Turn("user", Message("Hello, Claude!"))])
    output = generator.generate(conv)
    assert len(output) == 1
