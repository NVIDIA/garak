import httpx
import importlib
import os
import pytest
import types

import anthropic

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


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in AnthropicGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.usefixtures("set_fake_env")
@pytest.mark.respx(base_url="https://api.anthropic.com")
def test_anthropic_generator_backs_off_on_529(respx_mock, anthropic_compat_mocks):
    mock_response = anthropic_compat_mocks["anthropic_generation"]
    error_body = {
        "type": "error",
        "error": {"type": "overloaded_error", "message": "Overloaded"},
    }
    # Four 529s exhaust the SDK's own retries on the first call, so garak must
    # back off on the surfaced OverloadedError and retry the call itself
    respx_mock.post("/v1/messages").mock(
        side_effect=[httpx.Response(529, json=error_body)] * 4
        + [httpx.Response(mock_response["code"], json=mock_response["json"])]
    )
    generator = AnthropicGenerator(name=DEFAULT_MODEL_NAME)
    conv = Conversation([Turn("user", Message("Hello, Claude!"))])
    output = generator.generate(conv)
    assert len(output) == 1, "expected one generation after backing off on 529s"
    assert (
        output[0].text == "Hi there! How can I help you today?"
    ), "expected the retried call to return the mocked completion"


def _anthropic_status_error(status, error_cls=None):
    """Build an APIStatusError (or subclass) carrying the given HTTP status."""
    cls = error_cls or anthropic.APIStatusError
    return cls(
        "error",
        response=httpx.Response(
            status,
            request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
        ),
        body=None,
    )


class _ScriptedMessages:
    """Stand-in for client.messages with a scripted create() outcome list."""

    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.calls = 0

    def create(self, **kwargs):
        outcome = self._outcomes[self.calls]
        self.calls += 1
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _generator_with_scripted_client(outcomes):
    generator = AnthropicGenerator(name=DEFAULT_MODEL_NAME)
    generator.client = types.SimpleNamespace(messages=_ScriptedMessages(outcomes))
    return generator


def _success_response():
    return types.SimpleNamespace(content=[types.SimpleNamespace(text="Hi there!")])


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in AnthropicGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.usefixtures("set_fake_env")
def test_anthropic_backs_off_on_529_from_unexported_overloaded_error():
    # SDK 0.60.0-0.100.0 raise 529 as OverloadedError but only define it in
    # anthropic._exceptions, so a getattr guard on the top-level export
    # misses it and the run fails exactly as before the patch.
    class UnexportedOverloadedError(anthropic.APIStatusError):
        pass

    generator = _generator_with_scripted_client(
        [
            _anthropic_status_error(529, UnexportedOverloadedError),
            _anthropic_status_error(529, UnexportedOverloadedError),
            _success_response(),
        ]
    )
    conv = Conversation([Turn("user", Message("Hello, Claude!"))])
    output = generator.generate(conv)
    assert len(output) == 1, "expected one generation after backing off on 529s"
    assert output[0].text == "Hi there!"
    assert generator.client.messages.calls == 3, "expected two retries then success"


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in AnthropicGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.usefixtures("set_fake_env")
def test_anthropic_does_not_back_off_on_400():
    generator = _generator_with_scripted_client([_anthropic_status_error(400)])
    conv = Conversation([Turn("user", Message("Hello, Claude!"))])
    with pytest.raises(anthropic.APIStatusError):
        generator.generate(conv)
    assert generator.client.messages.calls == 1, "4xx errors must not be retried"


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in AnthropicGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.usefixtures("set_fake_env")
def test_anthropic_backs_off_on_502():
    generator = _generator_with_scripted_client(
        [_anthropic_status_error(502), _success_response()]
    )
    conv = Conversation([Turn("user", Message("Hello, Claude!"))])
    output = generator.generate(conv)
    assert len(output) == 1, "expected one generation after backing off on 502"
    assert output[0].text == "Hi there!"
    assert generator.client.messages.calls == 2, "expected one retry then success"
