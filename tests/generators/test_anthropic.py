import base64
import httpx
import importlib
import os
import pathlib
import pytest
from garak.attempt import Message, Turn, Conversation
from garak.exception import GarakException
from garak.generators.anthropic import AnthropicGenerator
from garak.harnesses.base import _modality_match
from garak.probes.visual_jailbreak import FigStep

DEFAULT_MODEL_NAME = "claude-sonnet-4-5"
IMAGE_ASSET = pathlib.Path(__file__).parents[1] / "_assets" / "tinytrans.gif"


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


def test_anthropic_image_turn_becomes_base64_image_block():
    conv = Conversation(
        [Turn("user", Message(text="describe", data_path=str(IMAGE_ASSET)))]
    )
    system, messages = AnthropicGenerator._split_system_and_messages(conv)
    assert system is None
    assert len(messages) == 1
    assert messages[0]["role"] == "user"
    image_block, text_block = messages[0]["content"]
    assert image_block["type"] == "image"
    assert image_block["source"]["type"] == "base64"
    assert image_block["source"]["media_type"] == "image/gif"
    assert base64.b64decode(image_block["source"]["data"]) == IMAGE_ASSET.read_bytes()
    assert text_block == {"type": "text", "text": "describe"}


@pytest.mark.parametrize("text", [None, ""])
def test_anthropic_image_only_turn_has_no_empty_text_block(text):
    # the Messages API rejects empty text blocks, so an image-only prompt
    # must be sent as just the image
    conv = Conversation([Turn("user", Message(text=text, data_path=str(IMAGE_ASSET)))])
    _, messages = AnthropicGenerator._split_system_and_messages(conv)
    assert [block["type"] for block in messages[0]["content"]] == ["image"]


def test_anthropic_text_turns_stay_plain_strings_alongside_images():
    conv = Conversation(
        [
            Turn("system", Message("You are concise.")),
            Turn("user", Message(text="what is this?", data_path=str(IMAGE_ASSET))),
            Turn("assistant", Message("A tiny transparent gif.")),
            Turn("user", Message("Are you sure?")),
        ]
    )
    system, messages = AnthropicGenerator._split_system_and_messages(conv)
    assert system == "You are concise."
    assert [m["role"] for m in messages] == ["user", "assistant", "user"]
    assert isinstance(messages[0]["content"], list)
    assert messages[1]["content"] == "A tiny transparent gif."
    assert messages[2]["content"] == "Are you sure?"


def test_anthropic_unsupported_attachment_type_raises():
    message = Message(text="listen", data_type=("audio/wav", None))
    message.data = b"RIFF"
    conv = Conversation([Turn("user", message)])
    with pytest.raises(GarakException, match="audio/wav"):
        AnthropicGenerator._split_system_and_messages(conv)


def test_anthropic_modality_accepts_image_probes():
    assert "image" in AnthropicGenerator.modality["in"]
    assert _modality_match(
        FigStep.modality["in"], AnthropicGenerator.modality["in"], strict=False
    )
    # text-only probes must still be scheduled
    assert _modality_match({"text"}, AnthropicGenerator.modality["in"], strict=False)


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in AnthropicGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.usefixtures("set_fake_env")
def test_anthropic_generator_sends_image_block(monkeypatch):
    generator = AnthropicGenerator(name=DEFAULT_MODEL_NAME)
    sent = {}

    class FakeBlock:
        text = "It is a transparent pixel."

    class FakeResponse:
        content = [FakeBlock()]

    def fake_create(*, model, messages, max_tokens, **kwargs):
        sent["messages"] = messages
        return FakeResponse()

    monkeypatch.setattr(generator.client.messages, "create", fake_create)
    conv = Conversation(
        [Turn("user", Message(text="describe", data_path=str(IMAGE_ASSET)))]
    )
    output = generator.generate(conv)
    assert output[0].text == "It is a transparent pixel."
    assert sent["messages"][0]["content"][0]["type"] == "image"
    assert sent["messages"][0]["content"][1] == {"type": "text", "text": "describe"}
