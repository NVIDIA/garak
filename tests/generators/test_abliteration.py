import base64
import os

import httpx
import pytest

from garak.attempt import Conversation, Message, Turn
from garak.generators.abliteration import AbliterationChat


@pytest.fixture
def set_fake_env(request) -> None:
    stored_env = os.getenv(AbliterationChat.ENV_VAR, None)

    def restore_env():
        if stored_env is not None:
            os.environ[AbliterationChat.ENV_VAR] = stored_env
        else:
            del os.environ[AbliterationChat.ENV_VAR]

    os.environ[AbliterationChat.ENV_VAR] = os.path.abspath(__file__)

    request.addfinalizer(restore_env)


@pytest.mark.usefixtures("set_fake_env")
def test_abliteration_instantiate():
    generator = AbliterationChat(name="abliterated-model")
    assert generator.name == "abliterated-model"
    assert generator.uri == "https://api.abliteration.ai/v1"


@pytest.mark.usefixtures("set_fake_env")
@pytest.mark.respx(base_url="https://api.abliteration.ai/v1")
def test_abliteration_generate(respx_mock, openai_compat_mocks):
    mock_resp = openai_compat_mocks["chat"]
    respx_mock.post("chat/completions").mock(
        return_value=httpx.Response(mock_resp["code"], json=mock_resp["json"])
    )

    generator = AbliterationChat(name="abliterated-model")
    output = generator.generate(
        Conversation([Turn(role="user", content=Message("Hello Abliteration"))])
    )

    assert len(output) == 1
    assert isinstance(output[0], Message)


def test_abliteration_multimodal_payload():
    image_bytes = b"not really a png"
    prompt = Conversation(
        [
            Turn(
                role="user",
                content=Message(
                    text="What's in this image?",
                    data_type=("image/png", None),
                ),
            )
        ]
    )
    prompt.turns[0].content.data = image_bytes

    expected_image_url = (
        f"data:image/png;base64,{base64.b64encode(image_bytes).decode('utf-8')}"
    )

    assert AbliterationChat._conversation_to_list(prompt) == [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "What's in this image?"},
                {
                    "type": "image_url",
                    "image_url": {"url": expected_image_url},
                },
            ],
        }
    ]
