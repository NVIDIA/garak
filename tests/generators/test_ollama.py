import importlib
import json
import os
import pytest
import respx
import httpx

from garak.attempt import Message, Turn, Conversation
from garak.generators.ollama import OllamaGeneratorChat, OllamaGenerator

PINGED_OLLAMA_SERVER = (
    False  # Avoid calling the server multiple times if it is not running
)
OLLAMA_SERVER_UP = False

try:
    import ollama
except:
    pytest.skip(
        "couldn't import ollama, skipping ollama tests", allow_module_level=True
    )


@pytest.mark.skipif(
    importlib.util.find_spec("ollama") is None,
    reason="requires 'ollama' Python module to be installed",
)
def ollama_is_running():
    global PINGED_OLLAMA_SERVER
    global OLLAMA_SERVER_UP

    if not PINGED_OLLAMA_SERVER:
        try:
            ollama.list()  # Gets a list of all pulled models. Used as a ping
            OLLAMA_SERVER_UP = True
        except ConnectionError:
            OLLAMA_SERVER_UP = False
        finally:
            PINGED_OLLAMA_SERVER = True
    return OLLAMA_SERVER_UP


def no_models():
    # In newer versions of ollama, list() returns a ListResponse object
    response = ollama.list()

    try:
        # Try to access the models attribute or property
        models = getattr(response, "models", None)
        if models is None:
            # If no models attribute, try using it as a dict
            models = response.get("models", [])

        # Check if models is empty
        return len(models) == 0
    except (AttributeError, TypeError):
        # If we can't access models, assume there are no models
        return True


@pytest.mark.skipif(
    not all(
        [
            importlib.util.find_spec(m)
            for m in OllamaGeneratorChat.extra_dependency_names
        ]
    ),
    reason="missing optional dependency",
)
@pytest.mark.skipif(
    not ollama_is_running(),
    reason=f"Ollama server is not currently running",
)
def test_error_on_nonexistant_model_chat():
    model_name = "non-existent-model"
    gen = OllamaGeneratorChat(model_name)
    with pytest.raises(ollama.ResponseError):
        conv = Conversation([Turn("user", Message("This shouldnt work"))])
        gen.generate(conv)


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in OllamaGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.skipif(
    not ollama_is_running(),
    reason=f"Ollama server is not currently running",
)
def test_error_on_nonexistant_model():
    model_name = "non-existant-model"
    gen = OllamaGenerator(model_name)
    with pytest.raises(ollama.ResponseError):
        conv = Conversation([Turn("user", Message("This shouldnt work"))])
        gen.generate(conv)


@pytest.mark.skipif(
    not all(
        [
            importlib.util.find_spec(m)
            for m in OllamaGeneratorChat.extra_dependency_names
        ]
    ),
    reason="missing optional dependency",
)
@pytest.mark.skipif(
    not ollama_is_running(),
    reason=f"Ollama server is not currently running",
)
@pytest.mark.skipif(
    not ollama_is_running() or no_models(),  # Avoid checking models if no server
    reason=f"No Ollama models pulled",
)
# This test might fail if the GPU is busy, and the generation takes more than 30 seconds
def test_generation_on_pulled_model_chat():
    model_name = ollama.list().models[0].model
    gen = OllamaGeneratorChat(model_name)
    conv = Conversation([Turn("user", Message('Say "Hello!"'))])
    responses = gen.generate(conv)
    assert len(responses) == 1
    assert all(isinstance(response, Message) for response in responses)
    assert all(len(response.text) > 0 for response in responses)


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in OllamaGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.skipif(
    not ollama_is_running(),
    reason=f"Ollama server is not currently running",
)
@pytest.mark.skipif(
    not ollama_is_running() or no_models(),  # Avoid checking models if no server
    reason=f"No Ollama models pulled",
)
# This test might fail if the GPU is busy, and the generation takes more than 30 seconds
def test_generation_on_pulled_model():
    model_name = ollama.list().models[0].model
    gen = OllamaGenerator(model_name)
    conv = Conversation([Turn("user", Message('Say "Hello!"'))])
    responses = gen.generate(conv)
    assert len(responses) == 1
    assert all(isinstance(response, Message) for response in responses)
    assert all(len(response.text) > 0 for response in responses)


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in OllamaGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.respx(base_url="http://" + OllamaGenerator.DEFAULT_PARAMS["host"])
def test_ollama_generation_mocked(respx_mock):
    mock_response = {"model": "mistral", "response": "Hello how are you?"}
    respx_mock.post("/api/generate").mock(
        return_value=httpx.Response(200, json=mock_response)
    )
    gen = OllamaGenerator("mistral")
    conv = Conversation([Turn("user", Message("Bla bla"))])
    generation = gen.generate(conv)
    assert generation == [Message("Hello how are you?")]


@pytest.mark.skipif(
    not all(
        [
            importlib.util.find_spec(m)
            for m in OllamaGeneratorChat.extra_dependency_names
        ]
    ),
    reason="missing optional dependency",
)
@pytest.mark.respx(base_url="http://" + OllamaGenerator.DEFAULT_PARAMS["host"])
def test_ollama_generation_chat_mocked(respx_mock):
    mock_response = {
        "model": "mistral",
        "message": {"role": "assistant", "content": "Hello how are you?"},
    }
    respx_mock.post("/api/chat").mock(
        return_value=httpx.Response(200, json=mock_response)
    )
    gen = OllamaGeneratorChat("mistral")
    conv = Conversation([Turn("user", Message("Bla bla"))])
    generation = gen.generate(conv)
    assert generation == [Message("Hello how are you?")]


@pytest.mark.respx(base_url="http://" + OllamaGenerator.DEFAULT_PARAMS["host"])
def test_empty_generation_is_retried(respx_mock):
    """An empty generation is retried and a recovered response is returned."""
    route = respx_mock.post("/api/generate").mock(
        side_effect=[
            httpx.Response(200, json={"model": "mistral", "response": None}),
            httpx.Response(200, json={"model": "mistral", "response": "Recovered"}),
        ]
    )
    gen = OllamaGenerator("mistral")
    conv = Conversation([Turn("user", Message("Bla bla"))])
    generation = gen.generate(conv)
    assert generation == [
        Message("Recovered")
    ], "an empty generation must be retried and the recovered text surfaced"
    assert (
        route.call_count == 2
    ), "the empty first response should have triggered exactly one retry"


@pytest.mark.respx(base_url="http://" + OllamaGenerator.DEFAULT_PARAMS["host"])
def test_empty_chat_generation_is_retried(respx_mock):
    """An empty chat generation is retried and a recovered response is returned."""
    route = respx_mock.post("/api/chat").mock(
        side_effect=[
            httpx.Response(
                200,
                json={"model": "mistral", "message": {"role": "assistant"}},
            ),
            httpx.Response(
                200,
                json={
                    "model": "mistral",
                    "message": {"role": "assistant", "content": "Recovered"},
                },
            ),
        ]
    )
    gen = OllamaGeneratorChat("mistral")
    conv = Conversation([Turn("user", Message("Bla bla"))])
    generation = gen.generate(conv)
    assert generation == [
        Message("Recovered")
    ], "an empty chat generation must be retried and the recovered text surfaced"
    assert (
        route.call_count == 2
    ), "the empty first chat response should have triggered exactly one retry"


@pytest.mark.respx(base_url="http://" + OllamaGenerator.DEFAULT_PARAMS["host"])
def test_content_generation_is_not_retried(respx_mock):
    """A response with content goes through on the first attempt."""
    route = respx_mock.post("/api/generate").mock(
        return_value=httpx.Response(200, json={"model": "mistral", "response": "Hi"})
    )
    gen = OllamaGenerator("mistral")
    conv = Conversation([Turn("user", Message("Bla bla"))])
    generation = gen.generate(conv)
    assert generation == [
        Message("Hi")
    ], "the content-bearing response is returned as is"
    assert (
        route.call_count == 1
    ), "a generation carrying content must not trigger retries"


@pytest.mark.respx(base_url="http://" + OllamaGenerator.DEFAULT_PARAMS["host"])
def test_error_on_nonexistant_model_mocked(respx_mock):
    mock_response = {"error": "No such model"}
    respx_mock.post("/api/generate").mock(
        return_value=httpx.Response(404, json=mock_response)
    )
    model_name = "non-existant-model"
    gen = OllamaGenerator(model_name)
    with pytest.raises(ollama.ResponseError):
        conv = Conversation([Turn("user", Message("This shouldnt work"))])
        gen.generate(conv)


@pytest.mark.respx(base_url="http://" + OllamaGenerator.DEFAULT_PARAMS["host"])
def test_error_on_nonexistant_model_chat_mocked(respx_mock):
    mock_response = {"error": "No such model"}
    respx_mock.post("/api/chat").mock(
        return_value=httpx.Response(404, json=mock_response)
    )
    model_name = "non-existant-model"
    gen = OllamaGeneratorChat(model_name)
    with pytest.raises(ollama.ResponseError):
        conv = Conversation([Turn("user", Message("This shouldnt work"))])
        gen.generate(conv)


@pytest.mark.skipif(
    not all(
        [
            importlib.util.find_spec(m)
            for m in OllamaGeneratorChat.extra_dependency_names
        ]
    ),
    reason="missing optional dependency",
)
@pytest.mark.respx(base_url="http://" + OllamaGenerator.DEFAULT_PARAMS["host"])
def test_ollama_chat_forwards_generation_options(respx_mock):
    mock_response = {
        "model": "mistral",
        "message": {"role": "assistant", "content": "Hello how are you?"},
    }
    respx_mock.post("/api/chat").mock(
        return_value=httpx.Response(200, json=mock_response)
    )
    gen = OllamaGeneratorChat("mistral")
    gen.max_tokens = 10
    gen.temperature = 0.1
    gen.top_k = 3
    gen.seed = 42
    conv = Conversation([Turn("user", Message("Bla bla"))])
    gen.generate(conv)

    sent = json.loads(respx_mock.calls.last.request.content)
    assert sent["options"]["num_predict"] == 10
    assert sent["options"]["temperature"] == 0.1
    assert sent["options"]["top_k"] == 3
    assert sent["options"]["seed"] == 42


@pytest.mark.skipif(
    not all(
        [importlib.util.find_spec(m) for m in OllamaGenerator.extra_dependency_names]
    ),
    reason="missing optional dependency",
)
@pytest.mark.respx(base_url="http://" + OllamaGenerator.DEFAULT_PARAMS["host"])
def test_ollama_forwards_generation_options(respx_mock):
    mock_response = {"model": "mistral", "response": "Hello how are you?"}
    respx_mock.post("/api/generate").mock(
        return_value=httpx.Response(200, json=mock_response)
    )
    gen = OllamaGenerator("mistral")
    gen.max_tokens = 10
    gen.temperature = 0.1
    gen.top_k = 3
    conv = Conversation([Turn("user", Message("Bla bla"))])
    gen.generate(conv)

    sent = json.loads(respx_mock.calls.last.request.content)
    assert sent["options"]["num_predict"] == 10
    assert sent["options"]["temperature"] == 0.1
    assert sent["options"]["top_k"] == 3


@pytest.mark.skipif(
    not all(
        [
            importlib.util.find_spec(m)
            for m in OllamaGeneratorChat.extra_dependency_names
        ]
    ),
    reason="missing optional dependency",
)
@pytest.mark.respx(base_url="http://" + OllamaGenerator.DEFAULT_PARAMS["host"])
def test_ollama_chat_sends_default_max_tokens(respx_mock):
    # max_tokens defaults to 150 in Generator.DEFAULT_PARAMS, so an unconfigured
    # generator still caps output. Nothing else is set, so no other option is sent.
    mock_response = {
        "model": "mistral",
        "message": {"role": "assistant", "content": "Hello how are you?"},
    }
    respx_mock.post("/api/chat").mock(
        return_value=httpx.Response(200, json=mock_response)
    )
    gen = OllamaGeneratorChat("mistral")
    conv = Conversation([Turn("user", Message("Bla bla"))])
    gen.generate(conv)

    sent = json.loads(respx_mock.calls.last.request.content)
    assert sent["options"] == {"num_predict": gen.max_tokens}


@pytest.mark.skipif(
    not all(
        [
            importlib.util.find_spec(m)
            for m in OllamaGeneratorChat.extra_dependency_names
        ]
    ),
    reason="missing optional dependency",
)
@pytest.mark.respx(base_url="http://" + OllamaGenerator.DEFAULT_PARAMS["host"])
def test_ollama_chat_honours_suppressed_params(respx_mock):
    # suppression applies at request-assembly time, so it wins over a set attribute
    mock_response = {
        "model": "mistral",
        "message": {"role": "assistant", "content": "Hello how are you?"},
    }
    respx_mock.post("/api/chat").mock(
        return_value=httpx.Response(200, json=mock_response)
    )
    gen = OllamaGeneratorChat("mistral")
    gen.temperature = 0.1
    gen.suppressed_params = {"temperature"}
    conv = Conversation([Turn("user", Message("Bla bla"))])
    gen.generate(conv)

    sent = json.loads(respx_mock.calls.last.request.content)
    assert "temperature" not in sent["options"]
    assert sent["options"]["num_predict"] == gen.max_tokens


@pytest.fixture
def set_fake_env(request) -> None:
    stored_env = os.getenv(OllamaGenerator.ENV_VAR, None)

    def restore_env():
        if stored_env is not None:
            os.environ[OllamaGenerator.ENV_VAR] = stored_env
        else:
            try:
                del os.environ[OllamaGenerator.ENV_VAR]
            except KeyError:
                pass

    os.environ[OllamaGenerator.ENV_VAR] = "sk-1234567abc"
    request.addfinalizer(restore_env)


@pytest.mark.usefixtures("set_fake_env")
def test_ollama_extra_params():
    """When a user provides extra_params as well as an API Key
    via the environment (here mocked with set_fake_env),
    both should combine into one headers dict without overriding each other.
    Additionally, if the user config requires to disable ssl verification,
    this should be passed to the ollama client constructor.
    """

    config = {
        "generators": {
            "ollama": {
                "OllamaGenerator": {
                    "verify_ssl": False,
                    "extra_params": {"headers": {"My-Header": "Test-1.0"}},
                }
            }
        }
    }
    gen = OllamaGenerator("gemma3", config_root=config)

    assert gen.api_key is not None
    assert gen.verify_ssl is False
    assert gen.client._client.headers["My-Header"] == "Test-1.0"
    assert gen.client._client.headers["Authorization"] == f"Bearer {gen.api_key}"


@pytest.mark.usefixtures("set_fake_env")
def test_ollama_no_api_key():
    """When no env variable key is provided the generator can be instantiated"""
    del os.environ[OllamaGenerator.ENV_VAR]

    gen = OllamaGenerator("gemma3")
    assert gen.api_key is None
