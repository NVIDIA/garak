import pytest
import ollama
import httpx

from garak.attempt import Turn
from garak.generators.ollama import OllamaGeneratorChat, OllamaGenerator

PINGED_OLLAMA_SERVER = (
    False  # Avoid calling the server multiple times if it is not running
)
OLLAMA_SERVER_UP = False


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
    return len(ollama.list().models) == 0


@pytest.mark.skipif(
    not ollama_is_running(),
    reason=f"Ollama server is not currently running",
)
def test_error_on_nonexistant_model_chat():
    model_name = "non-existent-model"
    gen = OllamaGeneratorChat(model_name)
    with pytest.raises(ollama.ResponseError):
        gen.generate(Turn("This shouldnt work"))


@pytest.mark.skipif(
    not ollama_is_running(),
    reason=f"Ollama server is not currently running",
)
def test_error_on_nonexistant_model():
    model_name = "non-existant-model"
    gen = OllamaGenerator(model_name)
    with pytest.raises(ollama.ResponseError):
        gen.generate(Turn("This shouldnt work"))


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
    responses = gen.generate(Turn('Say "Hello!"'))
    assert len(responses) == 1
    assert all(isinstance(response, Turn) for response in responses)
    assert all(len(response.text) > 0 for response in responses)


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
    responses = gen.generate(Turn('Say "Hello!"'))
    assert len(responses) == 1
    assert all(isinstance(response, Turn) for response in responses)
    assert all(len(response.text) > 0 for response in responses)


@pytest.mark.respx(base_url="http://" + OllamaGenerator.DEFAULT_PARAMS["host"])
def test_ollama_generation_mocked(respx_mock):
    mock_response = {"model": "mistral", "response": "Hello how are you?"}
    respx_mock.post("/api/generate").mock(
        return_value=httpx.Response(200, json=mock_response)
    )
    gen = OllamaGenerator("mistral")
    generation = gen.generate(Turn("Bla bla"))
    assert generation == [Turn("Hello how are you?")]


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
    generation = gen.generate(Turn("Bla bla"))
    assert generation == [Turn("Hello how are you?")]


@pytest.mark.respx(base_url="http://" + OllamaGenerator.DEFAULT_PARAMS["host"])
def test_error_on_nonexistant_model_mocked(respx_mock):
    mock_response = {"error": "No such model"}
    respx_mock.post("/api/generate").mock(
        return_value=httpx.Response(404, json=mock_response)
    )
    model_name = "non-existant-model"
    gen = OllamaGenerator(model_name)
    with pytest.raises(ollama.ResponseError):
        gen.generate(Turn("This shouldnt work"))


@pytest.mark.respx(base_url="http://" + OllamaGenerator.DEFAULT_PARAMS["host"])
def test_error_on_nonexistant_model_chat_mocked(respx_mock):
    mock_response = {"error": "No such model"}
    respx_mock.post("/api/chat").mock(
        return_value=httpx.Response(404, json=mock_response)
    )
    model_name = "non-existant-model"
    gen = OllamaGeneratorChat(model_name)
    with pytest.raises(ollama.ResponseError):
        gen.generate(Turn("This shouldnt work"))
