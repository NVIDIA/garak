import pytest
import ollama
import httpx

from garak.attempt import Message, Turn, Conversation
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
    # In newer versions of ollama, list() returns a ListResponse object
    response = ollama.list()
    
    try:
        # Try to access the models attribute or property
        models = getattr(response, 'models', None)
        if models is None:
            # If no models attribute, try using it as a dict
            models = response.get('models', [])
        
        # Check if models is empty
        return len(models) == 0
    except (AttributeError, TypeError):
        # If we can't access models, assume there are no models
        return True


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
