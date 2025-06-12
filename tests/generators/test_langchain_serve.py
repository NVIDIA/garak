import os
import pytest

from garak.attempt import Message, Turn, Conversation
from garak.generators.langchain_serve import LangChainServeLLMGenerator


@pytest.fixture
def set_env_vars():
    os.environ["LANGCHAIN_SERVE_URI"] = "http://127.0.0.1:8000"
    yield
    os.environ.pop("LANGCHAIN_SERVE_URI", None)


def test_validate_uri():
    assert LangChainServeLLMGenerator._validate_uri("http://127.0.0.1:8000") == True
    assert LangChainServeLLMGenerator._validate_uri("bad_uri") == False


@pytest.mark.usefixtures("set_env_vars")
def test_langchain_serve_generator_initialization():
    generator = LangChainServeLLMGenerator()
    assert generator.name == "127.0.0.1:8000"
    assert generator.api_endpoint == "http://127.0.0.1:8000/invoke"


@pytest.mark.usefixtures("set_env_vars")
def test_langchain_serve_generation(requests_mock):
    requests_mock.post(
        "http://127.0.0.1:8000/invoke?config_hash=default",
        json={"output": ["Generated text"]},
    )
    generator = LangChainServeLLMGenerator()
    conv = Conversation([Turn("user", Message("Hello LangChain!"))])
    output = generator._call_model(conv)
    assert len(output) == 1
    assert output[0] == Message("Generated text")


@pytest.mark.usefixtures("set_env_vars")
def test_error_handling(requests_mock):
    requests_mock.post(
        "http://127.0.0.1:8000/invoke?config_hash=default", status_code=500
    )
    generator = LangChainServeLLMGenerator()
    with pytest.raises(Exception):
        generator._call_model(Message("This should raise an error"))


@pytest.mark.usefixtures("set_env_vars")
def test_bad_response_handling(requests_mock):
    requests_mock.post(
        "http://127.0.0.1:8000/invoke?config_hash=default", json={}, status_code=200
    )
    generator = LangChainServeLLMGenerator()
    conv = Conversation([Turn("user", Message("This should not find output"))])
    output = generator._call_model(conv)
    assert output == [None]
