import os
import pytest

from garak.attempt import Message, Turn, Conversation
from garak.generators.langchain_serve import LangChainServeLLMGenerator

ENDPOINT = "http://127.0.0.1:8000/invoke?config_hash=default"


@pytest.fixture
def set_env_vars():
    os.environ["LANGCHAIN_SERVE_URI"] = "http://127.0.0.1:8000"
    yield
    os.environ.pop("LANGCHAIN_SERVE_URI", None)


def _generator():
    return LangChainServeLLMGenerator()


def _conversation(text="Hello LangChain!"):
    return Conversation([Turn("user", Message(text))])


def test_validate_uri():
    assert LangChainServeLLMGenerator._validate_uri("http://127.0.0.1:8000") == True
    assert LangChainServeLLMGenerator._validate_uri("bad_uri") == False


@pytest.mark.usefixtures("set_env_vars")
def test_langchain_serve_generator_initialization():
    generator = _generator()
    assert generator.name == "127.0.0.1:8000"
    assert generator.api_endpoint == "http://127.0.0.1:8000/invoke"


# Scenarios whose `/invoke` `output` carries usable text. LangServe returns the
# runnable output directly under `output`: a bare string for string/LLM chains,
# or a serialised message (flat or constructor form) for chat models.
@pytest.mark.parametrize(
    "scenario",
    ["string_output", "message_dict_output", "message_constructor_output"],
)
@pytest.mark.usefixtures("set_env_vars")
def test_langchain_serve_extracts_text(requests_mock, langchain_serve_mocks, scenario):
    mock = langchain_serve_mocks[scenario]
    requests_mock.post(ENDPOINT, json=mock["json"], status_code=mock["code"])
    output = _generator()._call_model(_conversation())
    assert output == [Message("Generated text")]


# Scenarios that do not fit the expected `/invoke` output contract must record a
# miss (`[None]`) rather than emit a stringified object. In particular a mapping
# such as `{"error": "err val"}` must not become the literal string
# "{'error': 'err val'}", and a list output (not emitted by LangServe) is not
# silently unwrapped.
@pytest.mark.parametrize(
    "scenario",
    ["unexpected_dict_output", "list_output", "missing_output_key"],
)
@pytest.mark.usefixtures("set_env_vars")
def test_langchain_serve_unexpected_shapes_return_none(
    requests_mock, langchain_serve_mocks, scenario
):
    mock = langchain_serve_mocks[scenario]
    requests_mock.post(ENDPOINT, json=mock["json"], status_code=mock["code"])
    output = _generator()._call_model(_conversation())
    assert output == [None]


@pytest.mark.usefixtures("set_env_vars")
def test_langchain_serve_does_not_stringify_mappings(
    requests_mock, langchain_serve_mocks
):
    mock = langchain_serve_mocks["unexpected_dict_output"]
    requests_mock.post(ENDPOINT, json=mock["json"], status_code=mock["code"])
    output = _generator()._call_model(_conversation())
    assert output == [None]
    assert output[0] is None


@pytest.mark.usefixtures("set_env_vars")
def test_langchain_serve_client_error_returns_none(
    requests_mock, langchain_serve_mocks
):
    mock = langchain_serve_mocks["client_error"]
    requests_mock.post(ENDPOINT, json=mock["json"], status_code=mock["code"])
    output = _generator()._call_model(_conversation())
    assert output == [None]


@pytest.mark.usefixtures("set_env_vars")
def test_langchain_serve_server_error_raises(requests_mock, langchain_serve_mocks):
    mock = langchain_serve_mocks["server_error"]
    requests_mock.post(ENDPOINT, json=mock["json"], status_code=mock["code"])
    with pytest.raises(Exception):
        _generator()._call_model(_conversation())


def test_extract_output_text_units():
    extract = LangChainServeLLMGenerator._extract_output_text
    assert extract("Generated text") == "Generated text"
    assert extract({"content": "Generated text", "type": "ai"}) == "Generated text"
    assert extract({"kwargs": {"content": "Generated text"}}) == "Generated text"
    assert extract({"error": "err val"}) is None
    assert extract(["Generated text"]) is None
    assert extract(None) is None
    assert extract(42) is None
