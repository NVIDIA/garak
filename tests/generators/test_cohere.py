import os
import json
import logging
import pytest
import httpx

from garak.attempt import Message, Turn, Conversation
from garak.generators.cohere import CohereGenerator, COHERE_GENERATION_LIMIT
from garak.exception import APIKeyMissingError

# Default model name and API URLs
DEFAULT_MODEL_NAME = "command"
COHERE_API_BASE = "https://api.cohere.com"
COHERE_V1 = f"{COHERE_API_BASE}/v1"
COHERE_V2 = f"{COHERE_API_BASE}/v2"

# API version constants
API_V1 = "v1"  # Legacy generate API
API_V2 = "v2"  # Recommended chat API

# ─── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def set_fake_env():
    """Autouse fixture to set and restore the Cohere API key."""
    var = CohereGenerator.ENV_VAR
    orig = os.environ.get(var)
    os.environ[var] = "fake-api-key"
    yield
    if orig is None:
        os.environ.pop(var, None)
    else:
        os.environ[var] = orig


@pytest.fixture
def cohere_mock_responses():
    """Provide mock HTTP response specs for Cohere endpoints."""
    return {
        "generate_response": {
            "code": 200,
            "json": {
                "generations": [
                    {"text": "Mocked generate response 1."},
                    {"text": "Mocked generate response 2."},
                ]
            },
        },
        "chat_response": {
            "code": 200,
            "json": {"message": {"content": [{"text": "Mocked chat response."}]}},
        },
        "missing_content_response": {
            "code": 200,
            "json": {"message": {}},  # no content
        },
    }


def mock_cohere_endpoint(respx_mock, path, spec):
    """Helper to mock a Cohere HTTP endpoint with a given response spec."""
    url = f"{COHERE_API_BASE}{path}"
    return respx_mock.post(url).mock(
        return_value=httpx.Response(spec["code"], json=spec["json"])
    )


# ─── Instantiation & Defaults ─────────────────────────────────────────


def test_cohere_instantiation():
    # Test v2 (default)
    gen_v2 = CohereGenerator()
    assert gen_v2.name == DEFAULT_MODEL_NAME
    assert gen_v2.api_key == "fake-api-key"
    assert hasattr(gen_v2, "generator")
    assert gen_v2.api_version == "v2"

    # Test v1
    gen_v1 = CohereGenerator()
    gen_v1.api_version = "v1"
    # Re-initialize the generator with v1
    gen_v1.__init__()
    assert gen_v1.api_version == "v1"


def test_cohere_missing_api_key():
    var = CohereGenerator.ENV_VAR
    saved = os.environ.pop(var, None)
    try:
        with pytest.raises(APIKeyMissingError):
            CohereGenerator()
    finally:
        if saved is not None:
            os.environ[var] = saved


def test_cohere_default_parameters():
    gen = CohereGenerator()
    assert gen.api_version == "v2"  # Default should be v2 (chat API)
    assert gen.temperature == CohereGenerator.DEFAULT_PARAMS["temperature"]
    assert gen.max_tokens == CohereGenerator.DEFAULT_PARAMS["max_tokens"]
    gen.temperature = 0.5
    assert gen.temperature == 0.5


# ─── API Version Tests ─────────────────────────────────────────────────────────


def test_api_version_validation():
    # Test invalid api_version gets corrected to v2
    gen = CohereGenerator()
    gen.api_version = "invalid"
    gen.__init__()
    assert gen.api_version == "v2"

    # Test v1 is accepted
    gen = CohereGenerator()
    gen.api_version = "v1"
    gen.__init__()
    assert gen.api_version == "v1"

    # Test v2 is accepted
    gen = CohereGenerator()
    gen.api_version = "v2"
    gen.__init__()
    assert gen.api_version == "v2"


# ─── (Optional) Generation Limit Enforcement ─────────────────────────────────
# If generate() does not currently enforce COHERE_GENERATION_LIMIT, this test is skipped
import pytest

# ─── Legacy Generate API (respx) (respx) ──────────────────────────────────────


@pytest.mark.respx(base_url=COHERE_API_BASE)
def test_cohere_generate_api_respx(respx_mock, cohere_mock_responses):
    route = mock_cohere_endpoint(
        respx_mock, "/v1/generate", cohere_mock_responses["generate_response"]
    )
    gen = CohereGenerator()
    gen.api_version = "v1"  # Use legacy generate API
    # Re-initialize the generator with v1
    gen.__init__()
    conv = Conversation([Turn("user", Message("Test prompt"))])
    result = gen.generate(conv, generations_this_call=1)

    # Assert headers
    last = respx_mock.calls.last.request
    assert last.headers["Authorization"] == "Bearer fake-api-key"
    assert "application/json" in last.headers.get("Content-Type", "")

    # Assert payload
    payload = json.loads(last.content)
    assert payload["model"] == DEFAULT_MODEL_NAME
    assert payload["prompt"] == "Test prompt"

    # Assert response parsing
    assert result == [
        cohere_mock_responses["generate_response"]["json"]["generations"][0]["text"],
        cohere_mock_responses["generate_response"]["json"]["generations"][1]["text"],
    ]


# ─── Chat API (respx) ─────────────────────────────────────────────────


@pytest.mark.respx(base_url=COHERE_API_BASE)
@pytest.mark.parametrize(
    "response_key, expect_error_str",
    [
        ("chat_response", False),
        ("missing_content_response", True),
    ],
)
def test_cohere_chat_api_respx(
    respx_mock, cohere_mock_responses, response_key, expect_error_str
):
    spec = cohere_mock_responses[response_key]
    mock_cohere_endpoint(respx_mock, "/v2/chat", spec)
    gen = CohereGenerator()
    # Default is already v2, but being explicit for test clarity
    gen.api_version = "v2"
    gen.__init__()
    conv = Conversation([Turn("user", Message("Test prompt"))])
    result = gen.generate(conv)

    # Header & payload checks
    last = respx_mock.calls.last.request
    assert last.headers["Authorization"] == "Bearer fake-api-key"
    payload = json.loads(last.content)
    assert payload.get("model") == DEFAULT_MODEL_NAME
    assert payload.get("messages")[0]["content"] == "Test prompt"

    # Check response or None for error cases
    if expect_error_str:
        assert result[0] is None, f"Expected None for error but got {result[0]}"
    else:
        assert isinstance(result[0], str) and result[0]


# ─── Logging on Error Variants ─────────────────────────────────────────


def test_chat_response_logs_warning(respx_mock, cohere_mock_responses, caplog):
    caplog.set_level(logging.WARNING)
    mock_cohere_endpoint(
        respx_mock, "/v2/chat", cohere_mock_responses["missing_content_response"]
    )

    gen = CohereGenerator()
    gen.api_version = "v2"  # Use chat API
    gen.__init__()
    caplog.clear()

    conv = Conversation([Turn("user", Message("Test prompt"))])
    result = gen.generate(conv)
    assert result[0] is None, f"Expected None for error but got {result[0]}"
    assert "warning" in caplog.text.lower() or "error" in caplog.text.lower()
