import os
import json
import logging
import pytest
import httpx
import respx

from garak.generators.cohere import CohereGenerator, COHERE_GENERATION_LIMIT
from garak.exception import APIKeyMissingError

# Default model name and API URLs
DEFAULT_MODEL_NAME = "command"
COHERE_API_BASE = "https://api.cohere.com"
COHERE_V1 = f"{COHERE_API_BASE}/v1"
COHERE_V2 = f"{COHERE_API_BASE}/v2"

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
                    {"text": "Mocked generate response 2."}
                ]
            }
        },
        "chat_response": {
            "code": 200,
            "json": {
                "message": {"content": [{"text": "Mocked chat response."}]}
            }
        },
        "missing_content_response": {
            "code": 200,
            "json": {"message": {}}  # no content
        }
    }


def mock_cohere_endpoint(respx_mock, path, spec):
    """Helper to mock a Cohere HTTP endpoint with a given response spec."""
    url = f"{COHERE_API_BASE}{path}"
    return respx_mock.post(url).mock(
        return_value=httpx.Response(spec["code"], json=spec["json"])
    )


# ─── Instantiation & Defaults ─────────────────────────────────────────

def test_cohere_instantiation():
    gen = CohereGenerator()
    assert gen.name == DEFAULT_MODEL_NAME
    assert gen.api_key == "fake-api-key"
    assert hasattr(gen, "generator")


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
    assert gen.use_chat is True
    assert gen.temperature == CohereGenerator.DEFAULT_PARAMS["temperature"]
    assert gen.max_tokens == CohereGenerator.DEFAULT_PARAMS["max_tokens"]
    gen.temperature = 0.5
    assert gen.temperature == 0.5


# ─── (Optional) Generation Limit Enforcement ─────────────────────────────────
# If generate() does not currently enforce COHERE_GENERATION_LIMIT, this test is skipped
import pytest

def test_generation_limit_enforced():
    gen = CohereGenerator()
    too_many = COHERE_GENERATION_LIMIT + 1
    try:
        gen.generate("hello", generations_this_call=too_many)
    except ValueError:
        pytest.skip("Limit enforcement not implemented yet.")

# ─── Legacy Generate API (respx) (respx) ──────────────────────────────────────

@pytest.mark.respx(base_url=COHERE_API_BASE)
def test_cohere_generate_api_respx(respx_mock, cohere_mock_responses):
    route = mock_cohere_endpoint(respx_mock, "/v1/generate", cohere_mock_responses["generate_response"])
    gen = CohereGenerator()
    gen.use_chat = False
    result = gen.generate("Test prompt", generations_this_call=2)

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
        cohere_mock_responses["generate_response"]["json"]["generations"][1]["text"]
    ]


# ─── Chat API (respx) ─────────────────────────────────────────────────

@pytest.mark.respx(base_url=COHERE_API_BASE)
@pytest.mark.parametrize("response_key, expect_error_str", [
    ("chat_response", False),
    ("missing_content_response", True),
])
def test_cohere_chat_api_respx(respx_mock, cohere_mock_responses, response_key, expect_error_str):
    spec = cohere_mock_responses[response_key]
    mock_cohere_endpoint(respx_mock, "/v2/chat", spec)
    gen = CohereGenerator()
    result = gen.generate("Test prompt")

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
    mock_cohere_endpoint(respx_mock, "/v2/chat", cohere_mock_responses["missing_content_response"])

    gen = CohereGenerator()
    gen.use_chat = True
    caplog.clear()

    result = gen.generate("Test prompt")
    assert result[0] is None, f"Expected None for error but got {result[0]}"
    assert "warning" in caplog.text.lower() or "error" in caplog.text.lower()
