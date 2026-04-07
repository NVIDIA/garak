import os
import json
import logging
import pickle
import pytest
import httpx

from garak.attempt import Message, Turn, Conversation
from garak.generators.cohere import CohereGenerator
from garak.exception import APIKeyMissingError, BadGeneratorException, TargetNameMissingError

try:
    import cohere

except Exception:
    pytest.skip(
        "couldn't import cohere, skipping cohere tests", allow_module_level=True
    )


# Default model name and API URLs
DEFAULT_MODEL_NAME = "command-r-plus"
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
def cohere_config_root():
    """Provide a config_root dict for CohereGenerator instantiation."""
    return {
        "generators": {
            "cohere": {
                "CohereGenerator": {
                    "name": DEFAULT_MODEL_NAME,
                }
            }
        }
    }


@pytest.fixture
def cohere_v1_config_root():
    """Provide a config_root dict for CohereGenerator with v1 API."""
    return {
        "generators": {
            "cohere": {
                "CohereGenerator": {
                    "name": DEFAULT_MODEL_NAME,
                    "api_version": "v1",
                }
            }
        }
    }


@pytest.fixture
def cohere_mock_responses():
    """Provide mock HTTP response specs for Cohere endpoints."""
    return {
        "generate_response": {
            "code": 200,
            "json": {
                "generations": [
                    {"text": "Mocked generate response 1."},
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
        "not_found_response": {
            "code": 404,
            "json": {"message": "model not found"},
        },
    }


def mock_cohere_endpoint(respx_mock, path, spec):
    """Helper to mock a Cohere HTTP endpoint with a given response spec."""
    url = f"{COHERE_API_BASE}{path}"
    return respx_mock.post(url).mock(
        return_value=httpx.Response(spec["code"], json=spec["json"])
    )


# ─── Instantiation & Defaults ─────────────────────────────────────────


def test_cohere_instantiation(cohere_config_root):
    # Test v2 (default) with config_root
    gen_v2 = CohereGenerator(config_root=cohere_config_root)
    assert gen_v2.name == DEFAULT_MODEL_NAME
    assert gen_v2.api_key == "fake-api-key"
    assert hasattr(gen_v2, "generator")
    assert gen_v2.api_version == "v2"


def test_cohere_missing_model_name():
    """Model name is required; omitting it raises TargetNameMissingError."""
    with pytest.raises(TargetNameMissingError):
        CohereGenerator()


def test_cohere_missing_api_key(cohere_config_root):
    var = CohereGenerator.ENV_VAR
    saved = os.environ.pop(var, None)
    try:
        with pytest.raises(APIKeyMissingError):
            CohereGenerator(config_root=cohere_config_root)
    finally:
        if saved is not None:
            os.environ[var] = saved


def test_cohere_default_parameters(cohere_config_root):
    gen = CohereGenerator(config_root=cohere_config_root)
    assert gen.api_version == "v2"  # Default should be v2 (chat API)
    assert gen.temperature == CohereGenerator.DEFAULT_PARAMS["temperature"]
    assert gen.max_tokens == CohereGenerator.DEFAULT_PARAMS["max_tokens"]
    gen.temperature = 0.5
    assert gen.temperature == 0.5


# ─── API Version Tests ─────────────────────────────────────────────────────────


def test_api_version_validation(cohere_config_root, cohere_v1_config_root):
    # Test invalid api_version gets corrected to v2
    invalid_config = {
        "generators": {
            "cohere": {
                "CohereGenerator": {
                    "name": DEFAULT_MODEL_NAME,
                    "api_version": "invalid",
                }
            }
        }
    }
    gen = CohereGenerator(config_root=invalid_config)
    assert gen.api_version == "v2"

    # Test v1 is accepted
    gen = CohereGenerator(config_root=cohere_v1_config_root)
    assert gen.api_version == "v1"

    # Test v2 is accepted
    gen = CohereGenerator(config_root=cohere_config_root)
    assert gen.api_version == "v2"


# ─── _load_unsafe Tests ──────────────────────────────────────────────


def test_load_unsafe_v1(cohere_config_root):
    gen = CohereGenerator(config_root=cohere_config_root)
    gen.api_version = "v1"
    gen._load_unsafe()
    assert isinstance(gen.generator, cohere.Client)


def test_load_unsafe_v2(cohere_config_root):
    gen = CohereGenerator(config_root=cohere_config_root)
    gen.api_version = "v2"
    gen._load_unsafe()
    assert isinstance(gen.generator, cohere.ClientV2)


def test_serialization_restores_client(cohere_config_root):
    """Pickling and unpickling should restore the Cohere client via _load_unsafe."""
    gen = CohereGenerator(config_root=cohere_config_root)
    data = pickle.dumps(gen)
    restored = pickle.loads(data)
    assert hasattr(restored, "generator")
    assert restored.generator is not None
    assert restored.name == DEFAULT_MODEL_NAME


# ─── Legacy Generate API (respx) ──────────────────────────────────────


@pytest.mark.respx(base_url=COHERE_API_BASE)
def test_cohere_generate_api_respx(respx_mock, cohere_mock_responses, cohere_v1_config_root):
    mock_cohere_endpoint(
        respx_mock, "/v1/generate", cohere_mock_responses["generate_response"]
    )
    gen = CohereGenerator(config_root=cohere_v1_config_root)
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

    # Assert response parsing - should be Message objects
    assert len(result) == 1
    assert isinstance(result[0], Message)
    assert result[0].text == "Mocked generate response 1."


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
    respx_mock, cohere_mock_responses, cohere_config_root, response_key, expect_error_str
):
    spec = cohere_mock_responses[response_key]
    mock_cohere_endpoint(respx_mock, "/v2/chat", spec)
    gen = CohereGenerator(config_root=cohere_config_root)
    conv = Conversation([Turn("user", Message("Test prompt"))])
    result = gen.generate(conv)

    # Header & payload checks
    last = respx_mock.calls.last.request
    assert last.headers["Authorization"] == "Bearer fake-api-key"
    payload = json.loads(last.content)
    assert payload.get("model") == DEFAULT_MODEL_NAME
    assert payload.get("messages")[0]["content"] == "Test prompt"

    # Check response - should be Message or None
    if expect_error_str:
        assert result[0] is None, f"Expected None for error but got {result[0]}"
    else:
        assert isinstance(result[0], Message)
        assert result[0].text == "Mocked chat response."


# ─── 404 Error Handling ──────────────────────────────────────────────


@pytest.mark.respx(base_url=COHERE_API_BASE)
def test_chat_api_404_raises_bad_generator(respx_mock, cohere_mock_responses):
    config_root = {
        "generators": {"cohere": {"CohereGenerator": {"name": "nonexistent-model"}}}
    }
    mock_cohere_endpoint(respx_mock, "/v2/chat", cohere_mock_responses["not_found_response"])
    gen = CohereGenerator(config_root=config_root)
    conv = Conversation([Turn("user", Message("Test prompt"))])
    with pytest.raises(BadGeneratorException):
        gen.generate(conv)


@pytest.mark.respx(base_url=COHERE_API_BASE)
def test_generate_api_404_raises_bad_generator(respx_mock, cohere_mock_responses):
    config_root = {
        "generators": {"cohere": {"CohereGenerator": {"name": "nonexistent-model", "api_version": "v1"}}}
    }
    mock_cohere_endpoint(respx_mock, "/v1/generate", cohere_mock_responses["not_found_response"])
    gen = CohereGenerator(config_root=config_root)
    conv = Conversation([Turn("user", Message("Test prompt"))])
    with pytest.raises(BadGeneratorException):
        gen.generate(conv)


# ─── Logging on Error Variants ─────────────────────────────────────────


def test_chat_response_logs_warning(respx_mock, cohere_mock_responses, cohere_config_root, caplog):
    caplog.set_level(logging.WARNING)
    mock_cohere_endpoint(
        respx_mock, "/v2/chat", cohere_mock_responses["missing_content_response"]
    )

    gen = CohereGenerator(config_root=cohere_config_root)
    caplog.clear()

    conv = Conversation([Turn("user", Message("Test prompt"))])
    result = gen.generate(conv)
    assert result[0] is None, f"Expected None for error but got {result[0]}"
    assert "warning" in caplog.text.lower() or "error" in caplog.text.lower()


# ─── Message Type Tests ──────────────────────────────────────────────


@pytest.mark.respx(base_url=COHERE_API_BASE)
def test_generate_returns_message_objects(respx_mock, cohere_mock_responses, cohere_config_root):
    """All non-None results from generate() should be Message objects."""
    mock_cohere_endpoint(respx_mock, "/v2/chat", cohere_mock_responses["chat_response"])
    gen = CohereGenerator(config_root=cohere_config_root)
    conv = Conversation([Turn("user", Message("Test prompt"))])
    result = gen.generate(conv)
    for item in result:
        assert item is None or isinstance(item, Message)


# ─── Live Endpoint Tests ─────────────────────────────────────────────
# These tests require a valid COHERE_API_KEY and are skipped in CI.

LIVE_MODEL = "command-a-03-2025"

_real_cohere_key = os.environ.get("COHERE_API_KEY", "")
_has_cohere_key = _real_cohere_key not in (None, "", "fake-api-key")


@pytest.fixture
def restore_real_api_key():
    """Temporarily restore the real API key for live tests."""
    var = CohereGenerator.ENV_VAR
    os.environ[var] = _real_cohere_key
    yield
    os.environ[var] = "fake-api-key"


@pytest.mark.skipif(not _has_cohere_key, reason="COHERE_API_KEY not set")
def test_live_chat_api_output_format(restore_real_api_key):
    """Verify live chat API (v2) returns Message objects with non-empty text."""
    config_root = {
        "generators": {"cohere": {"CohereGenerator": {"name": LIVE_MODEL}}}
    }
    gen = CohereGenerator(config_root=config_root)
    assert gen.api_version == "v2"
    conv = Conversation([Turn("user", Message("Say hello in one word."))])
    result = gen.generate(conv, generations_this_call=1)

    assert len(result) == 1
    assert isinstance(result[0], Message)
    assert isinstance(result[0].text, str)
    assert len(result[0].text) > 0


@pytest.mark.skipif(not _has_cohere_key, reason="COHERE_API_KEY not set")
def test_live_v1_api_rejects_new_model(restore_real_api_key):
    """Newer models are not available on the legacy v1 generate API.

    This verifies that the 404 handling correctly raises BadGeneratorException
    rather than silently returning None.
    """
    config_root = {
        "generators": {"cohere": {"CohereGenerator": {"name": LIVE_MODEL, "api_version": "v1"}}}
    }
    gen = CohereGenerator(config_root=config_root)
    conv = Conversation([Turn("user", Message("Say hello in one word."))])
    with pytest.raises(BadGeneratorException):
        gen.generate(conv, generations_this_call=1)
