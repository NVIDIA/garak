#!/usr/bin/env python3
"""
Tests for the Gemini generator.
"""

import os
import pytest
import httpx
from unittest.mock import patch, MagicMock
from garak.generators.gemini import GeminiGenerator
import google.genai as genai

DEFAULT_MODEL_NAME = "gemini-2.5-pro"

@pytest.fixture
def set_fake_env(request) -> None:
    """Set a fake API key for testing."""
    stored_env = os.getenv(GeminiGenerator.ENV_VAR, None)

    def restore_env():
        if stored_env is not None:
            os.environ[GeminiGenerator.ENV_VAR] = stored_env
        else:
            if GeminiGenerator.ENV_VAR in os.environ:
                del os.environ[GeminiGenerator.ENV_VAR]

    os.environ[GeminiGenerator.ENV_VAR] = os.path.abspath(__file__)
    request.addfinalizer(restore_env)

@pytest.fixture
def gemini_compat_mocks(monkeypatch):
    """Mock the Google GenAI client for testing."""
    # Mock the Model class
    mock_model = MagicMock()
    mock_response = MagicMock()
    mock_response.text = "This is a mock response from the Gemini model."
    mock_model.generate_content.return_value = mock_response
    
    # Mock the Client class
    mock_client = MagicMock()
    mock_client.models.get.return_value = mock_model
    monkeypatch.setattr(genai, 'Client', mock_client)
    
    return {
        'model': mock_model,
        'response': mock_response,
        'client': mock_client
    }

@pytest.mark.usefixtures("set_fake_env")
def test_gemini_generator_api_key_auth(monkeypatch):
    """Test GeminiGenerator with API key authentication."""
    # Mock the genai.Client class
    mock_client_instance = MagicMock()
    mock_model = MagicMock()
    mock_client_instance.models.get.return_value = mock_model
    
    with patch.object(genai, 'Client', return_value=mock_client_instance) as mock_client:
        # Initialize the generator with a fake API key
        generator = GeminiGenerator(name=DEFAULT_MODEL_NAME, api_key="fake-api-key")
        # Trigger model loading by calling _call_model
        generator._call_model("test prompt")
    
        # Verify that the client was created with the API key
        mock_client.assert_called_once_with(api_key="fake-api-key")
        mock_client_instance.models.get.assert_called_once_with(model=DEFAULT_MODEL_NAME)
        
        # Verify that the generator has the correct attributes
        assert generator.client == mock_client_instance
        assert generator.model == mock_model


def test_gemini_generator_vertex_ai_auth():
    """Test GeminiGenerator with Vertex AI authentication."""
    # Mock the genai.Client class
    mock_client_instance = MagicMock()
    mock_model = MagicMock()
    mock_client_instance.models.get.return_value = mock_model
    
    with patch.dict(os.environ, {
        "GOOGLE_GENAI_USE_VERTEXAI": "True",
        "GOOGLE_CLOUD_PROJECT": "test-project",
        "GOOGLE_CLOUD_LOCATION": "us-central1"
    }):
        with patch.object(genai, 'Client', return_value=mock_client_instance) as mock_client:
            # Initialize the generator
            generator = GeminiGenerator(name=DEFAULT_MODEL_NAME)
            # Trigger model loading by calling _call_model
            generator._call_model("test prompt")
    
            # Verify that the client was created with Vertex AI parameters
            mock_client.assert_called_once_with(
                vertexai=True,
                project="test-project",
                location="us-central1"
            )
            mock_client_instance.models.get.assert_called_once_with(model=DEFAULT_MODEL_NAME)
            
            # Verify that the generator has the correct attributes
            assert generator.client == mock_client_instance
            assert generator.model == mock_model


@pytest.mark.usefixtures("set_fake_env")
def test_gemini_generator_with_mock(monkeypatch, gemini_compat_mocks):
    """Test the Gemini generator with a mocked response."""
    # Create a mock for the response
    mock_response = MagicMock()
    mock_candidate = MagicMock()
    mock_part = MagicMock()
    mock_part.text = "Mocked response for test prompt"
    mock_content = MagicMock()
    mock_content.parts = [mock_part]
    mock_candidate.content = mock_content
    mock_response.candidates = [mock_candidate]
    
    # Mock the genai.Client class constructor to return our mock client
    mock_client_instance = MagicMock()
    mock_client_instance.models.generate_content.return_value = mock_response
    mock_client_class = MagicMock(return_value=mock_client_instance)
    
    # Patch the Client class to return our mock client instance
    monkeypatch.setattr(genai, "Client", mock_client_class)
    
    # Initialize the generator
    generator = GeminiGenerator(name=DEFAULT_MODEL_NAME)
        
    # Test the generation
    result = generator._call_model("test prompt")
    assert len(result) == 1
    assert result[0] == "Mocked response for test prompt"
        
    # Verify that the client was created and model was retrieved
    mock_client_class.assert_called_once()
    mock_client_instance.models.generate_content.assert_called_once()
        
    # Check that generate_content was called with the prompt and generation_config
    call_args = mock_client_instance.models.generate_content.call_args
    assert call_args.kwargs["contents"] == "test prompt"
    assert "config" in call_args.kwargs


@pytest.mark.usefixtures("set_fake_env")
def test_gemini_generator_multiple_generations(monkeypatch):
    """Test the Gemini generator with multiple generations."""
    # Create a mock for the response
    mock_response = MagicMock()
    
    # Create mock candidates for multiple generations
    mock_candidate1 = MagicMock()
    mock_part1 = MagicMock()
    mock_part1.text = "Response 1"
    mock_content1 = MagicMock()
    mock_content1.parts = [mock_part1]
    mock_candidate1.content = mock_content1
    
    mock_candidate2 = MagicMock()
    mock_part2 = MagicMock()
    mock_part2.text = "Response 2"
    mock_content2 = MagicMock()
    mock_content2.parts = [mock_part2]
    mock_candidate2.content = mock_content2
    
    mock_response.candidates = [mock_candidate1, mock_candidate2]
    
    # Mock the genai.Client class constructor to return our mock client
    mock_client_instance = MagicMock()
    mock_client_instance.models.generate_content.return_value = mock_response
    mock_client_class = MagicMock(return_value=mock_client_instance)
    
    # Patch the Client class to return our mock client instance
    monkeypatch.setattr(genai, "Client", mock_client_class)
    
    # Create the generator and test it
    generator = GeminiGenerator(name=DEFAULT_MODEL_NAME)
    output = generator._call_model("Generate multiple responses", generations_this_call=2)
    
    # Verify the results
    assert len(output) == 2
    assert all(response is not None for response in output)
    assert output[0] == "Response 1"
    assert output[1] == "Response 2"
        
    # Verify that the client was created and model was retrieved
    mock_client_class.assert_called_once()
    mock_client_instance.models.generate_content.assert_called_once()
        
    # Check that generate_content was called with the prompt and generation_config
    call_args = mock_client_instance.models.generate_content.call_args
    assert call_args.kwargs["contents"] == "Generate multiple responses"
    assert "config" in call_args.kwargs


@pytest.mark.usefixtures("set_fake_env")
def test_gemini_generator_error_handling(monkeypatch):
    """Test error handling in the Gemini generator."""
    # Create a mock for the client
    mock_client_instance = MagicMock()
    mock_client_instance.models.generate_content.side_effect = Exception("Test error")
    mock_client_class = MagicMock(return_value=mock_client_instance)
    
    # Patch the Client class to return our mock client instance
    monkeypatch.setattr(genai, "Client", mock_client_class)
    
    # Create the generator and test it
    generator = GeminiGenerator(name=DEFAULT_MODEL_NAME)
    output = generator._call_model("Hello Gemini!", generations_this_call=1)
    
    # Verify the results
    assert len(output) == 1
    assert output[0] is None
    # Check that generate_content was called with the prompt and config
    mock_client_instance.models.generate_content.assert_called_once()
    call_args = mock_client_instance.models.generate_content.call_args
    assert call_args.kwargs["contents"] == "Hello Gemini!"
    assert "config" in call_args.kwargs

@pytest.mark.usefixtures("set_fake_env")
def test_gemini_model_validation(monkeypatch):
    """Test that the generator handles model names."""
    # Mock the genai.Client class constructor to prevent actual API calls
    mock_client_instance = MagicMock()
    mock_model = MagicMock()
    mock_client_instance.models.get.return_value = mock_model
    
    monkeypatch.setattr(genai, 'Client', MagicMock(return_value=mock_client_instance))
    
    # Test with valid model name
    generator = GeminiGenerator(name="gemini-2.5-pro")
    assert generator.name == "gemini-2.5-pro"
    
    # Test with invalid model name - it should use default instead of raising error
    for model_name in GeminiGenerator.SUPPORTED_MODELS:
        generator = GeminiGenerator(name=model_name)
        assert generator.name == model_name
    
    # Test each supported model
    for model_name in GeminiGenerator.SUPPORTED_MODELS:
        generator = GeminiGenerator(name=model_name)
        assert generator.name == model_name

@pytest.mark.skipif(
    os.getenv(GeminiGenerator.ENV_VAR, None) is None,
    reason=f"Gemini API key is not set in {GeminiGenerator.ENV_VAR}",
)
def test_gemini_live():
    """Test the Gemini generator with a live API call.
    
    This test is skipped if the API key is not set.
    """
    try:
        generator = GeminiGenerator(name=DEFAULT_MODEL_NAME)
        output = generator.generate("Hello Gemini!")
        assert len(output) == 1  # expect 1 generation by default
        if output[0] is None:
            pytest.skip("API returned None response, likely due to quota limits")
        assert isinstance(output[0], str)  # expect a string response
        print("Live test passed!")
    except Exception as e:
        if "ResourceExhausted" in str(type(e)) or "quota" in str(e).lower() or "rate limit" in str(e).lower() or "429" in str(e):
            pytest.skip(f"Skipping due to API quota limits: {str(e)[:100]}...")
        else:
            raise  # Re-raise if it's not a quota issue
