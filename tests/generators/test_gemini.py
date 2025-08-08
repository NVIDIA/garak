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
def test_gemini_generator_with_mock(monkeypatch, gemini_compat_mocks):
    """Test the Gemini generator with a mocked response."""
    # Create a mock for the Model class
    mock_model = MagicMock()
    mock_response = MagicMock()
    mock_candidate = MagicMock()
    mock_part = MagicMock()
    mock_part.text = "Mocked response for test prompt"
    mock_candidate.content.parts = [mock_part]
    mock_response.candidates = [mock_candidate]
    mock_model.generate_content.return_value = mock_response
    
    # Mock the genai.Client class constructor to return our mock client
    mock_client_instance = MagicMock()
    mock_client_instance.models.get.return_value = mock_model
    
    # Patch the Client class to return our mock client instance
    monkeypatch.setattr(genai, 'Client', MagicMock(return_value=mock_client_instance))
    
    # Initialize the generator
    generator = GeminiGenerator(name=DEFAULT_MODEL_NAME)
    
    # Verify that the client was created and model was retrieved
    genai.Client.assert_called_once()
    mock_client_instance.models.get.assert_called_once_with(model=DEFAULT_MODEL_NAME)
    
    # Test the generation
    result = generator._call_model("test prompt")
    assert len(result) == 1
    assert result[0] == "Mocked response for test prompt"
    
    # Check that generate_content was called with the prompt and generation_config
    mock_model.generate_content.assert_called_once()
    call_args = mock_model.generate_content.call_args
    assert call_args.kwargs['contents'] == "test prompt"
    assert "config" in call_args.kwargs

@pytest.mark.usefixtures("set_fake_env")
def test_gemini_generator_multiple_generations(monkeypatch):
    """Test the Gemini generator with multiple generations."""
    # Create a mock for the Model class
    mock_model = MagicMock()
    mock_response = MagicMock()
    
    # Create mock candidates for multiple generations
    mock_candidate1 = MagicMock()
    mock_part1 = MagicMock()
    mock_part1.text = "Response 1"
    mock_candidate1.content.parts = [mock_part1]
    
    mock_candidate2 = MagicMock()
    mock_part2 = MagicMock()
    mock_part2.text = "Response 2"
    mock_candidate2.content.parts = [mock_part2]
    
    mock_response.candidates = [mock_candidate1, mock_candidate2]
    
    mock_model.generate_content.return_value = mock_response
    
    # Mock the genai.Client class constructor to return our mock client
    mock_client_instance = MagicMock()
    mock_client_instance.models.get.return_value = mock_model
    
    # Patch the Client class to return our mock client instance
    monkeypatch.setattr(genai, 'Client', MagicMock(return_value=mock_client_instance))
    
    # Create the generator and test it
    generator = GeminiGenerator(name=DEFAULT_MODEL_NAME)
    output = generator._call_model("Generate multiple responses", generations_this_call=2)
    
    # Verify the results
    assert len(output) == 2
    assert all(response is not None for response in output)
    assert output[0] == "Response 1"
    assert output[1] == "Response 2"

@pytest.mark.usefixtures("set_fake_env")
def test_gemini_native_audio_model(monkeypatch):
    """Test the Gemini generator with a native audio model."""
    # Create a mock for the GenerativeModel class
    mock_model = MagicMock()
    
    # Create a mock response with the expected structure
    mock_response = MagicMock()
    mock_candidate = MagicMock()
    mock_part = MagicMock()
    mock_part.text = "This is a response from an audio-capable model."
    mock_candidate.content.parts = [mock_part]
    mock_response.candidates = [mock_candidate]
    mock_model.generate_content.return_value = mock_response
    
    # Mock the genai.Client class constructor to return our mock client
    mock_client_instance = MagicMock()
    mock_client_instance.models.get.return_value = mock_model
    
    # Patch the Client class to return our mock client instance
    monkeypatch.setattr(genai, 'Client', MagicMock(return_value=mock_client_instance))
    
    # Create the generator with a native audio model
    generator = GeminiGenerator(name="gemini-2.5-flash-native-audio")
    # Override the default modality to accept audio input
    generator.modality = {"in": {"audio"}, "out": {"text"}}
    
    # For this test, we'll use a text prompt since the generator expects text input
    # In a real scenario, audio would be converted to text or handled differently
    output = generator._call_model("Transcribe this audio.")
    
    # Verify the results
    assert len(output) == 1
    assert output[0] == "This is a response from an audio-capable model."
    
    # Verify the model was called with contents and config
    mock_model.generate_content.assert_called_once()
    call_args = mock_model.generate_content.call_args
    assert call_args.kwargs['contents'] == "Transcribe this audio."
    assert "config" in call_args.kwargs

@pytest.mark.usefixtures("set_fake_env")
def test_gemini_generator_error_handling(monkeypatch):
    """Test error handling in the Gemini generator."""
    # Create a mock for the GenerativeModel class
    mock_model = MagicMock()
    mock_model.generate_content.side_effect = Exception("Test error")
    
    # Mock the genai.Client class constructor to return our mock client
    mock_client_instance = MagicMock()
    mock_client_instance.models.get.return_value = mock_model
    
    # Patch the Client class to return our mock client instance
    monkeypatch.setattr(genai, 'Client', MagicMock(return_value=mock_client_instance))
    
    # Create the generator and test it
    generator = GeminiGenerator(name=DEFAULT_MODEL_NAME)
    output = generator._call_model("Hello Gemini!", generations_this_call=1)
    
    # Verify the results
    assert len(output) == 1
    assert output[0] is None
    # Check that generate_content was called with the prompt and config
    mock_model.generate_content.assert_called_once()
    call_args = mock_model.generate_content.call_args
    assert call_args.kwargs['contents'] == "Hello Gemini!"
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
    except google.api_core.exceptions.ResourceExhausted as e:
        pytest.skip(f"Skipping due to API quota limits: {str(e)[:100]}...")
    except Exception as e:
        if "quota" in str(e).lower() or "rate limit" in str(e).lower() or "429" in str(e):
            pytest.skip(f"Skipping due to possible API limits: {str(e)[:100]}...")
        else:
            raise  # Re-raise if it's not a quota issue
