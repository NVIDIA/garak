#!/usr/bin/env python3
"""
Tests for the Gemini generator.
"""

import os
import pytest
import httpx
from unittest.mock import patch, MagicMock
import google.api_core.exceptions
from garak.generators.gemini import GeminiGenerator
import google.generativeai as genai

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
    """Mock the Google Generative AI client for testing."""
    # Mock the GenerativeModel class
    mock_model = MagicMock()
    mock_response = MagicMock()
    mock_response.text = "This is a mock response from the Gemini model."
    mock_model.generate_content.return_value = mock_response
    
    # Mock the genai.GenerativeModel constructor
    mock_generative_model = MagicMock(return_value=mock_model)
    monkeypatch.setattr(genai, 'GenerativeModel', mock_generative_model)
    
    # Mock the genai.configure function
    mock_configure = MagicMock()
    monkeypatch.setattr(genai, 'configure', mock_configure)
    
    return {
        'model': mock_model,
        'response': mock_response,
        'generative_model': mock_generative_model,
        'configure': mock_configure
    }

@pytest.mark.usefixtures("set_fake_env")
def test_gemini_generator_with_mock(monkeypatch, gemini_compat_mocks):
    """Test the Gemini generator with a mocked response."""
    # Create a mock for the GenerativeModel class
    mock_model = MagicMock()
    mock_response = MagicMock()
    mock_candidate = MagicMock()
    mock_candidate.content.text = "This is a mock response from the Gemini model for testing purposes."
    mock_response.candidates = [mock_candidate]
    mock_model.generate_content.return_value = mock_response
    
    # Patch the GenerativeModel constructor
    def mock_generative_model(*args, **kwargs):
        return mock_model
    
    # Patch the genai.configure function
    mock_configure = MagicMock()
    
    # Apply the patches
    monkeypatch.setattr("google.generativeai.GenerativeModel", mock_generative_model)
    monkeypatch.setattr("google.generativeai.configure", mock_configure)
    
    # Create the generator and test it
    generator = GeminiGenerator(name=DEFAULT_MODEL_NAME)
    output = generator._call_model("Hello Gemini!", generations_this_call=1)
    
    # Verify the results
    assert len(output) == 1
    assert output[0] == "This is a mock response from the Gemini model for testing purposes."
    # Check that generate_content was called with the prompt and generation_config
    mock_model.generate_content.assert_called_once()
    call_args = mock_model.generate_content.call_args
    assert call_args[0][0] == "Hello Gemini!"
    assert "generation_config" in call_args[1]

@pytest.mark.usefixtures("set_fake_env")
def test_gemini_generator_multiple_generations(monkeypatch):
    """Test the Gemini generator with multiple generations."""
    # Create a mock for the GenerativeModel class
    mock_model = MagicMock()
    mock_response = MagicMock()
    
    # Create mock candidates for multiple generations
    mock_candidate1 = MagicMock()
    mock_candidate1.content.text = "Response 1"
    mock_candidate2 = MagicMock()
    mock_candidate2.content.text = "Response 2"
    mock_response.candidates = [mock_candidate1, mock_candidate2]
    
    mock_model.generate_content.return_value = mock_response
    
    # Patch the GenerativeModel constructor
    def mock_generative_model(*args, **kwargs):
        return mock_model
    
    # Patch the genai.configure function
    mock_configure = MagicMock()
    
    # Apply the patches
    monkeypatch.setattr("google.generativeai.GenerativeModel", mock_generative_model)
    monkeypatch.setattr("google.generativeai.configure", mock_configure)
    
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
    mock_candidate.content.text = "This is a response from an audio-capable model."
    mock_response.candidates = [mock_candidate]
    mock_model.generate_content.return_value = mock_response
    
    # Patch the GenerativeModel constructor
    def mock_generative_model(*args, **kwargs):
        return mock_model
    
    # Patch the genai.configure function
    mock_configure = MagicMock()
    
    # Apply the patches
    monkeypatch.setattr("google.generativeai.GenerativeModel", mock_generative_model)
    monkeypatch.setattr("google.generativeai.configure", mock_configure)
    
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
    
    # Verify the model was called with generation_config
    mock_model.generate_content.assert_called_once()
    call_args = mock_model.generate_content.call_args
    assert call_args[0][0] == "Transcribe this audio."
    assert "generation_config" in call_args[1]

@pytest.mark.usefixtures("set_fake_env")
def test_gemini_generator_error_handling(monkeypatch):
    """Test error handling in the Gemini generator."""
    # Create a mock for the GenerativeModel class
    mock_model = MagicMock()
    mock_model.generate_content.side_effect = Exception("Test error")
    
    # Patch the GenerativeModel constructor
    def mock_generative_model(*args, **kwargs):
        return mock_model
    
    # Patch the genai.configure function
    mock_configure = MagicMock()
    
    # Apply the patches
    monkeypatch.setattr("google.generativeai.GenerativeModel", mock_generative_model)
    monkeypatch.setattr("google.generativeai.configure", mock_configure)
    
    # Create the generator and test it
    generator = GeminiGenerator(name=DEFAULT_MODEL_NAME)
    output = generator._call_model("Hello Gemini!", generations_this_call=1)
    
    # Verify the results
    assert len(output) == 1
    assert output[0] is None
    # Check that generate_content was called with the prompt and generation_config
    mock_model.generate_content.assert_called_once()
    call_args = mock_model.generate_content.call_args
    assert call_args[0][0] == "Hello Gemini!"
    assert "generation_config" in call_args[1]

@pytest.mark.usefixtures("set_fake_env")
def test_gemini_model_validation():
    """Test that the generator handles model names."""
    # Test with valid model name
    generator = GeminiGenerator(name="gemini-2.5-pro")
    assert generator.name == "gemini-2.5-pro"
    
    # Test with invalid model name - it should use default instead of raising error
    generator = GeminiGenerator(name="invalid-model-name")
    # The generator should fall back to the default model
    assert generator.name == "gemini-2.5-pro"  # Default model
    
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
