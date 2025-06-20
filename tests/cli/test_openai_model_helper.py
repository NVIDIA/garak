"""
Tests for the OpenAI model selection helper functionality in the CLI.
"""

import pytest
import os
import re
from unittest.mock import patch

from garak import cli
from garak.generators.openai import OpenAIGenerator


@pytest.mark.parametrize("has_api_key", [True, False])
def test_openai_model_selection_helper(has_api_key, capsys, monkeypatch):
    """Test the OpenAI model selection helper when no model name is provided."""
    
    # Set or clear the API key based on the test parameter
    if has_api_key:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test123456")
    elif "OPENAI_API_KEY" in os.environ:
        monkeypatch.delenv("OPENAI_API_KEY")
    
    # Create mock return values matching the function's expected output
    api_key_set = has_api_key
    model_info = {'chat': ['gpt-4', 'gpt-3.5-turbo'], 'completion': ['babbage-002', 'davinci-002']}
    api_models = ['gpt-4', 'gpt-3.5-turbo'] if has_api_key else []
    
    # Patch the function to return our test values
    with patch.object(OpenAIGenerator, 'get_available_models_info', return_value=(api_key_set, model_info, api_models)):
        # Run the CLI with the openai model type but no model name
        cli.main(["-m", "openai"])
        
        # The CLI should have printed the helper and error message
        
        # Check the output for expected helper text
        result = capsys.readouterr()
        output = result.out
        
        # Helper should be displayed
        assert "🔍 OpenAI Model Selection Helper" in output
        
        # API key status should be shown based on the test parameter
        if has_api_key:
            assert "✅ API Key found" in output
        else:
            assert "⚠️  No OpenAI API key found" in output
            assert "export OPENAI_API_KEY=" in output
        
        # Models should be listed
        if has_api_key:
            assert "Available models from your OpenAI account" in output
            # When using the API, we don't separate by model type
        else:
            assert "Chat Completion Models" in output or "Recommended OpenAI models" in output
            assert "Completion Models" in output
        
        # Example usage should be shown
        assert "Example usage:" in output
        assert "garak -m openai --model_name" in output


def test_openai_with_model_name(capsys, monkeypatch):
    """Test that providing a model name doesn't trigger the helper."""
    
    # Mock the OpenAIGenerator.get_available_models_info method to avoid API calls
    monkeypatch.setattr(
        OpenAIGenerator,
        "get_available_models_info",
        lambda cls: (False, {'chat': [], 'completion': []}, []),
    )
    
    # Run the command with a model name specified
    # It will fail due to missing API key, but we just care that helper is not shown
    try:
        cli.main(["-m", "openai", "--model_name", "gpt-3.5-turbo", "--probes", "encoding"])
    except Exception:
        # Any exception is ok - we're just checking output format
        pass
    
    # Check that the helper was not displayed
    result = capsys.readouterr()
    assert "🔍 OpenAI Model Selection Helper" not in result.out
