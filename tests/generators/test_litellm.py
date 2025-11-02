import pytest
from unittest.mock import patch
from os import getenv

from garak.attempt import Message, Turn, Conversation
from garak.exception import BadGeneratorException
from garak.generators.litellm import LiteLLMGenerator


@pytest.mark.skipif(
    getenv("OPENAI_API_KEY", None) is None,
    reason="OpenAI API key is not set in OPENAI_API_KEY",
)
def test_litellm_openai():
    target_name = "gpt-3.5-turbo"
    generator = LiteLLMGenerator(name=target_name)
    assert generator.name == target_name
    assert isinstance(generator.max_tokens, int)

    output = generator.generate(
        Conversation([Turn(role="user", content=Message("How do I write a sonnet?"))])
    )
    assert len(output) == 1  # expect 1 generation by default

    for item in output:
        assert isinstance(item, Message)


@pytest.mark.skipif(
    getenv("OPENROUTER_API_KEY", None) is None,
    reason="OpenRouter API key is not set in OPENROUTER_API_KEY",
)
def test_litellm_openrouter():
    target_name = "openrouter/google/gemma-7b-it"
    generator = LiteLLMGenerator(name=target_name)
    assert generator.name == target_name
    assert isinstance(generator.max_tokens, int)

    output = generator.generate(Message("How do I write a sonnet?"))
    assert len(output) == 1  # expect 1 generation by default

    for item in output:
        assert isinstance(item, Message)


def test_litellm_model_detection():
    custom_config = {
        "generators": {
            "litellm": {
                "api_base": "https://garak.example.com/v1",
            }
        }
    }
    target_name = "non-existent-model"
    generator = LiteLLMGenerator(name=target_name, config_root=custom_config)
    conv = Conversation(
        [Turn("user", Message("This should raise a BadGeneratorException"))]
    )
    with pytest.raises(BadGeneratorException):
        generator.generate(conv)
    generator = LiteLLMGenerator(name="openai/invalid-model", config_root=custom_config)
    with pytest.raises(BadGeneratorException):
        generator.generate(conv)


def test_litellm_suppressed_params():
    """Test that suppressed_params configuration works correctly."""
    # Create a mock response object that matches what litellm.completion returns
    mock_response = type('obj', (object,), {
        'choices': [
            type('obj', (object,), {
                'message': type('obj', (object,), {
                    'content': 'Mock response'
                })
            })
        ]
    })
    
    target_name = "gpt-4"
    
    # Test case 1: Suppress top_p parameter
    with patch('litellm.completion', return_value=mock_response) as mock_completion:
        custom_config = {
            "generators": {
                "litellm": {
                    "suppressed_params": ["top_p"]
                }
            }
        }
        generator = LiteLLMGenerator(name=target_name, config_root=custom_config)
        conv = Conversation([Turn("user", Message("Test message"))])
        generator.generate(conv)
        
        # Check that top_p was not included but temperature was
        args, kwargs = mock_completion.call_args
        assert 'temperature' in kwargs
        assert 'top_p' not in kwargs
        assert 'max_tokens' in kwargs
    
    # Test case 2: Suppress multiple parameters
    with patch('litellm.completion', return_value=mock_response) as mock_completion:
        custom_config = {
            "generators": {
                "litellm": {
                    "suppressed_params": ["top_p", "frequency_penalty", "presence_penalty"]
                }
            }
        }
        generator = LiteLLMGenerator(name=target_name, config_root=custom_config)
        conv = Conversation([Turn("user", Message("Test message"))])
        generator.generate(conv)
        
        # Check that suppressed params were not included
        args, kwargs = mock_completion.call_args
        assert 'temperature' in kwargs
        assert 'top_p' not in kwargs
        assert 'frequency_penalty' not in kwargs
        assert 'presence_penalty' not in kwargs
        assert 'max_tokens' in kwargs
        
    # Test case 3: No suppressed params (default behavior)
    with patch('litellm.completion', return_value=mock_response) as mock_completion:
        generator = LiteLLMGenerator(name=target_name)
        conv = Conversation([Turn("user", Message("Test message"))])
        generator.generate(conv)
        
        # Check that all standard parameters were included
        args, kwargs = mock_completion.call_args
        assert 'temperature' in kwargs
        assert 'top_p' in kwargs
        assert 'frequency_penalty' in kwargs
        assert 'presence_penalty' in kwargs
        assert 'max_tokens' in kwargs
