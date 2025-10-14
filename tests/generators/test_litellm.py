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


def test_litellm_claude_4_5_params():
    """Test that Claude 4.5 models on Bedrock only receive temperature parameter (not top_p)."""
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
    
    # Test case 1: Claude 4.5 model on AWS Bedrock (should omit top_p)
    with patch('litellm.completion', return_value=mock_response) as mock_completion:
        claude_model = "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"
        custom_config = {
            "generators": {
                "litellm": {
                    "provider": "bedrock",
                    "api_base": "https://bedrock-runtime.us-east-1.amazonaws.com"
                }
            }
        }
        generator = LiteLLMGenerator(name=claude_model, config_root=custom_config)
        conv = Conversation([Turn("user", Message("Test message"))])
        generator.generate(conv)

        args, kwargs = mock_completion.call_args
        assert 'temperature' in kwargs
        assert 'top_p' not in kwargs
    
    # Test case 2: Claude 4.5 model NOT on AWS Bedrock (should include top_p)
    with patch('litellm.completion', return_value=mock_response) as mock_completion:
        claude_model = "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"
        custom_config = {
            "generators": {
                "litellm": {
                    "provider": "openai",
                    "api_base": "https://api.openai.com/v1"
                }
            }
        }
        generator = LiteLLMGenerator(name=claude_model, config_root=custom_config)
        conv = Conversation([Turn("user", Message("Test message"))])
        generator.generate(conv)
        
        # Check that both temperature and top_p were included
        args, kwargs = mock_completion.call_args
        assert 'temperature' in kwargs
        assert 'top_p' in kwargs
        
    # Test case 3: Non-Claude 4.5 model (should include top_p)
    with patch('litellm.completion', return_value=mock_response) as mock_completion:
        other_model = "gpt-4"
        generator = LiteLLMGenerator(name=other_model)
        conv = Conversation([Turn("user", Message("Test message"))])
        generator.generate(conv)
        
        # Check that both temperature and top_p were included
        args, kwargs = mock_completion.call_args
        assert 'temperature' in kwargs
        assert 'top_p' in kwargs
