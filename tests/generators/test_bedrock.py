# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import sys
import pytest
from unittest.mock import Mock, patch, MagicMock

from garak.attempt import Message, Turn, Conversation

try:
    from botocore.exceptions import ClientError
except ImportError:
    ClientError = None


@pytest.fixture
def mock_boto3():
    """Mock boto3 module and client."""
    # Create mock boto3 module
    mock_boto3_module = MagicMock()
    mock_client = MagicMock()
    mock_boto3_module.client.return_value = mock_client

    # Mock successful converse response
    mock_client.converse.return_value = {
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": "This is a test response from Bedrock."}],
            }
        },
        "stopReason": "end_turn",
        "usage": {
            "inputTokens": 10,
            "outputTokens": 20,
            "totalTokens": 30,
        },
    }

    # Patch boto3 at sys.modules level
    with patch.dict(sys.modules, {"boto3": mock_boto3_module}):
        yield mock_client


@pytest.fixture
def set_aws_env(request):
    """Set up fake AWS environment variables for testing."""
    stored_env = {
        "AWS_ACCESS_KEY_ID": os.getenv("AWS_ACCESS_KEY_ID", None),
        "AWS_SECRET_ACCESS_KEY": os.getenv("AWS_SECRET_ACCESS_KEY", None),
        "AWS_REGION": os.getenv("AWS_REGION", None),
    }

    def restore_env():
        for k, v in stored_env.items():
            if v is not None:
                os.environ[k] = v
            elif k in os.environ:
                del os.environ[k]

    os.environ["AWS_ACCESS_KEY_ID"] = "test-access-key"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "test-secret-key"
    os.environ["AWS_REGION"] = "us-east-1"

    request.addfinalizer(restore_env)


def test_bedrock_import():
    """Test that the bedrock module can be imported."""
    from garak.generators import bedrock

    assert hasattr(bedrock, "BedrockGenerator")
    assert hasattr(bedrock, "DEFAULT_CLASS")
    assert bedrock.DEFAULT_CLASS == "BedrockGenerator"


@pytest.mark.usefixtures("set_aws_env", "mock_boto3")
def test_bedrock_initialization():
    """Test that BedrockGenerator can be initialized."""
    from garak.generators.bedrock import BedrockGenerator

    generator = BedrockGenerator(name="claude-4-5-sonnet")
    assert generator.name == "global.anthropic.claude-sonnet-4-5-20250929-v1:0"
    assert generator.generator_family_name == "Bedrock"


@pytest.mark.usefixtures("set_aws_env", "mock_boto3")
def test_bedrock_model_alias_resolution():
    """Test that model aliases are correctly resolved to full model IDs."""
    from garak.generators.bedrock import BedrockGenerator

    test_cases = [
        ("claude-4-5-haiku", "global.anthropic.claude-haiku-4-5-20251001-v1:0"),
        ("claude-4-5-sonnet", "global.anthropic.claude-sonnet-4-5-20250929-v1:0"),
        ("nova-premier", "us.amazon.nova-premier-v1:0"),
        ("nova-pro", "us.amazon.nova-pro-v1:0"),
    ]

    for alias, expected_full_id in test_cases:
        generator = BedrockGenerator(name=alias)
        assert (
            generator.name == expected_full_id
        ), f"Alias {alias} should resolve to {expected_full_id}"


@pytest.mark.usefixtures("set_aws_env", "mock_boto3")
def test_bedrock_invalid_model_id():
    """Test that invalid model ID raises appropriate error."""
    from garak.generators.bedrock import BedrockGenerator

    with pytest.raises(ValueError) as exc_info:
        generator = BedrockGenerator(name="invalid-model-name")

    assert "not in the list of supported Bedrock models" in str(exc_info.value)


@pytest.mark.usefixtures("set_aws_env", "mock_boto3")
def test_bedrock_successful_generation(mock_boto3):
    """Test successful text generation returns Message objects."""
    from garak.generators.bedrock import BedrockGenerator

    generator = BedrockGenerator(name="claude-4-5-sonnet")
    conv = Conversation([Turn(role="user", content=Message("Hello Bedrock!"))])

    output = generator.generate(conv, generations_this_call=1)

    assert len(output) == 1
    assert isinstance(output[0], Message)
    assert len(output[0].text) > 0
    assert output[0].text == "This is a test response from Bedrock."

    # Verify the client was called
    mock_boto3.converse.assert_called_once()


@pytest.mark.usefixtures("set_aws_env", "mock_boto3")
def test_bedrock_parameter_mapping(mock_boto3):
    """Test parameter mapping (temperature, max_tokens, top_p)."""
    from garak.generators.bedrock import BedrockGenerator

    generator = BedrockGenerator(name="claude-4-5-sonnet")
    generator.temperature = 0.8
    generator.max_tokens = 100
    generator.top_p = 0.9
    generator.stop = ["END", "STOP"]

    conv = Conversation([Turn(role="user", content=Message("Test prompt"))])
    output = generator.generate(conv, generations_this_call=1)

    # Verify the client was called with correct parameters
    mock_boto3.converse.assert_called_once()
    call_kwargs = mock_boto3.converse.call_args[1]

    assert "inferenceConfig" in call_kwargs
    inference_config = call_kwargs["inferenceConfig"]
    assert inference_config["temperature"] == 0.8
    assert inference_config["maxTokens"] == 100
    assert inference_config["topP"] == 0.9
    assert inference_config["stopSequences"] == ["END", "STOP"]


@pytest.mark.usefixtures("set_aws_env", "mock_boto3")
def test_bedrock_conversation_to_message_format(mock_boto3):
    """Test Conversation to message format conversion."""
    from garak.generators.bedrock import BedrockGenerator

    generator = BedrockGenerator(name="claude-4-5-sonnet")

    # Create a multi-turn conversation
    conv = Conversation(
        [
            Turn(role="user", content=Message("Hello")),
            Turn(role="assistant", content=Message("Hi there!")),
            Turn(role="user", content=Message("How are you?")),
        ]
    )

    output = generator.generate(conv, generations_this_call=1)

    # Verify the messages were formatted correctly
    mock_boto3.converse.assert_called_once()
    call_kwargs = mock_boto3.converse.call_args[1]

    assert "messages" in call_kwargs
    messages = call_kwargs["messages"]
    assert len(messages) == 3
    assert messages[0]["role"] == "user"
    assert messages[0]["content"][0]["text"] == "Hello"
    assert messages[1]["role"] == "assistant"
    assert messages[1]["content"][0]["text"] == "Hi there!"
    assert messages[2]["role"] == "user"
    assert messages[2]["content"][0]["text"] == "How are you?"


@pytest.mark.usefixtures("set_aws_env", "mock_boto3")
def test_bedrock_malformed_response_handling(mock_boto3):
    """Test malformed response handling."""
    from garak.generators.bedrock import BedrockGenerator

    generator = BedrockGenerator(name="claude-4-5-sonnet")
    conv = Conversation([Turn(role="user", content=Message("Test"))])

    # Test various malformed responses
    malformed_responses = [
        {},  # Empty response
        {"output": {}},  # Missing 'message'
        {"output": {"message": {}}},  # Missing 'content'
        {"output": {"message": {"content": []}}},  # Empty content
        {"output": {"message": {"content": [{}]}}},  # Missing 'text'
    ]

    for malformed_response in malformed_responses:
        mock_boto3.converse.return_value = malformed_response
        output = generator.generate(conv, generations_this_call=1)

        # Should return [None] for malformed responses
        assert len(output) == 1
        assert output[0] is None


@pytest.mark.usefixtures("set_aws_env", "mock_boto3")
@pytest.mark.skipif(ClientError is None, reason="botocore not installed")
def test_bedrock_validation_error_does_not_retry(mock_boto3):
    """Test validation error does not retry."""
    from garak.generators.bedrock import BedrockGenerator

    # Create a validation error
    validation_error = ClientError(
        {"Error": {"Code": "ValidationException", "Message": "Invalid parameter"}},
        "converse",
    )

    mock_boto3.converse.side_effect = validation_error

    generator = BedrockGenerator(name="claude-4-5-sonnet")
    conv = Conversation([Turn(role="user", content=Message("Test"))])

    output = generator.generate(conv, generations_this_call=1)

    # Should not retry, should return [None]
    assert len(output) == 1
    assert output[0] is None
    assert mock_boto3.converse.call_count == 1


@pytest.mark.usefixtures("set_aws_env", "mock_boto3")
@pytest.mark.skipif(ClientError is None, reason="botocore not installed")
def test_bedrock_access_denied_error_does_not_retry(mock_boto3):
    """Test access denied error does not retry."""
    from garak.generators.bedrock import BedrockGenerator

    # Create an access denied error
    access_denied_error = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
        "converse",
    )

    mock_boto3.converse.side_effect = access_denied_error

    generator = BedrockGenerator(name="claude-4-5-sonnet")
    conv = Conversation([Turn(role="user", content=Message("Test"))])

    output = generator.generate(conv, generations_this_call=1)

    # Should not retry, should return [None]
    assert len(output) == 1
    assert output[0] is None
    assert mock_boto3.converse.call_count == 1
