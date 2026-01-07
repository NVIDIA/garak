"""Tests for WebSocket generator"""

import pytest
import json
import uuid
from unittest.mock import Mock, patch, AsyncMock
import asyncio

from garak.generators.websocket import WebSocketGenerator


class TestWebSocketGenerator:
    """Test suite for WebSocketGenerator"""

    def test_init_basic(self):
        """Test basic initialization"""
        gen = WebSocketGenerator(uri="ws://localhost:3000")
        assert gen.uri == "ws://localhost:3000"
        assert gen.host == "localhost"
        assert gen.port == 3000
        assert gen.path == "/"
        assert not gen.secure

    def test_init_secure(self):
        """Test secure WebSocket initialization"""
        gen = WebSocketGenerator(uri="wss://api.example.com:443/chat")
        assert gen.secure
        assert gen.host == "api.example.com"
        assert gen.port == 443
        assert gen.path == "/chat"

    def test_init_invalid_scheme(self):
        """Test initialization with invalid scheme"""
        with pytest.raises(ValueError, match="URI must use ws:// or wss:// scheme"):
            WebSocketGenerator(uri="ftp://localhost:3000")

    def test_init_no_uri(self):
        """Test initialization without URI uses default"""
        gen = WebSocketGenerator()
        assert gen.uri == "wss://echo.websocket.org"
        assert gen.secure
        assert gen.host == "echo.websocket.org"

    def test_auth_basic(self):
        """Test basic authentication setup"""
        instance_config = {
            "generators": {
                "websocket": {
                    "WebSocketGenerator": {
                        "uri": "ws://localhost:3000",
                        "auth_type": "basic",
                        "username": "testuser",
                        "api_key": "testpass",
                    }
                }
            }
        }
        gen = WebSocketGenerator(config_root=instance_config)
        assert "Authorization" in gen.headers
        assert gen.headers["Authorization"].startswith("Basic ")

    def test_auth_bearer(self):
        """Test bearer token authentication"""
        instance_config = {
            "generators": {
                "websocket": {
                    "WebSocketGenerator": {
                        "uri": "ws://localhost:3000",
                        "auth_type": "bearer",
                        "api_key": "test_api_key",
                    }
                }
            }
        }
        gen = WebSocketGenerator(config_root=instance_config)
        assert gen.headers["Authorization"] == "Bearer test_api_key"

    @patch.dict("os.environ", {"TEST_API_KEY": "env_api_key"})
    def test_auth_env_var(self):
        """Test API key from environment variable"""
        instance_config = {
            "generators": {
                "websocket": {
                    "WebSocketGenerator": {
                        "uri": "ws://localhost:3000",
                        "auth_type": "bearer",
                        "key_env_var": "TEST_API_KEY",
                    }
                }
            }
        }
        gen = WebSocketGenerator(config_root=instance_config)
        assert gen.api_key == "env_api_key"
        assert gen.headers["Authorization"] == "Bearer env_api_key"

    def test_format_message_simple(self):
        """Test simple message formatting"""
        instance_config = {
            "generators": {
                "websocket": {
                    "WebSocketGenerator": {
                        "uri": "ws://localhost:3000",
                        "req_template": "User: $INPUT",
                    }
                }
            }
        }
        gen = WebSocketGenerator(config_root=instance_config)
        result = gen._format_message("Hello world")
        assert result == "User: Hello world"

    def test_format_message_json_object(self):
        """Test JSON object message formatting"""
        instance_config = {
            "generators": {
                "websocket": {
                    "WebSocketGenerator": {
                        "uri": "ws://localhost:3000",
                        "req_template_json_object": {
                            "message": "$INPUT",
                            "conversation_id": "$CONVERSATION_ID",
                            "api_key": "$KEY",
                        },
                        "conversation_id": "test_conv",
                        "api_key": "test_key",
                    }
                }
            }
        }
        gen = WebSocketGenerator(config_root=instance_config)
        result = gen._format_message("Hello")
        data = json.loads(result)
        assert data["message"] == "Hello"
        assert data["conversation_id"] == "test_conv"
        assert data["api_key"] == "test_key"

    def test_extract_response_text_plain(self):
        """Test plain text response extraction"""
        instance_config = {
            "generators": {
                "websocket": {
                    "WebSocketGenerator": {
                        "uri": "ws://localhost:3000",
                        "response_json": False,
                    }
                }
            }
        }
        gen = WebSocketGenerator(config_root=instance_config)
        result = gen._extract_response_text("Hello world")
        assert result == "Hello world"

    def test_extract_response_text_json(self):
        """Test JSON response extraction"""
        instance_config = {
            "generators": {
                "websocket": {
                    "WebSocketGenerator": {
                        "uri": "ws://localhost:3000",
                        "response_json": True,
                        "response_json_field": "text",
                    }
                }
            }
        }
        gen = WebSocketGenerator(config_root=instance_config)
        response = json.dumps({"text": "Hello world", "status": "ok"})
        result = gen._extract_response_text(response)
        assert result == "Hello world"

    def test_extract_response_text_jsonpath(self):
        """Test JSONPath response extraction"""
        instance_config = {
            "generators": {
                "websocket": {
                    "WebSocketGenerator": {
                        "uri": "ws://localhost:3000",
                        "response_json": True,
                        "response_json_field": "$.data.message",
                    }
                }
            }
        }
        gen = WebSocketGenerator(config_root=instance_config)
        response = json.dumps(
            {
                "status": "success",
                "data": {"message": "Hello world", "timestamp": "2023-01-01"},
            }
        )
        result = gen._extract_response_text(response)
        assert result == "Hello world"

    def test_extract_response_text_json_fallback(self):
        """Test JSON extraction fallback to raw response"""
        instance_config = {
            "generators": {
                "websocket": {
                    "WebSocketGenerator": {
                        "uri": "ws://localhost:3000",
                        "response_json": True,
                        "response_json_field": "nonexistent",
                    }
                }
            }
        }
        gen = WebSocketGenerator(config_root=instance_config)
        response = "Invalid JSON"
        result = gen._extract_response_text(response)
        assert result == "Invalid JSON"

    @pytest.mark.asyncio
    async def test_connect_websocket_success(self):
        """Test successful WebSocket connection"""
        gen = WebSocketGenerator(uri="ws://localhost:3000")

        mock_websocket = AsyncMock()
        # Mock websockets.connect to return the mock_websocket as an awaitable
        with patch("garak.generators.websocket.websockets.connect") as mock_connect:
            # Create an async mock that returns the mock_websocket when awaited
            async def async_connect(*args, **kwargs):
                return mock_websocket

            mock_connect.side_effect = async_connect

            await gen._connect_websocket()
            mock_connect.assert_called_once()
            assert gen.websocket == mock_websocket

    @pytest.mark.asyncio
    async def test_send_and_receive_basic(self):
        """Test basic send and receive"""
        instance_config = {
            "generators": {
                "websocket": {
                    "WebSocketGenerator": {
                        "uri": "ws://localhost:3000",
                        "response_after_typing": False,
                    }
                }
            }
        }
        gen = WebSocketGenerator(config_root=instance_config)

        mock_websocket = AsyncMock()
        mock_websocket.send = AsyncMock()
        mock_websocket.recv = AsyncMock(return_value="Hello response")
        gen.websocket = mock_websocket

        result = await gen._send_and_receive("Hello")

        mock_websocket.send.assert_called_once_with("Hello")
        assert result == "Hello response"

    @pytest.mark.asyncio
    async def test_send_and_receive_typing(self):
        """Test send and receive with typing indicator"""
        instance_config = {
            "generators": {
                "websocket": {
                    "WebSocketGenerator": {
                        "uri": "ws://localhost:3000",
                        "response_after_typing": True,
                        "typing_indicator": "typing",
                    }
                }
            }
        }
        gen = WebSocketGenerator(config_root=instance_config)

        mock_websocket = AsyncMock()
        mock_websocket.send = AsyncMock()
        # Simulate typing indicator followed by actual response
        mock_websocket.recv = AsyncMock(side_effect=["typing", "Hello response"])
        gen.websocket = mock_websocket

        result = await gen._send_and_receive("Hello")

        assert result == "Hello response"
        assert mock_websocket.recv.call_count == 2

    def test_call_model_integration(self):
        """Test full model call integration"""
        instance_config = {
            "generators": {
                "websocket": {
                    "WebSocketGenerator": {
                        "uri": "ws://localhost:3000",
                        "req_template": "User: $INPUT",
                        "response_json": False,
                    }
                }
            }
        }
        gen = WebSocketGenerator(config_root=instance_config)

        # Mock the async generation method
        async def mock_generate(prompt):
            return f"Response to: {prompt}"

        with patch.object(gen, "_generate_async", side_effect=mock_generate):
            result = gen._call_model("Test prompt")
            assert len(result) == 1
            assert result[0].text == "Response to: Test prompt"

    def test_call_model_error_handling(self):
        """Test error handling in model call"""
        gen = WebSocketGenerator(uri="ws://localhost:3000")

        # Mock an exception in async generation
        async def mock_generate_error(prompt):
            raise Exception("Connection failed")

        with patch.object(gen, "_generate_async", side_effect=mock_generate_error):
            result = gen._call_model("Test prompt")
            assert len(result) == 1
            assert result[0].text == ""  # Should return empty string on error

    def test_apply_replacements_nested(self):
        """Test recursive replacement in nested data structures"""
        gen = WebSocketGenerator(uri="ws://localhost:3000")

        # Use dynamic values to avoid hardcoding test expectations
        static_value = "static_value"
        input_value = f"test_input_{uuid.uuid4().hex[:8]}"
        key_value = f"test_key_{uuid.uuid4().hex[:8]}"
        conversation_value = f"test_conv_{uuid.uuid4().hex[:8]}"

        data = {
            "message": "$INPUT",
            "metadata": {"user": "$KEY", "conversation": "$CONVERSATION_ID"},
            "options": ["$INPUT", static_value],
        }

        replacements = {
            "$INPUT": input_value,
            "$KEY": key_value,
            "$CONVERSATION_ID": conversation_value,
        }

        result = gen._apply_replacements(data, replacements)

        assert result["message"] == input_value
        assert result["metadata"]["user"] == key_value
        assert result["metadata"]["conversation"] == conversation_value
        assert result["options"][0] == input_value
        assert result["options"][1] == static_value

    def test_default_params_coverage(self):
        """Test that all default parameters are properly set"""
        gen = WebSocketGenerator(uri="ws://localhost:3000")

        # Check that all DEFAULT_PARAMS keys are set as attributes
        for key in WebSocketGenerator.DEFAULT_PARAMS:
            assert hasattr(gen, key), f"Missing attribute: {key}"

        # Check specific defaults - note that name comes from DEFAULT_PARAMS now
        assert gen.name == "WebSocket LLM"
        assert gen.auth_type == "none"
        assert gen.req_template == "$INPUT"
        assert gen.response_json is False
        assert gen.response_json_field == "text"
        assert gen.request_timeout == 20
        assert gen.connection_timeout == 10
        assert gen.verify_ssl is True
