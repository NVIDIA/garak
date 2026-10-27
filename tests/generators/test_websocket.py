"""Tests for WebSocket generator"""

import pytest
import json
import uuid
from unittest.mock import patch, AsyncMock, MagicMock

from garak.generators.websocket import WebSocketGenerator
from garak.attempt import Conversation, Turn, Message


class TestWebSocketGenerator:
    """Test suite for WebSocketGenerator"""

    def test_init_basic(self):
        """Test basic initialization"""
        gen = WebSocketGenerator(uri="ws://localhost:3000")
        assert gen.uri == "ws://localhost:3000"
        assert not gen.secure

    def test_init_secure(self):
        """Test secure WebSocket initialization"""
        gen = WebSocketGenerator(uri="wss://api.example.com:443/chat")
        assert gen.secure

    def test_init_invalid_scheme(self):
        """Test initialization with invalid scheme"""
        with pytest.raises(ValueError, match="URI must use ws:// or wss:// scheme"):
            WebSocketGenerator(uri="ftp://localhost:3000")

    def test_init_no_uri(self):
        """Test initialization without URI uses default"""
        gen = WebSocketGenerator()
        assert gen.uri == "wss://echo.websocket.org"
        assert gen.secure

    @pytest.mark.parametrize("module_level", [False, True])
    def test_init_target_name_sets_uri(self, module_level):
        """--target_name reaches the generator as the "name" option and should set the uri"""
        opts = {"name": "ws://localhost:3000/chat"}
        ws_conf = opts if module_level else {"WebSocketGenerator": opts}
        gen = WebSocketGenerator(config_root={"generators": {"websocket": ws_conf}})
        assert gen.uri == "ws://localhost:3000/chat"
        assert not gen.secure

    def test_init_configured_uri_wins_over_name(self):
        """An explicitly configured uri is kept"""
        conf = {
            "WebSocketGenerator": {
                "uri": "wss://api.example.com/llm",
                "name": "ws://localhost:3000/chat",
            }
        }
        gen = WebSocketGenerator(config_root={"generators": {"websocket": conf}})
        assert gen.uri == "wss://api.example.com/llm"

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
        mock_connect = AsyncMock(return_value=mock_websocket)
        gen.websockets = MagicMock()
        gen.websockets.connect = mock_connect

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
        async def mock_generate(*prompt):
            return f"Response to: {prompt[0]}"

        with patch.object(gen, "_generate_async", side_effect=mock_generate):
            test_str = "Test prompt"
            prompt = Conversation([Turn(role="user", content=Message(text=test_str))])
            result = gen._call_model(prompt)
            assert len(result) == 1
            assert result[0].text == f"Response to: {test_str}"

    def test_call_model_error_handling(self):
        """Test error handling in model call"""
        gen = WebSocketGenerator(uri="ws://localhost:3000")

        # Mock an exception in async generation
        async def mock_generate_error(prompt):
            raise Exception("Connection failed")

        with patch.object(gen, "_generate_async", side_effect=mock_generate_error):
            test_str = "Test prompt"
            prompt = Conversation([Turn(role="user", content=Message(text=test_str))])
            result = gen._call_model(prompt)
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

    def test_not_parallel_capable(self):
        """WebSocketGenerator must run serially; parallel processes re-auth."""
        assert WebSocketGenerator.parallel_capable is False
        gen = WebSocketGenerator(uri="ws://localhost:3000")
        assert gen.parallel_capable is False

    def test_is_typing_indicator_exact_match_only(self):
        """Only a standalone indicator frame counts; answers containing the
        indicator text must not be mistaken for typing status (issue #2343)."""
        gen = WebSocketGenerator(uri="ws://localhost:3000")
        assert gen._is_typing_indicator("typing")
        assert gen._is_typing_indicator("  typing\n")
        assert not gen._is_typing_indicator("I can help with typing.")
        assert not gen._is_typing_indicator("")
        # Indicator-only frames, including trailing punctuation and JSON
        # status frames, are still status, not answers (review #2359)
        assert gen._is_typing_indicator("typing...")
        assert gen._is_typing_indicator("typing.")
        assert gen._is_typing_indicator("typing!")
        assert gen._is_typing_indicator('{"type": "typing"}')
        assert gen._is_typing_indicator('{"status": "typing"}')
        assert not gen._is_typing_indicator('{"type": "message", "text": "typing"}')
        assert not gen._is_typing_indicator("typing is hard")
        assert not gen._is_typing_indicator("typing... and then I answered")

    def _run_live_server_test(self, script, request_timeout=10, **extra_config):
        """Serve `script` (list of frames to send) and generate once; return text."""
        import asyncio
        import threading

        from websockets.asyncio.server import serve

        async def handler(ws):
            async for _msg in ws:
                for frame in script:
                    await ws.send(frame)
                return

        ready = threading.Event()
        holder = {}

        def run_server():
            async def main():
                async with serve(handler, "127.0.0.1", 0) as server:
                    holder["port"] = next(iter(server.sockets)).getsockname()[1]
                    ready.set()
                    await asyncio.Future()

            asyncio.run(main())

        threading.Thread(target=run_server, daemon=True).start()
        assert ready.wait(5), "test server did not start"

        instance_config = {
            "generators": {
                "websocket": {
                    "WebSocketGenerator": {
                        "uri": f"ws://127.0.0.1:{holder['port']}",
                        "response_after_typing": True,
                        "typing_indicator": "typing",
                        "request_timeout": request_timeout,
                        "connection_timeout": 5,
                        **extra_config,
                    }
                }
            }
        }
        gen = WebSocketGenerator(config_root=instance_config)
        out = gen.generate(Conversation([Turn("user", Message("Harmless test"))]))
        assert out and out[0] is not None
        return out[0].text

    def test_answer_containing_typing_is_preserved(self):
        """Regression test for issue #2343: a real answer containing the word
        'typing' must reach the caller instead of being dropped as a status."""
        answer = "I cannot assist with that request, but I can help with typing."
        assert self._run_live_server_test([answer]) == answer

    def test_typing_dots_frame_not_joined_onto_answer(self):
        """Reviewer reproducer #2359: a "typing..." status frame must be
        filtered, not joined onto the following answer."""
        answer = "I'm sorry, I can't help with that."
        assert self._run_live_server_test(["typing...", answer]) == answer

    def test_json_typing_frame_not_joined_onto_answer(self):
        """Reviewer reproducer #2359: a {"type": "typing"} JSON status
        frame must be filtered so only the message frame is extracted."""
        assert (
            self._run_live_server_test(
                [
                    '{"type": "typing"}',
                    '{"type": "message", "text": "I cannot help with that."}',
                ],
                response_json=True,
                response_json_field="text",
            )
            == "I cannot help with that."
        )

    def test_standalone_typing_frame_still_skipped(self):
        """The typing flow keeps working: a standalone 'typing' status frame
        followed by the real answer yields the answer."""
        answer = "Here is the answer you asked for."
        assert self._run_live_server_test(["typing", answer]) == answer

    def test_repeated_calls_return_each_response(self):
        """Later prompts must not come back empty after the first call.

        _call_model used to open and close a new event loop per call while
        keeping self.websocket, which stays bound to the first loop.
        """
        import asyncio
        import threading

        from websockets.asyncio.server import serve

        async def handler(ws):
            async for msg in ws:
                await ws.send("echo:" + msg)

        ready = threading.Event()
        holder = {}

        def run_server():
            async def main():
                async with serve(handler, "127.0.0.1", 0) as server:
                    holder["port"] = next(iter(server.sockets)).getsockname()[1]
                    ready.set()
                    await asyncio.Future()

            asyncio.run(main())

        threading.Thread(target=run_server, daemon=True).start()
        assert ready.wait(5), "echo server did not start"

        instance_config = {
            "generators": {
                "websocket": {
                    "WebSocketGenerator": {
                        "uri": f"ws://127.0.0.1:{holder['port']}",
                        "response_after_typing": False,
                        "request_timeout": 5,
                        "connection_timeout": 5,
                    }
                }
            }
        }
        gen = WebSocketGenerator(config_root=instance_config)
        prompts = ["hello", "world", "third"]
        texts = []
        loops = []
        for prompt in prompts:
            out = gen.generate(Conversation([Turn("user", Message(prompt))]))
            texts.append(out[0].text if out and out[0] is not None else None)
            loops.append(gen._loop)
        assert texts == [f"echo:{prompt}" for prompt in prompts]
        assert all(loop is loops[0] for loop in loops)
        assert not loops[0].is_closed()
