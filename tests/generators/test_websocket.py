import pytest
from unittest.mock import patch, MagicMock

from garak.generators.rest import WebSocketGenerator


@pytest.fixture
def ws_gen():
    gen = WebSocketGenerator()
    gen.uri = "ws://test"
    gen.body = '{"input": "$INPUT"}'
    gen.json_response = True
    gen.json_key = "output"
    return gen


def test_json_handler(ws_gen):
    data = '{"output": "test response"}'
    result = ws_gen.json_handler(data)
    assert result == '"test response"'


def test_live_request_raw_response(ws_gen):
    ws_gen.json_response = False
    ws_gen.uri = "wss://echo.websocket.events"
    result = ws_gen.request("test")
    assert "echo.websocket.events" in result
