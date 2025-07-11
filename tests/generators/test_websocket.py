import pytest
from unittest.mock import patch, MagicMock

from garak.generators.wsocket import WebSocketGenerator

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

@patch("garak.generators.wsocket.connect")
def test_request_json_response(mock_connect, ws_gen):
    mock_ws = MagicMock()
    mock_ws.recv.return_value = '{"output": "foo"}'
    mock_connect.return_value.__enter__.return_value = mock_ws

    result = ws_gen.request("bar")
    assert result == '"foo"'
    mock_ws.send.assert_called_once_with('{"input": "bar"}')

@patch("garak.generators.wsocket.connect")
def test_request_raw_response(mock_connect, ws_gen):
    ws_gen.json_response = False
    mock_ws = MagicMock()
    mock_ws.recv.return_value = "raw"
    mock_connect.return_value.__enter__.return_value = mock_ws

    result = ws_gen.request("baz")
    assert result == "raw"

def test_live_request_raw_response(ws_gen):
    ws_gen.json_response = False
    ws_gen.uri = "wss://echo.websocket.events"
    result = ws_gen.request("test")
    assert result == "test"
    