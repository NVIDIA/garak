import json
import logging
import re

from typing import List, Union
from garak.generators.base import Generator
from garak import _config

import websockets
from websockets.sync.client import connect

class WebSocketGenerator(Generator):
    """
    This is a generator to work with websockets
    """

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "uri": None,
        "auth_key": None,
        "body": '{}',
        "json_response": True,
        "json_key": "output",
    }

    def __init__(self, name="WebSocket", config_root=_config):
        super().__init__(name, config_root=config_root)
    
    def json_handler(self, data):
        response_json = json.loads(data)
        return json.dumps(response_json[self.json_key])


    def request(self, payload):
        with connect(self.uri) as websocket:
            websocket.send(self.body.replace("$INPUT", payload))
            message = websocket.recv()
            return self.json_handler(message) if self.json_response == True else message

        
    def _call_model(self, prompt: str, generations_this_call: int = 1 ) -> List[Union[str, None]]:
        if output := self.request(self, prompt) == dict :
            return output[self.json_key]
        else :
            return output

        
DEFAULT_CLASS = "WebSocketGenerator" 