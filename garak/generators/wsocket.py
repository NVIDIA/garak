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
        "temp_request": ["$INPUT"],
        "skip": [],
        "response_json": False,
        "response_json_field": False,
        "description": "bruh",
    }

    def __init__(self, name="WebSocket", config_root=_config):
        # Initialize and validate api_key
        super().__init__(name, config_root=config_root)
    
    def json_handler(self, data):
        #TODO: Add try catch 
        response_json = json.loads(data)
        print("AAAAAA")
        return json.dumps(response_json[self.response_json_field])


    def request(self, request, payload):
        with connect(self.uri) as websocket:
            websocket.send(request.replace("$INPUT", payload))
            message = websocket.recv()
            return self.json_handler(message) if self.response_json == True else message

    def mult_request(self, request, payload):
        with connect(self.uri) as websocket:
            for requests in self.temp_request:
                websocket.send(request.replace("$INPUT", payload))

        
    def _call_model(self, prompt: str, generations_this_call: int = 1 ) -> List[Union[str, None]]:
        return [str(self.request(self.temp_request[0], prompt))]


        #return [str(self.request(self.temp_request,prompt))]

        
DEFAULT_CLASS = "WebSocketGenerator" 