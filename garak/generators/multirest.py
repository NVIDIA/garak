import json
import logging
import re

from typing import List, Union
from garak.generators.base import Generator
from garak import _config

import xml.etree.ElementTree as ET

import requests


DEFAULT_CLASS = "MultiRestGenerator"


class MultiRestGenerator(Generator):
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "uri": None,
        "template_requests": [],
        "template_responses": [],
        "burpfile": "file://*.burp",
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self.get_reqrep_fromburp(self.burpfile)

    def variable_finder(self, dictionary: dict, locations: dict):
        # I apologize for anyone who has to read this code snippet.
        key = ""
        for (k, v) in dictionary.items():
            if type(v) == str:
                for placeholder in re.findall(r'\$[0-9]\$.*\$[0-9]\$', v):    
                    tag = re.search(r'\$[0-9]*\$', placeholder).group(0)
                    if not locations.get(tag):
                        locations[tag] = []
                    if k == "response_body" or k == "request_body":
                        locations[tag].append(k)
                        self.variable_finder(json.loads(v), locations)
                    #if not locations.get(tag):
                    #    locations[tag] = [k]
                    else:
                        locations[tag].append(k)
            else:
                # this condition currently assumes that the other option is JSON
                v_string = json.dumps(v)
                for placeholder in re.findall(r'\$[0-9]\$.*\$[0-9]\$', v_string):    
                    tag = re.search(r'\$[0-9]*\$', placeholder).group(0)
                    if not locations.get(tag):
                        locations[tag] = []
                    if k == "response_body" or k == "request_body":
                        locations[tag].append(k)
                        self.variable_finder(v, locations)
                    else:
                        locations[tag].append(k)

    def get_reqrep_fromburp(self, burpfile: str):
        tree = ET.parse(burpfile)
        root = tree.getroot()
        for item in root:
            for element in item:
                if element.tag == "request":
                    self.template_requests.append(
                        self.make_reqrep_dictionary(element.text)
                    )
                if element.tag == "response":
                    self.template_responses.append(
                        self.make_reqrep_dictionary(element.text)
                    )

    def make_reqrep_dictionary(text: str):
        packet = {}
        x = text.split("\n")
        for y in x:
            # change this to regex -> [a-zA-Z]:[a-z\ A-Z]* , something like that
            # This condition should parse headers
            if ":" in y:
                i = y.index(":")
                packet[y[:i]] = y[i + 1 :].rstrip("\n").lstrip(" ")
            # TODO: This needs to be changed to something more robust
            elif " HTTP/" in y:
                a = y.rstrip("\n").split(" ")
                packet["method"] = a[0]
                packet["endpoint"] = a[1]
            # TODO: This needs to be changed to something more robust
            elif "HTTP/" in y:
                a = y.rstrip("\n").split(" ")
                packet["status"] = a[1]
                packet["error message"] = "".join(a[2:])
            elif not y:
                # TODO: There is probably a more robust way of doing this too
                if packet.get("endpoint"):
                    packet["request_body"] = x[-1]
                else:
                    packet["response_body"] = x[-1]
                break
        return packet

    def grab_value(locations: list, dictionary: dict):
        tmp_value = dictionary
        for index in locations:
            tmp_value = tmp_value[index]
        return tmp_value

    def place_value(request_locations, lookup_table, example_request):
        tmp_value = example_request
        for (k, v) in request_locations.items():
            for index in range(len(v) - 1):
                key = v[index]
                tmp_value = tmp_value[key]
            leaf_key = v[-1]
            tmp_value[leaf_key] = lookup_table[k]

    def request_handler(req: dict):
        if req["method"] == "GET":
            uri = "https://"+ req["Host"] + req["endpoint"]
            headers = dict(list(req.items())[2:-1])
            resp = requests.get(uri, headers=headers)
        else:
            # Assuming POST request
            uri = "https://"+ req["Host"] + req["endpoint"]
            headers = dict(list(req.items())[2:-1])
            resp = requests.post(uri, headers=headers, json=req["request_body"])

    def run(self):
        output = ""
        for i in range(len(self.template_request))
            request_var_locations = self.variable_finder(self.template_request[i])
            self.place_value(request_var_locations, lookup_table, real_request)

            real_response = self.request_handler(real_request)

            response_var_locations = self.variable_finder(self.template_response[i])
            output = self.grab_value(response_var_locations, lookup_table, real_response)

        return output


    def _call_model(self, prompt: str, generations_this_call: int = 1 ) -> List[Union[str, None]]:
        return ["".join(self.run())]