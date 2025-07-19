import json
import re

from typing import List, Union
from garak.generators.base import Generator
from garak import _config

import xml.etree.ElementTree as ET

import requests


DEFAULT_CLASS = "MultiRestGenerator"


class MultiRestGenerator(Generator):
    """
    This is a generator to work with multiple request-response pairs using Burp Suite's exported XML format. It supports variable substitution, in case you need to build succeeding requests uponinformation from previous request/response pairs.
    The generator supports only JSON request and responses.

    To set a variable in the response, use the format $n$...$n$, where n is a number.

    When you save a Burpfile with reqeust and response items, be sure to uncheck the base64 button.

    For example:
        HTTP/2 200 OK
        Date: Tue, 20 May 2025 05:58:32 GMT
        Content-Type: application/json
        Content-Length: 52
        Server: uvicorn
        Apigw-Requestid: $2$K2kBRiewPHcEM8A=$2$
        Access-Control-Allow-Origin: https://platform.dreadnode.io

        {"id":"$1$999999$1$"}]]>

    The above response will set the variable 1 to "999999" and variable 2 to "K2kBRiewPHcEM8A="

    From there you can place these variables in the request body or headers like this:
        GET /score?id=$1$123$1$ HTTP/2
        Host: example.com
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0
        Accept: */*
        Accept-Language: en-US,en;q=0.5
        Accept-Encoding: gzip, deflate, br
        Referer: https://example.com/score
        Content-Type: application/json
        Origin: https://example.com
        Sec-Fetch-Dest: empty
        Sec-Fetch-Mode: cors
        Sec-Fetch-Site: same-site
        Dnt: 1
        Sec-Gpc: 1
        Priority: u=0
        Te: trailers

    The above request will replace $1$123$1$ with the value of variable 1, which is "999999".

    You can specify where the $INPUT and $OUTPUT variables go in the request and response, as well:

        POST /score HTTP/2
        Host: example.com
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0
        Accept: */*
        Accept-Language: en-US,en;q=0.5
        Accept-Encoding: gzip, deflate, br
        Content-Type: application/json
        Sec-Fetch-Mode: cors
        Sec-Fetch-Site: same-site
        Dnt: 1
        Sec-Gpc: 1
        Priority: u=0
        Te: trailers

        {"data":"$INPUT"}

    Here $INPUT will be replaced with the input value provided to call_model.

        HTTP/2 400 Bad Request
        Date: Tue, 20 May 2025 05:58:14 GMT
        Content-Type: application/json
        Content-Length: 46
        Server: uvicorn
        Apigw-Requestid: K2j-dj6KPHcEMvw=
        Access-Control-Allow-Origin: https://platform.dreadnode.io

        {"message":"$OUTPUT"}]]>

    Here the location of $OUTPUT in the response body indicates that the output value will be extracted from the response JSON under the "message" key.
    If the response is not JSON, it will be returned as is.

    You can also specify request-response pairs in a config file similar to that of the Rest Generator:
        {
        "multi_endpoint_rest": {
            "MultiEndpointGenerator": {
                "first_stage": {
                    "name": "request service",
                    "uri": "https://example.ai/llm",
                    "method": "post",
                    "headers": {
                        "X-Authorization": "$KEY",
                    },
                    "req_template_json_object": {
                        "text": "$INPUT"
                    },
                    "response_json": true,
                    "response_json_body": "$1$Hello$1$"
                },
                "second_stage": {
                    "name": "response service",
                    "uri": "https://example.ai/llm",
                    "method": "post",
                    "headers": {
                        "X-Authorization": "$KEY",
                    },
                    "req_template_json_object": {
                        "text": "$INPUT"
                    },
                    "response_json": true,
                    "response_template_json_object": {
                        "text": "$OUT$data$OUT$"
                    }
                }
            }
        }
    }
    """

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "reqresp_pairs": [],
        "burpfile": None,
        "manual": [],
    }

    def __init__(self, name="MultiRestGenerator", config_root=_config):
        super().__init__(name, config_root=config_root)
        # Error condition for when neither burpfile nor manual is provided
        if not self.burpfile and not self.manual:
            raise ValueError(
                "You must provide either a burpfile or manually define request and responses in the config file for MultiRestGenerator."
            )
        # Error condition for when both burpfile and manual is provided
        if self.burpfile and self.manual:
            raise ValueError(
                "You cannot provide both a burpfile and manual definitions to the MultiRestGenerator."
            )
        # Load request-response pairs from burpfile or manual
        if self.burpfile:
            self.reqresp_pairs = self.get_reqrep_fromburp()
        else:
            self.reqresp_pairs = self.get_reqrep_fromconfig()

    def get_reqrep_fromconfig(self):
        def parse_domain(uri):
            # Extracts the domain from a URI
            match = re.match(r"https?://([^/]+)", uri)
            return match.group(1) if match else None

        # Parses the manual definitions and returns a list of request-response pairs
        pairs = []
        for k, item in self.manual.items():
            # Might need to just move this to a separate function.
            req = {
                "headers": item["headers"] | {"Host": parse_domain(item["uri"])},
                "body": (
                    item["req_template_json_object"] if item["method"] == "post" else {}
                ),
                "method": item["method"],
                "endpoint": item["uri"][item["uri"].rindex("/") :],
            }
            resp = {
                "headers": {},
                "body": (
                    item["response_template_json_object"]
                    if item.get("response_json")
                    else {}
                ),
                "status": "",
                "error message": "",
            }
            pairs.append({"request": req, "response": resp})
        return pairs

    def get_reqrep_fromburp(self):
        # Parses the Burp Suite XML file and extracts request-response pairs
        tree = ET.parse(self.burpfile)
        root = tree.getroot()
        pairs = []
        for item in root.findall("item"):
            req = item.find("request").text
            resp = item.find("response").text
            pairs.append(
                {
                    "request": self.make_reqrep_dictionary(req),
                    "response": self.make_reqrep_dictionary(resp),
                }
            )
        return pairs

    def make_reqrep_dictionary(self, text: str):
        # Converts a raw HTTP request or response text into a dictionary format
        packet = {"headers": {}, "body": ""}
        http_line = text.split("\n")
        border = http_line.index("")
        for substring in http_line[:border]:
            # This condition assumes that the line is a Header
            if ":" in substring:
                i = substring.index(":")
                packet["headers"][substring[:i]] = (
                    substring[i + 1 :].rstrip("\n").lstrip(" ").lower()
                )
            # This condition assumes that the line is a Request
            elif " HTTP/" in substring:
                a = substring.rstrip("\n").split(" ")
                packet["method"] = a[0]
                packet["endpoint"] = a[1]
            # This condition assumes that the line is a Response
            elif "HTTP/" in substring:
                a = substring.rstrip("\n").split(" ")
                packet["status"] = a[1]
                packet["error message"] = "".join(a[2:])
        try:
            packet["body"] = json.loads(http_line[-1])
        except json.decoder.JSONDecodeError:
            packet["body"] = http_line[-1]
        return packet

    def make_request(self, packet):
        method = packet.get("method", "POST")
        url = f"https://{packet['headers'].get('Host')}{packet.get('endpoint', '')}"
        headers = {
            k: v
            for k, v in packet["headers"].items()
            if k not in ["method", "Host", "endpoint"]
        }
        data = packet.get("body", "")
        if method == "GET":
            resp = requests.get(url, headers=headers)
        else:
            try:
                json_data = json.loads(data)
                resp = requests.post(url, headers=headers, json=json_data)
            except Exception:
                resp = requests.post(url, headers=headers, data=data)
        return self.parse_response(resp)

    def compare_responses(self, expected, actual):
        # This just checks if the keys match.
        e_keys = list(expected.keys()).sort()
        a_keys = list(actual.keys()).sort()
        return e_keys == a_keys

    def extract_variable_locations(self, expected, location=None, locations=None):
        if location == None:
            location = []
        if locations == None:
            locations = {}

        if type(expected) == dict:
            for k, v in expected.items():
                self.extract_variable_locations(v, location + [k], locations)
        else:
            placeholders = re.findall(r"\$(OUT|\d+)\$", expected)
            for placeholder in placeholders:
                locations[placeholder] = location
        return locations

    def update_locations_dictionary(self, dictionary, packet):
        location_dict = dictionary.copy()
        result = packet
        for var_number, locations in location_dict.items():
            if type(locations) == list:
                for location in locations:
                    result = result[location]
            else:
                continue
            location_dict[var_number] = result
        return location_dict

    def place_var_into_request_packet(self, packet, locations, new_packet=None):
        if not new_packet:
            new_packet = {}
        if type(packet) == dict:
            for k, v in packet.items():
                new_packet[k] = self.place_var_into_request_packet(v, locations)
            return new_packet
        else:
            string_to_edit = packet  # At this point, this should be a string.

            def repl(match):
                num = match.group(1)
                return locations.get(num, match.group(0))

            return re.sub(r"\$(\d+)\$.*?\$\1\$", repl, string_to_edit)

    def place_input_into_request_packet(
        self, packet: dict, prompt: str, new_packet=None
    ):
        if not new_packet:
            new_packet = {}
        if type(packet) == dict:
            for k, v in packet.items():
                new_packet[k] = self.place_input_into_request_packet(v, prompt)
            return new_packet
        else:
            string_to_compare = packet  # At this point, this should be a string.
            if string_to_compare == "$INPUT":
                return prompt
            else:
                return string_to_compare

    def parse_response(self, raw_response: requests.Response) -> dict:
        return {
            "headers": raw_response.headers,
            "body": (
                raw_response.json()
                if raw_response.headers["Content-Type"] == "application/json"
                else raw_response.text
            ),
        }

    def run(self, prompt: str,locations = {}) -> str:
        
        for pair in self.reqresp_pairs:
            req_packet = self.place_input_into_request_packet(pair["request"], prompt)
            req_packet = self.place_var_into_request_packet(req_packet, locations)
            resp_packet = self.make_request(req_packet)
            if self.compare_responses(pair["response"], resp_packet):
                try:
                    locations.update(self.extract_variable_locations(pair["response"]))
                    locations.update(
                        self.update_locations_dictionary(locations, resp_packet)
                    )
                except:
                    raise KeyError(
                        f"Locator failure: Variable could not be found in actual response: {locations} -> {resp_packet}"
                    )
            else:
                raise ValueError(
                    f"Response mismatch: expected {pair["response"]}, got {resp_packet}"
                )
        if locations.get("OUT"):
            return locations["OUT"]
        else:
            return ""

    def _call_model(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        return ["".join(self.run(prompt))]
