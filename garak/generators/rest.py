# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""REST API generator interface

Generic Module for REST API connections
"""


import json
import xml.etree.ElementTree as ET
import logging
from typing import List, Union

import requests
from websockets.sync.client import connect

import re
import backoff
import jsonpath_ng
from jsonpath_ng.exceptions import JsonPathParserError

from garak import _config
from garak.exception import (
    APIKeyMissingError,
    BadGeneratorException,
    RateLimitHit,
    GarakBackoffTrigger,
)
from garak.generators.base import Generator


class RestGenerator(Generator):
    """Generic API interface for REST models

    See reference docs for details (https://reference.garak.ai/en/latest/garak.generators.rest.html)
    """

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "headers": {},
        "method": "post",
        "ratelimit_codes": [429],
        "skip_codes": [],
        "response_json": False,
        "response_json_field": None,
        "req_template": "$INPUT",
        "request_timeout": 20,
        "proxies": None,
        "verify_ssl": True,
    }

    ENV_VAR = "REST_API_KEY"
    generator_family_name = "REST"

    _supported_params = (
        "api_key",
        "name",
        "uri",
        "key_env_var",
        "req_template",
        "req_template_json",
        "context_len",
        "max_tokens",
        "method",
        "headers",
        "response_json",
        "response_json_field",
        "req_template_json_object",
        "request_timeout",
        "ratelimit_codes",
        "skip_codes",
        "skip_seq_start",
        "skip_seq_end",
        "temperature",
        "top_k",
        "proxies",
        "verify_ssl",
    )

    def __init__(self, uri=None, config_root=_config):
        self.uri = uri
        self.name = uri
        self.supports_multiple_generations = False  # not implemented yet
        self.escape_function = self._json_escape
        self.retry_5xx = True
        self.key_env_var = self.ENV_VAR if hasattr(self, "ENV_VAR") else None

        # load configuration since super.__init__ has not been called
        self._load_config(config_root)

        if (
            hasattr(self, "req_template_json_object")
            and self.req_template_json_object is not None
        ):
            self.req_template = json.dumps(self.req_template_json_object)

        if self.response_json:
            if self.response_json_field is None:
                raise ValueError(
                    "RestGenerator response_json is True but response_json_field isn't set"
                )
            if not isinstance(self.response_json_field, str):
                raise ValueError("response_json_field must be a string")
            if self.response_json_field == "":
                raise ValueError(
                    "RestGenerator response_json is True but response_json_field is an empty string. If the root object is the target object, use a JSONPath."
                )

        if self.name is None:
            self.name = self.uri

        if self.uri is None:
            raise ValueError(
                "No REST endpoint URI definition found in either constructor param, JSON, or --model_name. Please specify one."
            )

        self.fullname = f"{self.generator_family_name} {self.name}"

        self.method = self.method.lower()
        if self.method not in (
            "get",
            "post",
            "put",
            "patch",
            "options",
            "delete",
            "head",
        ):
            logging.info(
                "RestGenerator HTTP method %s not supported, defaulting to 'post'",
                self.method,
            )
            self.method = "post"
        self.http_function = getattr(requests, self.method)

        # validate proxies formatting
        # sanity check only leave actual parsing of values to the `requests` library on call.
        if hasattr(self, "proxies") and self.proxies is not None:
            if not isinstance(self.proxies, dict):
                raise BadGeneratorException(
                    "`proxies` value provided is not in the required format. See documentation from the `requests` package for details on expected format. https://requests.readthedocs.io/en/latest/user/advanced/#proxies"
                )

        # suppress warnings about intentional SSL validation suppression
        if isinstance(self.verify_ssl, bool) and not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()

        # validate jsonpath
        if self.response_json and self.response_json_field:
            try:
                self.json_expr = jsonpath_ng.parse(self.response_json_field)
            except JsonPathParserError as e:
                logging.critical(
                    "Couldn't parse response_json_field %s", self.response_json_field
                )
                raise e

        super().__init__(self.name, config_root=config_root)

    def _validate_env_var(self):
        key_match = "$KEY"
        header_requires_key = False
        for _k, v in self.headers.items():
            if key_match in v:
                header_requires_key = True
        if "$KEY" in self.req_template or header_requires_key:
            return super()._validate_env_var()

    def _json_escape(self, text: str) -> str:
        """JSON escape a string"""
        # trim first & last "
        return json.dumps(text)[1:-1]

    def _populate_template(
        self, template: str, text: str, json_escape_key: bool = False
    ) -> str:
        """Replace template placeholders with values

        Interesting values are:
        * $KEY - the API key set as an object variable
        * $INPUT - the prompt text

        $KEY is only set if the relevant environment variable is set; the
        default variable name is REST_API_KEY but this can be overridden.
        """
        output = template
        if "$KEY" in template:
            if self.api_key is None:
                raise APIKeyMissingError(
                    f"Template requires an API key but {self.key_env_var} env var isn't set"
                )
            if json_escape_key:
                output = output.replace("$KEY", self.escape_function(self.api_key))
            else:
                output = output.replace("$KEY", self.api_key)
        return output.replace("$INPUT", self.escape_function(text))

    @backoff.on_exception(
        backoff.fibo, (RateLimitHit, GarakBackoffTrigger), max_value=70
    )
    def _call_model(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        """Individual call to get a rest from the REST API

        :param prompt: the input to be placed into the request template and sent to the endpoint
        :type prompt: str
        """

        request_data = self._populate_template(self.req_template, prompt)

        request_headers = dict(self.headers)
        for k, v in self.headers.items():
            request_headers[k] = self._populate_template(v, prompt)

        # the prompt should not be sent via data when using a GET request. Prompt should be
        # serialized as parameters, in general a method could be created to add
        # the prompt data to a request via params or data based on the action verb
        data_kw = "params" if self.http_function == requests.get else "data"
        req_kArgs = {
            data_kw: request_data,
            "headers": request_headers,
            "timeout": self.request_timeout,
            "proxies": self.proxies,
            "verify": self.verify_ssl,
        }
        try:
            resp = self.http_function(self.uri, **req_kArgs)
        except UnicodeEncodeError as uee:
            # only RFC2616 (latin-1) is guaranteed
            # don't print a repr, this might leak api keys
            logging.error(
                "Only latin-1 encoding supported by HTTP RFC 2616, check headers and values for unusual chars",
                exc_info=uee,
            )
            raise BadGeneratorException from uee

        if resp.status_code in self.skip_codes:
            logging.debug(
                "REST skip prompt: %s - %s, uri: %s",
                resp.status_code,
                resp.reason,
                self.uri,
            )
            return [None]

        if resp.status_code in self.ratelimit_codes:
            raise RateLimitHit(
                f"Rate limited: {resp.status_code} - {resp.reason}, uri: {self.uri}"
            )

        if str(resp.status_code)[0] == "3":
            raise NotImplementedError(
                f"REST URI redirection: {resp.status_code} - {resp.reason}, uri: {self.uri}"
            )

        if str(resp.status_code)[0] == "4":
            raise ConnectionError(
                f"REST URI client error: {resp.status_code} - {resp.reason}, uri: {self.uri}"
            )

        if str(resp.status_code)[0] == "5":
            error_msg = f"REST URI server error: {resp.status_code} - {resp.reason}, uri: {self.uri}"
            if self.retry_5xx:
                raise GarakBackoffTrigger(error_msg)
            raise ConnectionError(error_msg)

        if not self.response_json:
            return [str(resp.text)]

        response_object = json.loads(resp.content)

        response = [None]

        # if response_json_field starts with a $, treat is as a JSONPath
        assert (
            self.response_json
        ), "response_json must be True at this point; if False, we should have returned already"
        assert isinstance(
            self.response_json_field, str
        ), "response_json_field must be a string"
        assert (
            len(self.response_json_field) > 0
        ), "response_json_field needs to be complete if response_json is true; ValueError should have been raised in constructor"
        if self.response_json_field[0] != "$":
            if isinstance(response_object, list):
                response = [item[self.response_json_field] for item in response_object]
            else:
                response = [response_object[self.response_json_field]]
        else:
            field_path_expr = jsonpath_ng.parse(self.response_json_field)
            responses = field_path_expr.find(response_object)
            if len(responses) == 1:
                response_value = responses[0].value
                if isinstance(response_value, str):
                    response = [response_value]
                elif isinstance(response_value, list):
                    response = response_value
            elif len(responses) > 1:
                response = [r.value for r in responses]
            else:
                logging.error(
                    "RestGenerator JSONPath in response_json_field yielded nothing. Response content: %s"
                    % repr(resp.content)
                )
                return [None]

        return response




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

        {"message":"$OUT$Hello World$OUT$"}]]>

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

    def run(self, prompt: str, locations={}) -> str:

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
                response = pair["response"]
                raise ValueError(
                    f"Response mismatch: expected {response}, got {resp_packet}"
                )
        if locations.get("OUT"):
            return locations["OUT"]
        else:
            return ""

    def _call_model(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        return ["".join(self.run(prompt))]


class WebSocketGenerator(Generator):
    """
    This is a generator to work with websockets
    """

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "uri": None,
        "auth_key": None,
        "body": "{}",
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

    def _call_model(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        if output := self.request(self, prompt) == dict:
            return output[self.json_key]
        else:
            return output
            
DEFAULT_CLASS = "RestGenerator"
