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
    The generator can handle both JSON and non-JSON responses.

    To set a variable in the response, use the format $n$...$n$, where n is a number.

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
    """
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "reqresp_pairs": [],
        "variables": {},
        "burpfile": "./tools/rest/multirest.xml",
    }

    def __init__(self, name="MultiRestGenerator", config_root=_config):
        super().__init__(name, config_root=config_root)

    def get_reqrep_fromburp(self, burpfile: str):
        tree = ET.parse(burpfile)
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

    def make_reqrep_dictionary(self, text):
        packet = {"headers": {}, "body": ""}
        http_line = text.split("\n")
        for substring in http_line:
            # change this to regex -> [a-zA-Z]:[a-z\ A-Z]* , something like that
            # This condition should parse headers
            if ":" in substring:
                i = substring.index(":")
                packet["headers"][substring[:i]] = (
                    substring[i + 1 :].rstrip("\n").lstrip(" ").lower()
                )
            # TODO: This needs to be changed to something more robust
            elif " HTTP/" in substring:
                a = substring.rstrip("\n").split(" ")
                packet["method"] = a[0]
                packet["endpoint"] = a[1]
            # TODO: This needs to be changed to something more robust
            elif "HTTP/" in substring:
                a = substring.rstrip("\n").split(" ")
                packet["status"] = a[1]
                packet["error message"] = "".join(a[2:])
            elif not substring:
                # TODO: There is probably a more robust way of doing this too
                packet["body"] = http_line[-1]
        return packet

    def extract_placeholders(self, text):
        # Finds all $n$...$n$ placeholders and returns a dict {n: value}
        matches = re.findall(r"\$(\d+)\$(.*?)\$\1\$", text)
        return {num: val for num, val in matches}

    def substitute_placeholders(self, text, input_value=None):
        # Replace $n$...$n$ with self.variables[n], and $INPUT with input_value
        def repl(match):
            num = match.group(1)
            return self.variables.get(num, match.group(0))

        text = re.sub(r"\$(\d+)\$.*?\$\1\$", repl, text)
        if input_value is not None:
            text = text.replace("$INPUT", input_value)
        return text

    def substitute_in_packet(self, packet, input_value=None):
        # Substitute placeholders in headers and body
        new_packet = packet.copy()
        new_packet["headers"] = {
            k: self.substitute_placeholders(v, input_value)
            for k, v in packet["headers"].items()
        }
        new_packet["body"] = self.substitute_placeholders(
            packet.get("body", ""), input_value
        )
        new_packet["endpoint"] = self.substitute_placeholders(
            packet.get("endpoint", ""), input_value
        )
        return new_packet

    def extract_vars_from_packet(self, packet):
        # Extract variables from headers and body
        vars_found = {}
        for v in packet["headers"].values():
            vars_found.update(self.extract_placeholders(v))
        vars_found.update(self.extract_placeholders(packet.get("body", "")))
        return vars_found

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
        return resp

    def compare_responses(self, expected, actual):
        if "$OUTPUT" in expected:
            return True
        try:
            expected_json = json.loads(expected)
            actual_json = actual.json()
            return expected_json == actual_json
        except Exception:
            return expected.strip() == actual.text.strip()

    def extract_output_from_json(self, template, real):
        outputs = []

        if isinstance(template, dict) and isinstance(real, dict):
            for k, v in template.items():
                if v == "$OUTPUT":
                    outputs.append(real.get(k))
                elif isinstance(v, (dict, list)):
                    outputs.extend(self.extract_output_from_json(v, real.get(k, {})))
        elif isinstance(template, list) and isinstance(real, list):
            for t_item, r_item in zip(template, real):
                outputs.extend(self.extract_output_from_json(t_item, r_item))
        return outputs

    def run(self, prompt):
        for pair in self.reqresp_pairs:
            # Substitute variables and $INPUT in request headers and body
            req_packet = self.substitute_in_packet(pair["request"], prompt)

            # Make the request
            resp = self.make_request(req_packet)

            # Extract variables from expected response headers and body
            vars_from_resp = self.extract_vars_from_packet(pair["response"])
            self.variables.update(vars_from_resp)

            # Compare actual and expected response
            expected_body = pair["response"].get("body", "")
            real_body = resp.text

            expected_body_sub = self.substitute_placeholders(
                pair["response"].get("body", "")
            )
            if self.compare_responses(expected_body_sub, resp):
                # If $OUTPUT is in the expected body and both are JSON, extract output
                if "$OUTPUT" in expected_body:
                    try:
                        expected_json = json.loads(expected_body)
                        real_json = resp.json()
                        outputs = self.extract_output_from_json(expected_json, real_json)
                        output = None
                        for key in range(len(outputs)):
                            output = outputs[key]
                        return output
                    except Exception:
                        return resp.text
            else:
                raise ValueError(
                    f"Response mismatch: expected {expected_body_sub}, got {real_body}"
                )

    def _call_model(
        self, prompt: str, generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        return ["".join(self.run(prompt))]
