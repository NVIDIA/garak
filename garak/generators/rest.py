# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""REST API generator interface

Generic Module for REST API connections
"""

import json
import logging
from typing import List, Union
import requests

import backoff
import jsonpath_ng
from jsonpath_ng.exceptions import JsonPathParserError

from garak import _config
from garak.attempt import Message, Conversation
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
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        """Individual call to get a rest from the REST API

        :param prompt: the input to be placed into the request template and sent to the endpoint
        :type prompt: str
        """

        # should this support a serialized Conversation?
        request_data = self._populate_template(
            self.req_template, prompt.last_message().text
        )

        request_headers = dict(self.headers)
        for k, v in self.headers.items():
            # why does this provide the prompt to fill out headers?
            request_headers[k] = self._populate_template(v, prompt.last_message().text)

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
            return [Message(str(resp.text))]

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

        return [Message(r) for r in response]


DEFAULT_CLASS = "RestGenerator"
