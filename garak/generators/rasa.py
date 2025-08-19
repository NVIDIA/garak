# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Contribution from rgstephens

"""Rasa REST API generator interface

Module for Rasa REST API connections (https://rasa.com/)
"""

import json

from garak.generators.rest import RestGenerator


class RasaRestGenerator(RestGenerator):
    """API interface for RASA models

    Uses the following options from ``_config.plugins.generators["rasa.RasaRestGenerator"]``:

    * ``uri`` - (optional) the URI of the REST endpoint; this can also be passed
            in --model_name
    * ``name`` - a short name for this service; defaults to the uri
    * ``key_env_var`` - (optional) the name of the environment variable holding an
            API key, by default RASA_API_KEY
    * ``req_template`` - a string where $KEY is replaced by env var RASA_API_KEY
            and $INPUT is replaced by the prompt. Default is to just send the
            input text.
    * ``req_template_json_object`` - (optional) the request template as a Python
            object, to be serialised as a JSON string before replacements
    * ``method`` - a string describing the HTTP method, to be passed to the
            requests module; default "post".
    * ``headers`` - dict describing HTTP headers to be sent with the request
    * ``response_json`` - Is the response in JSON format? (bool)
    * ``response_json_field`` - (optional) Which field of the response JSON
            should be used as the output string? Default ``text``. Can also
            be a JSONPath value, and ``response_json_field`` is used as such
            if it starts with ``$``.
    * ``request_timeout`` - How many seconds should we wait before timing out?
            Default 20
    * ``ratelimit_codes`` - Which endpoint HTTP response codes should be caught
            as indicative of rate limiting and retried? List[int], default [429]

    Templates can be either a string or a JSON-serialisable Python object.
    Instance of "$INPUT" here are replaced with the prompt; instances of "$KEY"
    are replaced with the specified API key. If no key is needed, just don't
    put $KEY in a template.

    The $INPUT and $KEY placeholders can also be specified in header values.

    If we want to call an endpoint where the API key is defined in the value
    of an ``X-Authorization`` header, sending and receiving JSON where the prompt
    and response value are both under the "text" key, we'd define the service
    using something like:

    .. code-block:: json

       {
           "rasa": {
               "RasaRestGenerator": {
                   "name": "example rasa service",
                   "uri": "https://test.com/webhooks/rest/webhook"
               }
           }
       }

    To use this specification with garak, you can either pass the JSON as a
    strong option on the command line via --generator_options, or save the
    JSON definition into a file and pass the filename to
    --generator_option_file / -G. For example, if we save the above JSON into
    ``example_rasa_service.json``, we can invoke garak as:

      garak --model_type rest -G example_rasa_service.json

    This will load up the default RasaRestGenerator and use the details in the
    JSON file to connect to the LLM endpoint.

    If you need something more flexible, add a new module or class and inherit
    from RasaRestGenerator :)
    """

    DEFAULT_PARAMS = RestGenerator.DEFAULT_PARAMS | {
        "headers": {
            "Content-Type": "application/json",
            "Authorization": "Bearer $KEY",
        },
        "method": "post",
        "ratelimit_codes": [429],
        "req_template": json.dumps({"sender": "garak", "message": "$INPUT"}),
        "request_timeout": 20,
        "response_json": True,
        "response_json_field": "text",
    }

    ENV_VAR = "RASA_API_KEY"

    generator_family_name = "RASA"


DEFAULT_CLASS = "RasaRestGenerator"
