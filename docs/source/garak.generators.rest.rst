garak.generators.rest
=====================

Flexible connector for REST-based APIs.

Uses the following options from ``_config.plugins.generators["rest.RestGenerator"]``:

* ``uri`` - (optional) the URI of the REST endpoint; this can also be passed in --model_name
* ``name`` - a short name for this service; defaults to the uri
* ``key_env_var`` - (optional) the name of the environment variable holding an API key, by default ``REST_API_KEY``
* ``req_template`` - a string where the text ``$KEY`` is replaced by env var ``REST_API_KEY``'s value (or whatever's specified in ``key_env_var``) and ``$INPUT`` is replaced by the prompt. Default is to just send the input text.
* ``req_template_json_object`` - (optional) the request template as a Python object, to be serialised as a JSON string before replacements
* ``method`` - a string describing the HTTP method, to be passed to the requests module; default "post".
* ``headers`` - dict describing HTTP headers to be sent with the request
* ``proxies`` - dict passed to ``requests`` method call. See `required format <https://requests.readthedocs.io/en/latest/user/advanced/#proxies>`_.
* ``response_json`` - Is the response in JSON format? (bool)
* ``response_json_field`` - (optional) Which field of the response JSON should be used as the output string? Default ``text``. Can also be a JSONPath value, and ``response_json_field`` is used as such if it starts with ``$``.
* ``request_timeout`` - How many seconds should we wait before timing out? Default 20
* ``ratelimit_codes`` - Which endpoint HTTP response codes should be caught as indicative of rate limiting and retried? ``List[int]``, default ``[429]``
* ``skip_codes`` - Which endpoint HTTP response code should lead to the generation being treated as not possible and skipped for this query. Takes precedence over ``ratelimit_codes``.
* ``verify_ssl`` - (optional) Enforce ssl certificate validation? Default is ``True``, a file path to a CA bundle can be provided. (bool|str)

Templates can be either a string or a JSON-serialisable Python object.
Instance of ``$INPUT`` here are replaced with the prompt; instances of ``$KEY``
are replaced with the specified API key. If no key is needed, just don't
put ``$KEY`` in a template.

The ``$INPUT`` and ``$KEY`` placeholders can also be specified in header values.

If we want to call an endpoint where the API key is defined in the value
of an ``X-Authorization`` header, sending and receiving JSON where the prompt
and response value are both under the ``text`` key, we'd define the service
using something like:

.. code-block:: JSON

   {
      "rest": {
         "RestGenerator": {
            "name": "example service",
            "uri": "https://example.ai/llm",
            "method": "post",
            "headers": {
               "X-Authorization": "$KEY"
            },
            "req_template_json_object": {
               "text": "$INPUT"
            },
            "response_json": true,
            "response_json_field": "text"
         }
      }
   }

NB. ``response_json_field`` can also be a JSONPath, for JSON responses where
the target text is not in a top level field. It is treated as a JSONPath
when ``response_json_field`` starts with ``$``.

To use this specification with garak, you can either pass the JSON as a
strong option on the command line via ``--generator_options``, or save the
JSON definition into a file and pass the filename to
``--generator_option_file`` / ``-G``. For example, if we save the above
JSON into ``example_service.json``, we can invoke garak as:

.. code-block::

   garak --model_type rest -G example_service.json

This will load up the default ``RestGenerator`` and use the details in the
JSON file to connect to the LLM endpoint.

If you need something more flexible, add a new module or class and inherit
from RestGenerator.

----

.. automodule:: garak.generators.rest
   :members:
   :undoc-members:
   :show-inheritance:
