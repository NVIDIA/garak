garak.generators.websocket
==========================

WebSocket connector for real-time LLM services.

This generator enables garak to test WebSocket-based LLM services that use 
real-time bidirectional communication, similar to modern chat applications.

Uses the following options from ``_config.plugins.generators["websocket"]["WebSocketGenerator"]``:

* ``uri`` - the WebSocket URI (ws:// or wss://); can also be passed in --model_name
* ``name`` - a short name for this service; defaults to "WebSocket Generator"
* ``auth_type`` - authentication method: "none", "basic", "bearer", or "custom"
* ``username`` - username for basic authentication
* ``api_key`` - API key for bearer token auth or password for basic auth
* ``key_env_var`` - environment variable holding API key; default ``WEBSOCKET_API_KEY``
* ``req_template`` - string template where ``$INPUT`` is replaced by prompt, ``$KEY`` by API key, ``$CONVERSATION_ID`` by conversation ID
* ``req_template_json_object`` - request template as Python object, serialized to JSON with placeholder replacements
* ``headers`` - dict of additional WebSocket headers
* ``response_json`` - is the response in JSON format? Set to ``True`` if the WebSocket returns JSON responses that need parsing (bool, default: ``False``)
* ``response_json_field`` - which field in the JSON response contains the actual text to extract? Supports simple field names like ``"text"`` or JSONPath notation like ``"$.data.message"`` for nested fields (str, default: ``"text"``)
* ``response_after_typing`` - wait for typing indicators to complete before returning response? Set to ``True`` for services that send typing notifications, ``False`` to return the first message immediately (bool, default: ``True``)
* ``typing_indicator`` - substring to detect in messages that indicates the service is still typing; messages containing this string are filtered out when ``response_after_typing`` is ``True`` (str, default: ``"typing"``)
* ``request_timeout`` - seconds to wait for response; default 20
* ``connection_timeout`` - seconds to wait for connection; default 10
* ``max_response_length`` - maximum response length; default 10000
* ``verify_ssl`` - enforce SSL certificate validation? Default ``True``

Templates work similarly to the REST generator. The ``$INPUT``, ``$KEY``, and 
``$CONVERSATION_ID`` placeholders are replaced in both string templates and 
JSON object templates.

JSON Response Extraction
------------------------

The ``response_json_field`` parameter supports JSONPath-style extraction:

* Simple field: ``"text"`` extracts ``response.text``
* Nested field: ``"$.data.message"`` extracts ``response.data.message``  
* Array access: ``"$.messages[0].content"`` extracts first message content

Authentication Methods
----------------------

**No Authentication:**

.. code-block:: JSON

   {
      "websocket": {
         "WebSocketGenerator": {
            "uri": "ws://localhost:3000/chat",
            "auth_type": "none"
         }
      }
   }

**Basic Authentication:**

.. code-block:: JSON

   {
      "websocket": {
         "WebSocketGenerator": {
            "uri": "ws://localhost:3000/chat",
            "auth_type": "basic",
            "username": "user"
         }
      }
   }

Set the password via environment variable:

.. code-block:: bash

   export WEBSOCKET_API_KEY="your_secure_password"

**Bearer Token:**

.. code-block:: JSON

   {
      "websocket": {
         "WebSocketGenerator": {
            "uri": "wss://api.example.com/llm",
            "auth_type": "bearer",
            "api_key": "your_api_key_here"
         }
      }
   }

**Environment Variable API Key:**

.. code-block:: JSON

   {
      "websocket": {
         "WebSocketGenerator": {
            "uri": "wss://api.example.com/llm", 
            "auth_type": "bearer",
            "key_env_var": "MY_LLM_API_KEY"
         }
      }
   }

Message Templates
-----------------

**Simple Text Template:**

.. code-block:: JSON

   {
      "websocket": {
         "WebSocketGenerator": {
            "uri": "ws://localhost:3000/chat",
            "req_template": "User: $INPUT"
         }
      }
   }

**JSON Object Template:**

.. code-block:: JSON

   {
      "websocket": {
         "WebSocketGenerator": {
            "uri": "ws://localhost:3000/chat",
            "req_template_json_object": {
               "message": "$INPUT",
               "conversation_id": "$CONVERSATION_ID",
               "api_key": "$KEY"
            },
            "response_json": true,
            "response_json_field": "text"
         }
      }
   }

**Complex JSON with Nested Response:**

.. code-block:: JSON

   {
      "websocket": {
         "WebSocketGenerator": {
            "uri": "wss://api.example.com/llm",
            "req_template_json_object": {
               "prompt": "$INPUT",
               "stream": false,
               "model": "gpt-4"
            },
            "response_json": true,
            "response_json_field": "$.choices[0].message.content"
         }
      }
   }

Usage Examples
---------------

**Command Line with JSON Options:**

.. code-block:: bash

   # Set password securely via environment variable
   export WEBSOCKET_API_KEY="your_secure_password"
   
   garak --model_type websocket.WebSocketGenerator \
         --generator_options '{"websocket": {"WebSocketGenerator": {"uri": "ws://localhost:3000", "auth_type": "basic", "username": "user"}}}' \
         --probes dan

**Configuration File:**

Save configuration to ``websocket_config.json`` and use:

.. code-block:: bash

   garak --model_type websocket.WebSocketGenerator \
         -G websocket_config.json \
         --probes encoding

**Testing with Public Echo Server:**

.. code-block:: bash

   garak --model_type websocket.WebSocketGenerator \
         --generator_options '{"websocket": {"WebSocketGenerator": {"uri": "wss://echo.websocket.org", "response_after_typing": false}}}' \
         --probes dan --generations 1

SSH Tunnel Support
------------------

The generator works seamlessly with SSH tunnels for secure remote testing:

.. code-block:: bash

   # Establish tunnel
   ssh -L 3000:target-host:3000 jump-host -N -f
   
   # Test through tunnel  
   garak --model_type websocket.WebSocketGenerator \
         --generator_options '{"websocket": {"WebSocketGenerator": {"uri": "ws://localhost:3000"}}}' \
         --probes malwaregen

Typing Indicators
-----------------

Many chat-based LLMs send typing indicators. Configure response handling:

* ``response_after_typing: true`` - Wait for typing to complete (default)
* ``response_after_typing: false`` - Return first substantial response
* ``typing_indicator`` - String to detect typing status (default "typing")

This enables proper testing of streaming/real-time LLM services.

----

.. automodule:: garak.generators.websocket
   :members:
   :undoc-members:
   :show-inheritance:


