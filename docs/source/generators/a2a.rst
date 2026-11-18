garak.generators.a2a
====================

Connector for AI agents exposed over the Agent-to-Agent (A2A) protocol
(task-based message exchange over JSON-RPC 2.0).

Probing an agent through A2A tests the deployed system, including its
server-side instructions, tools and guardrails, rather than the underlying model alone.

Protocol support
----------------

A2A spec 0.3 (``message/send``) is used by default. If the endpoint answers
with JSON-RPC error ``-32601`` (method not found), the generator falls back to
spec 0.2 (``tasks/send``) and keeps using it for the rest of the run. Set
``dialect`` to ``v03`` or ``v02`` to skip negotiation.

Requests ask the agent to block until the task completes. If the agent
still returns a task in the ``submitted`` or ``working`` state, the generator
polls ``tasks/get`` until the task finishes or ``request_timeout`` expires.

Rate limits are retried with backoff. This covers HTTP ``429`` responses, and
JSON-RPC errors whose message reports a ``429`` from the model behind the agent.
Other JSON-RPC error responses are logged and treated as no output from the target.

Conversations
-------------

A2A clients can only send ``user`` messages, and an agent's server-side
state can't be branched to follow different probe paths. Each call therefore
starts a new A2A context and sends the whole probe conversation in a single
message. Every turn becomes its own text part, with the role recorded in the
part ``metadata``. Earlier turns, including any system turn, are prefixed with
their role (``System:``, ``User:``, ``Assistant:``), and the final part is
the current user prompt.

Authentication
--------------

* ``auth_token`` is sent as ``Authorization: Bearer <token>``.
* ``api_key`` is sent in the header named by ``api_key_header``.
* If neither is configured, the key is read from the ``A2A_API_KEY``
  environment variable when it is set. Set ``key_env_var`` to use a different
  variable; the run fails if that variable is missing.
* With no credentials, requests are sent without authentication.

Configuration
-------------

Save the generator options in a JSON file:

.. code-block:: JSON

   {
      "a2a": {
         "A2AGenerator": {
            "uri": "https://agent.example.com/a2a",
            "name": "example agent"
         }
      }
   }

and pass it with ``--generator_option_file`` / ``-G``:

.. code-block::

   export A2A_API_KEY="XXXXXXX"
   garak --target_type a2a -G example_agent.json --spec probes.promptinject

The URI can also be given directly as ``--target_name``. See
:doc:`/configurable` for other ways to set these options.

Microsoft Foundry agents
------------------------

This generator has been tested against a Microsoft Foundry Agent Service
prompt agent with incoming A2A enabled, using A2A 0.3 over JSON-RPC. See
`Enable incoming A2A on a Foundry agent <https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/enable-agent-to-agent-endpoint>`_
for setup. Foundry requires a Microsoft Entra bearer token, which can be passed
through the ``Authorization`` header:

.. code-block:: JSON

   {
      "a2a": {
         "A2AGenerator": {
            "uri": "https://<account>.services.ai.azure.com/api/projects/<project>/agents/<agent>/endpoint/protocols/a2a",
            "api_key_header": "Authorization"
         }
      }
   }

.. code-block::

   export A2A_API_KEY="Bearer $(az account get-access-token --resource https://ai.azure.com --query accessToken -o tsv)"
   garak --target_type a2a -G foundry_agent.json --spec probes.promptinject

When Azure content filtering blocks a prompt, Foundry returns a generic JSON-RPC
``-32603`` error rather than a content-filter reason, so those attempts are
recorded as no output.

.. automodule:: garak.generators.a2a
   :members:
   :undoc-members:
   :show-inheritance:
