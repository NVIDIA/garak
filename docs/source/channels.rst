channels
========

The channel catalog names every place an indirect prompt injection
payload can reach a target. A channel is a third axis next to technique
(probe) and intent (``IntentService``): it says *where* the payload
arrives, how much trust the target gives that place (``user``,
``system``, or ``data``), and how delivery happens:

- ``conversation``: the payload is part of the ``Conversation``. No
  infrastructure.
- ``patch``: the generator changes its own request.
- ``out_of_band``: an injector changes a data source. The generator does
  nothing.

The catalog is closed: code references the module constants, YAML
accepts their string values, and ``get()`` validates with the valid ids
listed on error.

.. list-table::
   :header-rows: 1

   * - Channel
     - Trust
     - Delivery
     - Description
   * - ``user_turn``
     - user
     - conversation
     - user turns of the conversation itself
   * - ``system_prompt``
     - system
     - patch
     - the target's system prompt
   * - ``tool_result``
     - data
     - out_of_band
     - results of the tools the target calls
   * - ``workspace_file``
     - data
     - out_of_band
     - files in the target's workspace
   * - ``retrieval_document``
     - data
     - out_of_band
     - documents the target retrieves

Patch kinds name the request changes a generator can apply to route
traffic through an injector occupying a channel: ``system_prompt`` and
``mcp_server``. Generators declare the kinds they support through
``supported_patches``; injectors declare the channels they can reach;
probes declare the channels they can drive through
``supported_channels``. ``garak --list_channels`` prints the catalog
with the plugins that support each entry.

.. automodule:: garak.channels
   :members:
   :undoc-members:
   :show-inheritance:
