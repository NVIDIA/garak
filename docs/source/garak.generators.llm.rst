garak.generators.llm
====================

Wraps Simon Willison's ``llm`` library, which provides a unified interface
to many LLM providers (OpenAI, Claude, Gemini, Ollama, etc.) via plugins.

API keys and provider setup are managed by ``llm`` directly. Install the
base package and any provider plugins you need:

.. code-block:: bash

   pip install llm llm-claude-3

Then invoke garak with the ``llm`` model id:

.. code-block:: bash

   garak --model_type llm --model_name gpt-4o-mini

.. automodule:: garak.generators.llm
   :members:
   :undoc-members:
   :show-inheritance:
