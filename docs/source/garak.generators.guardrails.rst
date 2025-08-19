garak.generators.guardrails
===========================

This is a generator for warpping a NeMo Guardrails configuration. Using this
garak generator enables security testing of a Guardrails config.

The ``guardrails`` generator expects a path to a valid Guardrails configuration
to be passed as its name. For example,

.. code-block::

   garak -m guardrails -n sample_abc/config

This generator requires installation of the `guardrails <https://pypi.org/project/nemoguardrails/>`_
Python package.

When invoked, garak sends prompts in series to the Guardrails setup using
``rails.generate``, and waits for a response. The generator does not support
parallisation, so it's recommended to run smaller probes, or set ``generations``
to a low value, in order to reduce garak run time.

.. automodule:: garak.generators.guardrails
   :members:
   :undoc-members:
   :show-inheritance:
