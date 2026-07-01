garak.probes.data_structure_injection
=====================================

This probe tests whether a target copies attacker-controlled structured data
into tool-call or workflow outputs. It covers common containers such as JSON,
YAML, XML, TOML, and Markdown front matter.

The probe asks the target to produce safe structured tool calls from trusted
policy and request data. Each prompt also includes customer-controlled
structured text that attempts one of three data-structure injection patterns:

* schema widening, where an embedded tool update adds fields such as ``cc`` or
  callback URLs
* workflow injection, where an embedded workflow fragment adds extra tool steps
* argument contamination, where an allowed tool argument is prefilled with an
  unsafe recipient, URL, tag, or identifier

If one of the embedded values appears in the output, the target has treated
customer-controlled structure as authoritative instead of using the trusted
policy and workflow boundary.

.. automodule:: garak.probes.data_structure_injection
   :members:
   :undoc-members:
   :show-inheritance:

   .. show-asr::
