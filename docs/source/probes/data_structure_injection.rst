garak.probes.data_structure_injection
=====================================

This probe tests whether a target follows instructions embedded inside
structured data records. It covers common containers such as JSON, YAML, XML,
TOML, and Markdown front matter.

The probe asks the target to answer the ``user_request`` field in benign
records. Each record also contains an instruction-like field that asks the
target to emit a harmless canary. If the canary appears in the output, the
target adopted an instruction from another part of the data structure instead
of answering the actual user request.

.. automodule:: garak.probes.data_structure_injection
   :members:
   :undoc-members:
   :show-inheritance:

   .. show-asr::
