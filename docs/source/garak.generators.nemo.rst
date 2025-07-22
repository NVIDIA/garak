garak.generators.nemo
=====================

Wrapper for `nemollm <https://pypi.org/project/nemollm/>`_.

Expects NGC API key in the environment variable ``NGC_API_KEY`` and the
organisation ID in environment variable ``ORG_ID``.

Configurable values:

* temperature: 0.9
* top_p: 1.0
* top_k: 2
* repetition_penalty: 1.1 - between 1 and 2 incl., or none
* beam_search_diversity_rate: 0.0
* beam_width: 1
* length_penalty: 1
* guardrail: None -  (present in API but not implemented in library)
* api_uri: "https://api.llm.ngc.nvidia.com/v1" - endpoint URI




.. automodule:: garak.generators.nemo
   :members:
   :undoc-members:
   :show-inheritance:
