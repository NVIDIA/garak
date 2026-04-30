garak.detectors.harmbench
==================================

HarmBench classifier detectors. These wrap the upstream HarmBench classifier
models (``cais/HarmBench-Llama-2-13b-cls`` and
``cais/HarmBench-Mistral-7b-val-cls``) as garak detectors, loading the
classifier locally via Hugging Face Transformers and parsing a single
``Yes``/``No`` token per generation. The 13B classifier is the canonical
paper-numbers variant; the 7B Mistral subclass is a smaller alternative.

For the paper, see https://arxiv.org/abs/2402.04249. For the upstream
project, see https://github.com/centerforaisafety/HarmBench.


.. automodule:: garak.detectors.harmbench
   :members:
   :undoc-members:
   :show-inheritance:
