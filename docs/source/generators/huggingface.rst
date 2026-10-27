garak.generators.huggingface
============================

.. automodule:: garak.generators.huggingface
   :members:
   :undoc-members:
   :show-inheritance:

Pipeline tasks
--------------

``huggingface.Pipeline`` uses the ``text-generation`` Transformers task by
default. Set ``pipeline_task`` to ``text-to-audio`` to use a compatible model
as a text-to-speech helper. Text-to-audio results are returned as PCM-16 WAV
data in a :class:`garak.attempt.Message`. Standard ``hf_args`` configuration
continues to control revision, device, dtype, device map and remote-code trust.
