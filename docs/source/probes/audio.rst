garak.probes.audio
==================

.. automodule:: garak.probes.audio
   :members:
   :undoc-members:
   :show-inheritance:

Prompt extraction with text-to-speech
-------------------------------------

``PETTS`` renders intent stubs with a secondary garak generator, then sends the
generated WAV data to the assessed target. The default helper is
``huggingface.Pipeline`` using the public ``suno/bark-small`` model and the
``text-to-audio`` pipeline task. The helper is separate from the target being
assessed.

The target generator must declare audio input support and WAV compatibility.
For example, an audio-capable model exposed by NVIDIA NIM can be assessed with::

   NIM_API_KEY=<key> python -m garak \
     --target_type nim.NVMultimodal \
     --target_name microsoft/phi-4-multimodal-instruct \
     --spec probes.audio.PETTS

The first run downloads the configured text-to-audio model. Device placement
and other Transformers options are passed through ``tts_generator_config``.
For example, this probe configuration forces synthesis onto CPU::

   {
     "probes": {
       "audio": {
         "PETTS": {
           "tts_generator_config": {
             "pipeline_task": "text-to-audio",
             "hf_args": {"device": "cpu", "torch_dtype": "float32"}
           }
         }
       }
     }
   }

The model name, helper type and helper configuration can be replaced with any
garak generator that accepts text and returns a WAV audio ``Message``.
