Translation Support
===================

Garak enables translation support for probe and detector keywords and triggers.
Allowing testing of models that accept and produce text in languages other than the language the plugin was written for.

Limitations
-----------

- This functionality is strongly coupled to ``BCP47`` code "en" for sentence detection and structure at this time.
- Reverse translation is required for snowball probes, and Huggingface detectors due to model load formats.
- Huggingface detectors primarily load English models. Requiring a target language NLI model for the detector.
- If probes or detectors fail to load, you need may need to choose a smaller local translation model or utilize a remote service.
- Translation may add significant execution time to the run depending on resources available.

Supported Translation Services
------------------------------

- Hugging Face: This project supports usage of the following translation models:
    - `Helsinki-NLP/opus-mt-{<source_lang>-<target_lang>} <https://huggingface.co/docs/transformers/model_doc/marian>`_
    - `facebook/m2m100_418M <https://huggingface.co/facebook/m2m100_418M>`_
    - `facebook/m2m100_1.2B <https://huggingface.co/facebook/m2m100_1.2B>`_
- `DeepL <http://www.deepl.com>`_
- `NVIDIA Riva for Developers <https://developer.nvidia.com/riva>`_
- `Google Cloud Translation API <https://cloud.google.com/translate/docs/reference/api-overview>`_

API Key Requirements
--------------------

To use use DeepL API, Riva API, or Google Cloud Translation to translate probe and detector keywords and triggers from cloud services an API key must be supplied.

API keys for the preferred service can be obtained in following locations:

- `DeepL Pro-API <https://www.deepl.com/en/pro-api>`_
- `Riva on build.nvidia.com <https://build.nvidia.com/nvidia/megatron-1b-nmt>`_
- `Google Cloud Translation <https://cloud.google.com/translate/docs/authentication>`_

Supported languages for remote services:

- `DeepL Languages Supported | DeepL API documentation <https://developers.deepl.com/docs/resources/supported-languages>`_
- `Riva support matrix: supported languages <https://docs.nvidia.com/nim/riva/nmt/latest/getting-started.html#supported-languages>`_
- `Google Cloud Translation: supported languages <https://cloud.google.com/translate/docs/languages>`_

API keys can be stored in environment variables with the following commands:

DeepL
~~~~~

.. code-block:: bash

    export DEEPL_API_KEY=xxxx

RIVA
~~~~

.. code-block:: bash

    export RIVA_API_KEY=xxxx

Google Cloud Translation
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    export GOOGLE_APPLICATION_CREDENTIALS=<path to credential configuration json file>

Configuration File
------------------

Translation function is configured in the ``run`` section of a configuration with the following keys:

``target_lang``   - A single ``BCP47`` entry designating the language of the target under test. "ja", "fr", "jap" etc.
``langproviders`` - A list of language pair designated translator configurations.

* Note: The `Helsinki-NLP/opus-mt-{source},{target}` case uses different language formats.
  The language codes used to name models are inconsistent.
  Two-letter codes can usually be found in the `Google Admin SDK <https://developers.google.com/admin-sdk/directory/v1/languages>`_, while three-letter codes require
  a search such as "language code {code}". More details can be found in the `OPUS-MT-train <https://github.com/Helsinki-NLP/OPUS-MT-train/tree/master/models>`_ repository.

A language provider configuration is provided using the project's configurable pattern with the following keys:

* ``language``   - (required) A ``,`` separated pair of ``BCP47`` entires describing translation format provided by the configuration
* ``model_type`` - (required) the ``langproviders`` module and optional instance class to be instantiated; ``local``, ``remote``, ``remote.DeeplTranslator`` etc.
* ``model_name`` - (conditional) the model name loaded for translation. This field is required for ``local`` translator ``model_type``

(Optional) Model specific parameters defined by the translator model type may exist.

* Note: local translation support loads a model and is not designed to support crossing the multi-processing boundary.

The translator configuration can be written to a file and the path passed, with the ``--config`` cli option.

An example template is provided below.

.. code-block:: yaml

   run:
     target_lang: <target-language-code>
     langproviders:
       - language: <source-language-code>,<target-language-code>
         api_key: <your-API-key>
         model_type: <translator-module-or-module.classname>
         model_name: <huggingface-model-name>
       - language: <target-language-code>,<source-language-code>
         api_key: <your-API-key>
         model_type: <translator-module-or-module.classname>
         model_name: <huggingface-model-name>

* Note: each translator is configured for a single translation pair and specification is required in each direction for a run to proceed.

Examples for Translation Configuration
--------------------------------------

DeepL
~~~~~

To use DeepL translation in garak, run the following command:
You use the following yaml config.

.. code-block:: yaml

   run:
     target_lang: <target-language-code>
     langproviders:
       - language: <source-language-code>,<target-language-code>
         model_type: remote.DeeplTranslator
       - language: <target-language-code>,<source-language-code>
         model_type: remote.DeeplTranslator


.. code-block:: bash

   export DEEPL_API_KEY=xxxx
   python3 -m garak --target_type nim --target_name meta/llama-3.1-8b-instruct --probes encoding --config <path-to-your-yaml-config-file>


Riva
~~~~

For Riva, run the following command:
You use the following yaml config.

.. code-block:: yaml

   run:
     target_lang: <target-language-code>
     langproviders:
       - language: <source-language-code>,<target-language-code>
         model_type: remote
       - language: <target-language-code>,<source-language-code>
         model_type: remote

.. code-block:: bash

   export RIVA_API_KEY=xxxx
   python3 -m garak --target_type nim --target_name meta/llama-3.1-8b-instruct --probes encoding --config <path-to-your-yaml-config-file>


Google Cloud Translation
~~~~~~~~~~~~~~~~~~~~~~~~

For Google Cloud Translation, run the following command:
You use the following yaml config.

.. code-block:: yaml

    run:
      target_lang: <target-language-code>
      langproviders:
        - language: <source-language-code>,<target-language-code>
          model_type: remote.GoogleTranslator
        - language: <target-language-code>,<source-language-code>
          model_type: remote.GoogleTranslator


.. code-block:: bash

    export GOOGLE_APPLICATION_CREDENTIALS=<path to credential configuration json file>
    python3 -m garak --target_type nim --target_name meta/llama-3.1-8b-instruct --probes encoding --config <path-to-your-yaml-config-file>


Local
~~~~~

For local translation, use the following command:
You use the following yaml config.

.. code-block:: yaml

   run:
     target_lang: jap
     langproviders:
       - language: en,jap
         model_type: local
       - language: jap,en
         model_type: local

.. code-block:: bash

   python3 -m garak --target_type nim --target_name meta/llama-3.1-8b-instruct --probes encoding --config <path-to-your-yaml-config-file>

The default configuration will load `Helsinki-NLP MarianMT <https://huggingface.co/docs/transformers/model_doc/marian>`_ models for local translation.

Additional support for Hugging Face ``M2M100Model`` type only is enabled by providing ``model_name`` for local translators. The model name provided must
contain ``m2m100`` to be loaded by garak.

.. code-block:: yaml

   run:
     target_lang: ja
     langproviders:
       - language: en,ja
         model_type: local
         model_name: facebook/m2m100_418M
       - language: jap,en
         model_type: local
         model_name: facebook/m2m100_418M


.. code-block:: bash

   python3 -m garak --target_type nim --target_name meta/llama-3.1-8b-instruct --probes encoding --config <path-to-your-yaml-config-file>
