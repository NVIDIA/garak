..  headings: = - ^ "

Getting Started
===============

Listing Probes
--------------

By default, when you run a scan, garak runs all the probes on the model and uses the vulnerability detectors recommended by each probe.
You can list the probes by running the following command:

.. code-block:: console

    garak --list_probes

You can limit the probes to run by specifying more arguments.

For example, you can specify ``--probes promptinject`` to run only the PromptInject framework's methods. for example.
You can also specify specific probes instead of a probe family such as ``--probes lmrc.SlurUsage`` to probe a model for generating slurs based on the Language Model Risk Cards framework.

Running a Scan
--------------

To run a scan, you must specify at least the service to scan with the ``--target_type`` argument, such as ``openai``, ``huggingface``, or ``nim``.
In most cases, you will also specify the model to scan with the ``--target_name`` argument, such as ``gpt-3.5-turbo``, ``meta/llama-3.1-8b-instruct``, and so on.

For example, to run a scan on the Hugging Face version of GPT2, use ``--target_type huggingface`` and ``--target_name gpt2``.

Some hosted models can require an API key to be set as an environment variable.
If you do not set the associated environment variable, garak stops the scan and reports the required variable name.

Sample Scans
------------

Probe ChatGPT for encoding-based prompt injection (OSX/\*nix) (replace example value with a real OpenAI API key):

.. code-block:: console

    export OPENAI_API_KEY="sk-123XXXXXXXXXXXX"
    garak --target_type openai --target_name gpt-3.5-turbo --probes encoding


Determine if the Hugging Face version of GPT2 is vulnerable to DAN 11.0:

.. code-block:: console

    garak --target_type huggingface --target_name gpt2 --probes dan.Dan_11_0
