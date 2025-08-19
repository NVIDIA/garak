Usage
=====

.. _installation:

Installation
------------

``garak`` is a command-line tool. It's developed in Linux and OSX.

Friendly install instructions are at `<https://docs.garak.ai/garak/llm-scanning-basics/setting-up/installing-garak>`_ .
The instructions below will work, but you might need to be quite familiar with your OS to use them, because they assume some particular pieces of background knowledge.

Standard quick `pip` install
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To use garak, first install it using pip:

.. code-block:: console

   pip install garak


Install development version with `pip`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The standard pip version of ``garak`` is updated periodically. To get a fresher version, from GitHub, try:

.. code-block:: console

    python3 -m pip install -U git+https://github.com/NVIDIA/garak.git@main


For development: clone from `git`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can also clone the source and run ``garak`` directly. This works fine and is recommended for development.

``garak`` has its own dependencies. You can to install ``garak`` in its own Conda environment:

.. code-block:: console

    conda create --name garak "python>=3.10,<=3.12"
    conda activate garak
    gh repo clone NVIDIA/garak
    cd garak
    python3 -m pip install -r requirements.txt

OK, if that went fine, you're probably good to go!


Running garak
-------------


The general syntax is:

.. code-block:: console

    garak <options>

``garak`` needs to know what model to scan, and by default, it'll try all the probes it knows on that model, using the vulnerability detectors recommended by each probe. You can see a list of probes using:

.. code-block:: console

    garak --list_probes

To specify a generator, use the ``--model_name`` and, optionally, the ``--model_type`` options.
Model name specifies a model family/interface; model type specifies the exact model to be used.
The "Intro to generators" section below describes some of the generators supported.
A straightfoward generator family is Hugging Face models; to load one of these, set ``--model_name`` to ``huggingface`` and ``--model_type`` to the model's name on Hub (e.g. "RWKV/rwkv-4-169m-pile").
Some generators might need an API key to be set as an environment variable, and they'll let you know if they need that.

``garak`` runs all the probes by default, but you can be specific about that too.
``--probes promptinject`` will use only the `PromptInject <https://github.com/agencyenterprise/promptinject>`_ framework's methods, for example.
You can also specify one specific plugin instead of a plugin family by adding the plugin name after a ``.``; for example, ``--probes lmrc.SlurUsage`` will use an implementation of checking for models generating slurs based on the `Language Model Risk Cards <https://arxiv.org/abs/2303.18190>`_ framework.


Examples
^^^^^^^^

Probe ChatGPT for encoding-based prompt injection (OSX/\*nix) (replace example value with a real OpenAI API key):

.. code-block:: console

    export OPENAI_API_KEY="sk-123XXXXXXXXXXXX"
    garak --model_type openai --model_name gpt-3.5-turbo --probes encoding


See if the Hugging Face version of GPT2 is vulnerable to DAN 11.0:

.. code-block:: console

    garak --model_type huggingface --model_name gpt2 --probes dan.Dan_11_0
