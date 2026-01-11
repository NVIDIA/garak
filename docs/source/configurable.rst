..  headings: = - ^ "

Configuring garak
=================

Beyond the standard CLI options, garak is highly configurable.
You can use YAML files to configure a garak run, down to the level
of exactly how each plugin behaves.


Specifying Custom Configuration
-------------------------------

garak can be configured in multiple ways:

* Via command-line parameters
* Using YAML or JSON config files
* Through specifying JSON on the command line

The easiest way is often to use a config file (YAML or JSON), and how to do that is
described below.

Garak Config Hierarchy
^^^^^^^^^^^^^^^^^^^^^^

Configuration values can come from multiple places. At garak load, the
``_config`` module manages parsing configuration. This includes determining
the priority of which values go where. The hierarchy is as follows:

1. Values given at the command line
2. Config values given in a YAML or JSON file passed via ``--config``
3. Values in a YAML or JSON site config, ``garak.site.yaml``, ``garak.site.yml``, or ``garak.site.json``, placed in the config directory (``XDG_CONFIG_DIR``, which is ``~/.config/garak/`` on Linux; see XDG spec for details)
4. Fixed values kept in the garak core config - don't edit this. Package updates will overwrite it, and you might break your garak install. It's in ``garak/resources`` if you want to take a look.
5. Default values specified in plugin code

Config Files (YAML and JSON)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Let's take a look at the core config.

.. code-block:: yaml

    ---
    system:
        verbose: 0
        narrow_output: false
        parallel_requests: false
        parallel_attempts: false
        lite: true
        show_z: false
        enable_experimental: false
        max_workers: 500

    run:
        system_prompt: "You are an AI model and this is a system prompt"
        seed:
        deprefix: true
        eval_threshold: 0.5
        generations: 5
        probe_tags:
        user_agent: "garak/{version} (LLM vulnerability scanner https://garak.ai)"
        soft_probe_prompt_cap: 256

    plugins:
        target_type:
        target_name:
        probe_spec: all
        detector_spec: auto
        extended_detectors: false
        buff_spec:
        buffs_include_original_prompt: false
        buff_max:
        detectors: {}
        generators: {}
        buffs: {}
        harnesses: {}
        probes:
            encoding:
                payloads:
                    - default

    reporting:
        report_prefix:
        taxonomy:
        report_dir: garak_runs
        show_100_pass_modules: true
        group_aggregation_function: minimum

Here we can see many entries that correspond to command line options, such as
``target_name`` and ``target_type``, as well as some entried not exposed via CLI
such as ``show_100_pass_modules``.


System Config Items
"""""""""""""""""""

* ``parallel_attempts`` - For parallelisable generators, how many attempts should be run in parallel? Raising this is a great way of speeding up garak runs for API-based models
* ``parallel_requests`` - For generators not supporting multiple responses per prompt: how many requests to send in parallel with the same prompt? (raising ``parallel_attempts`` generally yields higher performance, depending on how high ``generations`` is set)
* ``lite`` - Should we display a caution message that the run might not give very thorough results?
* ``verbose`` - Degree of verbosity (values above 0 are experimental, the report & log are authoritative)
* ``narrow_output`` - Support output on narrower CLIs
* ``show_z`` - Display Z-scores and visual indicators on CLI. It's good, but may be too much info until one has seen garak run a couple of times
* ``enable_experimental`` - Enable experimental function CLI flags. Disabled by default. Experimental functions may disrupt your installation and provide unusual/unstable results. Can only be set by editing core config, so a git checkout of garak is recommended for this.
* ``max_workers`` - Cap on how many parallel workers can be requested. When raising this in order to use higher parallelisation, keep an eye on system resources (e.g. `ulimit -n 4026` on Linux)



**Parallel requests and parallel attempts** These items enable parallelisation within a probe, by launching multiple processes to either try many prompts at the same time (``parallel_attempts``), or to try multiple copies of the same prompt at the same time (``parallel_requests``).
In testing, garak maintainers find that ``parallel_attempts`` usually runs quicker - especially if the endpoint is capable of returning more than one response to a query at a time.

If an endpoint can only return one response to a query at a time, but generations is set to a value greater than one, then each prompt is posed to the endpoint multiple times.
This can be slow.
Setting ``parallel_requests`` to a value over one enables making all these requests at the same time, mitigating the wallclock-time cost of multiple generations.

Parameter ``parallel_requests`` has no effect if generations is set to 1.
Setting ``parallel_requests`` higher than generations also has the same effect as setting ``parallel_requests`` equal to generations.

In practice, ``parallel_requests`` and ``parallel_attempts`` are mutually exclusive, so you have to choose between them. 
We find that using ``parallel_attempts`` usually gives a faster run completion time - especially when the number of generations is lower than the number of different prompts from a probe, which is more oftent he case than not in a default garak run.


Run Config Items
""""""""""""""""

* ``system_prompt`` -- If given and not overriden by the probe itself, probes will pass the specified system prompt when possible for generators that support chat modality.
* ``probe_tags`` - If given, the probe selection is filtered according to these tags; probes that don't match the tags are not selected
* ``generations`` - How many times to send each prompt for inference
* ``deprefix`` - Remove the prompt from the start of the output (some models return the prompt as part of their output)
* ``seed`` - An optional random seed
* ``eval_threshold`` - At what point in the 0..1 range output by detectors does a result count as a successful attack / hit
* ``user_agent`` - What HTTP user agent string should garak use? ``{version}`` can be used to signify where garak version ID should go
* ``soft_probe_prompt_cap`` - For probes that auto-scale their prompt count, the preferred limit of prompts per probe
* ``target_lang`` - A single language (as BCP47 that the target application for LLM accepts as prompt and output
* ``langproviders`` - A list of configurations representing providers for converting from probe language to lang_spec target languages (BCP47)

Plugins Config Items
""""""""""""""""""""

* ``target_type`` - The type of target generator, e.g. "nim" or "huggingface"
* ``target_name`` - The specific name of the target to be used (optional - if blank, type-specific default is used)
* ``probe_spec`` - A comma-separated list of probe modules or probe classnames (in ``module.classname``) format to be used. If a module is given, only ``active`` plugin in that module are chosen, this is equivalent to passing `-p` to the CLI
* ``detector_spec`` - An optional spec of detectors to be used, if overriding those recommended in probes. Specifying ``detector_spec`` means the ``pxd`` harness will be used. This is equivalent to passing `-d` to the CLI
* ``extended_detectors`` - Should just the primary detector be used per probe, or should the extended detectors also be run? The former is fast, the latter thorough.
* ``buff_spec`` - Comma-separated list of buffs and buff modules to use; same format as ``probe_spec``.
* ``buffs_include_original_prompt`` - When buffing, should the original pre-buff prompt still be included in those posed to the model?
* ``buff_max`` - Upper bound on how many items a buff should return
* ``detectors`` - Root node for detector plugin configs
* ``generators`` - Root note for generator plugin configs
* ``buffs`` - Root note for buff plugin configs
* ``harnesses`` - Root note for harness plugin configs
* ``probes`` - Root note for probe plugin configs

For an example of how to use the ``detectors``, ``generators``, ``buffs``,
``harnesses``, and ``probes`` root entries, see :ref:`Configuring plugins with YAML <config_with_yaml>` below.

Reporting Config Items
""""""""""""""""""""""

* ``report_dir`` - Directory for reporting; defaults to ``$XDG_DATA/garak/garak_runs``
* ``report_prefix`` - Prefix for report files. Defaults to ``garak.$RUN_UUID``
* ``taxonomy`` - Which taxonomy to use to group probes when creating HTML report
* ``show_100_pass_modules`` - Should entries scoring 100% still be detailed in the HTML report?
* ``show_group_score`` - Should an aggregated score per group be shown in reports?
* ``group_aggregation_function`` - How should scored of probe groups (e.g. plugin modules or taxonomy categories) be aggregrated in the HTML report? Options are ``minimum``, ``mean``, ``median``, ``mean_minus_sd``, ``lower_quartile``, and ``proportion_passing``. NB averages like ``mean`` and ``median`` hide a lot of information and aren't recommended.
* ``show_top_group_score`` - Should the aggregated score be shown as a top-level figure in report concertinas?


Bundled Quick Configs
^^^^^^^^^^^^^^^^^^^^^

Garak comes bundled with some quick configs that can be loaded directly using ``--config``.

**Note on extensions:** JSON configs can be loaded without the ``.json`` extension (e.g., ``--config fast``).
YAML configs require the explicit ``.yaml`` or ``.yml`` extension (e.g., ``--config fast.yaml`` or ``--config fast.yml``).
Extensions are case-insensitive, so ``.JSON``, ``.YAML``, and ``.YML`` are also accepted.

Bundled configs include:

* ``broad`` - Run all active probes, just once each, for a rapid broad test
* ``fast`` - Go through a selection of light probes; skip extended detectors
* ``full`` - Select many probes, and multiple payloads; use a paraphrase buff to get multiple variations on each prompt
* ``long_attack_gen`` - Focus on ``atkgen``, with many generations, to give a higher chance of breaking through (i.e. yielding toxicity)
* ``notox`` - Scan without any toxicity-inducing probes
* ``tox_and_buffs`` - Go through toxicity & slur probes, using only relevant payloads, and a fast paraphraser

These are great places to look at to get an idea of how garak configs can look.
Quick configs are stored under ``garak/configs/`` in the source code/install.


Using a Custom Config
^^^^^^^^^^^^^^^^^^^^^

To override values in this we can create a new config file (YAML or JSON) and point to it from the
command line using ``--config``. For example, to select just ``latentinjection``
probes and run each prompt just once:

**YAML format:**

.. code-block:: yaml

    ---
    run:
        generations: 1

    plugins:
        probe_spec: latentinjection

If we save this as ``latent1.yaml`` somewhere, then we can use it with ``garak --config latent1.yaml``.
Note: YAML configs require the explicit ``.yaml`` or ``.yml`` extension (case-insensitive).

**JSON format:**

.. code-block:: json

    {
      "run": {
        "generations": 1
      },
      "plugins": {
        "probe_spec": "latentinjection"
      }
    }

If we save this as ``latent1.json`` somewhere, then we can use it with ``garak --config latent1.json``
or without the extension: ``garak --config latent1``.

Using a Custom JSON Config
^^^^^^^^^^^^^^^^^^^^^^^^^^

Some plugins can take a JSON config specified on the command line. This config
has the same structure as a YAML config, starting with the plugin model/type.
The config can either be written to a file and the path passed, with
`--generator_option_file` or `--probe_option_file`, or directly as JSON on the
command prompt, with `--generator_options` or `--probe_options`. An example
is given in :ref:`RestGenerator Config with JSON <rest_generator_with_json>` below.


Configuring Plugins
-------------------

Garak's functions are through its plugins. Most parts of garak are plugins,
like the ``probes`` and ``detectors`` that do the actual examination of the target,
the ``generators`` that interface with models, and even the ``harnesses``
that manage run orchestration. Each plugin is a class that has both descriptive
and configurable parameters.

Viewing Plugin Parameters
^^^^^^^^^^^^^^^^^^^^^^^^^

You can see the parameters for any given plugin using garak ``--plugin_info``.

.. code-block:: text

    $ python -m garak --plugin_info probes.grandma.Win10
    garak LLM vulnerability scanner v0.10.0 ( https://github.com/NVIDIA/garak ) at 2024-09-11T11:54:07.215242
    Configured info on probes.grandma.Win10:
                            description: Will the model yield a Windows 10 product key if we beg it to?
                         DEFAULT_PARAMS: {'generations': 1}
                                 active: True
                                   lang: en
                                doc_uri: https://www.independent.co.uk/tech/chatgpt-microsoft-windows-11-grandma-exploit-b2360213.html
                     extended_detectors: ['mitigation.MitigationBypass']
                                   goal: get model to output Win 10 product keys
                               modality: {'in': ['text']}
                parallelisable_attempts: True
                       primary_detector: productkey.Win5x5
                                   tags: ['avid-effect:security:S0300', 'owasp:llm06', 'risk-cards:lmrc:providing_illegal_info', 'quality:Behavioral:ContentSafety:LegalGoodsServices']
                               mod_time: 2024-07-01 04:16:40 +0000

Here, we see a list of the descriptive parameters of the plugin. We can see
a link to documentation about it, which detectors it uses, tags describing
the probe in various typologies, which languages and modalities it supports, and more.

We can also see a ``DEFAULT_PARAMS`` entry. This is a dictionary containing
configurable parameters for this plugin. In this case, there's a ``generations``
parameter set to ``1``; this is the default value for ``probes``, but is often
overridden at run time by the CLI setup.

At plugin load, the plugin instance has attributes named in ``DEFAULT_PARAMS``
automatically created, and populated with either values given in the supplied
config, or the default.

Fixed plugin parameters
^^^^^^^^^^^^^^^^^^^^^^^

Some plugin parameters aren't intended to be altered at instantiation via config.
These are the fixed plugin parameters, and are generally those not given in ``DEFAULT_PARAMS``.
Descriptions of these are as follows (for a probe - other plugins are similar):

* ``description`` - A short description of what the plugin does
* ``active`` - Whether or not the plugin is active (i.e. selected) by default
* ``doc_uri`` - Link to more information about the plugin
* ``extended_detectors`` - Option detectors to use on probe results
* ``extra_dependency_names`` - Extra Python modules that garka should import when instantiatng the plugin
* ``goal`` - Brief description in imperative form of the probe's intent
* ``modality`` - Which modalities the probe supports (as of Nov 2024 the list is ``text``, ``image``, ``audio``, ``video``, ``3d``)
* ``parallelisable_attempts`` - Is the probe parallelisable? Recommended false if it has to use an LLM to develop attacks, particularly a local one
* ``primary_detector`` - What detector should be used on the probe's outputs?
* ``tags`` - List of tags applicable to the plugin, drawn from ``garak/data/tags.misp.tsv``
* ``mod_time`` - Modification timestamp of the plugin source file used to generate this data


.. _config_with_yaml:

Configuring Plugins with YAML
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Plugin config happens inside the ``plugins`` block. Multiple plugins can be
configured in the same YAML. Descend through this specifying plugin type,
model, and optionally class, and set variables in the end. These will then
be loaded as the plugin's ``DEFAULT_PARAMS`` attribute is parsed and used to
populate instance attributes.

Here's an example of setting the temperature on an OpenAIGenerator:

.. code-block:: yaml

    plugins:
        generators:
            openai:
                OpenAIGenerator:
                    temperature: 1.0

As noted the class is optional, if the configuration defines keys at the module level
these will be applied to the instance and can be overridden by the class level. Here
is an example that is equivalent to the configuration above:

.. code-block:: yaml

    plugins:
        generators:
            openai:
                temperature: 1.0

Example: RestGenerator
^^^^^^^^^^^^^^^^^^^^^^

RestGenerator is a slightly complex generator, though mostly because it exposes
so many config values, allowing flexible integrations. This example sets
``target_type: rest`` to ensure that this model is selected for the run; that might
not always be wanted, and it isn't compulsory.

RestGenerator with YAML
"""""""""""""""""""""""

.. code-block:: yaml

    plugins:
        target_type: rest
        generators:
            rest:
                RestGenerator:
                    uri: https://api.example.ai/v1/
                    key_env_var: EXAMPLE_KEY
                    headers: Authentication: $KEY
                    response_json_field: text
                    request_timeout: 60

This defines a REST endpoint where:

* The URI is https://api.example.ai/v1/
* The API key can be found in the ``EXAMPLE_KEY`` environment variable's value (if unspecified, `REST_API_KEY` is checked)
* The HTTP header ``"Authentication:"`` should be sent in every request, with the API key as its parameter
* The output is JSON and the top-level field ``text`` holds the model's response
* Wait up to 60 seconds before timing out (the generator will backoff and retry when this is reached)

.. _rest_generator_with_json:

RestGenerator config with JSON
""""""""""""""""""""""""""""""

.. code-block:: JSON

    {
        "rest": {
            "RestGenerator": {
                "name": "example service",
                "uri": "https://127.0.0.1/llm",
                "method": "post",
                "headers": {
                    "X-Authorization": "$KEY"
                },
                "req_template_json_object": {
                    "text": "$INPUT"
                },
                "response_json": true,
                "response_json_field": "text"
            }
        }
    }

This defines a REST endpoint where:

* The URI is https://127.0.0.1/llm
* We'll use HTTP `POST` on requests
* The HTTP header ``"X-Authorization:"`` should be sent in every request, with the API key as its parameter
* The request template is to be a JSON dict with one key, `text`, holding the prompt
* The output is JSON and the top-level field ``text`` holds the model's response


This should be written to a file, and the file's path passed on the command
line with `-G`.

Configuration in Code
---------------------

The preferred way to instantiate a plugin is using ``garak._plugins.load_plugin()``.
This function takes two parameters:

* ``name``, the plugin's package, module, and class - e.g. ``generator.test.Lipsum``
* (optional) ``config_root``, either garak._config or a dictionary of a config, beginning at a top-level plugin type.

``load_plugin()`` returns a configured instance of the requested plugin.

OpenAIGenerator Config with Dictionary
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    >>> import garak._plugins
    >>> c = {"generators":{"openai":{"OpenAIGenerator":{"seed":30,"name":"gpt-4"}}}}
    >>> garak._plugins.load_plugin("generators.openai.OpenAIGenerator", config_root=c)
    🦜 loading generator: OpenAI: gpt-4
    <garak.generators.openai.OpenAIGenerator object at 0x71bc97693d70>
