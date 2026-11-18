garak.probes.hyperparams
========================

Sweep inference parameters (temperature, Top P, Top K, etc.) across the prompts
of any existing garak probe, to surface configurations that produce an
unacceptably high rate of erroneous or unsafe outputs. Supports detection of
`CWE-1434 <https://cwe.mitre.org/data/definitions/1434.html>`_: Insecure Setting
of Generative AI/ML Model Inference Parameters.

The module contains a single probe class, ``HyperparamBasher``, which
can be pointed at any existing probe via the ``source_probe`` configuration
parameter. This means there is no need for a separate class per probe — any
active probe in the package can be used as a source directly from YAML config.

How it works
------------

1. ``HyperparamBasher`` loads prompts and inherits the detector from the
   ``source_probe`` at initialisation time.
2. Inference parameter combinations are built from ``param_space`` according to
   ``sweep_strategy`` (single-param or random).
3. On the first call to ``probe()``, every parameter in ``param_space`` is
   validated against the connected generator. If a parameter is not an attribute
   of the generator a ``PluginConfigurationError`` is raised immediately, so the
   configuration can be corrected rather than running a silent partial sweep.
4. Source probe compatibility:

   * **Works correctly** — any source probe that does not define a custom
     ``_generator_precall_hook``.  For source probes that define a custom
     ``_attempt_prestore_hook`` (e.g. ``continuation.*``, ``leakreplay.*``,
     ``latentinjection.*``, ``goodside.*``, ``propile.*``, ``web_injection.*``),
     that hook is chained so ``attempt.notes["triggers"]`` and other per-prompt
     data are populated correctly for the sweep.
   * **Rejected at initialisation** — probes that define a custom
     ``_generator_precall_hook`` (``promptinject.*``, ``divergence.Repeat``);
     a ``PluginConfigurationError`` is raised immediately.

5. Each completed attempt records the active parameter combination and the
   original generator values in ``attempt.notes``:

   * ``attempt.notes["hyperparam_combo"]`` — the params applied this attempt
   * ``attempt.notes["hyperparam_original"]`` — the pre-sweep original values

6. After the run completes, use ``garak.analyze.hyperparam_summary`` to
   produce a per-combo pass/fail table (see `Viewing results`_ below).

Generator compatibility
-----------------------

``openai.OpenAICompatible`` and its subclasses are the intended generator
target. These generators read instance attributes dynamically via
``inspect.signature`` when constructing API requests, so each
``setattr(generator, param, value)`` call reaches the wire.

Template-based generators such as ``rest.RestGenerator`` store the attribute
but never interpolate it into the request body — the sweep has no effect and
results are misleading. ``_validate_params_against_generator`` cannot detect
this because the attribute exists on the generator; it simply goes unused. A
``WARNING`` is emitted when the generator's MRO does not include
``OpenAICompatible`` so that results from such generators are not trusted
silently.

Viewing results
---------------

After a run completes, use the bundled analysis script to print a per-combo
attack success rate table:

.. code-block:: bash

    python -m garak.analyze.hyperparam_summary --report garak_runs/garak.<run_id>.report.jsonl

The script reads ``detector_results`` written by the harness and prints
output of the form::

    HyperparamBasher — per-combo detection summary:
      {'temperature': 0.0} → 2/10 failed (20% attack success rate)
      {'temperature': 1.5} → 7/10 failed (70% attack success rate)

The terminal also prints this command with the correct report path filled in
at the end of each probe run, so you can copy-paste it directly.

Parameters
----------

* ``source_probe`` — dotted probe name to sweep across, e.g.
  ``"packagehallucination.Python"`` or ``"snowball.GraphConnectivity"``
* ``param_space`` — dict mapping generator attribute names to lists of values,
  e.g. ``{"temperature": [0.0, 0.5, 1.0, 1.5, 2.0], "top_p": [0.1, 0.5, 1.0]}``
* ``sweep_strategy`` — ``"single"`` (vary one parameter at a time; default) or
  ``"random"`` (sample ``random_samples`` combinations drawn without replacement
  from the full Cartesian product of ``param_space`` values)
* ``random_samples`` — number of combinations to draw when strategy is
  ``"random"``
* ``random_seed`` — integer seed for reproducible random sweeps when strategy is
  ``"random"``; omit or set to ``null`` for non-deterministic behaviour (default)
* ``follow_prompt_cap`` — whether to cap prompts at ``soft_probe_prompt_cap``

Basic example: package hallucination sweep
------------------------------------------

.. code-block:: yaml

    plugins:
        probes:
            hyperparams:
                HyperparamBasher:
                    source_probe: packagehallucination.Python
                    param_space:
                        temperature: [0.0, 0.5, 1.0, 1.5, 2.0]
                        top_p: [0.1, 0.5, 0.9, 1.0]
                    sweep_strategy: single

Example: random sweep across lmrc.Bullying
------------------------------------------

.. code-block:: yaml

    plugins:
        probes:
            hyperparams:
                HyperparamBasher:
                    source_probe: lmrc.Bullying
                    param_space:
                        temperature: [0.0, 0.5, 1.0, 1.5, 2.0]
                        frequency_penalty: [0.0, 0.5, 1.0, 2.0]
                    sweep_strategy: random
                    random_samples: 20
                    random_seed: 42

.. automodule:: garak.probes.hyperparams
   :members:
   :undoc-members:
   :show-inheritance:

   .. show-asr::
