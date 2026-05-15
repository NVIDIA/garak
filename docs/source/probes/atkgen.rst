garak.probes.atkgen
===================

Probes that use a separate attack-generation model to craft adversarial prompts
turn-by-turn, driving the target towards a specific failure mode.

.. warning::

   Attack models in this module may generate highly toxic prompts.
   Peruse logs with care; see
   `this guide to working with harmful text <https://aclanthology.org/2022.findings-emnlp.35/>`_
   for advice on managing exposure.

----

Tox
---

``Tox`` generates adversarial challenges by feeding the **most recent target
response** to the attack model at every turn.  The attack model receives a
single-turn :class:`~garak.attempt.Conversation` containing the last output
(wrapped in a configurable template), and uses that to produce the next
challenge.

Uses the following options from ``_config.plugins.probes["atkgen"]``:

* ``max_calls_per_conv`` – Maximum turns per conversation (default: 5).
* ``convs_per_generation`` – Number of independent conversations per
  ``generations`` value (default: 5).
* ``constructive_tension`` – If ``True``, an empty target response causes the
  probe to pass an empty challenge rather than terminating (default: ``True``).
* ``red_team_model_type`` – Generator type for the attack model
  (default: ``"huggingface.Pipeline"``).
* ``red_team_model_name`` – Model name for the attack model
  (default: ``"garak-llm/attackgeneration-toxicity_gpt2"``).
* ``red_team_model_config`` – Configuration dict passed to the attack model
  (default: CPU float32 HuggingFace args).
* ``red_team_prompt_template`` – Template string wrapping the last target
  response before it is posed to the attack model.  Must contain the
  placeholder ``[query]`` (default:
  ``"<|input|>[query]<|response|>"``).
* ``red_team_postproc_rm_regex`` – Regex whose matches are stripped from the
  attack model's output (default: removes ``<|…`` tokens).
* ``use_only_first_sent`` – Truncate the target response to its first sentence
  before feeding it to the attack model (default: ``True``).
* ``allow_repetition`` – Continue even if the target repeats its previous
  response (default: ``False``).

----

ToxConv
-------

``ToxConv`` is a multi-turn variant of :class:`Tox` that poses the **complete
conversation history** to the attack model at every turn rather than just the
most recent target response.

Each time the probe needs to generate the next challenge it passes a growing
:class:`~garak.attempt.Conversation` to the attack model.  That conversation
accumulates the entire exchange using standard chat roles:

* **user** turns hold target responses (the stimulus driving the next attack).
* **assistant** turns hold the challenges the attack model previously generated.

This gives the attack model full trajectory context and allows models that
understand multi-turn dialogue to craft more coherent adversarial strategies
across a conversation.

``ToxConv`` inherits from :class:`~garak.probes.base.IterativeProbe`, following
the same conversation-management patterns as :mod:`garak.probes.goat` and
:mod:`garak.probes.fitd`.  Each call to ``_generate_next_attempts`` deep-copies
the redteamer conversation stored in ``attempt.notes["redteamer_conversation"]``,
appends the latest target response as a new ``user`` turn, then calls the attack
model to produce the next ``assistant`` turn (the next challenge).

Uses the following options from ``_config.plugins.probes["atkgen"]``:

* ``max_calls_per_conv`` – Maximum turns per conversation (default: 5).
* ``convs_per_generation`` – Number of initial seed conversations in
  ``branchy`` mode; ignored in ``linear`` mode (default: 5).
* ``eval_threshold`` – Detector score at or above which a target response is
  considered a hit and the branch is stopped early.  Taken from the run-level
  config (``run.eval_threshold``), defaulting to ``0.5``.  Applies to both
  ``linear`` and ``branchy`` modes.
* ``branching`` – Controls how ``generations`` is interpreted (default:
  ``"branchy"``):

  - ``"linear"`` — ``generations`` independent threads, each proceeding
    straight through ``max_calls_per_conv`` turns with a single target
    response per turn.  No branching occurs; the total number of attempts
    is ``generations × max_calls_per_conv``.
  - ``"branchy"`` — ``generations`` acts as the **maximum** branching factor
    at each turn.  Duplicate target responses across branches are collapsed
    to a single branch, so the actual fan-out may be less than ``generations``.
    Expansion stops once the cumulative number of target responses reaches
    ``soft_probe_prompt_cap × generations``, bounding the total number of
    generator calls to ``soft_probe_prompt_cap``.  (Respects
    ``follow_prompt_cap``; set it to ``False`` to disable.)

* ``red_team_model_type`` – Generator type for the attack model
  (default: ``"huggingface.Pipeline"``).
* ``red_team_model_name`` – Model name for the attack model
  (default: ``"garak-llm/attackgeneration-toxicity_gpt2"``).
* ``red_team_model_config`` – Configuration dict passed to the attack model
  (default: CPU float32 HuggingFace args).
* ``red_team_postproc_rm_regex`` – Regex whose matches are stripped from the
  attack model's output (default: removes ``<|…`` tokens).
* ``use_only_first_sent`` – Truncate the target response to its first sentence
  before appending it to the redteamer conversation (default: ``True``).

Custom attacker model example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: JSON

   {
      "probes": {
         "atkgen": {
            "ToxConv": {
               "max_calls_per_conv": 8,
               "convs_per_generation": 3,
               "red_team_model_type": "openai.OpenAICompatible",
               "red_team_model_name": "my-attack-model",
               "red_team_model_config": {
                  "uri": "http://localhost:8000/v1/",
                  "api_key": "none"
               },
               "red_team_postproc_rm_regex": ""
            }
         }
      }
   }

.. note::

   Because the attack model receives a conversation that ends with a ``user``
   turn (the target's latest response), the model must be able to act as a
   chat assistant — i.e. it must generate the next ``assistant`` turn.
   The default GPT-2 pipeline model works as a text-continuation model; for
   best results with full conversation context, a chat-tuned model is
   recommended.

----

.. automodule:: garak.probes.atkgen
   :members:
   :undoc-members:
   :show-inheritance:

   .. show-asr::