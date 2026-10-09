Reporting
=========

By default, ``garak`` outputs:

* a JSONL file, with the name ``garak.<uuid>.report.jsonl``, that stores progress and outcomes from a scan
* an HTML report summarising scores
* a JSONL hit log, describing all the attempts from the run that were scored successful

For information on how detectors classify responses as hits or passes, and how detector performance is measured, see :doc:`detector_metrics`.

Report JSONL
------------

The report JSON consists of JSON rows. Each row has an ``entry_type`` field.
Different entry types have different other fields.
Attempt-type entries have uuid and status fields.
Status can be 0 (not sent to target), 1 (with target response but not evaluated), or 2 (with response and evaluation).
Eval-type entries are added after each probe/detector pair completes, and list the results used to compute the score.
When the probe is an ``IntentProbe`` (and therefore tags each attempt with an intent),
the corresponding ``eval`` entry also carries an optional ``intents`` field mapping
each intent name to its ``passed``, ``total_evaluated`` and ``nones`` counts
(``nones`` are unscoreable outputs, mirroring the top-level ``nones`` and excluded
from ``total_evaluated``).

The ``digest`` entry (added by ``report_digest``) carries a
``technique_intent_matrix`` field built from those ``eval`` ``intents`` counts: a
``technique -> intent`` cross-tab keyed on each probe's ``demon:*`` tags
(independent of ``reporting.taxonomy``). Each intent cell holds ``score``
(``passed / total_evaluated``, or ``null`` when ``total_evaluated`` is 0),
``passed``, ``total_evaluated``, ``nones`` and ``n_detectors``, plus a per-technique
``_summary`` of ``n_intents`` and ``n_detectors``. Counts are micro-averaged
(pooled) across contributing probes and detectors, so ``total_evaluated`` is an
evaluation count (attempt × detector). An intent whose outputs were all unscoreable
surfaces as ``0/0`` with ``nones`` > 0, signalling that the target never produced a
usable response for it.

.. seealso::

   :doc:`cas` for running intent-based scans and interpreting per-intent results.

Confidence Intervals (Optional)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Confidence intervals are enabled by default using the bootstrap method (see ``reporting.confidence_interval_method`` in :doc:`configurable`). Eval entries include bootstrap confidence intervals for attack success rates when sample size ≥ 30:

* ``confidence``: Confidence level (e.g., "0.95")
* ``confidence_lower``: Lower bound (0-1 scale)
* ``confidence_upper``: Upper bound (0-1 scale)

These intervals account for sampling uncertainty. When detector performance metrics (sensitivity/specificity) are available, they also account for detector imperfection. Otherwise, a perfect detector is assumed.

hit@k Attack Success Rate
^^^^^^^^^^^^^^^^^^^^^^^^^^

Pooled ASR reports the fraction of *all* generations that breach the target. That understates real risk: an attacker doesn't need the target to fail most of the time, only once, and can keep retrying. A jailbreak that succeeds on 1 reply in 5 is a working jailbreak, yet pooled ASR records it as a mild 20%.

``hit@k`` reframes the metric per prompt -- "given ``k`` attempts, does at least one breach the target?" -- and averages across prompts, following the pass@k estimator of Chen et al., `Evaluating Large Language Models Trained on Code <https://arxiv.org/abs/2107.03374>`_ (2021); it is named hit@k here because garak scores an attack success as a hit. ``hit@1`` recovers the familiar per-prompt success rate; larger ``k`` shows how fast a persistent attacker's odds climb.

Every prompt is always scored at ``k`` equal to the number of generations it actually got, so a run with ``run.generations: 5`` always reports ``hit@5``: with ``k`` at the full generation count the estimator collapses to "was this prompt breached at least once". ``reporting.hit_at_k`` (default ``[1]``) adds further k values below that. Set it to ``null`` to drop the metric entirely.

Each ``eval`` entry then carries a ``hit_at_k`` field:

.. code-block:: json

   "hit_at_k": {"1": {"score": 0.2, "prompts": 5}, "5": {"score": 1.0, "prompts": 5}}

Each entry holds ``score`` (mean hit@k over prompts, on a 0-1 scale) and ``prompts`` (how many prompts were eligible). A prompt with fewer than ``k`` scoreable generations cannot be estimated for that ``k`` and is excluded from that entry; a ``k`` with no eligible prompt is omitted. Where prompts got differing numbers of generations, as in probes that end conversations early, the always-on entry is keyed ``n`` rather than an integer and covers every prompt at its own generation count.

The same figures follow the attack success rate in the CLI summary, e.g. ``hit@1: 20.00%  hit@5: 100.00%``, and are copied into each detector's entry in the ``digest`` object written to the report, next to ``total_evaluated`` and ``passed``. Note that the digest's ``absolute_score`` is a pass rate while ``hit_at_k`` scores are hit rates.

Recalculating Confidence Intervals
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For reports created before CI support or to experiment with different parameters, use the standalone ``rebuild_cis`` tool:

.. code-block:: bash

   python -m garak.analyze.rebuild_cis -r path/to/garak.uuid.report.jsonl

By default, this writes the rebuilt report to a new file (e.g. ``garak.uuid.rebuilt.report.jsonl``) without modifying the original. To overwrite the original report in-place, use the ``-w`` flag:

.. code-block:: bash

   python -m garak.analyze.rebuild_cis -r path/to/report.jsonl -w

To write to a specific output path:

.. code-block:: bash

   python -m garak.analyze.rebuild_cis -r path/to/report.jsonl -o path/to/rebuilt.jsonl

To override bootstrap config defaults:

.. code-block:: bash

   python -m garak.analyze.rebuild_cis -r report.jsonl --bootstrap_num_iterations 50000 --bootstrap_confidence_level 0.99

.. note::

   ``rebuild_cis`` updates only the JSONL report file. To regenerate the HTML report
   after recalculating CIs, run ``digest_report`` separately:

   .. code-block:: bash

      python -m garak.analyze.report_digest -r path/to/report.jsonl -o path/to/report.html

Report HTML
-----------

The report HTML presents core items from the run.
Runs are broken down into:

1. modules/taxonomy entries
2. probes within those categories
3. detectors for each probe

Results given are both absolute and relative.

During console output, attack success rates may include confidence intervals displayed as: ``(attack success rate: 45.23% [40.50%, 50.30%])``.
The bracketed values show the lower and upper bounds of the requested (default 95%) confidence interval as percentages, preserving the asymmetry of the bootstrap distribution.
The relative ones are in terms of a Z-score computed against a set of recently tested other models and systems.
For Z-scores, 0 is average, negative is worse, positive is better.
Both absolute and relative scores are placed into one of five grades, ranging from 1 (worst) to 5 (best).
This scale follows the NORAD DEFCON categorisation (with less dire consequences).
Bounds for these categories are developed over many runs.
The absolute scores are only alarming or reassuring for very poor or very good Z-scores.
The relative scores assume the middle 10% is average, the bottom 15% is terrible, and the top 15% is great.

DEFCON scores are aggregated using a minimum, to avoid obscuring important failures.

.. toctree::
   :maxdepth: 2

   reporting.calibration