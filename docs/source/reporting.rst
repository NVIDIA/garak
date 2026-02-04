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

Confidence Intervals (Optional)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Confidence intervals are disabled by default but can be enabled via the ``reporting.confidence_interval_method`` configuration parameter (see :doc:`configurable`). When enabled, eval entries may include bootstrap confidence intervals for attack success rates when sample size ≥ 30:

* ``confidence``: Confidence level (e.g., "0.95")
* ``confidence_lower``: Lower bound (0-1 scale)
* ``confidence_upper``: Upper bound (0-1 scale)

These intervals account for sampling uncertainty. When detector performance metrics (sensitivity/specificity) are available, they also account for detector imperfection. Otherwise, a perfect detector is assumed.

Recalculating Confidence Intervals
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For reports created before CI support or to experiment with different parameters, use the ``--rebuild_cis`` command:

.. code-block:: bash

   garak --rebuild_cis path/to/garak.uuid.report.jsonl

This reconstructs binary pass/fail outcomes from attempt records and recalculates CIs using current config settings. The report file is updated in-place with new CI values in eval entries.

To override config defaults:

.. code-block:: bash

   garak --rebuild_cis report.jsonl --bootstrap_num_iterations 50000 --bootstrap_confidence_level 0.99

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