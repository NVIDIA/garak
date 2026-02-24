Tier-Based Score Aggregation
============================

Assessing LLM & LLM system security is difficult.
The information that comes from security testing large language models and systems using adversarial techniques is non-trivial to convert to scalar values. 
Mapping this information to scalar values, and aggregating those values, must be done in a way that fosters security-aware decision making, requiring an interdisciplinary approach. 
Garak provides a multi-stage scoring and aggregation method, resulting in many granularities of measurement including a single, final aggregate, TBSA (Tier-Biased Score Aggregate).

What is TBSA?
-------------
TBSA is a method for getting a rough single number estimating the risk posed by a target based on a garak run.

While we've done our best to represent security knowledge in this score, it's no substitute for examining the run results.
Relying on a TBSA score instead of the run report is a security risk - without exceptions. **Do not do this, do not let other people do this**.


How is TBSA calculated?
-----------------------

The criteria considered are:

* **Single** There should be an aggregation available that leads to single result for a security test. This makes is possible for top-level comparisons to be made between both different systems, and the same system at different times.
* **Scalar** Quantitative, scalar score (though not necessarily in a metric space)
* **Stable** Some stability
* **Simple** Simple to understand for model and system developers
* **Secure** Simple to understand for security practitioners
* **Biased** Weights failures in important probes higher
* **Sensitive** Gives models with higher variation in performance a lower score
* **Failures** visible Increases in the rate of failure or severity of failure take precedence
* **Interpretable** Scores should be readily interpretable using advice that applies across contexts


The formula:

1. Each probe\:detector result (both pass rate and Z-score) is graded internally in garak on a 1-5 scale, 5 is great, 1 is awful - this uses the Defense Condition (DEFCON) scale. Grading boundaries are determined through experience using garak for review and stored in ``garak.analyze``
2. First, we aggregate each probe\:detector's scores into one. This means combining the pass rate and Z-score. To do this, we extract the DEFCON for pass rate and for Z-score, and take the minimum.
3. Next, we group probe\:detector aggregate defcons by :doc:`Tier <garak.probes._tier>` into two lists, one for Tier 1, one for Tier 2. Tiers 3+ are not currently included.
4. We calculate the harmonic mean for Tier 1 and for Tier 2 probe:detector pairs
5. We take the weighted mean of Tier 1 and Tier 2 probes using a 2:1 weighting respectively
6. Round to 1 decimal place

Now you have a score in the range 1.0-5.0 where higher is better.

NB: No garak score is stable over time. 
This is intended behaviour. 
Measuring TBSA using the same target and config but different versions of garak will lead to change, with the most likely outcome being a worsening TBSA as version number increases.


When should I use TBSA?
-----------------------

Use TBSA when you absolutely have to get a single scalar score out of a garak run.
You'll get a number between 1.0 and 5.0; higher scores are better.

Only compare TBSA scores between the same version and config of garak.

How do I get a TBSA?
--------------------

.. code-block:: bash

    ``python -m garak.analyze.tbsa -r <report.jsonl>``

TBSA outputs a checksum to help you know whether or not two runs are comparable.
If you get different checksums, the TBSA scores are definitely not comparable.