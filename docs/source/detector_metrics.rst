Detector Quality Metrics
========================

Detectors in garak attempt to identify specific failure modes in model outputs. To assess detector performance, they must be evaluated against labeled benchmark datasets where the ground truth is known. This evaluation process measures how accurately each detector identifies its target failure mode.

This document explains how detectors are evaluated and ranked using F1 scores and related metrics. These measurements help assess detector quality, identify areas for improvement, and guide users in understanding detector reliability. For more information on how detectors work within garak, see :doc:`detectors` and :doc:`basic`.

What Are Hits and Passes?
-------------------------

Detector evaluation uses labeled ground truth datasets where model responses are classified into one of two categories based on whether the detector's target failure mode is present:

- **Hit**: A response exhibiting the failure mode the detector attempts to identify. This represents a case where the model demonstrated the problematic behavior, such as complying with a jailbreak attempt or generating unsafe content.

- **Pass**: A response that does not exhibit the target failure mode. This represents a case where the model behaved appropriately, such as refusing a harmful request or maintaining safety constraints.

**Example:**

- Testing a ``dan.DAN`` detector that catches jailbreak attempts
- **Hit**: "[DAN] Sure, I can help you with that. Here's how to..." (contains [DAN] marker, jailbreak successful)
- **Pass**: "I cannot assist with that request as it violates my guidelines." (no [DAN] marker, safety maintained)

Core Metrics
------------

Precision (hit_precision)
~~~~~~~~~~~~~~~~~~~~~~~~~

**Definition:** The proportion of responses a detector labels as a hit that are actual hits.

**Interpretation:** High precision indicates fewer false positives. A detector with high precision reliably identifies problematic behavior when it flags a response.

**Formula:** ``precision = TP / (TP + FP)``

Where:
- TP (True Positives): Correctly identified hits
- FP (False Positives): Incorrectly flagged passes

Recall (hit_recall)
~~~~~~~~~~~~~~~~~~~

**Definition:** The proportion of actual hits in the dataset that the detector successfully identifies.

**Interpretation:** High recall indicates fewer false negatives. A detector with high recall successfully identifies most instances of the target failure mode.

**Formula:** ``recall = TP / (TP + FN)``

Where:
- TP (True Positives): Correctly identified hits
- FN (False Negatives): Missed hits that were not flagged

F1 Score (hit_f1)
~~~~~~~~~~~~~~~~~

**Definition:** The harmonic mean of precision and recall, providing a balanced measure that gives equal weight to both metrics.

**Purpose:** F1 score serves as the primary ranking metric for detectors because:

- Precision alone is insufficient (detectors with low recall may have high precision but fail to identify most failure mode instances)
- Recall alone is insufficient (detectors with low precision may have high recall but generate excessive false positives)
- F1 provides a single balanced metric that accounts for both precision and recall performance

**Formula:** ``F1 = 2 × (precision × recall) / (precision + recall)``

**Range:** F1 scores range from 0.0 (worst) to 1.0 (perfect)

How Detectors Are Ranked
------------------------

Detectors are ranked by their ``hit_f1`` score, from highest to lowest. A higher F1 score means better overall performance at detecting problematic behavior.

Not all detectors have been evaluated against labeled benchmark datasets. Detectors without evaluation scores are not included in rankings. Additionally, F1 scores may not be meaningful for all detector types. For example, string matching detectors like ``dan.DAN`` that search for specific markers (e.g., "[DAN]") in responses have deterministic behavior. For these detectors, the metric may not indicate a problem with the detector itself given its current design, but rather may reveal opportunities for detector evolution. Hit samples that lack the expected patterns suggest scenarios the detector does not currently cover, indicating that enhanced detection logic could identify more instances of the failure mode.

Performance Tiers
~~~~~~~~~~~~~~~~~

Detectors are categorized into performance tiers based on their F1 scores:

- **Excellent** (F1 > 0.8)
- **Good** (0.6 < F1 ≤ 0.8)
- **Moderate** (0.4 < F1 ≤ 0.6)
- **Poor** (0.2 < F1 ≤ 0.4)
- **Critical** (F1 ≤ 0.2)

These tiers facilitate detector performance assessment and identification of improvement areas. Optimal detector selection for specific use cases may prioritize precision (minimizing false positives) or recall (minimizing false negatives), though F1 score provides a balanced effectiveness measure.

Accessing Detector Metrics
--------------------------

Detector evaluation metrics are stored in a JSON file located at::

    data/detectors-eval/detector_metrics_summary.json

This file is updated when detector evaluations are performed against labeled benchmark datasets.

Metrics File Structure
~~~~~~~~~~~~~~~~~~~~~~

The JSON file contains the following structure:

.. code-block:: json

    {
      "results": {
        "module_name.DetectorClass": {
          "metrics": {
            "accuracy": 0.85,
            "hit_precision": 0.80,
            "hit_recall": 0.90,
            "hit_f1": 0.85,
            "pass_precision": 0.88,
            "pass_recall": 0.75,
            "pass_f1": 0.81,
            "hit_f1_ci": {
              "mean": 0.85,
              "ci_lower": 0.78,
              "ci_upper": 0.91,
              "ci_width": 0.13,
              "n_samples": 100
            },
            "pass_f1_ci": {
              "mean": 0.81,
              "ci_lower": 0.74,
              "ci_upper": 0.87,
              "ci_width": 0.13,
              "n_samples": 100
            }
          }
        }
      },
      "metadata": {
        "evaluation_date": "2026-01-19T12:00:00.000000",
        "random_seed": 42,
        "balance_datasets": false,
        "save_datasets": false,
        "num_detectors_evaluated": 38,
        "errors": []
      }
    }

Key Fields
~~~~~~~~~~

- **results**: Contains metrics for each evaluated detector, keyed by detector module and class name
- **metrics**: Core performance metrics including precision, recall, and F1 scores for both hits and passes
- **hit_f1_ci** / **pass_f1_ci**: Optional confidence intervals for F1 scores. Only present when sufficient samples (≥50) are available. See :ref:`Confidence Intervals` section for field details.
- **metadata**: Evaluation metadata including date, random seed, dataset configuration, and any errors encountered

The primary ranking metric is ``hit_f1`` under each detector's metrics.

.. _Confidence Intervals:

Confidence Intervals
--------------------

To assess the statistical reliability of F1 scores, confidence intervals are computed using **stratified bootstrap resampling** with 10,000 replicates. For more information, see `Bootstrap (statistics) on Wikipedia <https://en.wikipedia.org/wiki/Bootstrap_(statistics)>`_.

How Bootstrap Resampling Works
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Stratified sampling**: For each bootstrap iteration, samples are drawn with replacement separately from the "hit" class predictions and "pass" class predictions. This preserves the original class balance, which is crucial for imbalanced datasets.

2. **F1 calculation per replicate**: For each of the 10,000 bootstrap samples, precision and recall are calculated, and combined into F1 using the formula ``F1 = 2 × (precision × recall) / (precision + recall)``.

3. **Percentile method**: After generating 10,000 F1 values through this process, confidence interval bounds are determined using the percentile method. For a 95% confidence level, the lower bound (``ci_lower``) is the 2.5th percentile and the upper bound (``ci_upper``) is the 97.5th percentile of the bootstrap distribution.

This non-parametric approach makes no assumptions about the underlying distribution of F1 scores. A minimum of 50 total samples is required for confidence interval computation.

Confidence Interval Fields
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The confidence interval objects contain the following fields:

- **ci_lower** and **ci_upper**: The 95% confidence interval bounds indicating the range where the true F1 score likely falls
- **ci_width**: The interval width (``ci_upper - ci_lower``); narrower intervals indicate more precise estimates
- **n_samples**: The number of evaluation samples used; larger sample sizes typically produce narrower confidence intervals
