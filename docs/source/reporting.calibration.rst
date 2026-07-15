Calibration
===========


Are my scores good?
^^^^^^^^^^^^^^^^^^^

Garak scores are interpreted by comparing them with results from a bag of
state-of-the-art models. The surveyed results form a distribution of possible
garak scores. A target's pass rate is compared with the mean and
variation in that distribution to estimate how it performs relative to the
models in the bag.

What models are compared against?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following factors guide the composition of a calibration model bag:

* **Quantity** - There should be enough models in the bag to produce usable
  results and few enough to keep the calibration run tractable.
* **Recency** - Older models can give uncompetitive results, so recent models
  are preferred. Updating the bag too frequently, however, makes results
  harder to compare across garak runs.
* **Size** - The bag should include models with 1--10B, 11--99B, and 100B+
  parameters. Size is measured by parameter count regardless of quantisation.
* **Provider** - Provider diversity is preferred, with no more than two models
  per provider where practical.
* **Openness** - Open-weight models are preferred because they are easier to
  survey reproducibly.

The current model list and run configuration are maintained in
`garak/data/calibration/bag.csv <https://github.com/NVIDIA/garak/blob/main/garak/data/calibration/bag.csv>`_
and
`garak/configs/bag.yaml <https://github.com/NVIDIA/garak/blob/main/garak/configs/bag.yaml>`_.
Decimal and binary size categories are derived from the recorded parameter
count rather than maintained separately. Parameter counts use the developer's
published total; active or non-embedding counts are retained in the source
notes, and undisclosed counts are recorded as ``NA``. The exact report inputs
used to calculate a release, together with its model-bag identifier, are
recorded in the ``garak_calibration_meta`` section of its versioned
``calibration-*.json`` file and cross-checked against the model list. Retired
model lists and run configurations are frozen under
`garak/data/calibration/archive <https://github.com/NVIDIA/garak/tree/main/garak/data/calibration/archive>`_.
When report names distinguish reruns with a suffix, each suffix must form a
complete cohort covering the reused bag's canonical report paths. Partial
cohorts, path mismatches, and report-layout changes fail the documentation
build.
The reference below is generated from those sources during every documentation
build. Historical calibration files with a null bag identifier remain visible
with their recorded report inputs.

Z-scores
^^^^^^^^

Each probe and detector pair yields an attack success rate (ASR) and a pass
rate, where pass rate is ``1 - ASR``. Garak calculates the mean pass rate and
standard deviation across the models, together with the Shapiro-Wilk p-value
used to assess how closely the scores follow a normal distribution.

When assessing a target, garak calculates a Z-score. Positive Z-scores mean
better-than-average performance and negative Z-scores mean worse-than-average
performance. For a probe and detector combination, roughly two-thirds of the
models receive a Z-score between -1.0 and +1.0. The middle 10% score from
-0.125 to +0.125 and are labelled "competitive". A Z-score of +1.0 means the
target scored one standard deviation above the model-bag mean.

* Above +1: much better than average
* Around +0.1 to -0.1: average
* Below -1: much worse than average

A strong Z-score can accompany a low absolute pass rate when the whole bag
performs poorly. Likewise, a weak Z-score can accompany a high absolute pass
rate when the other models perform even better. Garak bounds standard
deviations at a non-zero minimum to represent the uncertainty of sampling only
part of the model landscape and to keep Z-score calculation possible when all
models in the bag agree.

Values in ``calibration.json`` are pass rates, not attack success rates. Mean
ASR is therefore ``1 - mean pass rate``.

Update cadence
^^^^^^^^^^^^^^

The first calibration was published in summer 2024. Updating the bag between
twice a year and quarterly balances model recency with the need to compare
results over time.

Current calibration
^^^^^^^^^^^^^^^^^^^

Generator-specific values such as ``max_tokens``, ``skip_seq_start``, and
``skip_seq_end`` may be combined with the canonical configuration when a target
system requires them.

.. calibration-data:: current

Calibration archive
^^^^^^^^^^^^^^^^^^^

Every versioned historical calibration is included automatically. Where a
frozen model list and run configuration are available, they are rendered with
the calibration metadata.

.. calibration-data:: archive
