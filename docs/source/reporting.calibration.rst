Calibration
===========


Are my scores good?
^^^^^^^^^^^^^^^^^^^

Garak scores are interpreted by comparing them with results from a bag of
state-of-the-art models. The surveyed results form a distribution of possible
garak scores. A target model's pass rate is compared with the mean and
variation in that distribution to estimate how it performs relative to the
models in the bag.

What models are compared against?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following factors guide the composition of a calibration model bag:

* **Quantity** - The bag should contain enough models to produce usable results
  while keeping the calibration run tractable.
* **Recency** - Recent models keep the comparison relevant, but changing the
  bag too often makes results harder to compare across garak runs.
* **Size** - The bag should represent a range of parameter counts, regardless
  of quantisation.
* **Provider** - Provider diversity reduces the influence of any one model
  family.
* **Openness** - Open-weight models are preferred because they are easier to
  survey reproducibly.

The model list and run configuration for every published calibration are
archived as machine-readable CSV and YAML files in the
`calibration bag catalog <https://github.com/NVIDIA/garak/tree/main/garak/data/calibration/bags>`_.
The catalog's ``current`` field identifies the release used by
``calibration.json``.

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

Calibration archive
^^^^^^^^^^^^^^^^^^^

Winter 2026 (current)
---------------------

Generator-specific values for ``max_tokens``, ``skip_seq_start``, and
``skip_seq_end`` were combined with this configuration where required by the
target system.

.. csv-table:: Winter 2026 model bag
   :file: ../../garak/data/calibration/bags/2026-02/models.csv
   :header-rows: 1
   :widths: 13, 13, 18, 39, 17

.. literalinclude:: ../../garak/data/calibration/bags/2026-02/config.yaml
   :language: yaml
   :caption: Winter 2026 run configuration

Spring 2025
-----------

.. csv-table:: Spring 2025 model bag
   :file: ../../garak/data/calibration/bags/2025-05/models.csv
   :header-rows: 1
   :widths: 13, 13, 18, 39, 17

.. literalinclude:: ../../garak/data/calibration/bags/2025-05/config.yaml
   :language: yaml
   :caption: Spring 2025 run configuration

Summer 2024
-----------

Binary size categories were not recorded for this release.

.. csv-table:: Summer 2024 model bag
   :file: ../../garak/data/calibration/bags/2024-summer/models.csv
   :header-rows: 1
   :widths: 13, 13, 18, 39, 17

.. literalinclude:: ../../garak/data/calibration/bags/2024-summer/config.yaml
   :language: yaml
   :caption: Summer 2024 run configuration
