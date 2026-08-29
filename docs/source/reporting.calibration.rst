Calibration
===========


Are my scores good?
^^^^^^^^^^^^^^^^^^^

Garak scores are interpreted compared to the state of the art.
Using a "bag" of models and the results across those, we calibrate scores based on how those models perform on various probes and detectors.
The scores we get from the surveyed models are used to get a distribution of possible garak scores.
When surveying a target model, its pass rate is compared to the average and variation we see across state of the art models in order to estimate how well the target model is doing.

What models are compared against?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We look for the following things when composing the model bag for calibrating garak results:

* **Quantity** - There should be enough models in the bag to get usable results, and few enough to make running the experiments tractable
* **Recency** - Older models can give uncompetitive results, so we want recent ones. On the other hand, updating the bag very frequently makes it hard to compare results between garak runs.
* **Size** - We want models over a variety of sizes. Size is measured in parameter count, regardless of quantisation, and we look for models with 1-10B, 11-99B, and 100B+ parameters.
* **Provider** - No more than two models in the bag from the same provider
* **Openness** - Open weights models are easiest for us to survey, so we prefer to use those

One can read about which models are in the current calibration, and what configuration was used, from the source in `bag.md <https://github.com/NVIDIA/garak/blob/main/garak/data/calibration/bag.md>`_.

Z-scores
^^^^^^^^

Each probe & detector pair yields an attack success rate / pass rate (pass rate = 1-ASR). We measure the pass rate for each of the detectors that each probe requests. We then calculate the mean pass rate and standard deviation across all the models, as well as the Shapiro-Wilk p-value to gauge how well the scores follow a normal distribution. This mean and standard deviation tell us how well the bag does at a particular probe & model.

When assessing a target, we calculate a "Z-score". Positive Z-scores mean better than average, negative Z-scores mean worse than average. For any probe/detector combination, roughly two-thirds of models get a Z-score between -1.0 and +1.0. The middle 10% of models score -0.125 to +0.125. This is labelled "competitive". A Z-score of +1.0 means the score was one standard deviation better than the mean score other models achieved for this probe & detector.

* Over +1: much better than average
* Around +0.1 to -0.1: average
* Below -1: much worse than average

It's possible to get a great Z-score and a low absolute score. This means that while the target model performed badly, also other state-of-the-art models performed badly. Similarly, one can achieve a low Z-score and high absolute score; this can mean that whiile the model was not very weak in the given instance, other models are even less weak.

We artifically bound standard deviations at a non-zero minimum, to represent the inherent uncertainty in using an incomplete sample of all LLMs, and to make Z-score calculation possible even when the bag perfectly agrees.
