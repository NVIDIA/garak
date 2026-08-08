# Garak calibration model bag

The calibration model-bag documentation now lives in the
[calibration reference](https://docs.garak.ai/en/latest/reporting.calibration.html).
This file remains as a stable destination for existing links.

The canonical current model list is [`bag.csv`](bag.csv), and its run
configuration is [`garak/configs/bag.yaml`](../../configs/bag.yaml).
[`calibration.json`](calibration.json) identifies the current versioned
calibration file. Its `garak_calibration_meta` section records the model-bag ID
and exact report inputs, which are cross-checked against `bag.csv` when the
documentation is built. Model rows retain a first-party source and use
published total parameter counts; undisclosed counts are `NA`.

When the current bag changes, the retiring `bag.csv` and run configuration are
frozen under [`archive/`](archive/). Report inputs and generated statistics
remain in the corresponding versioned `calibration-*.json` files in this
directory. The calibration reference discovers and renders these sources
during the documentation build; release-specific tables are not maintained by
hand.

Generate an official calibration with
`python -m garak.analyze.perf_stats --bag-id <bag-id> <reports...>` so the
machine-readable relationship is recorded at creation time. A calibration can
reuse an existing bag ID; the calibration that introduced a bag uses its own
release ID. When report names use a suffix to distinguish reruns, that suffix
must form a complete cohort covering every canonical report path in the reused
bag; partial or path-mismatched cohorts fail the documentation build. Use a
null bag only when no model-bag snapshot exists.
