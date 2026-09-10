garak.harnesses.probewise
=========================

The probewise harness normally runs probes alphabetically. It can instead use
calibration data from garak's bag of models to run probes with the highest
expected attack success rate first. Enable this with harness options:

.. code-block:: console

   garak --target_type test.Repeat \
     --spec probes.encoding.InjectAscii85,probes.encoding.InjectBase64 \
     --harness_options '{"probewise":{"probe_order":"calibration"}}'

Calibration files contain pass rates, so the harness converts each mean pass
rate to an attack success rate. When a probe has more than one calibrated
detector, ``calibration_aggregation`` selects ``max``, ``mean``, ``median``, or
``min`` aggregation. ``max`` is the default.

Probes absent from the calibration data receive ``uncalibrated_score`` (``1.0``
by default). This allows unknown probes to run first for discovery, last with a
score of ``0.0``, or between calibrated probes with an intermediate value. Set
``skip_uncalibrated_probes`` to ``true`` to omit and log them. A custom
calibration file can be selected with ``calibration_path``.

The same options can be provided in a YAML configuration file:

.. code-block:: yaml

   plugins:
     harnesses:
       probewise:
         probe_order: calibration
         calibration_aggregation: max
         uncalibrated_score: 1.0
         skip_uncalibrated_probes: false
         calibration_path:

.. automodule:: garak.harnesses.probewise
   :members:
   :undoc-members:
   :show-inheritance:
