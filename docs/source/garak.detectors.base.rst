garak.detectors.base
====================

This class defines the basic structure of garak's detectors. All detectors inherit from ``garak.detectors.base.Detector``.

Hits and Passes
---------------

Detectors classify responses into two categories:

- **hit**: A response exhibiting the failure mode the detector identifies (e.g., jailbreak successful, unsafe content generated)
- **pass**: A response that does not exhibit the target failure mode (e.g., request refused, safety maintained)

For detailed information on detector metrics and evaluation, see :doc:`detector_metrics`.

Attributes
----------

1. **doc_uri**   URI for documentation of the detector (perhaps a paper)
1. **lang_spec**    Language this is for. format: a comma-separated list of BCP47 tags, or "*" for any or not applicable. Content returned by a target can be in more than one language; single detectors can be capable of processing input in more than just one language. This field tracks which ones are supported. NB this is different from probe, which is monolingual and uses ``lang``.
1. **active**    Should this detector be used by default?
1. **tags** MISP-format taxonomy categories
1. **modality**  Which modalities does this detector work on? ``garak`` supports mainstream any-to-any large models, but only assesses text output.


.. automodule:: garak.detectors.base
   :members:
   :undoc-members:
   :show-inheritance:
