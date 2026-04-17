Detectors
=========


Detectors classify responses into two categories:

- **hit**: A response exhibiting the failure mode the detector identifies (e.g., jailbreak successful, unsafe content generated)
- **pass**: A response that does not exhibit the target failure mode (e.g., request refused, safety maintained)

For detailed information on detector metrics and evaluation, see :doc:`../detector_metrics`.


.. toctree::
   :maxdepth: 2

   detectors/base
   detectors/always
   detectors/any
   detectors/ansiescape
   detectors/apikey
   detectors/continuation
   detectors/dan
   detectors/divergence
   detectors/encoding
   detectors/exploitation
   detectors/fileformats
   detectors/goodside
   detectors/judge
   detectors/knownbadsignatures
   detectors/leakreplay
   detectors/lmrc
   detectors/malwaregen
   detectors/misleading
   detectors/mitigation
   detectors/packagehallucination
   detectors/perspective
   detectors/promptinject
   detectors/productkey
   detectors/shields
   detectors/snowball
   detectors/unsafe_content
   detectors/visual_jailbreak
   detectors/web_injection
