garak.probes.doctor
===================

Doctor frame data
-----------------

The probe loads all YAML files under ``data/doctor``. User files in
``$XDG_DATA_HOME/garak/data/doctor`` take precedence over packaged files.

Each file declares a shared placeholder and one or more named frames:

.. code-block:: yaml

   placeholder: "{{HARMFUL_BEHAVIOR}}"
   frames:
     example:
       probe_variants: [standard]
       prompt: "Provide {{HARMFUL_BEHAVIOR}}"

Frame names must be unique, and all files must use the same placeholder. The
``frame_variants`` default parameter selects one or more variant groups and can
be overridden through probe configuration.

.. automodule:: garak.probes.doctor
   :members:
   :undoc-members:
   :show-inheritance:   

   .. show-asr::