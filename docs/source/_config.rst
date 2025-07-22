garak._config
=============


This module holds config values.

These are broken into the following major categories:

* system: options that don't affect the security assessment
* run: options that describe how a garak run will be conducted
* plugins: config for plugins (generators, probes, detectors, buffs)
* transient: internal values local to a single ``garak`` execution

Config values are loaded in the following priority (lowest-first):

* Plugin defaults in the code
* Core config: from ``garak/resources/garak.core.yaml``; not to be overridden
* Site config: from ``$HOME/.config/garak/garak.site.yaml``
* Runtime config: from an optional config file specified manually, via e.g. CLI parameter
* Command-line options


Code
^^^^


.. automodule:: garak._config
   :members:
   :undoc-members:
   :show-inheritance:
