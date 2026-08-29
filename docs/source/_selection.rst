run.spec resolution
===================


``garak/_selection.py`` resolves a ``run.spec`` selection against the plugin
registry. The grammar (parsing and serialisation) lives in :doc:`_spec`; this
module turns a ``Spec`` into concrete probe and buff names using the
active/tier/tag state from ``garak._plugins``.

``resolve_spec`` is the single entry point used by the CLI and harnesses; the
same plugin-path resolution core backs the ``parse_plugin_spec`` adapter used
for detectors.

See :doc:`configurable` for the user-facing grammar and examples, and :doc:`cas`
for the intent selection axis (``intent:``) that ``resolve_spec`` collects.


Code
^^^^


garak._selection
----------------

.. automodule:: garak._selection
   :members:
   :undoc-members:
   :show-inheritance:
