run.spec selection grammar
===========================


``garak/_spec.py`` implements the unified ``run.spec`` selection grammar: a
single internal ``Spec`` (a list of ``Selector`` with explicit polarity) that
both transports parse to.

* CLI string (comma separated), via ``parse_spec_string``
* config file form (YAML/JSON ``include``/``exclude`` lists), via ``parse_spec_file``

Selectors carry a category-prefixed plugin path (``probes.<module>[.<Class>]``,
``buffs.<module>[.<Class>]``), a probe filter (``tag:<prefix>``,
``tier:<N|name>``), an intent typology code (``intent:<code>``, or
``intent:*`` / ``intent:all`` for every intent), or the explicit
empty selection ``none`` / ``probes.none`` (distinct from an unspecified spec,
which defaults to ``probes.*``). A leading ``-`` excludes; ``tier:N`` is
inclusive ("log level": tiers ``1..N``).

``intent:`` is a separate selection axis consumed by the intent service, not a
plugin selection: it does not add or remove probes. When no ``intent:`` selector
is given, the configured default scope ``run.intent_spec`` (default ``S``, the
top-level *Safety* branch of the intent typology) is injected at resolve time. Typology expansion (child codes) and detectorless
filtering happen in the intent service, governed by the ``cas.*`` modifiers.

``garak/_spec.py`` covers the grammar: parsing and serialisation. Resolving a
``Spec`` to concrete plugin names (against active/tier/tag state) is done by
``garak._selection.resolve_spec``; the single plugin-path resolution core is
shared with the ``parse_plugin_spec`` adapter used for detectors.

See :doc:`configurable` for the user-facing grammar and examples.


Code
^^^^


garak._spec
-----------

.. automodule:: garak._spec
   :members:
   :undoc-members:
   :show-inheritance:
