Injectors
=========

Injector plugins occupy an interaction surface of a target and deliver
attack payloads through it, enabling indirect prompt injection testing.
An injector sits, for example, in front of the MCP servers a target
queries, and rewrites the tool results the target consumes.

The contract
------------

The extension axis is the **channel** (see :doc:`channels`): a catalog
id naming one place a payload can reach a target, with a trust level
and a delivery mode — ``conversation`` (the payload is part of the
Conversation), ``patch`` (the generator changes its own request), or
``out_of_band`` (an injector changes a data source; the generator does
nothing).

Surfaces come from the injector config, never from the scenario or the
generator: each names a channel, backend-owned endpoint data, and an
optional ``attach`` patch telling the generator how to route traffic
through the surface. Upstream endpoints live only here. The internal
surface keys are for logs and evidence; scenarios never refer to them.

An injector holds no per-execution state. ``Injector.validate()`` checks
that the injector can express a plan on a surface, and raises
``InvalidInjectionPlanError`` when it cannot. ``Injector.bind()``
occupies the surface for one execution and returns an
``InjectionBinding`` that owns its session, so one cached injector
instance can serve any number of probes or attempts in parallel.

A binding carries the ``target_patch`` a generator applies for its
generation (None for pure out-of-band surfaces), collects
``InjectionEvidence`` through ``collect_evidence()``, and releases the
surface through ``close()``, which is idempotent and never raises. A
binding with no operations relays traffic unchanged and records
evidence for control cases.

Generators declare the patch kinds they can apply through
``supported_patches`` and apply each handed patch or fail closed with
``UnsupportedInjectionError``. The generator does not know which
injections are available: the loaded injectors own that knowledge.

Selection and registry
----------------------

Injectors are selected with ``run.spec`` includes, like buffs; a config
block alone does not load an injector::

    run:
      spec:
        include:
          - probes.midojo.MidojoProbe
          - injectors.mimcp.MiMCPInjector

The run loads the selected injectors into a run-wide registry
(``_config.injectormanager``), which fails on duplicate internal surface
names and logs the exposed channels at startup. Probes query the
registry by channel and never name injector classes.

Writing an injector
-------------------

Subclass ``Injector``, declare the channels you can reach, and
implement ``validate()`` and ``bind()``:

.. code-block:: python

    class MyInjector(Injector):
        channels = frozenset({channels.TOOL_RESULT})


        def offered_surfaces(self):
            # parse the injector config into Surface objects
            return self._configured_surfaces


        def validate(self, plan, surface):
            super().validate(plan, surface)
            # reject operations this backend cannot express


        def bind(self, plan, surface, execution_id):
            return MyBinding(self, plan, surface, execution_id)

``bind()`` returns a binding, not a session handle: the binding owns
everything the execution needs, and maps whatever the backend records
onto the contract's ``ToolCallEvent`` records so detectors stay
backend-neutral.

Backends
--------

.. toctree::
   :maxdepth: 1

   injectors/base
   injectors/mimcp
   injectors/prompt
