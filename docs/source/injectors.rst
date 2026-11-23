Injectors
=========

Injector plugins occupy an interaction surface of a target and deliver
attack payloads through it, enabling indirect prompt injection testing.
An injector sits, for example, in front of the MCP servers a target
queries, and rewrites the tool results the target consumes.

The contract
------------

The extension axis is the **surface kind**: a namespaced string, for
example ``mcp.server``, that names one kind of interaction surface. Each
surface kind defines what its plans, routes, and operations mean.
Transport is an implementation detail of the injector and the generator.

An injector holds no per-execution state. ``Injector.validate()`` checks
that the injector can express a plan on a surface, and raises
``InvalidInjectionPlanError`` when it cannot. ``Injector.bind()``
occupies the surface for one execution and returns an
``InjectionBinding`` that owns its session, so one cached injector
instance can serve any number of probes or attempts in parallel.

A binding carries the ``route`` a generator applies for its generation,
collects ``InjectionEvidence`` through ``collect_evidence()``, and
releases the surface through ``close()``, which is idempotent and never
raises. Bindings work as context managers, so a generator exception
cannot leak a session.

Generators advertise the surfaces a target offers through
``Generator.injectable_surfaces()``; probes resolve a scenario case's
surface reference against that list before binding an injector to it.
A generator handed a route it cannot apply raises
``UnsupportedInjectionError``, so an unapplied injection is an
unsupported attempt, never a silently safe one.

The shared types live in :mod:`garak.injection`; the errors live in
:mod:`garak.exception`.

Writing an injector
-------------------

Subclass ``Injector``, declare the surface kinds you can occupy, and
implement ``validate()`` and ``bind()``:

.. code-block:: python

    class MyInjector(Injector):
        surface_kinds = frozenset({"my.kind"})


        def validate(self, plan, surface):
            super().validate(plan, surface)
            # reject operations this backend cannot express


        def bind(self, plan, surface, execution_id):
            return MyBinding(self, plan, surface, execution_id)

``bind()`` returns a binding, not a session handle: the binding owns
everything the execution needs, takes the upstream endpoint data from
the surface descriptor (never from the plan), and maps whatever the
backend records onto the contract's ``ToolCallEvent`` records so
detectors stay backend-neutral.

Backends
--------

.. toctree::
   :maxdepth: 1

   injectors/base
   injectors/mimcp
