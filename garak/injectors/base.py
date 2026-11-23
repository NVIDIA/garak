# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Base class for injectors.

An injector occupies an interaction surface of a target and delivers attack
payloads through it, enabling indirect prompt injection testing.
"""

import logging
from typing import Union

from colorama import Fore, Style

from garak import _config
from garak.capabilities import Capability
from garak.configurable import Configurable
from garak.exception import InvalidInjectionPlanError
from garak.injection import InjectionEvidence, InjectionPlan, SurfaceDescriptor


class InjectionBinding:
    """One execution of an injection plan against one surface.

    A binding owns the session state for exactly one generation: ``route``
    is what the generator applies, ``collect_evidence()`` reports what the
    execution learned, and ``close()`` releases the surface. ``close()`` is
    idempotent and must never raise: cleanup failures are logged and
    recorded as coverage errors instead. Bindings work as context managers,
    so a generator exception cannot leak a session.
    """

    route: object = None

    def __init__(self) -> None:
        self._closed = False
        #: coverage problems learned during this execution; folded into
        #: the evidence by ``collect_evidence()``
        self.coverage_errors: list[str] = []

    def collect_evidence(self) -> InjectionEvidence:
        """Return the evidence this execution collected."""
        raise NotImplementedError

    def close(self) -> None:
        """Release the surface; safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        self._close()

    def _close(self) -> None:
        """Release the surface; subclass hook, runs at most once."""

    def __enter__(self) -> "InjectionBinding":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False


class Injector(Configurable):
    """Base class for an injector.

    An injector sits on an interaction surface of a target, for example
    the tool results of an MCP server the target queries. ``bind()``
    occupies the surface for one execution and returns a binding that
    owns its session, so injectors hold no per-execution state and one
    cached instance can serve any number of probes or attempts in
    parallel. ``validate()`` checks a plan against a surface before any
    execution; the binding's ``route`` tells the generator how to send
    the target's traffic through the occupied surface.
    """

    doc_uri = ""
    active = True
    # surface kinds this injector can occupy, matched against
    # Generator.injectable_surfaces()
    surface_kinds: frozenset[str] = frozenset()
    # capability members naming the surfaces this injector can occupy;
    # legacy of the arm/disarm path, pending probe migration
    capabilities: list[Capability] = []

    DEFAULT_PARAMS = {}

    def __init__(self, config_root=_config) -> None:
        self._load_config(config_root)
        module = self.__class__.__module__.replace("garak.injectors.", "")
        self.fullname = f"{module}.{self.__class__.__name__}"
        print(
            f"💉 loading {Style.BRIGHT}{Fore.LIGHTBLUE_EX}injector{Style.RESET_ALL}: {self.fullname}"
        )
        logging.info("injector init: %s", self)
        self._load_deps()

    def validate(self, plan: InjectionPlan, surface: SurfaceDescriptor) -> None:
        """Check that this injector can express the plan on the surface.

        Raises ``InvalidInjectionPlanError`` when it cannot; subclasses
        extend this with the checks their surface kind requires.
        """
        if plan.surface_kind not in self.surface_kinds:
            raise InvalidInjectionPlanError(
                f"{self.fullname} cannot occupy {plan.surface_kind} surfaces; "
                f"it supports {sorted(self.surface_kinds)}"
            )
        if surface.kind != plan.surface_kind or surface.name != plan.surface_name:
            raise InvalidInjectionPlanError(
                f"the plan targets {plan.surface_kind}/{plan.surface_name} "
                f"but the surface is {surface.kind}/{surface.name}"
            )

    def bind(
        self, plan: InjectionPlan, surface: SurfaceDescriptor, execution_id: str
    ) -> InjectionBinding:
        """Occupy the surface for one execution and return its binding."""
        raise NotImplementedError

    def arm(self, payload: Union[str, dict]) -> dict:
        """Prime the injector with an attack payload and return an injection
        descriptor.

        Legacy of the pre-binding flow: the payload reaches the target
        through the injector, and the returned descriptor tells a
        generator how to route its traffic through the armed surface.
        Subclasses must implement this and must not mutate the payload.
        """
        raise NotImplementedError

    def disarm(self) -> None:
        """Return the injector to its unarmed state between attempts.

        Legacy of the pre-binding flow: probes call this once a generation
        is complete so that later attempts do not inherit earlier payloads.
        """
        raise NotImplementedError

    def get_calls(self) -> list[dict]:
        """Return the calls recorded on the armed surface.

        Legacy of the pre-binding flow: bindings collect their own
        evidence through ``collect_evidence()``.
        """
        return []

    def get_status(self) -> dict:
        """Return the armed surface's status view, or an empty dict.

        Probes read this after a generation to record delivery coverage.
        Injectors without a status concept return nothing.
        """
        return {}
