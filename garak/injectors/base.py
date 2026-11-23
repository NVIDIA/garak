# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Base class for injectors.

An injector occupies an interaction surface of a target and delivers attack
payloads through it, enabling indirect prompt injection testing.
"""

import logging

from colorama import Fore, Style

from garak import _config
from garak.configurable import Configurable
from garak.exception import InvalidInjectionPlanError
from garak.injection import (
    InjectionBinding,
    InjectionEvidence,
    InjectionPlan,
    SurfaceDescriptor,
)


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
