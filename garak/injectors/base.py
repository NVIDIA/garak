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
from garak.injection import InjectionBinding, InjectionPlan, Surface


class Injector(Configurable):
    """Base class for an injector.

    An injector sits on an interaction surface of a target, for example
    the tool results of an MCP server the target queries. It declares the
    channels it can reach (catalog ids from ``garak.channels``) and the
    surfaces its config offers, each with its channel, its tool list, and
    an optional attach patch. ``bind()`` occupies a surface for one
    execution and returns a binding that owns its session, so injectors
    hold no per-execution state and one cached instance can serve any
    number of probes or attempts in parallel. ``validate()`` checks a
    plan against a surface before any execution; the binding's
    ``target_patch`` tells the generator how to route the target's
    traffic through the occupied surface, or None for pure out-of-band
    surfaces.
    """

    doc_uri = ""
    active = True
    # channel ids from garak.channels this injector can reach
    channels: frozenset[str] = frozenset()

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

    def offered_surfaces(self) -> tuple[Surface, ...]:
        """Return the surfaces this injector occupies from its config.

        Each surface carries its channel, the tool names it offers, its
        backend-owned endpoint data, and the patch a generator must apply
        to route traffic through it.
        """
        return ()

    def validate(self, plan: InjectionPlan, surface: Surface) -> None:
        """Check that this injector can express the plan on the surface.

        Raises ``InvalidInjectionPlanError`` when it cannot; subclasses
        extend this with the checks their channels require.
        """
        if plan.channel not in self.channels:
            raise InvalidInjectionPlanError(
                f"{self.fullname} cannot reach the {plan.channel} channel; "
                f"it supports {sorted(self.channels)}"
            )
        if surface.channel != plan.channel:
            raise InvalidInjectionPlanError(
                f"the plan targets the {plan.channel} channel but the surface "
                f"{surface.name!r} is on {surface.channel}"
            )
        if plan.surface is not None and plan.surface != surface.name:
            raise InvalidInjectionPlanError(
                f"the plan names surface {plan.surface!r} but the resolved "
                f"surface is {surface.name!r}"
            )

    def bind(
        self, plan: InjectionPlan, surface: Surface, execution_id: str
    ) -> InjectionBinding:
        """Occupy the surface for one execution and return its binding."""
        raise NotImplementedError
