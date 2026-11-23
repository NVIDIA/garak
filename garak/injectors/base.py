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


class Injector(Configurable):
    """Base class for an injector.

    An injector sits on an interaction surface (a capability) of a target,
    for example the tool results of an MCP server the target queries. Probes
    arm an injector with a payload before a generation, hand the returned
    injection descriptor to the generator, and disarm the injector afterwards.
    The generator decides whether it can use the injection; matching happens
    on capability names advertised by ``Generator.list_capabilities``.
    """

    doc_uri = ""
    active = True
    # capability members naming the surfaces this injector can occupy,
    # matched against Generator.list_capabilities()
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

    def arm(self, payload: Union[str, dict]) -> dict:
        """Prime the injector with an attack payload and return an injection
        descriptor.

        The descriptor is a plain dict telling a generator how to route its
        traffic through the armed surface, for example the URL of a fake MCP
        server. Generators ignore descriptors whose capability they do not
        support. The payload reaches the target through the injector, not
        through the returned descriptor.

        Subclasses must implement this and must not mutate the payload.
        """
        raise NotImplementedError

    def disarm(self) -> None:
        """Return the injector to its unarmed state between attempts.

        Probes call this once a generation is complete so that later attempts
        do not inherit earlier payloads.
        """
        raise NotImplementedError

    def get_status(self) -> dict:
        """Return the armed surface's status view, or an empty dict.

        Probes read this after a generation to record delivery coverage.
        Injectors without a status concept return nothing.
        """
        return {}
