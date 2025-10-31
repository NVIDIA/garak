# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0


"""Centralized intent service to support technique & intent probing."""


import logging
from typing import List

from garak import _config, _plugins
from garak.exception import GarakException, PluginConfigurationError

intentproviders = {}


def tasks() -> List[str]:
    """number of intent providers to deal with, minus the no-op one"""
    return ["intentservice"]


def enabled() -> bool:
    """are all requirements met for intent service to be enabled"""
    return True


def start_msg() -> str:
    """return a start message, assumes enabled"""
    return "🌐", "loading intent services: " + " ".join(tasks())


def _load_intentprovider(language_service: dict = {}) -> LangProvider:
    """Load a single intent provider based on the configuration provided."""
    pass

def load():
    """Loads all language providers defined in configuration and validate bi-directional support"""

    has_all_required = True
    # (test intent providers)
    if has_all_required:
        return has_all_required

    msg = f"Intent provision unsuccessful"
    logging.error(msg)
    raise GarakException(msg)


def get_langprovider(source: str, *, reverse: bool = False):
    """Provides a singleton runtime language provider consumed in probes and detectors.

    returns a single direction langprovider for the `_config.run.target_lang` to encapsulate target language outside plugins
    """
    load()
    return {}
