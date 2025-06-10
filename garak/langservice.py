# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0


"""Centralized language specific service to support plugins."""


import logging
from typing import List

from garak import _config, _plugins
from garak.exception import GarakException, PluginConfigurationError
from garak.langproviders.base import LangProvider
from garak.langproviders.local import Passthru

langproviders = {}
native_langprovider = None


def tasks() -> List[str]:
    """number of translators to deal with, minus the no-op one"""
    models_to_init = []
    for t in _config.run.langproviders:
        if t["model_type"] == "local.Passthru":  # extra guard
            continue
        model_descr = f"{t['language']}->{t['model_type']}"
        if "model_name" in t:
            model_descr += f"[{t['model_name']}]"
        models_to_init.append(model_descr)
    return models_to_init


def enabled() -> bool:
    """are all requirements met for language service to be enabled"""
    if hasattr(_config.run, "langproviders"):
        return len(_config.run.langproviders) > 1
    return False


def start_msg() -> str:
    """return a start message, assumes enabled"""
    return "🌐", "loading language services: " + " ".join(tasks())


def _load_langprovider(language_service: dict = {}) -> LangProvider:
    """Load a single language provider based on the configuration provided."""
    langprovider_instance = None
    langprovider_config = {
        "langproviders": {language_service["model_type"]: language_service}
    }
    logging.debug(f"langauge provision service: {language_service['language']}")
    source_lang, target_lang = language_service["language"].split(",")
    if source_lang == target_lang:
        return Passthru(langprovider_config)
    model_type = language_service["model_type"]
    try:
        langprovider_instance = _plugins.load_plugin(
            path=f"langproviders.{model_type}",
            config_root=langprovider_config,
        )
    except ValueError as e:
        raise PluginConfigurationError(
            f"Failed to load '{language_service['language']}' langprovider of type '{model_type}'"
        ) from e
    return langprovider_instance


def load():
    """Loads all language providers defined in configuration and validate bi-directional support"""
    global langproviders, native_langprovider
    if len(langproviders) > 0:
        return True

    run_target_lang = _config.run.target_lang

    for entry in _config.run.langproviders:
        # example _config.run.langproviders[0]['language']: en-ja classname encoding
        # results in key "en-ja" and expects a "ja-en" to match that is not always present
        langproviders[entry["language"]] = _load_langprovider(
            # TODO: align class naming for Configurable consistency
            language_service=entry
        )
    native_language = f"{run_target_lang},{run_target_lang}"
    if langproviders.get(native_language, None) is None:
        # provide a native language object when configuration does not provide one
        langproviders[native_language] = _load_langprovider(
            language_service={"language": native_language, "model_type": "local"}
        )
    native_langprovider = langproviders[native_language]
    # validate loaded language providers have forward and reverse entries
    has_all_required = True
    source_lang, target_lang = None, None
    for langprovider_key in langproviders.keys():
        source_lang, target_lang = langprovider_key.split(",")
        if langproviders.get(f"{target_lang},{source_lang}", None) is None:
            has_all_required = False
            break
    if has_all_required:
        return has_all_required

    msg = f"The language provision configuration provided is missing language: {target_lang},{source_lang}. Configuration must specify language providers for each required direction."
    logging.error(msg)
    raise GarakException(msg)


def get_langprovider(source: str, *, reverse: bool = False):
    """Provides a singleton runtime language provider consumed in probes and detectors.

    returns a single direction langprovider for the `_config.run.target_lang` to encapsulate target language outside plugins
    """
    load()
    dest = _config.run.target_lang if hasattr(_config.run, "target_lang") else "en"
    key = f"{source},{dest}" if not reverse else f"{dest},{source}"
    return langproviders.get(key, native_langprovider)
