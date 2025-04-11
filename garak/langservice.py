# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0


"""Centralized language specific service to support plugins."""


import logging
from garak import _config, _plugins

from garak.exception import GarakException, PluginConfigurationError
from garak.translators.base import Translator
from garak.translators.local import NullTranslator

translators = {}
native_translator = None


def _load_translator(translation_service: dict = {}) -> Translator:
    """Load a single translator based on the configuration provided."""
    translator_instance = None
    translator_config = {
        "translators": {translation_service["model_type"]: translation_service}
    }
    logging.debug(f"translation_service: {translation_service['language']}")
    source_lang, target_lang = translation_service["language"].split(",")
    if source_lang == target_lang:
        return NullTranslator(translator_config)
    model_type = translation_service["model_type"]
    try:
        translator_instance = _plugins.load_plugin(
            path=f"translators.{model_type}",
            config_root=translator_config,
        )
    except ValueError as e:
        raise PluginConfigurationError(
            f"Failed to load '{translation_service['language']}' translator of type '{model_type}'"
        ) from e
    return translator_instance


def load_translators():
    """Loads all translators defined in configuration and validate bi-directional support"""
    global translators, native_translator
    if len(translators) > 0:
        return True

    run_target_lang = _config.run.target_lang

    for entry in _config.run.translators:
        # example _config.run.translators[0]['language']: en-ja classname encoding
        # results in key "en-ja" and expects a "ja-en" to match that is not always present
        translators[entry["language"]] = _load_translator(
            # TODO: align class naming for Configurable consistency
            translation_service=entry
        )
    native_language = f"{run_target_lang},{run_target_lang}"
    if translators.get(native_language, None) is None:
        # provide a native language object when configuration does not provide one
        translators[native_language] = _load_translator(
            translation_service={"language": native_language, "model_type": "local"}
        )
    native_translator = translators[native_language]
    # validate loaded translators have forward and reverse entries
    has_all_required = True
    source_lang, target_lang = None, None
    for translator_key in translators.keys():
        source_lang, target_lang = translator_key.split(",")
        if translators.get(f"{target_lang},{source_lang}", None) is None:
            has_all_required = False
            break
    if has_all_required:
        return has_all_required

    msg = f"The translator configuration provided is missing language: {target_lang},{source_lang}. Configuration must specify translators for each direction."
    logging.error(msg)
    raise GarakException(msg)


def get_translator(source: str, *, reverse: bool = False):
    """Provides a singleton runtime translator consumed in probes and detectors.

    returns a single direction translator for the `_config.run.target_lang` to encapsulate target language outside plugins
    """
    load_translators()
    dest = _config.run.target_lang if hasattr(_config.run, "target_lang") else "en"
    key = f"{source},{dest}" if not reverse else f"{dest},{source}"
    return translators.get(key, native_translator)
