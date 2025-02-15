# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0


""" Translator that translates a prompt. """


import logging
from garak import _config, _plugins

from garak.translators.base import Translator
from garak.translators.local import NullTranslator


def load_translator(
    translation_service: dict = {}, reverse: bool = False
) -> Translator:
    """Load a single translator based on the configuration provided."""
    translator_instance = None
    translator_config = {
        "translators": {translation_service["model_type"]: translation_service}
    }
    logging.debug(
        f"translation_service: {translation_service['language']} reverse: {reverse}"
    )
    source_lang, target_lang = translation_service["language"].split("-")
    if source_lang == target_lang:
        return NullTranslator(translator_config)
    model_type = translation_service["model_type"]
    translator_instance = _plugins.load_plugin(
        path=f"translators.{model_type}",
        config_root=translator_config,
    )
    return translator_instance


from garak import _config

translators = {}
native_translator = None


def load_translators():
    global translators, native_translator
    if len(translators) > 0:
        return True

    from garak.exception import GarakException

    run_target_lang = _config.run.lang_spec

    for entry in _config.run.translators:
        # example _config.run.translators[0]['language']: en-ja classname encoding
        # results in key "en-ja" and expects a "ja-en" to match that is not always present
        translators[entry["language"]] = load_translator(
            # TODO: align class naming for Configurable consistency
            translation_service=entry
        )
    native_language = f"{run_target_lang}-{run_target_lang}"
    if translators.get(native_language, None) is None:
        # provide a native language object when configuration does not provide one
        translators[native_language] = load_translator(
            translation_service={"language": native_language, "model_type": "local"}
        )
    native_translator = translators[native_language]
    # validate loaded translators have forward and reverse entries
    has_all_required = True
    source_lang, target_lang = None, None
    for translator_key in translators.keys():
        source_lang, target_lang = translator_key.split("-")
        if translators.get(f"{target_lang}-{source_lang}", None) is None:
            has_all_required = False
            break
    if has_all_required:
        return has_all_required

    msg = f"The translator configuration provided is missing language: {target_lang}-{source_lang}. Configuration must specify translators for each direction."
    logging.error(msg)
    raise GarakException(msg)


# TODO: Future iteration concerns, should this return a set of translators for all requested lang_spec targets?
# In the base case I expect most lang_spec values will target a single language however testing a multi-lingual aware model seems reasonable,
# to that end a translator from the source lang of the prompts to each target language seems reasonable however it is unclear where in the process
# the expansion should occur.
# * Should the harness process the probe for each target language in order?
# * Should the probe instantiation just generate prompts in all requested languages and attach the language under test to the prompt values?
# * Should we defer on multi-language runs and initially enforce a single value in `lang_spec` to avoid the need for attempts to know the target language?
def get_translator(source: str, reverse: bool = False):
    """Provider for runtime translator consumed in probes and detectors.

    initially returns a single direction translator for the first value in `lang_spec` to encapsulate target language outside plugins
    """
    load_translators()
    lang_spec = _config.run.lang_spec if hasattr(_config.run, "lang_spec") else "en"
    target_langs = lang_spec.split(",")
    returned_translators = []
    for dest in target_langs:
        key = f"{source}-{dest}" if not reverse else f"{dest}-{source}"
        translator = translators.get(key, None)
        if translator is not None:
            returned_translators.append(translator)
    # return only the first translator for now
    return (
        returned_translators[0] if len(returned_translators) > 0 else native_translator
    )
