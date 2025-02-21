# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import pathlib
import tempfile
import os

from garak import _config, _plugins


NON_PROMPT_PROBES = [
    "probes.dan.AutoDAN",
    "probes.tap.TAP",
    "probes.suffix.BEAST",
    "probes.suffix.GCG",
]
ATKGEN_PROMPT_PROBES = ["probes.atkgen.Tox"]
VISUAL_PROBES = [
    "probes.visual_jailbreak.FigStep",
    "probes.visual_jailbreak.FigStepTiny",
]
PROBES = [
    classname
    for (classname, _) in _plugins.enumerate_plugins("probes")
    if classname not in NON_PROMPT_PROBES
    and classname not in VISUAL_PROBES
    and classname not in ATKGEN_PROMPT_PROBES
]
openai_api_key_missing = not os.getenv("OPENAI_API_KEY")


@pytest.fixture(autouse=True)
def probe_pre_req(classname):
    # this sets up config for probes that access _config still
    _config.run.seed = 42
    local_config_path = str(
        pathlib.Path(__file__).parents[1] / "test_config" / "translation_local_low.yaml"
    )
    if os.path.exists(local_config_path) is False:
        pytest.skip("Local config file does not exist, skipping test.")
    _config.load_config(run_config_filename=local_config_path)
    # detectors run by probes write to the report file
    temp_report_file = tempfile.NamedTemporaryFile(mode="w+", delete=False)
    _config.transient.reportfile = temp_report_file
    _config.transient.report_filename = temp_report_file.name

    # since this does not go through cli generations must be set
    _, module, klass = classname.split(".")
    _config.plugins.probes[module][klass]["generations"] = 1


"""
Skip probes.tap.PAIR because it needs openai api key and large gpu resource
"""


@pytest.mark.parametrize("classname", ATKGEN_PROMPT_PROBES)
def test_atkgen_probe_translation(classname, mocker):
    # how can tests for atkgen probes be expanded to ensure translation is called?
    import garak.translator
    import garak.translators.base
    from garak.translators.local import NullTranslator

    null_translator = NullTranslator(
        {
            "translators": {
                "local": {
                    "language": "en-en",
                }
            }
        }
    )

    mocker.patch.object(
        garak.translator, "get_translator", return_value=null_translator
    )

    prompt_mock = mocker.patch.object(
        null_translator,
        "translate_prompts",
        wraps=null_translator.translate_prompts,
    )

    descr_mock = mocker.patch.object(
        null_translator,
        "translate_descr",
        wraps=null_translator.translate_descr,
    )

    probe_instance = _plugins.load_plugin(classname)

    if probe_instance.bcp47 != "en" or classname == "probes.tap.PAIR":
        return

    generator_instance = _plugins.load_plugin("generators.test.Repeat")

    probe_instance.probe(generator_instance)

    expected_translation_calls = 1
    if hasattr(probe_instance, "triggers"):
        # increase prompt calls by 1 or if triggers are lists by the len of triggers
        if isinstance(probe_instance.triggers[0], list):
            expected_translation_calls += len(probe_instance.triggers)
        else:
            expected_translation_calls += 1

    if hasattr(probe_instance, "attempt_descrs"):
        # this only exists in goodside should it be standardized in some way?
        descr_mock.assert_called_once()
        expected_translation_calls += len(probe_instance.attempt_descrs) * 2

    assert prompt_mock.call_count == expected_translation_calls


@pytest.mark.parametrize("classname", PROBES)
def test_probe_prompt_translation(classname, mocker):
    # instead of active translation this just checks that translation is called.
    # for instance if there are triggers ensure `translate_prompts` is called at least twice
    # if the triggers are a list call for each list then call for all actual `prompts`

    # initial translation is front loaded on __init__ of a probe for triggers, simple validation
    # of calls for translation should be sufficient as a unit test on all probes that follow
    # this standard pattern. Any probe that needs to call translation more than once during probing
    # should have a unique validation that translation is called in the correct runtime stage

    import garak.translator
    import garak.translators.base
    from garak.translators.local import NullTranslator

    null_translator = NullTranslator(
        {
            "translators": {
                "local": {
                    "language": "en-ja",
                    # Note: differing source and target language pair here forces translator calls
                }
            }
        }
    )

    mocker.patch.object(
        garak.translator, "get_translator", return_value=null_translator
    )

    prompt_mock = mocker.patch.object(
        null_translator,
        "translate_prompts",
        wraps=null_translator.translate_prompts,
    )

    descr_mock = mocker.patch.object(
        null_translator,
        "translate_descr",
        wraps=null_translator.translate_descr,
    )

    probe_instance = _plugins.load_plugin(classname)

    if probe_instance.bcp47 != "en" or classname == "probes.tap.PAIR":
        pytest.skip("Probe does not engage with translation")

    generator_instance = _plugins.load_plugin("generators.test.Repeat")

    probe_instance.probe(generator_instance)

    expected_translation_calls = len(probe_instance.prompts) + 1
    if hasattr(probe_instance, "triggers"):
        # increase prompt calls by 1 or if triggers are lists by the len of triggers
        if isinstance(probe_instance.triggers[0], list):
            expected_translation_calls += len(probe_instance.triggers)
        else:
            expected_translation_calls += 1

    if hasattr(probe_instance, "attempt_descrs"):
        # this only exists in goodside should it be standardized in some way?
        descr_mock.assert_called_once()
        expected_translation_calls += len(probe_instance.attempt_descrs) * 2

    assert prompt_mock.call_count == expected_translation_calls
