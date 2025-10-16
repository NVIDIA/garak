# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import pathlib
import tempfile
import os

from garak import _config, _plugins
from garak.attempt import Message, Attempt


NON_PROMPT_PROBES = [
    "probes.dan.AutoDAN",
    "probes.tap.TAP",
    "probes.suffix.BEAST",
    "probes.suffix.GCG",
]
ATKGEN_PROMPT_PROBES = ["probes.atkgen.Tox"]
VISUAL_PROBES = [
    "probes.visual_jailbreak.FigStep",
    "probes.visual_jailbreak.FigStepFull",
]
AUDIO_PROBES = [
    "probes.audio.AudioAchillesHeel",
]
PROBES = [
    classname
    for (classname, _) in _plugins.enumerate_plugins("probes")
    if classname not in NON_PROMPT_PROBES
    and classname not in VISUAL_PROBES
    and classname not in ATKGEN_PROMPT_PROBES
    and classname not in AUDIO_PROBES
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
    temp_report_file = tempfile.NamedTemporaryFile(
        mode="w+", delete=False, encoding="utf-8"
    )
    _config.transient.reportfile = temp_report_file
    _config.transient.report_filename = temp_report_file.name

    # since this does not go through cli generations must be set
    _, module, klass = classname.split(".")
    _config.plugins.probes[module][klass]["generations"] = 1


RESPONSE_SAMPLES = [
    (
        [
            Message("text to translate", lang="fr"),
            Message("text to translate", lang="fr"),
            Message("text to translate", lang="fr"),
        ],
        "probes.base.Probe",
    ),
    (
        [
            Message("text to translate", lang="fr"),
            None,
            None,
        ],
        "probes.base.Probe",
    ),
    (
        [
            None,
            Message("text to translate", lang="fr"),
            None,
        ],
        "probes.base.Probe",
    ),
    (
        [
            None,
            None,
            Message("text to translate", lang="fr"),
            None,
        ],
        "probes.base.Probe",
    ),
]


@pytest.mark.parametrize("responses, classname", RESPONSE_SAMPLES)
def test_base_postprocess_attempt(responses, mocker):
    """Validate processing of reverse translation for various response cases"""
    import garak.langservice
    import garak.probes.base
    from garak.langproviders.local import Passthru

    null_provider = Passthru(
        {
            "langproviders": {
                "local": {
                    "language": "en,en",
                }
            }
        }
    )

    mocker.patch.object(
        garak.langservice, "get_langprovider", return_value=null_provider
    )

    prompt_mock = mocker.patch.object(
        null_provider,
        "get_text",
        wraps=null_provider.get_text,
    )

    a = Attempt(prompt="just a test attempt", lang="fr")
    a.outputs = responses
    p = garak.probes.base.Probe()
    p.lang = "en"
    r = p._postprocess_attempt(a)
    assert prompt_mock.called
    assert len(r.reverse_translation_outputs) == len(responses)
    for response, output in zip(r.reverse_translation_outputs, r.outputs):
        assert type(response) == type(
            output
        ), "translation index outputs should align with output types"


"""
Skip probes.tap.PAIR because it needs openai api key and large gpu resource
"""


@pytest.mark.parametrize("classname", ATKGEN_PROMPT_PROBES)
def test_atkgen_probe_translation(classname, mocker):
    # how can tests for atkgen probes be expanded to ensure translation is called?
    import garak.langservice
    from garak.langproviders.local import Passthru

    null_provider = Passthru(
        {
            "langproviders": {
                "local": {
                    "language": "en,en",
                }
            }
        }
    )

    mocker.patch.object(
        garak.langservice, "get_langprovider", return_value=null_provider
    )

    prompt_mock = mocker.patch.object(
        null_provider,
        "get_text",
        wraps=null_provider.get_text,
    )

    probe_instance = _plugins.load_plugin(classname)
    # cut down test time
    probe_instance.max_calls_per_conv = 2
    probe_instance.convs_per_generation = 2
    probe_instance.allow_repetition = True  # we're counting responses, don't quit early

    if probe_instance.lang != "en" or classname == "probes.tap.PAIR":
        return

    generator_instance = _plugins.load_plugin("generators.test.Repeat")

    probe_instance.probe(generator_instance)

    expected_langprovision_calls = (
        2 * probe_instance.max_calls_per_conv * probe_instance.convs_per_generation
    )
    if hasattr(probe_instance, "triggers"):
        # increase prompt calls by 1 or if triggers are lists by the len of triggers
        if isinstance(probe_instance.triggers[0], list):
            expected_langprovision_calls += len(probe_instance.triggers)
        else:
            expected_langprovision_calls += 1

    assert prompt_mock.call_count == expected_langprovision_calls


@pytest.mark.parametrize("classname", VISUAL_PROBES)
def test_multi_modal_probe_translation(classname, mocker):
    import garak.langservice
    from garak.langproviders.local import Passthru

    null_provider = Passthru(
        {
            "langproviders": {
                "local": {
                    "language": "en,ja",
                    # Note: differing source and target language pair here forces langprovider calls
                }
            }
        }
    )

    mocker.patch.object(
        garak.langservice, "get_langprovider", return_value=null_provider
    )

    prompt_mock = mocker.patch.object(
        null_provider,
        "get_text",
        wraps=null_provider.get_text,
    )

    probe_instance = _plugins.load_plugin(classname)

    if probe_instance.lang != "en":
        pytest.skip("Probe does not engage with language provision")

    generator_instance = _plugins.load_plugin("generators.test.Repeat")
    generator_instance.modality["in"] = {"image", "text"}

    probe_instance.probe(generator_instance)

    expected_provision_calls = len(probe_instance.prompts) * 2
    if hasattr(probe_instance, "triggers"):
        # increase prompt calls by 1 or if triggers are lists by the len of triggers
        if isinstance(probe_instance.triggers[0], list):
            expected_provision_calls += len(probe_instance.triggers)
        else:
            expected_provision_calls += 1

    if hasattr(probe_instance, "attempt_descrs"):
        # this only exists in goodside should it be standardized in some way?
        expected_provision_calls += len(probe_instance.attempt_descrs) * 2

    assert prompt_mock.call_count == expected_provision_calls


@pytest.mark.parametrize("classname", PROBES)
def test_probe_prompt_translation(classname, mocker):
    # instead of active translation this just checks that translation is called.
    # for instance if there are triggers ensure `translate` is called at least twice
    # if the triggers are a list call for each list then call for all actual `prompts`

    # initial translation is front loaded on __init__ of a probe for triggers, simple validation
    # of calls for translation should be sufficient as a unit test on all probes that follow
    # this standard pattern. Any probe that needs to call translation more than once during probing
    # should have a unique validation that translation is called in the correct runtime stage

    import garak.langservice
    from garak.langproviders.local import Passthru

    null_provider = Passthru(
        {
            "langproviders": {
                "local": {
                    "language": "en,ja",
                    # Note: differing source and target language pair here forces langprovider calls
                }
            }
        }
    )

    mocker.patch.object(
        garak.langservice, "get_langprovider", return_value=null_provider
    )

    prompt_mock = mocker.patch.object(
        null_provider,
        "get_text",
        wraps=null_provider.get_text,
    )

    probe_instance = _plugins.load_plugin(classname)

    if probe_instance.lang != "en" or classname == "probes.tap.PAIR":
        pytest.skip("Probe does not engage with language provision")

    generator_instance = _plugins.load_plugin("generators.test.Repeat")

    probe_instance.probe(generator_instance)

    expected_provision_calls = len(probe_instance.prompts) + 1
    if hasattr(probe_instance, "triggers"):
        # increase prompt calls by 1 or if triggers are lists by the len of triggers
        if isinstance(probe_instance.triggers[0], list):
            expected_provision_calls += len(probe_instance.triggers)
        else:
            expected_provision_calls += 1

    if hasattr(probe_instance, "attempt_descrs"):
        # this only exists in goodside should it be standardized in some way?
        expected_provision_calls += len(probe_instance.attempt_descrs) * 2

    assert prompt_mock.call_count == expected_provision_calls
