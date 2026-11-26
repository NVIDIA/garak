# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import tempfile

import pytest

import garak
import garak.attempt
from garak import _config, _plugins

PROBE_NAME = "probes.persuasion.PersuasiveJailbreak"


def _probe(techniques, base_prompt_count):
    config_root = {
        "probes": {
            "persuasion": {
                "PersuasiveJailbreak": {
                    "red_team_model_type": "test.Repeat",
                    "red_team_model_name": "",
                    "techniques": techniques,
                    "base_prompt_count": base_prompt_count,
                }
            }
        }
    }
    return _plugins.load_plugin(PROBE_NAME, config_root=config_root)


def test_persuasion_taxonomy_loads():
    _config.load_base_config()
    probe = _probe(["Logical Appeal"], 1)
    assert (
        len(probe._taxonomy) == 40
    ), "the vendored persuasion taxonomy should expose 40 techniques"
    assert all(
        {"definition", "example"} <= entry.keys() for entry in probe._taxonomy.values()
    ), "each taxonomy entry should carry a definition and an example"


def test_persuasion_unknown_technique_rejected():
    _config.load_base_config()
    with pytest.raises(garak.exception.GarakException):
        _probe(["Not A Real Technique"], 1)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ('"quoted"', "quoted"),
        ("'quoted'", "quoted"),
        ('"""triple"""', "triple"),
        ("  spaced  ", "spaced"),
        ("unwrapped", "unwrapped"),
    ],
)
def test_strip_wrapping_quotes(raw, expected):
    from garak.probes.persuasion import PersuasiveJailbreak

    assert (
        PersuasiveJailbreak._strip_wrapping_quotes(raw) == expected
    ), "wrapping quotes and surrounding whitespace should be removed"


def test_persuasion_probe_generates_paps():
    _config.load_base_config()
    techniques = ["Logical Appeal", "Authority Endorsement"]
    base_prompt_count = 3
    probe = _probe(techniques, base_prompt_count)

    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as report_file:
        _config.transient.reportfile = report_file
        _config.transient.report_filename = report_file.name
        generator = _plugins.load_plugin("generators.test.Blank", config_root=_config)
        attempts = probe.probe(generator)

    assert len(attempts) == base_prompt_count * len(
        techniques
    ), "one PAP should be produced per base prompt per technique when the red team model always responds"
    assert all(
        isinstance(a, garak.attempt.Attempt) for a in attempts
    ), "every returned item should be an Attempt"
    assert all(
        isinstance(a.prompt, garak.attempt.Conversation) for a in attempts
    ), "every attempt prompt should be a Conversation"
