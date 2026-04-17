# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib

import pytest

from garak import _plugins
from garak.attempt import Attempt, Message

PROBES_WITH_REFUSAL_PRIMARY = [
    ("garak.probes.audio", "AudioAchillesHeel"),
    ("garak.probes.badchars", "BadCharacters"),
    ("garak.probes.dan", "DanInTheWildFull"),
    ("garak.probes.dan", "DanInTheWild"),
    ("garak.probes.doctor", "Puppetry"),
    ("garak.probes.doctor", "Bypass"),
    ("garak.probes.donotanswer", "DiscriminationExclusionToxicityHatefulOffensive"),
    ("garak.probes.donotanswer", "HumanChatbox"),
    ("garak.probes.donotanswer", "InformationHazard"),
    ("garak.probes.donotanswer", "MaliciousUses"),
    ("garak.probes.donotanswer", "MisinformationHarms"),
    ("garak.probes.dra", "DRA"),
    ("garak.probes.grandma", "Substances"),
    ("garak.probes.sata", "MLM"),
    ("garak.probes.smuggling", "HypotheticalResponse"),
    ("garak.probes.smuggling", "FunctionMasking"),
    ("garak.probes.suffix", "GCGCached"),
    ("garak.probes.suffix", "GCG"),
    ("garak.probes.suffix", "BEAST"),
    ("garak.probes.tap", "TAPCached"),
    ("garak.probes.tap", "TAP"),
    ("garak.probes.tap", "PAIR"),
    ("garak.probes.topic", "WordnetControversial"),
]

PROBES_WITH_REFUSAL_EXTENDED = [
    ("garak.probes.divergence", "Repeat"),
    ("garak.probes.grandma", "Win10"),
    ("garak.probes.grandma", "Win11"),
    ("garak.probes.grandma", "Slurs"),
    ("garak.probes.misleading", "FalseAssertion"),
]


@pytest.mark.parametrize("module_name,class_name", PROBES_WITH_REFUSAL_PRIMARY)
def test_probe_primary_detector_is_refusal_model(module_name, class_name):
    mod = importlib.import_module(module_name)
    probe_class = getattr(mod, class_name)
    assert probe_class.primary_detector == "mitigation.RefusalModel"


@pytest.mark.parametrize("module_name,class_name", PROBES_WITH_REFUSAL_EXTENDED)
def test_probe_extended_detectors_contains_refusal_model(module_name, class_name):
    mod = importlib.import_module(module_name)
    probe_class = getattr(mod, class_name)
    assert "mitigation.RefusalModel" in probe_class.extended_detectors


@pytest.mark.requires_storage(required_space_gb=2, path="/")
def test_refusal_model_smoke_wiring():
    d = _plugins.load_plugin("detectors.mitigation.RefusalModel")
    a = Attempt(
        prompt=Message(text="do something harmful", lang=d.lang_spec.split(",")[0])
    )
    a.outputs = ["I cannot help with that request."]
    results = d.detect(a)
    assert len(results) == 1
    assert isinstance(results[0], float)
