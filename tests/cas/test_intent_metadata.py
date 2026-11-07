# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import pytest

import garak._plugins
from garak.data import path as data_path
from garak.services.intentservice import validate_intent_specifier

CAS_PATH = data_path / "cas"

INTENT_DETECTORS_PATH = CAS_PATH / "intent_detectors.json"
TRAIT_TYPOLOGY_PATH = CAS_PATH / "trait_typology.json"
INTENT_SKIP_PATH = CAS_PATH / "intent_skip.json"

DETECTOR_LIST = [d for d, _ in garak._plugins.enumerate_plugins("detectors")]


# would prefer to run tests on these before making their contents available -
# but load exceptions are a fine enough signal anywhere, even from here
with open(TRAIT_TYPOLOGY_PATH, "r", encoding="utf-8") as ttf:
    TRAIT_TYPOLOGY = json.load(ttf)

with open(INTENT_DETECTORS_PATH, "r", encoding="utf-8") as idf:
    INTENT_DETECTORS = json.load(idf)

with open(INTENT_SKIP_PATH, "r", encoding="utf-8") as isf:
    INTENTS_TO_SKIP = json.load(isf)


@pytest.mark.parametrize("trait_code", TRAIT_TYPOLOGY.keys())
def test_intents_valid(trait_code):
    assert validate_intent_specifier(trait_code)
    entry = TRAIT_TYPOLOGY[trait_code]
    assert entry.get("name") is not None
    assert isinstance(entry["name"], str)
    assert len(entry["name"]) > 0


# intent_detectors have valid detectors, valid intents
@pytest.mark.parametrize("intent", INTENT_DETECTORS.keys())
def test_intent_detectors(intent):
    cache = garak._plugins.PluginCache()
    assert (
        intent in TRAIT_TYPOLOGY.keys()
    ), f"Intent {intent} in {INTENT_DETECTORS_PATH} not found in typology"
    detectors = INTENT_DETECTORS[intent]
    for detector in detectors:
        assert (
            "detectors." + detector in DETECTOR_LIST
        ), f"Intent {intent} specified unrecognised detector {detector} in {INTENT_DETECTORS_PATH}"


@pytest.mark.parametrize("intent_to_skip", INTENTS_TO_SKIP)
def test_intents_skip(intent_to_skip):
    assert (
        intent_to_skip in TRAIT_TYPOLOGY
    ), f"Intent to skip {intent_to_skip} not found in typology"


MAPPED_DETECTORS = sorted({d for ds in INTENT_DETECTORS.values() for d in ds})


# every mapped detector must resolve to a real Detector subclass, not just a
# name in the plugin cache
@pytest.mark.parametrize("detector", MAPPED_DETECTORS)
def test_intent_detector_class_loads(detector):
    import importlib
    import garak.detectors.base

    module_name, class_name = detector.split(".")
    module = importlib.import_module(f"garak.detectors.{module_name}")
    klass = getattr(module, class_name, None)
    assert klass is not None, f"{detector} not found in garak.detectors.{module_name}"
    assert issubclass(
        klass, garak.detectors.base.Detector
    ), f"{detector} must be a Detector subclass"


# leaf intents without their own mapping pick up the nearest mapped ancestor;
# leaves deliberately left unmapped must stay unscored
@pytest.mark.parametrize(
    "intent, mapped_ancestor",
    [
        ("S002med", "S002"),
        ("S003goods", "S003goods"),
        ("S003productkeyswin10", "S003productkeyswin10"),
        ("S003productkeysxbox", None),
        ("S006sh", None),
        ("T009reveal", "T009reveal"),
    ],
)
def test_get_detectors_resolves_nearest_mapped_ancestor(intent, mapped_ancestor):
    import garak.services.intentservice as intentservice

    intentservice._load_intent_detector_mapping()
    expected = INTENT_DETECTORS[mapped_ancestor] if mapped_ancestor else None
    assert (
        intentservice.get_detectors(intent, override_loaded_check=True) == expected
    ), f"{intent} must resolve to the {mapped_ancestor} mapping"
