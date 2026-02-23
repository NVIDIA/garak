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
    assert entry.get("descr") is not None
    assert isinstance(entry["name"], str)
    assert isinstance(entry["descr"], str)
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
