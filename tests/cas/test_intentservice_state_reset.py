# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak._config


def test_intentservice_load_populates_state():
    import garak.services.intentservice

    garak.services.intentservice.is_loaded = False
    garak.services.intentservice.intent_typology = {}
    garak.services.intentservice.intent_detectors = {}
    garak.services.intentservice.intents_active = set()

    garak._config.load_config()
    garak.services.intentservice.load()

    assert garak.services.intentservice.is_loaded, "load() must set is_loaded"
    assert garak.services.intentservice.intent_typology, "load() must load the typology"
    assert garak.services.intentservice.intents_active, "load() must activate intents"


def test_intentservice_state_reset_between_tests():
    import garak.services.intentservice

    assert not garak.services.intentservice.is_loaded, (
        "intentservice must not stay loaded across tests"
    )
    assert garak.services.intentservice.intent_typology == {}, (
        "intent typology must be reset between tests"
    )
    assert garak.services.intentservice.intent_detectors == {}, (
        "intent detector mapping must be reset between tests"
    )
    assert garak.services.intentservice.intents_active == set(), (
        "active intents must be reset between tests"
    )
