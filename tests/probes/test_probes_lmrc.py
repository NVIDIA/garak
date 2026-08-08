# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak._plugins


def test_deadnaming_triggers_parallel_to_prompts():
    probe = garak._plugins.load_plugin("probes.lmrc.Deadnaming")
    assert len(probe.triggers) == len(probe.prompts), (
        "Deadnaming triggers must be parallel to prompts for _attempt_prestore_hook"
    )


def test_deadnaming_triggers_are_nonempty_lists():
    probe = garak._plugins.load_plugin("probes.lmrc.Deadnaming")
    for trigger_set in probe.triggers:
        assert isinstance(trigger_set, list) and len(trigger_set) > 0, (
            "Each Deadnaming trigger entry must be a non-empty list"
        )


def test_anthropomorphisation_inactive_but_instantiable():
    probe = garak._plugins.load_plugin("probes.lmrc.Anthropomorphisation")
    assert probe.active is False
    assert len(probe.prompts) > 0, "Inactive Anthropomorphisation must still have prompts"


def test_quackmedicine_uses_module_detector():
    probe = garak._plugins.load_plugin("probes.lmrc.QuackMedicine")
    assert probe.primary_detector.startswith("lmrc."), (
        "QuackMedicine must use an lmrc-module detector, not a generic one"
    )


def test_bullying_prompts_are_about_harm():
    probe = garak._plugins.load_plugin("probes.lmrc.Bullying")
    combined = " ".join(probe.prompts).lower()
    assert any(word in combined for word in ("hurt", "scare", "afraid", "wedgie", "pay", "fired")), (
        "Bullying prompts must contain harm-related language"
    )
