# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

import pytest

import garak._plugins
import garak.probes.base
import garak.attempt

DATA_FILE = Path(__file__).parent.parent.parent / "garak" / "data" / "context_compliance.json"
EXPECTED_ENTRY_COUNT = 15
EXPECTED_ROLES = ["user", "assistant", "user"]


@pytest.fixture(scope="module")
def probe():
    return garak._plugins.load_plugin("probes.context_compliance.ContextCompliance")


@pytest.fixture(scope="module")
def data():
    if not DATA_FILE.exists():
        pytest.skip(f"Data file not found: {DATA_FILE}")
    with open(DATA_FILE, encoding="utf-8") as f:
        return json.load(f)


def test_data_file_exists():
    assert DATA_FILE.exists(), f"Data file not found: {DATA_FILE}"


def test_data_file_is_valid_json(data):
    assert "entries" in data


def test_data_file_has_15_entries(data):
    assert len(data["entries"]) == EXPECTED_ENTRY_COUNT


def test_data_entries_have_required_fields(data):
    for entry in data["entries"]:
        assert "payload" in entry
        assert "category" in entry
        assert "conversation" in entry


def test_data_entries_have_3_turn_conversations(data):
    for entry in data["entries"]:
        assert len(entry["conversation"]) == 3


def test_data_entries_have_correct_roles(data):
    for entry in data["entries"]:
        roles = [turn["role"] for turn in entry["conversation"]]
        assert roles == EXPECTED_ROLES


def test_data_last_turn_is_yes(data):
    for entry in data["entries"]:
        assert entry["conversation"][-1]["content"] == "yes."


def test_probe_loads(probe):
    assert isinstance(probe, garak.probes.base.Probe)


def test_probe_has_15_prompts(probe):
    assert len(probe.prompts) == EXPECTED_ENTRY_COUNT


def test_prompts_are_conversations(probe):
    for prompt in probe.prompts:
        assert isinstance(prompt, garak.attempt.Conversation)


def test_each_conversation_has_3_turns(probe):
    for conv in probe.prompts:
        assert len(conv.turns) == 3


def test_conversation_turn_roles(probe):
    for conv in probe.prompts:
        roles = [turn.role for turn in conv.turns]
        assert roles == EXPECTED_ROLES


def test_last_turn_content_is_yes(probe):
    for conv in probe.prompts:
        assert conv.turns[-1].content.text == "yes."


def test_probe_active(probe):
    assert probe.active is True


def test_probe_lang(probe):
    assert probe.lang == "en"


def test_probe_primary_detector(probe):
    assert probe.primary_detector == "mitigation.MitigationBypass"
