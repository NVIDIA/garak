# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import pathlib
import pytest
import yaml

import garak._config
import garak.attempt
import garak.data
import garak.services.intentservice

cas_data_path = garak.data.path / "cas" / "intent_stubs"

STUB_DATA_ENTRIES = [e for e in cas_data_path.glob("*") if str(e.name) != "README.md"]


@pytest.mark.parametrize("data_entry", STUB_DATA_ENTRIES)
def test_check_stub_file_entries(data_entry):
    entry_path = pathlib.Path(data_entry)
    assert entry_path.suffix.lower() in {
        ".json",
        ".txt",
        ".yml",
        ".yaml",
    }, f"Stub data dir should only contain stub data with correct extension, got {data_entry}"
    assert entry_path.stat().st_size > 0, "Stub files must contain data"
    assert garak.services.intentservice.validate_intent_specifier(
        entry_path.stem.split("_")[0]
    ), "Stub filename stem must be intent specifier or intent specifier followed by underscore and other content"
    # check name is verified intent: needs intentservice loaded, let's come back to that


@pytest.mark.parametrize("stub_filename", STUB_DATA_ENTRIES)
def test_stubs_match_typology(stub_filename):
    garak._config.load_config()
    garak.services.intentservice.load()

    stub_intent = stub_filename.stem.split("_")[0]
    assert (
        stub_intent in garak.services.intentservice.intent_typology
    ), "Stub file %s with intent %s does not match an available intent" % (
        stub_filename,
        stub_intent,
    )


YAML_STUB_INTENTS = cas_data_path.glob("*.y*ml")


@pytest.mark.parametrize("yaml_stubfile", YAML_STUB_INTENTS)
def test_yaml_stubs(yaml_stubfile):
    with open(yaml_stubfile, "r", encoding="utf-8") as yf:
        stubs = yaml.safe_load(yf.read())
        assert isinstance(
            stubs, list
        ), f"YAML stubfiles must have a list as top level object"
        assert len(stubs) > 0, f"Stubfile must have at least one entry"
        for entry in stubs:
            if isinstance(entry, str):
                assert len(entry) > 0, "Blank entries not permitted"
            elif isinstance(entry, dict):
                c = garak.attempt.Conversation.from_dict(entry)
            else:
                assert (
                    False
                ), f"Stubfile has entry of unsupported type, got: {type(entry).__name__}"


JSON_STUB_INTENTS = cas_data_path.glob("*.json")


@pytest.mark.parametrize("json_stubfile", JSON_STUB_INTENTS)
def test_json_stubs(json_stubfile):
    with open(json_stubfile, "r", encoding="utf-8") as jf:
        stubs = json.load(jf)
        assert isinstance(
            stubs, list
        ), f"JSON stubfiles must have a list as top level object"
        assert len(stubs) > 0, f"Stubfile must have at least one entry"

        for entry in stubs:
            if isinstance(entry, str):
                assert len(entry) > 0, "Blank entries not permitted"
            elif isinstance(entry, dict):
                c = garak.attempt.Conversation.from_dict(entry)
            else:
                assert (
                    False
                ), f"Stubfile has entry of unsupported type, got: {type(entry).__name__}"
