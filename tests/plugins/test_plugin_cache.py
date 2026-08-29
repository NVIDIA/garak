# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import pytest
import os
import sys
import tempfile

from pathlib import Path
from garak._plugins import PluginCache, PluginEncoder


@pytest.fixture(autouse=True)
def reset_cache(request) -> None:
    def reset_plugin_cache():
        PluginCache._plugin_cache_dict = None

    request.addfinalizer(reset_plugin_cache)


@pytest.fixture
def temp_cache_location(request) -> None:
    # override the cache file with a tmp location
    with tempfile.NamedTemporaryFile(buffering=0, delete=False) as tmp:
        PluginCache._user_plugin_cache_filename = Path(tmp.name)
        tmp.close()
        os.remove(tmp.name)
    # reset the class level singleton
    PluginCache._plugin_cache_dict = None

    def remove_cache_file():
        if os.path.exists(tmp.name):
            os.remove(tmp.name)

    request.addfinalizer(remove_cache_file)

    return tmp.name


@pytest.fixture
def remove_package_cache(request) -> None:
    # override the cache file with a tmp location
    original_path = PluginCache._plugin_cache_filename
    with tempfile.NamedTemporaryFile(buffering=0, delete=False) as tmp:
        PluginCache._plugin_cache_filename = Path(tmp.name)
        tmp.close()
        os.remove(tmp.name)
    # reset the class level singleton
    PluginCache._plugin_cache_dict = None

    def restore_package_path():
        PluginCache._plugin_cache_filename = original_path

    request.addfinalizer(restore_package_path)

    return tmp.name


def test_create(temp_cache_location):
    cache = PluginCache.instance()
    assert os.path.isfile(temp_cache_location)
    assert isinstance(cache, dict)


def test_existing():
    info = PluginCache.plugin_info("probes.test.Test")
    assert isinstance(info, dict)


def test_missing_from_cache():
    cache = PluginCache.instance()["probes"]
    del cache["probes.test.Test"]
    assert cache.get("probes.test.Test") is None
    info = PluginCache.plugin_info("probes.test.Test")
    assert isinstance(info, dict)


def test_unknown_type():
    with pytest.raises(ValueError) as exc_info:
        info = PluginCache.plugin_info("fake.test.missing")
    assert "plugin type" in str(exc_info.value)


def test_unknown_class():
    with pytest.raises(ValueError) as exc_info:
        info = PluginCache.plugin_info("probes.test.missing")
    assert "plugin from " in str(exc_info.value)


def test_unknown_module():
    with pytest.raises(ValueError) as exc_info:
        info = PluginCache.plugin_info("probes.invalid.missing")
    assert "plugin module" in str(exc_info.value)


def test_invalid_class_path():
    with pytest.raises(ValueError) as exc_info:
        info = PluginCache.plugin_info("probes.invalid.format.length")
    assert "plugin class" in str(exc_info.value)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows Github executor does not raise the ValueError",
)
def test_module_removed(temp_cache_location):
    cache = PluginCache.instance()
    cache["probes"]["probes.invalid.Removed"] = {
        "description": "Testing value to be purged"
    }
    with open(temp_cache_location, "w", encoding="utf-8") as cache_file:
        json.dump(cache, cache_file, cls=PluginEncoder, indent=2)
    PluginCache._plugin_cache_dict = None
    with pytest.raises(ValueError) as exc_info:
        PluginCache.plugin_info("probes.invalid.Removed")
    assert "plugin module" in str(exc_info.value)


@pytest.mark.usefixtures("remove_package_cache")
def test_report_missing_package_file():
    with pytest.raises(AssertionError) as exc_info:
        PluginCache.instance()
    assert "is missing or corrupt" in str(exc_info.value)
