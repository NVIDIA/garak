# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak import _config
from garak import _plugins
import garak.generators.base
import garak.generators.nvcf

PLUGINS = ("NvcfChat", "NvcfCompletion")


@pytest.mark.parametrize("klassname", PLUGINS)
def test_instantiate(klassname):
    _config.plugins.generators["nvcf"] = {}
    _config.plugins.generators["nvcf"][klassname] = {}
    _config.plugins.generators["nvcf"][klassname]["name"] = "placeholder name"
    _config.plugins.generators["nvcf"][klassname]["api_key"] = "placeholder key"
    g = _plugins.load_plugin(f"generators.nvcf.{klassname}")
    assert isinstance(g, garak.generators.base.Generator)


@pytest.mark.parametrize("klassname", PLUGINS)
def test_version_endpoint(klassname):
    name = "feedfacedeadbeef"
    version = "cafebabe"
    _config.plugins.generators["nvcf"] = {}
    _config.plugins.generators["nvcf"][klassname] = {}
    _config.plugins.generators["nvcf"][klassname]["name"] = name
    _config.plugins.generators["nvcf"][klassname]["api_key"] = "placeholder key"
    _config.plugins.generators["nvcf"][klassname]["version_id"] = version
    g = _plugins.load_plugin(f"generators.nvcf.{klassname}")
    assert g.invoke_uri == f"{g.invoke_uri_base}{name}/versions/{version}"


@pytest.mark.parametrize("klassname", PLUGINS)
def test_custom_keys(klassname):
    from garak.attempt import Message, Turn, Conversation

    name = "feedfacedeadbeef"
    params = {"n": 1, "model": "secret/model_1.8t"}
    _config.plugins.generators["nvcf"] = {}
    _config.plugins.generators["nvcf"][klassname] = {}
    _config.plugins.generators["nvcf"][klassname]["name"] = name
    _config.plugins.generators["nvcf"][klassname]["api_key"] = "placeholder key"
    _config.plugins.generators["nvcf"][klassname]["extra_params"] = params
    g = _plugins.load_plugin(f"generators.nvcf.{klassname}")
    conv = Conversation([Turn("user", Message("whatever prompt"))])
    test_payload = g._build_payload(conv)
    for k, v in params.items():
        assert test_payload[k] == v
