# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

import pytest
import requests

from garak import _config
from garak import _plugins
import garak.generators.base
import garak.generators.nvcf

PLUGINS = ("NvcfChat", "NvcfCompletion")


class _FakeResponse:
    def __init__(self, status_code, content):
        self.status_code = status_code
        self.content = content
        self.headers = {}


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


@pytest.mark.parametrize("klassname", PLUGINS)
def test_blank_prompt_400_skipped(klassname, monkeypatch, caplog):
    from garak.attempt import Message, Turn, Conversation

    _config.plugins.generators["nvcf"] = {}
    _config.plugins.generators["nvcf"][klassname] = {}
    _config.plugins.generators["nvcf"][klassname]["name"] = "placeholder name"
    _config.plugins.generators["nvcf"][klassname]["api_key"] = "placeholder key"
    g = _plugins.load_plugin(f"generators.nvcf.{klassname}")

    # blank-prompt refusals come back as a fragile multi-level wrapped JSON 400
    monkeypatch.setattr(
        requests.Session,
        "post",
        lambda self, *args, **kwargs: _FakeResponse(
            400, b'{"detail": {"error": {"message": "empty prompt"}}}'
        ),
    )

    blank_prompt = Conversation([Turn("user", Message(""))])
    with caplog.at_level(logging.WARNING):
        result = g._call_model(blank_prompt)

    assert result == [None], "a blank prompt rejected with HTTP 400 should yield [None]"
    assert (
        "skipping this prompt" not in caplog.text
    ), "blank prompt should hit the dedicated 400 guard, not the generic skip path"


@pytest.mark.parametrize("klassname", PLUGINS)
def test_nonblank_prompt_400_not_caught_by_blank_guard(klassname, monkeypatch, caplog):
    from garak.attempt import Message, Turn, Conversation

    _config.plugins.generators["nvcf"] = {}
    _config.plugins.generators["nvcf"][klassname] = {}
    _config.plugins.generators["nvcf"][klassname]["name"] = "placeholder name"
    _config.plugins.generators["nvcf"][klassname]["api_key"] = "placeholder key"
    g = _plugins.load_plugin(f"generators.nvcf.{klassname}")

    monkeypatch.setattr(
        requests.Session,
        "post",
        lambda self, *args, **kwargs: _FakeResponse(400, b"{}"),
    )

    real_prompt = Conversation([Turn("user", Message("a non-blank prompt"))])
    with caplog.at_level(logging.WARNING):
        result = g._call_model(real_prompt)

    assert result == [None], "a generic HTTP 400 should still be skipped"
    assert (
        "skipping this prompt" in caplog.text
    ), "a non-blank 400 must fall through to the generic skip path, not the blank guard"


@pytest.mark.parametrize(
    "content,expected",
    [
        (b'{"detail": "Input value error: blank prompt"}', True),
        (b'{"detail": "some other server error"}', False),
        (b"<html><body>502 Bad Gateway</body></html>", False),  # non-JSON body
        (b"", False),  # empty body
        (b"{}", False),  # JSON without a 'detail' key
        (b'{"detail": {"nested": "obj"}}', False),  # non-string detail
    ],
)
def test_nvcf_is_input_value_error_parses_defensively(content, expected):
    """A 500 body that is non-JSON or lacks a string 'detail' must not crash.

    Before guarding, json.loads(response.content)["detail"].startswith(...)
    raised an uncaught JSONDecodeError/KeyError/AttributeError on such bodies,
    aborting the whole scan instead of falling through to raise_for_status.
    """
    response = _FakeResponse(500, content)
    assert garak.generators.nvcf.NvcfChat._is_input_value_error(response) is expected
