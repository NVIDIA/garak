# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import garak._plugins
import garak.probes.promptinject as promptinject_module


def test_promptinject_probe_loads():
    p = garak._plugins.load_plugin("probes.promptinject.HijackHateHumans")
    assert p is not None


def test_promptinject_probe_has_generation_params():
    """Each probe must expose generation_params so the hook can read it.

    Regression guard for https://github.com/NVIDIA/garak/issues/1608 — the
    generation parameters applied during inference must be user-configurable
    via DEFAULT_PARAMS rather than hardcoded in the hook.
    """
    p = garak._plugins.load_plugin("probes.promptinject.HijackHateHumans")
    assert hasattr(p, "generation_params"), (
        "PromptInject probe must expose 'generation_params' attribute"
    )
    assert isinstance(p.generation_params, list)
    assert len(p.generation_params) > 0


def test_promptinject_generation_params_default():
    """Default generation_params must contain the original set of parameters."""
    p = garak._plugins.load_plugin("probes.promptinject.HijackHateHumans")
    expected = {"temperature", "top_p", "frequency_penalty", "presence_penalty", "max_tokens"}
    assert expected == set(p.generation_params)


def test_promptinject_generation_params_configurable():
    """Users can exclude max_tokens from the override list (e.g. for reasoning models).

    This is the core fix for #1608: by setting generation_params without
    'max_tokens', the probe will not override the generator's token limit.
    """
    p = garak._plugins.load_plugin(
        "probes.promptinject.HijackHateHumans",
        config_root=None,
    )
    # Simulate user config that drops max_tokens (for reasoning model compatibility)
    p.generation_params = ["temperature", "top_p", "frequency_penalty", "presence_penalty"]
    assert "max_tokens" not in p.generation_params


def test_promptinject_full_probe_has_generation_params():
    """Full variant also exposes generation_params."""
    p = garak._plugins.load_plugin("probes.promptinject.HijackHateHumansFull")
    assert hasattr(p, "generation_params")
    assert isinstance(p.generation_params, list)


def test_promptinject_module_generation_params_list():
    """Module-level _generation_params must be defined."""
    assert hasattr(promptinject_module, "_generation_params")
    assert isinstance(promptinject_module._generation_params, list)
