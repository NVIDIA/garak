# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
from garak._plugins import PluginProvider
from garak import _config
from garak.probes.test import Blank, Test


def test_plugin_provider_instance_not_found():
    assert isinstance(PluginProvider._instance_cache, dict)
    assert len(PluginProvider._instance_cache) == 0
    res = PluginProvider.getInstance(Blank, _config)
    assert res is None
    assert len(PluginProvider._instance_cache) == 0


def test_plugin_provider_store():
    assert isinstance(PluginProvider._instance_cache, dict)
    assert len(PluginProvider._instance_cache) == 0

    b = Blank(config_root=_config)
    b2 = Blank(config_root={})
    t = Test(config_root=_config)
    PluginProvider.storeInstance(b, _config)
    PluginProvider.storeInstance(b2, {})
    PluginProvider.storeInstance(t, _config)

    res_config = PluginProvider.getInstance(Blank, _config)
    res_empty_config = PluginProvider.getInstance(
        Blank, config_root={"does": "not exist"}
    )

    assert isinstance(res_config, Blank)
    assert res_config == b, "The returned instance did not match the original."
    assert res_empty_config is None, "The provider return an incorrect instance."
    assert (
        len(PluginProvider._instance_cache) == 2
    ), "The provider dictionary keys should equal the number of unique class types stored."


def test_plugin_provider_store_keeps_first_instance_for_key():
    """A late store for an existing (class, config_root) must not clobber the cache.

    ``load_plugin`` constructs outside the provider lock, so two racing loaders can
    both construct an instance; the first one stored must win and the late store
    must return the cached instance, or callers hold different objects for one key
    and the provider's dedup contract is broken.
    """
    first = Blank(config_root=_config)
    second = Blank(config_root=_config)
    assert PluginProvider.getInstance(Blank, _config) is None
    winner = PluginProvider.storeInstance(first, _config)
    assert winner is first
    late = PluginProvider.storeInstance(second, _config)
    assert late is first, "late store must return the cached instance, not replace it"
    assert PluginProvider.getInstance(Blank, _config) is first


def test_racing_load_plugin_calls_converge_on_one_instance():
    """Two threads loading the same plugin must end up with the same instance."""
    import threading

    from garak._plugins import load_plugin

    constructed = []
    original_init = Blank.__init__

    def instrumented_init(self, config_root=None):
        # Hold both constructors mid-init so both threads pass the getInstance
        # miss before either one stores — the tightest racing interleaving.
        barrier = _construction_barrier
        barrier.wait(timeout=5)
        original_init(self, config_root=config_root)
        constructed.append(self)

    _construction_barrier = threading.Barrier(2)
    Blank.__init__ = instrumented_init
    try:
        results = []
        threads = [
            threading.Thread(
                target=lambda: results.append(load_plugin("probes.test.Blank"))
            )
            for _ in range(2)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
    finally:
        Blank.__init__ = original_init

    assert len(results) == 2
    assert all(result is not None for result in results)
    assert results[0] is results[1], "racing loaders must converge on one instance"
    assert len(constructed) == 2, "both racers constructed before either stored"
