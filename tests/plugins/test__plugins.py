# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak import _plugins


def test_probe_enumerate():
    probe_plugins = _plugins.enumerate_plugins("probes")
    assert isinstance(probe_plugins, list), "enumerate_plugins must return a list"
    for name, status in probe_plugins:
        assert name.startswith("probes.")
        assert status in (True, False)


def test_probe_enumerate_filter_inactive():
    inactive_probe_plugins = _plugins.enumerate_plugins(
        "probes", filter={"active": False}
    )
    for name, status in inactive_probe_plugins:
        assert status is False
