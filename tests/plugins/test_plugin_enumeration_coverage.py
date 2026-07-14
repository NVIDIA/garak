# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression guard for plugin enumeration coverage (garak issue #713).

garak discovers plugins by scanning the modules in each package
(``garak.<category>``) for concrete subclasses of the package base classes
(``garak.<category>.base``). ``_plugins.enumerate_plugins()`` is the public
view of that discovery.

If a concrete plugin class is added to a module but not picked up by the
enumeration, it silently becomes invisible: probes/detectors that iterate
over ``enumerate_plugins()`` (including the test suite) will never exercise
it. Issue #713 asks for a test that flags exactly this gap.

This test mirrors the discovery logic in
``garak._plugins.PluginCache._enumerate_plugin_klasses`` and asserts that
every concrete plugin class it finds is present in the enumerated set.

Note on mixins/base classes: garak's plugin base classes are implemented as
``abc.ABC`` subclasses, so mixins and abstract bases are excluded by the
``inspect.isabstract`` check below -- the same check the discovery machinery
uses. Concrete classes that intentionally subclass a base only to be inherited
from must themselves be abstract, otherwise they *should* be enumerated.
"""

import importlib
import inspect
import os

import pytest

from garak import _config, _plugins

# Categories to cover. Issue #713 is scoped to plugin modules in general;
# detectors & probes are the largest and most security-relevant surfaces.
CATEGORIES = ("detectors", "probes")


def _base_plugin_classes(category):
    """Return the concrete base plugin classes for a category (e.g. Detector)."""
    base_mod = importlib.import_module(f"garak.{category}.base")
    return [
        getattr(base_mod, name)
        for name, klass in inspect.getmembers(base_mod, inspect.isclass)
        if klass.__module__.startswith(base_mod.__name__)
        and not inspect.isabstract(klass)
    ]


def _discover_plugin_classes(category):
    """Discover concrete plugin classes the way the enumeration machinery does.

    Mirrors ``PluginCache._enumerate_plugin_klasses``: scan every non-base,
    non-dunder module in the package for concrete subclasses of the base
    plugin classes. Returns a set of ``"<category>.<module>.<Class>"`` names
    (without the ``garak.`` prefix, matching ``enumerate_plugins`` output).
    """
    base_klasses = _base_plugin_classes(category)
    base_mod = importlib.import_module(f"garak.{category}.base")
    module_dir = os.path.dirname(base_mod.__file__)

    discovered = set()
    for filename in sorted(os.listdir(module_dir)):
        if not filename.endswith(".py"):
            continue
        if filename.startswith("__") or filename.startswith("_"):
            continue
        module_name = filename[:-3]
        if module_name == "base":
            continue
        mod = importlib.import_module(f"garak.{category}.{module_name}")
        for name, klass in inspect.getmembers(mod, inspect.isclass):
            if klass.__module__ != mod.__name__:
                continue  # imported, not defined here
            if inspect.isabstract(klass):
                continue
            if any(issubclass(klass, base) for base in base_klasses):
                discovered.add(f"{category}.{module_name}.{name}")
    return discovered


@pytest.mark.parametrize("category", CATEGORIES)
def test_all_plugin_classes_are_enumerated(category):
    """Every concrete plugin class must be returned by enumerate_plugins."""
    discovered = _discover_plugin_classes(category)
    enumerated = {name for (name, _active) in _plugins.enumerate_plugins(category)}

    missing = sorted(discovered - enumerated)
    assert missing == [], (
        f"concrete plugin classes in garak.{category} not picked up by "
        f"plugin enumeration (see issue #713): {missing}"
    )


@pytest.mark.parametrize("category", CATEGORIES)
def test_enumeration_matches_discovery_count(category):
    """Enumeration and discovery should agree on the set of plugin classes.

    Guards against the inverse drift too: a class present in enumeration that
    discovery no longer finds would indicate a stale plugin cache or a moved
    base class.
    """
    discovered = _discover_plugin_classes(category)
    enumerated = {name for (name, _active) in _plugins.enumerate_plugins(category)}

    assert discovered == enumerated, (
        "plugin enumeration and discovery disagree for "
        f"garak.{category}: discovered-only={sorted(discovered - enumerated)}, "
        f"enumerated-only={sorted(enumerated - discovered)}"
    )
