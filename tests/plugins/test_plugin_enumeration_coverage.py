# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Contract test for plugin enumeration coverage (garak issue #713).

enumerate_plugins() is the public view of garak's plugin discovery. Its
contract: every concrete plugin class in a category (probes/detectors/…)
should be returned by enumerate_plugins(), except base classes — which the
function deliberately excludes via the ``.base.`` name check.

This test validates that *contract* without re-implementing discovery: it
collects concrete plugin classes reachable from the category base classes via
the normal Python subclass registry, filters to the ``garak.<category>.``
namespace (matching what discovery enumerates), and asserts enumerate_plugins()
surfaces each one. Base classes are excluded exactly as enumerate_plugins does.
"""

import importlib
import inspect

import pytest

from garak import _plugins

CATEGORIES = ("detectors", "probes")


def _base_plugin_classes(category: str) -> list[type]:
    """Concrete base plugin classes for a category (e.g. Detector, Probe)."""
    base_mod = importlib.import_module(f"garak.{category}.base")
    return [
        klass
        for name, klass in inspect.getmembers(base_mod, inspect.isclass)
        if klass.__module__.startswith(base_mod.__name__)
        and not inspect.isabstract(klass)
    ]


def _concrete_plugin_classes(category: str) -> set[str]:
    """Concrete plugin classes in the garak.<category>. namespace.

    Reachable from the category base classes through the Python subclass
    registry — the same classes discovery walks. Base classes themselves are
    excluded, matching enumerate_plugins()'s ``.base.`` skip.
    """
    found = set()
    for base in _base_plugin_classes(category):
        for sub in base.__subclasses__():
            if sub.__module__.startswith(f"garak.{category}.") and not sub.__module__.endswith(".base"):
                name = f"{category}.{sub.__module__.split('.')[-1]}.{sub.__name__}"
                found.add(name)
    return found


@pytest.mark.parametrize("category", CATEGORIES)
def test_all_concrete_plugin_classes_are_enumerated(category: str) -> None:
    """Every concrete plugin class must be returned by enumerate_plugins()."""
    discovered = _concrete_plugin_classes(category)
    enumerated = {name for (name, _active) in _plugins.enumerate_plugins(category)}

    missing = sorted(discovered - enumerated)
    assert missing == [], (
        f"concrete plugin classes in garak.{category} not picked up by "
        f"plugin enumeration (see issue #713): {missing}"
    )


@pytest.mark.parametrize("category", CATEGORIES)
def test_base_classes_excluded_from_enumeration(category: str) -> None:
    """Base classes must NOT be enumerated (contract: `.base.` is skipped)."""
    enumerated = {name for (name, _active) in _plugins.enumerate_plugins(category)}
    base_leaks = sorted(n for n in enumerated if ".base." in n)
    assert base_leaks == [], (
        f"base classes should be excluded from enumeration but were found: {base_leaks}"
    )
