# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import inspect
import pytest

import garak
import garak._config
import garak._plugins
import garak.attempt
import garak.probes.beavertails


def test_beavertails_module_structure():
    """Test that BeaverTails module has correctly structured probe classes."""
    # Get all probe classes from beavertails module
    beavertails_classes = []
    for name, obj in inspect.getmembers(garak.probes.beavertails):
        if (
            inspect.isclass(obj)
            and obj.__module__ == "garak.probes.beavertails"
            and issubclass(obj, garak.probes.Probe)
            and name != "BeaverTailsBase"
        ):
            beavertails_classes.append((name, obj))

    # Verify we have the expected classes (1 base + 1 all + 14 categories = 16 total)
    assert (
        len(beavertails_classes) >= 15
    ), "Should have BeaverTailsAll and all category probes"

    # Check class naming
    for name, cls in beavertails_classes:
        assert name.startswith(
            "BeaverTails"
        ), f"Class {name} should start with 'BeaverTails'"


def test_beavertails_all_instantiation():
    """Test that BeaverTailsAll probe can be instantiated and loads data."""
    probe = garak.probes.beavertails.BeaverTailsAll()
    assert probe is not None
    # Check that it inherits from BeaverTailsBase
    assert isinstance(probe, garak.probes.beavertails.BeaverTailsBase)
    # Should have prompts loaded
    assert len(probe.prompts) > 0, "BeaverTailsAll should load prompts"


def test_beavertails_category_probes():
    """Test that category-specific probes can be instantiated."""
    category_classes = [
        (garak.probes.beavertails.BeaverTailsAnimalAbuse, 357),
        (garak.probes.beavertails.BeaverTailsChildAbuse, 185),
        (garak.probes.beavertails.BeaverTailsControversialTopics, 907),
        (garak.probes.beavertails.BeaverTailsDiscrimination, 2352),
        (garak.probes.beavertails.BeaverTailsHateSpeech, 2560),
        (garak.probes.beavertails.BeaverTailsUnethicalBehavior, 4821),
    ]

    for probe_class, expected_min_count in category_classes:
        probe = probe_class()
        assert probe is not None
        assert hasattr(probe, "data_file")
        assert probe.data_file is not None
        # Should have loaded prompts (allowing for soft cap)
        assert len(probe.prompts) > 0, f"{probe_class.__name__} should load prompts"


def test_beavertails_metadata():
    """Test that BeaverTails probes have required metadata."""
    try:
        probe = garak.probes.beavertails.BeaverTailsAll()
    except ImportError:
        pytest.skip("Required dependency not available")

    # Check required metadata
    assert isinstance(probe.goal, str), "goal should be a string"
    assert len(probe.goal) > 0, "goal should not be empty"
    assert probe.lang in ["en", "*"], "lang should be 'en' or '*'"
    assert isinstance(probe.doc_uri, str), "doc_uri should be a string"
    assert probe.doc_uri.startswith("http"), "doc_uri should start with http"
    assert probe.tier is not None, "tier should be specified"
    assert isinstance(probe.tier, garak.probes.Tier), "tier should be Tier enum"


def test_beavertails_detector_specified():
    """Test that BeaverTails probes have a detector specified."""
    try:
        probe = garak.probes.beavertails.BeaverTailsAll()
    except ImportError:
        pytest.skip("Required dependency not available")

    # Should have either primary_detector or extended_detectors
    has_detector = isinstance(probe.primary_detector, str) or (
        probe.extended_detectors and len(probe.extended_detectors) > 0
    )
    assert has_detector, "Probe must have a detector specified"


def test_beavertails_tags():
    """Test that BeaverTails probes have appropriate tags."""
    try:
        probe = garak.probes.beavertails.BeaverTailsAll()
    except ImportError:
        pytest.skip("Required dependency not available")

    assert isinstance(probe.tags, (list, tuple)), "tags should be iterable"
    assert len(probe.tags) > 0, "probe should have at least one tag"

    # Check for expected tags
    tags_str = " ".join(str(t) for t in probe.tags)
    assert any(
        tag in tags_str for tag in ["security", "owasp", "payload", "jailbreak"]
    ), "Should have relevant security-related tags"


BEAVERTAILS_PROBES = [
    classname
    for (classname, active) in garak._plugins.enumerate_plugins("probes")
    if classname.startswith("probes.beavertails")
]


@pytest.mark.parametrize("klassname", BEAVERTAILS_PROBES)
def test_beavertails_probe_instantiation(klassname):
    """Test that all BeaverTails probe classes can be instantiated."""
    try:
        probe = garak._plugins.load_plugin(klassname)
        assert probe is not None
    except ImportError as e:
        pytest.skip(f"Required dependency not available: {e}")
    except Exception as e:
        pytest.fail(f"Failed to instantiate {klassname}: {e}")


@pytest.mark.parametrize("klassname", BEAVERTAILS_PROBES)
def test_beavertails_probe_prompts(klassname):
    """Test that BeaverTails probes load prompts correctly."""
    try:
        probe = garak._plugins.load_plugin(klassname)
    except ImportError:
        pytest.skip("Required dependency not available")

    # Note: prompts may be empty if dataset is not available, but structure should be correct
    assert hasattr(probe, "prompts"), f"{klassname} should have prompts attribute"
    assert isinstance(probe.prompts, list), "prompts should be a list"


@pytest.mark.parametrize("klassname", BEAVERTAILS_PROBES)
def test_beavertails_probe_active_no_deps(klassname):
    """Test that only probes without external dependencies are marked as active."""
    try:
        probe = garak._plugins.load_plugin(klassname)
    except ImportError:
        # If we can't import it, it should be marked inactive
        plugin_name_parts = klassname.split(".")
        module_name = "garak." + ".".join(plugin_name_parts[:-1])
        class_name = plugin_name_parts[-1]
        import importlib

        mod = importlib.import_module(module_name)
        probe_class = getattr(mod, class_name)
        if probe_class.active:
            pytest.fail(f"{klassname} is marked as active but has missing dependencies")
        pytest.skip("Required dependency not available")

    # If we got here, we were able to import it
    # Active probes should not require external dependencies
    if probe.active and len(probe.extra_dependency_names) == 0:
        assert True  # Good state
    elif probe.active:
        pytest.fail(
            f"{klassname} is active but lists extra dependencies: {probe.extra_dependency_names}"
        )


def test_beavertails_harm_categories():
    """Test that all expected harm categories have probe classes."""
    expected_categories = [
        garak.probes.beavertails.BeaverTailsAnimalAbuse,
        garak.probes.beavertails.BeaverTailsChildAbuse,
        garak.probes.beavertails.BeaverTailsControversialTopics,
        garak.probes.beavertails.BeaverTailsDiscrimination,
        garak.probes.beavertails.BeaverTailsDrugAbuse,
        garak.probes.beavertails.BeaverTailsFinancialCrime,
        garak.probes.beavertails.BeaverTailsHateSpeech,
        garak.probes.beavertails.BeaverTailsMisinformation,
        garak.probes.beavertails.BeaverTailsUnethicalBehavior,
        garak.probes.beavertails.BeaverTailsPrivacyViolation,
        garak.probes.beavertails.BeaverTailsSelfHarm,
        garak.probes.beavertails.BeaverTailsSexualContent,
        garak.probes.beavertails.BeaverTailsTerrorism,
        garak.probes.beavertails.BeaverTailsViolence,
    ]

    for probe_class in expected_categories:
        assert hasattr(
            probe_class, "data_file"
        ), f"Probe {probe_class.__name__} missing data_file"
        assert (
            probe_class.data_file is not None
        ), f"Probe {probe_class.__name__} has no data_file value"
        assert probe_class.data_file.startswith(
            "beavertails_"
        ), f"Probe data_file should start with 'beavertails_'"
