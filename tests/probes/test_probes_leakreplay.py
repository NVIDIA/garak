# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import inspect
import pytest

import garak
import garak._config
import garak._plugins
import garak.attempt
import garak.cli
import garak.probes.leakreplay


def test_leakreplay_hitlog():

    args = "-m test.Blank -p leakreplay -d always.Fail".split()
    garak.cli.main(args)


def test_leakreplay_output_count():
    generations = 1
    garak._config.load_base_config()
    garak._config.transient.reportfile = open(os.devnull, "w+", encoding="utf-8")
    garak._config.plugins.probes["leakreplay"]["generations"] = generations
    a = garak.attempt.Attempt(prompt="test")
    p = garak._plugins.load_plugin(
        "probes.leakreplay.LiteratureCloze", config_root=garak._config
    )
    g = garak._plugins.load_plugin("generators.test.Blank", config_root=garak._config)
    p.generator = g
    results = p._execute_all([a])
    assert len(a.outputs) == generations


def test_leakreplay_handle_incomplete_attempt():
    p = garak.probes.leakreplay.LiteratureCloze()
    a = garak.attempt.Attempt(prompt="IS THIS BROKEN")
    a.outputs = [garak.attempt.Message(s) for s in ["", None]]
    p._postprocess_hook(a)


def test_leakreplay_module_structure():
    # Get all probe classes from leakreplay module
    leakreplay_classes = []
    for name, obj in inspect.getmembers(garak.probes.leakreplay):
        if (
            inspect.isclass(obj)
            and obj.__module__ == "garak.probes.leakreplay"
            and not name.endswith("Mixin")  # Skip mixin classes
            and issubclass(obj, garak.probes.Probe)
        ):
            leakreplay_classes.append(obj)
            assert (
                "Cloze" in name or "Complete" in name
            ), f"Leakreplay probe class {name} does not bear 'Cloze' or 'Complete'"

    # Test that we found at least 8 classes (there should be more)
    assert len(leakreplay_classes) >= 8, "Not all leakreplay probe classes were found"


LEAKREPLAY_PROBES = [
    classname
    for (classname, active) in garak._plugins.enumerate_plugins("probes")
    if classname.startswith("probes.leakreplay")
]


@pytest.mark.parametrize("klassname", LEAKREPLAY_PROBES)
def test_leakreplay_probe_structure(klassname):
    """Test that all leakreplay probe classes can be instantiated and function correctly.

    This test verifies:
    1. All probe classes can be instantiated without errors
    2. The string replacement works properly (with special characters like %)
    3. Tag inheritance works correctly from parent classes
    """

    # Test tag inheritance - check that all expected tags are inherited properly
    expected_tags = [
        "avid-effect:security:S0301",
        "owasp:llm10",
        "owasp:llm06",
        "quality:Security:ExtractionInversion",
        "payload:leak:training",
    ]
    expected_tag_count = len(expected_tags)

    probe_class = getattr(garak.probes.leakreplay, klassname)

    # Also verify the tag count & content to ensure no duplicates or extras
    if probe_class.__name__.endswith(
        ("Cloze", "ClozeFull", "Complete", "CompleteFull")
    ):
        assert (
            len(probe_class.tags) >= expected_tag_count
        ), f"incorrect number of tags: {len(probe_class.tags)} instead of >= {expected_tag_count}"
        for tag in expected_tags:
            assert tag in probe_class.tags, f"missing expected tag: {tag}"

    # instance checks
    probe = None
    try:
        # Should initialize without errors
        probe = garak._plugins.load_plugin(klassname)

        # Verify that prompts were created correctly (this tests the string replacement)
        assert len(probe.prompts) > 0, "no prompts"

        assert len(probe.prompts) == len(
            probe.triggers
        ), "mismatch between prompt and trigger count"

        # Test template handling (specific to our string replacement fix)
        if hasattr(probe, "_attempt_prestore_hook"):
            # Create an attempt with a prompt containing % characters
            # This would fail if we were using % string formatting
            special_prompt = "Test with 100% special % characters"
            a = garak.attempt.Attempt(prompt=special_prompt)

            # Should not raise errors when % is in the prompt
            probe._attempt_prestore_hook(a, 0)

    except Exception as e:
        assert False, f"Failed to initialize {probe_class.__name__}: {e}"


CLOZE_PROBES = [
    classname
    for (classname, active) in garak._plugins.enumerate_plugins("probes")
    if classname.startswith("probes.leakreplay") and "Cloze" in classname
]


@pytest.mark.parametrize("klassname", CLOZE_PROBES)
def test_leakreplay_probe_structure(klassname):
    probe = garak._plugins.load_plugin(klassname)

    for prompt in probe.prompts:
        assert (
            "%s" not in prompt
        ), "still has passage replacement marker %s in prompt, '{prompt}'"
        assert "[MASK]" in prompt, "missing [MASK] in prompt, '{prompt}'"

    assert hasattr(probe, "_postprocess_hook"), "Cloze probe missing _postprocess_hook"
    test_attempt = garak.attempt.Attempt(prompt="test")
    test_attempt.outputs = [garak.attempt.Message("<name>Test</name>")]
    processed = probe._postprocess_hook(test_attempt)
    # Check that name tags are properly removed (part of postprocessing)
    assert "<name>" not in processed.conversations[0].turns[-1].content.text
