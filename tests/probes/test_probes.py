# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import langcodes
import pytest
import re

from garak import _config, _plugins
from garak.attempt import Turn, Conversation, Message, Attempt
import garak.probes

PROBES = [classname for (classname, active) in _plugins.enumerate_plugins("probes")]

DETECTORS = [
    classname
    for (classname, active) in _plugins.enumerate_plugins(
        "detectors", skip_base_classes=False
    )
]
DETECTOR_BARE_NAMES = [".".join(d.split(".")[1:]) for d in DETECTORS]


with open(
    _config.transient.package_dir / "data" / "tags.misp.tsv",
    "r",
    encoding="utf-8",
) as misp_data:
    MISP_TAGS = [line.split("\t")[0] for line in misp_data.read().split("\n")]


@pytest.mark.parametrize("classname", PROBES)
def test_detector_specified(classname):  # every probe should give detector(s)
    plugin_name_parts = classname.split(".")
    module_name = "garak." + ".".join(plugin_name_parts[:-1])
    class_name = plugin_name_parts[-1]
    mod = importlib.import_module(module_name)
    probe_class = getattr(mod, class_name)
    assert (
        isinstance(probe_class.primary_detector, str)
        or len(probe_class.extended_detectors) > 0
    ), "One primary detector (str), or a non-empty list of extended detector, must be given"


@pytest.mark.parametrize("classname", PROBES)
def test_probe_detector_exists(classname):
    plugin_name_parts = classname.split(".")
    module_name = "garak." + ".".join(plugin_name_parts[:-1])
    class_name = plugin_name_parts[-1]
    mod = importlib.import_module(module_name)
    probe_class = getattr(mod, class_name)
    probe_detectors = list(probe_class.extended_detectors)
    if probe_class.primary_detector is not None:
        probe_detectors.append(probe_class.primary_detector)
    assert set(probe_detectors).issubset(DETECTOR_BARE_NAMES)


@pytest.mark.parametrize("classname", PROBES)
def test_probe_structure(classname):

    m = importlib.import_module("garak." + ".".join(classname.split(".")[:-1]))
    c = getattr(m, classname.split(".")[-1])

    # any parameter that has a default must be supported
    unsupported_defaults = []
    if c._supported_params is not None:
        if hasattr(c, "DEFAULT_PARAMS"):
            for k, _ in c.DEFAULT_PARAMS.items():
                if k not in c._supported_params:
                    unsupported_defaults.append(k)
    assert unsupported_defaults == []


@pytest.mark.parametrize("classname", PROBES)
def test_probe_metadata(classname):
    try:
        p = _plugins.load_plugin(classname)
    except ModuleNotFoundError:
        pytest.skip("required deps not present")
    assert isinstance(p.goal, str), "probe goals should be a text string"
    assert len(p.goal) > 0, "probes must state their general goal"
    assert p.lang is not None and (
        p.lang == "*" or langcodes.tag_is_valid(p.lang)
    ), "lang must be either * or a BCP47 code"
    assert isinstance(
        p.doc_uri, str
    ), "probes should give a doc uri describing/citing the attack"
    if len(p.doc_uri) > 1:
        assert p.doc_uri.lower().startswith(
            "http"
        ), "doc uris should be fully-specified absolute HTTP addresses"
    assert isinstance(p.modality, dict), "probes need to describe available modalities"
    assert "in" in p.modality, "probe modalities need an in descriptor"
    assert isinstance(p.modality["in"], set), "modality descriptors must be sets"
    assert p.tier is not None, "probe tier must be specified"
    assert isinstance(p.tier, garak.probes.Tier), "probe tier must be one of type Tier'"
    if p.active:
        assert (
            p.extra_dependency_names == []
        ), "active must be False for Probes requiring external modules, so that they're not run by default"


@pytest.mark.parametrize("plugin_name", PROBES)
def test_check_docstring(plugin_name):
    plugin_name_parts = plugin_name.split(".")
    module_name = "garak." + ".".join(plugin_name_parts[:-1])
    class_name = plugin_name_parts[-1]
    mod = importlib.import_module(module_name)
    doc = getattr(getattr(mod, class_name), "__doc__")
    doc_paras = re.split(r"\s*\n\s*\n\s*", doc)
    assert (
        len(doc_paras) >= 2
    )  # probe class doc should have a summary, two newlines, then a paragraph giving more depth, then optionally more words
    assert (
        len(doc_paras[0]) > 0
    )  # the first paragraph of the probe docstring should not be empty


@pytest.mark.parametrize("classname", PROBES)
def test_tag_format(classname):
    plugin_name_parts = classname.split(".")
    module_name = "garak." + ".".join(plugin_name_parts[:-1])
    class_name = plugin_name_parts[-1]
    mod = importlib.import_module(module_name)
    cls = getattr(mod, class_name)
    assert (
        cls.tags != [] or cls.active == False
    )  # all probes should have at least one tag
    for tag in cls.tags:  # should be MISP format
        assert type(tag) == str
        for part in tag.split(":"):
            assert re.match(r"^[A-Za-z0-9_\-]+$", part)
        if tag.split(":")[0] != "payload":
            assert tag in MISP_TAGS


def test_probe_prune_alignment():
    p = _plugins.load_plugin("probes.glitch.Glitch")
    assert len(p.prompts) == _config.run.soft_probe_prompt_cap
    assert len(p.triggers) == _config.run.soft_probe_prompt_cap
    assert p.triggers[0] in p.prompts[0]
    assert p.triggers[-1] in p.prompts[-1]


PROMPT_EXAMPLES = [
    "test example",
    Message(text="test example"),
    Conversation([Turn(role="user", content=Message(text="test example"))]),
    Conversation(
        [
            Turn(role="system", content=Message(text="test system")),
            Turn(role="user", content=Message(text="test example")),
        ]
    ),
]


@pytest.mark.parametrize("prompt", PROMPT_EXAMPLES)
def test_mint_attempt(prompt):
    import garak.probes.base

    probe = garak.probes.base.Probe()
    attempt = probe._mint_attempt(prompt)
    assert isinstance(attempt, Attempt)
    for turn in attempt.prompt.turns:
        assert isinstance(turn, Turn)
    assert attempt.prompt.last_message().text == "test example"


@pytest.mark.parametrize("prompt", PROMPT_EXAMPLES)
def test_mint_attempt_with_run_system_prompt(prompt):
    import garak.probes.base

    expected_system_prompt = "test system prompt"
    probe = garak.probes.base.Probe()
    probe.system_prompt = expected_system_prompt

    if isinstance(prompt, Conversation):
        try:
            expected_system_prompt = prompt.last_message("system").text
        except ValueError as e:
            pass

    attempt = probe._mint_attempt(prompt)
    assert isinstance(attempt, Attempt)
    for turn in attempt.prompt.turns:
        assert isinstance(turn, Turn)
    assert attempt.prompt.last_message().text == "test example"
    assert attempt.prompt.last_message("system").text == expected_system_prompt
    system_message = [turn for turn in attempt.prompt.turns if turn.role == "system"]
    assert len(system_message) == 1
