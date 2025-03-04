# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import pytest
import re

from garak import _config, _plugins

_config.load_base_config()

PROBES = [classname for (classname, active) in _plugins.enumerate_plugins("probes")]

DETECTORS = [
    classname
    for (classname, active) in _plugins.enumerate_plugins(
        "detectors", skip_base_classes=False
    )
]
DETECTOR_BARE_NAMES = [".".join(d.split(".")[1:]) for d in DETECTORS]

BCP_LENIENT_RE = re.compile(r"[a-z]{2}([\-A-Za-z]*)")

with open(
    _config.transient.package_dir / "data" / "misp_descriptions.tsv",
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
        or len(probe_class.recommended_detector) > 0
    )


@pytest.mark.parametrize("classname", PROBES)
def test_probe_detector_exists(classname):
    plugin_name_parts = classname.split(".")
    module_name = "garak." + ".".join(plugin_name_parts[:-1])
    class_name = plugin_name_parts[-1]
    mod = importlib.import_module(module_name)
    probe_class = getattr(mod, class_name)
    probe_detectors = probe_class.recommended_detector + probe_class.extended_detectors
    if probe_class.primary_detector is not None:
        probe_detectors += [probe_class.primary_detector]
    assert set(probe_detectors).issubset(DETECTOR_BARE_NAMES)


@pytest.mark.parametrize("classname", PROBES)
def test_probe_structure(classname):

    m = importlib.import_module("garak." + ".".join(classname.split(".")[:-1]))
    c = getattr(m, classname.split(".")[-1])

    # any parameter that has a default must be supported
    unsupported_defaults = []
    if c._supported_params is not None:
        if hasattr(g, "DEFAULT_PARAMS"):
            for k, _ in c.DEFAULT_PARAMS.items():
                if k not in c._supported_params:
                    unsupported_defaults.append(k)
    assert unsupported_defaults == []


@pytest.mark.parametrize("classname", PROBES)
def test_probe_metadata(classname):
    p = _plugins.load_plugin(classname)
    assert isinstance(p.goal, str), "probe goals should be a text string"
    assert len(p.goal) > 0, "probes must state their general goal"
    assert isinstance(
        p.bcp47, str
    ), "language codes should be described in a comma-separated string of bcp47 tags or *"
    bcp47_parts = p.bcp47.split(",")
    for bcp47_part in bcp47_parts:
        assert bcp47_part == "*" or re.match(
            BCP_LENIENT_RE, bcp47_part
        ), "langs must be described with either * or a bcp47 code"
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
