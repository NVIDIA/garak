# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import inspect
import pytest
import types

import langcodes

from garak import _plugins
from garak.attempt import Attempt, Message
from garak.configurable import Configurable
from garak.detectors.base import Detector
from garak.exception import APIKeyMissingError
import garak.detectors.base

DEFAULT_GENERATOR_NAME = "garak test"
DEFAULT_PROMPT_TEXT = "especially the lies"


DETECTORS = [
    classname
    for (classname, active) in _plugins.enumerate_plugins("detectors")
    if classname
    not in [  # filter detector classes used as templates
        "detectors.packagehallucination.PackageHallucinationDetector",
    ]
]
DOES_NOT_RELAY_NONE = [
    "detectors.always.Fail",
    "detectors.always.Pass",
    "detectors.always.Random",
]


@pytest.mark.parametrize("classname", DETECTORS)
def test_detector_structure(classname):

    m = importlib.import_module("garak." + ".".join(classname.split(".")[:-1]))
    d = getattr(m, classname.split(".")[-1])

    detect_signature = inspect.signature(d.detect)

    # has method detect
    assert "detect" in dir(d), f"detector {classname} must have a method detect"
    # _call_model has a generations_this_call param
    assert (
        "attempt" in detect_signature.parameters
    ), f"{classname}.detect() must accept parameter attempt"
    # any parameter that has a default must be supported
    unsupported_defaults = []
    if d._supported_params is not None:
        if hasattr(d, "DEFAULT_PARAMS"):
            for k, _ in d.DEFAULT_PARAMS.items():
                if k not in d._supported_params:
                    unsupported_defaults.append(k)
    assert (
        unsupported_defaults == []
    ), f"_supported_params must contain all DEFAULT_PARAMS; {unsupported_defaults} missing"


@pytest.mark.parametrize("classname", DETECTORS)
def test_detector_detect(classname):

    m = importlib.import_module("garak." + ".".join(classname.split(".")[:-1]))
    dc = getattr(m, classname.split(".")[-1])
    try:
        di = dc.__new__(dc)
        di.__init__()
    except APIKeyMissingError:
        pytest.skip(f"API key unavailable for {classname}")

    assert isinstance(di, Detector), "detectors must eventually inherit from Detector"
    assert isinstance(di, Configurable), "detectors must be configurable"

    a = Attempt()
    # dressing required to get 'some' detectors to return results
    a.notes["trigger"] = "x"
    a.notes["triggers"] = ["x", "x", "x", "x"]
    a.notes["repeat_word"] = "x"
    a.probe_classname = "test.Blank"

    a.prompt = Message("", lang=di.lang_spec.split(",")[0])
    a.notes["format"] = "local filename"
    a.outputs = ["test value", "", None, Message()]
    a.detector_results = {"x": [0.0, None]}
    try:
        results = di.detect(a)
    except APIKeyMissingError:
        pytest.skip(f"API key unavailable for {classname}")

    assert isinstance(
        results, (list, types.GeneratorType)
    ), "detect() should return an ordered iterable"
    for entry in results:
        # detect() should skip non-evaluated items from output. NB this breaks output:result alignment
        assert (
            isinstance(entry, float) or entry is None
        ), "detect() must return a list of floats or Nones"
        if isinstance(entry, float):
            assert 0.0 <= entry <= 1.0, "detect() values should be between 0.0 and 1.0"
    assert len(list(results)) <= len(
        list(a.outputs)
    ), "detect() should return no more values than # attempt outputs provided"

    if classname == "detectors.always.Passthru":
        return

    results = di.detect(a)
    if not isinstance(di, garak.detectors.base.FileDetector):
        assert len(list(results)) == len(
            a.outputs
        ), "detector should return as many results as in outputs"
        if not classname in DOES_NOT_RELAY_NONE:
            for output, result in zip(a.outputs, list(results)):
                if output is not None and output.text is not None:
                    assert isinstance(
                        result, float
                    ), "detector result entries must be a float or None"
                else:
                    assert (
                        result is None
                    ), "if detector result entry is not a float, it must be a None"


@pytest.mark.parametrize("classname", DETECTORS)
def test_detector_metadata(classname):
    if classname.startswith("detectors.base."):
        return
    # instantiation can fail e.g. due to missing API keys
    # luckily this info is descriptive rather than behaviour-altering, so we don't need an instance
    m = importlib.import_module("garak." + ".".join(classname.split(".")[:-1]))
    dc = getattr(m, classname.split(".")[-1])
    d = dc.__new__(dc)
    assert d.lang_spec == "*" or all(
        [langcodes.tag_is_valid(l) for l in d.lang_spec.split(",")]
    ), "detector lang must be either * or a comma-separated list of BCP47 language codes"
    assert isinstance(d.doc_uri, str) or d.doc_uri is None
    if isinstance(d.doc_uri, str):
        assert len(d.doc_uri) > 1, "string doc_uris must be populated. else use None"
        assert d.doc_uri.lower().startswith(
            "http"
        ), "doc uris should be fully-specified absolute HTTP addresses"
