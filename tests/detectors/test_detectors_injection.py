# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak.attempt
import garak.payloads
import garak.detectors.base
import garak.probes.injection
from garak import _plugins


def test_load_jinja_detector():
    d = _plugins.load_plugin("detectors.injection.JinjaTemplateDetector")
    assert isinstance(d, garak.detectors.base.Detector)


def test_load_python_detector():
    d = _plugins.load_plugin("detectors.injection.PythonCodeExecution")
    assert isinstance(d, garak.detectors.base.Detector)


def test_load_sqli_success_detector():
    d = _plugins.load_plugin("detectors.injection.SQLiSuccess")
    assert isinstance(d, garak.detectors.base.Detector)


def test_load_sqli_echo_detector():
    d = _plugins.load_plugin("detectors.injection.SQLiEcho")
    assert isinstance(d, garak.detectors.base.Detector)


def test_jinja():
    d = _plugins.load_plugin("detectors.injection.JinjaTemplateDetector")
    payload_template = (
        garak.probes.injection.JinjaTemplatePythonInjection.payload_template
    )
    payload = payload_template.format(
        "__import__('os').system('touch /tmp/garak.pwnd')"
    )
    a = garak.attempt.Attempt()
    a.prompt = "test prompt"
    a.outputs = [payload]
    assert d.detect(a) == [1.0], f"{payload} contains a valid Jinja template"

    # Adding another open bracket breaks the template
    payload = payload_template.format(
        "{__import__('os').system('touch /tmp/garak.pwnd')"
    )
    a = garak.attempt.Attempt()
    a.prompt = "test prompt"
    a.outputs = [payload]
    assert d.detect(a) == [0.0], f"{payload} does not contain a valid Jinja template"


def test_python_code():
    d = _plugins.load_plugin("detectors.injection.PythonCodeExecution")
    payload_template = (
        garak.probes.injection.JinjaTemplatePythonInjection.payload_template
    )
    payload = payload_template.format(
        "__import__('os').system('touch /tmp/garak.pwnd')"
    )
    a = garak.attempt.Attempt()
    a.prompt = "test prompt"
    a.outputs = [payload]
    assert d.detect(a) == [1.0], f"{payload} contains potential code execution"

    payload = payload_template.format("test response")
    a = garak.attempt.Attempt()
    a.prompt = "test prompt"
    a.outputs = [payload]
    assert d.detect(a) == [0.0], f"{payload} does not contain potential code execution"


def test_sqli_success():
    d = _plugins.load_plugin("detectors.injection.SQLiSuccess")
    a = garak.attempt.Attempt()
    a.prompt = "test prompt"
    a.outputs = ["SUCCESS"]
    assert d.detect(a) == [1.0], f"output does not include the success message"

    a = garak.attempt.Attempt()
    a.prompt = "test prompt"
    a.outputs = ["FAILURE"]
    assert d.detect(a) == [0.0], f"output does not match the failure message"


def test_sqli_echo():
    d = _plugins.load_plugin("detectors.injection.SQLiEcho")
    payloads = garak.payloads.load("sql_injection").payloads
    for payload in payloads:
        a = garak.attempt.Attempt()
        a.prompt = "test prompt"
        a.outputs = [payload]
        assert d.detect(a) == [1.0], f"{payload} is not detected as SQL injection"

    a = garak.attempt.Attempt()
    payload = "SELECT * FROM stuff WHERE attribute='whatever'"
    a.prompt = "test prompt"
    a.outputs = [payload]
    assert d.detect(a) == [0.0], f"{payload} does not contain a SQL injection"
