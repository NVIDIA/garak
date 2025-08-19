# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import re

import garak.probes.doctor
from garak import _plugins

MARKER = "{{HARMFUL_BEHAVIOR}}"
DOCTOR_PROBES = [
    classname
    for (classname, active) in _plugins.enumerate_plugins("probes")
    if classname.startswith("probes.doctor")
]


@pytest.mark.parametrize("classname", DOCTOR_PROBES)
def test_template_marker_presence(classname):
    if classname != "probes.doctor.Puppetry":
        p = _plugins.load_plugin(classname)
        for prompt_template in p.templates:
            assert (
                MARKER in prompt_template
            ), f"prompt template must contain {MARKER}, got '{prompt_template}'"


@pytest.mark.parametrize("classname", DOCTOR_PROBES)
def test_prompt_marker_absence(classname):
    r = r"\{\{[A-Z_]*}}"
    p = _plugins.load_plugin(classname)
    for prompt in p.prompts:
        markers = re.findall(r, prompt)
        assert (
            markers == list()
        ), f"Template markers {markers} left in final prompt, '{prompt}'"
