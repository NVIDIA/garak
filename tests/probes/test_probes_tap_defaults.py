# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""The OpenAI evaluator model TAP defaults to must be a current one."""

import inspect

import pytest

import garak.generators.openai
from garak.probes.tap import PAIR, TAP

RETIRED_EVALUATORS = ("gpt-5-nano",)  # retired by OpenAI on 2026-12-11


@pytest.mark.parametrize("probe_class", [TAP, PAIR])
def test_probe_default_evaluator_is_not_retired(probe_class):
    name = probe_class.DEFAULT_PARAMS["evaluator_model_name"]
    assert name not in RETIRED_EVALUATORS
    assert name in garak.generators.openai.chat_models


def test_run_tap_default_evaluator_matches_probes():
    from garak.resources.tap.tap_main import run_tap

    default = inspect.signature(run_tap).parameters["evaluator_model_name"].default
    assert default == TAP.DEFAULT_PARAMS["evaluator_model_name"]
    assert default not in RETIRED_EVALUATORS
