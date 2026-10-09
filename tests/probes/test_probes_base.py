# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os

import pytest

from garak import _config, _plugins
import garak.attempt
import garak.probes


class _MinimalIterativeProbe(garak.probes.IterativeProbe):
    """Smallest viable IterativeProbe: one initial turn, no follow-ups.

    Keeps the base class's termination bound reachable without the attack
    generator the in-tree subclasses need credentials for."""

    lang = "en"
    goal = "exercise the base iterative loop"
    end_condition = "verify"
    max_calls_per_conv = 1
    primary_detector = "always.Pass"

    def _create_init_attempts(self):
        return [self._mint_attempt(prompt="hello")]

    def _generate_next_attempts(self, last_attempt):
        return []


@pytest.fixture(autouse=True)
def base_config():
    """Probing writes attempts out, so a report sink has to exist."""
    _config.load_base_config()
    with open(os.devnull, "w+", encoding="utf-8") as fh:
        _config.transient.reportfile = fh
        yield
    _config.transient.reportfile = None


@pytest.fixture
def blank_generator():
    return _plugins.load_plugin("generators.test.Blank")


@pytest.mark.parametrize("cap", [None, 4])
def test_iterative_probe_runs_whatever_the_cap(cap, blank_generator):
    """An unset cap means no cap; it must not be multiplied into the bound."""
    original = _config.run.soft_probe_prompt_cap
    _config.run.soft_probe_prompt_cap = cap
    try:
        probe = _MinimalIterativeProbe()
        probe.soft_probe_prompt_cap = cap
        probe.probe(blank_generator)
    finally:
        _config.run.soft_probe_prompt_cap = original


def test_iterative_probe_unset_cap_leaves_bound_unlimited(blank_generator):
    """With no cap configured the termination bound stays infinite."""
    original = _config.run.soft_probe_prompt_cap
    _config.run.soft_probe_prompt_cap = None
    try:
        probe = _MinimalIterativeProbe()
        probe.soft_probe_prompt_cap = None
        probe.probe(blank_generator)
        assert probe.max_attempts_before_termination == float(
            "inf"
        ), "an unset cap must leave the iteration bound unlimited"
    finally:
        _config.run.soft_probe_prompt_cap = original


def test_iterative_probe_set_cap_bounds_iteration(blank_generator):
    """A configured cap still scales the bound by the number of initial turns."""
    original = _config.run.soft_probe_prompt_cap
    _config.run.soft_probe_prompt_cap = 4
    try:
        probe = _MinimalIterativeProbe()
        probe.soft_probe_prompt_cap = 4
        probe.probe(blank_generator)
        assert (
            probe.max_attempts_before_termination == 4
        ), "one initial turn with a cap of 4 must bound iteration at 4"
    finally:
        _config.run.soft_probe_prompt_cap = original


def test_iterative_probe_opt_out_leaves_bound_unlimited(blank_generator):
    """follow_prompt_cap=False must bypass the bound even with a cap set."""
    original = _config.run.soft_probe_prompt_cap
    _config.run.soft_probe_prompt_cap = 4
    try:
        probe = _MinimalIterativeProbe()
        probe.soft_probe_prompt_cap = 4
        probe.follow_prompt_cap = False
        probe.probe(blank_generator)
        assert probe.max_attempts_before_termination == float(
            "inf"
        ), "opting out of the cap must leave the iteration bound unlimited"
    finally:
        _config.run.soft_probe_prompt_cap = original
