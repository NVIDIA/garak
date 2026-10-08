# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.attempt import Attempt, Message
from garak.probes.base import IterativeProbe


class MinimalIterativeProbe(IterativeProbe):
    end_condition = "detector"


def test_iterative_probe_treats_unset_prompt_cap_as_unbounded(mocker):
    """An unset soft prompt cap must not prevent iterative probe execution."""
    probe = MinimalIterativeProbe()
    probe.follow_prompt_cap = True
    probe.soft_probe_prompt_cap = None
    probe.max_calls_per_conv = 1

    mocker.patch.object(
        probe,
        "_create_init_attempts",
        return_value=[Attempt(prompt=Message("initial prompt"))],
    )
    execute_all = mocker.patch.object(probe, "_execute_all", return_value=[])

    assert probe.probe(generator=None) == []
    assert probe.max_attempts_before_termination == float("inf")
    execute_all.assert_called_once()


def test_iterative_probe_applies_a_set_prompt_cap(mocker):
    """A configured soft prompt cap still limits iterative probe execution."""
    probe = MinimalIterativeProbe()
    probe.follow_prompt_cap = True
    probe.soft_probe_prompt_cap = 2
    probe.max_calls_per_conv = 1

    mocker.patch.object(
        probe,
        "_create_init_attempts",
        return_value=[Attempt(prompt=Message("initial prompt"))],
    )
    mocker.patch.object(probe, "_execute_all", return_value=[])

    probe.probe(generator=None)

    assert probe.max_attempts_before_termination == 2
