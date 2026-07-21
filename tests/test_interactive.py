# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from garak.interactive import GarakCommands

# do_probe is wrapped by @cmd2.with_argparser; call the original function
# directly (functools.wraps preserves __wrapped__) so tests don't need a
# full cmd2.Cmd/CommandSet registration or a real garak config.
_do_probe = GarakCommands.do_probe.__wrapped__


def _make_cmds(probe=None, generator=None):
    cmds = GarakCommands()
    cmds._cmd = SimpleNamespace(
        target_type="test",
        target_model="test",
        probe=probe,
        generator=generator,
        eval_threshold=0.5,
    )
    return cmds


def test_do_probe_sets_probe_when_none_was_previously_set():
    """A probe name passed on the first `probe <name>` call (no probe set yet)
    must actually be stored, not silently dropped."""
    cmds = _make_cmds(probe=None)
    args = SimpleNamespace(probe="mynewprobe")

    with (
        patch("garak.interactive.ThresholdEvaluator", MagicMock()),
        patch("garak.harnesses.probewise.ProbewiseHarness", MagicMock()),
    ):
        _do_probe(cmds, args)

    assert cmds._cmd.probe == "mynewprobe"


def test_do_probe_does_not_crash_when_generator_fails_to_load():
    """If loading the generator raises ImportError/AttributeError, do_probe
    must stop instead of falling through to use the never-assigned
    `generator` local variable."""
    cmds = _make_cmds(probe=None)
    args = SimpleNamespace(probe="mynewprobe")

    threshold_evaluator = MagicMock()
    harness_cls = MagicMock()
    with (
        patch("garak._plugins.load_plugin", side_effect=ImportError("boom")),
        patch("garak.interactive.ThresholdEvaluator", threshold_evaluator),
        patch("garak.harnesses.probewise.ProbewiseHarness", harness_cls),
    ):
        _do_probe(cmds, args)

    threshold_evaluator.assert_not_called()
    harness_cls.assert_not_called()


def test_do_probe_does_not_crash_when_generator_name_is_invalid():
    """Same as above, for the AttributeError branch."""
    cmds = _make_cmds(probe=None)
    args = SimpleNamespace(probe="mynewprobe")

    threshold_evaluator = MagicMock()
    harness_cls = MagicMock()
    with (
        patch("garak._plugins.load_plugin", side_effect=AttributeError("boom")),
        patch("garak.interactive.ThresholdEvaluator", threshold_evaluator),
        patch("garak.harnesses.probewise.ProbewiseHarness", harness_cls),
    ):
        _do_probe(cmds, args)

    threshold_evaluator.assert_not_called()
    harness_cls.assert_not_called()
