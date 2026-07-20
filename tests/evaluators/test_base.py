# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak._config
import garak.analyze
import garak.attempt
import garak.evaluators.base
import garak.resources.ansi


class _CalibrationStub:
    """Minimal calibration stub that raises on any call to defcon_and_comment."""

    def __init__(self, zscore):
        self._zscore = zscore

    def get_z_score(self, probe_module, probe_classname, detector_module, detector_classname, score):
        return self._zscore

    def defcon_and_comment(self, *args, **kwargs):
        raise AssertionError("get_z_rating must not call defcon_and_comment")


def _make_evaluator(zscore):
    ev = garak.evaluators.base.Evaluator.__new__(garak.evaluators.base.Evaluator)
    ev.calibration = _CalibrationStub(zscore)
    return ev


@pytest.mark.parametrize("zscore", [-2.0, -0.5, 0.0, 0.5, 2.0])
def test_get_z_rating_returns_symbol(zscore):
    ev = _make_evaluator(zscore)
    returned_z, symbol = ev.get_z_rating("probe.Probe", "detector.Detector", 50)
    assert returned_z == zscore
    assert symbol in ev.SYMBOL_SET.values()


def test_get_z_rating_none_zscore():
    ev = _make_evaluator(None)
    returned_z, symbol = ev.get_z_rating("probe.Probe", "detector.Detector", 50)
    assert returned_z is None
    assert symbol == ""


@pytest.mark.parametrize(
    "print_func_name", ["print_results_wide", "print_results_narrow"]
)
def test_print_results_prints_failing_output(capsys, monkeypatch, print_func_name):
    # messages hold Message objects, so the text has to come from .text
    monkeypatch.setattr(garak._config.system, "verbose", 1, raising=False)
    monkeypatch.setattr(garak._config.system, "show_z", False, raising=False)
    ev = garak.evaluators.base.Evaluator.__new__(garak.evaluators.base.Evaluator)
    ev.probename = "probe.Probe"
    messages = [garak.attempt.Message(text="unsafe\noutput"), None]
    getattr(ev, print_func_name)("detector.Detector", 0, 1, messages)
    assert "unsafe output" in capsys.readouterr().out


@pytest.mark.parametrize(
    "print_func_name", ["print_results_wide", "print_results_narrow"]
)
@pytest.mark.parametrize("payload", garak.resources.ansi.LIVE_PAYLOADS)
def test_print_results_escapes_ansi_payloads(
    capsys, monkeypatch, print_func_name, payload
):
    # a successful ansiescape probe must not replay its payload into the terminal
    monkeypatch.setattr(garak._config.system, "verbose", 1, raising=False)
    monkeypatch.setattr(garak._config.system, "show_z", False, raising=False)
    ev = garak.evaluators.base.Evaluator.__new__(garak.evaluators.base.Evaluator)
    ev.probename = "probe.Probe"
    getattr(ev, print_func_name)(
        "detector.Detector", 0, 1, [garak.attempt.Message(text=payload)]
    )
    # garak colours its own status line, so only the response line is in scope here
    response_lines = [
        line for line in capsys.readouterr().out.splitlines() if line.startswith("❌")
    ]
    assert response_lines
    for line in response_lines:
        assert not any(
            ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in line
        ), f"control character survived into {line!r}"


def test_escape_control_chars_keeps_ordinary_text():
    # non-control characters, including non-ASCII, have to survive untouched
    text = "plain text with unicode: é中文 and symbols !@#"
    assert garak.evaluators.base._escape_control_chars(text) == text
