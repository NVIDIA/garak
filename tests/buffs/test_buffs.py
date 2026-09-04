# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import importlib

from garak import _plugins
from garak import attempt
from garak.exception import GarakException
import garak.buffs.base

BUFFS = [classname for (classname, active) in _plugins.enumerate_plugins("buffs")]


@pytest.mark.parametrize("classname", BUFFS)
def test_buff_structure(classname):

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


@pytest.mark.parametrize("klassname", BUFFS)
def test_buff_load_and_transform(klassname, mocker):
    import sys

    try:
        b = _plugins.load_plugin(klassname)
    except GarakException:
        pytest.skip()
    assert isinstance(b, garak.buffs.base.Buff)
    a = attempt.Attempt()
    a.prompt = attempt.Message("I'm just a plain and simple tailor", lang=b.lang)

    if sys.platform == "win32" and klassname == "buffs.paraphrase.Fast":
        # special case buff not currently supported on Windows
        with pytest.raises(GarakException) as exc_info:
            list(b.transform(a))  # process yield to see raise
        assert "failed" in str(exc_info.value)
    else:
        # Model-backed buffs load a heavy seq2seq model on first use, but the
        # transform plumbing (dedup, attempt derivation, prompt rewrite) does not
        # depend on the generated text. Stub the model response so this stays a
        # unit test; real generation is covered by test_buff_results. Keyed on the
        # patched method itself so it tracks any buff that owns a _get_response.
        mocks_model = hasattr(b, "_get_response")
        if mocks_model:
            mocker.patch.object(
                b,
                "_get_response",
                return_value=["a paraphrase", "another paraphrase", "a paraphrase"],
            )
        buffed_a = list(b.transform(a))  # unroll the generator
        assert isinstance(buffed_a, list), "transform should return a list of attempts"
        if mocks_model:
            assert len(buffed_a) == 3, (
                "transform should yield the original attempt plus each unique "
                "paraphrase, with duplicates removed"
            )


def test_derive_new_attempt_does_not_share_notes_or_detector_results():
    # regression test: garak.buffs.base.Buff._derive_new_attempt used to pass
    # source_attempt.notes/detector_results/targets/probe_params straight
    # through, so a derived attempt and its source (and any siblings derived
    # from the same source) shared the same dicts/lists. Writing a detector
    # result or a note on one attempt then silently overwrote what every
    # sibling reported, and mutating targets/probe_params on one attempt
    # would leak into the others.
    b = garak.buffs.base.Buff()
    source_attempt = attempt.Attempt()
    source_attempt.prompt = attempt.Message("hello", lang="en")
    source_attempt.targets = ["target"]
    source_attempt.probe_params = {"param": "value"}

    derived_attempt = b._derive_new_attempt(source_attempt)

    assert derived_attempt.notes is not source_attempt.notes
    assert derived_attempt.detector_results is not source_attempt.detector_results
    assert derived_attempt.targets is not source_attempt.targets
    assert derived_attempt.probe_params is not source_attempt.probe_params

    derived_attempt.detector_results["always.Fail"] = [0.0]
    assert "always.Fail" not in source_attempt.detector_results

    source_attempt.notes["marker"] = "source"
    assert "marker" not in derived_attempt.notes

    derived_attempt.targets.append("other target")
    assert source_attempt.targets == ["target"]

    source_attempt.probe_params["other param"] = "other value"
    assert derived_attempt.probe_params == {"param": "value"}
