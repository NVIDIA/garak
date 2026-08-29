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
