# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import urllib.error
from unittest import mock

import pandas as pd
import pytest

import garak._config
from garak.resources import common


def test_load_advbench_reraises_http_error(tmp_path, monkeypatch):
    monkeypatch.setattr(garak._config.transient, "cache_dir", tmp_path)
    monkeypatch.setattr(common, "data_path", tmp_path / "missing_data")
    err = urllib.error.HTTPError(
        "https://example.com/harmful_behaviors.csv",
        404,
        "Not Found",
        {},
        None,
    )
    with mock.patch.object(common.pd, "read_csv", side_effect=err):
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            common.load_advbench()
    assert exc_info.value is err
    assert exc_info.value.code == 404


def test_load_advbench_reraises_parser_error(tmp_path, monkeypatch):
    monkeypatch.setattr(garak._config.transient, "cache_dir", tmp_path)
    monkeypatch.setattr(common, "data_path", tmp_path / "missing_data")
    err = pd.errors.ParserError("bad csv")
    with mock.patch.object(common.pd, "read_csv", side_effect=err):
        with pytest.raises(pd.errors.ParserError) as exc_info:
            common.load_advbench()
    assert exc_info.value is err
    assert str(exc_info.value) == "bad csv"
