# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import pytest
import pathlib


@pytest.fixture
def openai_compat_mocks():
    """Mock responses for OpenAI compatible endpoints"""
    with open(
        pathlib.Path(__file__).parents[1] / "_assets" / "generators" / "openai.json"
    ) as mock_openai:
        return json.load(mock_openai)


@pytest.fixture
def hf_endpoint_mocks():
    """Mock responses for Huggingface InferenceAPI based endpoints"""
    with open(
        pathlib.Path(__file__).parents[1]
        / "_assets"
        / "generators"
        / "hf_inference.json"
    ) as mock_openai:
        return json.load(mock_openai)


@pytest.fixture
def watsonx_compat_mocks():
    """Mock responses for watsonx.ai based endpoints"""
    with open(
        pathlib.Path(__file__).parents[1] / "_assets" / "generators" / "watsonx.json"
    ) as mock_watsonx:
        return json.load(mock_watsonx)


@pytest.fixture
def mistral_compat_mocks():
    """Mock responses for OpenAI compatible endpoints"""
    with open(
        pathlib.Path(__file__).parents[1] / "_assets" / "generators" / "mistral.json"
    ) as mock_mistral:
        return json.load(mock_mistral)
