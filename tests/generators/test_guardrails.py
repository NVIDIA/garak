# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import httpx
import pytest

from garak.attempt import Message, Turn, Conversation
from garak.generators.guardrails import NeMoGuardrailsServer


def guardrails_config(selected_rails):
    """helper method to provide generator configuration"""
    return {
        "generators": {
            "guardrails": {
                "NeMoGuardrailsServer": {
                    "name": "UnknownModel",
                    "config_ids": selected_rails,
                }
            }
        }
    }


@pytest.mark.parametrize(
    "selected_rails",
    [
        [],
        ["rail1"],
        ["rail1", "rail2"],
    ],
)
@pytest.mark.respx(base_url=NeMoGuardrailsServer.DEFAULT_PARAMS["uri"])
def test_guardrail_selection(selected_rails, respx_mock, openai_compat_mocks):
    """validate selected rails are passed as headers on the request"""
    mock_response = openai_compat_mocks["chat"]
    mock_request = respx_mock.post("chat/completions")
    mock_request.mock(
        return_value=httpx.Response(
            mock_response["code"],
            json=mock_response["json"],
        )
    )
    config_root = guardrails_config(selected_rails)
    g = NeMoGuardrailsServer(config_root=config_root)
    conv = Conversation(turns=[Turn(role="user", content=Message("Testing text"))])
    g.generate(conv)
    assert mock_request.called
    for rail in selected_rails:
        content = str(mock_request.calls.last.request.content)
        assert "guardrails" in content
        assert "config_ids" in content
        assert rail in content
