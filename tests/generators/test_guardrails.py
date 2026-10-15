# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json

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


def test_nonempty_extra_params_does_not_crash_init():
    """Construction with a non-empty extra_params lacking 'extra_body' must not crash.

    The removed block ran ``self.extra_params.append("extra_body")`` — .append
    on a dict — which raised AttributeError during __init__ for any user who
    set extra_params without an 'extra_body' key.
    """
    config_root = {
        "generators": {
            "guardrails": {
                "NeMoGuardrailsServer": {
                    "name": "UnknownModel",
                    "extra_params": {"foo": 1},
                }
            }
        }
    }
    g = NeMoGuardrailsServer(config_root=config_root)
    assert g.extra_params == {"foo": 1}


@pytest.mark.respx(base_url=NeMoGuardrailsServer.DEFAULT_PARAMS["uri"])
def test_user_extra_body_is_merged_not_shadowed_by_guardrails_config(
    respx_mock, openai_compat_mocks
):
    """A user-provided extra_body (via extra_params) must combine with, not be
    overwritten by, the guardrails config injected into self.extra_body — and
    must not remain in extra_params where it would independently overwrite
    self.extra_body again in _call_model().
    """
    mock_response = openai_compat_mocks["chat"]
    mock_request = respx_mock.post("chat/completions")
    mock_request.mock(
        return_value=httpx.Response(
            mock_response["code"],
            json=mock_response["json"],
        )
    )
    config_root = {
        "generators": {
            "guardrails": {
                "NeMoGuardrailsServer": {
                    "name": "UnknownModel",
                    "config_ids": ["rail1"],
                    "extra_params": {"extra_body": {"custom_key": "custom_value"}},
                }
            }
        }
    }
    g = NeMoGuardrailsServer(config_root=config_root)

    assert "extra_body" not in g.extra_params
    assert g.extra_body == {
        "custom_key": "custom_value",
        "guardrails": {"config_ids": ["rail1"]},
    }

    conv = Conversation(turns=[Turn(role="user", content=Message("Testing text"))])
    g.generate(conv)
    assert mock_request.called
    sent_body = json.loads(mock_request.calls.last.request.content)
    assert sent_body["custom_key"] == "custom_value"
    assert sent_body["guardrails"] == {"config_ids": ["rail1"]}


def test_non_dict_user_extra_body_raises_value_error():
    """A non-dict extra_params['extra_body'] must raise a clear ValueError at
    construction time rather than silently corrupting self.extra_body or
    failing later with an unrelated error.
    """
    config_root = {
        "generators": {
            "guardrails": {
                "NeMoGuardrailsServer": {
                    "name": "UnknownModel",
                    "extra_params": {"extra_body": "not-a-dict"},
                }
            }
        }
    }
    with pytest.raises(ValueError, match="must be a dict"):
        NeMoGuardrailsServer(config_root=config_root)
