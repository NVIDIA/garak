# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION &
#                         AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for simonw/llm-backed garak generator"""

import pytest
from unittest.mock import MagicMock

from garak.attempt import Conversation, Turn, Message
from garak._config import GarakSubConfig

# Adjust import path/module name to where you placed the wrapper
from garak.generators.llm import LLMGenerator


# ─── Helpers & Fixtures ─────────────────────────────────────────────────

class FakeResponse:
    """Minimal `llm` Response shim with .text()"""
    def __init__(self, txt: str):
        self._txt = txt
    def text(self) -> str:
        return self._txt


class FakeModel:
    """Minimal `llm` model shim with .prompt()"""
    def __init__(self):
        self.calls = []
    def prompt(self, prompt_text: str, **kwargs):
        self.calls.append((prompt_text, kwargs))
        return FakeResponse("OK_FAKE")


@pytest.fixture
def cfg():
    """Minimal garak sub-config; extend if you wire defaults via config."""
    c = GarakSubConfig()
    c.generators = {} 
    return c


@pytest.fixture
def fake_llm(monkeypatch):
    """
    Patch llm.get_model to return a fresh FakeModel for each test.
    Return the FakeModel so tests can inspect call args.
    """
    import llm 
    model = FakeModel()
    monkeypatch.setattr(llm, "get_model", lambda *a, **k: model)
    return model


# ─── Tests ──────────────────────────────────────────────────────────────

def test_instantiation_resolves_model(cfg, fake_llm):
    gen = LLMGenerator(name="my-alias", config_root=cfg)
    assert gen.name == "my-alias"
    assert hasattr(gen, "model")
    assert "LLM (simonw/llm)" in gen.fullname


def test_generate_returns_message(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)

    conv = Conversation([Turn("user", Message(text="ping"))])
    out = gen._call_model(conv)

    assert isinstance(out, list) and len(out) == 1
    assert isinstance(out[0], Message)
    assert out[0].text == "OK_FAKE"

    prompt_text, kwargs = fake_llm.calls[0]
    assert prompt_text == "ping"
    assert kwargs == {}  


def test_param_passthrough(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    gen.temperature = 0.2
    gen.max_tokens = 64
    gen.top_p = 0.9
    gen.stop = ["\n\n"]
    gen.system = "you are testy"

    conv = Conversation([Turn("user", Message(text="hello"))])
    _ = gen._call_model(conv)

    _, kwargs = fake_llm.calls[0]
    assert kwargs["temperature"] == 0.2
    assert kwargs["max_tokens"] == 64
    assert kwargs["top_p"] == 0.9
    assert kwargs["stop"] == ["\n\n"]
    assert kwargs["system"] == "you are testy"


def test_wrapper_handles_llm_exception(cfg, monkeypatch):
    """If the underlying `llm` call explodes, wrapper returns [None]."""
    import llm
    class BoomModel:
        def prompt(self, *a, **k):
            raise RuntimeError("boom")
    monkeypatch.setattr(llm, "get_model", lambda *a, **k: BoomModel())

    gen = LLMGenerator(name="alias", config_root=cfg)
    conv = Conversation([Turn("user", Message(text="ping"))])
    out = gen._call_model(conv)
    assert out == [None]


def test_default_model_when_name_empty(cfg, fake_llm, monkeypatch):
    """
    If name is empty, wrapper should call llm.get_model() with no args,
    i.e., use llm's configured default model.
    """
    import llm
    spy = MagicMock(side_effect=lambda *a, **k: fake_llm)
    monkeypatch.setattr(llm, "get_model", spy)

    gen = LLMGenerator(name="", config_root=cfg)
    conv = Conversation([Turn("user", Message(text="x"))])
    _ = gen._call_model(conv)

    spy.assert_called_once()
    assert spy.call_args.args == ()
    assert spy.call_args.kwargs == {}
