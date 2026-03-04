# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
    assert hasattr(gen, "target")
    assert "llm (simonw/llm)" in gen.fullname


def test_generate_returns_message(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)

    test_txt = "ping"
    conv = Conversation([Turn("user", Message(text=test_txt))])
    out = gen._call_model(conv)

    assert isinstance(out, list) and len(out) == 1
    assert isinstance(out[0], Message)
    assert out[0].text == "OK_FAKE"

    prompt_text, kwargs = fake_llm.calls[0]
    assert prompt_text == test_txt
    assert kwargs == {"max_tokens": gen.max_tokens}


def test_param_passthrough(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    temperature = 0.2
    max_tokens = 64
    top_p = 0.9
    stop = ["\n\n"]

    gen.temperature = temperature
    gen.max_tokens = max_tokens
    gen.top_p = top_p
    gen.stop = stop

    conv = Conversation([Turn("user", Message(text="hello"))])
    _ = gen._call_model(conv)

    _, kwargs = fake_llm.calls[0]
    assert kwargs["temperature"] == temperature
    assert kwargs["max_tokens"] == max_tokens
    assert kwargs["top_p"] == top_p
    assert kwargs["stop"] == stop


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


def test_skips_multiple_user_turns(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    user_turns = [
        Turn("user", Message(text="first")),
        Turn("user", Message(text="second")),
    ]
    conv = Conversation(user_turns)
    out = gen._call_model(conv)
    assert out == [None]
    assert fake_llm.calls == []


def test_skips_assistant_turns(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    conv = Conversation(
        [
            Turn("system", Message(text="system prompt")),
            Turn("assistant", Message(text="historic reply")),
            Turn("user", Message(text="question")),
        ]
    )
    out = gen._call_model(conv)
    assert out == [None]
    assert fake_llm.calls == []


def test_skips_multiple_system_turns(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    conv = Conversation(
        [
            Turn("system", Message(text="one")),
            Turn("system", Message(text="two")),
            Turn("user", Message(text="ping")),
        ]
    )
    out = gen._call_model(conv)
    assert out == [None]
    assert fake_llm.calls == []


def test_multiple_generations(cfg, fake_llm):
    """_call_model respects generations_this_call > 1."""
    gen = LLMGenerator(name="alias", config_root=cfg)
    conv = Conversation([Turn("user", Message(text="ping"))])
    generations = 3
    out = gen._call_model(conv, generations_this_call=generations)

    assert len(out) == generations
    assert all(isinstance(m, Message) for m in out)
    assert all(m.text == "OK_FAKE" for m in out)
    assert len(fake_llm.calls) == generations
