# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
from unittest.mock import MagicMock

from garak.attempt import Conversation, Turn, Message
from garak._config import GarakSubConfig

llm = pytest.importorskip("llm")

from garak.generators.llm import LLMGenerator


class FakeResponse:
    def __init__(self, txt):
        self._txt = txt

    def text(self):
        return self._txt


class FakeModel:
    def __init__(self):
        self.calls = []

    def prompt(self, prompt_text, **kwargs):
        self.calls.append((prompt_text, kwargs))
        return FakeResponse("OK_FAKE")


@pytest.fixture
def cfg():
    c = GarakSubConfig()
    c.generators = {}
    return c


@pytest.fixture
def fake_llm(monkeypatch):
    model = FakeModel()
    monkeypatch.setattr(llm, "get_model", lambda *a, **k: model)
    return model


def test_instantiation_resolves_model(cfg, fake_llm):
    gen = LLMGenerator(name="my-alias", config_root=cfg)
    assert gen.name == "my-alias"
    assert hasattr(gen, "target")


def test_generate_returns_message(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    conv = Conversation([Turn("user", Message(text="ping"))])
    out = gen.generate(conv)

    assert isinstance(out, list) and len(out) == 1
    assert isinstance(out[0], Message)
    assert out[0].text == "OK_FAKE"


def test_param_passthrough(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    gen.temperature = 0.2
    gen.max_tokens = 64
    gen.top_p = 0.9
    gen.stop = ["\n\n"]

    conv = Conversation([Turn("user", Message(text="hello"))])
    gen._call_model(conv)

    _, kwargs = fake_llm.calls[0]
    assert kwargs["temperature"] == 0.2
    assert kwargs["max_tokens"] == 64
    assert kwargs["top_p"] == 0.9
    assert kwargs["stop"] == ["\n\n"]


def test_handles_llm_exception(cfg, monkeypatch):
    class BoomModel:
        def prompt(self, *a, **k):
            raise RuntimeError("boom")

    monkeypatch.setattr(llm, "get_model", lambda *a, **k: BoomModel())
    gen = LLMGenerator(name="alias", config_root=cfg)
    conv = Conversation([Turn("user", Message(text="ping"))])
    out = gen._call_model(conv)
    assert out == [None]


def test_default_model_when_name_empty(cfg, fake_llm, monkeypatch):
    spy = MagicMock(side_effect=lambda *a, **k: fake_llm)
    monkeypatch.setattr(llm, "get_model", spy)

    gen = LLMGenerator(name="", config_root=cfg)
    conv = Conversation([Turn("user", Message(text="x"))])
    gen._call_model(conv)

    spy.assert_called()
    assert spy.call_args.args == ()
    assert spy.call_args.kwargs == {}


def test_skips_multiple_user_turns(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    conv = Conversation([
        Turn("user", Message(text="first")),
        Turn("user", Message(text="second")),
    ])
    out = gen._call_model(conv)
    assert out == [None]
    assert fake_llm.calls == []


def test_skips_assistant_turns(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    conv = Conversation([
        Turn("system", Message(text="system prompt")),
        Turn("assistant", Message(text="historic reply")),
        Turn("user", Message(text="question")),
    ])
    out = gen._call_model(conv)
    assert out == [None]
    assert fake_llm.calls == []


def test_skips_multiple_system_turns(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    conv = Conversation([
        Turn("system", Message(text="one")),
        Turn("system", Message(text="two")),
        Turn("user", Message(text="ping")),
    ])
    out = gen._call_model(conv)
    assert out == [None]
    assert fake_llm.calls == []


def test_multiple_generations(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    conv = Conversation([Turn("user", Message(text="ping"))])
    out = gen._call_model(conv, generations_this_call=3)

    assert len(out) == 3
    assert all(isinstance(m, Message) for m in out)
    assert all(m.text == "OK_FAKE" for m in out)
    assert len(fake_llm.calls) == 3
