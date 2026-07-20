# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
from unittest.mock import MagicMock

from garak.attempt import Conversation, Turn, Message
from garak._config import GarakSubConfig
from garak.exception import GeneratorBackoffTrigger, BadGeneratorException

llm = pytest.importorskip("llm")

from garak.generators.llm import LLMGenerator


class FakeOptions:
    model_fields = {
        "temperature": None,
        "max_tokens": None,
        "top_p": None,
        "stop": None,
    }


class FakeResponse:
    def __init__(self, txt):
        self._txt = txt

    def text(self):
        return self._txt


class FakeModel:
    Options = FakeOptions

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
    test_name = "my-alias"
    gen = LLMGenerator(name=test_name, config_root=cfg)
    assert gen.name == test_name
    assert isinstance(gen.target, FakeModel)


def test_generate_returns_message(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    conv = Conversation([Turn("user", Message(text="ping"))])
    out = gen.generate(conv)

    assert isinstance(out, list) and len(out) == 1
    assert isinstance(out[0], Message)
    assert out[0].text == "OK_FAKE"


def test_param_passthrough(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    temperature, max_tokens, top_p, stop = 0.2, 64, 0.9, ["\n\n"]
    gen.temperature = temperature
    gen.max_tokens = max_tokens
    gen.top_p = top_p
    gen.stop = stop

    conv = Conversation([Turn("user", Message(text="hello"))])
    gen._call_model(conv)

    _, kwargs = fake_llm.calls[0]
    assert kwargs["temperature"] == temperature
    assert kwargs["max_tokens"] == max_tokens
    assert kwargs["top_p"] == top_p
    assert kwargs["stop"] == stop


def test_unsupported_params_filtered(cfg, fake_llm):
    """Params not in the model's Options.model_fields should be excluded."""
    gen = LLMGenerator(name="alias", config_root=cfg)
    gen._accepted_params = {"temperature"}
    gen.temperature = 0.5
    gen.max_tokens = 100
    gen.top_p = 0.9

    conv = Conversation([Turn("user", Message(text="hello"))])
    gen._call_model(conv)

    _, kwargs = fake_llm.calls[0]
    assert "temperature" in kwargs
    assert "max_tokens" not in kwargs
    assert "top_p" not in kwargs


def test_suppressed_params_excludes_param(cfg, fake_llm):
    """Params in suppressed_params should not reach the model even if it supports them."""
    gen = LLMGenerator(name="alias", config_root=cfg)
    gen.temperature = 0.7
    gen.suppressed_params = {"temperature"}
    gen._accepted_params = gen._enumerate_model_params()

    conv = Conversation([Turn("user", Message(text="hello"))])
    gen._call_model(conv)

    _, kwargs = fake_llm.calls[0]
    assert "temperature" not in kwargs


def test_extra_params_included(cfg, fake_llm):
    """Params in extra_params should always be forwarded to the model."""
    gen = LLMGenerator(name="alias", config_root=cfg)
    gen.extra_params = {"custom_key": "custom_value"}

    conv = Conversation([Turn("user", Message(text="hello"))])
    gen._call_model(conv)

    _, kwargs = fake_llm.calls[0]
    assert kwargs.get("custom_key") == "custom_value"


def test_model_error_triggers_backoff(cfg, monkeypatch):
    """llm.ModelError (non-key errors) should trigger backoff for potential retry."""

    class ErrorModel:
        Options = FakeOptions

        def prompt(self, *a, **k):
            raise llm.ModelError("transient model error")

    monkeypatch.setattr(llm, "get_model", lambda *a, **k: ErrorModel())
    gen = LLMGenerator(name="alias", config_root=cfg)
    with pytest.raises(GeneratorBackoffTrigger):
        gen._call_single.__wrapped__(gen, "ping", None, {})


def test_needs_key_exception_raises(cfg, monkeypatch):
    """NeedsKeyException should raise BadGeneratorException — no API key means no recovery."""

    error_msg = "no API key configured"

    class NoKeyModel:
        Options = FakeOptions

        def prompt(self, *a, **k):
            raise llm.NeedsKeyException(error_msg)

    monkeypatch.setattr(llm, "get_model", lambda *a, **k: NoKeyModel())
    gen = LLMGenerator(name="alias", config_root=cfg)
    with pytest.raises(BadGeneratorException, match=error_msg):
        gen._call_single.__wrapped__(gen, "ping", None, {})


def test_non_model_error_returns_none(cfg, monkeypatch):
    """Non-retryable exceptions should log and return None, not loop."""

    class BoomModel:
        Options = FakeOptions

        def prompt(self, *a, **k):
            raise RuntimeError("boom")

    monkeypatch.setattr(llm, "get_model", lambda *a, **k: BoomModel())
    gen = LLMGenerator(name="alias", config_root=cfg)
    result = gen._call_single.__wrapped__(gen, "ping", None, {})
    assert result is None


def test_unknown_provider_error_returns_none(cfg, monkeypatch):
    """Unrecognised provider exceptions should log and return None."""

    class RateLimitError(Exception):
        pass

    class RateLimitModel:
        Options = FakeOptions

        def prompt(self, *a, **k):
            raise RateLimitError("rate limited")

    monkeypatch.setattr(llm, "get_model", lambda *a, **k: RateLimitModel())
    gen = LLMGenerator(name="alias", config_root=cfg)
    result = gen._call_single.__wrapped__(gen, "ping", None, {})
    assert result is None


def test_unknown_model_raises_immediately(cfg, monkeypatch):
    """UnknownModelError from get_model should not be caught by backoff."""
    monkeypatch.setattr(
        llm, "get_model", MagicMock(side_effect=llm.UnknownModelError("bad-model"))
    )
    with pytest.raises(KeyError):
        LLMGenerator(name="bad-model", config_root=cfg)


def test_default_model_when_name_empty(cfg, fake_llm, monkeypatch):
    spy = MagicMock(side_effect=lambda *a, **k: fake_llm)
    monkeypatch.setattr(llm, "get_model", spy)

    gen = LLMGenerator(name="", config_root=cfg)
    conv = Conversation([Turn("user", Message(text="x"))])
    gen._call_model(conv)

    spy.assert_called()
    assert spy.call_args.args == ()
    assert spy.call_args.kwargs == {}


def test_system_prompt_passthrough(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    conv = Conversation(
        [
            Turn("system", Message(text="You are helpful")),
            Turn("user", Message(text="hello")),
        ]
    )
    gen._call_model(conv)

    prompt_text, kwargs = fake_llm.calls[0]
    assert prompt_text == "hello"
    assert kwargs.get("system") == "You are helpful"


def test_skips_multiple_user_turns(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    conv = Conversation(
        [
            Turn("user", Message(text="first")),
            Turn("user", Message(text="second")),
        ]
    )
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
    gen = LLMGenerator(name="alias", config_root=cfg)
    conv = Conversation([Turn("user", Message(text="ping"))])
    out = gen._call_model(conv, generations_this_call=3)

    assert len(out) == 3
    assert all(isinstance(m, Message) for m in out)
    assert all(m.text == "OK_FAKE" for m in out)
    assert len(fake_llm.calls) == 3


def test_accepted_params_from_model_options(cfg, fake_llm):
    gen = LLMGenerator(name="alias", config_root=cfg)
    assert "temperature" in gen._accepted_params
    assert "max_tokens" in gen._accepted_params
    assert "top_p" in gen._accepted_params
    assert "stop" in gen._accepted_params
