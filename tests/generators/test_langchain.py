import importlib
from types import SimpleNamespace

import pytest

from garak.attempt import Conversation, Message, Turn
from garak.generators.langchain import LangChainLLMGenerator


def _generator_with_response(monkeypatch, response):
    """Build a LangChain generator whose chat model returns `response`.

    `init_chat_model` is stubbed so construction needs no real provider or
    API key; only the response handling in `_call_model` is exercised.
    """
    fake_model = SimpleNamespace(invoke=lambda messages: response)
    monkeypatch.setattr(
        "langchain.chat_models.init_chat_model", lambda *args, **kwargs: fake_model
    )
    return LangChainLLMGenerator(name="test-model")


def _conversation():
    return Conversation([Turn("user", Message("Hello LangChain!"))])


@pytest.mark.skipif(
    not all(
        [
            importlib.util.find_spec(m)
            for m in LangChainLLMGenerator.extra_dependency_names
        ]
    ),
    reason="missing optional dependency",
)
def test_langchain_returns_all_text_blocks(monkeypatch):
    """A reply split by a tool call must return all its text, not just the
    first block. Regression test for #2513."""
    from langchain_core.messages import AIMessage

    response = AIMessage(
        content=[
            {"text": "FIRST PART ", "type": "text"},
            {
                "id": "toolu_1",
                "input": {"q": "x"},
                "name": "search",
                "type": "tool_use",
            },
            {"text": "SECOND PART", "type": "text"},
        ]
    )
    generator = _generator_with_response(monkeypatch, response)
    output = generator.generate(_conversation())
    assert len(output) == 1
    assert output[0].text == "FIRST PART SECOND PART"


@pytest.mark.skipif(
    not all(
        [
            importlib.util.find_spec(m)
            for m in LangChainLLMGenerator.extra_dependency_names
        ]
    ),
    reason="missing optional dependency",
)
def test_langchain_returns_all_text_blocks_with_text_attributes(monkeypatch):
    """Attribute-style chunks (other LangChain integrations) join the same
    way as mapping blocks."""
    response = SimpleNamespace(
        content=[
            SimpleNamespace(text="FIRST PART "),
            SimpleNamespace(type="tool_use", id="toolu_1", name="search", input={}),
            SimpleNamespace(text="SECOND PART"),
        ]
    )
    generator = _generator_with_response(monkeypatch, response)
    output = generator.generate(_conversation())
    assert len(output) == 1
    assert output[0].text == "FIRST PART SECOND PART"


@pytest.mark.skipif(
    not all(
        [
            importlib.util.find_spec(m)
            for m in LangChainLLMGenerator.extra_dependency_names
        ]
    ),
    reason="missing optional dependency",
)
def test_langchain_returns_none_when_list_content_has_no_text(monkeypatch):
    """A tool-call-only reply carries no reply text, so it records a miss
    rather than a list landing in `Message.text`."""
    response = SimpleNamespace(
        content=[
            {
                "id": "toolu_1",
                "input": {"q": "x"},
                "name": "search",
                "type": "tool_use",
            }
        ]
    )
    generator = _generator_with_response(monkeypatch, response)
    output = generator.generate(_conversation())
    assert output == [None]


@pytest.mark.skipif(
    not all(
        [
            importlib.util.find_spec(m)
            for m in LangChainLLMGenerator.extra_dependency_names
        ]
    ),
    reason="missing optional dependency",
)
def test_langchain_passes_plain_string_content_through(monkeypatch):
    response = SimpleNamespace(content="plain reply")
    generator = _generator_with_response(monkeypatch, response)
    output = generator.generate(_conversation())
    assert len(output) == 1
    assert output[0].text == "plain reply"


@pytest.mark.skipif(
    not all(
        [
            importlib.util.find_spec(m)
            for m in LangChainLLMGenerator.extra_dependency_names
        ]
    ),
    reason="missing optional dependency",
)
def test_langchain_returns_none_when_content_is_none(monkeypatch):
    response = SimpleNamespace(content=None)
    generator = _generator_with_response(monkeypatch, response)
    output = generator.generate(_conversation())
    assert output == [None]
