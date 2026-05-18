# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_generator():
    """Create a mock generator with configurable translation response."""
    mock_gen = MagicMock()
    mock_msg = MagicMock()
    mock_msg.text = "Translated text"
    mock_gen._call_model.return_value = [mock_msg]
    return mock_gen


def make_config_root(overrides=None):
    """Build a config_root dict for LLMTranslator.

    Configurable expects: config_root["langproviders"]["llm"][...params...]
    """
    params = {
        "language": "en,zh",
        "translation_model_name": "llama3",
        "translation_model_config": {
            "uri": "http://localhost:11434/v1",
            "api_key": "test-key",
        },
    }
    if overrides:
        params.update(overrides)
    return {"langproviders": {"llm": params}}


class TestLLMTranslatorInit:
    """Test LLMTranslator initialization."""

    def test_language_pair_parsing(self, mock_generator):
        """Source and target languages are parsed correctly."""
        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(config_root=make_config_root())
            assert translator.source_lang == "en"
            assert translator.target_lang == "zh"

    def test_generator_created_with_correct_params(self, mock_generator):
        """Generator is loaded via _plugins with correct config."""
        with patch(
            "garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator
        ) as mock_load:
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(config_root=make_config_root())
            assert translator._generator is mock_generator

            call_args = mock_load.call_args
            assert call_args[0][0] == "generators.openai.OpenAICompatible"

            config_root = call_args[1]["config_root"]
            openai_conf = config_root["generators"]["openai"]["OpenAICompatible"]
            assert openai_conf["uri"] == "http://localhost:11434/v1"
            assert openai_conf["api_key"] == "test-key"
            assert openai_conf["name"] == "llama3"

    def test_custom_translation_model_type(self, mock_generator):
        """Custom translation_model_type is used to select the generator."""
        with patch(
            "garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator
        ) as mock_load:
            from garak.langproviders.llm import LLMTranslator

            LLMTranslator(
                config_root=make_config_root({"translation_model_type": "nim"})
            )
            assert mock_load.call_args[0][0] == "generators.nim"

    def test_key_env_var_in_model_config_passed_through(self, mock_generator):
        """key_env_var in translation_model_config is forwarded to the generator config."""
        with patch(
            "garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator
        ) as mock_load:
            from garak.langproviders.llm import LLMTranslator

            LLMTranslator(
                config_root=make_config_root(
                    {
                        "translation_model_config": {
                            "uri": "http://localhost:11434/v1",
                            "key_env_var": "MY_CUSTOM_KEY",
                        }
                    }
                )
            )
            config_root = mock_load.call_args[1]["config_root"]
            openai_conf = config_root["generators"]["openai"]["OpenAICompatible"]
            assert openai_conf["key_env_var"] == "MY_CUSTOM_KEY"

    def test_max_concurrent_requests_inherits_from_parallel_attempts(self, mock_generator):
        """max_concurrent_requests inherits from system.parallel_attempts."""
        mock_system = MagicMock()
        mock_system.parallel_attempts = 32

        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            with patch("garak.langproviders.llm._config.system", mock_system):
                from garak.langproviders.llm import LLMTranslator

                translator = LLMTranslator(config_root=make_config_root())
                assert translator.max_concurrent_requests == 32

    def test_max_concurrent_requests_explicit_overrides_parallel_attempts(self, mock_generator):
        """Explicit max_concurrent_requests overrides system.parallel_attempts."""
        mock_system = MagicMock()
        mock_system.parallel_attempts = 32

        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            with patch("garak.langproviders.llm._config.system", mock_system):
                from garak.langproviders.llm import LLMTranslator

                translator = LLMTranslator(
                    config_root=make_config_root({"max_concurrent_requests": 5})
                )
                assert translator.max_concurrent_requests == 5

    def test_max_concurrent_requests_defaults_to_10_when_parallel_attempts_false(
        self, mock_generator
    ):
        """max_concurrent_requests defaults to 10 when parallel_attempts is False."""
        mock_system = MagicMock()
        mock_system.parallel_attempts = False

        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            with patch("garak.langproviders.llm._config.system", mock_system):
                from garak.langproviders.llm import LLMTranslator

                translator = LLMTranslator(config_root=make_config_root())
                assert translator.max_concurrent_requests == 10


class TestLLMTranslatorTranslate:
    """Test LLMTranslator._translate method."""

    def test_translate_success(self, mock_generator):
        """Successful translation returns LLM response."""
        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(config_root=make_config_root())
            result = translator._translate("Hello")
            assert result == "Translated text"

    def test_translate_empty_text(self, mock_generator):
        """Empty text returns unchanged."""
        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(config_root=make_config_root())
            assert translator._translate("") == ""
            assert translator._translate("   ") == "   "

    def test_translate_error_returns_original(self, mock_generator):
        """On error, original text is returned."""
        mock_generator._call_model.side_effect = Exception("API error")

        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(config_root=make_config_root())
            result = translator._translate("Hello")
            assert result == "Hello"

    def test_translate_empty_response(self, mock_generator):
        """Empty LLM response returns original text."""
        mock_generator._call_model.return_value = []

        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(config_root=make_config_root())
            result = translator._translate("Hello")
            assert result == "Hello"


class TestLLMTranslatorGetText:
    """Test LLMTranslator.get_text parallel processing."""

    def test_get_text_parallel_execution(self, mock_generator):
        """Multiple prompts are translated in parallel."""
        call_count = 0

        def mock_call_model(conversation, generations_this_call=1):
            nonlocal call_count
            call_count += 1
            msg = MagicMock()
            msg.text = f"Translated {call_count}"
            return [msg]

        mock_generator._call_model.side_effect = mock_call_model

        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(config_root=make_config_root())
            prompts = ["Hello", "World", "Test"]
            results = translator.get_text(prompts)

            assert len(results) == 3
            assert all(r.startswith("Translated") for r in results)
            assert call_count == 3

    def test_get_text_preserves_order(self, mock_generator):
        """Results maintain same order as input prompts."""
        import time

        def mock_call_model(conversation, generations_this_call=1):
            user_turn = conversation.turns[-1]
            content = user_turn.content.text
            if "slowly" in content:
                time.sleep(0.05)
            msg = MagicMock()
            msg.text = f"T:{content}"
            return [msg]

        mock_generator._call_model.side_effect = mock_call_model

        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(config_root=make_config_root())
            prompts = [
                "Please translate this slowly",
                "Quick sentence here",
                "Another slowly translated text",
            ]
            results = translator.get_text(prompts)

            assert len(results) == 3
            assert "slowly" in results[0]
            assert "quick" in results[1].lower()
            assert "slowly" in results[2]

    def test_get_text_empty_list(self, mock_generator):
        """Empty prompt list returns empty list."""
        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(config_root=make_config_root())
            results = translator.get_text([])
            assert results == []

    def test_get_text_callback_invoked(self, mock_generator):
        """Notify callback is invoked for each prompt."""
        callback_count = 0

        def callback():
            nonlocal callback_count
            callback_count += 1

        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(config_root=make_config_root())
            prompts = ["A", "B", "C"]
            translator.get_text(prompts, notify_callback=callback)

            assert callback_count == 3

    def test_get_text_with_none_prompt(self, mock_generator):
        """None prompts are handled gracefully."""
        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(config_root=make_config_root())
            prompts = ["Hello", None, "World"]
            results = translator.get_text(prompts)

            assert len(results) == 3
            assert results[1] is None


class TestLLMTranslatorSystemPrompt:
    """Test custom system prompt configuration."""

    def test_default_system_prompt(self, mock_generator):
        """Default system prompt includes target language name."""
        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(config_root=make_config_root())
            assert "Chinese" in translator._system_prompt
            assert "translation" in translator._system_prompt.lower()

    def test_custom_system_prompt(self, mock_generator):
        """Custom system prompt uses human-readable language name."""
        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(
                config_root=make_config_root({"system_prompt": "Translate to {target_lang}"})
            )
            assert translator._system_prompt == "Translate to Chinese"


class TestLLMTranslatorPickle:
    """Test pickle/unpickle behavior."""

    def test_unsafe_attributes(self, mock_generator):
        """Generator is marked as unsafe for serialization."""
        with patch("garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator):
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(config_root=make_config_root())
            assert "_generator" in translator._unsafe_attributes

    def test_load_unsafe_reinitializes_generator(self, mock_generator):
        """_load_unsafe recreates the generator."""
        with patch(
            "garak.langproviders.llm._plugins.load_plugin", return_value=mock_generator
        ) as mock_load:
            from garak.langproviders.llm import LLMTranslator

            translator = LLMTranslator(config_root=make_config_root())
            initial_call_count = mock_load.call_count

            translator._generator = None
            translator._load_unsafe()

            assert mock_load.call_count == initial_call_count + 1
            assert translator._generator is not None
