# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
from unittest.mock import MagicMock, patch

import pytest

from garak.attempt import Message


@pytest.fixture
def mock_openai_client():
    """Create a mock OpenAI client with configurable responses."""
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = "Translated text"
    mock_response.choices = [mock_choice]
    mock_client.chat.completions.create.return_value = mock_response
    return mock_client


@pytest.fixture
def translator_config():
    """Base configuration for LLMTranslator tests."""
    return {
        "language": "en,zh",
        "model_type": "llm.LLMTranslator",
        "uri": "http://localhost:11434/v1",
        "model_name": "llama3",
        "key": "test-key",
    }


class TestLLMTranslatorInit:
    """Test LLMTranslator initialization."""

    def test_init_with_config_key(self, translator_config, mock_openai_client):
        """Key from config takes precedence."""
        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            assert translator.key == "test-key"

    def test_init_with_env_var(self, translator_config, mock_openai_client):
        """LLM_TRANSLATOR_API_KEY env var is used when config key not set."""
        config = translator_config.copy()
        del config["key"]

        with patch.dict(os.environ, {"LLM_TRANSLATOR_API_KEY": "env-key"}):
            with patch("openai.OpenAI", return_value=mock_openai_client):
                from garak.services.langservice import _load_langprovider

                translator = _load_langprovider(config)
                assert translator.key == "env-key"

    def test_init_fallback_to_openai_key(self, translator_config, mock_openai_client):
        """Falls back to OPENAI_API_KEY when LLM_TRANSLATOR_API_KEY not set."""
        config = translator_config.copy()
        del config["key"]

        env = {"OPENAI_API_KEY": "openai-key"}
        with patch.dict(os.environ, env, clear=False):
            if "LLM_TRANSLATOR_API_KEY" in os.environ:
                del os.environ["LLM_TRANSLATOR_API_KEY"]
            with patch("openai.OpenAI", return_value=mock_openai_client):
                from garak.services.langservice import _load_langprovider

                translator = _load_langprovider(config)
                assert translator.key == "openai-key"

    def test_language_pair_parsing(self, translator_config, mock_openai_client):
        """Source and target languages are parsed correctly."""
        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            assert translator.source_lang == "en"
            assert translator.target_lang == "zh"

    def test_generator_created_with_correct_params(
        self, translator_config, mock_openai_client
    ):
        """Internal generator is created with correct parameters."""
        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            assert translator._generator is not None
            assert translator._generator.name == "llama3"
            assert translator._generator.uri == "http://localhost:11434/v1"

    def test_key_passed_to_openai_client(self, translator_config, mock_openai_client):
        """Key is correctly passed to the OpenAI client constructor."""
        with patch("openai.OpenAI", return_value=mock_openai_client) as mock_class:
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            # Verify OpenAI was called with the correct key (as api_key param)
            mock_class.assert_called_with(
                base_url="http://localhost:11434/v1",
                api_key="test-key",
            )

    def test_max_concurrent_requests_inherits_from_parallel_attempts(
        self, translator_config, mock_openai_client
    ):
        """max_concurrent_requests inherits from system.parallel_attempts."""
        mock_system = MagicMock()
        mock_system.parallel_attempts = 32

        with patch("openai.OpenAI", return_value=mock_openai_client):
            with patch("garak.langproviders.llm._config.system", mock_system):
                from garak.services.langservice import _load_langprovider

                translator = _load_langprovider(translator_config)
                assert translator.max_concurrent_requests == 32

    def test_max_concurrent_requests_explicit_overrides_parallel_attempts(
        self, translator_config, mock_openai_client
    ):
        """Explicit max_concurrent_requests overrides system.parallel_attempts."""
        mock_system = MagicMock()
        mock_system.parallel_attempts = 32
        config = translator_config.copy()
        config["max_concurrent_requests"] = 5

        with patch("openai.OpenAI", return_value=mock_openai_client):
            with patch("garak.langproviders.llm._config.system", mock_system):
                from garak.services.langservice import _load_langprovider

                translator = _load_langprovider(config)
                assert translator.max_concurrent_requests == 5

    def test_max_concurrent_requests_defaults_to_10_when_parallel_attempts_false(
        self, translator_config, mock_openai_client
    ):
        """max_concurrent_requests defaults to 10 when parallel_attempts is False."""
        mock_system = MagicMock()
        mock_system.parallel_attempts = False

        with patch("openai.OpenAI", return_value=mock_openai_client):
            with patch("garak.langproviders.llm._config.system", mock_system):
                from garak.services.langservice import _load_langprovider

                translator = _load_langprovider(translator_config)
                assert translator.max_concurrent_requests == 10


class TestLLMTranslatorTranslate:
    """Test LLMTranslator._translate method."""

    def test_translate_success(self, translator_config, mock_openai_client):
        """Successful translation returns LLM response."""
        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            result = translator._translate("Hello")
            assert result == "Translated text"

    def test_translate_empty_text(self, translator_config, mock_openai_client):
        """Empty text returns unchanged."""
        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            assert translator._translate("") == ""
            assert translator._translate("   ") == "   "

    def test_translate_error_returns_original(
        self, translator_config, mock_openai_client
    ):
        """On error, original text is returned."""
        mock_openai_client.chat.completions.create.side_effect = Exception("API error")

        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            result = translator._translate("Hello")
            assert result == "Hello"

    def test_translate_empty_response(self, translator_config, mock_openai_client):
        """Empty LLM response returns original text."""
        mock_response = MagicMock()
        mock_response.choices = []
        mock_openai_client.chat.completions.create.return_value = mock_response

        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            result = translator._translate("Hello")
            assert result == "Hello"


class TestLLMTranslatorGetText:
    """Test LLMTranslator.get_text parallel processing."""

    def test_get_text_parallel_execution(self, translator_config, mock_openai_client):
        """Multiple prompts are translated in parallel."""
        call_count = 0

        def mock_create(**kwargs):
            nonlocal call_count
            call_count += 1
            mock_response = MagicMock()
            mock_choice = MagicMock()
            mock_choice.message.content = f"Translated {call_count}"
            mock_response.choices = [mock_choice]
            return mock_response

        mock_openai_client.chat.completions.create.side_effect = mock_create

        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            prompts = ["Hello", "World", "Test"]
            results = translator.get_text(prompts)

            assert len(results) == 3
            assert all(r.startswith("Translated") for r in results)
            assert call_count == 3

    def test_get_text_preserves_order(self, translator_config, mock_openai_client):
        """Results maintain same order as input prompts."""
        import time

        def mock_create(**kwargs):
            # Add varying delays to test order preservation
            user_msg = kwargs["messages"][1]["content"]
            if "slowly" in user_msg:
                time.sleep(0.05)
            mock_response = MagicMock()
            mock_choice = MagicMock()
            mock_choice.message.content = f"T:{user_msg}"
            mock_response.choices = [mock_choice]
            return mock_response

        mock_openai_client.chat.completions.create.side_effect = mock_create

        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            # Use proper English sentences that pass is_english() check
            prompts = [
                "Please translate this slowly",
                "Quick sentence here",
                "Another slowly translated text",
            ]
            results = translator.get_text(prompts)

            # Results should maintain order despite varying completion times
            assert len(results) == 3
            assert "slowly" in results[0]
            assert "quick" in results[1].lower()
            assert "slowly" in results[2]

    def test_get_text_empty_list(self, translator_config, mock_openai_client):
        """Empty prompt list returns empty list."""
        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            results = translator.get_text([])
            assert results == []

    def test_get_text_callback_invoked(self, translator_config, mock_openai_client):
        """Notify callback is invoked for each prompt."""
        callback_count = 0

        def callback():
            nonlocal callback_count
            callback_count += 1

        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            prompts = ["A", "B", "C"]
            translator.get_text(prompts, notify_callback=callback)

            assert callback_count == 3

    def test_get_text_with_none_prompt(self, translator_config, mock_openai_client):
        """None prompts are handled gracefully."""
        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            prompts = ["Hello", None, "World"]
            results = translator.get_text(prompts)

            assert len(results) == 3
            assert results[1] is None


class TestLLMTranslatorSystemPrompt:
    """Test custom system prompt configuration."""

    def test_default_system_prompt(self, translator_config, mock_openai_client):
        """Default system prompt includes target language name."""
        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            # Should use human-readable name "Chinese" instead of code "zh"
            assert "Chinese" in translator._system_prompt
            assert "translation" in translator._system_prompt.lower()

    def test_custom_system_prompt(self, translator_config, mock_openai_client):
        """Custom system prompt uses human-readable language name."""
        config = translator_config.copy()
        config["system_prompt"] = "Translate to {target_lang}"

        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(config)
            # Should use "Chinese" instead of "zh"
            assert translator._system_prompt == "Translate to Chinese"


class TestLLMTranslatorPickle:
    """Test pickle/unpickle behavior."""

    def test_unsafe_attributes(self, translator_config, mock_openai_client):
        """Generator is marked as unsafe for serialization."""
        with patch("openai.OpenAI", return_value=mock_openai_client):
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            assert "_generator" in translator._unsafe_attributes

    def test_load_unsafe_reinitializes_generator(
        self, translator_config, mock_openai_client
    ):
        """_load_unsafe recreates the generator."""
        with patch("openai.OpenAI", return_value=mock_openai_client) as mock_class:
            from garak.services.langservice import _load_langprovider

            translator = _load_langprovider(translator_config)
            initial_call_count = mock_class.call_count

            translator._generator = None
            translator._load_unsafe()

            assert mock_class.call_count == initial_call_count + 1
            assert translator._generator is not None
