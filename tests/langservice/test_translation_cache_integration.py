# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

from garak.langproviders.base import LangProvider, TranslationCache

class TestTranslationCacheIntegration:
    """Integration test for translation caching functionality."""

    @pytest.fixture
    def temp_cache_dir(self):
        """Create a temporary cache directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)

    def test_remote_translator_integration(self, temp_cache_dir):
        """Test that remote translators work correctly in integration scenarios."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            from garak.langproviders.remote import RivaTranslator
            
            config = {
                "langproviders": {
                    "riva": {
                        "language": "en,ja",
                        "model_type": "remote.RivaTranslator",
                        "api_key": "test_key"
                    }
                }
            }
            
            # Mock API key validation and create test subclass
            with patch.object(RivaTranslator, '_validate_env_var'), patch.object(RivaTranslator, '_load_langprovider'):
                class TestRivaTranslator(RivaTranslator):
                    def __init__(self, config_root={}):
                        self.language = "en,ja"
                        self.model_type = "remote.RivaTranslator"
                        super().__init__(config_root)
                
                translator = TestRivaTranslator(config_root=config)
                
                # Test that translator can be instantiated and has cache
                assert translator.cache is not None
                assert translator.source_lang == "en"
                assert translator.target_lang == "ja"
                
                # Test that cache file path is correctly generated
                cache_file_path = translator.cache.cache_file
                assert "en_ja" in str(cache_file_path)
                assert "remote.RivaTranslator" in str(cache_file_path)
                assert "default" in str(cache_file_path)  # Default model_name
                
                # Test that translator can handle translation requests (mock)
                with patch.object(translator, '_translate_impl', return_value="こんにちは世界"):
                    result = translator._translate_with_cache("Hello world")
                    assert result == "こんにちは世界"
                    
                    # Second call should use cache
                    result2 = translator._translate_with_cache("Hello world")
                    assert result2 == "こんにちは世界"

    def test_local_translator_integration(self, temp_cache_dir):
        """Test that local translators work correctly in integration scenarios (mocked, no Passthru)."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            # モックLangProviderサブクラス
            class MockLocalProvider(LangProvider):
                def __init__(self):
                    self.language = "en,ja"
                    self.model_type = "local"
                    self.model_name = "test_model"
                    self.source_lang, self.target_lang = self.language.split(",")
                    self._validate_env_var = lambda: None
                    self._load_langprovider = lambda: None
                    self.cache = TranslationCache(self)
                def _translate(self, text):
                    return ""
                def _translate_impl(self, text):
                    return ""
            
            translator = MockLocalProvider()
            
            # Test that translator can be instantiated and has cache
            assert translator.cache is not None
            assert translator.source_lang == "en"
            assert translator.target_lang == "ja"
            
            # Test that cache file path is correctly generated
            cache_file_path = translator.cache.cache_file
            assert "en_ja" in str(cache_file_path)
            assert "local" in str(cache_file_path)
            assert "test_model" in str(cache_file_path)
            
            # Test that translator can handle translation requests (mock)
            with patch.object(translator, '_translate_impl', return_value="こんにちは世界"):
                result = translator._translate_with_cache("Hello world")
                assert result == "こんにちは世界"
                
                # Second call should use cache
                result2 = translator._translate_with_cache("Hello world")
                assert result2 == "こんにちは世界"

    def test_cache_persistence_across_sessions(self, temp_cache_dir):
        """Test that cache persists across different translator sessions (mocked, no Passthru)."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            class MockLocalProvider(LangProvider):
                def __init__(self):
                    self.language = "en,ja"
                    self.model_type = "local"
                    self.model_name = "test_model"
                    self.source_lang, self.target_lang = self.language.split(",")
                    self._validate_env_var = lambda: None
                    self._load_langprovider = lambda: None
                    self.cache = TranslationCache(self)
                def _translate(self, text):
                    return ""
            # Create first translator instance
            translator1 = MockLocalProvider()
            # Set cache entry
            test_text = "Hello world"
            test_translation = "こんにちは世界"
            translator1.cache.set(test_text, test_translation)
            # Verify cache entry was saved
            cache_entry = translator1.cache.get_cache_entry(test_text)
            assert cache_entry is not None
            assert cache_entry["translation"] == test_translation
            # Create second translator instance (simulating new session)
            translator2 = MockLocalProvider()
            # Verify cache entry is still available
            cached_translation = translator2.cache.get(test_text)
            assert cached_translation == test_translation
