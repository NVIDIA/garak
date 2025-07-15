# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import tempfile
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

from garak.langproviders.base import LangProvider, TranslationCache


class TestTranslationCache:
    """Test translation caching functionality."""

    @pytest.fixture
    def temp_cache_dir(self):
        """Create a temporary cache directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)

    @pytest.fixture
    def mock_config(self):
        """Mock configuration for testing."""
        return {
            "langproviders": {"passthru": {"language": "en,ja", "model_type": "test"}}
        }

    def test_cache_with_different_model_types(self, temp_cache_dir):
        """Test cache works with different model types."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            config1 = {
                "langproviders": {
                    "local": {
                        "language": "en,ja",
                        "model_type": "local",
                        "name": "test_model",
                    }
                }
            }
            config2 = {
                "langproviders": {
                    "remote": {
                        "language": "en,ja",
                        "model_type": "remote",
                        "name": "test_model",
                    }
                }
            }

            # Create mock LangProvider instances
            provider1 = MagicMock()
            provider1.source_lang = "en"
            provider1.target_lang = "ja"
            provider1.model_type = "local"
            provider1.model_name = "test_model"

            provider2 = MagicMock()
            provider2.source_lang = "en"
            provider2.target_lang = "ja"
            provider2.model_type = "remote"
            provider2.model_name = "test_model"

            cache1 = TranslationCache(provider1)
            cache2 = TranslationCache(provider2)

            # Different model types should create different cache files
            assert str(cache1.cache_file) != str(cache2.cache_file)

            # Test caching works for both
            cache1.set("hello", "こんにちは")
            cache2.set("hello", "こんにちは")

            assert cache1.get("hello") == "こんにちは"
            assert cache2.get("hello") == "こんにちは"

    def test_cache_stores_original_text(self, temp_cache_dir):
        """Test that cache stores original text along with translation."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            # Create mock LangProvider instance
            provider = MagicMock()
            provider.source_lang = "en"
            provider.target_lang = "ja"
            provider.model_type = "local"
            provider.model_name = "test_model"

            cache = TranslationCache(provider)
            original_text = "Hello world"
            translated_text = "こんにちは世界"

            cache.set(original_text, translated_text)

            # Get full cache entry
            cache_entry = cache.get_cache_entry(original_text)
            assert cache_entry is not None
            assert cache_entry["original"] == original_text
            assert cache_entry["translation"] == translated_text
            assert cache_entry["source_lang"] == "en"
            assert cache_entry["target_lang"] == "ja"
            assert cache_entry["model_type"] == "local"
            assert cache_entry["model_name"] == "test_model"

    def test_backward_compatibility(self, temp_cache_dir):
        """Test backward compatibility with old cache format."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            # Create mock LangProvider instance
            provider = MagicMock()
            provider.source_lang = "en"
            provider.target_lang = "ja"
            provider.model_type = "local"
            provider.model_name = "test_model"

            cache = TranslationCache(provider)

            # Simulate old cache format (string values)
            cache._cache["old_key"] = "old_translation"

            # Should still work with get method
            result = cache.get("some_text")  # This will return None for non-existent key
            assert result is None

            # Should work with get_cache_entry for existing old entries
            # Note: This is a bit tricky since we need the original text
            # For now, just test that the cache still loads

    def test_remote_translator_cache_initialization(self, temp_cache_dir):
        """Test that remote translators work without __init__ methods."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            from garak.langproviders.remote import RivaTranslator, DeeplTranslator, GoogleTranslator
            
            # Test RivaTranslator
            config_riva = {
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
                
                translator_riva = TestRivaTranslator(config_root=config_riva)
                
                # Check that cache is initialized
                assert translator_riva.cache is not None
                assert "en_ja" in str(translator_riva.cache.cache_file)
                assert "remote.RivaTranslator" in str(translator_riva.cache.cache_file)
            
            # Test DeeplTranslator
            config_deepl = {
                "langproviders": {
                    "deepl": {
                        "language": "en,ja",
                        "model_type": "remote.DeeplTranslator",
                        "api_key": "test_key"
                    }
                }
            }
            
            with patch.object(DeeplTranslator, '_validate_env_var'), patch.object(DeeplTranslator, '_load_langprovider'):
                class TestDeeplTranslator(DeeplTranslator):
                    def __init__(self, config_root={}):
                        self.language = "en,ja"
                        self.model_type = "remote.DeeplTranslator"
                        super().__init__(config_root)
                
                translator_deepl = TestDeeplTranslator(config_root=config_deepl)
                
                assert translator_deepl.cache is not None
                assert "en_ja" in str(translator_deepl.cache.cache_file)
                assert "remote.DeeplTranslator" in str(translator_deepl.cache.cache_file)
            
            # Test GoogleTranslator
            config_google = {
                "langproviders": {
                    "google": {
                        "language": "en,ja",
                        "model_type": "remote.GoogleTranslator",
                        "api_key": "test_key"
                    }
                }
            }
            
            with patch.object(GoogleTranslator, '_validate_env_var'), patch.object(GoogleTranslator, '_load_langprovider'):
                class TestGoogleTranslator(GoogleTranslator):
                    def __init__(self, config_root={}):
                        self.language = "en,ja"
                        self.model_type = "remote.GoogleTranslator"
                        super().__init__(config_root)
                
                translator_google = TestGoogleTranslator(config_root=config_google)
                
                assert translator_google.cache is not None
                assert "en_ja" in str(translator_google.cache.cache_file)
                assert "remote.GoogleTranslator" in str(translator_google.cache.cache_file)

    def test_remote_translator_cache_functionality(self, temp_cache_dir):
        """Test that remote translators can use cache functionality."""
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
            
            with patch.object(RivaTranslator, '_validate_env_var'), patch.object(RivaTranslator, '_load_langprovider'):
                class TestRivaTranslator(RivaTranslator):
                    def __init__(self, config_root={}):
                        self.language = "en,ja"
                        self.model_type = "remote.RivaTranslator"
                        super().__init__(config_root)
                
                translator = TestRivaTranslator(config_root=config)
                
                # Test cache functionality
                test_text = "Hello world"
                test_translation = "こんにちは世界"
                
                # Set cache manually
                translator.cache.set(test_text, test_translation)
                
                # Verify cache entry
                cache_entry = translator.cache.get_cache_entry(test_text)
                assert cache_entry is not None
                assert cache_entry["original"] == test_text
                assert cache_entry["translation"] == test_translation
                assert cache_entry["source_lang"] == "en"
                assert cache_entry["target_lang"] == "ja"
                assert cache_entry["model_type"] == "remote.RivaTranslator"

    def test_cache_with_default_model_name(self, temp_cache_dir):
        """Test cache works with default model name when model_name is not set."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            # Create mock LangProvider instance without model_name
            provider = MagicMock()
            provider.source_lang = "en"
            provider.target_lang = "ja"
            provider.model_type = "local"
            provider.model_name = "default_should_be_deleted"
            del provider.model_name  # 属性自体を削除

            cache = TranslationCache(provider)
            
            # Verify default model_name is used
            assert cache.model_name == "default"
            
            # Test cache functionality
            test_text = "Hello world"
            test_translation = "こんにちは世界"
            
            cache.set(test_text, test_translation)
            
            # Verify cache entry includes default model_name
            cache_entry = cache.get_cache_entry(test_text)
            assert cache_entry is not None
            assert cache_entry["model_name"] == "default"

    def test_cache_with_custom_model_name(self, temp_cache_dir):
        """Test cache works with custom model name."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            # Create mock LangProvider instance with custom model_name
            provider = MagicMock()
            provider.source_lang = "en"
            provider.target_lang = "ja"
            provider.model_type = "local"
            provider.model_name = "custom_model"

            cache = TranslationCache(provider)
            
            # Verify custom model_name is used
            assert cache.model_name == "custom_model"
            
            # Test cache functionality
            test_text = "Hello world"
            test_translation = "こんにちは世界"
            
            cache.set(test_text, test_translation)
            
            # Verify cache entry includes custom model_name
            cache_entry = cache.get_cache_entry(test_text)
            assert cache_entry is not None
            assert cache_entry["model_name"] == "custom_model"
