# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import tempfile
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

from garak.langproviders.base import LangProvider, TranslationCache
from garak.langproviders.local import Passthru


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

    def test_cache_initialization(self, temp_cache_dir, mock_config):
        """Test that cache is properly initialized."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            # Create a test-specific subclass that properly initializes
            class TestPassthru(Passthru):
                def __init__(self, config_root={}):
                    # Set language before calling parent __init__
                    self.language = "en,ja"
                    self.model_type = "test"
                    super().__init__(config_root)

            translator = TestPassthru(config_root=mock_config)

            # Check that cache directory was created
            cache_dir = temp_cache_dir / "translation"
            assert cache_dir.exists()

            # Check that cache file was created with correct name
            expected_cache_file = cache_dir / "translation_cache_en_ja_test.json"
            assert translator.cache.cache_file_path == expected_cache_file

            # Check that cache is initialized as empty dict
            assert translator.cache.cache == {}

    def test_cache_save_and_load(self, temp_cache_dir, mock_config):
        """Test that cache can be saved and loaded."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            # Create a test-specific subclass that properly initializes
            class TestPassthru(Passthru):
                def __init__(self, config_root={}):
                    # Set language before calling parent __init__
                    self.language = "en,ja"
                    self.model_type = "test"
                    super().__init__(config_root)

            translator = TestPassthru(config_root=mock_config)

            # Add some test data to cache
            test_text = "Hello world"
            test_translation = "こんにちは世界"
            translator.cache.set(test_text, test_translation)

            # Check that cache file was created
            assert translator.cache.cache_file_path.exists()

            # Create new translator instance to test loading
            translator2 = TestPassthru(config_root=mock_config)

            # Check that cached translation is loaded
            cached_result = translator2.cache.get(test_text)
            assert cached_result == test_translation

    def test_cache_key_generation(self, temp_cache_dir, mock_config):
        """Test that cache keys are generated consistently."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            # Create a test-specific subclass that properly initializes
            class TestPassthru(Passthru):
                def __init__(self, config_root={}):
                    # Set language before calling parent __init__
                    self.language = "en,ja"
                    self.model_type = "test"
                    super().__init__(config_root)

            translator = TestPassthru(config_root=mock_config)

            text1 = "Hello world"
            text2 = "Hello world"  # Same text
            text3 = "Different text"

            key1 = translator.cache.get_cache_key(text1)
            key2 = translator.cache.get_cache_key(text2)
            key3 = translator.cache.get_cache_key(text3)

            # Same text should have same key
            assert key1 == key2

            # Different text should have different key
            assert key1 != key3

    def test_translate_with_cache(self, temp_cache_dir, mock_config):
        """Test that translation uses cache when available."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            # Create a test-specific subclass that properly initializes
            class TestPassthru(Passthru):
                def __init__(self, config_root={}):
                    # Set language before calling parent __init__
                    self.language = "en,ja"
                    self.model_type = "test"
                    super().__init__(config_root)

            translator = TestPassthru(config_root=mock_config)

            test_text = "Hello world"

            # First translation should not be cached
            result1 = translator._translate_with_cache(test_text)
            assert result1 == test_text  # Passthru returns original text

            # Second translation should use cache
            with patch.object(translator, "_translate_impl") as mock_translate:
                result2 = translator._translate_with_cache(test_text)
                # Should not call _translate_impl again
                mock_translate.assert_not_called()
                assert result2 == test_text

    def test_cache_file_corruption_handling(self, temp_cache_dir, mock_config):
        """Test that corrupted cache files are handled gracefully."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            # Create a test-specific subclass that properly initializes
            class TestPassthru(Passthru):
                def __init__(self, config_root={}):
                    # Set language before calling parent __init__
                    self.language = "en,ja"
                    self.model_type = "test"
                    super().__init__(config_root)

            translator = TestPassthru(config_root=mock_config)

            # Create a corrupted cache file
            translator.cache.cache_file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(translator.cache.cache_file_path, "w") as f:
                f.write("invalid json content")

            # Should handle corruption gracefully
            translator.cache._cache = translator.cache._load_cache()
            assert translator.cache.cache == {}

    def test_cache_with_different_language_pairs(self, temp_cache_dir, mock_config):
        """Test that different language pairs use different cache files."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            # Create translator with en->ja
            class TestPassthru1(Passthru):
                def __init__(self, config_root={}):
                    self.language = "en,ja"
                    self.model_type = "test"
                    super().__init__(config_root)

            translator1 = TestPassthru1(config_root=mock_config)

            # Create translator with ja->en
            mock_config_ja_en = {
                "langproviders": {
                    "passthru": {"language": "ja,en", "model_type": "test"}
                }
            }

            class TestPassthru2(Passthru):
                def __init__(self, config_root={}):
                    self.language = "ja,en"
                    self.model_type = "test"
                    super().__init__(config_root)

            translator2 = TestPassthru2(config_root=mock_config_ja_en)

            # Check that different cache files are created
            assert (
                translator1.cache.cache_file_path != translator2.cache.cache_file_path
            )
            assert "en_ja" in str(translator1.cache.cache_file_path)
            assert "ja_en" in str(translator2.cache.cache_file_path)

    def test_cache_with_different_model_types(self):
        """Test cache works with different model types."""
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

        cache1 = TranslationCache(config1)
        cache2 = TranslationCache(config2)

        # Different model types should create different cache files
        assert cache1.cache_file_path != cache2.cache_file_path

        # Test caching works for both
        cache1.set("hello", "こんにちは")
        cache2.set("hello", "こんにちは")

        assert cache1.get("hello") == "こんにちは"
        assert cache2.get("hello") == "こんにちは"

    def test_cache_stores_original_text(self):
        """Test that cache stores original text along with translation."""
        config = {
            "langproviders": {
                "local": {
                    "language": "en,ja",
                    "model_type": "local",
                    "name": "test_model",
                }
            }
        }

        cache = TranslationCache(config)
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

    def test_backward_compatibility(self):
        """Test backward compatibility with old cache format."""
        config = {
            "langproviders": {
                "local": {
                    "language": "en,ja",
                    "model_type": "local",
                    "name": "test_model",
                }
            }
        }

        cache = TranslationCache(config)

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
                assert "en_ja" in str(translator_riva.cache.cache_file_path)
                assert "remote.RivaTranslator" in str(translator_riva.cache.cache_file_path)
            
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
                assert "en_ja" in str(translator_deepl.cache.cache_file_path)
                assert "remote.DeeplTranslator" in str(translator_deepl.cache.cache_file_path)
            
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
                assert "en_ja" in str(translator_google.cache.cache_file_path)
                assert "remote.GoogleTranslator" in str(translator_google.cache.cache_file_path)

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
