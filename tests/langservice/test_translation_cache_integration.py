# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch

from garak.langproviders.local import Passthru
from garak.langproviders.base import LangProvider


class TestTranslationCacheIntegration:
    """Integration test for translation caching functionality."""

    @pytest.fixture
    def temp_cache_dir(self):
        """Create a temporary cache directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)

    @pytest.fixture
    def mock_config(self):
        """Mock configuration for testing."""
        return {
            "langproviders": {"passthru": {"language": "ja,en", "model_type": "test"}}
        }

    def test_get_text_with_cache(self, temp_cache_dir, mock_config):
        """Test that get_text method uses cache correctly."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            # Create a test-specific subclass that properly initializes
            class TestPassthru(Passthru):
                def __init__(self, config_root={}):
                    # Set language before calling parent __init__
                    self.language = "ja,en"
                    self.model_type = "test"
                    super().__init__(config_root)

            translator = TestPassthru(config_root=mock_config)

            prompts = [
                "こんにちは",
                "おはよう",
                "こんにちは",
            ]  # Japanese text, duplicate

            # First call should translate all prompts
            results1 = translator.get_text(prompts)
            assert results1 == ["こんにちは", "おはよう", "こんにちは"]

            # Second call should use cache for duplicate
            results2 = translator.get_text(prompts)
            assert results2 == ["こんにちは", "おはよう", "こんにちは"]

            # Verify cache was used by checking if cache file exists
            assert translator.cache.cache_file_path.parent.exists()

    def test_cache_persistence(self, temp_cache_dir, mock_config):
        """Test that cache persists between translator instances."""
        with patch("garak._config.transient.cache_dir", temp_cache_dir):
            # Create a test-specific subclass that properly initializes
            class TestPassthru(Passthru):
                def __init__(self, config_root={}):
                    # Set language before calling parent __init__
                    self.language = "ja,en"
                    self.model_type = "test"
                    super().__init__(config_root)

            # Create first translator
            translator1 = TestPassthru(config_root=mock_config)
            translator1._translate("テストテキスト")

            # Create second translator with same config
            translator2 = TestPassthru(config_root=mock_config)

            # Check that cache file is shared
            assert (
                translator1.cache.cache_file_path == translator2.cache.cache_file_path
            )

            # Verify cache was loaded
            cached_result = translator2.cache.get("テストテキスト")
            assert cached_result == "テストテキスト"

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
                cache_file_path = translator.cache.cache_file_path
                assert "en_ja" in str(cache_file_path)
                assert "remote.RivaTranslator" in str(cache_file_path)
                
                # Test that translator can handle translation requests (mock)
                with patch.object(translator, '_translate_impl', return_value="こんにちは世界"):
                    result = translator._translate_with_cache("Hello world")
                    assert result == "こんにちは世界"
                    
                    # Second call should use cache
                    result2 = translator._translate_with_cache("Hello world")
                    assert result2 == "こんにちは世界"
