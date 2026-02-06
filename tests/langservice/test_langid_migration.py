# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import re

# Test imports for langid
try:
    import langid
    LANGID_AVAILABLE = True
except ImportError:
    LANGID_AVAILABLE = False


@pytest.mark.skipif(not LANGID_AVAILABLE, reason="langid not installed")
class TestLangidMigration:
    """Test suite for langid migration from langdetect"""

    def test_langid_import(self):
        """Test that langid can be imported successfully"""
        import langid
        assert langid is not None
        assert hasattr(langid, 'classify')

    def test_langid_classify_basic(self):
        """Test basic langid.classify functionality"""
        # Test English
        lang, conf = langid.classify("Hello world")
        assert lang == "en"
        assert isinstance(conf, float)
        
        # Test Spanish
        lang, conf = langid.classify("Hola mundo")
        assert lang == "es"
        
        # Test French
        lang, conf = langid.classify("Bonjour le monde")
        assert lang == "fr"
        
        # Test Japanese
        lang, conf = langid.classify("こんにちは世界")
        assert lang == "ja"
        
        # Test Russian (might be detected as similar Cyrillic language)
        lang, conf = langid.classify("Привет мир")
        assert lang in ["ru", "bg", "mk"]  # Russian, Bulgarian, or Macedonian are acceptable

    @pytest.mark.parametrize("text,expected_lang", [
        ("Hello world", "en"),
        ("Hola mundo", "es"),
        ("Bonjour le monde", "fr"),
        ("Guten Tag", "de"),
        ("Ciao mondo", "it"),
        ("Olá mundo", "pt"),
        ("こんにちは", "ja"),
        ("你好世界", "zh"),
        ("مرحبا بالعالم", "ar"),
        ("Здравствуй мир", ["ru", "bg", "mk"]),  # Cyrillic could be detected as multiple languages
    ])
    def test_langid_multiple_languages(self, text, expected_lang):
        """Test langid with multiple languages"""
        lang, conf = langid.classify(text)
        if isinstance(expected_lang, list):
            assert lang in expected_lang
        else:
            assert lang == expected_lang

    def test_langid_edge_cases(self):
        """Test langid handles edge cases gracefully"""
        # Empty string
        lang, conf = langid.classify("")
        assert isinstance(lang, str)
        assert isinstance(conf, float)
        
        # Whitespace only
        lang, conf = langid.classify("   ")
        assert isinstance(lang, str)
        
        # Numbers only
        lang, conf = langid.classify("12345")
        assert isinstance(lang, str)
        
        # Special characters
        lang, conf = langid.classify("!@#$%^&*()")
        assert isinstance(lang, str)
        
        # Mixed content
        lang, conf = langid.classify("Hello123世界")
        assert isinstance(lang, str)

    def test_langid_confidence_scores(self):
        """Test that langid returns reasonable confidence scores"""
        # Clear English text should have high confidence
        lang, conf = langid.classify("This is a clear English sentence with multiple words.")
        assert lang == "en"
        
        # Short text might have lower confidence but should still work
        lang, conf = langid.classify("Hi")
        assert isinstance(conf, float)
        
        # Gibberish should still return something
        lang, conf = langid.classify("asdfghjkl")
        assert isinstance(lang, str)
        assert isinstance(conf, float)


class TestIsMeaningStringFunction:
    """Test the is_meaning_string function with langid"""
    
    def _is_meaning_string(self, text: str) -> bool:
        """Reimplementation of is_meaning_string for testing"""
        # Detect Language: Skip if no valid language is detected
        try:
            lang, confidence = langid.classify(text)
        except Exception:
            return False

        if lang == "en":
            return False

        # Length and pattern checks: Skip if it's too short or repetitive
        if len(text) < 3 or re.match(r"(.)\1{3,}", text):  # e.g., "aaaa" or "123123"
            return False

        return True

    @pytest.mark.skipif(not LANGID_AVAILABLE, reason="langid not installed")
    def test_is_meaning_string_english(self):
        """Test that English text returns False"""
        assert self._is_meaning_string("Hello world") == False
        assert self._is_meaning_string("This is English") == False
        assert self._is_meaning_string("Testing") == False

    @pytest.mark.skipif(not LANGID_AVAILABLE, reason="langid not installed")
    def test_is_meaning_string_non_english(self):
        """Test that non-English text returns True"""
        assert self._is_meaning_string("Hola mundo") == True
        assert self._is_meaning_string("Bonjour le monde") == True
        assert self._is_meaning_string("こんにちは") == True
        # Test with Cyrillic text (detected as non-English)
        cyrillic_text = "Привет мир"
        lang, _ = langid.classify(cyrillic_text)
        expected = lang != "en"  # Should be non-English
        assert self._is_meaning_string(cyrillic_text) == expected

    @pytest.mark.skipif(not LANGID_AVAILABLE, reason="langid not installed")
    def test_is_meaning_string_edge_cases(self):
        """Test edge cases for is_meaning_string"""
        # Too short
        assert self._is_meaning_string("ab") == False
        assert self._is_meaning_string("a") == False
        
        # Repetitive patterns
        assert self._is_meaning_string("aaaa") == False
        assert self._is_meaning_string("1111") == False
        assert self._is_meaning_string("abababab") == False  # This might pass as it's not (.)\1{3,}
        
        # Empty or whitespace
        assert self._is_meaning_string("") == False
        assert self._is_meaning_string("   ") == False

    @pytest.mark.skipif(not LANGID_AVAILABLE, reason="langid not installed")
    @pytest.mark.parametrize("text,expected", [
        ("Hello world", False),  # English
        ("Hola mundo", True),    # Spanish
        ("Bonjour", True),       # French
        ("aaaa", False),         # Repetitive
        ("ab", False),           # Too short
        ("123123", False),       # Pattern
        ("", False),             # Empty
        ("こんにちは", True),      # Japanese
        ("Test", False),         # English
        ("café", True),          # French with accent
    ])
    def test_is_meaning_string_parametrized(self, text, expected):
        """Parametrized test for is_meaning_string"""
        assert self._is_meaning_string(text) == expected


class TestLangidPerformance:
    """Test langid performance characteristics"""
    
    @pytest.mark.skipif(not LANGID_AVAILABLE, reason="langid not installed")
    def test_langid_consistency(self):
        """Test that langid gives consistent results"""
        text = "Hello world"
        results = []
        for _ in range(5):
            lang, _ = langid.classify(text)
            results.append(lang)
        
        # All results should be the same
        assert len(set(results)) == 1
        assert results[0] == "en"

    @pytest.mark.skipif(not LANGID_AVAILABLE, reason="langid not installed")
    def test_langid_handles_mixed_scripts(self):
        """Test langid with mixed scripts"""
        # English with some numbers
        lang, _ = langid.classify("Hello 123 world")
        assert lang == "en"
        
        # Japanese with English
        lang, _ = langid.classify("こんにちは Hello")
        assert lang in ["ja", "en"]  # Could be detected as either
        
        # URL-like text
        lang, _ = langid.classify("https://example.com")
        assert isinstance(lang, str)  # Should not crash


@pytest.mark.skipif(not LANGID_AVAILABLE, reason="langid not installed")
def test_langid_vs_langdetect_compatibility():
    """Test that langid can replace langdetect functionality"""
    # This test verifies that langid provides similar functionality to langdetect
    # We focus on longer, clearer texts for more reliable detection
    test_texts = {
        "en": ["Hello world this is English", "This is a test sentence in English"],
        "es": ["Hola mundo esto es español", "Esta es una oración de prueba en español"],
        "fr": ["Bonjour monde c'est français", "Ceci est une phrase de test en français"],
        "de": ["Hallo Welt das ist Deutsch", "Das ist ein deutscher Testsatz"],
        "ja": ["これは日本語のテストです", "こんにちは世界これは日本語です"],
    }
    
    correct_detections = 0
    total_detections = 0
    
    for expected_lang, texts in test_texts.items():
        for text in texts:
            lang, conf = langid.classify(text)
            total_detections += 1
            if lang == expected_lang:
                correct_detections += 1
            # Print mismatches for debugging (but don't fail the test)
            elif len(text) > 10:  # Only report on longer texts
                print(f"Note: Expected {expected_lang} for '{text}' but got {lang}")
    
    # We expect at least 70% accuracy for longer, clear texts
    accuracy = correct_detections / total_detections
    assert accuracy >= 0.7, f"Language detection accuracy {accuracy:.2%} is below 70%"


if __name__ == "__main__":
    # Allow running tests directly without pytest
    import sys
    
    if not LANGID_AVAILABLE:
        print("langid is not installed. Please install it with: pip install langid")
        sys.exit(1)
    
    print("Running langid migration tests...")
    
    # Create test instances
    test_basic = TestLangidMigration()
    test_function = TestIsMeaningStringFunction()
    test_perf = TestLangidPerformance()
    
    # Run basic tests
    test_basic.test_langid_import()
    print("✓ langid import test passed")
    
    test_basic.test_langid_classify_basic()
    print("✓ langid classify basic test passed")
    
    test_basic.test_langid_edge_cases()
    print("✓ langid edge cases test passed")
    
    # Run function tests
    test_function.test_is_meaning_string_english()
    print("✓ is_meaning_string English test passed")
    
    test_function.test_is_meaning_string_non_english()
    print("✓ is_meaning_string non-English test passed")
    
    test_function.test_is_meaning_string_edge_cases()
    print("✓ is_meaning_string edge cases test passed")
    
    # Run performance tests
    test_perf.test_langid_consistency()
    print("✓ langid consistency test passed")
    
    test_perf.test_langid_handles_mixed_scripts()
    print("✓ langid mixed scripts test passed")
    
    test_langid_vs_langdetect_compatibility()
    print("✓ langid vs langdetect compatibility test passed")
    
    print("\n✅ All langid migration tests passed successfully!")