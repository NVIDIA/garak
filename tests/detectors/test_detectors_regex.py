"""Tests for regex detector (detectors.regex.RegexDetector)"""

import pytest

from garak import _plugins
from garak.exception import GarakException
import garak.attempt


class TestRegexDetector:
    """Tests for RegexDetector"""
    
    def test_regex_via_plugin_system(self):
        """Test RegexDetector loaded via plugin system with config"""
        config = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['password', 'api.?key'],
                            'match_type': 'any',
                            're_flags': ['IGNORECASE']
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config)
        
        # Verify config loaded
        assert detector.patterns == ['password', 'api.?key']
        assert detector.match_type == 'any'
        assert detector.re_flags == ['IGNORECASE']
        
        # Test detection
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [
            garak.attempt.Message("This contains password123"),
            garak.attempt.Message("This is clean"),
        ]
        
        results = detector.detect(attempt)
        assert results[0] == 1.0  # Matches "password"
        assert results[1] == 0.0  # No match
    
    def test_multiple_patterns_any(self):
        """Test matching any of multiple patterns"""
        config = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['hack', 'exploit', 'malware'],
                            'match_type': 'any'
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config)
        
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [
            garak.attempt.Message("This talks about hacking"),
            garak.attempt.Message("This has exploit code"),
            garak.attempt.Message("This is clean"),
        ]
        
        results = detector.detect(attempt)
        assert results[0] == 1.0  # Matches "hack"
        assert results[1] == 1.0  # Matches "exploit"
        assert results[2] == 0.0  # No match
    
    def test_multiple_patterns_all(self):
        """Test requiring all patterns to match"""
        config = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['sudo', 'rm'],
                            'match_type': 'all'
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config)
        
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [
            garak.attempt.Message("sudo rm -rf /"),  # Both
            garak.attempt.Message("sudo command"),   # Only sudo
            garak.attempt.Message("rm file"),        # Only rm
        ]
        
        results = detector.detect(attempt)
        assert results[0] == 1.0  # Both patterns
        assert results[1] == 0.0  # Missing "rm"
        assert results[2] == 0.0  # Missing "sudo"
    
    def test_case_sensitivity(self):
        """Test case-sensitive vs case-insensitive matching using re_flags"""
        config_insensitive = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['PASSWORD'],
                            're_flags': ['IGNORECASE']
                        }
                    }
                }
        }
        
        config_sensitive = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['PASSWORD'],
                            're_flags': ['NOFLAG']  # No flags = case-sensitive
                        }
                    }
                }
        }
        
        detector_insensitive = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config_insensitive)
        detector_sensitive = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config_sensitive)
        
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [garak.attempt.Message("password in lowercase")]
        
        results_insensitive = detector_insensitive.detect(attempt)
        results_sensitive = detector_sensitive.detect(attempt)
        
        assert results_insensitive[0] == 1.0  # Matches (case-insensitive)
        assert results_sensitive[0] == 0.0    # No match (case-sensitive)
    
    def test_none_output_handling(self):
        """Test that None outputs are handled gracefully"""
        config = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['test']
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config)
        
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [
            garak.attempt.Message("has test"),
            None,
            garak.attempt.Message("no match"),
        ]
        
        results = detector.detect(attempt)
        assert results[0] == 1.0
        assert results[1] is None  # None preserved
        assert results[2] == 0.0
    
    def test_empty_patterns_returns_safe(self):
        """Test that RegexDetector with no patterns returns 0.0 (safe)"""
        config = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': []  # Empty patterns
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config)
        
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [garak.attempt.Message("any text here")]
        
        results = detector.detect(attempt)
        assert results[0] == 0.0  # Safe with no patterns
    
    def test_multiline_flag(self):
        """Test MULTILINE flag for matching at line boundaries"""
        config_multiline = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['^import\\s+os'],  # Match "import os" at start of line
                            're_flags': ['MULTILINE', 'IGNORECASE']
                        }
                    }
                }
        }
        
        config_no_multiline = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['^import\\s+os'],
                            're_flags': ['IGNORECASE']  # No MULTILINE
                        }
                    }
                }
        }
        
        detector_multiline = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config_multiline)
        detector_no_multiline = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config_no_multiline)
        
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        # "import os" appears at start of second line, not start of string
        attempt.outputs = [garak.attempt.Message("some code\nimport os\nmore code")]
        
        results_multiline = detector_multiline.detect(attempt)
        results_no_multiline = detector_no_multiline.detect(attempt)
        
        assert results_multiline[0] == 1.0  # Matches (^ matches line start with MULTILINE)
        assert results_no_multiline[0] == 0.0  # No match (^ only matches string start)
    
    def test_dotall_flag(self):
        """Test DOTALL flag for matching newlines with dot"""
        config_dotall = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['start.*end'],  # Match "start" to "end" across lines
                            're_flags': ['DOTALL', 'IGNORECASE']
                        }
                    }
                }
        }
        
        config_no_dotall = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['start.*end'],
                            're_flags': ['IGNORECASE']  # No DOTALL
                        }
                    }
                }
        }
        
        detector_dotall = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config_dotall)
        detector_no_dotall = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config_no_dotall)
        
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [garak.attempt.Message("start\nmiddle\nend")]
        
        results_dotall = detector_dotall.detect(attempt)
        results_no_dotall = detector_no_dotall.detect(attempt)
        
        assert results_dotall[0] == 1.0  # Matches (. matches newline with DOTALL)
        assert results_no_dotall[0] == 0.0  # No match (. doesn't match newline)
    
    def test_multiple_flags_combined(self):
        """Test combining multiple regex flags"""
        config = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['^secret.*key'],
                            're_flags': ['IGNORECASE', 'MULTILINE', 'DOTALL']
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config)
        
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [
            garak.attempt.Message("line1\nSECRET\nKEY"),  # Multiline + case-insensitive + dotall
        ]
        
        results = detector.detect(attempt)
        assert results[0] == 1.0  # All flags working together
    
    def test_short_flag_aliases(self):
        """Test using short flag names (I, M, S, etc.)"""
        config = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['^test'],
                            're_flags': ['I', 'M']  # Short for IGNORECASE, MULTILINE
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config)
        
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [garak.attempt.Message("line1\nTEST here")]
        
        results = detector.detect(attempt)
        assert results[0] == 1.0  # Short aliases work
    
    def test_invalid_flag_skipped_with_warning(self):
        """Test that invalid re_flags are skipped (not raising error)"""
        config = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['test'],
                            're_flags': ['INVALID_FLAG', 'IGNORECASE']  # Mix of invalid and valid
                        }
                    }
                }
        }
        
        # Should not raise - invalid flags are skipped with warning
        detector = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config)
        
        # Only valid flags should remain
        assert 'IGNORECASE' in detector.re_flags
        assert 'INVALID_FLAG' not in detector.re_flags
        
        # Detector should still work
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [garak.attempt.Message("TEST")]
        results = detector.detect(attempt)
        assert results[0] == 1.0  # Case-insensitive match works
    
    def test_default_flags_noflag(self):
        """Test that default re_flags includes NOFLAG"""
        config = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['PASSWORD']
                            # No re_flags specified - should default to NOFLAG
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config)
        
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [garak.attempt.Message("password")]  # lowercase
        
        results = detector.detect(attempt)
        assert results[0] == 0.0  # Default is NOFLAG (case-sensitive)
    
    def test_invalid_match_type_defaults_to_any(self):
        """Test that invalid match_type defaults to 'any' with warning (no error)"""
        config = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['hack', 'exploit'],
                            'match_type': 'invalid_type'  # Invalid
                        }
                    }
                }
        }
        
        # Should not raise - defaults to 'any' with warning
        detector = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config)
        
        assert detector.match_type == 'any'  # Defaulted
        
        # Should work with 'any' semantics
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [
            garak.attempt.Message("This has hack"),  # Matches one
            garak.attempt.Message("clean text"),     # No match
        ]
        
        results = detector.detect(attempt)
        assert results[0] == 1.0  # 'any' match
        assert results[1] == 0.0
    
    def test_invalid_regex_pattern_skipped(self):
        """Test that invalid regex patterns are skipped (not raising error)"""
        config = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['[invalid(regex', 'valid_pattern'],  # First is invalid
                            're_flags': ['IGNORECASE']
                        }
                    }
                }
        }
        
        # Should not raise - invalid patterns are skipped with warning
        detector = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config)
        
        # Only valid pattern should be compiled
        assert len(detector.compiled_patterns) == 1
        
        # Detector should still work with valid pattern
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [garak.attempt.Message("has valid_pattern here")]
        
        results = detector.detect(attempt)
        assert results[0] == 1.0
    
    def test_single_string_pattern_normalized(self):
        """Test that single string pattern is normalized to list"""
        config = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': 'single_pattern'  # String, not list
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config)
        
        # Should be normalized to list
        assert isinstance(detector.patterns, list)
        assert detector.patterns == ['single_pattern']
        
        # Should work
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [garak.attempt.Message("has single_pattern")]
        
        results = detector.detect(attempt)
        assert results[0] == 1.0
    
    def test_single_string_re_flags_normalized(self):
        """Test that single string re_flags is normalized to list"""
        config = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['test'],
                            're_flags': 'MULTILINE'  # String, not list
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config)
        
        # Should be normalized to list
        assert isinstance(detector.re_flags, list)
        assert 'MULTILINE' in detector.re_flags
    
    def test_all_invalid_patterns_returns_safe(self):
        """Test that if all patterns are invalid, detector returns 0.0 (safe)"""
        config = {
                'detectors': {
                    'regex': {
                        'RegexDetector': {
                            'patterns': ['[invalid', '(also_invalid']  # All invalid
                        }
                    }
                }
        }
        
        # Should not raise
        detector = _plugins.load_plugin('detectors.regex.RegexDetector', config_root=config)
        
        # No valid patterns compiled
        assert len(detector.compiled_patterns) == 0
        
        # Should return safe (0.0)
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [garak.attempt.Message("any text")]
        
        results = detector.detect(attempt)
        assert results[0] == 0.0  # Safe when no valid patterns
