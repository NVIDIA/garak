"""Tests for custom detectors (RegexDetector and FunctionDetector)"""

import pytest
import tempfile
import sys
from pathlib import Path

from garak import _plugins
from garak.exception import GarakException
import garak.attempt


class TestRegexDetector:
    """Tests for RegexDetector"""
    
    def test_regex_via_plugin_system(self):
        """Test RegexDetector loaded via plugin system with config"""
        config = {
                'detectors': {
                    'custom': {
                        'RegexDetector': {
                            'patterns': ['password', 'api.?key'],
                            'match_type': 'any',
                            'case_sensitive': False
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.custom.RegexDetector', config_root=config)
        
        # Verify config loaded
        assert detector.patterns == ['password', 'api.?key']
        assert detector.match_type == 'any'
        assert detector.case_sensitive == False
        
        # Test detection
        attempt = garak.attempt.Attempt(prompt="test")
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
                    'custom': {
                        'RegexDetector': {
                            'patterns': ['hack', 'exploit', 'malware'],
                            'match_type': 'any'
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.custom.RegexDetector', config_root=config)
        
        attempt = garak.attempt.Attempt(prompt="test")
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
                    'custom': {
                        'RegexDetector': {
                            'patterns': ['sudo', 'rm'],
                            'match_type': 'all'
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.custom.RegexDetector', config_root=config)
        
        attempt = garak.attempt.Attempt(prompt="test")
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
        """Test case-sensitive vs case-insensitive matching"""
        config_insensitive = {
                'detectors': {
                    'custom': {
                        'RegexDetector': {
                            'patterns': ['PASSWORD'],
                            'case_sensitive': False
                        }
                    }
                }
        }
        
        config_sensitive = {
                'detectors': {
                    'custom': {
                        'RegexDetector': {
                            'patterns': ['PASSWORD'],
                            'case_sensitive': True
                        }
                    }
                }
        }
        
        detector_insensitive = _plugins.load_plugin('detectors.custom.RegexDetector', config_root=config_insensitive)
        detector_sensitive = _plugins.load_plugin('detectors.custom.RegexDetector', config_root=config_sensitive)
        
        attempt = garak.attempt.Attempt(prompt="test")
        attempt.outputs = [garak.attempt.Message("password in lowercase")]
        
        results_insensitive = detector_insensitive.detect(attempt)
        results_sensitive = detector_sensitive.detect(attempt)
        
        assert results_insensitive[0] == 1.0  # Matches (case-insensitive)
        assert results_sensitive[0] == 0.0    # No match (case-sensitive)
    
    def test_none_output_handling(self):
        """Test that None outputs are handled gracefully"""
        config = {
                'detectors': {
                    'custom': {
                        'RegexDetector': {
                            'patterns': ['test']
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.custom.RegexDetector', config_root=config)
        
        attempt = garak.attempt.Attempt(prompt="test")
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
                    'custom': {
                        'RegexDetector': {
                            'patterns': []  # Empty patterns
                        }
                    }
                }
        }
        
        detector = _plugins.load_plugin('detectors.custom.RegexDetector', config_root=config)
        
        attempt = garak.attempt.Attempt(prompt="test")
        attempt.outputs = [garak.attempt.Message("any text here")]
        
        results = detector.detect(attempt)
        assert results[0] == 0.0  # Safe with no patterns


class TestFunctionDetector:
    """Tests for FunctionDetector"""
    
    def test_function_detector_with_module(self):
        """Test FunctionDetector with module#function pattern"""
        # Create a test module with detection function
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False, dir='.'
        ) as f:
            f.write("""
def check_length(output_text, min_len=10):
    return 1.0 if len(output_text) > min_len else 0.0
""")
            module_path = Path(f.name)
        
        try:
            module_name = module_path.stem
            
            config = {
                    'detectors': {
                        'custom': {
                            'FunctionDetector': {
                                'function_name': f"{module_name}#check_length",
                                'kwargs': {'min_len': 15}
                            }
                        }
                    }
            }
            
            detector = _plugins.load_plugin('detectors.custom.FunctionDetector', config_root=config)
            
            # Verify function loaded
            assert detector.function_name == f"{module_name}#check_length"
            assert callable(detector.detection_function)
            
            # Test detection
            attempt = garak.attempt.Attempt(prompt="test")
            attempt.outputs = [
                garak.attempt.Message("short"),  # <15 chars
                garak.attempt.Message("this is a much longer message"),  # >15 chars
            ]
            
            results = detector.detect(attempt)
            assert results[0] == 0.0  # Short text
            assert results[1] == 1.0  # Long text
            
        finally:
            module_path.unlink()
            if module_name in sys.modules:
                del sys.modules[module_name]
    
    def test_function_with_kwargs(self):
        """Test that kwargs are passed to detection function"""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False, dir='.'
        ) as f:
            f.write("""
def check_with_params(output_text, threshold=50, multiplier=2.0):
    length_score = len(output_text) / threshold
    return min(1.0, length_score * multiplier)
""")
            module_path = Path(f.name)
        
        try:
            module_name = module_path.stem
            
            config = {
                    'detectors': {
                        'custom': {
                            'FunctionDetector': {
                                'function_name': f"{module_name}#check_with_params",
                                'kwargs': {'threshold': 20, 'multiplier': 1.0}
                            }
                        }
                    }
            }
            
            detector = _plugins.load_plugin('detectors.custom.FunctionDetector', config_root=config)
            
            attempt = garak.attempt.Attempt(prompt="test")
            attempt.outputs = [
                garak.attempt.Message("12345"),  # (5 chars / 20) * 1.0 = 0.25
                garak.attempt.Message("12345678901234567890"),  # (20 chars / 20) * 1.0 = 1.0
            ]
            
            results = detector.detect(attempt)
            assert results[0] == 0.25
            assert results[1] == 1.0
            
        finally:
            module_path.unlink()
            if module_name in sys.modules:
                del sys.modules[module_name]
    
    def test_function_error_returns_none(self):
        """Test that function errors result in None (not crash)"""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False, dir='.'
        ) as f:
            f.write("""
def buggy_check(output_text):
    raise RuntimeError("Intentional error")
""")
            module_path = Path(f.name)
        
        try:
            module_name = module_path.stem
            
            config = {
                    'detectors': {
                        'custom': {
                            'FunctionDetector': {
                                'function_name': f"{module_name}#buggy_check"
                            }
                        }
                    }
            }
            
            detector = _plugins.load_plugin('detectors.custom.FunctionDetector', config_root=config)
            
            attempt = garak.attempt.Attempt(prompt="test")
            attempt.outputs = [garak.attempt.Message("test")]
            
            # Should not raise, should return None
            results = detector.detect(attempt)
            assert results[0] is None  # Error defaults to None
            
        finally:
            module_path.unlink()
            if module_name in sys.modules:
                del sys.modules[module_name]
    
    def test_invalid_function_format(self):
        """Test that function_name without # raises error"""
        config = {
                'detectors': {
                    'custom': {
                        'FunctionDetector': {
                            'function_name': 'invalid_format'  # No '#' separator
                        }
                    }
                }
        }
        
        with pytest.raises(GarakException, match="must be in format 'module#function'"):
            _plugins.load_plugin('detectors.custom.FunctionDetector', config_root=config)
    
    def test_module_not_found(self):
        """Test that non-existent module raises ImportError"""
        config = {
                'detectors': {
                    'custom': {
                        'FunctionDetector': {
                            'function_name': 'nonexistent_module#function'
                        }
                    }
                }
        }
        
        with pytest.raises(GarakException, match="Could not import module"):
            _plugins.load_plugin('detectors.custom.FunctionDetector', config_root=config)
    
    def test_function_not_found(self):
        """Test that non-existent function raises AttributeError"""
        config = {
                'detectors': {
                    'custom': {
                        'FunctionDetector': {
                            'function_name': 'os#nonexistent_function'
                        }
                    }
                }
        }
        
        with pytest.raises(GarakException, match="Function .* not found"):
            _plugins.load_plugin('detectors.custom.FunctionDetector', config_root=config)
