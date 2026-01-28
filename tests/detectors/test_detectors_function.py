"""Tests for function detector (detectors.function.FunctionDetector)"""

import pytest
import tempfile
import sys
from pathlib import Path

from garak import _plugins
from garak.exception import GarakException
import garak.attempt


class TestFunctionDetector:
    """Tests for FunctionDetector"""

    def test_default_dummy_function(self):
        """Test that the default dummy function always passes"""
        detector = _plugins.load_plugin('detectors.function.FunctionDetector')
        
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [garak.attempt.Message("test")]
        
        results = detector.detect(attempt)
        assert results[0] == 0.0 # default dummy function always passes
    
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
                        'function': {
                            'FunctionDetector': {
                                'function_name': f"{module_name}#check_length",
                                'kwargs': {'min_len': 15}
                            }
                        }
                    }
            }
            
            detector = _plugins.load_plugin('detectors.function.FunctionDetector', config_root=config)
            
            # Verify function loaded
            assert detector.function_name == f"{module_name}#check_length"
            assert callable(detector.detection_function)
            
            # Test detection
            attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
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
                        'function': {
                            'FunctionDetector': {
                                'function_name': f"{module_name}#check_with_params",
                                'kwargs': {'threshold': 20, 'multiplier': 1.0}
                            }
                        }
                    }
            }
            
            detector = _plugins.load_plugin('detectors.function.FunctionDetector', config_root=config)
            
            attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
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
                        'function': {
                            'FunctionDetector': {
                                'function_name': f"{module_name}#buggy_check"
                            }
                        }
                    }
            }
            
            detector = _plugins.load_plugin('detectors.function.FunctionDetector', config_root=config)
            
            attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
            attempt.outputs = [garak.attempt.Message("test")]
            
            # Should not raise, should return None
            results = detector.detect(attempt)
            assert results[0] is None  # Error defaults to None
            
        finally:
            module_path.unlink()
            if module_name in sys.modules:
                del sys.modules[module_name]
    
    def test_invalid_function_format(self):
        """Test that function_name without # logs warning and returns None for all outputs"""
        config = {
                'detectors': {
                    'function': {
                        'FunctionDetector': {
                            'function_name': 'invalid_format'  # No '#' separator
                        }
                    }
                }
        }
        
        # Should not raise - graceful handling
        detector = _plugins.load_plugin('detectors.function.FunctionDetector', config_root=config)
        
        # detection_function should be None
        assert detector.detection_function is None
        
        # detect() should return [None] * len(outputs)
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [garak.attempt.Message("test"), garak.attempt.Message("test2")]
        
        results = detector.detect(attempt)
        assert results == [None, None]
    
    def test_module_not_found(self):
        """Test that non-existent module logs warning and returns None for all outputs"""
        config = {
                'detectors': {
                    'function': {
                        'FunctionDetector': {
                            'function_name': 'nonexistent_module#function'
                        }
                    }
                }
        }
        
        # Should not raise - graceful handling
        detector = _plugins.load_plugin('detectors.function.FunctionDetector', config_root=config)
        
        # detection_function should be None
        assert detector.detection_function is None
        
        # detect() should return [None] * len(outputs)
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [garak.attempt.Message("test")]
        
        results = detector.detect(attempt)
        assert results == [None]
    
    def test_function_not_found(self):
        """Test that non-existent function logs warning and returns None for all outputs"""
        config = {
                'detectors': {
                    'function': {
                        'FunctionDetector': {
                            'function_name': 'os#nonexistent_function'
                        }
                    }
                }
        }
        
        # Should not raise - graceful handling
        detector = _plugins.load_plugin('detectors.function.FunctionDetector', config_root=config)
        
        # detection_function should be None
        assert detector.detection_function is None
        
        # detect() should return [None] * len(outputs)
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
        attempt.outputs = [garak.attempt.Message("test")]
        
        results = detector.detect(attempt)
        assert results == [None]
    
    def test_none_output_handling(self):
        """Test that None outputs are handled gracefully"""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False, dir='.'
        ) as f:
            f.write("""
def simple_check(output_text):
    return 1.0 if 'test' in output_text else 0.0
""")
            module_path = Path(f.name)
        
        try:
            module_name = module_path.stem
            
            config = {
                    'detectors': {
                        'function': {
                            'FunctionDetector': {
                                'function_name': f"{module_name}#simple_check"
                            }
                        }
                    }
            }
            
            detector = _plugins.load_plugin('detectors.function.FunctionDetector', config_root=config)
            
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
            
        finally:
            module_path.unlink()
            if module_name in sys.modules:
                del sys.modules[module_name]
    
    def test_score_clamping(self):
        """Test that scores outside 0-1 range are clamped"""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False, dir='.'
        ) as f:
            f.write("""
def bad_score(output_text):
    if 'high' in output_text:
        return 5.0  # Too high
    elif 'low' in output_text:
        return -1.0  # Too low
    return 0.5
""")
            module_path = Path(f.name)
        
        try:
            module_name = module_path.stem
            
            config = {
                    'detectors': {
                        'function': {
                            'FunctionDetector': {
                                'function_name': f"{module_name}#bad_score"
                            }
                        }
                    }
            }
            
            detector = _plugins.load_plugin('detectors.function.FunctionDetector', config_root=config)
            
            attempt = garak.attempt.Attempt(prompt=garak.attempt.Message())
            attempt.outputs = [
                garak.attempt.Message("high score"),
                garak.attempt.Message("low score"),
                garak.attempt.Message("normal"),
            ]
            
            results = detector.detect(attempt)
            assert results[0] == 1.0  # Clamped from 5.0
            assert results[1] == 0.0  # Clamped from -1.0
            assert results[2] == 0.5  # Normal
            
        finally:
            module_path.unlink()
            if module_name in sys.modules:
                del sys.modules[module_name]
