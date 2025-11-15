"""Custom detectors for flexible success criteria.

This module provides customizable detectors that allow users to define
their own success criteria without writing detector classes:

1. RegexDetector - Match regex patterns in outputs
2. FunctionDetector - Call user-provided functions for custom logic

CLI Examples:
    # Regex detector
    garak --detectors custom.RegexDetector \\
          --detector_options '{"custom": {"RegexDetector": {"patterns": ["api.?key","sk-[A-Za-z0-9]{32,}"]}}}
    
    # Function detector  
    garak --detectors custom.FunctionDetector \\
          --detector_options '{"custom": {"FunctionDetector": {"function_name": "mymodule#check_harmful"}}}' \\
          --probes dan.Dan_11_0
    
    # Or use config file
    garak --detectors custom.RegexDetector \\
          --detector_option_file detector_config.json \\
          --probes dan.Dan_11_0
"""

import importlib
import logging
import re
from typing import List

from garak import _config
import garak.attempt
from garak.detectors.base import Detector
from garak.resources.function_detector import dummy

class RegexDetector(Detector):
    """Detector that matches regex patterns in model outputs.
    
    Useful for detecting specific strings,
    code patterns, credentials, or any text that matches regex patterns.
    
    Configuration:
        {
          "custom": {
            "RegexDetector": {
              "patterns": ["pattern1", "pattern2", ...],
              "match_type": "any",       # or "all"
              "case_sensitive": false
            }
          }
        }
    
    Examples:
        # Detect credentials
        --detector_options '{"custom": {"RegexDetector": {
            "patterns": ["api.?key", "sk-[A-Za-z0-9]{32,}"]
        }}}'
        
        # Detect dangerous commands
        --detector_options '{"custom": {"RegexDetector": {
            "patterns": ["sudo", "rm -rf", "DROP TABLE"],
            "match_type": "any",
            "case_sensitive": false
        }}}'
    """
    lang_spec = "*"

    DEFAULT_PARAMS = Detector.DEFAULT_PARAMS | {
        "patterns": [], # users must provide patterns
        "match_type": "any",  # "any" or "all"
        "case_sensitive": False,
    }
    
    active = False
    tags = []
    
    def __init__(self, config_root=_config):
        """Initialize RegexDetector from config.
        
        Args:
            config_root: Configuration root object containing detector configuration
        
        Raises:
            ValueError: If no patterns provided or invalid regex pattern
        """
        super().__init__(config_root=config_root)
        
        # Normalize to list
        if isinstance(self.patterns, str):
            self.patterns = [self.patterns]
        
        # Validate match_type
        self.match_type = str(self.match_type).lower()
        if self.match_type not in ("any", "all"):
            raise ValueError(f"match_type must be 'any' or 'all', got '{self.match_type}'")
        
        # Compile regex patterns
        flags = 0 if self.case_sensitive else re.IGNORECASE
        try:
            self.compiled_patterns = [
                re.compile(pattern, flags) for pattern in self.patterns
            ]
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}") from e
        
        # Update description
        self.description = (
            f"Regex detector matching {self.match_type} of {len(self.patterns)} pattern(s)"
        )
        
        logging.info(
            "RegexDetector initialized with %d patterns (match_type=%s, case_sensitive=%s)",
            len(self.patterns), self.match_type, self.case_sensitive
        )
    
    def detect(self, attempt: garak.attempt.Attempt) -> List[float]:
        """Detect if outputs match regex patterns.
        
        Returns 1.0 if match found (vulnerability), 0.0 otherwise.
        
        Args:
            attempt: Attempt object containing outputs to check
            
        Returns:
            List of scores (0.0 or 1.0) for each output
        """
        results = []
        for output in attempt.outputs:
            output_text = output.text if output else None
            if output_text is None:
                results.append(None)
                continue
            
            if not self.compiled_patterns:
                results.append(0.0) # default to safe if no patterns are provided
                continue

            # Check patterns based on match_type
            if self.match_type == "any":
                # Match if ANY pattern is found
                matched = any(
                    pattern.search(output_text) for pattern in self.compiled_patterns
                )
            elif self.match_type == "all":
                # Match only if ALL patterns are found
                matched = all(
                    pattern.search(output_text) for pattern in self.compiled_patterns
                )
            else:
                raise ValueError(f"Invalid match_type: {self.match_type}")
            
            results.append(1.0 if matched else 0.0)
        
        return results


class FunctionDetector(Detector):
    """Detector that calls user-provided function for custom detection logic.
    
    Inspired by function.py generator. The user specifies a function in the format
    'module#function', and it's called with each output string.
    
    The function must have signature: function(output_text: str) -> float
    where return value is 0.0 (safe) to 1.0 (detected).
    
    Configuration (via --detector_options or --detector_option_file):
        {
          "custom": {
            "FunctionDetector": {
              "function_name": "mymodule#myfunction",
              "kwargs": {  # Optional: additional args passed to function
                "threshold": 0.5,
                "custom_param": "value"
              }
            }
          }
        }
    
    Examples:
        # In mydetectors.py:
        def check_length(output_text, min_length=100):
            return 1.0 if len(output_text) > min_length else 0.0
        
        # CLI:
        --detector_options '{"custom": {"FunctionDetector": {
            "function_name": "mydetectors#check_length",
            "kwargs": {"min_length": 150}
        }}}'
        
        # In mydetectors.py:
        def check_pii(output_text):
            import re
            has_ssn = bool(re.search(r'\\d{3}-\\d{2}-\\d{4}', output_text))
            has_email = bool(re.search(r'\\S+@\\S+', output_text))
            return 1.0 if (has_ssn or has_email) else 0.0
        
        # CLI:
        --detector_options '{"custom": {"FunctionDetector": {
            "function_name": "mydetectors#check_pii"
        }}}'
    """
    
    DEFAULT_PARAMS = Detector.DEFAULT_PARAMS | {
        "function_name": f"{dummy.__name__}#always_pass",  # users must provide a function name. We provide a dummy function for tests.
        "kwargs": {},           # Optional: additional kwargs for function
    }
    
    active = False
    tags = []
    lang_spec = "*"
    
    def __init__(self, config_root=_config):
        """Initialize FunctionDetector from config.
        
        Loads the specified function dynamically using importlib, similar to
        how function.py generator works.
        
        Args:
            config_root: Configuration root object containing detector configuration
        
        Raises:
            ValueError: If function_name not provided or invalid format
            ImportError: If module cannot be imported
            AttributeError: If function not found in module
        """
        super().__init__(config_root=config_root)

        self.function_name = str(self.function_name)

        # Parse module#function format
        if "#" not in self.function_name:
            raise ValueError(
                f"function_name must be in format 'module#function', got '{self.function_name}'"
            )
        
        module_name, func_name = self.function_name.split("#", 1)
        
        # Load the module and function
        try:
            module = importlib.import_module(module_name)
        except ImportError as e:
            raise ImportError(
                f"Could not import module '{module_name}' for FunctionDetector"
            ) from e
        
        try:
            self.detection_function = getattr(module, func_name)
        except AttributeError as e:
            raise AttributeError(
                f"Function '{func_name}' not found in module '{module_name}'"
            ) from e
        
        # Validate function is callable
        if not callable(self.detection_function):
            raise ValueError(
                f"{module_name}#{func_name} is not callable"
            )
        
        # Update description
        self.description = f"Function detector using {self.function_name}"
        
        logging.info(
            "FunctionDetector initialized with function %s (kwargs=%s)",
            self.function_name, self.kwargs
        )
    
    def detect(self, attempt: garak.attempt.Attempt) -> List[float]:
        """Call user function to detect issues in outputs.
        
        The function receives the output text (str) and returns a score (float).
        Additional kwargs from config are passed to the function.
        
        Args:
            attempt: Attempt object containing outputs to check
            
        Returns:
            List of scores (0.0-1.0) for each output
        """
        results = []
        for output in attempt.outputs:
            output_text = output.text if output else None
            if output_text is None:
                results.append(None)
                continue
        
            try:
                # Call user's function with output text
                score = self.detection_function(output_text, **self.kwargs)
                
                # Validate return type
                if not isinstance(score, (int, float)):
                    logging.error(
                        "Function %s returned non-numeric value: %s (type: %s)",
                        self.function_name, score, type(score)
                    )
                    score = 0.0
                
                # Clamp to 0-1 range (shall we raise if outside range?)
                score_clamped = max(0.0, min(1.0, float(score)))
                if score != score_clamped:
                    logging.warning(
                        "Function %s returned score outside 0-1 range: %s (clamped to %s)",
                        self.function_name, score, score_clamped
                    )
                results.append(score_clamped)
                
            except Exception as e:
                logging.error(
                    "Error calling detection function %s: %s",
                    self.function_name, e, exc_info=e
                )
                results.append(None)  # Default to None on error
        
        return results
