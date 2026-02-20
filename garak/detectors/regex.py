"""Regex-based detector for pattern matching in model outputs.

This module provides a configurable regex detector that allows users to
detect specific patterns in LLM outputs.

CLI Examples:
    # Using --config with a consolidated YAML config file (recommended)
    garak --config my_scan_config.yaml
    
    # Example my_scan_config.yaml:
    # ---
    # plugins:
    #   probe_spec: dan.Dan_11_0
    #   detector_spec: regex.RegexDetector
    #   detectors:
    #     regex:
    #       RegexDetector:
    #         patterns:
    #           - "api.?key"
    #           - "sk-[A-Za-z0-9]{32,}"
    #         match_type: "any"
    #         re_flags: ["IGNORECASE"] # list of re.RegexFlag names (NOFLAG by default)
    
    # Or using inline --detector_options
    garak --detectors regex.RegexDetector \\
          --detector_options '{"regex": {"RegexDetector": {"patterns": ["api.?key","sk-[A-Za-z0-9]{32,}"]}}}' \\
          --probes dan.Dan_11_0
"""

import logging
import re
from typing import List

from garak import _config
import garak.attempt
from garak.detectors.base import Detector


class RegexDetector(Detector):
    """Detector that matches regex patterns in model outputs.
    
    Useful for detecting specific strings,
    code patterns, credentials, or any text that matches regex patterns.
    
    Available re_flags (from re.RegexFlag):
        - NOFLAG: No special flags (default behavior)
        - IGNORECASE (or I): Case-insensitive matching
        - MULTILINE (or M): ^ and $ match at line boundaries
        - DOTALL (or S): . matches any character including newline
        - VERBOSE (or X): Allow comments and whitespace in pattern
        - ASCII (or A): ASCII-only matching for \\w, \\b, etc.
        - LOCALE (or L): Locale-dependent matching (discouraged)
    """
    lang_spec = "*"

    DEFAULT_PARAMS = Detector.DEFAULT_PARAMS | {
        "patterns": [],  # users must provide patterns
        "match_type": "any",  # "any" or "all"
        "re_flags": ["NOFLAG"],  # list of re.RegexFlag names to combine
    }
    
    active = False
    tags = []
    
    def __init__(self, config_root=_config):
        """Initialize RegexDetector from config.
        
        Args:
            config_root: Configuration root object containing detector configuration
        """
        super().__init__(config_root=config_root)
        
        # Normalize patterns to list
        if isinstance(self.patterns, str):
            self.patterns = [self.patterns]
        
        # Validate match_type
        self.match_type = str(self.match_type).lower()
        if self.match_type not in ("any", "all"):
            logging.warning(
                "regex.RegexDetector: match_type must be 'any' or 'all', got '%s' - defaulting to 'any'", self.match_type
            )
            self.match_type = "any"
        
        # Normalize re_flags to list
        if isinstance(self.re_flags, str):
            self.re_flags = [self.re_flags]
        
        # Validate and combine regex flags (skip invalid ones with warning)
        # Use 0 for compatibility with Python 3.10 (re.NOFLAG added in 3.11)
        combined_flags = getattr(re, "NOFLAG", 0)
        valid_flags = []
        for flag_name in self.re_flags:
            flag_name_upper = str(flag_name).upper()
            if not hasattr(re, flag_name_upper):
                logging.warning(
                    "regex.RegexDetector: Unknown flag '%s' - skipping", flag_name
                )
                continue
            flag_value = getattr(re, flag_name_upper)
            # Ensure it's actually a RegexFlag, not some other re attribute
            if not isinstance(flag_value, re.RegexFlag):
                logging.warning(
                    "regex.RegexDetector: '%s' is not a valid re.RegexFlag - skipping", flag_name
                )
                continue
            combined_flags |= flag_value
            valid_flags.append(flag_name_upper)
        
        self.re_flags = valid_flags  # Update to only valid flags
        
        self._combined_flags = combined_flags
        
        # Compile regex patterns with combined flags
        self.compiled_patterns = []
        for pattern in self.patterns:
            try:
                self.compiled_patterns.append(re.compile(pattern, combined_flags))
            except re.error as e:
                logging.warning(
                    "regex.RegexDetector: Invalid regex pattern '%s': %s - skipping", pattern, e
                )
                continue
        
        # Update description
        flags_str = "|".join(self.re_flags) if self.re_flags else "NOFLAG"
        self.description = (
            f"Regex detector matching {self.match_type} of {len(self.patterns)} pattern(s) "
            f"with flags: {flags_str}"
        )
        
        logging.info(
            "regex.RegexDetector initialized with %d patterns (match_type=%s, re_flags=%s)",
            len(self.patterns), self.match_type, self.re_flags
        )
    
    def detect(self, attempt: garak.attempt.Attempt) -> List[float]:
        """Detect if outputs match regex patterns.
        
        Returns 1.0 if match found (vulnerability), 0.0 otherwise.
        
        Args:
            attempt: Attempt object containing outputs to check
            
        Returns:
            List of scores (0.0 or 1.0) for each output
        """
        results = [None] * len(attempt.outputs)
        
        for idx, output in enumerate(attempt.outputs):
            output_text = output.text if output else None
            if output_text is None:
                continue

            # If no patterns configured, return 0.0 (no match) for valid outputs
            if not self.compiled_patterns:
                logging.warning(
                    "regex.RegexDetector: No compiled patterns found, setting 0.0 (no match or safe)"
                )
                results[idx] = 0.0
                continue

            # Check patterns based on match_type
            matched = False
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
                logging.warning(
                    "regex.RegexDetector: Invalid match_type: '%s'", self.match_type
                )
                continue
            
            results[idx] = 1.0 if matched else 0.0
        
        return results
