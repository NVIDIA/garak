"""Function-based detector for custom detection logic.

Call a given function to use as a detector; specify this as the
function_name parameter in the format 'module#function'.

This detector is analogous to generators.function and allows users to
provide custom detection logic without writing detector classes.

CLI Examples:
    # Using --config with a consolidated YAML config file (recommended)
    garak --config my_scan_config.yaml
    
    # Example my_scan_config.yaml:
    # ---
    # plugins:
    #   probe_spec: dan.Dan_11_0
    #   detector_spec: function.FunctionDetector
    #   detectors:
    #     function:
    #       FunctionDetector:
    #         function_name: "mymodule#check_harmful"
    #         kwargs:
    #           threshold: 0.5
    
    # Or using inline --detector_options
    garak --detectors function.FunctionDetector \\
          --detector_options '{"function": {"FunctionDetector": {"function_name": "mymodule#check_harmful"}}}' \\
          --probes dan.Dan_11_0
"""

import importlib
import logging
from typing import List

from garak import _config
import garak.attempt
from garak.detectors.base import Detector
from garak.resources.function_detector import dummy


class FunctionDetector(Detector):
    """Detector that calls user-provided function for custom detection logic.
    
    Inspired by generators.function. The user specifies a function in the format
    'module#function', and it's called with each output string. Additional kwargs 
    can be passed to the function.
    
    The function must have signature: function(output_text: str, **kwargs) -> float
    where return value is 0.0 (safe) to 1.0 (detected).
    """
    
    DEFAULT_PARAMS = Detector.DEFAULT_PARAMS | {
        "function_name": f"{dummy.__name__}#always_pass",  # users must provide a function name. We provide a dummy function for tests.
        "kwargs": {},  # Optional: additional kwargs for function
    }
    
    active = False
    tags = []
    lang_spec = "*"
    
    def __init__(self, config_root=_config):
        """Initialize FunctionDetector from config.
        
        Loads the specified function dynamically using importlib, similar to
        how generators.function works.
        
        Args:
            config_root: Configuration root object containing detector configuration
        """
        super().__init__(config_root=config_root)

        self.function_name = str(self.function_name)
        self.detection_function = None  # Will be set if loading succeeds

        # Parse module#function format
        if "#" not in self.function_name:
            logging.warning(
                "function.FunctionDetector: function_name must be in format 'module#function', "
                "got '%s' - detector will return None for all outputs",
                self.function_name
            )
            self.description = f"Function detector (invalid config: {self.function_name})"
            return
        
        module_name, func_name = self.function_name.split("#", 1)
        
        # Load the module and function
        # Note: module reference is not stored; we only keep self.detection_function
        # The function object holds a reference to its module, preventing garbage collection
        try:
            module = importlib.import_module(module_name)
        except ImportError as e:
            logging.warning(
                "function.FunctionDetector: Could not import module '%s': %s - "
                "detector will return None for all outputs",
                module_name, e
            )
            self.description = f"Function detector (module not found: {module_name})"
            return
        
        try:
            self.detection_function = getattr(module, func_name)
        except AttributeError:
            logging.warning(
                "function.FunctionDetector: Function '%s' not found in module '%s' - "
                "detector will return None for all outputs",
                func_name, module_name
            )
            self.description = f"Function detector (function not found: {func_name})"
            return
        
        # Validate function is callable
        if not callable(self.detection_function):
            logging.warning(
                "function.FunctionDetector: '%s#%s' is not callable - "
                "detector will return None for all outputs",
                module_name, func_name
            )
            self.detection_function = None
            self.description = f"Function detector (not callable: {self.function_name})"
            return
        
        # Update description
        self.description = f"Function detector using {self.function_name}"
        
        logging.info(
            "function.FunctionDetector initialized with function %s (kwargs=%s)",
            self.function_name, self.kwargs
        )
    
    def detect(self, attempt: garak.attempt.Attempt) -> List[float]:
        """Call user function to detect issues in outputs.
        
        The function receives the output text (str) and returns a score (float).
        Additional kwargs from config are passed to the function.
        
        Args:
            attempt: Attempt object containing outputs to check
            
        Returns:
            List of scores (0.0-1.0) for each output, or [None] * len if detector failed to initialize
        """
        results = [None] * len(attempt.outputs)
        for idx, output in enumerate(attempt.outputs):
            output_text = output.text if output else None
            
            if output_text is None:
                continue

            if self.detection_function is None:
                logging.warning(
                    "function.FunctionDetector: No detection function found (or failed to load), setting None",
                )
                continue
        
            try:
                # Call user's function with output text
                score = self.detection_function(output_text, **self.kwargs)
                
                # Validate return type
                if not isinstance(score, (int, float)):
                    logging.error(
                        "function.FunctionDetector: %s returned non-numeric value: %s (type: %s). Setting 0.0",
                        self.function_name, score, type(score)
                    )
                    score = 0.0
                
                # Clamp to 0-1 range
                score_clamped = max(0.0, min(1.0, float(score)))
                if score != score_clamped:
                    logging.warning(
                        "function.FunctionDetector: %s returned score outside 0-1 range: %s (clamped to %s)",
                        self.function_name, score, score_clamped
                    )
                results[idx] = score_clamped
                
            except Exception as e:
                logging.error(
                    "function.FunctionDetector: Error calling %s: %s",
                    self.function_name, e, exc_info=e
                )
                results[idx] = None  # Default to None on error
        
        return results
