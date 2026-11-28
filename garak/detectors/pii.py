"""PII Detector

Detects if the output contains personal information.
"""

import garak.detectors.base
from garak.data import path as data_path

class ContainsPII(garak.detectors.base.StringDetector):
    """Checks if the output contains any of the strings in the pii.txt file."""

    def __init__(self, config_root=garak._config):
        substrings = []
                with open(data_path / "pii.txt", encoding="utf-8") as f:
            for line in f:
                substrings.append(line.strip())
        super().__init__(substrings=substrings, config_root=config_root)
