# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
from json import JSONDecodeError
import logging
from pathlib import Path
from typing import Optional, Tuple

from garak import _config
from garak.data import path as data_path


# Module-level cache for singleton instance
_detector_metrics_cache: Optional["DetectorMetrics"] = None


class DetectorMetrics:
    """Helper for managing detector performance metrics (sensitivity/specificity)"""

    def _load_metrics(self) -> bool:
        metrics_file = (
            Path(data_path) / "detectors_eval" / "detector_metrics_summary.json"
        )

        try:
            with open(metrics_file, "r", encoding="utf-8") as f:
                self._data = json.load(f)

            logging.debug("Loaded detector metrics from %s", metrics_file)
            return True

        except FileNotFoundError:
            logging.debug(
                "Detector metrics file not found at %s. Using default metrics (Se=1.0, Sp=1.0).",
                metrics_file,
            )
            return False

        except (JSONDecodeError, OSError) as e:
            logging.warning(
                "Could not load detector metrics from %s: %s", metrics_file, e
            )
            return False

    def get_detector_se_sp(self, detector_name: str) -> Tuple[float, float]:
        """Get sensitivity and specificity for a detector; returns (1.0, 1.0) if not found"""
        # TODO: support probe-detector pair metrics for Se/Sp (detector performance is probe dependent)
        if not self.metrics_loaded:
            return (1.0, 1.0)

        if detector_name.startswith("detector."):
            detector_name = detector_name[9:]

        results = self._data.get("results", {})
        detector_data = results.get(detector_name, {})
        metrics = detector_data.get("metrics", {})

        sensitivity = metrics.get("hit_sensitivity")
        specificity = metrics.get("hit_specificity")

        if sensitivity is None or specificity is None:
            return (1.0, 1.0)

        try:
            se = float(sensitivity)
            sp = float(specificity)

            if not (0.0 <= se <= 1.0):
                logging.warning(
                    "Invalid sensitivity %.3f for %s (must be in [0,1]), using default (1.0, 1.0)",
                    se,
                    detector_name,
                )
                return (1.0, 1.0)

            if not (0.0 <= sp <= 1.0):
                logging.warning(
                    "Invalid specificity %.3f for %s (must be in [0,1]), using default (1.0, 1.0)",
                    sp,
                    detector_name,
                )
                return (1.0, 1.0)

            return (se, sp)
        except (TypeError, ValueError) as e:
            logging.warning(
                "Could not parse metrics for %s: %s. Using default (1.0, 1.0)",
                detector_name,
                e,
            )
            return (1.0, 1.0)

    def __init__(self) -> None:
        self._data = {}
        self.metrics_loaded = self._load_metrics()


def get_detector_metrics() -> DetectorMetrics:
    """Get cached DetectorMetrics instance (singleton pattern)

    Returns the same instance across multiple calls to avoid reloading
    the metrics file from disk.
    """
    global _detector_metrics_cache
    if _detector_metrics_cache is None:
        _detector_metrics_cache = DetectorMetrics()
    return _detector_metrics_cache
