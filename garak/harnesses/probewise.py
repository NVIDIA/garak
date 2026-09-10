# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Probewise harness

Selects detectors to run for each probe based on that probe's recommendations
"""

import logging
import math
import statistics
from pathlib import Path

from colorama import Fore, Style

from garak.analyze.calibration import Calibration
from garak.detectors.base import Detector
from garak.harnesses.base import Harness

from garak import _config, _plugins


class ProbewiseHarness(Harness):
    """Run probes with their recommended detectors."""

    probe_order: str
    calibration_path: str | Path | None
    calibration_aggregation: str
    uncalibrated_score: float
    skip_uncalibrated_probes: bool

    DEFAULT_PARAMS = Harness.DEFAULT_PARAMS | {
        "probe_order": "alphabetical",
        "calibration_path": None,
        "calibration_aggregation": "max",
        "uncalibrated_score": 1.0,
        "skip_uncalibrated_probes": False,
    }

    _calibration_aggregators = {
        "max": max,
        "mean": statistics.fmean,
        "median": statistics.median,
        "min": min,
    }

    def _validate_calibration_config(self) -> None:
        if self.calibration_aggregation not in self._calibration_aggregators:
            choices = ", ".join(sorted(self._calibration_aggregators))
            raise ValueError(f"calibration_aggregation must be one of: {choices}")

        if (
            isinstance(self.uncalibrated_score, bool)
            or not isinstance(self.uncalibrated_score, (int, float))
            or not math.isfinite(self.uncalibrated_score)
            or not 0.0 <= self.uncalibrated_score <= 1.0
        ):
            raise ValueError("uncalibrated_score must be between 0.0 and 1.0")

        if not isinstance(self.skip_uncalibrated_probes, bool):
            raise ValueError("skip_uncalibrated_probes must be a boolean")

    def _order_probes(self, probenames: list[str]) -> list[str]:
        if self.probe_order == "alphabetical":
            return sorted(probenames)
        if self.probe_order != "calibration":
            raise ValueError("probe_order must be 'alphabetical' or 'calibration'")

        self._validate_calibration_config()
        calibration = Calibration(self.calibration_path)
        if not calibration.calibration_successfully_loaded:
            raise ValueError(
                f"Unable to load calibration data from {calibration.calibration_filename}"
            )

        aggregate = self._calibration_aggregators[self.calibration_aggregation]
        scored_probes = []
        skipped_probes = []
        for probename in probenames:
            detector_asrs = calibration.get_probe_asrs(probename)
            if detector_asrs:
                score = aggregate(detector_asrs)
            elif self.skip_uncalibrated_probes:
                skipped_probes.append(probename)
                continue
            else:
                score = self.uncalibrated_score
            scored_probes.append((probename, score))

        if skipped_probes:
            logging.warning(
                "Skipping probes absent from calibration data: %s",
                ", ".join(sorted(skipped_probes)),
            )

        return [
            probename
            for probename, _ in sorted(
                scored_probes, key=lambda probe_score: (-probe_score[1], probe_score[0])
            )
        ]

    def _load_detector(self, detector_name: str) -> Detector:
        detector = _plugins.load_plugin(
            "detectors." + detector_name, break_on_fail=False
        )
        if detector:
            return detector
        else:
            print(f" detector load failed: {detector_name}, skipping >>")
            logging.error(f" detector load failed: {detector_name}, skipping >>")
        return False

    def run(self, model, probenames, evaluator, buff_names=None):
        """Execute a probe-by-probe scan

        Probes are executed in the configured order. For each probe, the
        detectors recommended by that probe are loaded and used to provide
        scores of the results. The detector(s) to be used are determined with the
        following formula:
        * if the probe specifies a ``primary_detector``; ``_config.args`` is
        set; and ``_config.args.extended_detectors`` is true; the union of
        ``primary_detector`` and ``extended_detectors`` are used.
        * if the probe specifies a ``primary_detector`` and ``_config.args.extended_detectors``
        if false, or ``_config.args`` is not set, then only the detector in
        ``primary_detector`` is used.
        * if the probe does not specify ``primary_detector`` value, or this is
        ``None``, then detectors are queued based on the from the probe's
        ``recommended_detectors`` value; see :class:`garak.probes.base.Probe` for the defaults.

        :param model: an instantiated generator providing an interface to the model to be examined
        :type model: garak.generators.base.Generator
        :param probenames: a list of probe names to be run
        :type probenames: List[str]
        :param evaluator: an instantiated evaluator for judging detector results
        :type evaluator: garak.evaluators.base.Evaluator
        :param buff_names: a list of buff names to be used this run
        :type buff_names: List[str]
        """

        if buff_names is None:
            buff_names = []

        if not probenames:
            msg = "No probes, nothing to do"
            logging.warning(msg)
            if hasattr(_config.system, "verbose") and _config.system.verbose >= 2:
                print(msg)
            raise ValueError(msg)

        self._load_buffs(buff_names)

        probenames = self._order_probes(probenames)
        print(
            f"🕵️  queue of {Style.BRIGHT}{Fore.LIGHTYELLOW_EX}probes:{Style.RESET_ALL} "
            + ", ".join([name.replace("probes.", "") for name in probenames])
        )
        logging.info("probe queue: %s", " ".join(probenames))
        for probename in probenames:
            try:
                probe = _plugins.load_plugin(probename)
            except Exception as e:
                print(f"failed to load probe {probename}")
                logging.warning("failed to load probe %s:", repr(e))
                continue
            if not probe:
                continue
            detectors = []

            if probe.primary_detector:
                d = self._load_detector(probe.primary_detector)
                if d:
                    detectors = [d]
                if _config.plugins.extended_detectors is True:
                    for detector_name in sorted(probe.extended_detectors):
                        d = self._load_detector(detector_name)
                        if d:
                            detectors.append(d)

            else:
                # Fallback for edge cases where migration didn't occur
                from garak import command

                command.deprecation_notice(
                    f"recommended_detector in probe {probename} (fallback path)",
                    "0.9.0.6",
                    logging=logging,
                )
                for detector_name in sorted(probe.recommended_detector):
                    d = self._load_detector(detector_name)
                    if d:
                        detectors.append(d)

            super().run(model, [probe], detectors, evaluator, announce_probe=False)
            # del probe, h, detectors
