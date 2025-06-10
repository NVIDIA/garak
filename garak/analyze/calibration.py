# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
from json import JSONDecodeError
import os
import logging
import pathlib
import re
from typing import Union


from garak.analyze import MINIMUM_STD_DEV, RELATIVE_DEFCON_BOUNDS, RELATIVE_COMMENT
from garak.data import path as data_path


class Calibration:
    """Helper for managing probe/detector score calibration data processing"""

    def _load_calibration(
        self, calibration_filename: Union[str, None] = None
    ) -> Union[None, int]:

        if calibration_filename is None:
            calibration_filename = self.calibration_filename

        if os.path.isfile(calibration_filename):
            try:
                with open(
                    calibration_filename, "r", encoding="utf-8"
                ) as calibration_file:
                    content = calibration_file.read().strip()
            except Exception as e:  # don't stop here
                logging.warning(
                    "Exception during calibration data load: %s", e, exc_info=e
                )
                return None

            if re.match(
                r"^calibration[^/\\]+.json$", content
            ):  # win git can check out symlinks as text files of destination
                calibration_filename = self._build_path(content)

                try:
                    with open(
                        calibration_filename, "r", encoding="utf-8"
                    ) as calibration_file:
                        content = calibration_file.read().strip()
                except Exception as e:  # don't stop here
                    logging.warning(
                        "Exception during calibration data load: %s", e, exc_info=e
                    )
                    return None
            try:
                self._data = json.loads(content)
            except JSONDecodeError as je:
                logging.warning(
                    "Couldn't decode calibration JSON in %s: %s",
                    calibration_filename,
                    je,
                    exc_info=je,
                )
                return None

        else:
            logging.warning("Calibration path not found: %s", calibration_filename)
            return None

        if "garak_calibration_meta" in self._data:
            self.metadata = self._data["garak_calibration_meta"]
            del self._data["garak_calibration_meta"]

        return len(self._data)

    def _calc_z(self, mu: float, sigma: float, score: float) -> float:
        zscore = (score - mu) / sigma
        return zscore

    def get_z_score(
        self,
        probe_module: str,
        probe_classname: str,
        detector_module: str,
        detector_classname: str,
        score: float,
    ) -> Union[float, None]:

        if not self.calibration_successfully_loaded:
            return None

        calibration_key = (
            f"{probe_module}.{probe_classname}/{detector_module}.{detector_classname}"
        )
        zscore = None
        if calibration_key in self._data:
            distr = self._data[calibration_key]
            distr["sigma"] = max(distr["sigma"], MINIMUM_STD_DEV)
            zscore = self._calc_z(distr["mu"], distr["sigma"], score)
        return zscore

    def defcon_and_comment(
        self, zscore: float, defcon_comments: Union[None, dict] = None
    ):
        if defcon_comments == None:
            defcon_comments = RELATIVE_COMMENT

        zscore_defcon, zscore_comment = None, None
        if zscore < RELATIVE_DEFCON_BOUNDS.TERRIBLE:
            zscore_defcon = 1
        elif zscore < RELATIVE_DEFCON_BOUNDS.BELOW_AVG:
            zscore_defcon = 2
        elif zscore < RELATIVE_DEFCON_BOUNDS.ABOVE_AVG:
            zscore_defcon = 3
        elif zscore <= RELATIVE_DEFCON_BOUNDS.EXCELLENT:
            zscore_defcon = 4
        else:
            zscore_defcon = 5
        zscore_comment = defcon_comments[zscore_defcon]
        return zscore_defcon, zscore_comment

    def _build_path(self, filename):
        return data_path / "calibration" / filename

    def __init__(self, calibration_path: Union[None, str, pathlib.Path] = None) -> None:

        self._data = {}
        self.metadata = None

        if calibration_path is None:
            self.calibration_filename = self._build_path("calibration.json")

        else:
            if not isinstance(calibration_path, str) or isinstance(
                calibration_path, pathlib.Path
            ):
                raise ValueError("calibration_path must be a string or Path")
            self.calibration_filename = calibration_path

        entries_loaded = self._load_calibration(self.calibration_filename)

        self.calibration_successfully_loaded = entries_loaded != None
