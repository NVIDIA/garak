# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""pxd harness

The pxd (probes x detectors) harness runs all specified probes and analyses
results using all specified detectors.

It's thorough, and might end up doing some comparisons that don't make so
much sense, because not all detectors are designed to pick up failure modes
in all situations.
"""

import logging
from colorama import Fore, Style

from garak.harnesses.base import Harness

import garak._plugins as _plugins


class PxD(Harness):
    def run(self, model, probe_names, detector_names, evaluator, buff_names=None):
        if buff_names is None:
            buff_names = []
        probe_names = sorted(probe_names)
        detector_names = sorted(detector_names)
        print(
            f"🕵️  queue of {Style.BRIGHT}{Fore.LIGHTYELLOW_EX}probes:{Style.RESET_ALL} "
            + ", ".join([name.replace("probes.", "") for name in probe_names])
        )
        print(
            f"🔎 queue of {Style.RESET_ALL}{Fore.LIGHTBLUE_EX}detectors:{Style.RESET_ALL} "
            + ", ".join([name.replace("detectors.", "") for name in detector_names])
        )
        logging.info("probe queue: %s", " ".join(probe_names))
        self._load_buffs(buff_names)
        for probename in probe_names:
            try:
                probe = _plugins.load_plugin(probename)
            except Exception as e:
                message = f"{probename} load exception 🛑, skipping >>"
                print(message, str(e))
                logging.error("%s %s", message, str(e))
                continue
            if not probe:
                message = f"{probename} load failed ⚠️, skipping >>"
                print(message)
                logging.warning(message)
                continue
            detectors = []
            for detector_name in detector_names:
                detector = _plugins.load_plugin(detector_name, break_on_fail=False)
                if detector:
                    detectors.append(detector)
                else:
                    msg = f" detector load failed: {detector_name}, skipping >>"
                    print(msg)
                    logging.error(msg)
            super().run(model, [probe], detectors, evaluator, announce_probe=False)
            # del probe, h, detectors
