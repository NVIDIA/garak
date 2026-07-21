#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Calculate calibration statistics from one or more garak JSONL reports."""

from collections import defaultdict
import argparse
import datetime
import json
import re
import sys

import numpy as np
import scipy

import garak
from garak import _config

_BAG_ID = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")


def _validate_bag_id(bag_id):
    """Return a valid model-bag ID or raise ``ValueError``."""
    if bag_id is not None and (
        not isinstance(bag_id, str) or _BAG_ID.fullmatch(bag_id) is None
    ):
        raise ValueError(f"invalid model-bag ID: {bag_id!r}")
    return bag_id


def _bag_id_argument(value):
    """Validate a model-bag ID for argparse."""
    try:
        return _validate_bag_id(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def build_score_dict(filenames, bag_id=None):
    """Build calibration statistics with their source and model-bag metadata."""
    bag_id = _validate_bag_id(bag_id)

    eval_scores = defaultdict(list)
    for filename in filenames:
        with open(filename, "r", encoding="utf-8") as report_file:
            for line in report_file:
                if not line.strip():
                    continue
                record = json.loads(line)
                if record["entry_type"] == "eval":
                    key = (
                        record["probe"]
                        + "/"
                        + record["detector"].replace("detector.", "")
                    )
                    if record["total_evaluated"] != 0:
                        value = float(record["passed"]) / record["total_evaluated"]
                        eval_scores[key].append(value)
                    else:
                        print(
                            f"invalid result check {filename} for {key}: "
                            "total tests was 0"
                        )

    distribution_dict = {}
    for key in eval_scores:
        mu = np.mean(eval_scores[key])
        sigma = np.std(eval_scores[key])
        sw_p = float(scipy.stats.shapiro(eval_scores[key]).pvalue)
        distribution_dict[key] = {"mu": mu, "sigma": sigma, "sw_p": sw_p}

    distribution_dict["garak_calibration_meta"] = {
        "bag": bag_id,
        "date": str(datetime.datetime.now(datetime.timezone.utc)) + "Z",
        "filenames": filenames,
    }

    return distribution_dict


def main(argv=None) -> None:
    """Run the calibration statistics command-line interface."""
    if argv is None:
        argv = sys.argv[1:]

    _config.load_config()
    print(
        f"garak {garak.__description__} v{_config.version} ( https://github.com/NVIDIA/garak )"
    )

    parser = argparse.ArgumentParser(
        prog="python -m garak.analyze.perf_stats",
        description="Compute performance statistics across one or more garak JSONL reports",
        epilog="See https://github.com/NVIDIA/garak",
        allow_abbrev=False,
    )
    parser.add_argument(
        "-r",
        "--report_paths",
        metavar="REPORT",
        nargs="+",
        help="One or more garak JSONL report paths",
    )
    parser.add_argument(
        "reports_positional",
        nargs="*",
        help="One or more garak JSONL report paths (positional)",
    )
    parser.add_argument(
        "--bag-id",
        metavar="ID",
        type=_bag_id_argument,
        help="Model-bag ID recorded in the calibration metadata",
    )
    args = parser.parse_args(argv)

    sys.stdout.reconfigure(encoding="utf-8")
    report_list = args.report_paths or args.reports_positional
    if not report_list:
        parser.error(
            "one or more report paths are required (-r/--report_paths or positional)"
        )
    distribution_dict = build_score_dict(report_list, bag_id=args.bag_id)
    print(json.dumps(distribution_dict, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
