#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# calculate calibration data given a list of report.jsonl files
# input: list of report jsonl
# process:
#  for each combination of probe & detector:
#   compute mean, standard deviation, shapiro-wilk across all input report evals
# output: json dict: keys are probe/detector, values are dict: keys are mu, sigma, sw

from collections import defaultdict
import datetime
import json
import sys

import numpy as np
import scipy

import garak
from garak import _config


def build_score_dict(filenames):
    eval_scores = defaultdict(list)
    for filename in filenames:
        records = (
            json.loads(line.strip())
            for line in open(filename, "r", encoding="utf-8")
            if line.strip()
        )
        for r in records:
            if r["entry_type"] == "eval":
                key = r["probe"] + "/" + r["detector"].replace("detector.", "")
                if r["total_evaluated"] != 0:
                    value = float(r["passed"]) / r["total_evaluated"]
                    eval_scores[key].append(value)
                else:
                    print(
                        f"invalid result check {filename} for {key}: total tests was 0"
                    )

    distribution_dict = {}
    for key in eval_scores:
        mu = np.mean(eval_scores[key])
        sigma = np.std(eval_scores[key])
        sw_p = float(scipy.stats.shapiro(eval_scores[key]).pvalue)
        distribution_dict[key] = {"mu": mu, "sigma": sigma, "sw_p": sw_p}

    distribution_dict["garak_calibration_meta"] = {
        "date": str(datetime.datetime.now(datetime.UTC)) + "Z",
        "filenames": filenames,
    }

    return distribution_dict


def main(argv=None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    import argparse

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
    args = parser.parse_args(argv)

    sys.stdout.reconfigure(encoding="utf-8")
    report_list = args.report_paths or args.reports_positional
    if not report_list:
        parser.error(
            "one or more report paths are required (-r/--report_paths or positional)"
        )
    distribution_dict = build_score_dict(report_list)
    print(json.dumps(distribution_dict, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
