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
import scipy.stats

import garak
from garak import _config


def _normalize_name(name: str, category: str) -> str:
    for prefix in (f"garak.{category}.", f"{category}."):
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


def build_score_dict(filenames):
    eval_scores = defaultdict(list)
    for filename in filenames:
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                if r.get("entry_type") == "eval":
                    probe_name = _normalize_name(r["probe"], "probes")
                    detector_name = _normalize_name(r["detector"], "detectors")
                    key = f"{probe_name}/{detector_name}"
                    if r.get("total_evaluated", 0) != 0:
                        value = float(r["passed"]) / r["total_evaluated"]
                        eval_scores[key].append(value)
                    else:
                        print(
                            f"invalid result check {filename} for {key}: total tests was 0"
                        )

    distribution_dict = {}
    for key in eval_scores:
        scores = eval_scores[key]
        mu = float(np.mean(scores))
        sigma = float(np.std(scores))
        if len(scores) >= 3:
            sw_stat = scipy.stats.shapiro(scores)
            pvalue = float(sw_stat.pvalue)
            sw_p = pvalue if not np.isnan(pvalue) else None
        else:
            sw_p = None
        distribution_dict[key] = {"mu": mu, "sigma": sigma, "sw_p": sw_p}

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if now_iso.endswith("+00:00"):
        now_iso = now_iso[:-6] + "Z"
    distribution_dict["garak_calibration_meta"] = {
        "date": now_iso,
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
