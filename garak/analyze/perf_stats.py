#!/usr/bin/env python

# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# input: list of report jsonl
# process:
#  for each combination of probe & detector:
#   compute mean, standard deviation, shapiro-wilk across all input report evals
# output: json dict: keys are probe/detector, values are dict: keys are mu, sigma, sw

from collections import defaultdict
import datetime
from glob import glob
import json
import os

import numpy as np
import scipy


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
                if r["total"] != 0:
                    value = float(r["passed"]) / r["total"]
                    eval_scores[key].append(value)
                else:
                    print(f"invalid result check {filename} for {key}: total tests was 0")

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


if __name__ == "__main__":
    import sys

    sys.stdout.reconfigure(encoding="utf-8")

    input_filenames = sys.argv[1:]
    distribution_dict = build_score_dict(input_filenames)
    print(json.dumps(distribution_dict, indent=2, sort_keys=True))
