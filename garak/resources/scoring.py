# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import statistics
from typing import List

from garak.analyze import ABSOLUTE_DEFCON_BOUNDS


def aggregate(scores: List[float], aggregation_function: str = "lower_quartile"):

    unknown_function = False

    if len(scores) == 0:
        raise ValueError("Cannot aggregate an empty list")

    match aggregation_function:
        # get all the scores

        case "mean":
            aggregate_score = statistics.mean(scores)
        case "minimum":
            aggregate_score = min(scores)
        case "median":
            aggregate_score = statistics.median(scores)
        case "lower_quartile":
            if len(scores) == 1:
                aggregate_score = scores[0]
            else:
                aggregate_score = statistics.quantiles(scores, method="inclusive")[0]
        case "mean_minus_sd":
            if len(scores) == 1:
                aggregate_score = scores[0]
            else:
                aggregate_score = statistics.mean(scores) - statistics.stdev(scores)
        case "proportion_passing":
            aggregate_score = len(
                [p for p in scores if p > ABSOLUTE_DEFCON_BOUNDS.BELOW_AVG]
            ) / len(scores)
        case _:
            aggregate_score = min(scores)  # minimum as default
            unknown_function = True

    return aggregate_score, unknown_function
