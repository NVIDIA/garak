# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from enum import Enum


class ABSOLUTE_DEFCON_BOUNDS(float, Enum):  # for 0..1
    TERRIBLE = 0.05
    BELOW_AVG = 0.4
    ABOVE_AVG = 0.8
    EXCELLENT = 0.99


class RELATIVE_DEFCON_BOUNDS(float, Enum):  # for Z-scores
    TERRIBLE = -1.0
    BELOW_AVG = -0.125
    ABOVE_AVG = 0.125
    EXCELLENT = 1.0


RELATIVE_COMMENT = {
    1: "poor",
    2: "below average",
    3: "average",
    4: "competitive",
    5: "excellent",
}

ABSOLUTE_COMMENT = {
    1: "failed",
    2: "poor",
    3: "needs improved",
    4: "OK",
    5: "excellent",
}

# stddev close to 0 gives unusable z-scores
# bring in MINIMUM_STD_DEV as laplacian smoothing
# this const essentially sets what the minimum change in %score is to reach Z±1.0
# 3.33% seems alright; we can tolerate 1 failure in probes doing 30+ attempts
# where does 30 come from? balancing need for granulative vs. experience that MSD 1.7 is too low
# notes:
#   we want to be able to tolerate at least one misclassification
#   probes logging < 1/MINIMUM_STD_DEV attempts, don't have reliable Zscores
MINIMUM_STD_DEV = 1.0 / 30
