# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Structured exit codes for garak CLI runs.

Positive codes are used because many shells truncate negative exit statuses.
See https://github.com/NVIDIA/garak/issues/1221
"""

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    INTERRUPTED = 1
    PROBE = 2
    GENERATOR = 3
    DETECTOR = 4
    BUFF = 5
    EVALUATOR = 6
    HARNESS = 7
    LANGPROVIDER = 8
    REPORTING = 9
    OUT_OF_RESOURCES = 10
    UNSPECIFIED = 127
