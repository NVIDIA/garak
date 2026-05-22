# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from enum import IntEnum


class ExitCode(IntEnum):
    """Exit codes for garak CLI.

    Wrapping tools (CI pipelines, orchestration, garak-as-a-service) can use
    these to distinguish failure modes without parsing stderr.  Codes follow
    the proposal in https://github.com/NVIDIA/garak/issues/1221.
    """

    SUCCESS = 0
    INTERRUPTED = -1  # ctrl-c / SIGTERM / SIGKILL
    PROBE_EXCEPTION = -2  # unhandled exception inside a probe
    GENERATOR_EXCEPTION = -3  # unhandled exception inside a generator
    DETECTOR_EXCEPTION = -4  # unhandled exception inside a detector
    BUFF_EXCEPTION = -5  # unhandled exception inside a buff
    EVALUATOR_EXCEPTION = -6  # unhandled exception inside an evaluator
    HARNESS_EXCEPTION = -7  # unhandled exception inside a harness
    LANGPROVIDER_EXCEPTION = -8  # unhandled exception inside a langprovider
    REPORT_EXCEPTION = -9  # unhandled exception during reporting
    OUT_OF_LOCAL_RESOURCES = -10  # memory / disk exhaustion
    UNSPECIFIED_EXCEPTION = -127  # any other unhandled exception


class GarakException(Exception):
    """Base class for all  garak exceptions"""


class APIKeyMissingError(GarakException):
    """Exception to be raised if a required API key is not found"""


class TargetNameMissingError(GarakException):
    """A generator requires target_name to be set, but it wasn't"""


class GeneratorBackoffTrigger(GarakException):
    """Thrown when backoff should be triggered"""


class PluginConfigurationError(GarakException):
    """Plugin config/description is not usable"""


class BadGeneratorException(PluginConfigurationError):
    """Generator invocation requested is not usable"""


class RateLimitHit(Exception):
    """Raised when a rate limiting response is returned"""


class ConfigFailure(GarakException):
    """Raised when plugin configuration fails"""


class PayloadFailure(GarakException):
    """Problem instantiating/using payloads"""


class ReportIncompatibleError(GarakException):
    """Report references plugins unknown to the current garak install; the report is not compatible with this version"""
