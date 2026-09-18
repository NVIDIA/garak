# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from enum import IntEnum


class ExitCode(IntEnum):
    """Exit codes for garak CLI.

    Wrapping tools (CI pipelines, orchestration, garak-as-a-service) can use
    these to distinguish failure modes without parsing stderr, using
    positive values so they map cleanly onto POSIX/Windows exit-status
    conventions (0-255, treated as unsigned) instead of negative integers.
    Garak-specific codes (168-176) sit above the 128+signal range so they
    can't collide with a signal-derived exit; `/usr/include/sysexits.h` and
    https://tldp.org/LDP/abs/html/exitcodes.html were consulted as reference
    points, and OUT_OF_LOCAL_RESOURCES intentionally reuses sysexits.h's
    EX_OSERR (71) for its close semantic match.
    """

    SIGNAL_BASE = 128  # base for exit codes derived from a signal number

    # OS standard exits adopted from https://tldp.org/LDP/abs/html/exitcodes.html
    SUCCESS = 0
    OUT_OF_LOCAL_RESOURCES = 71  # memory / disk exhaustion
    INTERRUPTED = 130  # ctrl-c / fatal error signal 2 (128 + SIGINT)

    # garak specific exit codes
    UNSPECIFIED_EXCEPTION = 168  # any other unhandled exception
    PROBE_EXCEPTION = 169  # unhandled exception inside a probe
    GENERATOR_EXCEPTION = 170  # unhandled exception inside a generator
    DETECTOR_EXCEPTION = 171  # unhandled exception inside a detector
    BUFF_EXCEPTION = 172  # unhandled exception inside a buff
    EVALUATOR_EXCEPTION = 173  # unhandled exception inside an evaluator
    HARNESS_EXCEPTION = 174  # unhandled exception inside a harness
    LANGPROVIDER_EXCEPTION = 175  # unhandled exception inside a langprovider
    REPORT_EXCEPTION = 176  # unhandled exception during reporting


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
