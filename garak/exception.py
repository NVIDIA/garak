# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from enum import IntEnum


class GarakExitCodes(IntEnum):
    """Standardized exit codes for garak CLI exits.

    These codes allow wrapping tools such as CI/CD pipelines and garak ms to
    detect precisely what went wrong during a garak run, rather than relying
    on a generic non-zero exit or inspecting log output.

    Negative values are used to avoid collisions with conventional UNIX exit
    codes (0 = success, 1 = general error, 2 = misuse of shell builtins, etc.).
    """

    INTERRUPTED = -1
    PROBE_EXCEPTION = -2
    GENERATOR_EXCEPTION = -3
    DETECTOR_EXCEPTION = -4
    BUFF_EXCEPTION = -5
    EVALUATOR_EXCEPTION = -6
    HARNESS_EXCEPTION = -7
    LANGPROVIDER_EXCEPTION = -8
    REPORTING_EXCEPTION = -9
    RESOURCE_EXHAUSTED = -10
    UNSPECIFIED_EXCEPTION = -127


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
