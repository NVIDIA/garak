# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.exit_codes import ExitCode


class GarakException(Exception):
    """Base class for all  garak exceptions"""

    exit_code: int | None = None


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


class ProbeError(GarakException):
    exit_code = ExitCode.PROBE


class GeneratorError(GarakException):
    exit_code = ExitCode.GENERATOR


class DetectorError(GarakException):
    exit_code = ExitCode.DETECTOR


class BuffError(GarakException):
    exit_code = ExitCode.BUFF


class EvaluatorError(GarakException):
    exit_code = ExitCode.EVALUATOR


class HarnessError(GarakException):
    exit_code = ExitCode.HARNESS


class LangProviderError(GarakException):
    exit_code = ExitCode.LANGPROVIDER


class ReportingError(GarakException):
    exit_code = ExitCode.REPORTING
