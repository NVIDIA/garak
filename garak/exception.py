# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0


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


# Exit codes used by the CLI on abnormal termination. The bucket layout
# follows the proposal in https://github.com/NVIDIA/garak/issues/1221.
# The negatives in that proposal are flattened to positive ints here because
# shells wrap process exit codes to an unsigned 8-bit value.
EXIT_OK = 0
EXIT_INTERRUPTED = 1
EXIT_PROBE_ERROR = 2
EXIT_GENERATOR_ERROR = 3
EXIT_DETECTOR_ERROR = 4
EXIT_BUFF_ERROR = 5
EXIT_EVALUATOR_ERROR = 6
EXIT_HARNESS_ERROR = 7
EXIT_LANGPROVIDER_ERROR = 8
EXIT_REPORTING_ERROR = 9
EXIT_OUT_OF_LOCAL_RESOURCES = 10
EXIT_CONFIG_ERROR = 11
EXIT_UNSPECIFIED = 127
