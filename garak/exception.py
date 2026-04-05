# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from enum import IntEnum


class ExitCode(IntEnum):
    """Standard exit codes for the garak CLI.

    Follows common Unix conventions:
    - 0: success
    - 1: general / runtime error
    - 2: CLI usage / argument error
    - 3: configuration error
    - 4: plugin error (missing API key, bad generator, etc.)
    - 5: user-initiated interrupt (Ctrl-C / SIGINT)
    """

    SUCCESS = 0
    RUNTIME_ERROR = 1
    USAGE_ERROR = 2
    CONFIG_ERROR = 3
    PLUGIN_ERROR = 4
    INTERRUPTED = 5


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
