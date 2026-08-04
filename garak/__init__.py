"""Top-level package for garak"""

__version__ = "0.16.0.pre1"
__app__ = "garak"
__description__ = "LLM vulnerability scanner"

import logging
import os
from garak import _config

GARAK_LOG_FILE_VAR = "GARAK_LOG_FILE"

LOG_FORMAT = "%(asctime)s  %(levelname)s  %(message)s"


def setup_logger(filename=None):
    """Configure the root logger with garak's standard format/level.

    This is the single place the garak log configuration is defined. It is
    called once on initial import of this module, and may be called again
    (e.g. by a :mod:`multiprocessing` pool initializer) to re-apply the same
    configuration after handlers have been reset, such as when a worker
    process needs to close inherited file descriptors and open its own.

    :param filename: path to the log file. Defaults to the currently
        configured ``_config.transient.log_filename``.
    """
    if filename is None:
        filename = _config.transient.log_filename
    logging.basicConfig(
        filename=filename,
        level=logging.DEBUG,
        format=LOG_FORMAT,
    )


# allow for a file path configuration from the ENV and set for child processes
_log_filename = os.getenv(GARAK_LOG_FILE_VAR, default=None)
if _log_filename is None:
    _log_filename = _config.transient.data_dir / "garak.log"
    os.environ[GARAK_LOG_FILE_VAR] = str(_log_filename)

_config.transient.log_filename = _log_filename

setup_logger(_log_filename)
