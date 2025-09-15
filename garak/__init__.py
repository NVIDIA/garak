"""Top-level package for garak"""

__version__ = "0.13.1.pre1"
__app__ = "garak"
__description__ = "LLM vulnerability scanner"

import os
from garak import _config

GARAK_LOG_FILE_VAR = "GARAK_LOG_FILE"

# allow for a file path configuration from the ENV and set for child processes
_log_filename = os.getenv(GARAK_LOG_FILE_VAR, default=None)
if _log_filename is None:
	_log_filename = _config.transient.data_dir / "garak.log"
	os.environ[GARAK_LOG_FILE_VAR] = str(_log_filename)

_config.transient.log_filename = _log_filename

# Note: Logging configuration is performed in garak.command.start_logging()
# to enable a process-safe Queue-based logging architecture.
