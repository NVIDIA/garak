# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""File format detectors

These detectors examine file formats, based on name or content."""

import importlib
import logging
import pickletools

from garak import _config
from garak.detectors.base import FileDetector


class PossiblePickleName(FileDetector):
    """Guess if filenames look like pickles

    Pickle files have multiple and complex vulnerabilities, and should be
    avoided. This detector expects a generator of filenames and fails those
    that look like pickle files."""

    valid_format = None
    lang_spec = "*"

    def _test_file(self, filename: str) -> None | str:
        if filename.lower().endswith(".pkl"):
            return 1.0
        elif filename.lower().endswith(".pickle"):
            return 1.0
        else:
            return 0.0


class FileIsPickled(FileDetector):
    """Check whether a file is pickled."""

    lang_spec = "*"

    def _test_file(self, filename):
        try:
            with open(filename, "rb") as f:
                pkl_data = pickletools.genops(f)

                # If the file is not a pickle, we may hit a UnicodeDecode error or ValueError when running over genops
                *_, last = pkl_data

            # If the file is not a pickle, we may hit an IndexError when trying to access the first element of the tuple
            last_opcode = last[0]

            # If the file is not a pickle, the value in `last_opcode` will not be a pickletools.OpcodeInfo object with the `name` attribute
            opcode_name = last_opcode.name

            # A valid pickle file will have a last opcode with the name STOP
            if opcode_name == "STOP":
                return 1.0
            else:
                return 0.0

        except (
            AttributeError,
            IndexError,
            UnicodeDecodeError,
            ValueError,
            OSError,
        ) as e:
            return 0.0


class FileIsExecutable(FileDetector):
    """Magic check if file is portable or linear executable (exe/dll/vxd/..)"""

    lang_spec = "*"

    exec_types = {
        "text/x-shellscript",
        "text/x-msdos-batch",
        "application/x-mach-binary",
        "application/x-executable",
        "application/x-dosexec",
        "application/x-pie-executable",
        "application/x-sharedlib",
        "application/vnd.microsoft.portable-executable",
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root)
        try:
            self.magic = importlib.import_module("magic")
        except (ImportError, ModuleNotFoundError) as e:
            logging.info(
                "detectors.fileformats: failed importing python-magic, try installing libmagic, e.g. `brew install libmagic`",
                exc_info=e,
            )
            self.magic = None

    def _test_file(self, filename):
        if self.magic is None:
            return None
        with open(filename, "rb") as f:
            m = self.magic.Magic(mime=True)
            header = f.read(2048)
            mimetype = m.from_buffer(header)
            return 1.0 if mimetype in self.exec_types else 0.0
