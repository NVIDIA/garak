# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Local read only resources found by precedence matching supported paths

Ideal usage:

```
file_path = resources / "filename"
with open(file_path) as f:
    f.read()
```

Resources that do not have a `shipped` version should wrap path access in a try block:
```
try:
    file_path = resources / "filename"
except GarakException as e:
    logging.warn("No resource file found.", exc_info=e)
```
"""

import pathlib

from garak import _config
from garak.exception import GarakException


class LocalDataPath(type(pathlib.Path())):
    """restricted Path object usable only for existing resource files"""

    ORDERED_SEARCH_PATHS = [
        _config.transient.data_dir / "data",
        _config.transient.package_dir / "data",
    ]

    def _determine_suffix(self):
        for path in self.ORDERED_SEARCH_PATHS:
            if path == self or path in self.parents:
                return self.relative_to(path)

    def _eval_paths(self, segment, next_call, relative):
        if self in self.ORDERED_SEARCH_PATHS and segment == relative:
            raise GarakException(
                f"The requested resource does not refer to a valid path"
            )

        prefix_removed = self._determine_suffix()
        if prefix_removed is None:
            # if LocalDataPath is instantiated using a path not in ORDERED_SEARCH_PATHS
            raise GarakException(
                f"The requested resource does not refer to a valid path: {self}"
            )
        for path in self.ORDERED_SEARCH_PATHS:
            if segment == relative:
                projected = (path / prefix_removed).parent
            else:
                current_path = path / prefix_removed
                projected = getattr(current_path, next_call)(segment)
            if projected.exists():
                return LocalDataPath(projected)

        if projected in self.ORDERED_SEARCH_PATHS:
            return LocalDataPath(projected)

        raise GarakException(f"The resource requested does not exist {segment}")

    def _glob(self, pattern, recursive=False):
        glob_method = "rglob" if recursive else "glob"

        prefix_removed = self._determine_suffix()
        candidate_files = []
        for path in self.ORDERED_SEARCH_PATHS:
            candidate_path = path / prefix_removed
            dir_files = getattr(candidate_path, glob_method)(pattern)
            candidate_files.append(dir_files)
        relative_paths = []
        selected_files = []
        for files in candidate_files:
            for file in files:
                suffix = LocalDataPath(file)._determine_suffix()
                if suffix not in relative_paths:
                    selected_files.append(file)
                    relative_paths.append(suffix)

        return selected_files

    def glob(self, pattern):
        return self._glob(pattern, recursive=False)

    def rglob(self, pattern):
        return self._glob(pattern, recursive=True)

    def _make_child(self, segment):
        return self._eval_paths(segment, "_make_child", ("..",))

    def joinpath(self, *pathsegments):
        for segment in pathsegments:
            projected = self._eval_paths(segment, "joinpath", "..")
        return projected

    import sys

    if sys.version_info >= (3, 13, 0):
        # disabled override on older versions
        def with_segments(self, *args):
            if isinstance(args[0], LocalDataPath):
                for segment in args:
                    projected = self._eval_paths(segment, "joinpath", "..")
                return projected
            return super().with_segments(*args)


path = LocalDataPath(_config.transient.data_dir / "data")
