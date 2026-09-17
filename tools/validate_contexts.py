# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""**Validate contexts**

Utility to validate the JSON schema expected by contexts stored in garak/data/contexts/

Usage:
`python validate_contexts.py <path_to_json_file>`

"""

import json
from sys import argv
import pathlib


def validate_schema(filename: str) -> bool:
    """Series of checks to see if the file is a valid context json file"""
    filepath = pathlib.Path(filename)
    error_in_file = False

    if not filepath.is_file():
        print(f"{filepath} is not a file.")
        error_in_file = True

    if filepath.suffix != ".json":
        print("Expected a file with a .json extension")
        error_in_file = True

    if error_in_file:
        print("Please fix the existing errors and try again to validate schema.")
        exit(0)

    with open(filepath, mode="r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.decoder.JSONDecodeError as e:
            print(f"{filepath} is not a valid json file")
            exit(1)

        if not isinstance(data, dict):
            print(f"{filepath} did not return a dict when calling json.load")
            exit(0)

    if "context_name" not in data.keys():
        print(f"{filepath} is missing a 'context_name' key.")
        error_in_file = True
    if "detector_name" not in data.keys():
        print(f"{filepath} is missing a 'detector_name' key.")
        error_in_file = True
    if "injection_marker" not in data.keys():
        print(f"{filepath} is missing a 'injection_marker' key.")
        error_in_file = True
    if "contexts" not in data.keys():
        print(f"{filepath} is missing a 'contexts' key.")
        error_in_file = True
    if "lang" not in data.keys():
        print(f"{filepath} is missing a 'lang' key.")
        error_in_file = True

    if "contexts" in data.keys():
        contexts = data["contexts"]
        if isinstance(contexts, list):
            for context in contexts:
                if not isinstance(context, str):
                    print(f"Not all values in 'contexts' are strings.")
                    error_in_file = True
                    break

        else:
            print(f"Value in 'contexts' key is {type(contexts)} but should be a list.")
            error_in_file = True

    return error_in_file


if __name__ == "__main__":
    error = validate_schema(argv[1])
    if error:
        print("Please fix the existing errors and try again to validate schema.")
    else:
        print("Schema validated successfully.")
