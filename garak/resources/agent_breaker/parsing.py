# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""JSON parsing helpers for model and target output used by Agent Breaker plugins."""

import json


class DuplicateJsonKeyError(ValueError):
    """Signal an ambiguous JSON object containing a repeated field name."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def loads_unique_keys(text: str) -> object:
    """Parse a complete JSON document, rejecting objects with repeated keys.

    The standard library keeps the last of any repeated key, so text such as
    ``{"verdict": "NO", "verdict": "YES"}`` would silently change meaning.

    :raises DuplicateJsonKeyError: when any object repeats a field name
    :raises ValueError: when ``text`` is not valid JSON
    """
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except RecursionError as error:
        raise ValueError("JSON nesting is too deep") from error


def _as_object(parsed: object, text: str, position: int) -> dict:
    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, dict):
                return item
    raise json.JSONDecodeError("No JSON object found", text, position)


def extract_json_object(text: str) -> dict:
    """Extract the first JSON object from model output.

    Accepts output where a model wraps the object in a top-level array or
    appends an explanation after it.

    :raises json.JSONDecodeError: when no complete JSON object can be parsed
    """
    if not isinstance(text, str):
        raise json.JSONDecodeError("Model output must be text", "", 0)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        pass
    except (RecursionError, ValueError) as error:
        raise json.JSONDecodeError("Invalid JSON object", text, 0) from error
    else:
        return _as_object(parsed, text, 0)

    brace_start = text.find("{")
    if brace_start == -1:
        raise json.JSONDecodeError("No JSON object found", text, 0)

    depth = 0
    in_string = False
    escape_next = False
    for index, character in enumerate(text[brace_start:], start=brace_start):
        if escape_next:
            escape_next = False
            continue
        if character == "\\":
            escape_next = True
            continue
        if character == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                try:
                    parsed = json.loads(text[brace_start : index + 1])
                except (RecursionError, ValueError) as error:
                    raise json.JSONDecodeError(
                        "Invalid JSON object", text, brace_start
                    ) from error
                return _as_object(parsed, text, brace_start)

    raise json.JSONDecodeError("Unterminated JSON object", text, brace_start)
