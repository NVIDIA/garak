"""Validate literal artifact evidence used by ToolChain execution."""

import json
import math
import re


def literal_in_text(value: object, text: str) -> bool:
    """Match a scalar value without confusing short identifiers with substrings."""
    if not isinstance(text, str):
        return False
    if isinstance(value, str):
        if not value.strip():
            return False
        forms = [value, json.dumps(value, ensure_ascii=False)[1:-1]]
    elif type(value) is int or (type(value) is float and math.isfinite(value)):
        forms = [str(value)]
    else:
        return False
    for form in forms:
        # Numeric identifiers must not match part of another number or a sign.
        if re.fullmatch(r"[+-]?\d+(?:\.\d+)?", form):
            pattern = rf"(?<![\w.+-]){re.escape(form)}(?!\w|\.\w)"
        else:
            pattern = rf"(?<!\w){re.escape(form)}(?!\w)"
        if re.search(pattern, text):
            return True
    return False


def validate_artifact(
    item: object, request: str, response: str, name_limit: int, value_limit: int
) -> bool:
    """Check an extracted value and its quoted response evidence.

    ``accepted_request`` values must occur in the submitted request. The caller
    must first establish that the step completed; the extraction model judges
    whether the quoted response confirms acceptance of that particular value.
    """
    if not isinstance(item, dict) or set(item) != {
        "name",
        "value",
        "source",
        "evidence",
    }:
        return False
    name, value, source, evidence = (
        item["name"],
        item["value"],
        item["source"],
        item["evidence"],
    )
    if (
        not isinstance(name, str)
        or not name.strip()
        or len(name) > name_limit
        or not isinstance(evidence, str)
        or not evidence.strip()
        or len(evidence) > value_limit
        or evidence not in response
        or not isinstance(source, str)
        or source not in {"response", "accepted_request"}
    ):
        return False
    if not isinstance(value, str) and type(value) not in (int, float):
        return False
    if len(str(value)) > value_limit:
        return False
    if source == "response":
        return literal_in_text(value, evidence)
    return literal_in_text(value, request)
