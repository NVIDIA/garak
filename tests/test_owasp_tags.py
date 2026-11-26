"""Tests verifying OWASP tag formatting, year-qualification, and schema validation (issue #2139)."""

import re
import pytest

from garak import _plugins
from garak.data import path as data_path

BARE_OWASP_PATTERN = re.compile(r"^owasp:llm\d+$")
YEAR_QUALIFIED_OWASP_PATTERN = re.compile(r"^owasp:\d{4}:llm\d+$")


def validate_owasp_tag(tag: str) -> bool:
    """Validate that an OWASP tag uses the year-qualified format owasp:YYYY:llmNN.

    Returns False if the tag is in the deprecated un-year-qualified format owasp:llmNN.
    Returns True for correctly formatted tags (or non-OWASP tags).
    """
    if BARE_OWASP_PATTERN.match(tag):
        return False
    return True


def test_validator_rejects_un_year_qualified_owasp_tag():
    """Negative test: verify that legacy un-year-qualified tags are detected and rejected."""
    # Deprecated bare format must be rejected
    assert not validate_owasp_tag("owasp:llm01")
    assert not validate_owasp_tag("owasp:llm08")
    assert not validate_owasp_tag("owasp:llm10")

    # Correct year-qualified format must pass
    assert validate_owasp_tag("owasp:2023:llm01")
    assert validate_owasp_tag("owasp:2023:llm08")
    assert validate_owasp_tag("owasp:2025:llm06")

    # Non-OWASP tags must not be affected
    assert validate_owasp_tag("avid-effect:security:S0403")
    assert validate_owasp_tag("quality:Security:PromptStability")


def test_no_un_year_qualified_owasp_probe_tags():
    """CI enforcement: verify all probes in garak carry year-qualified OWASP tags."""
    violations = []
    for plugin_name, _ in _plugins.enumerate_plugins("probes"):
        info = _plugins.PluginCache.plugin_info(plugin_name)
        for tag in info.get("tags", []):
            if BARE_OWASP_PATTERN.match(tag):
                violations.append((plugin_name, tag))

    assert not violations, (
        f"Found {len(violations)} probe(s) using un-year-qualified OWASP tags: {violations}. "
        "OWASP tags must follow the format 'owasp:YYYY:llmNN' (e.g. 'owasp:2023:llm01'). "
        "See issue #2139."
    )


def test_no_un_year_qualified_owasp_detector_tags():
    """CI enforcement: verify all detectors in garak carry year-qualified OWASP tags."""
    violations = []
    for plugin_name, _ in _plugins.enumerate_plugins("detectors"):
        info = _plugins.PluginCache.plugin_info(plugin_name)
        for tag in info.get("tags", []):
            if BARE_OWASP_PATTERN.match(tag):
                violations.append((plugin_name, tag))

    assert not violations, (
        f"Found {len(violations)} detector(s) using un-year-qualified OWASP tags: {violations}. "
        "OWASP tags must follow the format 'owasp:YYYY:llmNN' (e.g. 'owasp:2023:llm01'). "
        "See issue #2139."
    )


def test_tags_misp_tsv_owasp_year_qualification():
    """Verify garak/data/tags.misp.tsv contains no bare tags and defines year-qualified categories."""
    misp_file = data_path / "tags.misp.tsv"
    assert misp_file.is_file(), f"tags.misp.tsv not found at {misp_file}"

    defined_tags = set()
    bare_tags = []
    with open(misp_file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            tag = line.split("\t")[0]
            defined_tags.add(tag)
            if BARE_OWASP_PATTERN.match(tag):
                bare_tags.append(tag)

    assert not bare_tags, (
        f"tags.misp.tsv contains un-year-qualified OWASP tags: {bare_tags}. "
        "Expected all OWASP tags to follow 'owasp:YYYY:llmNN'."
    )

    # Verify key 2023 and 2025 tags are present
    assert (
        "owasp:2023:llm01" in defined_tags
    ), "owasp:2023:llm01 must be defined in tags.misp.tsv"
    assert (
        "owasp:2023:llm08" in defined_tags
    ), "owasp:2023:llm08 must be defined in tags.misp.tsv"
    assert (
        "owasp:2025:llm06" in defined_tags
    ), "owasp:2025:llm06 must be defined in tags.misp.tsv"
