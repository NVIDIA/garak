# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak import _plugins
import garak.payloads
import garak.probes.base
import garak.probes.latentinjection

LATENT_INJECTION_PROBES = [
    classname
    for (classname, active) in _plugins.enumerate_plugins("probes")
    if classname.startswith("probes.latentinjection")
]


@pytest.mark.parametrize("classname", LATENT_INJECTION_PROBES)
def test_latentinjection_structure(classname):
    p = _plugins.load_plugin(classname)
    assert isinstance(
        p, garak.probes.base.Probe
    ), "Latent injection probes must be instances of probes.base.Probe"
    assert len(p.prompts) == len(p.triggers), "Each prompt must have a matching trigger"
    list_attribs = "top_instructions contexts injection_sep_pairs injection_instructions payloads payload_triggers".split()
    for list_attrib in list_attribs:
        p_list_attrib = getattr(p, list_attrib)
        assert (
            isinstance(p_list_attrib, list) and len(p_list_attrib) > 0
        ), f"{p_list_attrib} must be a non-empty list"

    for i in range(len(p.prompts)):
        assert (
            p.triggers[i] in p.prompts[i]
        ), "Each prompt must contain its accompanying trigger verbatim"
    assert isinstance(p.top_instructions, list)
    for _ti_e in enumerate(p.top_instructions):
        assert isinstance(
            _ti_e[1], str
        ), "Top-level instructions must be a string. index " + str(_ti_e[0])
    for _context_e in enumerate(p.contexts):
        assert garak.probes.latentinjection.INJECTION_MARKER in _context_e[1], (
            "Each context must contain an injection marker - missing f-string? index "
            + str(_context_e[0])
        )
    for _ii_e in enumerate(p.injection_instructions):
        assert garak.probes.latentinjection.PAYLOAD_MARKER in _ii_e[1], (
            "Each injection instruction must contain a payload marker - missing f-string? index "
            + str(_ii_e[0])
        )
    for _payload_e in enumerate(p.payloads):
        assert garak.probes.latentinjection.TRIGGER_MARKER in _payload_e[1], (
            "Each payload instruction must contain a trigger marker - missing f-string? index"
            + str(_payload_e[0])
        )
    for pair in p.injection_sep_pairs:
        assert len(pair) == 2, "separation pairs should have a start and end"
        assert isinstance(pair[0], str)
        assert isinstance(pair[1], str)


def test_whois_payload_injection_marker():
    marker = "{INJECTION_MARKER}"
    payload_name = "whois_injection_contexts"
    for id, payload in enumerate(garak.payloads.load(payload_name).payloads):
        assert (
            marker in payload
        ), f"Each whois payload must contain {marker} but this was not found in {payload_name} payload {id}"


class TestFactSnippet(
    garak.probes.latentinjection.FactSnippetMixin, garak.probes.Probe
):
    snippets_per_context = 5
    snippet_context_cap = 20
    snippet_raw_marker = True
    snippet_sep = "\n"
    paragraphs = list("ABCDEFGH")


def test_fact_snippet_build():
    t = TestFactSnippet()

    t.snippet_raw_marker = True
    t._build_snippet_contexts()
    assert len(t.contexts) == t.snippet_context_cap, "Not enough contexts returned"
    assert len(set(t.contexts)) == len(
        t.contexts
    ), "Contexts should be unique w/ no duplicates"
    for context in t.contexts:
        parts = context.split(t.snippet_sep)
        for part in parts:
            assert (
                part in t.paragraphs
                or part == garak.probes.latentinjection.INJECTION_MARKER
            ), "found unrecognised context component: '%s' in context '%s'" % (
                part,
                context,
            )
        assert garak.probes.latentinjection.INJECTION_MARKER in context, (
            "Missing injection marker in '%s'" % context
        )

    t.snippet_raw_marker = False
    t.paragraphs = [p + "{INJECTION_MARKER}" for p in t.paragraphs]
    t._build_snippet_contexts()
    assert len(t.contexts) == t.snippet_context_cap, "Not enough contexts returned"
    assert len(set(t.contexts)) == len(
        t.contexts
    ), "Contexts should be unique w/ no duplicates"
    for context in t.contexts:
        parts = context.split(t.snippet_sep)
        assert (
            len(parts) == t.snippets_per_context
        ), "Should be %s snippets in this context, got %s: %s" % (
            t.snippets_per_context,
            len(parts),
            repr(context),
        )
        for part in parts:
            assert part in [
                p.replace(
                    "{INJECTION_MARKER}", garak.probes.latentinjection.INJECTION_MARKER
                )
                for p in t.paragraphs
            ] or part in [
                p.replace("{INJECTION_MARKER}", "") for p in t.paragraphs
            ], "found unrecognised context component: %s in context %s" % (
                repr(part),
                repr(context),
            )
        assert (
            garak.probes.latentinjection.INJECTION_MARKER in context
        ), "Missing injection marker in %s" % repr(context)
