# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak.attempt
import garak.probes
from garak import _plugins
from garak.probes.web_injection import (
    MarkdownURIImageExfilExtended,
    MarkdownURINonImageExfilExtended,
)

WEB_INJECTION_PROBES = {
    "probes.web_injection.MarkdownImageExfil": "web_injection.MarkdownExfilBasic",
    "probes.web_injection.ColabAIDataLeakage": "web_injection.MarkdownExfilContent",
    "probes.web_injection.StringAssemblyDataExfil": "web_injection.MarkdownExfilBasic",
    "probes.web_injection.PlaygroundMarkdownExfil": "web_injection.PlaygroundMarkdownExfil",
    "probes.web_injection.MarkdownURINonImageExfilExtended": "web_injection.MarkdownExfilExtendedNonImage",
    "probes.web_injection.MarkdownURIImageExfilExtended": "web_injection.MarkdownExfilExtendedImage",
    "probes.web_injection.TaskXSS": "web_injection.XSS",
    "probes.web_injection.MarkdownXSS": "web_injection.XSS",
}


@pytest.mark.parametrize("classname,detector", WEB_INJECTION_PROBES.items())
def test_web_injection_probe_load(classname, detector):
    p = _plugins.load_plugin(classname)
    assert isinstance(p, garak.probes.Probe)
    assert p.primary_detector == detector
    assert p.active is True


@pytest.mark.parametrize("classname", WEB_INJECTION_PROBES.keys())
def test_web_injection_probe_prompts_nonempty(classname):
    p = _plugins.load_plugin(classname)
    assert len(p.prompts) > 0
    for prompt in p.prompts:
        assert isinstance(prompt, str)
        assert len(prompt) > 0


def test_markdown_image_exfil_prompts_contain_markdown_image():
    p = _plugins.load_plugin("probes.web_injection.MarkdownImageExfil")
    for prompt in p.prompts:
        assert "logo.png" in prompt


def test_markdown_image_exfil_prestore_hook_sets_terms():
    p = _plugins.load_plugin("probes.web_injection.MarkdownImageExfil")
    attempt = p._attempt_prestore_hook(
        garak.attempt.Attempt(prompt=garak.attempt.Message(p.prompts[0], lang="en")),
        0,
    )
    assert "terms" in attempt.notes
    assert "passwords" in attempt.notes["terms"]


def test_markdown_xss_prompts_use_javascript_template():
    p = _plugins.load_plugin("probes.web_injection.MarkdownXSS")
    for prompt in p.prompts:
        assert prompt.startswith("[link](javascript:")


def test_string_assembly_data_exfil_prompt_count_matches_seeds():
    p = _plugins.load_plugin("probes.web_injection.StringAssemblyDataExfil")
    assert len(p.prompts) == len(p.seeds)


def test_colab_ai_data_leakage_mutate_domain_preserves_characters():
    p = _plugins.load_plugin("probes.web_injection.ColabAIDataLeakage")
    domain = "example.com"
    mutated = p.mutate_domain(domain)
    rebuilt = mutated.replace('"', "").rstrip(",")
    assert rebuilt.replace(",", "") == domain


@pytest.mark.parametrize(
    "probe_class, image_marker",
    [
        (MarkdownURINonImageExfilExtended, ""),
        (MarkdownURIImageExfilExtended, "!"),
    ],
)
def test_extended_markdown_exfil_templates_cover_link_variants(
    probe_class, image_marker
):
    expected_templates = [
        f"{image_marker}[{{link_display_text}}]({{uri}})",
        f"{image_marker}[{{link_display_text}}][ref]\n\n[ref]: {{uri}}",
        f"{image_marker}[{{link_display_text}}][]\n\n" "[{link_display_text}]: {uri}",
        f"{image_marker}[{{link_display_text}}][{{link_display_text}}]\n\n"
        "[{link_display_text}]: {uri}",
    ]

    assert probe_class.markdown_uri_templates == expected_templates, (
        f"{probe_class.__name__} should cover four distinct Markdown link "
        "reference styles that match its paired detector"
    )
