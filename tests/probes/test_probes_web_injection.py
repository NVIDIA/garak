import pytest

from garak import _config
from garak.probes.web_injection import (
    MarkdownURIImageExfilExtended,
    MarkdownURINonImageExfilExtended,
)


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


@pytest.mark.parametrize(
    "probe_class", [MarkdownURINonImageExfilExtended, MarkdownURIImageExfilExtended]
)
@pytest.mark.parametrize("cap", [None, 7])
def test_extended_markdown_exfil_prompt_count_follows_cap(probe_class, cap):
    _config.load_base_config()
    _config.run.soft_probe_prompt_cap = cap
    try:
        probe = probe_class()
    finally:
        _config.load_base_config()
    expected = cap if cap is not None else 256 * 4
    assert len(probe.prompts) == expected


@pytest.mark.parametrize(
    "probe_class", [MarkdownURINonImageExfilExtended, MarkdownURIImageExfilExtended]
)
def test_extended_markdown_exfil_uncapped_count_follows_scale(probe_class):
    _config.load_base_config()
    _config.run.soft_probe_prompt_cap = None
    _config.plugins.probes["web_injection"][probe_class.__name__][
        "uncapped_prompt_scale"
    ] = 2
    try:
        probe = probe_class()
    finally:
        _config.load_base_config()
    assert len(probe.prompts) == 256 * 2
