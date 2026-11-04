import pytest

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
