import pytest
import re

from garak import cli, _plugins

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def _plugin_lines(text: str):
    clean = _strip_ansi(text)
    lines = [ln.strip() for ln in clean.splitlines()]
    # collect any line that contains a plugin prefix (don’t require it to be at col 0)
    plugin_lines = []
    for plugin_type in _plugins.PLUGIN_TYPES:
        [plugin_lines.append(ln) for ln in lines if f"{plugin_type}:" in ln]
    return plugin_lines


@pytest.mark.parametrize(
    "options",
    [
        ("--list_probes",),
        ("--list_probes", "-p", "dan"),
        ("--list_probes", "-p", "dan,dan.AntiDAN"),
    ],
)
def test_list_probes_with_probe_spec(capsys, options):
    cli.main(options)
    lines = _plugin_lines(capsys.readouterr().out)
    assert all(
        ln.startswith("probes: ") for ln in lines
    ), "expected all 'probes:' lines"

    if len(options) > 1:
        parts = options[2].split(",")
        assert all(
            any(part in ln for part in parts) for ln in lines
        ), "expected all spec values to be present"
    else:
        # look for active and family listing
        assert any("🌟" in ln for ln in lines)
        assert any("💤" in ln for ln in lines)


@pytest.mark.parametrize(
    "options",
    [
        ("--list_detectors",),
        ("--list_detectors", "-d", "unsafe_content"),
        ("--list_detectors", "-d", "unsafe_content,shields.Up"),
    ],
)
def test_list_probes_with_detector_spec(capsys, options):
    cli.main(options)
    lines = _plugin_lines(capsys.readouterr().out)
    assert all(
        ln.startswith("detectors: ") for ln in lines
    ), "expected all 'detectors:' lines"

    if len(options) > 1:
        parts = options[2].split(",")
        assert all(
            any(part in ln for part in parts) for ln in lines
        ), "expected all spec values to be present"
    else:
        assert any("🌟" in ln for ln in lines)


def test_list_probes_shows_tier(capsys):
    """Test that --list_probes shows tier information for probe classes."""
    cli.main(["--list_probes"])
    lines = _plugin_lines(capsys.readouterr().out)
    # Check that at least some probe lines contain tier information
    tier_lines = [ln for ln in lines if "Tier" in ln and "." in ln]
    assert len(tier_lines) > 0, "expected some probe lines to show tier info"
    # Verify tier format (Tier 1, Tier 2, Tier 3, or Tier 9)
    assert any("Tier 1" in ln or "Tier 2" in ln or "Tier 3" in ln or "Tier 9" in ln for ln in tier_lines)


@pytest.mark.parametrize(
    "tier",
    [1, 2, 3, 9],
)
def test_list_probes_filter_by_tier(capsys, tier):
    """Test that --list_probes <tier> filters probes by tier."""
    cli.main(["--list_probes", str(tier)])
    lines = _plugin_lines(capsys.readouterr().out)
    # Should only have probe classes (with dots), not module headers (module headers don't have tier)
    class_lines = [ln for ln in lines if "." in ln.split("probes: ")[-1].split()[0]]
    # All probe classes shown should be of the specified tier
    if class_lines:  # Some tiers might have no probes
        for ln in class_lines:
            assert f"Tier {tier}" in ln, f"expected all probes to be Tier {tier}, got: {ln}"


def test_list_probes_tier_filter_with_probe_spec(capsys):
    """Test combining --list_probes <tier> with -p probe_spec."""
    # This tests that tier filter and probe spec can work together
    cli.main(["--list_probes", "1", "-p", "encoding"])
    lines = _plugin_lines(capsys.readouterr().out)
    # Should only show encoding probes that are Tier 1
    for ln in lines:
        if "." in ln.split("probes: ")[-1].split()[0]:
            assert "encoding" in ln, "expected only encoding probes"
            assert "Tier 1" in ln, "expected only Tier 1 probes"
